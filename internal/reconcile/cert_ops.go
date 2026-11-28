package reconcile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/state"
)

// ReloadCertConsumers reloads or restarts active TLS consumers (nginx, dex-xray, and optionally dex-daemon).
func ReloadCertConsumers(ctx context.Context, exec SystemExecutor, includeDaemon bool, stdout io.Writer) {
	if exec == nil {
		return
	}
	initSys := exec.DetectInitSystem()
	var reloaded []string
	if exec.ServiceIsActive(ctx, initSys, "nginx") {
		if err := exec.ServiceReload(ctx, initSys, "nginx"); err != nil {
			_ = exec.ServiceRestart(ctx, initSys, "nginx")
		}
		reloaded = append(reloaded, "nginx")
	}
	if exec.ServiceIsActive(ctx, initSys, "dex-xray") {
		_ = exec.ServiceRestart(ctx, initSys, "dex-xray")
		reloaded = append(reloaded, "dex-xray")
	}
	if stdout != nil && len(reloaded) > 0 {
		fmt.Fprintf(stdout, "Reloaded TLS consumers: %s\n", strings.Join(reloaded, ", "))
	}
	if includeDaemon && exec.ServiceIsActive(ctx, initSys, "dex-daemon") {
		_ = exec.ServiceRestart(ctx, initSys, "dex-daemon")
		if stdout != nil {
			fmt.Fprintln(stdout, "Reloaded TLS consumers: dex-daemon")
		}
	}
}

func runCertReload(ctx context.Context, exec SystemExecutor, includeDaemon bool, stdout io.Writer, reloadFn func(context.Context)) {
	if reloadFn != nil {
		reloadFn(ctx)
		return
	}
	ReloadCertConsumers(ctx, exec, includeDaemon, stdout)
}

// CleanupTProxyPolicyRoutes removes dex fwmark 0x9 policy routing rules and flushes table 220 across IPv4/IPv6.
func CleanupTProxyPolicyRoutes(ctx context.Context, exec SystemExecutor) {
	if exec == nil || !exec.HasCommand("ip") {
		return
	}
	mark := fmt.Sprintf("0x%x", state.TProxyMark)
	table := fmt.Sprintf("%d", state.TProxyRouteTable)
	for _, family := range []string{"-4", "-6"} {
		for i := 0; i < 4; i++ {
			if _, err := exec.RunCommand(ctx, nil, "ip", family, "rule", "del", "fwmark", mark, "table", table); err != nil {
				break
			}
		}
		_, _ = exec.RunCommand(ctx, nil, "ip", family, "route", "flush", "table", table)
	}
}

func firstNonEmptyCertStr(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// IssueACMEParams configures IssueACMEAndSync.
type IssueACMEParams struct {
	Mode          string
	Domain        string
	CFToken       string
	CFEmail       string
	Webroot       string
	AutoRenew     *bool
	ReloadCmd     string
	IncludeDaemon bool
	LogOut        io.Writer
	ReloadFn      func(context.Context) // optional override invoked once instead of default ReloadCertConsumers
}

// IssueACMEAndSync issues an ACME certificate (Cloudflare DNS-01 or HTTP-01), atomically updates state
// and reconciles if transitioning away from an external cert path, then reloads active TLS consumers once.
func IssueACMEAndSync(
	ctx context.Context,
	store *state.Store,
	exec SystemExecutor,
	applyOpts ApplyOptions,
	runner cert.ACMERunner,
	p IssueACMEParams,
) (*cert.CertReport, string, error) {
	st, stErr := store.Load()
	dom := strings.TrimSpace(p.Domain)
	tok := strings.TrimSpace(p.CFToken)
	email := strings.TrimSpace(p.CFEmail)
	autoRenew := true
	if stErr == nil && st != nil {
		if dom == "" {
			dom = firstNonEmptyCertStr(st.Cert.Domain, st.Server.Domain)
		}
		if tok == "" {
			tok = st.Cert.CFToken
		}
		if email == "" {
			email = st.Cert.CFEmail
		}
		if p.AutoRenew != nil {
			autoRenew = *p.AutoRenew
		}
	} else if p.AutoRenew != nil {
		autoRenew = *p.AutoRenew
	}

	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" {
		mode = "cf"
	}
	cfg := cert.ACMEConfig{
		Domain:    dom,
		CFToken:   tok,
		CFEmail:   email,
		Webroot:   strings.TrimSpace(p.Webroot),
		ListenV6:  st != nil && st.System.EnableIPv6,
		AutoRenew: autoRenew,
		CertPath:  store.DefaultCert(),
		KeyPath:   store.DefaultKey(),
		ReloadCmd: p.ReloadCmd,
	}

	var (
		rep      *cert.CertReport
		certMode string
		err      error
	)
	switch mode {
	case "cf", "cloudflare", "dns":
		certMode = "acme_cf"
		rep, err = cert.IssueCloudflareACME(ctx, runner, cfg)
	case "http", "http-01":
		certMode = "acme_http"
		rep, err = cert.IssueHTTPACME(ctx, runner, cfg)
	default:
		return nil, "", fmt.Errorf("mode must be 'cf' or 'http' (got %q)", p.Mode)
	}
	if err != nil {
		return nil, "", err
	}

	if stErr == nil && st != nil {
		if lerr := store.WithApplyLock(ctx, func(locked *state.Store) error {
			var hadCustomExternal bool
			if _, uerr := locked.Update(st.Role, func(cur *state.State) error {
				hadCustomExternal = locked.HasCustomExternalCert(cur)
				cur.Cert.UseACME(certMode, dom, autoRenew, tok, email)
				return nil
			}); uerr != nil {
				return fmt.Errorf("update state after issue: %w", uerr)
			}
			if hadCustomExternal {
				if _, rerr := Reconcile(ctx, locked, exec, applyOpts); rerr != nil {
					return fmt.Errorf("reconcile after cert issue: %w", rerr)
				}
			}
			return nil
		}); lerr != nil {
			return nil, "", lerr
		}
	}
	runCertReload(ctx, exec, p.IncludeDaemon, p.LogOut, p.ReloadFn)
	return rep, dom, nil
}

// ImportCertAndSync validates and installs external cert/key files into Store defaults, atomically updates state
// and reconciles if switching away from custom external paths, then reloads active TLS consumers once.
func ImportCertAndSync(
	ctx context.Context,
	store *state.Store,
	exec SystemExecutor,
	applyOpts ApplyOptions,
	srcCert, srcKey string,
	allowSelfSigned bool,
	includeDaemon bool,
	logOut io.Writer,
	reloadFn func(context.Context),
) (*cert.CertReport, bool, bool, error) {
	st, stErr := store.Load()
	if stErr != nil && !errors.Is(stErr, state.ErrNotFound) {
		return nil, false, false, stErr
	}
	var checkDomains []string
	if st != nil {
		if d := firstNonEmptyCertStr(st.Cert.Domain, st.Server.Domain); d != "" {
			checkDomains = append(checkDomains, d)
		}
	}
	rep, changed, err := cert.ImportPair(srcCert, srcKey, store.DefaultCert(), store.DefaultKey(), allowSelfSigned, checkDomains)
	if err != nil {
		return nil, false, false, err
	}

	pathsChanged := false
	if st != nil {
		if lerr := store.WithApplyLock(ctx, func(locked *state.Store) error {
			if _, uerr := locked.Update(st.Role, func(cur *state.State) error {
				pathsChanged = locked.HasCustomExternalCert(cur)
				cur.Cert.UseImported(locked.DefaultCert(), locked.DefaultKey())
				return nil
			}); uerr != nil {
				return fmt.Errorf("update state after import: %w", uerr)
			}
			if pathsChanged {
				if _, rerr := Reconcile(ctx, locked, exec, applyOpts); rerr != nil {
					return fmt.Errorf("reconcile after cert import: %w", rerr)
				}
			}
			return nil
		}); lerr != nil {
			return nil, false, false, lerr
		}
	}
	if changed || pathsChanged {
		runCertReload(ctx, exec, includeDaemon, logOut, reloadFn)
	}
	return rep, changed, pathsChanged, nil
}

// SelfSignCertAndSync generates or ensures a self-signed certificate pair, atomically updates state to self_signed
// and reconciles if transitioning from a custom external cert path, then reloads active TLS consumers once.
func SelfSignCertAndSync(
	ctx context.Context,
	store *state.Store,
	exec SystemExecutor,
	applyOpts ApplyOptions,
	cn string,
	force bool,
	includeDaemon bool,
	logOut io.Writer,
	reloadFn func(context.Context),
) (*cert.CertReport, bool, bool, error) {
	st, stErr := store.Load()
	if stErr != nil && !errors.Is(stErr, state.ErrNotFound) {
		return nil, false, false, stErr
	}
	effectiveCN := firstNonEmptyCertStr(cn)
	if effectiveCN == "" && st != nil {
		effectiveCN = firstNonEmptyCertStr(st.Cert.Domain, st.Server.Domain)
	}
	if effectiveCN == "" {
		effectiveCN = "localhost"
	}

	certChanged := false
	if force {
		if err := cert.ForceSelfSigned(store.DefaultCert(), store.DefaultKey(), effectiveCN); err != nil {
			return nil, false, false, err
		}
		certChanged = true
	} else {
		prevCert, _ := os.ReadFile(store.DefaultCert())
		if err := cert.EnsureSelfSigned(store.DefaultCert(), store.DefaultKey(), effectiveCN); err != nil {
			return nil, false, false, err
		}
		afterCert, _ := os.ReadFile(store.DefaultCert())
		certChanged = !bytes.Equal(prevCert, afterCert)
	}

	hadCustomExternal := false
	if st != nil {
		if lerr := store.WithApplyLock(ctx, func(locked *state.Store) error {
			if _, uerr := locked.Update(st.Role, func(cur *state.State) error {
				hadCustomExternal = locked.HasCustomExternalCert(cur)
				cur.Cert.UseSelfSigned()
				return nil
			}); uerr != nil {
				return fmt.Errorf("update state after self-sign: %w", uerr)
			}
			if hadCustomExternal {
				if _, rerr := Reconcile(ctx, locked, exec, applyOpts); rerr != nil {
					return fmt.Errorf("reconcile after self-sign: %w", rerr)
				}
			}
			return nil
		}); lerr != nil {
			return nil, false, false, lerr
		}
	}
	if certChanged || hadCustomExternal {
		runCertReload(ctx, exec, includeDaemon, logOut, reloadFn)
	}
	cb, _ := os.ReadFile(store.DefaultCert())
	kb, _ := os.ReadFile(store.DefaultKey())
	rep, _ := cert.InspectPair(cb, kb)
	return rep, certChanged, hadCustomExternal, nil
}
