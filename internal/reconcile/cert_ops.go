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

// ResolveActiveCertPaths returns the active TLS certificate and key paths for st,
// preferring external imported paths when configured and falling back to Store defaults.
func ResolveActiveCertPaths(store *state.Store, st *state.State) (string, string) {
	if store == nil {
		return "", ""
	}
	if st != nil && st.Cert.Mode == "imported" && st.Cert.CertFile != "" && st.Cert.KeyFile != "" {
		return st.Cert.CertFile, st.Cert.KeyFile
	}
	return store.DefaultCert(), store.DefaultKey()
}

// HasCustomExternalCert reports whether st currently points to a custom external certificate/key pair
// outside store.DefaultCert() / store.DefaultKey().
func HasCustomExternalCert(store *state.Store, st *state.State) bool {
	if st == nil || store == nil {
		return false
	}
	return st.Cert.Mode == "imported" &&
		((st.Cert.CertFile != "" && st.Cert.CertFile != store.DefaultCert()) ||
			(st.Cert.KeyFile != "" && st.Cert.KeyFile != store.DefaultKey()))
}

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
}

// IssueACMEAndSync issues an ACME certificate (Cloudflare DNS-01 or HTTP-01), updates state,
// reconciles configs if transitioning away from an external cert path, and reloads active TLS consumers.
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
		hadCustomExternal := HasCustomExternalCert(store, st)
		if _, uerr := store.Update(st.Role, func(cur *state.State) error {
			cur.Cert.Mode = certMode
			cur.Cert.Domain = dom
			cur.Cert.CertFile = ""
			cur.Cert.KeyFile = ""
			cur.Cert.AutoRenew = autoRenew
			if certMode == "acme_http" {
				// HTTP-01 does not rely on CF API tokens
			} else if autoRenew {
				cur.Cert.CFToken = tok
				cur.Cert.CFEmail = email
			} else {
				cur.Cert.CFToken = ""
				cur.Cert.CFEmail = ""
			}
			return nil
		}); uerr != nil {
			return nil, "", fmt.Errorf("update state after issue: %w", uerr)
		}
		if hadCustomExternal {
			if _, rerr := Reconcile(ctx, store, exec, applyOpts); rerr != nil {
				return nil, "", fmt.Errorf("reconcile after cert issue: %w", rerr)
			}
		}
	}
	ReloadCertConsumers(ctx, exec, p.IncludeDaemon, p.LogOut)
	return rep, dom, nil
}

// ImportCertAndSync validates and installs external cert/key files into Store defaults, updates state,
// reconciles if switching away from custom external paths, and reloads active TLS consumers.
func ImportCertAndSync(
	ctx context.Context,
	store *state.Store,
	exec SystemExecutor,
	applyOpts ApplyOptions,
	srcCert, srcKey string,
	allowSelfSigned bool,
	includeDaemon bool,
	logOut io.Writer,
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
		pathsChanged = HasCustomExternalCert(store, st)
		if _, uerr := store.Update(st.Role, func(cur *state.State) error {
			cur.Cert.Mode = "imported"
			cur.Cert.CertFile = store.DefaultCert()
			cur.Cert.KeyFile = store.DefaultKey()
			return nil
		}); uerr != nil {
			return nil, false, false, fmt.Errorf("update state after import: %w", uerr)
		}
		if pathsChanged {
			if _, rerr := Reconcile(ctx, store, exec, applyOpts); rerr != nil {
				return nil, false, false, fmt.Errorf("reconcile after cert import: %w", rerr)
			}
		}
	}
	if changed || pathsChanged {
		ReloadCertConsumers(ctx, exec, includeDaemon, logOut)
	}
	return rep, changed, pathsChanged, nil
}

// SelfSignCertAndSync generates or ensures a self-signed certificate pair, updates state to self_signed,
// reconciles if transitioning from a custom external cert path, and reloads active TLS consumers.
func SelfSignCertAndSync(
	ctx context.Context,
	store *state.Store,
	exec SystemExecutor,
	applyOpts ApplyOptions,
	cn string,
	force bool,
	includeDaemon bool,
	logOut io.Writer,
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
		hadCustomExternal = HasCustomExternalCert(store, st)
		if _, uerr := store.Update(st.Role, func(cur *state.State) error {
			cur.Cert.Mode = "self_signed"
			cur.Cert.CertFile = ""
			cur.Cert.KeyFile = ""
			return nil
		}); uerr != nil {
			return nil, false, false, fmt.Errorf("update state after self-sign: %w", uerr)
		}
		if hadCustomExternal {
			if _, rerr := Reconcile(ctx, store, exec, applyOpts); rerr != nil {
				return nil, false, false, fmt.Errorf("reconcile after self-sign: %w", rerr)
			}
		}
	}
	if certChanged || hadCustomExternal {
		ReloadCertConsumers(ctx, exec, includeDaemon, logOut)
	}
	cb, _ := os.ReadFile(store.DefaultCert())
	kb, _ := os.ReadFile(store.DefaultKey())
	rep, _ := cert.InspectPair(cb, kb)
	return rep, certChanged, hadCustomExternal, nil
}
