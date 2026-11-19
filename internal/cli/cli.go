package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stuinxo/de_GWD/v3/internal/cert"
	"github.com/stuinxo/de_GWD/v3/internal/cryptoext"
	"github.com/stuinxo/de_GWD/v3/internal/daemon"
	"github.com/stuinxo/de_GWD/v3/internal/doh"
	"github.com/stuinxo/de_GWD/v3/internal/migrate"
	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/render"
	"github.com/stuinxo/de_GWD/v3/internal/socks5out"
	"github.com/stuinxo/de_GWD/v3/internal/state"
	"github.com/stuinxo/de_GWD/v3/internal/version"
	"github.com/stuinxo/de_GWD/v3/internal/web"
)

// Run is the main CLI entrypoint invoked by cmd/dex/main.go and tests.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	stateDir := strings.TrimSpace(os.Getenv("DEX_STATE_DIR"))
	if stateDir == "" {
		stateDir = "/etc/dex"
	}

	// Parse leading global --state-dir flag
	for len(args) > 0 && strings.HasPrefix(args[0], "--state-dir") {
		if args[0] == "--state-dir" {
			if len(args) < 2 {
				fmt.Fprintln(stderr, "missing argument for --state-dir")
				return 2
			}
			stateDir = args[1]
			args = args[2:]
		} else if val, ok := strings.CutPrefix(args[0], "--state-dir="); ok {
			stateDir = val
			args = args[1:]
		}
	}

	store := state.NewStore(stateDir)
	store.OnApplyLockWait = func() {
		fmt.Fprintln(stderr, "waiting for another dex apply...")
	}
	exec := reconcile.OSExecutor{}

	if len(args) == 0 {
		return runInteractiveMenu(store, exec, stdin, stdout, stderr)
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "dex %s\n", version.Summary())
		return 0
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "menu":
		return runInteractiveMenu(store, exec, stdin, stdout, stderr)
	case "init":
		return cmdInit(store, exec, rest, stdout, stderr)
	case "apply":
		return cmdApply(store, exec, rest, stdout, stderr)
	case "refresh":
		return cmdApply(store, exec, rest, stdout, stderr)
	case "status":
		return cmdStatus(store, exec, stdout, stderr)
	case "node":
		return cmdNode(store, exec, rest, stdout, stderr)
	case "cert":
		return cmdCert(store, exec, rest, stdout, stderr)
	case "wg":
		return cmdWG(store, exec, rest, stdout, stderr)
	case "ddns":
		return cmdDDNS(store, exec, rest, stdout, stderr)
	case "socks5":
		return cmdSocks5(store, exec, rest, stdout, stderr)
	case "relay":
		return cmdRelay(store, exec, rest, stdout, stderr)
	case "rproxy":
		return cmdRproxy(store, exec, rest, stdout, stderr)
	case "extra":
		return cmdExtra(store, exec, rest, stdout, stderr)
	case "rules":
		return cmdRules(store, exec, rest, stdout, stderr)
	case "update":
		return cmdUpdate(store, exec, rest, stdout, stderr)
	case "migrate":
		return cmdMigrate(store, exec, rest, stdout, stderr)
	case "daemon":
		return cmdDaemon(store, exec, rest, stdout, stderr)
	case "serve-doh":
		return cmdServeDoH(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", sub)
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `DEX v3 — Unified Bypass Gateway & Node Controller

Usage:
  dex [--state-dir DIR] [command] [flags]

Commands:
  menu                  Open interactive numbered menu (default when no args)
  init                  Initialize a new client / server / landing / relay state
  apply                 Validate, render, pre-flight check, and reconcile configs
  status                Show role, active node, certificate, and service health
  node <subcmd>         Manage client outbound nodes (list|add|del|select|show)
  cert <subcmd>         Manage TLS certificates (self-sign|import|issue|inspect|reload)
  wg <subcmd>           Manage WireGuard VPN (enable|disable|peer-add|peer-del|show)
  ddns <subcmd>         Manage Cloudflare DDNS (set|sync|disable)
  socks5 <subcmd>       Manage server Option 35 SOCKS5 exits (list|add|del|toggle|test)
  relay <subcmd>        Manage Option 44 port forwards (list|add|del)
  rproxy <subcmd>       Manage RproxyS/RproxyC reverse proxy (show|set|map-add|map-del|disable|client-*)
  extra <subcmd>        Manage Option 55 extra inbounds (list|add-reality|add-socks5|del)
  rules <subcmd>        Inspect or hot-update GeoIP/Domain rule files (status|update)
  update                Upgrade dex, xray, mosdns, and/or rule datasets cleanly
  migrate               Import v2 0conf, v2 server, des, or dexs state (--cleanup-v2 --apply)
  daemon                Run embedded Web UI + failover + Cloudflare DDNS loops
  serve-doh             Run standalone RFC 8484 DoH forwarding server
  refresh               Re-resolve dynamic relay targets and re-apply nftables
  version               Print dex version
`)
}

func cmdInit(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	role := fs.String("role", state.RoleClient, "role: client|server|landing|relay")
	domain := fs.String("domain", "", "domain name")
	connectHost := fs.String("connect-host", "", "external host/IP for clients")
	port := fs.Int("port", 0, "listen port")
	pubPort := fs.Int("public-port", 0, "NAT public port")
	tlsMode := fs.String("tls-mode", "", "server tls_mode: nginx|direct")
	pw := fs.String("password", "", "web UI password (random 16-char if omitted)")
	uuid := fs.String("uuid", "", "primary UUID (auto-generated if omitted)")
	doh := fs.String("doh", "", "custom DoH URL(s), comma-separated (client role)")
	doApply := fs.Bool("apply", false, "apply configuration immediately")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	st := state.NewDefaultState(*role)
	rawPW := *pw
	if rawPW == "" {
		var err error
		rawPW, err = cryptoext.GenerateInitialPassword()
		if err != nil {
			fmt.Fprintf(stderr, "generate password: %v\n", err)
			return 1
		}
	}
	hash, err := cryptoext.HashPassword(rawPW)
	if err != nil {
		fmt.Fprintf(stderr, "hash password: %v\n", err)
		return 1
	}
	st.Auth.PasswordHash = hash

	u := *uuid
	if u == "" {
		u, err = cryptoext.GenerateUUID()
		if err != nil {
			fmt.Fprintf(stderr, "generate uuid: %v\n", err)
			return 1
		}
	}

	switch st.Role {
	case state.RoleServer, state.RoleLanding:
		if *domain == "" {
			*domain = "node.example.com"
		}
		if *tlsMode != "" {
			st.Server.TLSMode = *tlsMode
		}
		if *port > 0 {
			st.Server.ListenPort = *port
		}
		st.Server.PublicPort = *pubPort
		st.Server.Domain = *domain
		st.Server.ConnectHost = *connectHost
		st.Server.UUIDs = []string{u}
		st.Server.Path = cryptoext.UUIDToDefaultPath(u)
		st.Cert.Domain = *domain
	case state.RoleClient:
		if *port > 0 {
			st.Auth.ListenAddr = fmt.Sprintf(":%d", *port)
		}
		if *domain != "" {
			st.Auth.ServerName = *domain
		}
		if strings.TrimSpace(*doh) != "" {
			var list []string
			for _, u := range strings.Split(*doh, ",") {
				u = strings.TrimSpace(u)
				if u != "" {
					list = append(list, u)
				}
			}
			if len(list) > 0 {
				st.Client.DNS.DoHServers = list
			}
		}
	}

	if err := cert.EnsureSelfSigned(store.DefaultCert(), store.DefaultKey(), st.Auth.ServerName); err != nil {
		fmt.Fprintf(stderr, "ensure cert: %v\n", err)
		return 1
	}
	if err := store.Save(st); err != nil {
		fmt.Fprintf(stderr, "save state: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Initialized %s state at %s\n", st.Role, store.StatePath())
	if *pw == "" {
		fmt.Fprintf(stdout, "Initial Web Password: %s\n", rawPW)
	}
	if st.Role == state.RoleServer || st.Role == state.RoleLanding {
		fmt.Fprintf(stdout, "Main Node URI: %s\n", render.BuildServerMainURI(st))
	}

	if *doApply {
		if _, err := reconcile.Reconcile(context.Background(), store, exec, reconcile.ApplyOptions{}); err != nil {
			fmt.Fprintf(stderr, "apply failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Configuration reconciled successfully.")
	}
	return 0
}

func cmdApply(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dryRun := fs.Bool("dry-run", false, "render and validate without modifying system")
	outDir := fs.String("out-dir", "", "optional directory to write rendered files during --dry-run")
	force := fs.Bool("force", false, "overwrite manually modified managed files")
	restartAll := fs.Bool("restart-all", false, "force restart of all active managed services")
	rootPrefix := fs.String("root-prefix", "", "optional target root directory prefix")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	res, err := reconcile.Reconcile(context.Background(), store, exec, reconcile.ApplyOptions{
		DryRun:     *dryRun,
		Force:      *force,
		RestartAll: *restartAll,
		RootPrefix: *rootPrefix,
	})
	if err != nil {
		fmt.Fprintf(stderr, "apply failed: %v\n", err)
		return 1
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	if *dryRun {
		if *outDir != "" {
			for _, f := range res.Bundle.Files {
				rel := f.RelName
				if rel == "" {
					rel = strings.TrimPrefix(filepath.Clean(f.TargetPath), string(filepath.Separator))
				}
				dst := filepath.Join(*outDir, filepath.Clean(rel))
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					fmt.Fprintf(stderr, "write rendered %s: %v\n", dst, err)
					return 1
				}
				if err := os.WriteFile(dst, f.Content, f.Mode); err != nil {
					fmt.Fprintf(stderr, "write rendered %s: %v\n", dst, err)
					return 1
				}
			}
		}
		fmt.Fprintf(stdout, "Dry-run OK (%d files rendered):\n", len(res.Bundle.Files))
		for _, f := range res.Bundle.Files {
			fmt.Fprintf(stdout, "  - %s (%d bytes, mode %04o)\n", f.TargetPath, len(f.Content), f.Mode)
		}
		return 0
	}
	restarted := "none"
	if len(res.ServicesRestarted) > 0 {
		restarted = strings.Join(res.ServicesRestarted, ", ")
	}
	fmt.Fprintf(stdout, "Applied %d file(s). Active services: %s (restarted: %s)\n", len(res.FilesWritten), strings.Join(res.ServicesOn, ", "), restarted)
	return 0
}

func cmdStatus(store *state.Store, exec reconcile.SystemExecutor, stdout, stderr io.Writer) int {
	st, err := store.Load()
	if err != nil {
		fmt.Fprintf(stderr, "load state: %v\n", err)
		return 1
	}
	initSys := exec.DetectInitSystem()
	fmt.Fprintf(stdout, "DEX %s | Role: %s | Init: %s | Mem: %d MiB\n",
		version.Summary(), st.Role, initSys, exec.DetectMemMB())
	fmt.Fprintf(stdout, "State: %s\n", store.StatePath())
	if st.Role == state.RoleClient {
		if active := st.Client.ActiveNode(); active != nil {
			fmt.Fprintf(stdout, "Active Node: %s (%s %s:%d)\n", active.Name, active.Protocol, active.Address, active.Port)
		} else {
			fmt.Fprintln(stdout, "Active Node: (none)")
		}
		fmt.Fprintf(stdout, "Failover: %v | WireGuard: %v (%d peers) | DDNS: %v\n",
			st.Client.FailoverEnabled, st.Client.WireGuard.Enabled, len(st.Client.WireGuard.Peers), st.Client.DDNS.Enabled)
	} else if st.Role == state.RoleServer || st.Role == state.RoleLanding {
		fmt.Fprintf(stdout, "Domain: %s | Mode: %s | Port: %d (pub %d)\n",
			st.Server.Domain, st.Server.TLSMode, st.Server.ListenPort, st.Server.EffectivePublicPort())
	}
	fmt.Fprintf(stdout, "Relay Forwards: %d | RproxyS: %v | Extra Inbounds: %d\n",
		len(st.Relay.Forwards), st.RproxyS.Enabled, len(st.ExtraInbounds))
	return 0
}

func cmdNode(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "list" {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		if st.Role == state.RoleServer || st.Role == state.RoleLanding {
			fmt.Fprintf(stdout, "Main Node: %s\n", render.BuildServerMainURI(st))
			return 0
		}
		for _, n := range st.Client.Nodes {
			mark := " "
			if n.ID == st.Client.ActiveNodeID {
				mark = "*"
			}
			fmt.Fprintf(stdout, "%s [%s] %-16s %-13s %s:%d\n", mark, n.ID, n.Name, n.Protocol, n.Address, n.Port)
		}
		return 0
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "show":
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		if st.Role == state.RoleServer || st.Role == state.RoleLanding {
			fmt.Fprintf(stdout, "Domain:   %s\nAddress:  %s:%d\nUUIDs:    %s\nPath:     %s\nURI:      %s\n",
				st.Server.Domain, st.Server.EffectiveConnectHost(), st.Server.EffectivePublicPort(),
				strings.Join(st.Server.UUIDs, ", "),
				render.NormalizePath(st.Server.Path, firstOrEmpty(st.Server.UUIDs)),
				render.BuildServerMainURI(st))
			return 0
		}
		var target *state.OutboundNode
		if len(rest) > 0 {
			target = st.Client.FindNode(rest[0])
		} else {
			target = st.Client.ActiveNode()
		}
		if target == nil {
			fmt.Fprintln(stderr, "no matching node found")
			return 1
		}
		fmt.Fprintf(stdout, "ID:       %s\nName:     %s\nProtocol: %s\nAddress:  %s:%d\nSNI:      %s\nURI:      %s\n",
			target.ID, target.Name, target.Protocol, target.Address, target.Port,
			target.EffectiveSNI(), render.BuildNodeURI(*target))
		return 0

	case "add":
		fs := flag.NewFlagSet("node add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		id := fs.String("id", "", "node id")
		name := fs.String("name", "", "node name")
		proto := fs.String("proto", "vless-xhttp", "protocol")
		addr := fs.String("address", "", "server host/ip")
		port := fs.Int("port", 443, "server port")
		uuid := fs.String("uuid", "", "UUID")
		sni := fs.String("sni", "", "TLS SNI")
		path := fs.String("path", "", "WS/XHTTP path")
		pbk := fs.String("pbk", "", "Reality public key")
		sid := fs.String("sid", "", "Reality shortId")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *addr == "" {
			fmt.Fprintln(stderr, "--address is required")
			return 2
		}
		if *uuid == "" {
			*uuid, _ = cryptoext.GenerateUUID()
		}
		if *id == "" {
			*id = fmt.Sprintf("node-%d", time.Now().UnixNano()%1000000)
		}
		if *name == "" {
			*name = *addr
		}
		mut := func(cur *state.State) error {
			cur.Client.Nodes = append(cur.Client.Nodes, state.OutboundNode{
				ID:             *id,
				Name:           *name,
				Protocol:       *proto,
				Address:        *addr,
				Port:           *port,
				UUID:           *uuid,
				TLSSNI:         *sni,
				Path:           *path,
				RealityPubKey:  *pbk,
				RealityShortID: *sid,
			})
			if cur.Client.ActiveNodeID == "" {
				cur.Client.ActiveNodeID = *id
			}
			return nil
		}
		if err := applyOrSave(store, exec, state.RoleClient, *doApply, mut); err != nil {
			fmt.Fprintf(stderr, "node add failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Added node %s (%s)\n", *id, *addr)
		return 0

	case "del":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: dex node del <id> [--apply]")
			return 2
		}
		id := rest[0]
		doApply := len(rest) > 1 && rest[1] == "--apply"
		mut := func(cur *state.State) error {
			var next []state.OutboundNode
			found := false
			for _, n := range cur.Client.Nodes {
				if n.ID == id {
					found = true
					continue
				}
				next = append(next, n)
			}
			if !found {
				return fmt.Errorf("node %q not found", id)
			}
			cur.Client.Nodes = next
			if cur.Client.ActiveNodeID == id {
				if len(next) > 0 {
					cur.Client.ActiveNodeID = next[0].ID
				} else {
					cur.Client.ActiveNodeID = ""
				}
			}
			return nil
		}
		if err := applyOrSave(store, exec, state.RoleClient, doApply, mut); err != nil {
			fmt.Fprintf(stderr, "node del failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Deleted node %s\n", id)
		return 0

	case "select":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: dex node select <id> [--apply]")
			return 2
		}
		id := rest[0]
		doApply := len(rest) > 1 && rest[1] == "--apply"
		mut := func(cur *state.State) error {
			if cur.Client.FindNode(id) == nil {
				return fmt.Errorf("node %q not found", id)
			}
			cur.Client.ActiveNodeID = id
			return nil
		}
		if err := applyOrSave(store, exec, state.RoleClient, doApply, mut); err != nil {
			fmt.Fprintf(stderr, "node select failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Selected node %s\n", id)
		return 0

	default:
		fmt.Fprintf(stderr, "unknown node subcommand %q\n", sub)
		return 2
	}
}

func cmdCert(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "inspect" {
		cb, err1 := os.ReadFile(store.DefaultCert())
		kb, err2 := os.ReadFile(store.DefaultKey())
		if err1 != nil || err2 != nil {
			fmt.Fprintf(stderr, "cannot read cert/key in %s: %v / %v\n", store.CertDir(), err1, err2)
			return 1
		}
		rep, err := cert.InspectPair(cb, kb)
		if err != nil {
			fmt.Fprintf(stderr, "inspect error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "CN: %s\nSANs: %s\nExpires: %s\nSelfSigned: %v | ChainValid: %v\n",
			rep.CommonName, strings.Join(rep.SANs, ", "), rep.NotAfter.Format(time.RFC3339), rep.SelfSigned, rep.ChainValid)
		for _, w := range rep.Warnings {
			fmt.Fprintf(stdout, "Warning: %s\n", w)
		}
		return 0
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "self-sign":
		cn := "localhost"
		if len(rest) > 0 {
			cn = rest[0]
		}
		prevCert, _ := os.ReadFile(store.DefaultCert())
		if err := cert.EnsureSelfSigned(store.DefaultCert(), store.DefaultKey(), cn); err != nil {
			fmt.Fprintf(stderr, "self-sign failed: %v\n", err)
			return 1
		}
		afterCert, _ := os.ReadFile(store.DefaultCert())
		if !bytes.Equal(prevCert, afterCert) {
			reloadCertConsumers(context.Background(), exec, stdout)
		}
		fmt.Fprintf(stdout, "Self-signed certificate ready at %s\n", store.DefaultCert())
		return 0
	case "import":
		if len(rest) < 2 {
			fmt.Fprintln(stderr, "usage: dex cert import <cert.pem> <key.pem> [--allow-self-signed]")
			return 2
		}
		allowSelf := len(rest) > 2 && rest[2] == "--allow-self-signed"
		var checkDomains []string
		if st, err := store.Load(); err == nil && st.Server.Domain != "" {
			checkDomains = append(checkDomains, st.Server.Domain)
		}
		rep, changed, err := cert.ImportPair(rest[0], rest[1], store.DefaultCert(), store.DefaultKey(), allowSelf, checkDomains)
		if err != nil {
			fmt.Fprintf(stderr, "import failed: %v\n", err)
			return 1
		}
		if changed {
			reloadCertConsumers(context.Background(), exec, stdout)
		}
		fmt.Fprintf(stdout, "Certificate imported (changed=%v, expires=%s, SANs=%s)\n",
			changed, rep.NotAfter.Format("2006-01-02"), strings.Join(rep.SANs, ", "))
		return 0
	case "issue":
		fs := flag.NewFlagSet("cert issue", flag.ContinueOnError)
		fs.SetOutput(stderr)
		dom := fs.String("domain", "", "domain")
		tok := fs.String("cf-token", "", "Cloudflare API Token")
		renew := fs.Bool("renew", false, "keep CF token for automatic renewal")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		st, _ := store.Load()
		if *dom == "" && st != nil {
			*dom = st.Cert.Domain
			if *dom == "" {
				*dom = st.Server.Domain
			}
		}
		if *tok == "" && st != nil {
			*tok = st.Cert.CFToken
		}
		rep, err := cert.IssueCloudflareACME(context.Background(), nil, cert.ACMEConfig{
			Domain:    *dom,
			CFToken:   *tok,
			AutoRenew: *renew,
			CertPath:  store.DefaultCert(),
			KeyPath:   store.DefaultKey(),
			ReloadCmd: buildCertReloadCmd(store.Dir),
		})
		if err != nil {
			fmt.Fprintf(stderr, "acme issue failed: %v\n", err)
			return 1
		}
		if st != nil {
			_, _ = store.Update(st.Role, func(cur *state.State) error {
				cur.Cert.Mode = "acme"
				cur.Cert.Domain = *dom
				cur.Cert.AutoRenew = *renew
				if *renew {
					cur.Cert.CFToken = *tok
				} else {
					cur.Cert.CFToken = ""
				}
				return nil
			})
		}
		reloadCertConsumers(context.Background(), exec, stdout)
		fmt.Fprintf(stdout, "Certificate issued for %s (expires %s)\n", strings.Join(rep.SANs, ", "), rep.NotAfter.Format("2006-01-02"))
		return 0
	case "reload":
		reloadCertConsumers(context.Background(), exec, stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown cert subcommand %q\n", sub)
		return 2
	}
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func buildCertReloadCmd(stateDir string) string {
	exe, err := os.Executable()
	if err != nil || exe == "" || strings.HasSuffix(exe, ".test") || strings.Contains(exe, "/go-build") {
		exe = "/usr/local/bin/dex"
	}
	return fmt.Sprintf("%s --state-dir %s cert reload", shellSingleQuote(exe), shellSingleQuote(stateDir))
}

func reloadCertConsumers(ctx context.Context, exec reconcile.SystemExecutor, stdout io.Writer) {
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
	for _, svc := range []string{"dex-xray", "dex-daemon"} {
		if exec.ServiceIsActive(ctx, initSys, svc) {
			_ = exec.ServiceRestart(ctx, initSys, svc)
			reloaded = append(reloaded, svc)
		}
	}
	if stdout != nil && len(reloaded) > 0 {
		fmt.Fprintf(stdout, "Reloaded TLS consumers: %s\n", strings.Join(reloaded, ", "))
	}
}

func cmdWG(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "show" {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		wg := st.Client.WireGuard
		if len(args) > 1 {
			for _, p := range wg.Peers {
				if p.Name == args[1] {
					fmt.Fprint(stdout, render.BuildWGPeerConfig(wg, p))
					return 0
				}
			}
			fmt.Fprintf(stderr, "peer %q not found\n", args[1])
			return 1
		}
		fmt.Fprintf(stdout, "WireGuard: enabled=%v endpoint=%s:%d subnet=%s peers=%d\n",
			wg.Enabled, wg.EndpointHost, wg.ListenPort, wg.SubnetCIDR, len(wg.Peers))
		for _, p := range wg.Peers {
			fmt.Fprintf(stdout, "  - %-12s %s\n", p.Name, p.IP)
		}
		return 0
	}

	sub := args[0]
	rest := args[1:]
	switch sub {
	case "enable":
		fs := flag.NewFlagSet("wg enable", flag.ContinueOnError)
		fs.SetOutput(stderr)
		ep := fs.String("endpoint", "", "public endpoint host/IP")
		port := fs.Int("port", 51820, "UDP listen port")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		mut := func(cur *state.State) error {
			cur.Client.WireGuard.Enabled = true
			if *ep != "" {
				cur.Client.WireGuard.EndpointHost = *ep
			}
			if cur.Client.WireGuard.EndpointHost == "" {
				cur.Client.WireGuard.EndpointHost = "vpn.example.com"
			}
			cur.Client.WireGuard.ListenPort = *port
			if cur.Client.WireGuard.SubnetCIDR == "" {
				cur.Client.WireGuard.SubnetCIDR = "172.16.66.1/24"
			}
			if cur.Client.WireGuard.ServerPrivateKey == "" {
				priv, pub, err := cryptoext.GenerateWireGuardKeypair()
				if err != nil {
					return err
				}
				cur.Client.WireGuard.ServerPrivateKey = priv
				cur.Client.WireGuard.ServerPublicKey = pub
			}
			return nil
		}
		if err := applyOrSave(store, exec, state.RoleClient, *doApply, mut); err != nil {
			fmt.Fprintf(stderr, "wg enable failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "WireGuard enabled.")
		return 0

	case "disable":
		doApply := len(rest) > 0 && rest[0] == "--apply"
		if err := applyOrSave(store, exec, state.RoleClient, doApply, func(cur *state.State) error {
			cur.Client.WireGuard.Enabled = false
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "wg disable failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "WireGuard disabled.")
		return 0

	case "peer-add":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: dex wg peer-add <name> [--apply]")
			return 2
		}
		name := rest[0]
		doApply := len(rest) > 1 && rest[1] == "--apply"
		priv, pub, err := cryptoext.GenerateWireGuardKeypair()
		if err != nil {
			fmt.Fprintf(stderr, "generate keypair: %v\n", err)
			return 1
		}
		var cfgText string
		mut := func(cur *state.State) error {
			wg := &cur.Client.WireGuard
			for _, p := range wg.Peers {
				if p.Name == name {
					return fmt.Errorf("peer %q already exists", name)
				}
			}
			if wg.ServerPrivateKey == "" {
				sp, spub, kerr := cryptoext.GenerateWireGuardKeypair()
				if kerr != nil {
					return kerr
				}
				wg.ServerPrivateKey = sp
				wg.ServerPublicKey = spub
			}
			if wg.ListenPort == 0 {
				wg.ListenPort = 51820
			}
			if wg.SubnetCIDR == "" {
				wg.SubnetCIDR = "172.16.66.1/24"
			}
			if wg.EndpointHost == "" {
				if cur.Client.DDNS.Domain != "" {
					wg.EndpointHost = cur.Client.DDNS.Domain
				} else {
					wg.EndpointHost = "vpn.example.com"
				}
			}
			wg.Enabled = true
			ip := fmt.Sprintf("172.16.66.%d", 11+len(wg.Peers))
			peer := state.WGPeer{Name: name, IP: ip, PrivateKey: priv, PublicKey: pub}
			wg.Peers = append(wg.Peers, peer)
			cfgText = render.BuildWGPeerConfig(*wg, peer)
			return nil
		}
		if err := applyOrSave(store, exec, state.RoleClient, doApply, mut); err != nil {
			fmt.Fprintf(stderr, "wg peer-add failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Added peer %s:\n%s", name, cfgText)
		return 0

	case "peer-del":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: dex wg peer-del <name> [--apply]")
			return 2
		}
		name := rest[0]
		doApply := len(rest) > 1 && rest[1] == "--apply"
		if err := applyOrSave(store, exec, state.RoleClient, doApply, func(cur *state.State) error {
			var next []state.WGPeer
			found := false
			for _, p := range cur.Client.WireGuard.Peers {
				if p.Name == name {
					found = true
					continue
				}
				next = append(next, p)
			}
			if !found {
				return fmt.Errorf("peer %q not found", name)
			}
			cur.Client.WireGuard.Peers = next
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "wg peer-del failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Deleted peer %s\n", name)
		return 0

	default:
		fmt.Fprintf(stderr, "unknown wg subcommand %q\n", sub)
		return 2
	}
}

func cmdDDNS(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: dex ddns <set|sync|disable>")
		return 2
	}
	switch args[0] {
	case "set":
		fs := flag.NewFlagSet("ddns set", flag.ContinueOnError)
		fs.SetOutput(stderr)
		dom := fs.String("domain", "", "domain")
		tok := fs.String("token", "", "Cloudflare API Token")
		v6 := fs.Bool("ipv6", false, "also update AAAA")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := applyOrSave(store, exec, state.RoleClient, false, func(cur *state.State) error {
			cur.Client.DDNS = state.DDNSConfig{
				Enabled:    true,
				Provider:   "cloudflare",
				Domain:     *dom,
				CFToken:    *tok,
				EnableIPv6: *v6,
			}
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "ddns set failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Cloudflare DDNS configured.")
		return 0
	case "sync":
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		d := daemon.NewCloudflareDDNS(nil)
		res, err := d.SyncOnce(context.Background(), st.Client.DDNS.Domain, st.Client.DDNS.CFToken, st.Client.DDNS.EnableIPv6, true)
		if err != nil {
			fmt.Fprintf(stderr, "ddns sync failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "DDNS synced %s -> IPv4=%s (updated=%v) IPv6=%s (updated=%v)\n",
			res.Domain, res.IPv4, res.Updated4, res.IPv6, res.Updated6)
		return 0
	case "disable":
		if err := applyOrSave(store, exec, state.RoleClient, false, func(cur *state.State) error {
			cur.Client.DDNS.Enabled = false
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "ddns disable failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "DDNS disabled.")
		return 0
	default:
		fmt.Fprintf(stderr, "unknown ddns subcommand %q\n", args[0])
		return 2
	}
}

func cmdSocks5(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "list" {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		for _, p := range st.Server.Socks5Outbounds {
			fmt.Fprintf(stdout, "%-12s enabled=%-5v %s domains=%d ips=%d\n",
				p.Name, p.Enabled, socks5out.FormatEndpoint(p.Address, p.Port), len(p.Domains), len(p.IPs))
		}
		return 0
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "add":
		fs := flag.NewFlagSet("socks5 add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "default", "profile name")
		ep := fs.String("endpoint", "", "SOCKS5 endpoint URI/tuple/host:port")
		port := fs.Int("port", 1080, "port if endpoint omitted port")
		domains := fs.String("domains", "", "comma-separated domain rules or @ai,@stream,@tg")
		ips := fs.String("ips", "", "comma-separated IP/CIDR rules or @tg")
		privBypass := fs.Bool("private-bypass", true, "bypass private CIDRs for global default")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		parsed, err := socks5out.ParseEndpoint(*ep)
		if err != nil {
			fmt.Fprintf(stderr, "invalid endpoint: %v\n", err)
			return 1
		}
		pPort := parsed.Port
		if pPort == 0 {
			pPort = *port
		}
		domList, err := socks5out.ExpandPresetRules("domain", *domains)
		if err != nil {
			fmt.Fprintf(stderr, "invalid domains: %v\n", err)
			return 1
		}
		ipList, err := socks5out.ExpandPresetRules("ip", *ips)
		if err != nil {
			fmt.Fprintf(stderr, "invalid ips: %v\n", err)
			return 1
		}
		mut := func(cur *state.State) error {
			prof := state.Socks5Profile{
				Name:          *name,
				Enabled:       true,
				Address:       parsed.Address,
				Port:          pPort,
				Username:      parsed.Username,
				Password:      parsed.Password,
				Domains:       domList,
				IPs:           ipList,
				PrivateBypass: *privBypass,
			}
			for i, existing := range cur.Server.Socks5Outbounds {
				if existing.Name == *name {
					cur.Server.Socks5Outbounds[i] = prof
					return nil
				}
			}
			cur.Server.Socks5Outbounds = append(cur.Server.Socks5Outbounds, prof)
			return nil
		}
		if err := applyOrSave(store, exec, state.RoleServer, *doApply, mut); err != nil {
			fmt.Fprintf(stderr, "socks5 add failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Configured SOCKS5 profile %s (%s:%d)\n", *name, parsed.Address, pPort)
		return 0

	case "del":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: dex socks5 del <name> [--apply]")
			return 2
		}
		target := rest[0]
		doApply := len(rest) > 1 && rest[1] == "--apply"
		if err := applyOrSave(store, exec, state.RoleServer, doApply, func(cur *state.State) error {
			var next []state.Socks5Profile
			for _, p := range cur.Server.Socks5Outbounds {
				if p.Name != target {
					next = append(next, p)
				}
			}
			cur.Server.Socks5Outbounds = next
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "socks5 del failed: %v\n", err)
			return 1
		}
		return 0

	case "toggle":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: dex socks5 toggle <name> [--apply]")
			return 2
		}
		target := rest[0]
		doApply := len(rest) > 1 && rest[1] == "--apply"
		if err := applyOrSave(store, exec, state.RoleServer, doApply, func(cur *state.State) error {
			for i := range cur.Server.Socks5Outbounds {
				if cur.Server.Socks5Outbounds[i].Name == target {
					cur.Server.Socks5Outbounds[i].Enabled = !cur.Server.Socks5Outbounds[i].Enabled
					return nil
				}
			}
			return fmt.Errorf("profile %q not found", target)
		}); err != nil {
			fmt.Fprintf(stderr, "socks5 toggle failed: %v\n", err)
			return 1
		}
		return 0

	case "test":
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		for _, p := range st.Server.Socks5Outbounds {
			if len(rest) > 0 && p.Name != rest[0] {
				continue
			}
			res, perr := socks5out.ProbeProfile(context.Background(), p.Address, p.Port, p.Username, p.Password, nil)
			if perr != nil {
				fmt.Fprintf(stdout, "[FAIL] %s: %v\n", p.Name, perr)
			} else {
				fmt.Fprintf(stdout, "[OK]   %s: IP=%s loc=%s RTT=%dms\n", p.Name, res.ExitIP, res.Location, res.Latency.Milliseconds())
			}
		}
		return 0

	default:
		fmt.Fprintf(stderr, "unknown socks5 subcommand %q\n", sub)
		return 2
	}
}

func cmdRelay(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "list" {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		for _, f := range st.Relay.Forwards {
			fmt.Fprintf(stdout, "[%s] :%d -> %s:%d [%s] [%s]\n", f.ID, f.ListenPort, f.TargetHost, f.TargetPort, f.Proto, f.Engine)
		}
		return 0
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("relay add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		id := fs.String("id", "", "rule id")
		listen := fs.Int("listen", 0, "listen port")
		targetHost := fs.String("target-host", "", "target host")
		targetPort := fs.Int("target-port", 443, "target port")
		proto := fs.String("proto", "tcp", "tcp|udp|tcp,udp")
		engine := fs.String("engine", "nft", "nft|haproxy|xray")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *listen <= 0 || *targetHost == "" {
			fmt.Fprintln(stderr, "--listen and --target-host are required")
			return 2
		}
		if *id == "" {
			*id = fmt.Sprintf("fwd-%d", *listen)
		}
		if err := applyOrSave(store, exec, state.RoleRelay, *doApply, func(cur *state.State) error {
			cur.Relay.Forwards = append(cur.Relay.Forwards, state.ForwardRule{
				ID:         *id,
				ListenPort: *listen,
				PublicPort: *listen,
				TargetHost: *targetHost,
				TargetPort: *targetPort,
				Proto:      *proto,
				Engine:     *engine,
			})
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "relay add failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Added relay %s :%d -> %s:%d (%s)\n", *id, *listen, *targetHost, *targetPort, *engine)
		return 0
	case "del":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "usage: dex relay del <id-or-port> [--apply]")
			return 2
		}
		key := args[1]
		doApply := len(args) > 2 && args[2] == "--apply"
		portNum, _ := strconv.Atoi(key)
		if err := applyOrSave(store, exec, state.RoleRelay, doApply, func(cur *state.State) error {
			var next []state.ForwardRule
			for _, f := range cur.Relay.Forwards {
				if f.ID == key || (portNum > 0 && f.ListenPort == portNum) {
					continue
				}
				next = append(next, f)
			}
			cur.Relay.Forwards = next
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "relay del failed: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown relay subcommand %q\n", args[0])
		return 2
	}
}

func existingRoleOr(store *state.Store, fallback string) string {
	if st, err := store.Load(); err == nil && st.Role != "" {
		return st.Role
	}
	return fallback
}

func upsertRproxyServerMapping(list []state.RproxyServerMapping, item state.RproxyServerMapping) []state.RproxyServerMapping {
	for i := range list {
		if list[i].Port == item.Port {
			list[i] = item
			return list
		}
	}
	return append(list, item)
}

func upsertRproxyClientMapping(list []state.RproxyClientMapping, item state.RproxyClientMapping) []state.RproxyClientMapping {
	for i := range list {
		if list[i].ExtPort == item.ExtPort {
			list[i] = item
			return list
		}
	}
	return append(list, item)
}

func cmdRproxy(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "show" {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "RproxyS: enabled=%v domain=%s port=%d uuids=%v mappings=%d\n",
			st.RproxyS.Enabled, st.RproxyS.Domain, st.RproxyS.ListenPort, st.RproxyS.UUIDs, len(st.RproxyS.Mappings))
		for _, m := range st.RproxyS.Mappings {
			fmt.Fprintf(stdout, "  S-Map :%d (%s)\n", m.Port, m.Proto)
		}
		fmt.Fprintf(stdout, "RproxyC: enabled=%v tunnel=%s:%d uuid=%s mappings=%d\n",
			st.Client.RproxyC.Enabled, st.Client.RproxyC.TunnelAddress, st.Client.RproxyC.TunnelPort, st.Client.RproxyC.TunnelUUID, len(st.Client.RproxyC.Mappings))
		for _, m := range st.Client.RproxyC.Mappings {
			fmt.Fprintf(stdout, "  C-Map :%d (%s) -> %s:%d\n", m.ExtPort, m.Proto, m.IntIP, m.IntPort)
		}
		return 0
	}
	defRole := existingRoleOr(store, state.RoleRelay)
	switch args[0] {
	case "set":
		fs := flag.NewFlagSet("rproxy set", flag.ContinueOnError)
		fs.SetOutput(stderr)
		dom := fs.String("domain", "", "tunnel domain")
		port := fs.Int("port", 20000, "tunnel listen port")
		uuid := fs.String("uuid", "", "tunnel UUID")
		mapPort := fs.Int("map-port", 0, "optional mapped port to add")
		mapProto := fs.String("map-proto", "tcp", "tcp|udp|tcp,udp")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *uuid == "" {
			*uuid, _ = cryptoext.GenerateUUID()
		}
		if err := applyOrSave(store, exec, defRole, *doApply, func(cur *state.State) error {
			cur.RproxyS.Enabled = true
			if *dom != "" {
				cur.RproxyS.Domain = *dom
			}
			cur.RproxyS.ListenPort = *port
			cur.RproxyS.UUIDs = []string{*uuid}
			if *mapPort > 0 {
				cur.RproxyS.Mappings = upsertRproxyServerMapping(cur.RproxyS.Mappings, state.RproxyServerMapping{
					Port:  *mapPort,
					Proto: *mapProto,
				})
			}
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "rproxy set failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "RproxyS configured on :%d (UUID: %s)\n", *port, *uuid)
		return 0
	case "map-add":
		fs := flag.NewFlagSet("rproxy map-add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		port := fs.Int("port", 0, "mapped public port")
		proto := fs.String("proto", "tcp", "tcp|udp|tcp,udp")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *port <= 0 || *port > 65535 {
			fmt.Fprintln(stderr, "--port must be 1..65535")
			return 2
		}
		if err := applyOrSave(store, exec, defRole, *doApply, func(cur *state.State) error {
			if !cur.RproxyS.Enabled {
				return errors.New("enable RproxyS via 'dex rproxy set' first")
			}
			cur.RproxyS.Mappings = upsertRproxyServerMapping(cur.RproxyS.Mappings, state.RproxyServerMapping{
				Port:  *port,
				Proto: *proto,
			})
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "rproxy map-add failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Added RproxyS mapping :%d (%s)\n", *port, *proto)
		return 0
	case "map-del":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "usage: dex rproxy map-del <port> [--apply]")
			return 2
		}
		p, err := strconv.Atoi(args[1])
		if err != nil || p <= 0 {
			fmt.Fprintln(stderr, "invalid port")
			return 2
		}
		doApply := len(args) > 2 && args[2] == "--apply"
		if err := applyOrSave(store, exec, defRole, doApply, func(cur *state.State) error {
			var next []state.RproxyServerMapping
			for _, m := range cur.RproxyS.Mappings {
				if m.Port != p {
					next = append(next, m)
				}
			}
			cur.RproxyS.Mappings = next
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "rproxy map-del failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Removed RproxyS mapping :%d\n", p)
		return 0
	case "disable":
		doApply := len(args) > 1 && args[1] == "--apply"
		if err := applyOrSave(store, exec, defRole, doApply, func(cur *state.State) error {
			cur.RproxyS.Enabled = false
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "rproxy disable failed: %v\n", err)
			return 1
		}
		return 0
	case "client-set":
		fs := flag.NewFlagSet("rproxy client-set", flag.ContinueOnError)
		fs.SetOutput(stderr)
		addr := fs.String("address", "", "tunnel server host/IP")
		port := fs.Int("port", 20000, "tunnel server port")
		uuid := fs.String("uuid", "", "tunnel UUID")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if strings.TrimSpace(*addr) == "" {
			fmt.Fprintln(stderr, "--address is required")
			return 2
		}
		if err := applyOrSave(store, exec, state.RoleClient, *doApply, func(cur *state.State) error {
			u := strings.TrimSpace(*uuid)
			if u == "" {
				u = cur.Client.RproxyC.TunnelUUID
			}
			if u == "" {
				return errors.New("--uuid is required")
			}
			cur.Client.RproxyC.Enabled = true
			cur.Client.RproxyC.TunnelAddress = strings.TrimSpace(*addr)
			cur.Client.RproxyC.TunnelPort = *port
			cur.Client.RproxyC.TunnelUUID = u
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "rproxy client-set failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "RproxyC tunnel -> %s:%d\n", strings.TrimSpace(*addr), *port)
		return 0
	case "client-map-add":
		fs := flag.NewFlagSet("rproxy client-map-add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		extPort := fs.Int("ext-port", 0, "remote mapped port")
		intTarget := fs.String("int", "", "local LAN target ip:port")
		proto := fs.String("proto", "tcp", "tcp|udp|tcp,udp")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *extPort <= 0 || *extPort > 65535 || strings.TrimSpace(*intTarget) == "" {
			fmt.Fprintln(stderr, "--ext-port and --int ip:port are required")
			return 2
		}
		intIP, intPortStr, err := net.SplitHostPort(strings.TrimSpace(*intTarget))
		if err != nil {
			fmt.Fprintf(stderr, "invalid --int target %q: %v\n", *intTarget, err)
			return 2
		}
		intPort, err := strconv.Atoi(intPortStr)
		if err != nil || intPort <= 0 || intPort > 65535 {
			fmt.Fprintf(stderr, "invalid internal port %q\n", intPortStr)
			return 2
		}
		if err := applyOrSave(store, exec, state.RoleClient, *doApply, func(cur *state.State) error {
			cur.Client.RproxyC.Mappings = upsertRproxyClientMapping(cur.Client.RproxyC.Mappings, state.RproxyClientMapping{
				ExtPort: *extPort,
				Proto:   *proto,
				IntIP:   strings.Trim(intIP, "[]"),
				IntPort: intPort,
			})
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "rproxy client-map-add failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Added RproxyC mapping :%d (%s) -> %s:%d\n", *extPort, *proto, strings.Trim(intIP, "[]"), intPort)
		return 0
	case "client-map-del":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "usage: dex rproxy client-map-del <ext-port> [--apply]")
			return 2
		}
		ep, err := strconv.Atoi(args[1])
		if err != nil || ep <= 0 {
			fmt.Fprintln(stderr, "invalid ext-port")
			return 2
		}
		doApply := len(args) > 2 && args[2] == "--apply"
		if err := applyOrSave(store, exec, state.RoleClient, doApply, func(cur *state.State) error {
			var next []state.RproxyClientMapping
			for _, m := range cur.Client.RproxyC.Mappings {
				if m.ExtPort != ep {
					next = append(next, m)
				}
			}
			cur.Client.RproxyC.Mappings = next
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "rproxy client-map-del failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Removed RproxyC mapping :%d\n", ep)
		return 0
	case "client-disable":
		doApply := len(args) > 1 && args[1] == "--apply"
		if err := applyOrSave(store, exec, state.RoleClient, doApply, func(cur *state.State) error {
			cur.Client.RproxyC.Enabled = false
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "rproxy client-disable failed: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown rproxy subcommand %q\n", args[0])
		return 2
	}
}

func buildExtraShareURI(st *state.State, ex state.ExtraInbound) string {
	host := strings.TrimSpace(ex.Domain)
	if host == "" && st != nil {
		host = st.Server.EffectiveConnectHost()
	}
	if host == "" {
		host = "node.example.com"
	}
	return render.BuildNodeURI(state.OutboundNode{
		Name:           ex.Tag,
		Protocol:       ex.Protocol,
		Address:        host,
		Port:           ex.ListenPort,
		UUID:           ex.UUID,
		TLSSNI:         firstNonEmpty(ex.RealitySNI, ex.Domain, host),
		Path:           ex.Path,
		RealityPubKey:  ex.RealityPubKey,
		RealityShortID: ex.RealityShortID,
		Username:       ex.SocksUser,
		Password:       ex.SocksPass,
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func upsertExtraInbound(list []state.ExtraInbound, ex state.ExtraInbound) []state.ExtraInbound {
	for i := range list {
		if list[i].Tag == ex.Tag {
			list[i] = ex
			return list
		}
	}
	return append(list, ex)
}

func cmdExtra(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "list" {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		for _, ex := range st.ExtraInbounds {
			fmt.Fprintf(stdout, "[%s] %-14s :%d via_nginx=%v", ex.Tag, ex.Protocol, ex.ListenPort, ex.ViaNginx)
			if ex.Protocol == "vless-reality" {
				fmt.Fprintf(stdout, " sni=%s pbk=%s sid=%s uuid=%s", ex.RealitySNI, ex.RealityPubKey, ex.RealityShortID, ex.UUID)
			}
			fmt.Fprintln(stdout)
			if uri := buildExtraShareURI(st, ex); uri != "" {
				fmt.Fprintf(stdout, "  URI: %s\n", uri)
			}
		}
		return 0
	}

	defRole := existingRoleOr(store, state.RoleServer)
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "add-reality":
		fs := flag.NewFlagSet("extra add-reality", flag.ContinueOnError)
		fs.SetOutput(stderr)
		port := fs.Int("port", 0, "listen port")
		sni := fs.String("sni", "www.apple.com", "Reality SNI")
		dest := fs.String("dest", "", "Reality dest host:port (defaults to <sni>:443)")
		uuid := fs.String("uuid", "", "UUID (auto-generated if empty)")
		tag := fs.String("tag", "", "inbound tag")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *port <= 0 || *port > 65535 {
			fmt.Fprintln(stderr, "--port must be 1..65535")
			return 2
		}
		priv, pub, err := cryptoext.GenerateRealityKeypair()
		if err != nil {
			fmt.Fprintf(stderr, "generate reality keys: %v\n", err)
			return 1
		}
		sid, err := cryptoext.GenerateHexToken(4)
		if err != nil {
			fmt.Fprintf(stderr, "generate shortId: %v\n", err)
			return 1
		}
		u := strings.TrimSpace(*uuid)
		if u == "" {
			u, _ = cryptoext.GenerateUUID()
		}
		t := strings.TrimSpace(*tag)
		if t == "" {
			t = fmt.Sprintf("inbound-reality-%d", *port)
		}
		d := strings.TrimSpace(*dest)
		if d == "" {
			d = strings.TrimSpace(*sni) + ":443"
		}
		ex := state.ExtraInbound{
			Tag:            t,
			Protocol:       "vless-reality",
			ListenPort:     *port,
			UUID:           u,
			RealitySNI:     strings.TrimSpace(*sni),
			RealityDest:    d,
			RealityPrivKey: priv,
			RealityPubKey:  pub,
			RealityShortID: sid,
		}
		if err := applyOrSave(store, exec, defRole, *doApply, func(cur *state.State) error {
			cur.ExtraInbounds = upsertExtraInbound(cur.ExtraInbounds, ex)
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "extra add-reality failed: %v\n", err)
			return 1
		}
		st, _ := store.Load()
		fmt.Fprintf(stdout, "Added %s (%s :%d)\nUUID: %s\nPBK:  %s\nSID:  %s\nSNI:  %s\nURI:  %s\n",
			ex.Tag, ex.Protocol, ex.ListenPort, ex.UUID, ex.RealityPubKey, ex.RealityShortID, ex.RealitySNI, buildExtraShareURI(st, ex))
		return 0

	case "add-socks5":
		fs := flag.NewFlagSet("extra add-socks5", flag.ContinueOnError)
		fs.SetOutput(stderr)
		port := fs.Int("port", 0, "listen port")
		user := fs.String("user", "", "username")
		pass := fs.String("pass", "", "password")
		tag := fs.String("tag", "", "inbound tag")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *port <= 0 || *port > 65535 {
			fmt.Fprintln(stderr, "--port must be 1..65535")
			return 2
		}
		t := strings.TrimSpace(*tag)
		if t == "" {
			t = fmt.Sprintf("inbound-socks5-%d", *port)
		}
		ex := state.ExtraInbound{
			Tag:        t,
			Protocol:   "socks5",
			ListenPort: *port,
			SocksUser:  *user,
			SocksPass:  *pass,
		}
		if err := applyOrSave(store, exec, defRole, *doApply, func(cur *state.State) error {
			cur.ExtraInbounds = upsertExtraInbound(cur.ExtraInbounds, ex)
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "extra add-socks5 failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Added %s (socks5 :%d)\n", ex.Tag, ex.ListenPort)
		return 0

	case "del":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: dex extra del <tag-or-port> [--apply]")
			return 2
		}
		key := rest[0]
		doApply := len(rest) > 1 && rest[1] == "--apply"
		portNum, _ := strconv.Atoi(key)
		if err := applyOrSave(store, exec, defRole, doApply, func(cur *state.State) error {
			var next []state.ExtraInbound
			found := false
			for _, ex := range cur.ExtraInbounds {
				if ex.Tag == key || (portNum > 0 && ex.ListenPort == portNum) {
					found = true
					continue
				}
				next = append(next, ex)
			}
			if !found {
				return fmt.Errorf("extra inbound %q not found", key)
			}
			cur.ExtraInbounds = next
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "extra del failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Deleted extra inbound %s\n", key)
		return 0

	default:
		fmt.Fprintf(stderr, "unknown extra subcommand %q\n", sub)
		return 2
	}
}

func cmdMigrate(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	return runMigrateWithExec(store, exec, "/opt/de_GWD/nftables", reconcile.ApplyOptions{}, args, stdout, stderr)
}

func runMigrateWithExec(store *state.Store, exec reconcile.SystemExecutor, v2NFTDir string, baseOpts reconcile.ApplyOptions, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "/opt/de_GWD/0conf", "source file or root path")
	kind := fs.String("kind", "v2_client", "v2_client|v2_server|des|dexs")
	doApply := fs.Bool("apply", false, "apply immediately after migration")
	cleanupV2 := fs.Bool("cleanup-v2", false, "stop legacy v2 services, pihole container, and v2 nft tables (requires --apply)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *cleanupV2 && !*doApply {
		fmt.Fprintln(stderr, "migrate failed: --cleanup-v2 requires --apply")
		return 2
	}

	var imported *state.State
	var notes []string
	var err error
	switch *kind {
	case "v2_client":
		imported, notes, err = migrate.ImportV2Client(*from, filepath.Dir(*from))
	case "v2_server":
		imported, notes, err = migrate.ImportV2Server(*from)
	case "des":
		imported, notes, err = migrate.ImportDES(*from)
	case "dexs":
		imported, notes, err = migrate.ImportDEXS(*from)
	default:
		fmt.Fprintf(stderr, "unknown migrate kind %q\n", *kind)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "migrate failed: %v\n", err)
		return 1
	}

	if imported.Auth.PasswordHash == "" {
		if cur, cerr := store.Load(); cerr == nil && cur.Auth.PasswordHash != "" {
			imported.Auth.PasswordHash = cur.Auth.PasswordHash
		} else {
			pw, _ := cryptoext.GenerateInitialPassword()
			imported.Auth.PasswordHash, _ = cryptoext.HashPassword(pw)
			fmt.Fprintf(stdout, "Generated initial Web password: %s\n", pw)
		}
	}

	if err := store.Save(imported); err != nil {
		fmt.Fprintf(stderr, "save migrated state: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Migrated %s -> %s (role=%s)\n", *kind, store.StatePath(), imported.Role)
	for _, n := range notes {
		fmt.Fprintf(stdout, "  * %s\n", n)
	}
	ctx := context.Background()
	if *cleanupV2 {
		dryOpts := baseOpts
		dryOpts.DryRun = true
		if _, err := reconcile.Reconcile(ctx, store, exec, dryOpts); err != nil {
			fmt.Fprintf(stderr, "migrate dry-run validation failed (legacy v2 untouched): %v\n", err)
			return 1
		}
		snap := cleanupLegacyV2WithNFTDir(ctx, exec, v2NFTDir, stdout)
		if _, err := reconcile.Reconcile(ctx, store, exec, baseOpts); err != nil {
			snap.restore(ctx, exec, stderr)
			fmt.Fprintf(stderr, "apply failed after v2 cleanup (legacy v2 restored): %v\n", err)
			return 1
		}
		return 0
	}
	if *doApply {
		if _, err := reconcile.Reconcile(ctx, store, exec, baseOpts); err != nil {
			fmt.Fprintf(stderr, "apply failed: %v\n", err)
			return 1
		}
	}
	return 0
}

func cmdDaemon(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDirFlag := fs.String("state-dir", "", "override state directory")
	listen := fs.String("listen", "", "override Web UI listen address")
	httpOnly := fs.Bool("http", false, "serve plain HTTP (e.g. behind local proxy)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*stateDirFlag) != "" {
		store = state.NewStore(strings.TrimSpace(*stateDirFlag))
	}

	st, err := store.Load()
	if err != nil {
		fmt.Fprintf(stderr, "load state: %v\n", err)
		return 1
	}
	addr := st.Auth.ListenAddr
	if *listen != "" {
		addr = *listen
	}
	if addr == "" {
		addr = ":8443"
	}

	hub := daemon.NewTaskHub(300)
	runner := daemon.NewRunner(store, exec, hub)
	webSrv := web.NewServer(store, exec, hub, runner.DDNS, reconcile.ApplyOptions{})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go runner.RunLoops(ctx)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           webSrv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if *httpOnly {
			fmt.Fprintf(stdout, "dex daemon listening HTTP on %s\n", addr)
			errCh <- httpSrv.ListenAndServe()
			return
		}
		cer := store.DefaultCert()
		key := store.DefaultKey()
		if st.Cert.Mode == "imported" && st.Cert.CertFile != "" && st.Cert.KeyFile != "" {
			cer = st.Cert.CertFile
			key = st.Cert.KeyFile
		}
		if err := cert.EnsureSelfSigned(cer, key, st.Auth.ServerName); err != nil {
			errCh <- err
			return
		}
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		fmt.Fprintf(stdout, "dex daemon listening HTTPS on %s\n", addr)
		errCh <- httpSrv.ListenAndServeTLS(cer, key)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		return 0
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "daemon error: %v\n", err)
			return 1
		}
		return 0
	}
}

func cmdServeDoH(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve-doh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:9853", "listen addr")
	upstream := fs.String("upstream", "1.1.1.1:53,8.8.8.8:53,127.0.0.53:53,127.0.0.1:53", "comma-separated DNS upstreams")
	path := fs.String("path", "/dq", "HTTP DoH path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var ups []string
	for _, u := range strings.Split(*upstream, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			ups = append(ups, u)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stdout, "dex serve-doh listening on %s%s -> %v\n", *listen, *path, ups)
	if err := doh.ListenAndServe(ctx, doh.Config{
		ListenAddr: *listen,
		Path:       *path,
		Upstreams:  ups,
	}); err != nil {
		fmt.Fprintf(stderr, "serve-doh error: %v\n", err)
		return 1
	}
	return 0
}

func applyOrSave(store *state.Store, exec reconcile.SystemExecutor, defRole string, doApply bool, mut func(*state.State) error) error {
	if doApply {
		_, _, err := reconcile.UpdateAndReconcile(context.Background(), store, defRole, exec, reconcile.ApplyOptions{}, mut)
		return err
	}
	_, err := store.Update(defRole, mut)
	return err
}

func firstOrEmpty(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}
