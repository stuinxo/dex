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
	osexec "os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/daemon"
	"github.com/stuinxo/dex/internal/doh"
	"github.com/stuinxo/dex/internal/fsutil"
	"github.com/stuinxo/dex/internal/migrate"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/socks5out"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/version"
	"github.com/stuinxo/dex/internal/web"
)

// Run is the main CLI entrypoint invoked by cmd/dex/main.go and tests.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return RunWithExecutor(args, reconcile.OSExecutor{}, stdin, stdout, stderr)
}

// RunWithExecutor executes the CLI with a caller-provided SystemExecutor (primarily for tests).
func RunWithExecutor(args []string, exec reconcile.SystemExecutor, stdin io.Reader, stdout, stderr io.Writer) int {
	if exec == nil {
		exec = reconcile.OSExecutor{}
	}
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
	case "-c", "--client":
		return dispatchRoleFlag(store, exec, state.RoleClient, rest, stdin, stdout, stderr)
	case "-s", "--server":
		return dispatchRoleFlag(store, exec, state.RoleServer, rest, stdin, stdout, stderr)
	case "-r", "--relay":
		return dispatchRoleFlag(store, exec, state.RoleRelay, rest, stdin, stdout, stderr)
	case "-l", "--landing":
		return dispatchRoleFlag(store, exec, state.RoleLanding, rest, stdin, stdout, stderr)
	case "init":
		return cmdInit(store, exec, rest, stdout, stderr)
	case "apply":
		return cmdApply(store, exec, rest, stdout, stderr)
	case "refresh":
		return cmdApply(store, exec, rest, stdout, stderr)
	case "status":
		return cmdStatus(store, exec, stdout, stderr)
	case "server":
		return cmdServer(store, exec, rest, stdout, stderr)
	case "dns":
		return cmdDNS(store, exec, rest, stdout, stderr)
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
	case "kernel":
		return cmdKernel(store, exec, rest, stdout, stderr)
	case "migrate":
		return cmdMigrate(store, exec, rest, stdout, stderr)
	case "daemon":
		return cmdDaemon(store, exec, rest, stdout, stderr)
	case "serve-doh":
		return cmdServeDoH(rest, stdout, stderr)
	default:
		if isShareNodeURI(sub) {
			return dispatchRoleFlag(store, exec, state.RoleClient, args, stdin, stdout, stderr)
		}
		fmt.Fprintf(stderr, "unknown command %q\n\n", sub)
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `DEX — Unified Bypass Gateway & Node Controller

Usage:
  dex [--state-dir DIR] [command] [flags]
  dex 'vless://...'
  dex [-c|-s|-r|-l] [flags]

Role Shortcuts:
  'vless://...'         Initialize & apply client role directly from Server share URI (auto-derives /dq DoH)
  -c, --client          Initialize & apply client role (wizard if no args, e.g. dex -c 'vless://...')
  -s, --server          Initialize & apply server role (wizard if no args, e.g. dex -s srv.example.com)
  -r, --relay           Initialize & apply relay role (wizard if no args, or pass --no-apply to skip apply)
  -l, --landing         Initialize & apply landing role (wizard if no args, e.g. dex -l land.example.com)

Commands:
  menu                  Open interactive numbered menu (default when no args)
  init                  Initialize a new client / server / landing / relay state
  apply                 Validate, render, pre-flight check, and reconcile configs
  status                Show role, active node, certificate, and service health
  server <subcmd>       Inspect or update server/landing configuration (show|set)
  dns <subcmd>          Inspect or update client DNS & DoH server (show|set)
  node <subcmd>         Manage client outbound nodes (list|add|edit|move|del|select|probe|show)
  cert <subcmd>         Manage TLS certificates (self-sign|import|issue|inspect|reload)
  wg <subcmd>           Manage WireGuard VPN (enable|disable|keygen-server|peer-add|peer-regen|peer-del|show)
  ddns <subcmd>         Manage Cloudflare DDNS (set|sync|disable)
  socks5 <subcmd>       Manage server Option 35 SOCKS5 exits (list|add|del|toggle|test)
  relay <subcmd>        Manage Option 44 port forwards (list|add|del)
  rproxy <subcmd>       Manage RproxyS/RproxyC reverse proxy (show|set|map-add|map-del|disable|client-*)
  extra <subcmd>        Manage Option 55 extra inbounds (list|add-reality|add-xhttp|add-vless-ws|add-vmess-ws|add-dokodemo|add-socks5|del|disable-all)
  rules <subcmd>        Inspect or hot-update GeoIP/Domain rule files (status|update)
  update                Upgrade dex, xray, mosdns, and/or rule datasets cleanly
  kernel <subcmd>       Inspect kernel or install Zabbly mainline kernel (status|zabbly)
  migrate               Import v2 0conf, v2 server, des, or dexs state (--cleanup-v2 --apply)
  daemon                Run embedded Web UI (client :443 + :80->HTTPS redirect; server 127.0.0.1:8443) + failover + DDNS loops
  serve-doh             Run standalone RFC 8484 DoH forwarding server
  refresh               Re-resolve dynamic relay targets and re-apply nftables
  version               Print dex version
`)
}

func isIPv6OnlyHost() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	hasGlobalV6 := false
	hasNonLoopbackV4 := false
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			if ip.To4() != nil {
				hasNonLoopbackV4 = true
			} else if ip.IsGlobalUnicast() {
				hasGlobalV6 = true
			}
		}
	}
	return hasGlobalV6 && !hasNonLoopbackV4
}

func shouldAutoApplyInit(exec reconcile.SystemExecutor, defaultApply, applyExplicit, applyVal, noApplyVal bool) bool {
	if noApplyVal {
		return false
	}
	if applyExplicit {
		return applyVal
	}
	if defaultApply {
		_, isOS := exec.(reconcile.OSExecutor)
		return isOS
	}
	return false
}

func dispatchRoleFlag(store *state.Store, exec reconcile.SystemExecutor, role string, rest []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(rest) == 0 {
		return runRoleInitWizard(store, exec, role, stdin, stdout, stderr)
	}
	return cmdInitWithDefaultApply(store, exec, append([]string{"--role", role}, rest...), true, stdout, stderr)
}

func reorderInitArgs(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		if strings.Contains(a, "=") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		switch name {
		case "role", "domain", "connect-host", "port", "public-port", "tls-mode", "password", "uuid", "doh", "node":
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return append(flags, pos...)
}

func isShareNodeURI(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(s, "vless://") || strings.HasPrefix(s, "vmess://") || strings.HasPrefix(s, "socks5://")
}

func parseNodeURIList(raw string) ([]state.OutboundNode, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})
	var nodes []state.OutboundNode
	for i, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := render.ParseNodeURI(f)
		if err != nil {
			return nil, fmt.Errorf("invalid node URI %q: %w", f, err)
		}
		if n.ID == "" {
			n.ID = fmt.Sprintf("node-%d", i+1)
		}
		if n.Name == "" {
			n.Name = n.Address
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		return nil, errors.New("at least one valid node URI (vless:// or vmess://) is required")
	}
	return nodes, nil
}

func printServerClientBootstrapInfo(w io.Writer, store *state.Store, st *state.State) {
	if st == nil || (st.Role != state.RoleServer && st.Role != state.RoleLanding) {
		return
	}
	hostname, _ := os.Hostname()
	mainURI := render.BuildServerMainURI(st)
	dohURL := render.BuildDoHURL(st, hostname)
	installCmd := render.BuildClientBootstrapCommand(st, hostname)
	initCmd := render.BuildClientInitCommand(st, hostname)

	fmt.Fprintln(w, "\n── Client 对接必要信息 ──────────────────────────────────────")
	fmt.Fprintf(w, "Main Node URI:  %s\n", mainURI)
	if dohURL != "" {
		fmt.Fprintf(w, "DoH URL:        %s\n", dohURL)
	} else {
		fmt.Fprintln(w, "DoH URL:        (本角色未启用 DoH，Client 需另填其它 Server 的自建 DoH)")
	}
	if installCmd != "" {
		fmt.Fprintf(w, "Client Install: %s   (运行后粘贴上方 Main Node URI 即可)\n", installCmd)
	}
	if initCmd != "" {
		fmt.Fprintf(w, "Client Quick:   %s\n", initCmd)
	}
	if store != nil {
		certFile, keyFile := resolveActiveCertPaths(store, st)
		if cb, err1 := os.ReadFile(certFile); err1 == nil {
			if kb, err2 := os.ReadFile(keyFile); err2 == nil {
				if rep, ierr := cert.InspectPair(cb, kb); ierr == nil && rep.SelfSigned {
					fmt.Fprintln(w, "[!] 证书提示: 当前仍为自签证书；Client 的 Xray 与 DoH 均强制校验 CA 证书，请先执行 'dex cert issue ...' (或菜单 3 -> 2) 签发/导入正式证书。")
				}
			}
		}
	}
	fmt.Fprintln(w, "─────────────────────────────────────────────────────────────")
}

func cmdInit(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	return cmdInitWithDefaultApply(store, exec, args, false, stdout, stderr)
}

func cmdInitWithDefaultApply(store *state.Store, exec reconcile.SystemExecutor, args []string, defaultApply bool, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	role := fs.String("role", state.RoleClient, "role: client|server|landing|relay")
	shortClient := fs.Bool("c", false, "shorthand for --role client")
	shortServer := fs.Bool("s", false, "shorthand for --role server")
	shortRelay := fs.Bool("r", false, "shorthand for --role relay")
	shortLanding := fs.Bool("l", false, "shorthand for --role landing")
	domain := fs.String("domain", "", "domain name")
	connectHost := fs.String("connect-host", "", "external host/IP for clients")
	port := fs.Int("port", 0, "listen port")
	pubPort := fs.Int("public-port", 0, "NAT public port")
	tlsMode := fs.String("tls-mode", "", "server tls_mode: nginx|direct")
	pw := fs.String("password", "", "web UI password (random 16-char if omitted)")
	uuid := fs.String("uuid", "", "primary UUID (auto-generated if omitted)")
	nodeURIs := fs.String("node", "", "initial Server node URI(s) (vless:// or vmess://), comma-separated (client role)")
	doh := fs.String("doh", "", "custom DoH URL(s), comma-separated (client role)")
	enableIPv6 := fs.Bool("ipv6", false, "enable IPv6 dual-stack inbound/forwarding")
	doApply := fs.Bool("apply", false, "apply configuration immediately (default true when invoked via -c/-s/-r/-l)")
	noApply := fs.Bool("no-apply", false, "only write state without applying configuration")
	force := fs.Bool("force", false, "overwrite existing state file")
	if err := fs.Parse(reorderInitArgs(args)); err != nil {
		return 2
	}

	ipv6Explicit := false
	roleExplicit := false
	applyExplicit := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "ipv6":
			ipv6Explicit = true
		case "role":
			roleExplicit = true
		case "apply":
			applyExplicit = true
		}
	})
	effectiveApply := shouldAutoApplyInit(exec, defaultApply, applyExplicit, *doApply, *noApply)

	shortCount := 0
	shortRole := ""
	if *shortClient {
		shortCount++
		shortRole = state.RoleClient
	}
	if *shortServer {
		shortCount++
		shortRole = state.RoleServer
	}
	if *shortRelay {
		shortCount++
		shortRole = state.RoleRelay
	}
	if *shortLanding {
		shortCount++
		shortRole = state.RoleLanding
	}
	if shortCount > 1 {
		fmt.Fprintln(stderr, "cannot combine multiple role flags (-c, -s, -r, -l)")
		return 2
	}
	if shortRole != "" {
		if roleExplicit && *role != shortRole {
			fmt.Fprintf(stderr, "conflicting --role %q and shorthand role %q\n", *role, shortRole)
			return 2
		}
		*role = shortRole
	}

	if fs.NArg() > 0 {
		switch {
		case *role == state.RoleClient:
			var posNodes, posDoHs []string
			for _, a := range fs.Args() {
				if isShareNodeURI(a) {
					posNodes = append(posNodes, a)
				} else {
					posDoHs = append(posDoHs, a)
				}
			}
			if len(posNodes) > 0 {
				if strings.TrimSpace(*nodeURIs) != "" {
					fmt.Fprintf(stderr, "unexpected argument(s): %s\n", strings.Join(posNodes, " "))
					return 2
				}
				*nodeURIs = strings.Join(posNodes, ",")
			}
			if len(posDoHs) > 0 {
				if strings.TrimSpace(*doh) != "" {
					fmt.Fprintf(stderr, "unexpected argument(s): %s\n", strings.Join(posDoHs, " "))
					return 2
				}
				*doh = strings.Join(posDoHs, ",")
			}
		case (*role == state.RoleServer || *role == state.RoleLanding) && strings.TrimSpace(*domain) == "" && fs.NArg() == 1:
			*domain = fs.Arg(0)
		default:
			fmt.Fprintf(stderr, "unexpected argument(s): %s\n", strings.Join(fs.Args(), " "))
			return 2
		}
	}

	if _, err := os.Stat(store.StatePath()); err == nil && !*force {
		fmt.Fprintf(stderr, "state file already exists at %s; use 'dex apply' to apply configuration or pass '--force' to overwrite\n", store.StatePath())
		return 1
	}

	st := state.NewDefaultState(*role)
	autoDetectedIPv6Only := false
	if ipv6Explicit {
		st.System.EnableIPv6 = *enableIPv6
	} else {
		if _, isOS := exec.(reconcile.OSExecutor); isOS && isIPv6OnlyHost() {
			st.System.EnableIPv6 = true
			autoDetectedIPv6Only = true
		}
	}
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
		if strings.TrimSpace(*nodeURIs) != "" {
			nodes, nerr := parseNodeURIList(*nodeURIs)
			if nerr != nil {
				fmt.Fprintf(stderr, "invalid --node: %v\n", nerr)
				return 1
			}
			st.Client.Nodes = nodes
			st.Client.ActiveNodeID = nodes[0].ID
			if strings.TrimSpace(*doh) == "" {
				var derived []string
				seen := make(map[string]struct{})
				for _, n := range nodes {
					if d := render.DeriveServerDoHFromNode(n); d != "" {
						if _, dup := seen[d]; !dup {
							seen[d] = struct{}{}
							derived = append(derived, d)
						}
					}
				}
				if len(derived) > 0 {
					st.Client.DNS.DoHServers = derived
				}
			}
		}
		if strings.TrimSpace(*doh) != "" {
			list, perr := parseAndNormalizeDoHList(*doh)
			if perr != nil {
				fmt.Fprintf(stderr, "invalid --doh: %v\n", perr)
				return 1
			}
			st.Client.DNS.DoHServers = list
		}
	}

	certCN := st.Auth.ServerName
	if (st.Role == state.RoleServer || st.Role == state.RoleLanding) && strings.TrimSpace(st.Server.Domain) != "" {
		certCN = strings.TrimSpace(st.Server.Domain)
	}
	if err := cert.EnsureSelfSigned(store.DefaultCert(), store.DefaultKey(), certCN); err != nil {
		fmt.Fprintf(stderr, "ensure cert: %v\n", err)
		return 1
	}
	if err := store.Save(st); err != nil {
		fmt.Fprintf(stderr, "save state: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Initialized %s state at %s\n", st.Role, store.StatePath())
	if autoDetectedIPv6Only {
		fmt.Fprintln(stdout, "Detected IPv6-only host: enabled system.enable_ipv6=true")
	}
	if *pw == "" {
		fmt.Fprintf(stdout, "Initial Web Password: %s\n", rawPW)
	}
	if st.Role == state.RoleClient {
		if active := st.Client.ActiveNode(); active != nil {
			fmt.Fprintf(stdout, "Active Node: %s (%s:%d)\n", active.ID, active.Address, active.Port)
		}
		fmt.Fprintf(stdout, "Upstream DoH: %s\n", strings.Join(st.Client.DNS.DoHServers, ", "))
	}

	if effectiveApply {
		if _, isOS := exec.(reconcile.OSExecutor); isOS {
			if err := bootstrapRoleRuntimeDeps(context.Background(), store, exec, st.Role, OpsConfig{}, stdout); err != nil {
				fmt.Fprintf(stderr, "bootstrap runtime dependencies failed: %v\n", err)
				return 1
			}
		}
		if _, err := reconcile.Reconcile(context.Background(), store, exec, reconcile.ApplyOptions{}); err != nil {
			fmt.Fprintf(stderr, "apply failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Configuration reconciled successfully.")
	}
	if st.Role == state.RoleServer || st.Role == state.RoleLanding {
		printServerClientBootstrapInfo(stdout, store, st)
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

func serviceNamesForState(st *state.State, initSys string) []string {
	return render.ComputeServicePlan(st).ManagedServiceUnits(st, initSys)
}

func serviceStatusSummary(exec reconcile.SystemExecutor, st *state.State) string {
	if exec == nil || st == nil {
		return ""
	}
	initSys := exec.DetectInitSystem()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var parts []string
	for _, svc := range serviceNamesForState(st, initSys) {
		stateLabel := "inactive"
		if exec.ServiceIsActive(ctx, initSys, svc) {
			stateLabel = "active"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", svc, stateLabel))
	}
	return strings.Join(parts, " ")
}

func resolveActiveCertPaths(store *state.Store, st *state.State) (string, string) {
	if st != nil && st.Cert.Mode == "imported" && st.Cert.CertFile != "" && st.Cert.KeyFile != "" {
		return st.Cert.CertFile, st.Cert.KeyFile
	}
	return store.DefaultCert(), store.DefaultKey()
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
	if netOpt := reconcile.ReadKernelNetOpt(); netOpt != "" {
		fmt.Fprintf(stdout, "Net Opt: %s | Sysctl: %v | Flowtable: %v\n",
			netOpt, st.System.AutoTuneSysctl, st.System.EnableFlowtable)
	} else {
		fmt.Fprintf(stdout, "Sysctl: %v | Flowtable: %v\n",
			st.System.AutoTuneSysctl, st.System.EnableFlowtable)
	}
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
		fmt.Fprintf(stdout, "Domain: %s | Mode: %s | Protocol: %s | Port: %d (pub %d)\n",
			st.Server.Domain, st.Server.TLSMode, st.Server.EffectiveProtocol(), st.Server.ListenPort, st.Server.EffectivePublicPort())
	}
	hostname, _ := os.Hostname()
	if dohURL := render.BuildDoHURL(st, hostname); dohURL != "" {
		fmt.Fprintf(stdout, "DoH URL: %s\n", dohURL)
	}
	fmt.Fprintf(stdout, "Relay Forwards: %d | RproxyS: %v | Extra Inbounds: %d\n",
		len(st.Relay.Forwards), st.RproxyS.Enabled, len(st.ExtraInbounds))
	if sum := serviceStatusSummary(exec, st); sum != "" {
		fmt.Fprintf(stdout, "Services: %s\n", sum)
	}
	certFile, keyFile := resolveActiveCertPaths(store, st)
	if cb, err1 := os.ReadFile(certFile); err1 == nil {
		if kb, err2 := os.ReadFile(keyFile); err2 == nil {
			if rep, ierr := cert.InspectPair(cb, kb); ierr == nil {
				fmt.Fprintf(stdout, "Certificate: CN=%s Expires=%s SelfSigned=%v ChainValid=%v ExpiringSoon=%v\n",
					rep.CommonName, rep.NotAfter.Format("2006-01-02"), rep.SelfSigned, rep.ChainValid, rep.ExpiringSoon)
			} else {
				fmt.Fprintf(stdout, "Certificate: invalid (%v)\n", ierr)
			}
		} else {
			fmt.Fprintf(stdout, "Certificate: key unreadable (%v)\n", err2)
		}
	} else {
		fmt.Fprintf(stdout, "Certificate: missing (%s)\n", certFile)
	}
	return 0
}

func cmdServer(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "show" {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Role:             %s\n", st.Role)
		fmt.Fprintf(stdout, "Domain:           %s\n", st.Server.Domain)
		fmt.Fprintf(stdout, "ConnectHost:      %s\n", st.Server.EffectiveConnectHost())
		fmt.Fprintf(stdout, "TLSMode:          %s\n", st.Server.TLSMode)
		fmt.Fprintf(stdout, "Protocol:         %s\n", st.Server.EffectiveProtocol())
		fmt.Fprintf(stdout, "ListenPort:       %d\n", st.Server.ListenPort)
		fmt.Fprintf(stdout, "PublicPort:       %d\n", st.Server.EffectivePublicPort())
		fmt.Fprintf(stdout, "Path:             %s\n", render.NormalizePath(st.Server.Path, firstOrEmpty(st.Server.UUIDs)))
		fmt.Fprintf(stdout, "UUIDs:            %s\n", strings.Join(st.Server.UUIDs, ", "))
		fmt.Fprintf(stdout, "EnableDoH:        %v\n", st.Server.EnableDoH)
		if st.Server.CamouflageDir != "" {
			fmt.Fprintf(stdout, "CamouflageDir:    %s\n", st.Server.CamouflageDir)
		}
		hostname, _ := os.Hostname()
		if uri := render.BuildServerMainURI(st); uri != "" {
			fmt.Fprintf(stdout, "MainURI:          %s\n", uri)
		}
		if dohURL := render.BuildDoHURL(st, hostname); dohURL != "" {
			fmt.Fprintf(stdout, "DoHURL:           %s\n", dohURL)
		}
		if cmd := render.BuildClientBootstrapCommand(st, hostname); cmd != "" {
			fmt.Fprintf(stdout, "ClientInstall:    %s\n", cmd)
		}
		return 0
	}

	sub := args[0]
	rest := args[1:]
	if sub != "set" {
		fmt.Fprintf(stderr, "unknown server subcommand %q (expected show|set)\n", sub)
		return 2
	}

	fs := flag.NewFlagSet("server set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	domain := fs.String("domain", "", "server domain")
	connectHost := fs.String("connect-host", "", "external host/IP for clients")
	tlsMode := fs.String("tls-mode", "", "tls mode: nginx|direct")
	proto := fs.String("protocol", "", "main inbound protocol: vless-xhttp|vmess-ws|vless-ws")
	port := fs.Int("port", 0, "listen port")
	pubPort := fs.Int("public-port", 0, "NAT public port")
	path := fs.String("path", "", "WS/XHTTP path")
	uuidVal := fs.String("uuid", "", "replace UUID list (comma-separated)")
	addUUID := fs.String("add-uuid", "", "append UUID")
	delUUID := fs.String("del-uuid", "", "remove UUID")
	enableDoH := fs.Bool("enable-doh", false, "enable server RFC 8484 DoH endpoint")
	camoDir := fs.String("camouflage-dir", "", "nginx camouflage root directory")
	doApply := fs.Bool("apply", false, "apply immediately")
	if err := fs.Parse(rest); err != nil {
		return 2
	}

	setFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	defRole := existingRoleOr(store, state.RoleServer)
	mut := func(cur *state.State) error {
		if setFlags["domain"] {
			cur.Server.Domain = strings.TrimSpace(*domain)
		}
		if setFlags["connect-host"] {
			cur.Server.ConnectHost = strings.TrimSpace(*connectHost)
		}
		if setFlags["tls-mode"] {
			cur.Server.TLSMode = strings.TrimSpace(*tlsMode)
		}
		if setFlags["protocol"] {
			cur.Server.Protocol = strings.TrimSpace(*proto)
		}
		if setFlags["port"] {
			cur.Server.ListenPort = *port
		}
		if setFlags["public-port"] {
			cur.Server.PublicPort = *pubPort
		}
		if setFlags["path"] {
			cur.Server.Path = strings.TrimSpace(*path)
		}
		if setFlags["uuid"] {
			var next []string
			for _, u := range strings.Split(*uuidVal, ",") {
				if u = strings.TrimSpace(u); u != "" {
					next = append(next, u)
				}
			}
			cur.Server.UUIDs = next
		}
		if setFlags["add-uuid"] {
			u := strings.TrimSpace(*addUUID)
			if u == "" {
				var err error
				u, err = cryptoext.GenerateUUID()
				if err != nil {
					return err
				}
			}
			exists := false
			for _, ex := range cur.Server.UUIDs {
				if ex == u {
					exists = true
					break
				}
			}
			if !exists {
				cur.Server.UUIDs = append(cur.Server.UUIDs, u)
			}
		}
		if setFlags["del-uuid"] {
			target := strings.TrimSpace(*delUUID)
			var next []string
			for _, ex := range cur.Server.UUIDs {
				if ex != target {
					next = append(next, ex)
				}
			}
			cur.Server.UUIDs = next
		}
		if setFlags["enable-doh"] {
			if *enableDoH && cur.Role != state.RoleServer {
				return fmt.Errorf("DoH server is only supported on server and client roles (current role=%s)", cur.Role)
			}
			cur.Server.EnableDoH = *enableDoH
		}
		if setFlags["camouflage-dir"] {
			cur.Server.CamouflageDir = strings.TrimSpace(*camoDir)
		}
		return nil
	}
	if err := applyOrSave(store, exec, defRole, *doApply, mut); err != nil {
		fmt.Fprintf(stderr, "server set failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "Server configuration updated.")
	return 0
}

func parseAndNormalizeDoHList(raw string) ([]string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	seen := make(map[string]struct{}, len(fields))
	var out []string
	for _, f := range fields {
		norm := render.NormalizeDoHUpstream(f)
		if norm == "" {
			continue
		}
		host := render.ExtractDoHHost(norm)
		if host == "" || !state.IsValidAddress(host) {
			return nil, fmt.Errorf("invalid DoH server %q", f)
		}
		if _, dup := seen[norm]; !dup {
			seen[norm] = struct{}{}
			out = append(out, norm)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one DoH server is required")
	}
	return out, nil
}

func cmdDNS(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "show" {
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		hostname, _ := os.Hostname()
		fmt.Fprintf(stdout, "Role:             %s\n", st.Role)
		fmt.Fprintf(stdout, "EnableDoHServer:  %v\n", st.Client.DNS.EnableDoHServer)
		fmt.Fprintf(stdout, "DoHServerPath:    %s\n", st.Client.DNS.EffectiveDoHPath())
		if u := render.BuildDoHURL(st, hostname); u != "" {
			fmt.Fprintf(stdout, "DoHServerURL:     %s\n", u)
		}
		fmt.Fprintf(stdout, "BlockAds:         %v\n", st.Client.DNS.BlockAds)
		fmt.Fprintf(stdout, "BlockExternal53:  %v\n", st.Client.DNS.BlockExternal53)
		fmt.Fprintf(stdout, "ChinaServers:     %s\n", strings.Join(st.Client.DNS.ChinaServers, ", "))
		fmt.Fprintf(stdout, "DoHUpstreams:     %s\n", strings.Join(st.Client.DNS.DoHServers, ", "))
		return 0
	}

	sub := args[0]
	rest := args[1:]
	if sub != "set" {
		fmt.Fprintf(stderr, "unknown dns subcommand %q (expected show|set)\n", sub)
		return 2
	}

	fs := flag.NewFlagSet("dns set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	enableDoHSrv := fs.Bool("enable-doh-server", false, "enable client RFC 8484 DoH endpoint")
	dohPath := fs.String("doh-path", "", "client DoH HTTP path (e.g. /dq-xxxxxx or /dq)")
	regenDoHPath := fs.Bool("regen-doh-path", false, "regenerate random /dq-xxxxxx path")
	dohUpstreams := fs.String("doh", "", "upstream self-hosted DoH server(s), comma-separated")
	blockAds := fs.Bool("block-ads", false, "enable MosDNS ad-blocking")
	block53 := fs.Bool("block-53", false, "block external inbound port 53")
	doApply := fs.Bool("apply", false, "apply immediately")
	if err := fs.Parse(rest); err != nil {
		return 2
	}

	setFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	defRole := existingRoleOr(store, state.RoleClient)
	mut := func(cur *state.State) error {
		if cur.Role != state.RoleClient {
			return fmt.Errorf("dns command requires client role (current role=%s)", cur.Role)
		}
		if setFlags["enable-doh-server"] {
			cur.Client.DNS.EnableDoHServer = *enableDoHSrv
			if *enableDoHSrv && strings.TrimSpace(cur.Client.DNS.DoHServerPath) == "" {
				cur.Client.DNS.DoHServerPath = state.GenerateDefaultClientDoHPath()
			}
		}
		if setFlags["doh-path"] {
			p := strings.TrimSpace(*dohPath)
			if p != "" && !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			cur.Client.DNS.DoHServerPath = p
		}
		if *regenDoHPath {
			cur.Client.DNS.DoHServerPath = state.GenerateDefaultClientDoHPath()
		}
		if setFlags["doh"] {
			list, perr := parseAndNormalizeDoHList(*dohUpstreams)
			if perr != nil {
				return perr
			}
			cur.Client.DNS.DoHServers = list
		}
		if setFlags["block-ads"] {
			cur.Client.DNS.BlockAds = *blockAds
		}
		if setFlags["block-53"] {
			cur.Client.DNS.BlockExternal53 = *block53
		}
		return nil
	}
	if err := applyOrSave(store, exec, defRole, *doApply, mut); err != nil {
		fmt.Fprintf(stderr, "dns set failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "Client DNS configuration updated.")
	return 0
}

func maybePrintQR(stdout io.Writer, uri string, force bool) {
	if uri == "" {
		return
	}
	if !force {
		f, ok := stdout.(*os.File)
		if !ok {
			return
		}
		fi, err := f.Stat()
		if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
			return
		}
	}
	bin, err := osexec.LookPath("qrencode")
	if err != nil {
		return
	}
	cmd := osexec.Command(bin, "-t", "ANSIUTF8", uri)
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		fmt.Fprintln(stdout)
		_, _ = stdout.Write(out)
	}
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
		fs := flag.NewFlagSet("node show", flag.ContinueOnError)
		fs.SetOutput(stderr)
		qrFlag := fs.Bool("qr", false, "render terminal QR code via qrencode if available")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		if st.Role == state.RoleServer || st.Role == state.RoleLanding {
			mainURI := render.BuildServerMainURI(st)
			fmt.Fprintf(stdout, "Domain:   %s\nAddress:  %s:%d\nMode:     %s (%s)\nUUIDs:    %s\nPath:     %s\nURI:      %s\n",
				st.Server.Domain, st.Server.EffectiveConnectHost(), st.Server.EffectivePublicPort(),
				st.Server.TLSMode, st.Server.EffectiveProtocol(),
				strings.Join(st.Server.UUIDs, ", "),
				render.NormalizePath(st.Server.Path, firstOrEmpty(st.Server.UUIDs)),
				mainURI)
			if u := render.BuildDoHURL(st, "localhost"); u != "" {
				fmt.Fprintf(stdout, "DoH URL:  %s\n", u)
			}
			if cmd := render.BuildClientBootstrapCommand(st, "localhost"); cmd != "" {
				fmt.Fprintf(stdout, "Client Install:\n  %s\n", cmd)
			}
			for _, ex := range st.ExtraInbounds {
				if uri := render.BuildExtraURI(st, ex); uri != "" {
					fmt.Fprintf(stdout, "Extra [%s] (%s:%d): %s\n", ex.Tag, ex.Protocol, ex.ListenPort, uri)
				} else if ex.Protocol == "dokodemo" {
					fmt.Fprintf(stdout, "Extra [%s] (dokodemo :%d -> %s:%d)\n", ex.Tag, ex.ListenPort, ex.TargetAddr, ex.TargetPort)
				}
			}
			for _, rf := range st.Relay.Forwards {
				fmt.Fprintf(stdout, "Relay [%s] :%d -> %s:%d (%s/%s)\n", rf.ID, rf.ListenPort, rf.TargetHost, rf.TargetPort, rf.Proto, rf.Engine)
			}
			maybePrintQR(stdout, mainURI, *qrFlag)
			return 0
		}
		var target *state.OutboundNode
		if fs.NArg() > 0 {
			target = st.Client.FindNode(fs.Arg(0))
		} else {
			target = st.Client.ActiveNode()
		}
		if target == nil {
			fmt.Fprintln(stderr, "no matching node found")
			return 1
		}
		uri := render.BuildNodeURI(*target)
		fmt.Fprintf(stdout, "ID:       %s\nName:     %s\nProtocol: %s\nAddress:  %s:%d\nSNI:      %s\nURI:      %s\n",
			target.ID, target.Name, target.Protocol, target.Address, target.Port,
			target.EffectiveSNI(), uri)
		if len(st.Client.DNS.DoHServers) > 0 {
			fmt.Fprintf(stdout, "DoH:      %s\n", strings.Join(st.Client.DNS.DoHServers, ", "))
		}
		if u := render.BuildDoHURL(st, "localhost"); u != "" {
			fmt.Fprintf(stdout, "DoH URL:  %s\n", u)
		}
		if u0 := render.BuildFWDURI(st, "fwd0", ""); u0 != "" {
			fmt.Fprintf(stdout, "FWD0 URI: %s\n", u0)
		}
		if u1 := render.BuildFWDURI(st, "fwd1", ""); u1 != "" {
			fmt.Fprintf(stdout, "FWD1 URI: %s\n", u1)
		}
		for _, rf := range st.Relay.Forwards {
			fmt.Fprintf(stdout, "Relay [%s] :%d -> %s:%d (%s/%s)\n", rf.ID, rf.ListenPort, rf.TargetHost, rf.TargetPort, rf.Proto, rf.Engine)
		}
		maybePrintQR(stdout, uri, *qrFlag)
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
		user := fs.String("username", "", "SOCKS5 username")
		pass := fs.String("password", "", "SOCKS5 password")
		fromURI := fs.String("from-uri", "", "parse node settings from vless://, vmess://, or socks5:// URI")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		setFlags := make(map[string]bool)
		fs.Visit(func(f *flag.Flag) {
			setFlags[f.Name] = true
		})

		node := state.OutboundNode{
			Protocol: *proto,
			Port:     *port,
		}
		if strings.TrimSpace(*fromURI) != "" {
			parsed, err := render.ParseNodeURI(*fromURI)
			if err != nil {
				fmt.Fprintf(stderr, "parse --from-uri: %v\n", err)
				return 2
			}
			node = parsed
		}
		if setFlags["id"] {
			node.ID = *id
		}
		if setFlags["name"] {
			node.Name = *name
		}
		if setFlags["proto"] {
			node.Protocol = *proto
		}
		if setFlags["address"] {
			node.Address = *addr
		}
		if setFlags["port"] {
			node.Port = *port
		}
		if setFlags["uuid"] {
			node.UUID = *uuid
		}
		if setFlags["sni"] {
			node.TLSSNI = *sni
		}
		if setFlags["path"] {
			node.Path = *path
		}
		if setFlags["pbk"] {
			node.RealityPubKey = *pbk
		}
		if setFlags["sid"] {
			node.RealityShortID = *sid
		}
		if setFlags["username"] {
			node.Username = *user
		}
		if setFlags["password"] {
			node.Password = *pass
		}

		if node.Address == "" {
			fmt.Fprintln(stderr, "--address (or --from-uri) is required")
			return 2
		}
		if node.UUID == "" && node.Protocol != "socks5" {
			node.UUID, _ = cryptoext.GenerateUUID()
		}
		if node.ID == "" {
			node.ID = fmt.Sprintf("node-%d", time.Now().UnixNano()%1000000)
		}
		if node.Name == "" {
			node.Name = node.Address
		}
		mut := func(cur *state.State) error {
			cur.Client.Nodes = append(cur.Client.Nodes, node)
			if cur.Client.ActiveNodeID == "" {
				cur.Client.ActiveNodeID = node.ID
			}
			return nil
		}
		if err := applyOrSave(store, exec, state.RoleClient, *doApply, mut); err != nil {
			fmt.Fprintf(stderr, "node add failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Added node %s (%s)\n", node.ID, node.Address)
		return 0

	case "edit":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: dex node edit <id> [flags] [--apply]")
			return 2
		}
		id := rest[0]
		fs := flag.NewFlagSet("node edit", flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "", "node name")
		proto := fs.String("proto", "", "protocol")
		addr := fs.String("address", "", "server host/ip")
		port := fs.Int("port", 0, "server port")
		uuid := fs.String("uuid", "", "UUID")
		sni := fs.String("sni", "", "TLS SNI")
		path := fs.String("path", "", "WS/XHTTP path")
		pbk := fs.String("pbk", "", "Reality public key")
		sid := fs.String("sid", "", "Reality shortId")
		user := fs.String("username", "", "SOCKS5 username")
		pass := fs.String("password", "", "SOCKS5 password")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(rest[1:]); err != nil {
			return 2
		}
		setFlags := make(map[string]bool)
		fs.Visit(func(f *flag.Flag) {
			setFlags[f.Name] = true
		})
		mut := func(cur *state.State) error {
			target := cur.Client.FindNode(id)
			if target == nil {
				return fmt.Errorf("node %q not found", id)
			}
			if setFlags["name"] {
				target.Name = *name
			}
			if setFlags["proto"] {
				target.Protocol = *proto
			}
			if setFlags["address"] {
				target.Address = *addr
			}
			if setFlags["port"] {
				target.Port = *port
			}
			if setFlags["uuid"] {
				target.UUID = *uuid
			}
			if setFlags["sni"] {
				target.TLSSNI = *sni
			}
			if setFlags["path"] {
				target.Path = *path
			}
			if setFlags["pbk"] {
				target.RealityPubKey = *pbk
			}
			if setFlags["sid"] {
				target.RealityShortID = *sid
			}
			if setFlags["username"] {
				target.Username = *user
			}
			if setFlags["password"] {
				target.Password = *pass
			}
			return nil
		}
		if err := applyOrSave(store, exec, state.RoleClient, *doApply, mut); err != nil {
			fmt.Fprintf(stderr, "node edit failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Updated node %s\n", id)
		return 0

	case "move":
		if len(rest) < 2 {
			fmt.Fprintln(stderr, "usage: dex node move <id> <up|down> [--apply]")
			return 2
		}
		id := rest[0]
		dir := strings.ToLower(strings.TrimSpace(rest[1]))
		if dir != "up" && dir != "down" {
			fmt.Fprintln(stderr, "direction must be 'up' or 'down'")
			return 2
		}
		doApply := len(rest) > 2 && rest[2] == "--apply"
		mut := func(cur *state.State) error {
			idx := -1
			for i, n := range cur.Client.Nodes {
				if n.ID == id {
					idx = i
					break
				}
			}
			if idx < 0 {
				return fmt.Errorf("node %q not found", id)
			}
			if dir == "up" && idx > 0 {
				cur.Client.Nodes[idx-1], cur.Client.Nodes[idx] = cur.Client.Nodes[idx], cur.Client.Nodes[idx-1]
			} else if dir == "down" && idx+1 < len(cur.Client.Nodes) {
				cur.Client.Nodes[idx+1], cur.Client.Nodes[idx] = cur.Client.Nodes[idx], cur.Client.Nodes[idx+1]
			}
			return nil
		}
		if err := applyOrSave(store, exec, state.RoleClient, doApply, mut); err != nil {
			fmt.Fprintf(stderr, "node move failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Moved node %s %s\n", id, dir)
		return 0

	case "probe":
		st, err := store.Load()
		if err != nil {
			fmt.Fprintf(stderr, "load state: %v\n", err)
			return 1
		}
		var targets []state.OutboundNode
		if len(rest) > 0 {
			n := st.Client.FindNode(rest[0])
			if n == nil {
				fmt.Fprintf(stderr, "node %q not found\n", rest[0])
				return 1
			}
			targets = []state.OutboundNode{*n}
		} else {
			targets = st.Client.Nodes
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, n := range targets {
			res := daemon.ProbeNodeHealth(ctx, n, 5*time.Second, false)
			if res.Healthy {
				fmt.Fprintf(stdout, "[OK]   %-14s %-16s %4d ms (code=%d)\n", n.ID, n.Name, res.LatencyMS, res.StatusCode)
			} else {
				fmt.Fprintf(stdout, "[FAIL] %-14s %-16s %4d ms (%s)\n", n.ID, n.Name, res.LatencyMS, res.Error)
			}
		}
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
			cur.Client.PruneNodeRefs(id)
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
	return cmdCertWithOpts(store, exec, reconcile.ApplyOptions{}, args, stdout, stderr)
}

func cmdCertWithOpts(store *state.Store, exec reconcile.SystemExecutor, applyOpts reconcile.ApplyOptions, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "inspect" {
		st, _ := store.Load()
		certFile, keyFile := resolveActiveCertPaths(store, st)
		if applyOpts.RootPrefix != "" {
			certFile = fsutil.MapRootPrefix(applyOpts.RootPrefix, certFile)
			keyFile = fsutil.MapRootPrefix(applyOpts.RootPrefix, keyFile)
		}
		cb, err1 := os.ReadFile(certFile)
		kb, err2 := os.ReadFile(keyFile)
		if err1 != nil || err2 != nil {
			fmt.Fprintf(stderr, "cannot read cert/key (%s / %s): %v / %v\n", certFile, keyFile, err1, err2)
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
		fs := flag.NewFlagSet("cert self-sign", flag.ContinueOnError)
		fs.SetOutput(stderr)
		force := fs.Bool("force", false, "overwrite existing valid certificate")
		cn := "localhost"
		parseArgs := rest
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			cn = rest[0]
			parseArgs = rest[1:]
		}
		if err := fs.Parse(parseArgs); err != nil {
			return 2
		}
		if fs.NArg() > 0 && cn == "localhost" {
			cn = fs.Arg(0)
		}
		certChanged := false
		if *force {
			if err := cert.ForceSelfSigned(store.DefaultCert(), store.DefaultKey(), cn); err != nil {
				fmt.Fprintf(stderr, "self-sign failed: %v\n", err)
				return 1
			}
			certChanged = true
		} else {
			prevCert, _ := os.ReadFile(store.DefaultCert())
			if err := cert.EnsureSelfSigned(store.DefaultCert(), store.DefaultKey(), cn); err != nil {
				fmt.Fprintf(stderr, "self-sign failed: %v\n", err)
				return 1
			}
			afterCert, _ := os.ReadFile(store.DefaultCert())
			certChanged = !bytes.Equal(prevCert, afterCert)
		}
		hadCustomExternal := false
		if st, err := store.Load(); err == nil && st != nil {
			hadCustomExternal = st.Cert.Mode == "imported" &&
				((st.Cert.CertFile != "" && st.Cert.CertFile != store.DefaultCert()) ||
					(st.Cert.KeyFile != "" && st.Cert.KeyFile != store.DefaultKey()))
			if _, uerr := store.Update(st.Role, func(cur *state.State) error {
				cur.Cert.Mode = "self_signed"
				cur.Cert.CertFile = ""
				cur.Cert.KeyFile = ""
				return nil
			}); uerr != nil {
				fmt.Fprintf(stderr, "update state after self-sign failed: %v\n", uerr)
				return 1
			}
			if hadCustomExternal {
				if _, rerr := reconcile.Reconcile(context.Background(), store, exec, applyOpts); rerr != nil {
					fmt.Fprintf(stderr, "reconcile after self-sign failed: %v\n", rerr)
					return 1
				}
			}
		}
		if certChanged || hadCustomExternal {
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
		st, stErr := store.Load()
		if stErr == nil && st != nil && st.Server.Domain != "" {
			checkDomains = append(checkDomains, st.Server.Domain)
		}
		rep, changed, err := cert.ImportPair(rest[0], rest[1], store.DefaultCert(), store.DefaultKey(), allowSelf, checkDomains)
		if err != nil {
			fmt.Fprintf(stderr, "import failed: %v\n", err)
			return 1
		}
		pathsChanged := false
		if stErr == nil && st != nil {
			pathsChanged = (st.Cert.CertFile != "" && st.Cert.CertFile != store.DefaultCert()) ||
				(st.Cert.KeyFile != "" && st.Cert.KeyFile != store.DefaultKey())
			if _, uerr := store.Update(st.Role, func(cur *state.State) error {
				cur.Cert.Mode = "imported"
				cur.Cert.CertFile = store.DefaultCert()
				cur.Cert.KeyFile = store.DefaultKey()
				return nil
			}); uerr != nil {
				fmt.Fprintf(stderr, "update state after import failed: %v\n", uerr)
				return 1
			}
			if pathsChanged {
				if _, rerr := reconcile.Reconcile(context.Background(), store, exec, applyOpts); rerr != nil {
					fmt.Fprintf(stderr, "reconcile after cert import failed: %v\n", rerr)
					return 1
				}
			}
		}
		if changed || pathsChanged {
			reloadCertConsumers(context.Background(), exec, stdout)
		}
		fmt.Fprintf(stdout, "Certificate imported (changed=%v, expires=%s, SANs=%s)\n",
			changed, rep.NotAfter.Format("2006-01-02"), strings.Join(rep.SANs, ", "))
		return 0
	case "issue":
		fs := flag.NewFlagSet("cert issue", flag.ContinueOnError)
		fs.SetOutput(stderr)
		mode := fs.String("mode", "cf", "ACME validation mode: cf|http")
		dom := fs.String("domain", "", "domain")
		tok := fs.String("cf-token", "", "Cloudflare API Token (or Global API Key with --cf-email)")
		email := fs.String("cf-email", "", "Cloudflare account email (for Global API Key)")
		webroot := fs.String("webroot", "", "HTTP-01 webroot directory (uses --standalone if empty)")
		renew := fs.Bool("renew", true, "keep CF token for automatic renewal")
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
		if *email == "" && st != nil {
			*email = st.Cert.CFEmail
		}
		acmeMode := strings.ToLower(strings.TrimSpace(*mode))
		var (
			rep *cert.CertReport
			err error
		)
		cfg := cert.ACMEConfig{
			Domain:    *dom,
			CFToken:   *tok,
			CFEmail:   *email,
			Webroot:   *webroot,
			ListenV6:  st != nil && st.System.EnableIPv6,
			AutoRenew: *renew,
			CertPath:  store.DefaultCert(),
			KeyPath:   store.DefaultKey(),
			ReloadCmd: buildCertReloadCmd(store.Dir),
		}
		switch acmeMode {
		case "", "cf", "cloudflare", "dns":
			rep, err = cert.IssueCloudflareACME(context.Background(), nil, cfg)
		case "http", "http-01":
			rep, err = cert.IssueHTTPACME(context.Background(), nil, cfg)
		default:
			fmt.Fprintf(stderr, "unsupported --mode %q (expected cf or http)\n", *mode)
			return 2
		}
		if err != nil {
			fmt.Fprintf(stderr, "acme issue failed: %v\n", err)
			return 1
		}
		if st != nil {
			hadCustomExternal := (st.Cert.CertFile != "" && st.Cert.CertFile != store.DefaultCert()) ||
				(st.Cert.KeyFile != "" && st.Cert.KeyFile != store.DefaultKey())
			certMode := "acme_cf"
			if acmeMode == "http" || acmeMode == "http-01" {
				certMode = "acme_http"
			}
			if _, uerr := store.Update(st.Role, func(cur *state.State) error {
				cur.Cert.Mode = certMode
				cur.Cert.Domain = *dom
				cur.Cert.CertFile = ""
				cur.Cert.KeyFile = ""
				cur.Cert.AutoRenew = *renew
				if certMode == "acme_http" {
					// HTTP-01 does not rely on CF API tokens
				} else if *renew {
					cur.Cert.CFToken = *tok
					cur.Cert.CFEmail = *email
				} else {
					cur.Cert.CFToken = ""
					cur.Cert.CFEmail = ""
				}
				return nil
			}); uerr != nil {
				fmt.Fprintf(stderr, "update state after issue failed: %v\n", uerr)
				return 1
			}
			if hadCustomExternal {
				if _, rerr := reconcile.Reconcile(context.Background(), store, exec, applyOpts); rerr != nil {
					fmt.Fprintf(stderr, "reconcile after cert issue failed: %v\n", rerr)
					return 1
				}
			}
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

func buildCertReloadCmd(stateDir string) string {
	exe, err := os.Executable()
	if err != nil || exe == "" || strings.HasSuffix(exe, ".test") || strings.Contains(exe, "/go-build") {
		exe = "/usr/local/bin/dex"
	}
	return fmt.Sprintf("%s --state-dir %s cert reload", render.ShellSingleQuote(exe), render.ShellSingleQuote(stateDir))
}

func reloadNonDaemonCertConsumers(ctx context.Context, exec reconcile.SystemExecutor, stdout io.Writer) {
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
}

func reloadCertConsumers(ctx context.Context, exec reconcile.SystemExecutor, stdout io.Writer) {
	if exec == nil {
		return
	}
	reloadNonDaemonCertConsumers(ctx, exec, stdout)
	initSys := exec.DetectInitSystem()
	if exec.ServiceIsActive(ctx, initSys, "dex-daemon") {
		_ = exec.ServiceRestart(ctx, initSys, "dex-daemon")
		if stdout != nil {
			fmt.Fprintln(stdout, "Reloaded TLS consumers: dex-daemon")
		}
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
			ip, ipErr := render.NextAvailableWGIP(wg.SubnetCIDR, wg.Peers)
			if ipErr != nil {
				return ipErr
			}
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

	case "keygen-server":
		doApply := len(rest) > 0 && rest[0] == "--apply"
		priv, pub, err := cryptoext.GenerateWireGuardKeypair()
		if err != nil {
			fmt.Fprintf(stderr, "generate server keypair: %v\n", err)
			return 1
		}
		if err := applyOrSave(store, exec, state.RoleClient, doApply, func(cur *state.State) error {
			cur.Client.WireGuard.ServerPrivateKey = priv
			cur.Client.WireGuard.ServerPublicKey = pub
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "wg keygen-server failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Regenerated WireGuard server keypair (pubkey=%s)\n", pub)
		return 0

	case "peer-regen":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: dex wg peer-regen <name> [--apply]")
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
		if err := applyOrSave(store, exec, state.RoleClient, doApply, func(cur *state.State) error {
			wg := &cur.Client.WireGuard
			for i := range wg.Peers {
				if wg.Peers[i].Name == name {
					wg.Peers[i].PrivateKey = priv
					wg.Peers[i].PublicKey = pub
					cfgText = render.BuildWGPeerConfig(*wg, wg.Peers[i])
					return nil
				}
			}
			return fmt.Errorf("peer %q not found", name)
		}); err != nil {
			fmt.Fprintf(stderr, "wg peer-regen failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Regenerated peer %s:\n%s", name, cfgText)
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
		tok := fs.String("token", "", "Cloudflare API Token or Global Key")
		email := fs.String("email", "", "Cloudflare email (for Global API Key)")
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
				CFEmail:    *email,
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
		res, err := d.SyncOnceWithEmail(context.Background(), st.Client.DDNS.Domain, st.Client.DDNS.CFToken, st.Client.DDNS.CFEmail, st.Client.DDNS.EnableIPv6, true)
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
				p.Name, p.Enabled, state.FormatEndpoint(p.Address, p.Port), len(p.Domains), len(p.IPs))
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
		assignedID := strings.TrimSpace(*id)
		if err := applyOrSave(store, exec, state.RoleRelay, *doApply, func(cur *state.State) error {
			if assignedID == "" {
				used := make(map[string]bool, len(cur.Relay.Forwards))
				for _, f := range cur.Relay.Forwards {
					used[f.ID] = true
				}
				cand := fmt.Sprintf("fwd-%d", *listen)
				if used[cand] {
					pTag := strings.ReplaceAll(strings.TrimSpace(*proto), ",", "-")
					if pTag == "" {
						pTag = "tcp"
					}
					cand = fmt.Sprintf("fwd-%s-%d", pTag, *listen)
					for suffix := 2; used[cand]; suffix++ {
						cand = fmt.Sprintf("fwd-%s-%d-%d", pTag, *listen, suffix)
					}
				}
				assignedID = cand
			}
			cur.Relay.Forwards = append(cur.Relay.Forwards, state.ForwardRule{
				ID:         assignedID,
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
		fmt.Fprintf(stdout, "Added relay %s :%d -> %s:%d (%s)\n", assignedID, *listen, *targetHost, *targetPort, *engine)
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
			if strings.TrimSpace(m.UUID) != "" {
				fmt.Fprintf(stdout, "  S-Map :%d (%s) -> uuid=%s\n", m.Port, m.Proto, strings.TrimSpace(m.UUID))
			} else {
				fmt.Fprintf(stdout, "  S-Map :%d (%s)\n", m.Port, m.Proto)
			}
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
		uuid := fs.String("uuid", "", "tunnel UUID (comma-separated for multiple clients)")
		mapPort := fs.Int("map-port", 0, "optional mapped port to add")
		mapProto := fs.String("map-proto", "tcp", "tcp|udp|tcp,udp")
		mapUUID := fs.String("map-uuid", "", "optional client UUID binding for --map-port")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		var uuids []string
		for _, part := range strings.Split(*uuid, ",") {
			if u := strings.TrimSpace(part); u != "" {
				uuids = append(uuids, u)
			}
		}
		if len(uuids) == 0 {
			gen, _ := cryptoext.GenerateUUID()
			uuids = []string{gen}
		}
		if err := applyOrSave(store, exec, defRole, *doApply, func(cur *state.State) error {
			cur.RproxyS.Enabled = true
			if *dom != "" {
				cur.RproxyS.Domain = *dom
			}
			cur.RproxyS.ListenPort = *port
			cur.RproxyS.UUIDs = uuids
			if *mapPort > 0 {
				cur.RproxyS.Mappings = upsertRproxyServerMapping(cur.RproxyS.Mappings, state.RproxyServerMapping{
					Port:  *mapPort,
					Proto: *mapProto,
					UUID:  strings.TrimSpace(*mapUUID),
				})
			}
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "rproxy set failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "RproxyS configured on :%d (UUID: %s)\n", *port, strings.Join(uuids, ","))
		return 0
	case "map-add":
		fs := flag.NewFlagSet("rproxy map-add", flag.ContinueOnError)
		fs.SetOutput(stderr)
		port := fs.Int("port", 0, "mapped public port")
		proto := fs.String("proto", "tcp", "tcp|udp|tcp,udp")
		uuid := fs.String("uuid", "", "optional client UUID for multi-client isolation")
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
				UUID:  strings.TrimSpace(*uuid),
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

func addTLSExtraInbound(store *state.Store, exec reconcile.SystemExecutor, defRole, proto, cmdName string, rest []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	port := fs.Int("port", 0, "listen port")
	domain := fs.String("domain", "", "TLS domain/SNI (optional when sharing server domain)")
	path := fs.String("path", "", "WS/XHTTP path (auto-derived if empty)")
	uuid := fs.String("uuid", "", "UUID (auto-generated if empty)")
	viaNginx := fs.Bool("via-nginx", false, "terminate TLS via Nginx SNI/path proxy")
	tag := fs.String("tag", "", "inbound tag")
	doApply := fs.Bool("apply", false, "apply immediately")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if *port <= 0 || *port > 65535 {
		fmt.Fprintln(stderr, "--port must be 1..65535")
		return 2
	}
	u := strings.TrimSpace(*uuid)
	if u == "" {
		u, _ = cryptoext.GenerateUUID()
	}
	t := strings.TrimSpace(*tag)
	if t == "" {
		t = fmt.Sprintf("inbound-%s-%d", strings.ReplaceAll(proto, "vless-", ""), *port)
	}
	ex := state.ExtraInbound{
		Tag:        t,
		Protocol:   proto,
		ListenPort: *port,
		Domain:     strings.TrimSpace(*domain),
		Path:       strings.TrimSpace(*path),
		UUID:       u,
		ViaNginx:   *viaNginx,
	}
	if err := applyOrSave(store, exec, defRole, *doApply, func(cur *state.State) error {
		cur.ExtraInbounds = upsertExtraInbound(cur.ExtraInbounds, ex)
		return nil
	}); err != nil {
		fmt.Fprintf(stderr, "%s failed: %v\n", cmdName, err)
		return 1
	}
	st, _ := store.Load()
	fmt.Fprintf(stdout, "Added %s (%s :%d via_nginx=%v)\nUUID: %s\nPath: %s\nURI:  %s\n",
		ex.Tag, ex.Protocol, ex.ListenPort, ex.ViaNginx, ex.UUID, render.NormalizePath(ex.Path, ex.UUID), render.BuildExtraURI(st, ex))
	return 0
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
			switch ex.Protocol {
			case "vless-reality":
				fmt.Fprintf(stdout, " sni=%s pbk=%s sid=%s uuid=%s", ex.RealitySNI, ex.RealityPubKey, ex.RealityShortID, ex.UUID)
			case "dokodemo":
				netLabel := ex.Network
				if netLabel == "" {
					netLabel = "tcp,udp"
				}
				fmt.Fprintf(stdout, " -> %s:%d (%s)", ex.TargetAddr, ex.TargetPort, netLabel)
			case "vless-xhttp", "vless-ws", "vmess-ws":
				fmt.Fprintf(stdout, " domain=%s path=%s", ex.Domain, render.NormalizePath(ex.Path, ex.UUID))
			}
			fmt.Fprintln(stdout)
			if uri := render.BuildExtraURI(st, ex); uri != "" {
				fmt.Fprintf(stdout, "  URI: %s\n", uri)
			}
		}
		return 0
	}

	defRole := existingRoleOr(store, state.RoleServer)
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "add-xhttp":
		return addTLSExtraInbound(store, exec, defRole, "vless-xhttp", "extra add-xhttp", rest, stdout, stderr)
	case "add-vless-ws":
		return addTLSExtraInbound(store, exec, defRole, "vless-ws", "extra add-vless-ws", rest, stdout, stderr)
	case "add-vmess-ws":
		return addTLSExtraInbound(store, exec, defRole, "vmess-ws", "extra add-vmess-ws", rest, stdout, stderr)
	case "add-dokodemo":
		fs := flag.NewFlagSet("extra add-dokodemo", flag.ContinueOnError)
		fs.SetOutput(stderr)
		port := fs.Int("port", 0, "listen port")
		target := fs.String("target", "", "target host:port")
		targetAddr := fs.String("target-addr", "", "target host/IP")
		targetPort := fs.Int("target-port", 0, "target port")
		network := fs.String("network", "tcp,udp", "network: tcp|udp|tcp,udp")
		tag := fs.String("tag", "", "inbound tag")
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if *port <= 0 || *port > 65535 {
			fmt.Fprintln(stderr, "--port must be 1..65535")
			return 2
		}
		tAddr := strings.TrimSpace(*targetAddr)
		tPort := *targetPort
		if strings.TrimSpace(*target) != "" {
			h, pStr, err := net.SplitHostPort(strings.TrimSpace(*target))
			if err != nil {
				fmt.Fprintf(stderr, "invalid --target %q: %v\n", *target, err)
				return 2
			}
			pVal, err := strconv.Atoi(pStr)
			if err != nil || pVal < 1 || pVal > 65535 {
				fmt.Fprintf(stderr, "invalid --target port %q\n", pStr)
				return 2
			}
			if tAddr == "" {
				tAddr = h
			}
			if tPort == 0 {
				tPort = pVal
			}
		}
		if tAddr == "" || tPort <= 0 || tPort > 65535 {
			fmt.Fprintln(stderr, "--target (or --target-addr and --target-port) is required")
			return 2
		}
		t := strings.TrimSpace(*tag)
		if t == "" {
			t = fmt.Sprintf("inbound-dokodemo-%d", *port)
		}
		ex := state.ExtraInbound{
			Tag:        t,
			Protocol:   "dokodemo",
			ListenPort: *port,
			TargetAddr: tAddr,
			TargetPort: tPort,
			Network:    strings.TrimSpace(*network),
		}
		if err := applyOrSave(store, exec, defRole, *doApply, func(cur *state.State) error {
			cur.ExtraInbounds = upsertExtraInbound(cur.ExtraInbounds, ex)
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "extra add-dokodemo failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Added %s (dokodemo :%d -> %s:%d %s)\n", ex.Tag, ex.ListenPort, ex.TargetAddr, ex.TargetPort, ex.Network)
		return 0
	case "disable-all":
		fs := flag.NewFlagSet("extra disable-all", flag.ContinueOnError)
		fs.SetOutput(stderr)
		doApply := fs.Bool("apply", false, "apply immediately")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if err := applyOrSave(store, exec, defRole, *doApply, func(cur *state.State) error {
			cur.ExtraInbounds = nil
			return nil
		}); err != nil {
			fmt.Fprintf(stderr, "extra disable-all failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "Disabled all extra inbounds.")
		return 0
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
			ex.Tag, ex.Protocol, ex.ListenPort, ex.UUID, ex.RealityPubKey, ex.RealityShortID, ex.RealitySNI, render.BuildExtraURI(st, ex))
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
		st, _ := store.Load()
		fmt.Fprintf(stdout, "Added %s (socks5 :%d)\nURI: %s\n", ex.Tag, ex.ListenPort, render.BuildExtraURI(st, ex))
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
			for i, ex := range cur.ExtraInbounds {
				if ex.Tag == key {
					cur.ExtraInbounds = append(cur.ExtraInbounds[:i], cur.ExtraInbounds[i+1:]...)
					return nil
				}
			}
			if portNum > 0 {
				var matchedIdx []int
				var matchedTags []string
				for i, ex := range cur.ExtraInbounds {
					if ex.ListenPort == portNum {
						matchedIdx = append(matchedIdx, i)
						matchedTags = append(matchedTags, ex.Tag)
					}
				}
				if len(matchedIdx) == 1 {
					idx := matchedIdx[0]
					cur.ExtraInbounds = append(cur.ExtraInbounds[:idx], cur.ExtraInbounds[idx+1:]...)
					return nil
				}
				if len(matchedIdx) > 1 {
					return fmt.Errorf("multiple extra inbounds listen on port %d (%s); specify exact tag to delete", portNum, strings.Join(matchedTags, ", "))
				}
			}
			return fmt.Errorf("extra inbound %q not found", key)
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
		nginxConfDir := "/etc/nginx/conf.d"
		if baseOpts.RootPrefix != "" {
			nginxConfDir = filepath.Join(baseOpts.RootPrefix, "etc", "nginx", "conf.d")
		}
		snap := cleanupLegacyV2WithPaths(ctx, exec, v2NFTDir, nginxConfDir, stdout)
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
		switch st.Role {
		case state.RoleClient:
			addr = ":443"
		case state.RoleServer:
			addr = "127.0.0.1:8443"
		default:
			addr = ":8443"
		}
	}

	hub := daemon.NewTaskHub(300)
	runner := daemon.NewRunner(store, exec, hub)
	webSrv := web.NewServer(store, exec, hub, runner.DDNS, reconcile.ApplyOptions{})
	webSrv.Notifier = runner.Notifier
	webSrv.Metrics = runner.Metrics
	webSrv.CertReloadCmd = buildCertReloadCmd(store.Dir)
	webSrv.UpdateRulesFn = func(ctx context.Context, includeAds bool, w io.Writer) error {
		return UpdateRules(ctx, store, exec, OpsConfig{}, includeAds, false, w)
	}
	webSrv.UpdateComponentsFn = func(ctx context.Context, component, ver string, w io.Writer) error {
		return UpdateComponents(ctx, store, exec, OpsConfig{SkipDaemonRestart: true}, component, ver, w)
	}
	webSrv.ReloadCertFn = func(ctx context.Context) {
		reloadNonDaemonCertConsumers(ctx, exec, nil)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go runner.RunLoops(ctx)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           webSrv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var redirSrv *http.Server
	if st.Role == state.RoleClient && !*httpOnly {
		_, httpsPort, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			httpsPort = "443"
		}
		if httpsPort != "80" {
			ln80, lerr := net.Listen("tcp", ":80")
			if lerr != nil {
				fmt.Fprintf(stderr, "warning: HTTP->HTTPS redirect on :80 disabled: %v\n", lerr)
			} else {
				redirSrv = &http.Server{
					Addr:              ":80",
					Handler:           newHTTPSRedirectHandler(httpsPort),
					ReadHeaderTimeout: 5 * time.Second,
				}
				fmt.Fprintf(stdout, "dex daemon listening HTTP->HTTPS redirect on :80 -> :%s\n", httpsPort)
				go func() {
					if serr := redirSrv.Serve(ln80); serr != nil && !errors.Is(serr, http.ErrServerClosed) {
						fmt.Fprintf(stderr, "http redirect error: %v\n", serr)
					}
				}()
			}
		}
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
		if redirSrv != nil {
			_ = redirSrv.Shutdown(shutCtx)
		}
		_ = httpSrv.Shutdown(shutCtx)
		return 0
	case err := <-errCh:
		if redirSrv != nil {
			_ = redirSrv.Close()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "daemon error: %v\n", err)
			return 1
		}
		return 0
	}
}

func newHTTPSRedirectHandler(httpsPort string) http.Handler {
	port := strings.TrimSpace(httpsPort)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := extractRedirectHost(r.Host)
		if host == "" || strings.ContainsAny(host, "/\\@ \t\r\n") {
			http.Error(w, "invalid Host header", http.StatusBadRequest)
			return
		}
		var authority string
		if port == "" || port == "443" {
			if strings.Contains(host, ":") {
				authority = "[" + host + "]"
			} else {
				authority = host
			}
		} else {
			authority = net.JoinHostPort(host, port)
		}

		reqURI := r.URL.RequestURI()
		if reqURI == "" || !strings.HasPrefix(reqURI, "/") {
			reqURI = "/"
		}
		// Collapse multiple leading slashes or leading backslash (e.g. //evil.com, /\evil.com)
		// so the path never looks like a scheme-relative URL.
		if strings.HasPrefix(reqURI, "//") || strings.HasPrefix(reqURI, "/\\") {
			reqURI = "/" + strings.TrimLeft(reqURI, "/\\")
		}
		target := "https://" + authority + reqURI
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func extractRedirectHost(rawHost string) string {
	h := strings.TrimSpace(rawHost)
	if h == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(h); err == nil {
		return parsedHost
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1]
	}
	return h
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
