package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/update"
	"github.com/stuinxo/dex/internal/version"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
		certFile, keyFile := store.ActiveCertPaths(st)
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
			if err := bootstrapRoleRuntimeDeps(context.Background(), store, exec, st.Role, update.OpsConfig{}, stdout); err != nil {
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
	certFile, keyFile := store.ActiveCertPaths(st)
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
