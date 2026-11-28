package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/socks5out"
	"github.com/stuinxo/dex/internal/state"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

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
				assignedID = cur.Relay.NextForwardID(*listen, *proto)
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
		t = state.DefaultExtraInboundTag(proto, *port)
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
			t = state.DefaultExtraInboundTag("dokodemo", *port)
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
			t = state.DefaultExtraInboundTag("vless-reality", *port)
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
			t = state.DefaultExtraInboundTag("socks5", *port)
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
