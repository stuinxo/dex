package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/daemon"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
	"io"
	"os"
	osexec "os/exec"
	"strings"
	"time"
)

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
			return cur.EnableWireGuard(*ep, *port, "")
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
		var cfgText string
		mut := func(cur *state.State) error {
			peer, perr := cur.AddWireGuardPeer(name, "", 0, "")
			if perr != nil {
				return perr
			}
			cfgText = render.BuildWGPeerConfig(cur.Client.WireGuard, peer)
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
		var pub string
		if err := applyOrSave(store, exec, state.RoleClient, doApply, func(cur *state.State) error {
			var kerr error
			pub, kerr = cur.RegenerateWireGuardServerKeys()
			return kerr
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
		var cfgText string
		if err := applyOrSave(store, exec, state.RoleClient, doApply, func(cur *state.State) error {
			peer, perr := cur.RegenerateWireGuardPeer(name)
			if perr != nil {
				return perr
			}
			cfgText = render.BuildWGPeerConfig(cur.Client.WireGuard, peer)
			return nil
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
			return cur.DeleteWireGuardPeer(name)
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
