package render

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/stuinxo/dex/internal/state"
)

func findFile(bundle *RenderBundle, rel string) (RenderedFile, bool) {
	for _, f := range bundle.Files {
		if f.RelName == rel {
			return f, true
		}
	}
	return RenderedFile{}, false
}

func TestRenderClientAllSubsystems(t *testing.T) {
	s := state.NewDefaultState(state.RoleClient)
	s.System.LANInterface = "eth0"
	s.System.LANAddrCIDR = "192.168.10.2/24"
	s.System.EnableIPv6 = true
	s.Client.Nodes = []state.OutboundNode{
		{
			ID:       "n1",
			Name:     "HK-Main",
			Protocol: "vless-xhttp",
			Address:  "hk.example.com",
			Port:     443,
			UUID:     "11111111-1111-4111-8111-111111111111",
		},
		{
			ID:             "n2",
			Name:           "JP-Reality",
			Protocol:       "vless-reality",
			Address:        "198.51.100.10",
			Port:           443,
			UUID:           "22222222-2222-4222-8222-222222222222",
			TLSSNI:         "www.apple.com",
			RealityPubKey:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			RealityShortID: "abcd1234",
		},
	}
	s.Client.ActiveNodeID = "n1"
	s.Client.Routing.ServiceMap["openai"] = "n2"
	s.Client.Routing.ServiceMap["meta"] = "n1"
	s.Client.Routing.Divert = state.DivertConfig{
		Enabled:          true,
		NodeID:           "n2",
		CHNProxyLANIPs:   []string{"192.168.10.50"},
		GlobalProxyLANIP: []string{"192.168.10.60"},
		DirectLANIPs:     []string{"192.168.10.70"},
	}
	s.Client.FWD1 = state.FWD1Config{
		Enabled:        true,
		Port:           2443,
		UUIDs:          []string{"33333333-3333-4333-8333-333333333333"},
		UpstreamNodeID: "n1",
	}
	s.Client.RproxyC = state.RproxyCConfig{
		Enabled:       true,
		TunnelAddress: "tun.example.com",
		TunnelPort:    8443,
		TunnelUUID:    "44444444-4444-4444-8444-444444444444",
		Mappings: []state.RproxyClientMapping{
			{ExtPort: 18080, Proto: "tcp", IntIP: "192.168.10.10", IntPort: 80},
		},
	}
	s.Client.WireGuard = state.WireGuardConfig{
		Enabled:          true,
		EndpointHost:     "home.example.com",
		ListenPort:       51820,
		SubnetCIDR:       "172.16.66.1/24",
		ServerPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ServerPublicKey:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		Peers: []state.WGPeer{{
			Name:       "laptop",
			IP:         "172.16.66.11",
			PrivateKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
			PublicKey:  "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=",
		}},
	}

	s.Client.DNS.DoHServers = []string{
		"https://vtw.example.com/dq",
		"https://dns.google/dns-query",
	}

	opts := RenderOptions{
		StateDir:     "/tmp/dex-test",
		PhysicalNICs: []string{"eth0"},
		ResolvedHostIPs: map[string][]netip.Addr{
			"hk.example.com":  {netip.MustParseAddr("203.0.113.10")},
			"tun.example.com": {netip.MustParseAddr("203.0.113.20")},
			"vtw.example.com": {netip.MustParseAddr("203.0.113.30")},
			"dns.google":      {netip.MustParseAddr("8.8.8.8")},
		},
		ChnRouteCIDRs: []string{"1.0.1.0/24"},
	}

	bundle, err := RenderAll(s, opts)
	if err != nil {
		t.Fatalf("RenderAll client: %v", err)
	}
	if !bundle.XrayNeeded || !bundle.NFTClientNeeded || !bundle.MosDNSNeeded || !bundle.WireGuardNeeded || !bundle.DaemonNeeded || !bundle.RulesTimerNeeded {
		t.Fatalf("missing expected active subsystems: %+v", bundle)
	}

	// Verify Xray JSON structure & Xray 26 freedom finalRules invariants
	xf, ok := findFile(bundle, "xray.json")
	if !ok {
		t.Fatalf("missing xray.json")
	}
	var xcfg map[string]any
	if err := json.Unmarshal(xf.Content, &xcfg); err != nil {
		t.Fatalf("unmarshal xray.json: %v", err)
	}
	outbounds := xcfg["outbounds"].([]any)
	freedomCount := 0
	for _, obRaw := range outbounds {
		ob := obRaw.(map[string]any)
		if ob["protocol"] == "freedom" {
			freedomCount++
			settings := ob["settings"].(map[string]any)
			if _, hasFR := settings["finalRules"]; !hasFR {
				t.Fatalf("freedom outbound %v missing Xray 26 finalRules", ob["tag"])
			}
		}
	}
	if freedomCount < 2 { // direct + mapping0
		t.Fatalf("expected at least 2 freedom outbounds, got %d", freedomCount)
	}
	dnsHosts := xcfg["dns"].(map[string]any)["hosts"].(map[string]any)
	if dnsHosts["tun.example.com"] != "203.0.113.20" {
		t.Fatalf("expected Rproxy tunnel domain in xray dns.hosts, got %+v", dnsHosts)
	}

	// Verify nftables QUIC UDP/443 reject + dual-stack sets + WireGuard
	nf, ok := findFile(bundle, "nftables.conf")
	if !ok {
		t.Fatalf("missing nftables.conf")
	}
	nftStr := string(nf.Content)
	for _, needle := range []string{
		"table inet dex_client {}",
		"table inet dex_client {",
		"meta mark 0x8 meta l4proto udp th dport 443 counter reject",
		"203.0.113.10",
		"203.0.113.30",
		"1.0.1.0/24",
		"tproxy ip to 127.0.0.1:9896 meta mark set 0x9",
		"tproxy ip6 to [::1]:9896 meta mark set 0x9",
		`iifname "wg0" accept`,
	} {
		if !strings.Contains(nftStr, needle) {
			t.Errorf("nftables.conf missing %q", needle)
		}
	}
	if strings.Contains(nftStr, "8.8.8.8") {
		t.Errorf("expected blocked public Anycast DoH IP 8.8.8.8 excluded when nodes exist")
	}

	// Verify MosDNS config
	mf, ok := findFile(bundle, "mosdns/mosdns.yaml")
	if !ok || !strings.Contains(string(mf.Content), "resp_ip &/tmp/dex-test/rules/IPchnroute") {
		t.Fatalf("mosdns.yaml invalid or missing unquoted resp_ip path: %v", ok)
	}

	// Verify WireGuard server & peer config
	wg0, ok := findFile(bundle, "wg0.conf")
	if !ok || !strings.Contains(string(wg0.Content), "Address = 172.16.66.1/24") || strings.Contains(string(wg0.Content), "DNS =") {
		t.Fatalf("unexpected wg0.conf:\n%s", string(wg0.Content))
	}
	wgf, ok := findFile(bundle, "wg-peers/peer-laptop.conf")
	if !ok || !strings.Contains(string(wgf.Content), "Endpoint = home.example.com:51820") || !strings.Contains(string(wgf.Content), "DNS = 172.16.66.1") {
		t.Fatalf("missing or malformed wireguard peer config")
	}

	// Verify URI builder
	uri := BuildNodeURI(s.Client.Nodes[0])
	if !strings.HasPrefix(uri, "vless://11111111-1111-4111-8111-111111111111@hk.example.com:443?") || !strings.Contains(uri, "type=xhttp") {
		t.Fatalf("unexpected BuildNodeURI: %q", uri)
	}
}

func TestRenderRelayPureNFTZeroXray(t *testing.T) {
	s := state.NewDefaultState(state.RoleRelay)
	s.Relay.Forwards = []state.ForwardRule{
		{
			ID:         "r1",
			ListenPort: 10001,
			TargetHost: "landing.example.com",
			TargetPort: 20001,
			Proto:      "tcp",
			Engine:     "nft",
		},
		{
			ID:         "r2",
			ListenPort: 10002,
			TargetHost: "ha.example.com",
			TargetPort: 443,
			Proto:      "tcp",
			Engine:     "haproxy",
		},
		{
			ID:         "r3",
			ListenPort: 10003,
			TargetHost: "198.51.100.99",
			TargetPort: 8443,
			Proto:      "tcp",
			Engine:     "haproxy",
		},
	}
	opts := RenderOptions{
		ResolvedHostIPs: map[string][]netip.Addr{
			"landing.example.com": {netip.MustParseAddr("2001:db8::5")},
		},
	}
	bundle, err := RenderAll(s, opts)
	if err != nil {
		t.Fatalf("RenderAll relay: %v", err)
	}
	if bundle.XrayNeeded {
		t.Fatalf("expected XrayNeeded=false for nft+haproxy relay")
	}
	if !bundle.NFTRelayNeeded || !bundle.HAProxyNeeded {
		t.Fatalf("expected both NFTRelayNeeded and HAProxyNeeded")
	}
	nf, _ := findFile(bundle, "nftables.conf")
	if !strings.Contains(string(nf.Content), "dnat ip6 to [2001:db8::5]:20001") {
		t.Fatalf("expected IPv6 DNAT rule in nftables.conf, got:\n%s", string(nf.Content))
	}
	hf, _ := findFile(bundle, "haproxy.cfg")
	hfStr := string(hf.Content)
	if !strings.Contains(hfStr, "server srv1 ha.example.com:443 check resolvers dex_dns init-addr libc,none") {
		t.Fatalf("unexpected domain haproxy.cfg:\n%s", hfStr)
	}
	if !strings.Contains(hfStr, "server srv1 198.51.100.99:8443 check\n") {
		t.Fatalf("expected literal IP haproxy rule without resolvers:\n%s", hfStr)
	}
}

func TestRenderServerSocks5AndNginx(t *testing.T) {
	s := state.NewDefaultState(state.RoleServer)
	s.Server.TLSMode = "nginx"
	s.Server.Domain = "srv.example.com"
	s.Server.ListenPort = 443
	s.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	s.Server.EnableDoH = true
	s.Server.Socks5Outbounds = []state.Socks5Profile{
		{
			Name:          "default",
			Enabled:       true,
			Address:       "socks.example.net",
			Port:          1080,
			Username:      "u",
			Password:      "p",
			PrivateBypass: true,
		},
		{
			Name:    "sg",
			Enabled: true,
			Address: "sg.example.net",
			Port:    1081,
			Domains: []string{"geosite:netflix"},
			IPs:     []string{"geoip:telegram"},
		},
	}

	bundle, err := RenderAll(s, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderAll server: %v", err)
	}
	if !bundle.XrayNeeded || !bundle.NginxNeeded || !bundle.DoHNeeded || !bundle.DaemonNeeded {
		t.Fatalf("expected Xray+Nginx+DoH+Daemon needed: %+v", bundle)
	}
	xf, _ := findFile(bundle, "xray.json")
	var xcfg map[string]any
	_ = json.Unmarshal(xf.Content, &xcfg)
	outbounds := xcfg["outbounds"].([]any)
	if outbounds[0].(map[string]any)["tag"] != "socks5-exit" {
		t.Fatalf("expected global default socks5-exit at outbounds[0], got %v", outbounds[0])
	}
	if xcfg["routing"].(map[string]any)["domainStrategy"] != "IPIfNonMatch" {
		t.Fatalf("expected domainStrategy=IPIfNonMatch when IP rules present")
	}

	ng, _ := findFile(bundle, "nginx-dex.conf")
	ngStr := string(ng.Content)
	if !strings.Contains(ngStr, "listen 80;") || !strings.Contains(ngStr, "listen 443 ssl;") || !strings.Contains(ngStr, "location /dq") || !strings.Contains(ngStr, "location /11111111") {
		t.Fatalf("unexpected nginx-dex.conf:\n%s", ngStr)
	}
}

func TestRenderWave1ProtocolsAndDataPlane(t *testing.T) {
	// 1. Client with vmess-tcp, FWD0 vmess-tcp, RproxyC pinnedPeerCertSha256 + OutDirect,
	// IPv6, wildcard hosts, block53, block_ads, Apple/Steam, Blacklist/Whitelist domains, DoH normalization.
	s := state.NewDefaultState(state.RoleClient)
	s.System.EnableIPv6 = true
	s.System.LANAddrCIDR = "192.168.10.2/24"
	s.Client.Nodes = []state.OutboundNode{{
		ID:       "tcp-1",
		Name:     "LegacyVMessTCP",
		Protocol: "vmess-tcp",
		Address:  "203.0.113.50",
		Port:     10443,
		UUID:     "11111111-1111-4111-8111-111111111111",
	}}
	s.Client.ActiveNodeID = "tcp-1"
	s.Client.FWD0 = state.FWD0Config{
		Enabled:  true,
		Protocol: "vmess-tcp",
		Port:     1443,
		UUIDs:    []string{"22222222-2222-4222-8222-222222222222"},
	}
	s.Client.RproxyC = state.RproxyCConfig{
		Enabled:              true,
		TunnelAddress:        "198.51.100.77",
		TunnelPort:           20000,
		TunnelUUID:           "33333333-3333-4333-8333-333333333333",
		Security:             "tls",
		ServerName:           "tun.example.com",
		PinnedPeerCertSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		OutDirect:            true,
		Mappings: []state.RproxyClientMapping{
			{ExtPort: 18080, Proto: "tcp", IntIP: "192.168.10.10", IntPort: 80},
		},
	}
	s.Client.DNS.ChinaServers = []string{"2400:3200::1", "223.5.5.5"}
	s.Client.DNS.DoHServers = []string{
		"dns.example.com",
		"quic://dns.adguard-dns.com",
		"https://cloudflare-dns.com/dns-query",
	}
	s.Client.DNS.Hosts = map[string]string{"*.home.arpa": "192.168.10.5"}
	s.Client.DNS.BlockAds = true
	s.Client.DNS.BlockExternal53 = true
	s.Client.DNS.BlacklistDomains = []string{"blocked.example.org"}
	s.Client.DNS.WhitelistDomains = []string{"direct.example.org"}
	s.Client.Routing.AppleNodeID = "tcp-1"
	s.Client.Routing.SteamProxy = false

	opts := RenderOptions{
		StateDir:           "/etc/dex",
		InitSystem:         "openrc",
		DomainsAppleExists: true,
		DomainsGamesExists: true,
		ResolvedHostIPs: map[string][]netip.Addr{
			"cloudflare-dns.com":  {netip.MustParseAddr("104.16.248.249")},
			"blocked.example.org": {netip.MustParseAddr("198.51.100.11")},
			"direct.example.org":  {netip.MustParseAddr("198.51.100.12")},
		},
		ChnRouteCIDRs: []string{"1.0.1.0/24"},
	}

	bundle, err := RenderAll(s, opts)
	if err != nil {
		t.Fatalf("RenderAll client: %v", err)
	}

	// Verify xray.json
	xf, _ := findFile(bundle, "xray.json")
	xrayStr := string(xf.Content)
	if strings.Contains(xrayStr, `"allowInsecure": true`) {
		t.Fatalf("xray.json must never emit allowInsecure: true:\n%s", xrayStr)
	}
	var xcfg map[string]any
	if err := json.Unmarshal(xf.Content, &xcfg); err != nil {
		t.Fatalf("unmarshal xray.json: %v", err)
	}

	// Check vmess-tcp outbound, tproxy-in-v6, forward0 vmess-tcp, directOut, pinnedPeerCertSha256
	inbs := xcfg["inbounds"].([]any)
	hasTProxyV6, hasFWD0VMess := false, false
	for _, raw := range inbs {
		m := raw.(map[string]any)
		if m["tag"] == "tproxy-in-v6" && m["listen"] == "::1" {
			hasTProxyV6 = true
		}
		if m["tag"] == "forward0" && m["protocol"] == "vmess" {
			stream := m["streamSettings"].(map[string]any)
			if stream["network"] == "tcp" && stream["security"] == nil {
				hasFWD0VMess = true
			}
		}
	}
	if !hasTProxyV6 || !hasFWD0VMess {
		t.Fatalf("missing tproxy-in-v6 (%v) or forward0 vmess-tcp (%v)", hasTProxyV6, hasFWD0VMess)
	}

	obs := xcfg["outbounds"].([]any)
	hasDefaultVMessTCP, hasDirectOut, hasReversePCS := false, false, false
	for _, raw := range obs {
		m := raw.(map[string]any)
		switch m["tag"] {
		case "default":
			stream := m["streamSettings"].(map[string]any)
			sock := stream["sockopt"].(map[string]any)
			if m["protocol"] == "vmess" && stream["network"] == "tcp" && stream["security"] == nil && sock["mark"] == float64(255) {
				hasDefaultVMessTCP = true
			}
		case "directOut":
			if m["protocol"] == "freedom" {
				hasDirectOut = true
			}
		case "reverseTunnel":
			tls := m["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
			if tls["serverName"] == "tun.example.com" && tls["pinnedPeerCertSha256"] == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
				hasReversePCS = true
			}
		}
	}
	if !hasDefaultVMessTCP || !hasDirectOut || !hasReversePCS {
		t.Fatalf("missing outbound expectations: default=%v directOut=%v reversePCS=%v", hasDefaultVMessTCP, hasDirectOut, hasReversePCS)
	}

	// Verify routing order: bridge mapping0 (with ip 127.0.0.1) before directOut; whitelist -> direct; blacklist -> default
	rules := xcfg["routing"].(map[string]any)["rules"].([]any)
	mapIdx, directOutIdx, whiteIdx, blackIdx := -1, -1, -1, -1
	for i, raw := range rules {
		r := raw.(map[string]any)
		switch r["outboundTag"] {
		case "mapping0":
			mapIdx = i
			ips, _ := r["ip"].([]any)
			if len(ips) != 1 || ips[0] != "127.0.0.1" {
				t.Fatalf("expected mapping0 rule ip=[\"127.0.0.1\"], got %+v", r["ip"])
			}
		case "directOut":
			directOutIdx = i
		case "direct":
			if doms, ok := r["domain"].([]any); ok && len(doms) == 1 && doms[0] == "direct.example.org" {
				whiteIdx = i
			}
		case "default":
			if doms, ok := r["domain"].([]any); ok && len(doms) == 1 && doms[0] == "blocked.example.org" {
				blackIdx = i
			}
		}
	}
	if mapIdx < 0 || directOutIdx < 0 || mapIdx >= directOutIdx || whiteIdx < 0 || blackIdx < 0 {
		t.Fatalf("unexpected routing indices: map=%d directOut=%d white=%d black=%d", mapIdx, directOutIdx, whiteIdx, blackIdx)
	}

	// Verify BlacklistDomains/WhitelistDomains appear before default Apple/Steam direct rules
	sDefaultApple := *s
	sDefaultApple.Client.Routing.AppleNodeID = ""
	sDefaultApple.Client.Routing.SteamProxy = false
	xfDef, _, err := RenderXray(&sDefaultApple, opts)
	if err != nil {
		t.Fatalf("RenderXray default apple: %v", err)
	}
	var xcfgDef map[string]any
	_ = json.Unmarshal(xfDef, &xcfgDef)
	defRules := xcfgDef["routing"].(map[string]any)["rules"].([]any)
	defBlackIdx, defAppleIdx, defSteamIdx := -1, -1, -1
	for i, raw := range defRules {
		r := raw.(map[string]any)
		if doms, ok := r["domain"].([]any); ok && len(doms) > 0 {
			switch doms[0] {
			case "blocked.example.org":
				defBlackIdx = i
			case "geosite:apple":
				defAppleIdx = i
			case "domain:steamserver.net":
				defSteamIdx = i
			}
		}
	}
	if defBlackIdx < 0 || defAppleIdx < 0 || defSteamIdx < 0 || defBlackIdx >= defAppleIdx || defBlackIdx >= defSteamIdx {
		t.Fatalf("expected blacklist rule before default Apple/Steam direct rules: black=%d apple=%d steam=%d", defBlackIdx, defAppleIdx, defSteamIdx)
	}

	// Check vmess-tcp BuildNodeURI & BuildFWDURI
	tcpURI := BuildNodeURI(s.Client.Nodes[0])
	if !strings.HasPrefix(tcpURI, "vmess://") {
		t.Fatalf("expected vmess:// URI, got %q", tcpURI)
	}
	rawJSON, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(tcpURI, "vmess://"))
	if err != nil || !strings.Contains(string(rawJSON), `"net":"tcp"`) || !strings.Contains(string(rawJSON), `"tls":""`) {
		t.Fatalf("unexpected vmess-tcp URI payload: %s err=%v", string(rawJSON), err)
	}
	s.Client.DDNS.Domain = "home.example.com"
	fwdURI := BuildFWDURI(s, "fwd0", "")
	if !strings.HasPrefix(fwdURI, "vmess://") {
		t.Fatalf("expected BuildFWDURI vmess:// for vmess-tcp FWD0, got %q", fwdURI)
	}

	// Check MosDNS config
	mf, _ := findFile(bundle, "mosdns/mosdns.yaml")
	mStr := string(mf.Content)
	for _, needle := range []string{
		`"[2400:3200::1]:53"`,
		`"https://dns.example.com/dq"`,
		`"quic://dns.adguard-dns.com"`,
		`listen: "[::]:53"`,
	} {
		if !strings.Contains(mStr, needle) {
			t.Errorf("mosdns.yaml missing %q", needle)
		}
	}
	whitePos := strings.Index(mStr, "domains_white.txt")
	adsPos := strings.Index(mStr, "Domains.ads.txt")
	applePos := strings.Index(mStr, "Domains.apple.txt")
	gamesPos := strings.Index(mStr, "Domains.games.txt")
	chnPos := strings.Index(mStr, "Domains.chn.txt")
	if whitePos < 0 || adsPos < 0 || whitePos > adsPos {
		t.Fatalf("expected domains_white.txt before Domains.ads.txt: white=%d ads=%d", whitePos, adsPos)
	}
	if applePos < 0 || gamesPos < 0 || chnPos < 0 || applePos > chnPos || gamesPos > chnPos {
		t.Fatalf("expected Apple/Games before Domains.chn.txt: apple=%d games=%d chn=%d", applePos, gamesPos, chnPos)
	}
	hf, _ := findFile(bundle, "mosdns/hosts.txt")
	if !strings.Contains(string(hf.Content), "domain:home.arpa 192.168.10.5") {
		t.Fatalf("expected wildcard converted to domain:home.arpa in hosts.txt:\n%s", string(hf.Content))
	}

	// Check nftables: block_external_53, cloudflare 104.16.248.249 excluded, list_b/list_w populated
	nf, _ := findFile(bundle, "nftables.conf")
	nStr := string(nf.Content)
	if !strings.Contains(nStr, "meta l4proto { tcp, udp } th dport 53 drop") {
		t.Fatalf("missing block_external_53 rule in nftables.conf")
	}
	if strings.Contains(nStr, "104.16.248.249") {
		t.Fatalf("expected cloudflare DoH IP 104.16.248.249 excluded from @global_dns_v4")
	}
	if !strings.Contains(nStr, "198.51.100.11") || !strings.Contains(nStr, "198.51.100.12") {
		t.Fatalf("expected resolved blacklist/whitelist domain IPs in nftables.conf")
	}

	// Check OpenRC units
	if mosUnit, ok := findFile(bundle, "openrc/dex-mosdns"); !ok || mosUnit.TargetPath != "/etc/init.d/dex-mosdns" {
		t.Fatalf("missing openrc/dex-mosdns unit")
	}
	nftUnit, ok := findFile(bundle, "openrc/dex-nft")
	if !ok || !strings.Contains(string(nftUnit.Content), "table 220") || !strings.Contains(string(nftUnit.Content), "ip -6 route replace local default dev lo table 220") {
		t.Fatalf("openrc/dex-nft missing IPv4/IPv6 table 220 policy routing:\n%s", string(nftUnit.Content))
	}

	// 2. Server with vmess-ws, NginxLegacyHTTP2, RproxyS InUUIDs + Security=none
	srv := state.NewDefaultState(state.RoleServer)
	srv.Server.Protocol = "vmess-ws"
	srv.Server.TLSMode = "nginx"
	srv.Server.Domain = "ws.example.com"
	srv.Server.ListenPort = 443
	srv.Server.Path = "/ws-main"
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	srv.RproxyS = state.RproxySConfig{
		Enabled:    true,
		ListenPort: 20000,
		Security:   "none",
		UUIDs:      []string{"22222222-2222-4222-8222-222222222222"},
		InUUIDs:    []string{"33333333-3333-4333-8333-333333333333"},
	}
	sBundle, err := RenderAll(srv, RenderOptions{NginxLegacyHTTP2: true})
	if err != nil {
		t.Fatalf("RenderAll server vmess-ws: %v", err)
	}
	ngf, _ := findFile(sBundle, "nginx-dex.conf")
	ngStr := string(ngf.Content)
	if !strings.Contains(ngStr, "listen 443 ssl http2;") || !strings.Contains(ngStr, "Upgrade $http_upgrade;") || !strings.Contains(ngStr, `Connection "upgrade";`) {
		t.Fatalf("expected legacy http2 + WS upgrade headers in nginx-dex.conf:\n%s", ngStr)
	}
	sxf, _ := findFile(sBundle, "xray.json")
	var sxcfg map[string]any
	_ = json.Unmarshal(sxf.Content, &sxcfg)
	sInbs := sxcfg["inbounds"].([]any)
	mainInb := sInbs[0].(map[string]any)
	if mainInb["protocol"] != "vmess" || mainInb["streamSettings"].(map[string]any)["network"] != "ws" {
		t.Fatalf("expected server main inbound vmess+ws, got %+v", mainInb)
	}
	rpsInb := sInbs[1].(map[string]any)
	if rpsInb["streamSettings"].(map[string]any)["security"] != "none" {
		t.Fatalf("expected RproxyS security=none, got %+v", rpsInb["streamSettings"])
	}
	if len(rpsInb["settings"].(map[string]any)["clients"].([]any)) != 2 {
		t.Fatalf("expected 2 clients in rps-tunnel (tunnel + in_uuid)")
	}
	mainURI := BuildServerMainURI(srv)
	if !strings.HasPrefix(mainURI, "vmess://") {
		t.Fatalf("expected vmess:// BuildServerMainURI for vmess-ws, got %q", mainURI)
	}
}

func TestWave2ParseNodeURIWGIPAndTimers(t *testing.T) {
	// 1. ParseNodeURI round-trips across all 6 protocols
	cases := []state.OutboundNode{
		{
			Name:     "xhttp1",
			Protocol: "vless-xhttp",
			Address:  "x.example.com",
			Port:     443,
			UUID:     "11111111-1111-4111-8111-111111111111",
			TLSSNI:   "sni.example.com",
			Path:     "/xhttp-path",
		},
		{
			Name:           "real1",
			Protocol:       "vless-reality",
			Address:        "198.51.100.10",
			Port:           2443,
			UUID:           "22222222-2222-4222-8222-222222222222",
			TLSSNI:         "www.apple.com",
			RealityPubKey:  "pubkey123",
			RealityShortID: "abcd",
		},
		{
			Name:     "vlessws1",
			Protocol: "vless-ws",
			Address:  "ws.example.com",
			Port:     8443,
			UUID:     "33333333-3333-4333-8333-333333333333",
			TLSSNI:   "ws.example.com",
			Path:     "/vws",
		},
		{
			Name:     "vmessws1",
			Protocol: "vmess-ws",
			Address:  "vm.example.com",
			Port:     443,
			UUID:     "44444444-4444-4444-8444-444444444444",
			TLSSNI:   "vm.example.com",
			Path:     "/vmws",
		},
		{
			Name:     "vmesstcp1",
			Protocol: "vmess-tcp",
			Address:  "198.51.100.20",
			Port:     9800,
			UUID:     "55555555-5555-4555-8555-555555555555",
		},
		{
			Name:     "socks1",
			Protocol: "socks5",
			Address:  "127.0.0.1",
			Port:     1080,
			Username: "u1",
			Password: "p1",
		},
	}
	for _, tc := range cases {
		uri := BuildNodeURI(tc)
		got, err := ParseNodeURI(uri)
		if err != nil {
			t.Fatalf("ParseNodeURI(%s): %v (uri=%q)", tc.Protocol, err, uri)
		}
		if got.Protocol != tc.Protocol || got.Address != tc.Address || got.Port != tc.Port || got.UUID != tc.UUID {
			t.Fatalf("round-trip mismatch for %s: got=%+v want=%+v", tc.Protocol, got, tc)
		}
	}

	// 2. NextAvailableWGIP fills gaps cleanly
	ip, err := NextAvailableWGIP("172.16.66.1/24", []state.WGPeer{
		{Name: "p1", IP: "172.16.66.11"},
		{Name: "p3", IP: "172.16.66.13"},
	})
	if err != nil || ip != "172.16.66.12" {
		t.Fatalf("expected gap IP 172.16.66.12, got %q err=%v", ip, err)
	}

	// 3. Refresh timer (4h vs 5min) and AutoUpdateCore timer
	c := state.NewDefaultState(state.RoleClient)
	c.System.AutoUpdateCore = true
	c.Client.Nodes = []state.OutboundNode{{
		ID: "n1", Protocol: "vless-xhttp", Address: "node.example.com", Port: 443,
		UUID: "11111111-1111-4111-8111-111111111111",
	}}
	bDom, err := RenderAll(c, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderAll domain client: %v", err)
	}
	if !bDom.RefreshTimerNeeded || bDom.RefreshInterval != "4h" || !bDom.CoreUpdateTimerNeeded {
		t.Fatalf("expected RefreshTimerNeeded(4h) & CoreUpdateTimerNeeded, got %+v", bDom)
	}
	if refT, ok := findFile(bDom, "systemd/dex-refresh.timer"); !ok || !strings.Contains(string(refT.Content), "OnUnitActiveSec=4h") {
		t.Fatalf("expected 4h refresh timer unit")
	}
	if updT, ok := findFile(bDom, "systemd/dex-core-update.timer"); !ok || !strings.Contains(string(updT.Content), "OnCalendar=weekly") {
		t.Fatalf("expected dex-core-update.timer unit")
	}

	c.Relay.Forwards = []state.ForwardRule{{
		ID: "r1", ListenPort: 10001, TargetHost: "relay.example.com", TargetPort: 443, Proto: "tcp", Engine: "nft",
	}}
	bRelay, err := RenderAll(c, RenderOptions{
		ResolvedHostIPs: map[string][]netip.Addr{
			"relay.example.com": {netip.MustParseAddr("198.51.100.99")},
		},
	})
	if err != nil {
		t.Fatalf("RenderAll relay client: %v", err)
	}
	if !bRelay.RefreshTimerNeeded || bRelay.RefreshInterval != "5min" {
		t.Fatalf("expected 5min refresh interval when NFTRelayNeeded, got %+v", bRelay)
	}
}

func TestRenderNFTablesWireGuardSubnetAndBypass(t *testing.T) {
	s := state.NewDefaultState(state.RoleClient)
	s.System.LANInterface = "eth0"
	s.System.EnableFlowtable = true
	s.Client.WireGuard = state.WireGuardConfig{
		Enabled:          true,
		EndpointHost:     "10.0.0.230",
		ListenPort:       51821,
		SubnetCIDR:       "10.66.66.1/24",
		ServerPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ServerPublicKey:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
	}

	data, clientNeeded, _, err := RenderNFTables(s, RenderOptions{PhysicalNICs: []string{"eth0"}})
	if err != nil {
		t.Fatalf("RenderNFTables: %v", err)
	}
	if !clientNeeded {
		t.Fatalf("expected clientNeeded=true")
	}
	nftStr := string(data)

	for _, needle := range []string{
		"ct state established ip daddr 10.66.66.0/24 flow offload @acceleration",
		"ct state established ip saddr 10.66.66.0/24 flow offload @acceleration",
		`oifname "eth0" ip saddr 10.66.66.0/24 masquerade`,
		"meta l4proto udp th dport 51821 accept",
		"meta l4proto udp th sport 51821 accept",
	} {
		if !strings.Contains(nftStr, needle) {
			t.Errorf("nftables.conf missing %q\n%s", needle, nftStr)
		}
	}
	if strings.Contains(nftStr, "172.16.66.0/24") {
		t.Errorf("unexpected hardcoded 172.16.66.0/24 when custom subnet configured")
	}

	// Verify prerouting has dport accept and output has sport accept in the respective chains
	preIdx := strings.Index(nftStr, "chain prerouting {")
	outIdx := strings.Index(nftStr, "chain output {")
	// Note: dex_filter also has chain output, so find the dex_client chain output (type route hook output)
	dexClientIdx := strings.Index(nftStr, "table inet dex_client {")
	clientPreIdx := dexClientIdx + strings.Index(nftStr[dexClientIdx:], "chain prerouting {")
	clientOutIdx := dexClientIdx + strings.Index(nftStr[dexClientIdx:], "chain output {")
	if dexClientIdx < 0 || preIdx < 0 || outIdx < 0 || clientPreIdx >= clientOutIdx {
		t.Fatalf("unexpected dex_client layout")
	}
	preSection := nftStr[clientPreIdx:clientOutIdx]
	outSection := nftStr[clientOutIdx:]
	if !strings.Contains(preSection, "meta l4proto udp th dport 51821 accept") {
		t.Errorf("dex_client prerouting missing dport 51821 accept")
	}
	if !strings.Contains(outSection, "meta l4proto udp th sport 51821 accept") {
		t.Errorf("dex_client output missing sport 51821 accept")
	}

	// Fallback when SubnetCIDR is invalid/empty
	s.Client.WireGuard.SubnetCIDR = "not-a-cidr"
	fallbackData, _, _, err := RenderNFTables(s, RenderOptions{PhysicalNICs: []string{"eth0"}})
	if err != nil {
		t.Fatalf("RenderNFTables fallback: %v", err)
	}
	if !strings.Contains(string(fallbackData), `oifname "eth0" ip saddr 172.16.66.0/24 masquerade`) {
		t.Errorf("expected fallback 172.16.66.0/24 in dex_nat")
	}
}

func TestRenderSystemdDexNFTExecStopIPv6Cleanup(t *testing.T) {
	s := state.NewDefaultState(state.RoleClient)
	s.System.EnableIPv6 = true
	b := &RenderBundle{NFTClientNeeded: true}
	files := RenderUnits(s, RenderOptions{InitSystem: "systemd"}, b)
	var nftUnit RenderedFile
	found := false
	for _, f := range files {
		if f.RelName == "systemd/dex-nft.service" {
			nftUnit = f
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing systemd/dex-nft.service")
	}
	content := string(nftUnit.Content)
	for _, needle := range []string{
		"ip rule del fwmark 0x9 table 220 priority 100",
		"ip route del local default dev lo table 220",
		"ip -6 rule del fwmark 0x9 table 220 priority 100",
		"ip -6 route del local default dev lo table 220",
	} {
		if !strings.Contains(content, needle) {
			t.Errorf("systemd/dex-nft.service ExecStop missing %q\n%s", needle, content)
		}
	}
}

func TestHardeningServerSSRFRelayAndClientFreedom(t *testing.T) {
	// 1. RoleServer (with Socks5 PrivateBypass=true, dokodemo, rproxys, and relay fwd):
	//    - direct outbound uses block-then-allow finalRules
	//    - routing has ssrf-block-private & ssrf-block-localhost -> blocked after dokodemo/rps rules
	//    - no rule routes xrayPrivateCIDRs to "direct"
	//    - fwd-* and dokodemo route to outbound-dokodemo (which keeps allow-all freedomFinalRules)
	srv := state.NewDefaultState(state.RoleServer)
	srv.Server.TLSMode = "nginx"
	srv.Server.Domain = "srv.example.com"
	srv.Server.ListenPort = 443
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	srv.Server.Socks5Outbounds = []state.Socks5Profile{{
		Name:          "default",
		Enabled:       true,
		Address:       "socks.example.net",
		Port:          1080,
		PrivateBypass: true,
	}}
	srv.RproxyS = state.RproxySConfig{
		Enabled:    true,
		ListenPort: 20000,
		UUIDs:      []string{"22222222-2222-4222-8222-222222222222"},
		InUUIDs:    []string{"33333333-3333-4333-8333-333333333333"},
	}
	srv.ExtraInbounds = []state.ExtraInbound{{
		Tag:        "doko-1",
		Protocol:   "dokodemo",
		ListenPort: 10053,
		TargetAddr: "1.1.1.1",
		TargetPort: 53,
		Network:    "udp",
	}}
	srv.Relay.Forwards = []state.ForwardRule{{
		ID:         "fwd-1",
		ListenPort: 10080,
		TargetHost: "10.0.0.5",
		TargetPort: 80,
		Proto:      "tcp",
		Engine:     "xray",
	}}

	xb, needed, err := RenderXray(srv, RenderOptions{})
	if err != nil || !needed {
		t.Fatalf("RenderXray server: err=%v needed=%v", err, needed)
	}
	var cfg map[string]any
	if err := json.Unmarshal(xb, &cfg); err != nil {
		t.Fatalf("unmarshal xray: %v", err)
	}
	obs := cfg["outbounds"].([]any)
	var directFR, dokoFR []any
	for _, raw := range obs {
		m := raw.(map[string]any)
		switch m["tag"] {
		case "direct":
			directFR = m["settings"].(map[string]any)["finalRules"].([]any)
		case "outbound-dokodemo":
			dokoFR = m["settings"].(map[string]any)["finalRules"].([]any)
		}
	}
	if len(directFR) != 2 || directFR[0].(map[string]any)["action"] != "block" || directFR[1].(map[string]any)["action"] != "allow" {
		t.Fatalf("server direct outbound must block private CIDRs before allow, got %+v", directFR)
	}
	blockIPs := directFR[0].(map[string]any)["ip"].([]any)
	for _, wantCIDR := range []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "ff00::/8"} {
		found := false
		for _, got := range blockIPs {
			if got == wantCIDR {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("server direct finalRules block missing %q", wantCIDR)
		}
	}
	if len(dokoFR) != 1 || dokoFR[0].(map[string]any)["action"] != "allow" {
		t.Fatalf("outbound-dokodemo must preserve allow-all finalRules, got %+v", dokoFR)
	}

	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	dokoIdx, rpsIdx, privIdx, localhostIdx := -1, -1, -1, -1
	for i, raw := range rules {
		r := raw.(map[string]any)
		if r["outboundTag"] == "outbound-dokodemo" {
			dokoIdx = i
			inbs := r["inboundTag"].([]any)
			if len(inbs) != 2 {
				t.Fatalf("expected doko-1 and fwd-10080 routed to outbound-dokodemo, got %+v", inbs)
			}
		}
		if r["outboundTag"] == "portal" {
			rpsIdx = i
		}
		if r["ruleTag"] == "socks5-exit-private-direct" {
			t.Fatalf("unexpected PrivateBypass rule routing private CIDRs to direct")
		}
		if r["ruleTag"] == "ssrf-block-private" && r["outboundTag"] == "blocked" {
			privIdx = i
		}
		if r["ruleTag"] == "ssrf-block-localhost" && r["outboundTag"] == "blocked" {
			localhostIdx = i
		}
	}
	if dokoIdx < 0 || rpsIdx < 0 || privIdx < 0 || localhostIdx < 0 || dokoIdx > privIdx || rpsIdx > privIdx {
		t.Fatalf("unexpected server SSRF rule indices: doko=%d rps=%d priv=%d localhost=%d", dokoIdx, rpsIdx, privIdx, localhostIdx)
	}

	// 2. RoleRelay direct outbound also blocks SSRF while fwd-* uses outbound-dokodemo
	rel := state.NewDefaultState(state.RoleRelay)
	rel.Relay.Forwards = []state.ForwardRule{{
		ID: "f1", ListenPort: 10001, TargetHost: "198.51.100.2", TargetPort: 443, Proto: "tcp", Engine: "xray",
	}}
	rxb, rNeeded, err := RenderXray(rel, RenderOptions{})
	if err != nil || !rNeeded {
		t.Fatalf("RenderXray relay: err=%v needed=%v", err, rNeeded)
	}
	var rcfg map[string]any
	_ = json.Unmarshal(rxb, &rcfg)
	for _, raw := range rcfg["outbounds"].([]any) {
		m := raw.(map[string]any)
		if m["tag"] == "direct" {
			fr := m["settings"].(map[string]any)["finalRules"].([]any)
			if fr[0].(map[string]any)["action"] != "block" {
				t.Fatalf("relay direct outbound must use serverDirectFreedomOutbound, got %+v", fr)
			}
		}
	}
}

func TestHardeningMosDNSDoHLoopNodeFallbackIPv6AndMultiViaNginx(t *testing.T) {
	// 1. Client with EnableIPv6=false, custom DoH domain + IP DoH, vmess-tcp FWD0, malicious resolved node IPs
	c := state.NewDefaultState(state.RoleClient)
	c.System.EnableIPv6 = false
	c.System.AutoTuneSysctl = true
	c.Client.WireGuard = state.WireGuardConfig{
		Enabled:          true,
		EndpointHost:     "vpn.example.com",
		ListenPort:       51820,
		SubnetCIDR:       "172.16.66.1/24",
		ServerPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ServerPublicKey:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
	}
	c.Client.Nodes = []state.OutboundNode{{
		ID: "n1", Protocol: "vless-xhttp", Address: "evil-node.example.com", Port: 443,
		UUID: "11111111-1111-4111-8111-111111111111",
	}}
	c.Client.ActiveNodeID = "n1"
	c.Client.FWD0 = state.FWD0Config{
		Enabled:  true,
		Protocol: "vmess-tcp",
		Port:     1443,
		UUIDs:    []string{"22222222-2222-4222-8222-222222222222"},
	}
	c.Client.DNS.DoHServers = []string{
		"https://doh.custom.example/dq",
		"https://1.1.1.1/dns-query",
	}

	bundle, err := RenderAll(c, RenderOptions{
		StateDir: "/tmp/dex-h",
		ResolvedHostIPs: map[string][]netip.Addr{
			"evil-node.example.com": {
				netip.MustParseAddr("127.0.0.1"),
				netip.MustParseAddr("169.254.169.254"),
				netip.MustParseAddr("::1"),
				netip.MustParseAddr("fe80::1"),
				netip.MustParseAddr("224.0.0.1"),
				netip.MustParseAddr("203.0.113.88"),
			},
			"doh.custom.example": {netip.MustParseAddr("203.0.113.99")},
		},
	})
	if err != nil {
		t.Fatalf("RenderAll client: %v", err)
	}

	// MosDNS: domains_doh.txt + forward_chn before domains_black/global_sequence + node_fallback
	dohFile, ok := findFile(bundle, "mosdns/domains_doh.txt")
	if !ok {
		t.Fatalf("missing mosdns/domains_doh.txt")
	}
	if strings.TrimSpace(string(dohFile.Content)) != "doh.custom.example" {
		t.Fatalf("expected only non-IP DoH domain in domains_doh.txt, got %q", string(dohFile.Content))
	}
	mf, _ := findFile(bundle, "mosdns/mosdns.yaml")
	mStr := string(mf.Content)
	for _, needle := range []string{
		"tag: node_fallback",
		"primary: global_sequence",
		"secondary: forward_chn",
		"threshold: 1500",
		"always_standby: false",
		"domains_doh.txt\n        exec: $forward_chn",
		"domains_nodes.txt\n        exec: $node_fallback",
	} {
		if !strings.Contains(mStr, needle) {
			t.Errorf("mosdns.yaml missing %q\n%s", needle, mStr)
		}
	}
	dohPos := strings.Index(mStr, "domains_doh.txt")
	blackPos := strings.Index(mStr, "domains_black.txt")
	if dohPos < 0 || blackPos < 0 || dohPos > blackPos {
		t.Fatalf("expected domains_doh.txt before domains_black.txt (doh=%d black=%d)", dohPos, blackPos)
	}

	// Sysctl: explicit IPv6 forwarding = 0 when disabled
	sf, _ := findFile(bundle, "sysctl-99-dex.conf")
	sStr := string(sf.Content)
	if !strings.Contains(sStr, "net.ipv6.conf.all.forwarding = 0") || !strings.Contains(sStr, "net.ipv6.conf.default.forwarding = 0") {
		t.Fatalf("expected IPv6 forwarding disabled in sysctl:\n%s", sStr)
	}

	// NFTables: IPv6 reject before wg0 accept in chain forward; restricted resolved node IPs filtered from v2node sets
	nf, _ := findFile(bundle, "nftables.conf")
	nStr := string(nf.Content)
	fwdStart := strings.Index(nStr, "chain forward {")
	if fwdStart < 0 {
		t.Fatalf("missing chain forward in nftables.conf")
	}
	fwdSection := nStr[fwdStart:]
	rejNeedle := "meta nfproto ipv6 ip6 daddr != { ::1/128, fc00::/7, fe80::/10, ff00::/8 } counter reject"
	rejPos := strings.Index(fwdSection, rejNeedle)
	wgPos := strings.Index(fwdSection, `iifname "wg0" accept`)
	if rejPos < 0 || wgPos < 0 || rejPos > wgPos {
		t.Fatalf("expected IPv6 reject rule before wg0 accept in chain forward: rej=%d wg=%d\n%s", rejPos, wgPos, fwdSection)
	}
	v2nodeIdx := strings.Index(nStr, "set v2node_v4 {")
	v2nodeEnd := v2nodeIdx + strings.Index(nStr[v2nodeIdx:], "set chnroute_v4 {")
	v2Section := nStr[v2nodeIdx:v2nodeEnd]
	for _, badIP := range []string{"127.0.0.1", "169.254.169.254", "::1", "fe80::1", "224.0.0.1"} {
		if strings.Contains(v2Section, badIP) {
			t.Errorf("restricted IP %q leaked into v2node sets:\n%s", badIP, v2Section)
		}
	}
	if !strings.Contains(v2Section, "203.0.113.88") {
		t.Errorf("expected valid node IP 203.0.113.88 in v2node_v4:\n%s", v2Section)
	}

	// Xray FWD0 vmess-tcp has sniffing enabled
	xf, _ := findFile(bundle, "xray.json")
	var xcfg map[string]any
	_ = json.Unmarshal(xf.Content, &xcfg)
	foundFWD0 := false
	for _, raw := range xcfg["inbounds"].([]any) {
		m := raw.(map[string]any)
		if m["tag"] == "forward0" {
			foundFWD0 = true
			sniff, ok := m["sniffing"].(map[string]any)
			if !ok || sniff["enabled"] != true || sniff["routeOnly"] != true {
				t.Fatalf("expected sniffing enabled on forward0 vmess-tcp, got %+v", m["sniffing"])
			}
		}
	}
	if !foundFWD0 {
		t.Fatalf("missing forward0 inbound")
	}

	// 2. Multi via_nginx on :443 renders matching internal ports in xray.json and nginx-dex.conf
	srv := state.NewDefaultState(state.RoleServer)
	srv.Server.TLSMode = "nginx"
	srv.Server.Domain = "main.example.com"
	srv.Server.ListenPort = 443
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	srv.ExtraInbounds = []state.ExtraInbound{
		{Tag: "vn-a", Protocol: "vless-xhttp", ListenPort: 443, Domain: "a.example.com", UUID: "22222222-2222-4222-8222-222222222222", ViaNginx: true},
		{Tag: "vn-b", Protocol: "vless-ws", ListenPort: 443, Domain: "b.example.com", UUID: "33333333-3333-4333-8333-333333333333", ViaNginx: true},
	}
	sBundle, err := RenderAll(srv, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderAll multi via_nginx: %v", err)
	}
	ngf, _ := findFile(sBundle, "nginx-dex.conf")
	ngStr := string(ngf.Content)
	if !strings.Contains(ngStr, "proxy_pass http://127.0.0.1:10443;") || !strings.Contains(ngStr, "proxy_pass http://127.0.0.1:10444;") {
		t.Fatalf("expected 10443 and 10444 in nginx-dex.conf:\n%s", ngStr)
	}
	sxf, _ := findFile(sBundle, "xray.json")
	var sxcfg map[string]any
	_ = json.Unmarshal(sxf.Content, &sxcfg)
	portsByTag := map[string]float64{}
	for _, raw := range sxcfg["inbounds"].([]any) {
		m := raw.(map[string]any)
		portsByTag[m["tag"].(string)] = m["port"].(float64)
	}
	if portsByTag["vn-a"] != 10443 || portsByTag["vn-b"] != 10444 {
		t.Fatalf("expected vn-a=10443 and vn-b=10444 in xray.json, got %+v", portsByTag)
	}
}

func TestHardeningWGPeerCollisionRelayTagsIPv6RproxyAndNginxDualStack(t *testing.T) {
	// 1. WireGuard Chinese / colliding peer names produce 100% unique TargetPath
	wgState := state.NewDefaultState(state.RoleClient)
	wgState.Client.WireGuard = state.WireGuardConfig{
		Enabled:          true,
		EndpointHost:     "wg.example.com",
		ListenPort:       51820,
		SubnetCIDR:       "172.16.66.1/24",
		ServerPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		ServerPublicKey:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		Peers: []state.WGPeer{
			{Name: "手机", IP: "172.16.66.11", PrivateKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=", PublicKey: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="},
			{Name: "平板", IP: "172.16.66.12", PrivateKey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=", PublicKey: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF="},
			{Name: "phone!", IP: "172.16.66.13", PrivateKey: "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG=", PublicKey: "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH="},
			{Name: "phone?", IP: "172.16.66.14", PrivateKey: "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII=", PublicKey: "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ="},
		},
	}
	wgFiles, needed, err := RenderWireGuard(wgState, RenderOptions{})
	if err != nil || !needed {
		t.Fatalf("RenderWireGuard: err=%v needed=%v", err, needed)
	}
	seenPaths := make(map[string]bool)
	for _, f := range wgFiles {
		if seenPaths[f.TargetPath] {
			t.Fatalf("duplicate WireGuard TargetPath %q", f.TargetPath)
		}
		seenPaths[f.TargetPath] = true
	}
	if len(wgFiles) != 5 {
		t.Fatalf("expected 5 rendered WG files, got %d", len(wgFiles))
	}

	// 2. Xray relay forwards on same port (TCP + UDP) get unique tags from fwd.ID + RproxyC IPv6 bracket formatting
	cli := state.NewDefaultState(state.RoleClient)
	cli.Client.Nodes = []state.OutboundNode{{
		ID:       "n1",
		Name:     "Primary",
		Protocol: "vless-xhttp",
		Address:  "1.1.1.1",
		Port:     443,
		UUID:     "11111111-1111-4111-8111-111111111111",
	}}
	cli.Client.ActiveNodeID = "n1"
	cli.Client.RproxyC = state.RproxyCConfig{
		Enabled:       true,
		TunnelAddress: "rps.example.com",
		TunnelPort:    20000,
		TunnelUUID:    "11111111-1111-4111-8111-111111111111",
		Mappings: []state.RproxyClientMapping{
			{ExtPort: 20080, Proto: "tcp", IntIP: "fd00::10", IntPort: 8080},
		},
	}
	cli.Relay.Forwards = []state.ForwardRule{
		{ID: "fwd-10001", ListenPort: 10001, TargetHost: "8.8.8.8", TargetPort: 53, Proto: "tcp", Engine: "xray"},
		{ID: "fwd-udp-10001", ListenPort: 10001, TargetHost: "8.8.8.8", TargetPort: 53, Proto: "udp", Engine: "xray"},
	}
	xb, needed, err := RenderXray(cli, RenderOptions{})
	if err != nil || !needed {
		t.Fatalf("RenderXray: err=%v needed=%v", err, needed)
	}
	var xcfg map[string]any
	_ = json.Unmarshal(xb, &xcfg)
	inbTags := make(map[string]bool)
	for _, raw := range xcfg["inbounds"].([]any) {
		tag := raw.(map[string]any)["tag"].(string)
		if inbTags[tag] {
			t.Fatalf("duplicate xray inbound tag %q", tag)
		}
		inbTags[tag] = true
	}
	if !inbTags["fwd-10001"] || !inbTags["fwd-udp-10001"] {
		t.Fatalf("expected distinct fwd tags in xray inbounds, got %+v", inbTags)
	}
	foundIPv6Redirect := false
	for _, raw := range xcfg["outbounds"].([]any) {
		m := raw.(map[string]any)
		if m["tag"] == "mapping0" {
			redir := m["settings"].(map[string]any)["redirect"]
			if redir == "[fd00::10]:8080" {
				foundIPv6Redirect = true
			}
		}
	}
	if !foundIPv6Redirect {
		t.Fatalf("expected IPv6 RproxyC redirect [fd00::10]:8080 in xray outbounds")
	}

	// 3. RenderNginx dual-stack IPv6 listen directives when EnableIPv6=true vs IPv4-only when false
	srv := state.NewDefaultState(state.RoleServer)
	srv.Server.Domain = "srv.example.com"
	srv.Server.TLSMode = "nginx"
	srv.Server.ListenPort = 443
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	srv.ExtraInbounds = []state.ExtraInbound{{
		Tag:        "vn-extra",
		Protocol:   "vless-ws",
		ListenPort: 8444,
		Domain:     "extra.example.com",
		UUID:       "22222222-2222-4222-8222-222222222222",
		ViaNginx:   true,
	}}
	ngV4, _, err := RenderNginx(srv, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderNginx v4: %v", err)
	}
	if strings.Contains(string(ngV4), "[::]:") {
		t.Fatalf("expected no IPv6 listen when EnableIPv6=false, got:\n%s", string(ngV4))
	}
	srv.System.EnableIPv6 = true
	ngDual, _, err := RenderNginx(srv, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderNginx dual-stack: %v", err)
	}
	ngDualStr := string(ngDual)
	for _, want := range []string{"listen [::]:80;", "listen [::]:443 ssl;", "listen [::]:8444 ssl;"} {
		if !strings.Contains(ngDualStr, want) {
			t.Fatalf("expected %q in dual-stack nginx config:\n%s", want, ngDualStr)
		}
	}
	ngLegacyDual, _, err := RenderNginx(srv, RenderOptions{NginxLegacyHTTP2: true})
	if err != nil {
		t.Fatalf("RenderNginx legacy dual-stack: %v", err)
	}
	if !strings.Contains(string(ngLegacyDual), "listen [::]:443 ssl http2;") {
		t.Fatalf("expected legacy IPv6 http2 directive:\n%s", string(ngLegacyDual))
	}
}

func TestRenderClientRproxySRuleOrderAndMosDNSNon443DialAddr(t *testing.T) {
	c := state.NewDefaultState(state.RoleClient)
	c.Client.Nodes = []state.OutboundNode{{
		ID: "n1", Protocol: "vless-ws", Address: "hnn.example.com", Port: 32087,
		UUID: "11111111-1111-4111-8111-111111111111", TLSSNI: "hnn.example.com", Path: "/ws",
	}}
	c.Client.ActiveNodeID = "n1"
	c.Client.DNS.DoHServers = []string{
		"https://hnn.example.com:32087/dq",
		"https://default-port.example.com/dq",
	}
	c.RproxyS = state.RproxySConfig{
		Enabled:    true,
		Domain:     "gw.example.com",
		ListenPort: 20000,
		UUIDs:      []string{"22222222-2222-4222-8222-222222222222"},
		InUUIDs:    []string{"33333333-3333-4333-8333-333333333333"},
		Mappings:   []state.RproxyServerMapping{{Port: 20443, Proto: "tcp"}},
	}

	ropts := RenderOptions{
		ResolvedHostIPs: map[string][]netip.Addr{
			"hnn.example.com":          {netip.MustParseAddr("198.51.100.10")},
			"default-port.example.com": {netip.MustParseAddr("198.51.100.11")},
		},
	}

	xb, xNeeded, err := RenderXray(c, ropts)
	if err != nil || !xNeeded {
		t.Fatalf("RenderXray client+RproxyS: err=%v needed=%v", err, xNeeded)
	}
	var xcfg map[string]any
	if err := json.Unmarshal(xb, &xcfg); err != nil {
		t.Fatalf("unmarshal xray: %v", err)
	}
	rules := xcfg["routing"].(map[string]any)["rules"].([]any)
	rpsMapIdx, rpsTunIdx, privIdx := -1, -1, -1
	for i, raw := range rules {
		r := raw.(map[string]any)
		if r["outboundTag"] == "portal" {
			if inbs, ok := r["inboundTag"].([]any); ok && len(inbs) > 0 {
				if inbs[0] == "rps-map-20443" {
					rpsMapIdx = i
				} else if inbs[0] == "rps-tunnel" {
					rpsTunIdx = i
				}
			}
		}
		if ips, ok := r["ip"].([]any); ok && len(ips) > 0 && ips[0] == "geoip:private" && r["outboundTag"] == "direct" {
			privIdx = i
		}
	}
	if rpsMapIdx < 0 || rpsTunIdx < 0 || privIdx < 0 || rpsMapIdx > privIdx || rpsTunIdx > privIdx {
		t.Fatalf("expected RproxyS portal rules before geoip:private direct rule, got rpsMap=%d rpsTun=%d priv=%d", rpsMapIdx, rpsTunIdx, privIdx)
	}

	mFiles, mNeeded, err := RenderMosDNS(c, ropts)
	if err != nil || !mNeeded {
		t.Fatalf("RenderMosDNS: err=%v needed=%v", err, mNeeded)
	}
	var myStr string
	for _, rf := range mFiles {
		if rf.RelName == "mosdns/mosdns.yaml" {
			myStr = string(rf.Content)
		}
	}
	if !strings.Contains(myStr, `dial_addr: "198.51.100.10:32087"`) {
		t.Fatalf("expected non-443 DoH dial_addr with :32087, got:\n%s", myStr)
	}
	if !strings.Contains(myStr, `dial_addr: "198.51.100.11"`) {
		t.Fatalf("expected default-port DoH dial_addr without port, got:\n%s", myStr)
	}
}
