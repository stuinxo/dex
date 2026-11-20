package render

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/stuinxo/de_GWD/v3/internal/state"
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
