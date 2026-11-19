package render

import (
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

	opts := RenderOptions{
		StateDir:     "/tmp/dex-test",
		PhysicalNICs: []string{"eth0"},
		ResolvedHostIPs: map[string][]netip.Addr{
			"hk.example.com":  {netip.MustParseAddr("203.0.113.10")},
			"tun.example.com": {netip.MustParseAddr("203.0.113.20")},
			"dns.google":      {netip.MustParseAddr("8.8.8.8")},
		},
		ChnRouteCIDRs: []string{"1.0.1.0/24"},
	}

	bundle, err := RenderAll(s, opts)
	if err != nil {
		t.Fatalf("RenderAll client: %v", err)
	}
	if !bundle.XrayNeeded || !bundle.NFTClientNeeded || !bundle.MosDNSNeeded || !bundle.WireGuardNeeded {
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

	// Verify nftables QUIC UDP/443 reject + dual-stack sets + WireGuard
	nf, ok := findFile(bundle, "nftables.conf")
	if !ok {
		t.Fatalf("missing nftables.conf")
	}
	nftStr := string(nf.Content)
	for _, needle := range []string{
		"table inet dex_client",
		"meta mark 0x8 meta l4proto udp th dport 443 counter reject",
		"203.0.113.10",
		"1.0.1.0/24",
		"tproxy ip to 127.0.0.1:9896 meta mark set 0x9",
		"tproxy ip6 to [::1]:9896 meta mark set 0x9",
		`iifname "wg0" accept`,
	} {
		if !strings.Contains(nftStr, needle) {
			t.Errorf("nftables.conf missing %q", needle)
		}
	}

	// Verify MosDNS config
	mf, ok := findFile(bundle, "mosdns/mosdns.yaml")
	if !ok || !strings.Contains(string(mf.Content), "resp_ip") {
		t.Fatalf("mosdns.yaml invalid or missing resp_ip fallback")
	}

	// Verify WireGuard peer config
	wgf, ok := findFile(bundle, "wg-peers/peer-laptop.conf")
	if !ok || !strings.Contains(string(wgf.Content), "Endpoint = home.example.com:51820") {
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
	if !strings.Contains(string(hf.Content), "server srv1 ha.example.com:443 check resolvers dex_dns init-addr none") {
		t.Fatalf("unexpected haproxy.cfg:\n%s", string(hf.Content))
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
			Name:     "sg",
			Enabled:  true,
			Address:  "sg.example.net",
			Port:     1081,
			Domains:  []string{"geosite:netflix"},
			IPs:      []string{"geoip:telegram"},
		},
	}

	bundle, err := RenderAll(s, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderAll server: %v", err)
	}
	if !bundle.XrayNeeded || !bundle.NginxNeeded || !bundle.DoHNeeded {
		t.Fatalf("expected Xray+Nginx+DoH needed: %+v", bundle)
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
	if !strings.Contains(ngStr, "location /dq") || !strings.Contains(ngStr, "location /11111111") {
		t.Fatalf("unexpected nginx-dex.conf:\n%s", ngStr)
	}
}
