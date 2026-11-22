package state

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStoreConcurrentLockingAndBackupRecovery(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(dir)

	initState := NewDefaultState(RoleClient)
	initState.Client.Nodes = []OutboundNode{{
		ID:       "n1",
		Name:     "Primary",
		Protocol: "vless-xhttp",
		Address:  "node.example.com",
		Port:     443,
		UUID:     "11111111-1111-4111-8111-111111111111",
	}}
	initState.Client.ActiveNodeID = "n1"
	if err := st.Save(initState); err != nil {
		t.Fatalf("Save initial: %v", err)
	}

	const workers = 12
	const iters = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*iters)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				key := fmt.Sprintf("h%d-%d.local", worker, i)
				_, err := st.Update(RoleClient, func(cur *State) error {
					cur.Client.DNS.Hosts[key] = "192.168.1.2"
					return nil
				})
				if err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent update error: %v", err)
	}

	loaded, err := st.Load()
	if err != nil {
		t.Fatalf("Load after concurrent updates: %v", err)
	}
	if len(loaded.Client.DNS.Hosts) != workers*iters {
		t.Fatalf("lost concurrent host writes: got %d, want %d", len(loaded.Client.DNS.Hosts), workers*iters)
	}

	info, err := os.Stat(st.StatePath())
	if err != nil {
		t.Fatalf("stat state.json: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state.json perm = %o, want 0600", info.Mode().Perm())
	}

	// Corrupt primary state.json and verify Load falls back to state.json.bak
	if err := os.WriteFile(st.StatePath(), []byte("{corrupt json"), 0o600); err != nil {
		t.Fatalf("corrupt state.json: %v", err)
	}
	recovered, err := st.Load()
	if err != nil {
		t.Fatalf("Load backup fallback failed: %v", err)
	}
	if recovered.Client.ActiveNodeID != "n1" {
		t.Fatalf("unexpected recovered state: %+v", recovered)
	}
}

func TestStoreTransactionRollback(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(dir)

	s := NewDefaultState(RoleRelay)
	s.Relay.Forwards = []ForwardRule{{
		ID:         "f1",
		ListenPort: 10001,
		TargetHost: "1.2.3.4",
		TargetPort: 443,
		Proto:      "tcp",
		Engine:     "nft",
	}}
	if err := st.Save(s); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := st.BeginTxn(); err != nil {
		t.Fatalf("BeginTxn: %v", err)
	}
	if _, err := st.Update(RoleRelay, func(cur *State) error {
		cur.Relay.Forwards[0].ListenPort = 20002
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	restored, err := st.RollbackTxn()
	if err != nil {
		t.Fatalf("RollbackTxn: %v", err)
	}
	if restored.Relay.Forwards[0].ListenPort != 10001 {
		t.Fatalf("expected rollback to port 10001, got %d", restored.Relay.Forwards[0].ListenPort)
	}
}

func TestValidationRules(t *testing.T) {
	// Role default listen_addr check
	if got := NewDefaultState(RoleClient).Auth.ListenAddr; got != ":443" {
		t.Fatalf("client default listen_addr = %q, want :443", got)
	}
	if got := NewDefaultState(RoleServer).Auth.ListenAddr; got != "127.0.0.1:8443" {
		t.Fatalf("server default listen_addr = %q, want 127.0.0.1:8443", got)
	}
	if got := NewDefaultState(RoleLanding).Auth.ListenAddr; got != ":8443" {
		t.Fatalf("landing default listen_addr = %q, want :8443", got)
	}
	if got := NewDefaultState(RoleRelay).Auth.ListenAddr; got != ":8443" {
		t.Fatalf("relay default listen_addr = %q, want :8443", got)
	}

	// Port conflict check
	c := NewDefaultState(RoleClient)
	c.Client.FWD0 = FWD0Config{
		Enabled: true,
		Port:    443, // conflicts with client default web-ui :443
		UUIDs:   []string{"11111111-1111-4111-8111-111111111111"},
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "port conflict") {
		t.Fatalf("expected port conflict error, got %v", err)
	}

	// Self-loop & duplicate domain check in SOCKS5 outbounds
	srv := NewDefaultState(RoleServer)
	srv.Server.Domain = "srv.example.com"
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	srv.ExtraInbounds = []ExtraInbound{{
		Tag:        "inbound-socks5",
		Protocol:   "socks5",
		ListenPort: 1080,
		SocksUser:  "u",
		SocksPass:  "p",
	}}
	srv.Server.Socks5Outbounds = []Socks5Profile{{
		Name:    "default",
		Enabled: true,
		Address: "127.0.0.1",
		Port:    1080,
	}}
	if err := srv.Validate(); err == nil || !strings.Contains(err.Error(), "self-loop") {
		t.Fatalf("expected self-loop error, got %v", err)
	}

	srv.Server.Socks5Outbounds = []Socks5Profile{
		{
			Name:    "sg",
			Enabled: true,
			Address: "sg.example.net",
			Port:    1080,
			Domains: []string{"geosite:netflix"},
		},
		{
			Name:    "us",
			Enabled: true,
			Address: "us.example.net",
			Port:    1081,
			Domains: []string{"geosite:netflix"},
		},
	}
	if err := srv.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate domain") {
		t.Fatalf("expected duplicate domain error, got %v", err)
	}
}

func TestStoreWithApplyLockWaitWarning(t *testing.T) {
	dir := t.TempDir()
	st := NewStore(dir)

	var warned atomic.Int32
	st.OnApplyLockWait = func() {
		warned.Add(1)
	}

	holding := make(chan struct{})
	release := make(chan struct{})
	done1 := make(chan error, 1)
	go func() {
		done1 <- st.WithApplyLock(context.Background(), func() error {
			close(holding)
			<-release
			return nil
		})
	}()

	<-holding
	go func() {
		time.Sleep(1150 * time.Millisecond)
		close(release)
	}()

	if err := st.WithApplyLock(context.Background(), func() error {
		return nil
	}); err != nil {
		t.Fatalf("second WithApplyLock failed: %v", err)
	}
	if err := <-done1; err != nil {
		t.Fatalf("first WithApplyLock failed: %v", err)
	}
	if got := warned.Load(); got != 1 {
		t.Fatalf("expected OnApplyLockWait called once after >1s wait, got %d", got)
	}
}

func TestWave1StateValidationAdditions(t *testing.T) {
	// vmess-tcp node allowed without path
	c := NewDefaultState(RoleClient)
	c.Client.Nodes = []OutboundNode{{
		ID:       "v2-tcp",
		Name:     "LegacyTCP",
		Protocol: "vmess-tcp",
		Address:  "node.example.com",
		Port:     10443,
		UUID:     "11111111-1111-4111-8111-111111111111",
	}}
	c.Client.ActiveNodeID = "v2-tcp"
	c.Client.DNS.Hosts["*.lan.home"] = "192.168.10.2"
	c.Client.DNS.Hosts["domain:corp.internal"] = "10.0.0.5"
	c.Client.DNS.Hosts["full:exact.home"] = "192.168.10.3"
	c.Client.DNS.BlockExternal53 = true
	c.Client.FWD0 = FWD0Config{
		Enabled:  true,
		Protocol: "vmess-tcp",
		Port:     1443,
		UUIDs:    []string{"22222222-2222-4222-8222-222222222222"},
	}
	c.Client.FWD1 = FWD1Config{
		Enabled:        true,
		Protocol:       "vmess-tcp",
		Port:           2443,
		UUIDs:          []string{"33333333-3333-4333-8333-333333333333"},
		UpstreamNodeID: "v2-tcp",
	}
	c.Client.RproxyC = RproxyCConfig{
		Enabled:              true,
		TunnelAddress:        "198.51.100.2",
		TunnelPort:           20000,
		TunnelUUID:           "44444444-4444-4444-8444-444444444444",
		Security:             "tls",
		ServerName:           "tun.example.com",
		PinnedPeerCertSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		OutDirect:            true,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid Wave 1 client state, got %v", err)
	}

	cBadHost := NewDefaultState(RoleClient)
	cBadHost.Client.DNS.Hosts["*bad.example.com"] = "1.2.3.4"
	if err := cBadHost.Validate(); err == nil {
		t.Fatalf("expected invalid wildcard host rejected")
	}

	cBadSec := NewDefaultState(RoleClient)
	cBadSec.Client.RproxyC = RproxyCConfig{
		Enabled:       true,
		TunnelAddress: "198.51.100.2",
		TunnelPort:    20000,
		TunnelUUID:    "44444444-4444-4444-8444-444444444444",
		Security:      "xtls",
	}
	if err := cBadSec.Validate(); err == nil {
		t.Fatalf("expected invalid rproxyc.security rejected")
	}

	// Server protocols: vmess-ws / vless-ws + RproxyS InUUIDs & Security
	srv := NewDefaultState(RoleServer)
	srv.Server.Protocol = "vmess-ws"
	srv.Server.Domain = "srv.example.com"
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	srv.RproxyS = RproxySConfig{
		Enabled:    true,
		ListenPort: 20000,
		Security:   "none",
		UUIDs:      []string{"22222222-2222-4222-8222-222222222222"},
		InUUIDs:    []string{"33333333-3333-4333-8333-333333333333"},
	}
	if err := srv.Validate(); err != nil {
		t.Fatalf("expected valid server vmess-ws + rproxys state, got %v", err)
	}

	srv.Server.Protocol = "vmess-tcp"
	if err := srv.Validate(); err == nil {
		t.Fatalf("expected unsupported server.protocol rejected")
	}
}

func TestWave2ViaNginxConflictsAndDokodemoNetwork(t *testing.T) {
	srv := NewDefaultState(RoleServer)
	srv.Server.TLSMode = "nginx"
	srv.Server.Domain = "srv.example.com"
	srv.Server.ListenPort = 443
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}

	// Same port+domain as main nginx server must fail
	srv.ExtraInbounds = []ExtraInbound{{
		Tag:        "extra-dup",
		Protocol:   "vless-xhttp",
		ListenPort: 443,
		Domain:     "srv.example.com",
		UUID:       "22222222-2222-4222-8222-222222222222",
		ViaNginx:   true,
	}}
	if err := srv.Validate(); err == nil {
		t.Fatalf("expected via_nginx conflict with main nginx server rejected")
	}

	// Same port with different domain succeeds
	srv.ExtraInbounds[0].Domain = "alt.example.com"
	if err := srv.Validate(); err != nil {
		t.Fatalf("expected via_nginx on different domain accepted, got %v", err)
	}

	// Two extra via_nginx on same port+domain fail
	srv.ExtraInbounds = append(srv.ExtraInbounds, ExtraInbound{
		Tag:        "extra-dup2",
		Protocol:   "vless-ws",
		ListenPort: 443,
		Domain:     "ALT.example.com",
		UUID:       "33333333-3333-4333-8333-333333333333",
		ViaNginx:   true,
	})
	if err := srv.Validate(); err == nil {
		t.Fatalf("expected duplicate via_nginx port+domain rejected")
	}

	// Dokodemo network validation
	srv.ExtraInbounds = []ExtraInbound{{
		Tag:        "doko",
		Protocol:   "dokodemo",
		ListenPort: 10053,
		TargetAddr: "1.1.1.1",
		TargetPort: 53,
		Network:    "udp",
	}}
	if err := srv.Validate(); err != nil {
		t.Fatalf("expected valid dokodemo network=udp, got %v", err)
	}
	srv.ExtraInbounds[0].Network = "sctp"
	if err := srv.Validate(); err == nil {
		t.Fatalf("expected invalid dokodemo network=sctp rejected")
	}
}

func TestCamouflageDirExtraDomainAndListenAddrValidation(t *testing.T) {
	// 1. CamouflageDir validation
	validSrv := func() *State {
		s := NewDefaultState(RoleServer)
		s.Server.Domain = "srv.example.com"
		s.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
		return s
	}

	sOK := validSrv()
	sOK.Server.CamouflageDir = "/var/www/camo-site"
	if err := sOK.Validate(); err != nil {
		t.Fatalf("expected valid CamouflageDir accepted, got %v", err)
	}

	badDirs := []string{
		"/",
		"relative/dir",
		"/var/www/../etc",
		"/var/www/html/",
		"/var/www/my site",
		"/var/www/html;return 200",
		"/var/www/html{x}",
		"/var/www/html\"x",
		"/var/www/html'x",
		"/var/www/$root",
		"/var/www\\evil",
		"/var/www/#comment",
		"/var/www/bad\nline",
		"/" + strings.Repeat("a", 256),
	}
	for _, bad := range badDirs {
		sBad := validSrv()
		sBad.Server.CamouflageDir = bad
		if err := sBad.Validate(); err == nil {
			t.Errorf("expected invalid CamouflageDir %q rejected", bad)
		}
	}

	// 2. ExtraInbound.Domain checked regardless of ViaNginx
	for _, viaNginx := range []bool{false, true} {
		sBadDom := validSrv()
		sBadDom.ExtraInbounds = []ExtraInbound{{
			Tag:        "ex-inj",
			Protocol:   "vless-xhttp",
			ListenPort: 9443,
			Domain:     "evil.com; return 200",
			UUID:       "22222222-2222-4222-8222-222222222222",
			ViaNginx:   viaNginx,
		}}
		if err := sBadDom.Validate(); err == nil {
			t.Errorf("expected invalid ExtraInbound.Domain rejected (viaNginx=%v)", viaNginx)
		}
	}

	// 3. Auth.ListenAddr IPv6 syntax & Server port conflict
	for _, goodAddr := range []string{":8443", "127.0.0.1:8443", "localhost:8443", "[::1]:8443", "[::]:8443"} {
		sAddr := validSrv()
		sAddr.Auth.ListenAddr = goodAddr
		if err := sAddr.Validate(); err != nil {
			t.Errorf("expected valid ListenAddr %q accepted, got %v", goodAddr, err)
		}
	}
	for _, badAddr := range []string{"8443", "::1:8443", "[::1]", "[fe80::1%eth0]:8443", "evil host:8443", "127.0.0.1:0", "127.0.0.1:70000"} {
		sAddr := validSrv()
		sAddr.Auth.ListenAddr = badAddr
		if err := sAddr.Validate(); err == nil {
			t.Errorf("expected invalid ListenAddr %q rejected", badAddr)
		}
	}

	sConflict := validSrv()
	sConflict.Auth.ListenAddr = "127.0.0.1:8443"
	sConflict.ExtraInbounds = []ExtraInbound{{
		Tag:        "ex-conflict",
		Protocol:   "vless-xhttp",
		ListenPort: 8443,
		Domain:     "ex.example.com",
		UUID:       "22222222-2222-4222-8222-222222222222",
	}}
	if err := sConflict.Validate(); err == nil || !strings.Contains(err.Error(), "port conflict") {
		t.Fatalf("expected server web-ui port conflict error, got %v", err)
	}
}

func TestHardeningValidationRules(t *testing.T) {
	// 1. Cert.CertFile and Cert.KeyFile reject nginx-unsafe / non-clean paths
	validSrv := func() *State {
		s := NewDefaultState(RoleServer)
		s.Server.Domain = "srv.example.com"
		s.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
		return s
	}
	sCertOK := validSrv()
	sCertOK.Cert.CertFile = "/etc/dex/ssl/dex.cer"
	sCertOK.Cert.KeyFile = "/etc/dex/ssl/dex.key"
	if err := sCertOK.Validate(); err != nil {
		t.Fatalf("expected clean cert/key paths accepted, got %v", err)
	}
	badPaths := []string{
		"/",
		"relative/cert.pem",
		"/etc/dex/../ssl/dex.cer",
		"/etc/dex/ssl/a b.cer",
		"/etc/dex/ssl/a;return 200",
		"/etc/dex/ssl/a{b}",
		"/etc/dex/ssl/a\"b",
		"/etc/dex/ssl/a'b",
		"/etc/dex/ssl/$cert",
		"/etc/dex/ssl/a\\b",
		"/etc/dex/ssl/#comment",
		"/etc/dex/ssl/a\nb",
		"/" + strings.Repeat("c", 256),
	}
	for _, bp := range badPaths {
		sc := validSrv()
		sc.Cert.CertFile = bp
		if err := sc.Validate(); err == nil {
			t.Errorf("expected bad cert.cert_file %q rejected", bp)
		}
		sk := validSrv()
		sk.Cert.KeyFile = bp
		if err := sk.Validate(); err == nil {
			t.Errorf("expected bad cert.key_file %q rejected", bp)
		}
	}

	// 2. Client.Nodes and RproxyC.TunnelAddress reject restricted IP literals
	restrictedIPs := []string{
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"::",
		"169.254.169.254",
		"fe80::1",
		"224.0.0.1",
		"ff02::1",
	}
	for _, rip := range restrictedIPs {
		c := NewDefaultState(RoleClient)
		c.Client.Nodes = []OutboundNode{{
			ID: "bad", Protocol: "socks5", Address: rip, Port: 1080,
		}}
		if err := c.Validate(); err == nil {
			t.Errorf("expected restricted node IP %q rejected", rip)
		}

		cr := NewDefaultState(RoleClient)
		cr.Client.RproxyC = RproxyCConfig{
			Enabled:       true,
			TunnelAddress: rip,
			TunnelPort:    20000,
			TunnelUUID:    "11111111-1111-4111-8111-111111111111",
		}
		if err := cr.Validate(); err == nil {
			t.Errorf("expected restricted rproxyc.tunnel_address %q rejected", rip)
		}
	}

	// 3. Multiple ViaNginx extra inbounds on same port get distinct internal ports avoiding occupied ports
	sMulti := validSrv()
	sMulti.Server.TLSMode = "nginx"
	sMulti.ExtraInbounds = []ExtraInbound{
		{Tag: "vn-1", Protocol: "vless-xhttp", ListenPort: 443, Domain: "a.example.com", UUID: "22222222-2222-4222-8222-222222222222", ViaNginx: true},
		{Tag: "occupy-10444", Protocol: "socks5", ListenPort: 10444},
		{Tag: "vn-2", Protocol: "vless-ws", ListenPort: 443, Domain: "b.example.com", UUID: "33333333-3333-4333-8333-333333333333", ViaNginx: true},
		{Tag: "vn-3", Protocol: "vmess-ws", ListenPort: 443, Domain: "c.example.com", UUID: "44444444-4444-4444-8444-444444444444", ViaNginx: true},
	}
	if err := sMulti.Validate(); err != nil {
		t.Fatalf("expected multi via_nginx with different domains valid, got %v", err)
	}
	ports := AllocateViaNginxInternalPorts(sMulti)
	if ports["vn-1"] != 10443 || ports["vn-2"] != 10445 || ports["vn-3"] != 10446 {
		t.Fatalf("unexpected allocated via_nginx internal ports: %+v", ports)
	}
}

func TestHardeningAuditRegressions(t *testing.T) {
	// 1. PruneNodeRefs clears all 5 node reference locations and updates ActiveNodeID
	c := &ClientConfig{
		ActiveNodeID: "n1",
		Nodes: []OutboundNode{
			{ID: "n1", Name: "N1"},
			{ID: "n2", Name: "N2"},
		},
		Routing: RoutingConfig{
			ServiceMap:  map[string]string{"ai": "n1", "stream": "n2"},
			AppleNodeID: "n1",
			Divert:      DivertConfig{Enabled: true, NodeID: "n1"},
			Custom:      CustomRouteConfig{Enabled: true, NodeID: "n1"},
		},
		FWD1: FWD1Config{Enabled: true, UpstreamNodeID: "n1"},
	}
	c.Nodes = c.Nodes[1:] // remove n1
	c.PruneNodeRefs("n1")
	if c.ActiveNodeID != "n2" {
		t.Fatalf("expected ActiveNodeID fallback to n2, got %q", c.ActiveNodeID)
	}
	if _, exists := c.Routing.ServiceMap["ai"]; exists || c.Routing.ServiceMap["stream"] != "n2" {
		t.Fatalf("expected ServiceMap[ai] pruned and stream kept, got %+v", c.Routing.ServiceMap)
	}
	if c.Routing.AppleNodeID != "" || c.Routing.Divert.NodeID != "" || c.Routing.Custom.NodeID != "" || c.FWD1.UpstreamNodeID != "" {
		t.Fatalf("expected all n1 refs pruned, got apple=%q divert=%q custom=%q fwd1=%q",
			c.Routing.AppleNodeID, c.Routing.Divert.NodeID, c.Routing.Custom.NodeID, c.FWD1.UpstreamNodeID)
	}

	// 2. WireGuard peer uniqueness validation (name, pubkey, tunnel IP)
	baseWG := func() *State {
		st := NewDefaultState(RoleClient)
		st.Client.WireGuard = WireGuardConfig{
			Enabled:          true,
			EndpointHost:     "wg.example.com",
			ListenPort:       51820,
			SubnetCIDR:       "172.16.66.1/24",
			ServerPrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			ServerPublicKey:  "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
			Peers: []WGPeer{
				{
					Name:       "phone",
					IP:         "172.16.66.11",
					PrivateKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
					PublicKey:  "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=",
				},
			},
		}
		return st
	}
	if err := baseWG().Validate(); err != nil {
		t.Fatalf("valid WG failed: %v", err)
	}
	wgEmptyName := baseWG()
	wgEmptyName.Client.WireGuard.Peers[0].Name = "  "
	if err := wgEmptyName.Validate(); err == nil {
		t.Fatalf("expected empty WG peer name rejected")
	}
	wgDupName := baseWG()
	wgDupName.Client.WireGuard.Peers = append(wgDupName.Client.WireGuard.Peers, WGPeer{
		Name:       "phone",
		IP:         "172.16.66.12",
		PrivateKey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=",
		PublicKey:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=",
	})
	if err := wgDupName.Validate(); err == nil {
		t.Fatalf("expected duplicate WG peer name rejected")
	}
	wgDupPub := baseWG()
	wgDupPub.Client.WireGuard.Peers = append(wgDupPub.Client.WireGuard.Peers, WGPeer{
		Name:       "tablet",
		IP:         "172.16.66.12",
		PrivateKey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=",
		PublicKey:  "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=",
	})
	if err := wgDupPub.Validate(); err == nil {
		t.Fatalf("expected duplicate WG peer pubkey rejected")
	}
	wgSrvPub := baseWG()
	wgSrvPub.Client.WireGuard.Peers[0].PublicKey = wgSrvPub.Client.WireGuard.ServerPublicKey
	if err := wgSrvPub.Validate(); err == nil {
		t.Fatalf("expected WG peer pubkey matching server pubkey rejected")
	}
	wgDupIP := baseWG()
	wgDupIP.Client.WireGuard.Peers = append(wgDupIP.Client.WireGuard.Peers, WGPeer{
		Name:       "tablet",
		IP:         "172.16.66.11/32",
		PrivateKey: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=",
		PublicKey:  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=",
	})
	if err := wgDupIP.Validate(); err == nil {
		t.Fatalf("expected duplicate WG peer IP (with /32) rejected")
	}
	wgSrvIP := baseWG()
	wgSrvIP.Client.WireGuard.Peers[0].IP = "172.16.66.1/32"
	if err := wgSrvIP.Validate(); err == nil {
		t.Fatalf("expected WG peer IP matching server tunnel IP rejected")
	}

	// 3. ViaNginx protocol/role validation
	for _, role := range []string{RoleClient, RoleLanding} {
		stRole := NewDefaultState(role)
		if role == RoleLanding {
			stRole.Server.Domain = "land.example.com"
			stRole.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
		}
		stRole.ExtraInbounds = []ExtraInbound{{
			Tag:        "vn-bad-role",
			Protocol:   "vless-xhttp",
			ListenPort: 8444,
			UUID:       "22222222-2222-4222-8222-222222222222",
			ViaNginx:   true,
		}}
		if err := stRole.Validate(); err == nil {
			t.Errorf("expected via_nginx rejected on role %s", role)
		}
	}
	badViaProtos := []ExtraInbound{
		{Tag: "vn-real", Protocol: "vless-reality", ListenPort: 8444, UUID: "22222222-2222-4222-8222-222222222222", RealityPrivKey: "priv", RealityDest: "www.apple.com:443", RealitySNI: "www.apple.com", ViaNginx: true},
		{Tag: "vn-s5", Protocol: "socks5", ListenPort: 8444, ViaNginx: true},
		{Tag: "vn-doko", Protocol: "dokodemo", ListenPort: 8444, TargetAddr: "1.1.1.1", TargetPort: 53, ViaNginx: true},
	}
	for _, ex := range badViaProtos {
		stSrv := NewDefaultState(RoleServer)
		stSrv.Server.Domain = "srv.example.com"
		stSrv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
		stSrv.ExtraInbounds = []ExtraInbound{ex}
		if err := stSrv.Validate(); err == nil {
			t.Errorf("expected via_nginx rejected for protocol %s", ex.Protocol)
		}
	}

	// 4. Relay.Forwards ID uniqueness & non-empty
	stRelEmpty := NewDefaultState(RoleRelay)
	stRelEmpty.Relay.Forwards = []ForwardRule{{ID: "", ListenPort: 10001, TargetHost: "1.1.1.1", TargetPort: 443, Proto: "tcp", Engine: "nft"}}
	if err := stRelEmpty.Validate(); err == nil {
		t.Fatalf("expected empty relay forward ID rejected")
	}
	stRelDup := NewDefaultState(RoleRelay)
	stRelDup.Relay.Forwards = []ForwardRule{
		{ID: "fwd-10001", ListenPort: 10001, TargetHost: "1.1.1.1", TargetPort: 443, Proto: "tcp", Engine: "nft"},
		{ID: "fwd-10001", ListenPort: 10001, TargetHost: "1.1.1.1", TargetPort: 443, Proto: "udp", Engine: "nft"},
	}
	if err := stRelDup.Validate(); err == nil {
		t.Fatalf("expected duplicate relay forward ID rejected")
	}
}
