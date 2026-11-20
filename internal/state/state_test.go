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
	// Port conflict check
	c := NewDefaultState(RoleClient)
	c.Client.FWD0 = FWD0Config{
		Enabled: true,
		Port:    8443, // conflicts with client web-ui :8443
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
