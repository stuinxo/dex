package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

func TestProbeNodeHealthEnforcesSNI(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "landing.sni.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"landing.sni.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	var gotSNI string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			gotSNI = r.TLS.ServerName
		}
		w.WriteHeader(http.StatusNotFound) // 404 is normal XHTTP probe status
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	res := ProbeNodeHealth(context.Background(), state.OutboundNode{
		ID:       "relay-to-landing",
		Protocol: "vless-xhttp",
		Address:  "127.0.0.1",
		Port:     port,
		UUID:     "11111111-1111-4111-8111-111111111111",
		TLSSNI:   "landing.sni.test",
		Path:     "/11111111",
	}, 3*time.Second, true)

	if !res.Healthy || res.StatusCode != 404 {
		t.Fatalf("expected healthy 404 probe, got %+v", res)
	}
	if gotSNI != "landing.sni.test" {
		t.Fatalf("expected TLS ServerName=landing.sni.test, got %q", gotSNI)
	}

	// Verify HTTP/2 ALPN TLS servers (like nginx/xray with h2) also probe cleanly
	srvH2 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	srvH2.EnableHTTP2 = true
	srvH2.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	srvH2.StartTLS()
	defer srvH2.Close()
	u2, _ := url.Parse(srvH2.URL)
	port2, _ := strconv.Atoi(u2.Port())
	res2 := ProbeNodeHealth(context.Background(), state.OutboundNode{
		ID:       "nginx-h2",
		Protocol: "vless-xhttp",
		Address:  "127.0.0.1",
		Port:     port2,
		UUID:     "11111111-1111-4111-8111-111111111111",
		TLSSNI:   "landing.sni.test",
	}, 3*time.Second, true)
	if !res2.Healthy || res2.StatusCode != 400 {
		t.Fatalf("expected healthy HTTP/2 TLS probe, got %+v", res2)
	}
}

func TestFailoverAndFailbackStateMachine(t *testing.T) {
	hub := NewTaskHub(50)
	st := state.NewDefaultState(state.RoleClient)
	st.Client.FailoverEnabled = true
	st.Client.Nodes = []state.OutboundNode{
		{ID: "n1", Name: "Primary", Protocol: "vless-xhttp", Address: "1.1.1.1", Port: 443, UUID: "11111111-1111-4111-8111-111111111111"},
		{ID: "n2", Name: "Backup", Protocol: "vless-xhttp", Address: "2.2.2.2", Port: 443, UUID: "22222222-2222-4222-8222-222222222222"},
	}
	st.Client.ActiveNodeID = "n1"

	egressOK := false
	nodeHealthy := map[string]bool{"n1": false, "n2": true}

	fc := NewFailoverController(hub, func(ctx context.Context, id string) error {
		st.Client.ActiveNodeID = id
		return nil
	})
	fc.ProbeEgress = func(ctx context.Context) bool { return egressOK }
	fc.ProbeNode = func(ctx context.Context, n state.OutboundNode) ProbeNodeResult {
		return ProbeNodeResult{NodeID: n.ID, Healthy: nodeHealthy[n.ID]}
	}

	// 2 failures should NOT trigger failover yet (threshold = 3)
	fc.Step(context.Background(), st)
	fc.Step(context.Background(), st)
	if st.Client.ActiveNodeID != "n1" {
		t.Fatalf("premature failover after 2 errors")
	}

	// 3rd failure switches to n2
	fc.Step(context.Background(), st)
	if st.Client.ActiveNodeID != "n2" {
		t.Fatalf("expected failover to n2, got %q", st.Client.ActiveNodeID)
	}

	// Now n1 recovers; 3 consecutive probes should failback to n1
	egressOK = true
	nodeHealthy["n1"] = true
	fc.Step(context.Background(), st)
	fc.Step(context.Background(), st)
	if st.Client.ActiveNodeID != "n2" {
		t.Fatalf("premature failback before 3 healthy checks")
	}
	fc.Step(context.Background(), st)
	if st.Client.ActiveNodeID != "n1" {
		t.Fatalf("expected failback to n1, got %q", st.Client.ActiveNodeID)
	}

	// Manual Reality mode pauses failover even if egress fails
	st.Client.Nodes[0].Protocol = "vless-reality"
	egressOK = false
	for i := 0; i < 5; i++ {
		fc.Step(context.Background(), st)
	}
	if st.Client.ActiveNodeID != "n1" {
		t.Fatalf("expected failover paused in vless-reality mode")
	}
}

func TestCloudflareDDNSCreateAndUpdate(t *testing.T) {
	var mu sync.Mutex
	recordContent := ""
	created := false
	updated := false

	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer test-cf-token" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{{"id": "z1", "name": "example.com"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/z1/dns_records":
			var list []map[string]string
			if recordContent != "" {
				list = append(list, map[string]string{"id": "r1", "name": "home.example.com", "content": recordContent})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": list})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/z1/dns_records":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			recordContent = body["content"].(string)
			created = true
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "r1"}})
		case r.Method == http.MethodPut && r.URL.Path == "/zones/z1/dns_records/r1":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			recordContent = body["content"].(string)
			updated = true
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "r1"}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer cfSrv.Close()

	hub := NewTaskHub(20)
	ddns := NewCloudflareDDNS(hub)
	ddns.BaseURL = cfSrv.URL
	curIP := "203.0.113.10"
	ddns.FetchPublic4 = func(ctx context.Context) (string, error) { return curIP, nil }

	res1, err := ddns.SyncOnce(context.Background(), "home.example.com", "test-cf-token", false, false)
	if err != nil || !res1.Updated4 || !created || recordContent != "203.0.113.10" {
		t.Fatalf("first DDNS sync failed: res=%+v err=%v created=%v content=%q", res1, err, created, recordContent)
	}

	// Same IP -> no-op
	res2, err := ddns.SyncOnce(context.Background(), "home.example.com", "test-cf-token", false, false)
	if err != nil || res2.Updated4 || updated {
		t.Fatalf("unchanged IP should not update: res=%+v err=%v updated=%v", res2, err, updated)
	}

	// Changed IP -> PUT update
	curIP = "203.0.113.20"
	res3, err := ddns.SyncOnce(context.Background(), "home.example.com", "test-cf-token", false, false)
	if err != nil || !res3.Updated4 || !updated || recordContent != "203.0.113.20" {
		t.Fatalf("changed IP update failed: res=%+v err=%v updated=%v content=%q", res3, err, updated, recordContent)
	}
}

func TestCloudflareDDNSGlobalAPIKeyHeaders(t *testing.T) {
	var gotEmail, gotKey, gotAuth string
	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEmail = r.Header.Get("X-Auth-Email")
		gotKey = r.Header.Get("X-Auth-Key")
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{{"id": "z1", "name": "example.com"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/z1/dns_records":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{{"id": "r1", "name": "home.example.com", "content": "203.0.113.99"}},
			})
		default:
			w.WriteHeader(404)
		}
	}))
	defer cfSrv.Close()

	ddns := NewCloudflareDDNS(NewTaskHub(10))
	ddns.BaseURL = cfSrv.URL
	ddns.FetchPublic4 = func(ctx context.Context) (string, error) { return "203.0.113.99", nil }

	res, err := ddns.SyncOnceWithEmail(context.Background(), "home.example.com", "global-key-xyz", "user@example.com", false, false)
	if err != nil {
		t.Fatalf("SyncOnceWithEmail failed: %v", err)
	}
	if !res.Updated4 {
		t.Fatalf("expected Updated4=true")
	}
	if gotEmail != "user@example.com" || gotKey != "global-key-xyz" || gotAuth != "" {
		t.Fatalf("unexpected auth headers: email=%q key=%q auth=%q", gotEmail, gotKey, gotAuth)
	}

	// Verify direct HTTP client (SO_MARK=0xff with non-root EPERM fallback) can dial local test server
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.55\n"))
	}))
	defer ipSrv.Close()
	gotIP, err := fetchPublicIP(context.Background(), newDirectHTTPClient(), []string{ipSrv.URL}, false)
	if err != nil || gotIP != "203.0.113.55" {
		t.Fatalf("direct client fetchPublicIP failed: got=%q err=%v", gotIP, err)
	}
}

type stubDaemonExec struct {
	reconcile.OSExecutor
	active map[string]bool
}

func (s *stubDaemonExec) DetectInitSystem() string { return "systemd" }
func (s *stubDaemonExec) ServiceIsActive(_ context.Context, _ string, unit string) bool {
	return s.active[unit]
}
func (s *stubDaemonExec) ResolveHostIPs(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func TestWave2FailoverSkipsWhenProxyPaused(t *testing.T) {
	store := state.NewStore(t.TempDir())
	st := state.NewDefaultState(state.RoleClient)
	st.Client.FailoverEnabled = true
	st.Client.Nodes = []state.OutboundNode{
		{ID: "n1", Protocol: "vless-xhttp", Address: "1.1.1.1", Port: 443, UUID: "11111111-1111-4111-8111-111111111111"},
		{ID: "n2", Protocol: "vless-xhttp", Address: "2.2.2.2", Port: 443, UUID: "22222222-2222-4222-8222-222222222222"},
	}
	st.Client.ActiveNodeID = "n1"
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	exec := &stubDaemonExec{active: map[string]bool{"dex-xray": false, "dex-nft": true}}
	runner := NewRunner(store, exec, NewTaskHub(10))
	probed := 0
	runner.Failover.ProbeEgress = func(context.Context) bool {
		probed++
		return false
	}

	// While dex-xray is inactive (proxy paused), failover tick must skip probing.
	runner.runFailoverTick(context.Background())
	if probed != 0 {
		t.Fatalf("expected failover skipped while dex-xray inactive, got probed=%d", probed)
	}

	// While dex-xray is active but dex-nft is inactive, failover tick must also skip probing.
	exec.active["dex-xray"] = true
	exec.active["dex-nft"] = false
	runner.runFailoverTick(context.Background())
	if probed != 0 {
		t.Fatalf("expected failover skipped while dex-nft inactive, got probed=%d", probed)
	}

	// Once both dex-xray and dex-nft are active, failover tick runs normally.
	exec.active["dex-nft"] = true
	runner.runFailoverTick(context.Background())
	if probed != 1 {
		t.Fatalf("expected failover to probe when dex-xray and dex-nft active, got probed=%d", probed)
	}
}

func TestCloudflareDDNSZoneLookupMoreThan50AndCacheSelfHeal(t *testing.T) {
	var mu sync.Mutex
	var zoneQueries []string
	recordContent := "198.51.100.1"
	currentRecID := "r-old"
	putCount := 0

	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			name := r.URL.Query().Get("name")
			zoneQueries = append(zoneQueries, r.URL.RawQuery)
			if name == "example.com" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": true,
					"result":  []map[string]string{{"id": "z-exact", "name": "example.com"}},
				})
				return
			}
			// Simulate >50-domain account where /zones?per_page=50 omits example.com
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/z-exact/dns_records":
			var list []map[string]string
			if currentRecID != "" {
				list = append(list, map[string]string{"id": currentRecID, "name": "a.b.example.com", "content": recordContent})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": list})
		case r.Method == http.MethodPut && r.URL.Path == "/zones/z-exact/dns_records/r-old":
			// First time succeeds; once deleted externally, returns 404
			if currentRecID != "r-old" {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []string{"not found"}})
				return
			}
			putCount++
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			recordContent = body["content"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "r-old"}})
		case r.Method == http.MethodPut && r.URL.Path == "/zones/z-exact/dns_records/r-new":
			if currentRecID != "r-new" {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []string{"not found"}})
				return
			}
			putCount++
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			recordContent = body["content"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "r-new"}})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/z-exact/dns_records":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			recordContent = body["content"].(string)
			currentRecID = "r-created"
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "r-created"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer cfSrv.Close()

	ddns := NewCloudflareDDNS(NewTaskHub(10))
	ddns.BaseURL = cfSrv.URL
	curIP := "203.0.113.10"
	ddns.FetchPublic4 = func(context.Context) (string, error) { return curIP, nil }

	// 1. Multi-level subdomain queries name=a.b.example.com -> b.example.com -> example.com
	res1, err := ddns.SyncOnce(context.Background(), "a.b.example.com", "tok", false, false)
	if err != nil || !res1.Updated4 || recordContent != "203.0.113.10" {
		t.Fatalf("multi-level zone lookup failed: res=%+v err=%v", res1, err)
	}
	if len(zoneQueries) < 3 || zoneQueries[0] != "name=a.b.example.com" || zoneQueries[1] != "name=b.example.com" || zoneQueries[2] != "name=example.com" {
		t.Fatalf("unexpected zone query sequence: %v", zoneQueries)
	}

	// 2. Simulate external replacement of r-old -> r-new; cached PUT fails and self-heals
	mu.Lock()
	currentRecID = "r-new"
	mu.Unlock()
	curIP = "203.0.113.20"
	res2, err := ddns.SyncOnce(context.Background(), "a.b.example.com", "tok", false, false)
	if err != nil || !res2.Updated4 || recordContent != "203.0.113.20" {
		t.Fatalf("stale recCache self-heal to new record failed: res=%+v err=%v", res2, err)
	}

	// 3. Simulate external deletion of r-new; cached PUT fails and falls back to POST
	mu.Lock()
	currentRecID = ""
	mu.Unlock()
	curIP = "203.0.113.30"
	res3, err := ddns.SyncOnce(context.Background(), "a.b.example.com", "tok", false, false)
	if err != nil || !res3.Updated4 || recordContent != "203.0.113.30" || currentRecID != "r-created" {
		t.Fatalf("stale recCache self-heal to POST failed: res=%+v err=%v recID=%q", res3, err, currentRecID)
	}
}

func TestTaskHubSeqAndSubscribeWithSnapshot(t *testing.T) {
	hub := NewTaskHub(10)
	hub.Log("INFO", "boot", "m1")
	hub.Log("INFO", "boot", "m2")

	snap, ch, cancel := hub.SubscribeWithSnapshot(1)
	defer cancel()
	if len(snap) != 1 || snap[0].Seq != 2 || snap[0].Message != "m2" {
		t.Fatalf("unexpected snapshot since seq 1: %+v", snap)
	}
	hub.Log("WARN", "daemon", "m3")
	select {
	case got := <-ch:
		if got.Seq != 3 || got.Message != "m3" {
			t.Fatalf("unexpected live entry: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for live entry")
	}
}
