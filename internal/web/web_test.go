package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/daemon"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/socks5out"
	"github.com/stuinxo/dex/internal/state"
)

type stubExec struct{}

func (stubExec) RunCommand(context.Context, []string, string, ...string) (string, error) {
	return "ok", nil
}
func (stubExec) HasCommand(string) bool                                   { return false }
func (stubExec) DaemonReload(context.Context, string) error               { return nil }
func (stubExec) ServiceEnableStart(context.Context, string, string) error { return nil }
func (stubExec) ServiceRestart(context.Context, string, string) error     { return nil }
func (stubExec) ServiceReload(context.Context, string, string) error      { return nil }
func (stubExec) ServiceStopDisable(context.Context, string, string) error { return nil }
func (stubExec) ServiceIsActive(context.Context, string, string) bool     { return true }
func (stubExec) DetectInitSystem() string                                 { return "systemd" }
func (stubExec) DetectIsContainer() bool                                  { return false }
func (stubExec) DetectMemMB() int                                         { return 512 }
func (stubExec) DetectPhysicalNICs() []string                             { return []string{"eth0"} }
func (stubExec) ResolveHostIPs(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil
}

func setupTestWeb(t *testing.T, useLegacyHash bool) (*Server, *state.Store, string) {
	t.Helper()
	root := t.TempDir()
	store := state.NewStore(root + "/etc/dex")

	st := state.NewDefaultState(state.RoleClient)
	if useLegacyHash {
		h, err := cryptoext.FormatLegacyV2Hash(cryptoext.LegacyV2Digest("myPass123"))
		if err != nil {
			t.Fatal(err)
		}
		st.Auth.PasswordHash = h
	} else {
		h, err := cryptoext.HashPassword("myPass123")
		if err != nil {
			t.Fatal(err)
		}
		st.Auth.PasswordHash = h
	}
	st.Client.Nodes = []state.OutboundNode{{
		ID:       "n1",
		Name:     "<script>alert(1)</script>",
		Protocol: "vless-xhttp",
		Address:  "hk.example.com",
		Port:     443,
		UUID:     "11111111-1111-4111-8111-111111111111",
	}}
	st.Client.ActiveNodeID = "n1"
	st.Cert.CFToken = "secret-cf-token"
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	hub := daemon.NewTaskHub(50)
	hub.Log("INFO", "boot", "test boot log")
	srv := NewServer(store, stubExec{}, hub, daemon.NewCloudflareDDNS(hub), reconcile.ApplyOptions{
		RootPrefix: root,
	})
	return srv, store, root
}

func TestWebSecurityAuthRateLimitCSRFAndRedaction(t *testing.T) {
	srv, store, _ := setupTestWeb(t, true)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 1. Static embedded UI assets load offline without auth
	uiResp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	uiBody, _ := io.ReadAll(uiResp.Body)
	_ = uiResp.Body.Close()
	if uiResp.StatusCode != 200 || !strings.Contains(string(uiBody), "寒月 · DEX") {
		t.Fatalf("expected embedded index.html, got status=%d", uiResp.StatusCode)
	}
	if uiResp.Header.Get("X-Frame-Options") != "DENY" || uiResp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers: %+v", uiResp.Header)
	}

	// 2. Protected endpoints reject unauthenticated requests (401)
	unauthResp, _ := http.Get(ts.URL + "/api/v1/state")
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauth GET /api/v1/state, got %d", unauthResp.StatusCode)
	}

	// 3. Rate limit after 10 failed logins -> 429 + Retry-After: 60
	for i := 0; i < 10; i++ {
		r, _ := http.Post(ts.URL+"/api/v1/auth/login", "application/json", strings.NewReader(`{"password":"bad"}`))
		_ = r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, r.StatusCode)
		}
	}
	rlResp, _ := http.Post(ts.URL+"/api/v1/auth/login", "application/json", strings.NewReader(`{"password":"myPass123"}`))
	_ = rlResp.Body.Close()
	if rlResp.StatusCode != http.StatusTooManyRequests || rlResp.Header.Get("Retry-After") != "60" {
		t.Fatalf("expected 429 + Retry-After:60, got status=%d retry=%q", rlResp.StatusCode, rlResp.Header.Get("Retry-After"))
	}

	// 4. Login from another IP succeeds and transparently upgrades legacy-sha256d$ -> pbkdf2-sha256$
	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	recW := httptest.NewRecorder()
	loginReq.RemoteAddr = "192.168.1.99:55555"
	srv.ServeHTTP(recW, loginReq)
	if recW.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d (%s)", recW.Code, recW.Body.String())
	}
	var loginData map[string]any
	_ = json.Unmarshal(recW.Body.Bytes(), &loginData)
	csrf := loginData["csrf_token"].(string)
	cookies := recW.Result().Cookies()

	reloaded, _ := store.Load()
	if !strings.HasPrefix(reloaded.Auth.PasswordHash, cryptoext.PBKDF2Scheme+"$") {
		t.Fatalf("expected legacy password hash upgraded to PBKDF2, got %q", reloaded.Auth.PasswordHash)
	}

	// 5. Missing/wrong CSRF token on mutation returns 403
	badCSRFReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/apply", nil)
	for _, c := range cookies {
		badCSRFReq.AddCookie(c)
	}
	badCSRFRec := httptest.NewRecorder()
	srv.ServeHTTP(badCSRFRec, badCSRFReq)
	if badCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF token, got %d", badCSRFRec.Code)
	}

	// 6. GET /api/v1/state redacts password_hash & masks cf_token; PUT preserves them
	getReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/state", nil)
	for _, c := range cookies {
		getReq.AddCookie(c)
	}
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)
	if getRec.Code != 200 {
		t.Fatalf("GET /api/v1/state status=%d", getRec.Code)
	}
	var statePayload struct {
		State state.State `json:"state"`
	}
	_ = json.Unmarshal(getRec.Body.Bytes(), &statePayload)
	if statePayload.State.Auth.PasswordHash != "" {
		t.Fatalf("password_hash leaked in GET /api/v1/state")
	}
	if statePayload.State.Cert.CFToken != secretKeepSentinel {
		t.Fatalf("expected masked cf_token %q, got %q", secretKeepSentinel, statePayload.State.Cert.CFToken)
	}

	putBytes, _ := json.Marshal(statePayload.State)
	putReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/state", bytes.NewReader(putBytes))
	putReq.Header.Set("X-CSRF-Token", csrf)
	putReq.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		putReq.AddCookie(c)
	}
	putRec := httptest.NewRecorder()
	srv.ServeHTTP(putRec, putReq)
	if putRec.Code != 200 {
		t.Fatalf("PUT /api/v1/state failed: %d %s", putRec.Code, putRec.Body.String())
	}
	afterPut, _ := store.Load()
	if afterPut.Auth.PasswordHash == "" || afterPut.Cert.CFToken != "secret-cf-token" {
		t.Fatalf("PUT /api/v1/state lost preserved secrets")
	}

	// 7. WireGuard peer creation & config retrieval
	wgReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/wireguard/peers", strings.NewReader(`{"name":"laptop"}`))
	wgReq.Header.Set("X-CSRF-Token", csrf)
	wgReq.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		wgReq.AddCookie(c)
	}
	wgRec := httptest.NewRecorder()
	srv.ServeHTTP(wgRec, wgReq)
	if wgRec.Code != 200 || !strings.Contains(wgRec.Body.String(), "172.16.66.11/32") {
		t.Fatalf("add WG peer failed: %d %s", wgRec.Code, wgRec.Body.String())
	}

	// 8. SSE log stream returns boot snapshot
	sseReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/logs/stream?once=1", nil)
	for _, c := range cookies {
		sseReq.AddCookie(c)
	}
	sseRec := httptest.NewRecorder()
	srv.ServeHTTP(sseRec, sseReq)
	if sseRec.Code != 200 || !strings.Contains(sseRec.Body.String(), "test boot log") {
		t.Fatalf("SSE log stream failed: %d %s", sseRec.Code, sseRec.Body.String())
	}
}

func TestWave2EndpointsAndSecurity(t *testing.T) {
	srv, store, root := setupTestWeb(t, false)
	srv.ProbeConnectivityFn = func(context.Context) (daemon.ConnectivityCheck, daemon.ConnectivityCheck) {
		return daemon.ConnectivityCheck{OK: true, StatusCode: 200, LatencyMS: 12},
			daemon.ConnectivityCheck{OK: true, StatusCode: 204, LatencyMS: 45}
	}
	srv.ProbeDoHFn = func(_ context.Context, u string) DoHProbeResult {
		return DoHProbeResult{URL: u, OK: true, Status: 200, LatencyMS: 18}
	}
	srv.ProbeSocks5Fn = func(context.Context, string, int, string, string, []string) (*socks5out.ProbeResult, error) {
		return &socks5out.ProbeResult{StatusCode: 200, ExitIP: "198.51.100.77", Location: "US"}, nil
	}
	var rulesCalled, updateCalled bool
	srv.UpdateRulesFn = func(_ context.Context, _ bool, w io.Writer) error {
		rulesCalled = true
		_, _ = io.WriteString(w, "rules updated\n")
		return nil
	}
	srv.UpdateComponentsFn = func(_ context.Context, comp, _ string, w io.Writer) error {
		updateCalled = comp == "xray"
		_, _ = io.WriteString(w, "xray updated\n")
		return nil
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Unauth check on new mutating endpoint -> 401
	unauth, _ := http.Post(ts.URL+"/api/v1/connectivity", "application/json", strings.NewReader(`{}`))
	_ = unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauth POST /api/v1/connectivity, got %d", unauth.StatusCode)
	}

	// Login
	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	srv.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != 200 {
		t.Fatalf("login failed: %d", loginRec.Code)
	}
	var lData map[string]any
	_ = json.Unmarshal(loginRec.Body.Bytes(), &lData)
	csrf := lData["csrf_token"].(string)
	cookies := loginRec.Result().Cookies()

	doReq := func(method, path, body string, useCSRF bool) *httptest.ResponseRecorder {
		var rBody io.Reader
		if body != "" {
			rBody = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rBody)
		if useCSRF {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	// CSRF check -> 403
	if rec := doReq(http.MethodPost, "/api/v1/connectivity", `{}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF, got %d", rec.Code)
	}

	// parse-uri, probe with DoH, connectivity, socks5 test
	if rec := doReq(http.MethodPost, "/api/v1/nodes/parse-uri", `{"uri":"socks5://u:p@127.0.0.1:1080#S1"}`, true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"protocol":"socks5"`) {
		t.Fatalf("parse-uri failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(http.MethodPost, "/api/v1/nodes/probe", `{"include_doh":true}`, true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"doh_results"`) {
		t.Fatalf("nodes/probe with doh failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(http.MethodPost, "/api/v1/connectivity", `{}`, true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"latency_ms":12`) {
		t.Fatalf("connectivity failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(http.MethodPost, "/api/v1/socks5/test", `{"address":"127.0.0.1","port":1080}`, true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"198.51.100.77"`) {
		t.Fatalf("socks5/test failed: %d %s", rec.Code, rec.Body.String())
	}

	// rules status/update, update components, proxy restart/stop
	if rec := doReq(http.MethodGet, "/api/v1/rules/status", "", false); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"Domains.apple.txt"`) {
		t.Fatalf("rules/status failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(http.MethodPost, "/api/v1/rules/update", `{"include_ads":false}`, true); rec.Code != 200 || !rulesCalled {
		t.Fatalf("rules/update failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(http.MethodPost, "/api/v1/update", `{"component":"xray"}`, true); rec.Code != 200 || !updateCalled {
		t.Fatalf("update failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(http.MethodPost, "/api/v1/proxy/restart", `{}`, true); rec.Code != 200 {
		t.Fatalf("proxy/restart failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(http.MethodPost, "/api/v1/proxy/stop", `{}`, true); rec.Code != 200 {
		t.Fatalf("proxy/stop failed: %d %s", rec.Code, rec.Body.String())
	}

	// cert self-sign & PEM import
	if rec := doReq(http.MethodPost, "/api/v1/cert/self-sign", `{"cn":"web.example.com","force":true}`, true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"web.example.com"`) {
		t.Fatalf("cert/self-sign failed: %d %s", rec.Code, rec.Body.String())
	}
	afterSelfSign, _ := store.Load()
	if afterSelfSign.Cert.Mode != "self_signed" {
		t.Fatalf("expected Cert.Mode=self_signed, got %q", afterSelfSign.Cert.Mode)
	}
	impDir := filepath.Join(store.Dir, "imp")
	_ = os.MkdirAll(impDir, 0o755)
	_ = cert.EnsureSelfSigned(impDir+"/c.pem", impDir+"/k.pem", "imp.example.com")
	cBytes, _ := io.ReadAll(func() io.Reader { b, _ := state.NewStore(impDir).Load(); _ = b; return strings.NewReader("") }())
	_ = cBytes
	certRaw, _ := json.Marshal(map[string]any{
		"cert_path":         impDir + "/c.pem",
		"key_path":          impDir + "/k.pem",
		"allow_self_signed": true,
	})
	if rec := doReq(http.MethodPost, "/api/v1/cert/import", string(certRaw), true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"imp.example.com"`) {
		t.Fatalf("cert/import failed: %d %s", rec.Code, rec.Body.String())
	}

	// WG peer add + regen + download=1 + regen-server
	if rec := doReq(http.MethodPost, "/api/v1/wireguard/peers", `{"name":"ipad"}`, true); rec.Code != 200 {
		t.Fatalf("add peer failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(http.MethodPost, "/api/v1/wireguard/peers/ipad/regen", `{}`, true); rec.Code != 200 || !strings.Contains(rec.Body.String(), "[Interface]") {
		t.Fatalf("peer regen failed: %d %s", rec.Code, rec.Body.String())
	}
	dlRec := doReq(http.MethodGet, "/api/v1/wireguard/peers/ipad/config?download=1", "", false)
	if dlRec.Code != 200 || !strings.Contains(dlRec.Header().Get("Content-Disposition"), "wg-ipad.conf") {
		t.Fatalf("peer config download failed: %d disp=%q", dlRec.Code, dlRec.Header().Get("Content-Disposition"))
	}
	if rec := doReq(http.MethodPost, "/api/v1/wireguard/regen-server", `{}`, true); rec.Code != 200 {
		t.Fatalf("wg regen-server failed: %d %s", rec.Code, rec.Body.String())
	}

	// Backup returns unredacted CFToken & PasswordHash with Cache-Control: no-store; migrate kind=v3_state restores cleanly from raw_json or path
	bakRec := doReq(http.MethodGet, "/api/v1/backup", "", false)
	if bakRec.Code != 200 || !strings.Contains(bakRec.Body.String(), "secret-cf-token") || bakRec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("backup failed, missing no-store, or redacted secrets: code=%d cc=%q", bakRec.Code, bakRec.Header().Get("Cache-Control"))
	}
	bakFile := filepath.Join(store.Dir, "backup.json")
	if err := os.WriteFile(bakFile, bakRec.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	migPathPayload, _ := json.Marshal(map[string]any{
		"kind":  "v3_state",
		"path":  bakFile,
		"apply": false,
	})
	if rec := doReq(http.MethodPost, "/api/v1/migrate", string(migPathPayload), true); rec.Code != 200 {
		t.Fatalf("migrate v3_state from path failed: %d %s", rec.Code, rec.Body.String())
	}
	migPayload, _ := json.Marshal(map[string]any{
		"kind":     "v3_state",
		"raw_json": bakRec.Body.String(),
		"apply":    false,
	})
	if rec := doReq(http.MethodPost, "/api/v1/migrate", string(migPayload), true); rec.Code != 200 {
		t.Fatalf("migrate v3_state failed: %d %s", rec.Code, rec.Body.String())
	}
	restored, _ := store.Load()
	if restored.Cert.CFToken != "secret-cf-token" || len(restored.Client.WireGuard.Peers) != 1 || root == "" {
		t.Fatalf("unexpected state after v3_state restore: %+v", restored)
	}

	// Status filters client services (no inactive nginx/dex-doh/haproxy) and exposes proxy_paused
	stRec := doReq(http.MethodGet, "/api/v1/status", "", false)
	if stRec.Code != 200 {
		t.Fatalf("status failed: %d", stRec.Code)
	}
	var stBody map[string]any
	_ = json.Unmarshal(stRec.Body.Bytes(), &stBody)
	if paused, ok := stBody["proxy_paused"].(bool); !ok || paused {
		t.Fatalf("expected proxy_paused=false when stubExec active, got %v", stBody["proxy_paused"])
	}

	// Apply accepts JSON body force/restart_all without breaking empty body
	if rec := doReq(http.MethodPost, "/api/v1/apply", `{"force":true,"restart_all":true}`, true); rec.Code != 200 {
		t.Fatalf("apply with JSON flags failed: %d %s", rec.Code, rec.Body.String())
	}

	// PUT /api/v1/system updates hostname cleanly (CSRF enforced)
	if rec := doReq(http.MethodPut, "/api/v1/system", `{"hostname":"gw-livingroom"}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on PUT /api/v1/system without CSRF, got %d", rec.Code)
	}
	if rec := doReq(http.MethodPut, "/api/v1/system", `{"hostname":"gw-livingroom"}`, true); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"gw-livingroom"`) {
		t.Fatalf("PUT /api/v1/system failed: %d %s", rec.Code, rec.Body.String())
	}
	afterSys, _ := store.Load()
	if afterSys.System.Hostname != "gw-livingroom" {
		t.Fatalf("expected hostname gw-livingroom, got %q", afterSys.System.Hostname)
	}
}

func TestWireGuardAutoKeygenOnPutAndPeerEndpointSync(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	srv.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != 200 {
		t.Fatalf("login failed: %d", loginRec.Code)
	}
	var lData map[string]any
	_ = json.Unmarshal(loginRec.Body.Bytes(), &lData)
	csrf := lData["csrf_token"].(string)
	cookies := loginRec.Result().Cookies()

	doReq := func(method, path, body string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	// 1. PUT /api/v1/state with wireguard.enabled=true and empty server keypair auto-generates valid keypair
	cur, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cur.Client.WireGuard.Enabled = true
	cur.Client.WireGuard.EndpointHost = "10.0.0.230"
	cur.Client.WireGuard.ListenPort = 51820
	cur.Client.WireGuard.SubnetCIDR = "172.16.66.1/24"
	cur.Client.WireGuard.ServerPrivateKey = ""
	cur.Client.WireGuard.ServerPublicKey = ""
	putBytes, _ := json.Marshal(cur)
	putRec := doReq(http.MethodPut, "/api/v1/state", string(putBytes))
	if putRec.Code != 200 {
		t.Fatalf("PUT /api/v1/state with empty WG server keys failed: %d %s", putRec.Code, putRec.Body.String())
	}
	afterPut, _ := store.Load()
	if afterPut.Client.WireGuard.ServerPrivateKey == "" || afterPut.Client.WireGuard.ServerPublicKey == "" {
		t.Fatalf("expected auto-generated WG server keypair, got priv=%q pub=%q",
			afterPut.Client.WireGuard.ServerPrivateKey, afterPut.Client.WireGuard.ServerPublicKey)
	}
	derivedPub, derr := cryptoext.DeriveWireGuardPublicKey(afterPut.Client.WireGuard.ServerPrivateKey)
	if derr != nil || derivedPub != afterPut.Client.WireGuard.ServerPublicKey {
		t.Fatalf("auto-generated WG keypair mismatch: derived=%q stored=%q err=%v",
			derivedPub, afterPut.Client.WireGuard.ServerPublicKey, derr)
	}

	// 2. POST /api/v1/wireguard/peers syncs endpoint_host / listen_port and returns updated Endpoint in config
	peerPayload := `{"name":"phone","endpoint_host":"home.ddns.example","listen_port":51822,"subnet_cidr":"10.66.66.1/24"}`
	peerRec := doReq(http.MethodPost, "/api/v1/wireguard/peers", peerPayload)
	if peerRec.Code != 200 {
		t.Fatalf("POST /api/v1/wireguard/peers failed: %d %s", peerRec.Code, peerRec.Body.String())
	}
	var peerResp struct {
		OK     bool   `json:"ok"`
		Config string `json:"config"`
	}
	_ = json.Unmarshal(peerRec.Body.Bytes(), &peerResp)
	if !strings.Contains(peerResp.Config, "Endpoint = home.ddns.example:51822") {
		t.Fatalf("expected synced Endpoint in peer config, got:\n%s", peerResp.Config)
	}
	if !strings.Contains(peerResp.Config, "DNS = 10.66.66.1") || !strings.Contains(peerResp.Config, "Address = 10.66.66.11/32") {
		t.Fatalf("expected synced subnet in peer config, got:\n%s", peerResp.Config)
	}
	afterPeer, _ := store.Load()
	if afterPeer.Client.WireGuard.EndpointHost != "home.ddns.example" || afterPeer.Client.WireGuard.ListenPort != 51822 {
		t.Fatalf("expected persisted WG endpoint/port, got %+v", afterPeer.Client.WireGuard)
	}
}

func TestLogsStreamSinceAndSystemAutoUpdateReconcileAndMemoryCaps(t *testing.T) {
	srv, store, root := setupTestWeb(t, false)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	srv.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != 200 {
		t.Fatalf("login failed: %d", loginRec.Code)
	}
	var lData map[string]any
	_ = json.Unmarshal(loginRec.Body.Bytes(), &lData)
	csrf := lData["csrf_token"].(string)
	cookies := loginRec.Result().Cookies()

	doReq := func(method, path, body string) *httptest.ResponseRecorder {
		var rBody io.Reader
		if body != "" {
			rBody = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rBody)
		req.Header.Set("X-CSRF-Token", csrf)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	// 1. SSE log stream ?since=<seq> and id: <seq> framing
	srv.Hub.Log("INFO", "probe", "entry-2")
	snap := srv.Hub.Snapshot()
	firstSeq := snap[0].Seq
	sseRec := doReq(http.MethodGet, fmt.Sprintf("/api/v1/logs/stream?once=1&since=%d", firstSeq), "")
	if sseRec.Code != 200 {
		t.Fatalf("SSE ?since failed: %d", sseRec.Code)
	}
	sseBody := sseRec.Body.String()
	if strings.Contains(sseBody, "test boot log") || !strings.Contains(sseBody, "entry-2") || !strings.Contains(sseBody, fmt.Sprintf("id: %d\n", snap[len(snap)-1].Seq)) {
		t.Fatalf("unexpected SSE ?since output:\n%s", sseBody)
	}

	// 2. PUT /api/v1/system toggling auto_update_core triggers Reconcile (creates/removes dex-core-update.timer)
	sysRec := doReq(http.MethodPut, "/api/v1/system", `{"auto_update_core":true}`)
	if sysRec.Code != 200 || !strings.Contains(sysRec.Body.String(), `"reconciled":true`) {
		t.Fatalf("expected reconciled=true on auto_update_core toggle: %d %s", sysRec.Code, sysRec.Body.String())
	}
	timerPath := filepath.Join(root, "etc", "systemd", "system", "dex-core-update.timer")
	if _, err := os.Stat(timerPath); err != nil {
		t.Fatalf("expected dex-core-update.timer written on auto_update_core=true, err=%v", err)
	}
	sysRec2 := doReq(http.MethodPut, "/api/v1/system", `{"hostname":"only-name-change"}`)
	if sysRec2.Code != 200 || !strings.Contains(sysRec2.Body.String(), `"reconciled":false`) {
		t.Fatalf("expected reconciled=false on hostname-only change: %d %s", sysRec2.Code, sysRec2.Body.String())
	}
	_ = store

	// 3. Memory cap protection on sessions (<= 256) and failures (<= 4096)
	srv.sessMu.Lock()
	srv.sessions["expired-1"] = &sessionRecord{id: "expired-1", expiresAt: time.Now().Add(-time.Minute)}
	for i := 0; i < maxActiveSessions+10; i++ {
		id := fmt.Sprintf("s-%d", i)
		srv.sessions[id] = &sessionRecord{id: id, expiresAt: time.Now().Add(time.Duration(i+1) * time.Minute)}
	}
	srv.sessMu.Unlock()

	capLoginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	capLoginReq.Header.Set("Content-Type", "application/json")
	capLoginReq.RemoteAddr = "10.99.0.1:12345"
	capLoginRec := httptest.NewRecorder()
	srv.ServeHTTP(capLoginRec, capLoginReq)
	if capLoginRec.Code != 200 {
		t.Fatalf("login during session cap test failed: %d", capLoginRec.Code)
	}
	srv.sessMu.RLock()
	sessCount := len(srv.sessions)
	_, hasExpired := srv.sessions["expired-1"]
	srv.sessMu.RUnlock()
	if sessCount > maxActiveSessions || hasExpired {
		t.Fatalf("session cap/cleanup failed: count=%d (max=%d) hasExpired=%v", sessCount, maxActiveSessions, hasExpired)
	}

	srv.rlMu.Lock()
	srv.failures["old-expired-ip"] = []time.Time{time.Now().Add(-2 * rateLimitWindow)}
	for i := 0; i < maxFailureBuckets+20; i++ {
		ip := fmt.Sprintf("192.0.%d.%d", i/256, i%256)
		srv.failures[ip] = []time.Time{time.Now().Add(-time.Duration(i%30) * time.Second)}
	}
	srv.rlMu.Unlock()
	srv.recordLoginFailure("198.51.100.250")
	srv.rlMu.Lock()
	failCount := len(srv.failures)
	_, hasOld := srv.failures["old-expired-ip"]
	srv.rlMu.Unlock()
	if failCount > maxFailureBuckets || hasOld {
		t.Fatalf("failures cap/cleanup failed: count=%d (max=%d) hasOld=%v", failCount, maxFailureBuckets, hasOld)
	}
}

func TestHardeningWebPathWhitelistProxyRateLimitAndBodyLimits(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 1. isHTTPSRequest & clientIPKey trust X-Forwarded-* / X-Real-IP ONLY from loopback RemoteAddr
	nonLoopReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	nonLoopReq.RemoteAddr = "192.0.2.50:12345"
	nonLoopReq.Header.Set("X-Forwarded-Proto", "https")
	nonLoopReq.Header.Set("X-Real-IP", "203.0.113.99")
	if isHTTPSRequest(nonLoopReq) {
		t.Fatalf("non-loopback RemoteAddr must not trust X-Forwarded-Proto")
	}
	if got := clientIPKey(nonLoopReq); got != "192.0.2.50" {
		t.Fatalf("non-loopback RemoteAddr must ignore X-Real-IP, got %q", got)
	}

	loopReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	loopReq.RemoteAddr = "127.0.0.1:54321"
	loopReq.Header.Set("X-Forwarded-Proto", "https")
	loopReq.Header.Set("X-Real-IP", "203.0.113.10")
	if !isHTTPSRequest(loopReq) {
		t.Fatalf("loopback RemoteAddr with X-Forwarded-Proto=https should be HTTPS")
	}
	if got := clientIPKey(loopReq); got != "203.0.113.10" {
		t.Fatalf("loopback RemoteAddr should extract X-Real-IP, got %q", got)
	}

	// 2. Reverse proxy rate-limit isolates per X-Real-IP behind loopback Nginx
	for i := 0; i < rateLimitMaxFails; i++ {
		r, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"wrong"}`))
		r.RemoteAddr = "127.0.0.1:40000"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Real-IP", "203.0.113.10")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, r)
	}
	// 203.0.113.10 is blocked, while 203.0.113.20 behind same loopback proxy logs in cleanly
	blockedReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	blockedReq.RemoteAddr = "127.0.0.1:40001"
	blockedReq.Header.Set("Content-Type", "application/json")
	blockedReq.Header.Set("X-Real-IP", "203.0.113.10")
	blockedRec := httptest.NewRecorder()
	srv.ServeHTTP(blockedRec, blockedReq)
	if blockedRec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for rate-limited X-Real-IP 203.0.113.10, got %d", blockedRec.Code)
	}

	okReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	okReq.RemoteAddr = "127.0.0.1:40002"
	okReq.Header.Set("Content-Type", "application/json")
	okReq.Header.Set("X-Real-IP", "203.0.113.20")
	okRec := httptest.NewRecorder()
	srv.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("expected distinct X-Real-IP 203.0.113.20 login 200, got %d (%s)", okRec.Code, okRec.Body.String())
	}
	var lData map[string]any
	_ = json.Unmarshal(okRec.Body.Bytes(), &lData)
	csrf := lData["csrf_token"].(string)
	cookies := okRec.Result().Cookies()

	doReq := func(method, path, body string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	// 3. /api/v1/migrate & /api/v1/cert/import reject non-whitelisted paths and symlinks escaping whitelist
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.json")
	_ = os.WriteFile(outsideFile, []byte("{}"), 0o600)

	for _, badMig := range []string{
		fmt.Sprintf(`{"kind":"v3_state","path":%q}`, outsideFile),
		`{"kind":"v3_state","path":"/etc/passwd"}`,
		`{"kind":"v3_state","path":"/etc/dex/../passwd"}`,
		`{"kind":"v3_state","path":"/"}`,
	} {
		if rec := doReq(http.MethodPost, "/api/v1/migrate", badMig); rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for non-whitelisted migrate path %s, got %d (%s)", badMig, rec.Code, rec.Body.String())
		}
	}

	symCert := filepath.Join(store.Dir, "evil-sym.pem")
	_ = os.Symlink(outsideFile, symCert)
	for _, badCert := range []string{
		fmt.Sprintf(`{"cert_path":%q,"key_path":%q}`, outsideFile, outsideFile),
		fmt.Sprintf(`{"cert_path":%q,"key_path":%q}`, symCert, filepath.Join(store.Dir, "ssl", "dex.key")),
		`{"cert_path":"/etc/shadow","key_path":"/etc/dex/ssl/dex.key"}`,
	} {
		if rec := doReq(http.MethodPost, "/api/v1/cert/import", badCert); rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for non-whitelisted cert/import %s, got %d (%s)", badCert, rec.Code, rec.Body.String())
		}
	}

	// 4. decodeJSONBody rejects oversized body & trailing non-whitespace tokens
	bigBody := `{"password":"` + strings.Repeat("a", 5000) + `"}`
	bigReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(bigBody))
	var dst map[string]any
	if err := decodeJSONBody(bigReq, &dst, 4096); err == nil || !strings.Contains(err.Error(), "request body too large") {
		t.Fatalf("expected 'request body too large', got %v", err)
	}
	trailReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"x"}{"extra":1}`))
	if err := decodeJSONBody(trailReq, &dst, 4096); err == nil {
		t.Fatalf("expected trailing JSON token rejected")
	}
}

type pausedXrayExec struct {
	stubExec
	active map[string]bool
}

func (p *pausedXrayExec) ServiceIsActive(_ context.Context, _, unit string) bool {
	if p.active != nil {
		return p.active[unit]
	}
	return unit == "dex-daemon" || unit == "nginx" || unit == "dex-doh"
}

func (p *pausedXrayExec) ServiceEnableStart(_ context.Context, _, unit string) error {
	if p.active == nil {
		p.active = map[string]bool{"dex-daemon": true, "nginx": true, "dex-doh": true}
	}
	p.active[unit] = true
	return nil
}

func (p *pausedXrayExec) ServiceStopDisable(_ context.Context, _, unit string) error {
	if p.active == nil {
		p.active = map[string]bool{"dex-daemon": true, "nginx": true, "dex-doh": true}
	}
	p.active[unit] = false
	return nil
}

func TestHardeningWebStatusServerPauseAndCertExternalReconcile(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)
	extCert := filepath.Join(root, "var", "www", "ssl", "de_GWD.cer")
	extKey := filepath.Join(root, "var", "www", "ssl", "de_GWD.key")
	if err := cert.EnsureSelfSigned(extCert, extKey, "srv.example.com"); err != nil {
		t.Fatal(err)
	}

	st := state.NewDefaultState(state.RoleServer)
	st.Server.Domain = "srv.example.com"
	st.Server.TLSMode = "nginx"
	st.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	st.Cert = state.CertConfig{
		Mode:     "imported",
		CertFile: extCert,
		KeyFile:  extKey,
	}
	hash, _ := cryptoext.HashPassword("myPass123")
	st.Auth.PasswordHash = hash
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	hub := daemon.NewTaskHub(20)
	exec := &pausedXrayExec{active: map[string]bool{"dex-daemon": true, "nginx": true, "dex-doh": true}}
	srv := NewServer(store, exec, hub, daemon.NewCloudflareDDNS(hub), reconcile.ApplyOptions{
		RootPrefix: root,
	})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	srv.ServeHTTP(loginRec, loginReq)
	var lData map[string]any
	_ = json.Unmarshal(loginRec.Body.Bytes(), &lData)
	csrf := lData["csrf_token"].(string)
	cookies := loginRec.Result().Cookies()

	doReq := func(method, path, body string) *httptest.ResponseRecorder {
		var rBody io.Reader
		if body != "" {
			rBody = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rBody)
		req.Header.Set("X-CSRF-Token", csrf)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	// 1. Server status reports proxy_paused=true when dex-xray is inactive and omits dex-nft when no nft forwards exist
	stRec := doReq(http.MethodGet, "/api/v1/status", "")
	if stRec.Code != 200 {
		t.Fatalf("status failed: %d %s", stRec.Code, stRec.Body.String())
	}
	var stBody map[string]any
	_ = json.Unmarshal(stRec.Body.Bytes(), &stBody)
	if stBody["proxy_paused"] != true {
		t.Fatalf("expected proxy_paused=true on server with dex-xray inactive, got %v", stBody["proxy_paused"])
	}
	svcs := stBody["services"].(map[string]any)
	if _, hasNFT := svcs["dex-nft"]; hasNFT {
		t.Fatalf("expected dex-nft omitted on server without nft forwards, got %+v", svcs)
	}

	// 2. handleCertSelfSign reconciles nginx back to store.DefaultCert() when switching away from external path
	ssRec := doReq(http.MethodPost, "/api/v1/cert/self-sign", `{"cn":"srv.example.com","force":true}`)
	if ssRec.Code != 200 {
		t.Fatalf("cert/self-sign failed: %d %s", ssRec.Code, ssRec.Body.String())
	}
	ngBytes, err := os.ReadFile(filepath.Join(root, "etc", "nginx", "conf.d", "dex-server.conf"))
	if err != nil || !strings.Contains(string(ngBytes), store.DefaultCert()) {
		t.Fatalf("expected nginx config reconciled to DefaultCert %q after self-sign, err=%v", store.DefaultCert(), err)
	}

	// 3. RoleRelay with nft-only forward reports proxy_paused=false while dex-nft is active, and true when dex-nft stops
	relRoot := t.TempDir()
	relStore := state.NewStore(filepath.Join(relRoot, "etc", "dex"))
	relSt := state.NewDefaultState(state.RoleRelay)
	relSt.Auth.PasswordHash = hash
	relSt.Relay.Forwards = []state.ForwardRule{{
		ID:         "fwd-10001",
		ListenPort: 10001,
		TargetHost: "1.1.1.1",
		TargetPort: 443,
		Proto:      "tcp",
		Engine:     "nft",
	}}
	if err := relStore.Save(relSt); err != nil {
		t.Fatal(err)
	}
	relExec := &pausedXrayExec{active: map[string]bool{"dex-nft": true, "dex-xray": false, "dex-daemon": false}}
	relSrv := NewServer(relStore, relExec, daemon.NewTaskHub(10), daemon.NewCloudflareDDNS(hub), reconcile.ApplyOptions{
		RootPrefix: relRoot,
	})
	relTS := httptest.NewServer(relSrv)
	defer relTS.Close()

	relLoginReq, _ := http.NewRequest(http.MethodPost, relTS.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	relLoginReq.Header.Set("Content-Type", "application/json")
	relLoginRec := httptest.NewRecorder()
	relSrv.ServeHTTP(relLoginRec, relLoginReq)
	relCookies := relLoginRec.Result().Cookies()

	getRelStatus := func() map[string]any {
		req, _ := http.NewRequest(http.MethodGet, relTS.URL+"/api/v1/status", nil)
		for _, c := range relCookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		relSrv.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("relay status failed: %d %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	if got := getRelStatus()["proxy_paused"]; got != false {
		t.Fatalf("expected RoleRelay nft-only with dex-nft active to report proxy_paused=false, got %v", got)
	}
	relExec.active["dex-nft"] = false
	if got := getRelStatus()["proxy_paused"]; got != true {
		t.Fatalf("expected RoleRelay nft-only with dex-nft inactive to report proxy_paused=true, got %v", got)
	}
}

func TestV004WebStatusNetOptAndSystemNetSwitches(t *testing.T) {
	srv, store, root := setupTestWeb(t, false)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	loginReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	srv.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != 200 {
		t.Fatalf("login failed: %d", loginRec.Code)
	}
	var lData map[string]any
	_ = json.Unmarshal(loginRec.Body.Bytes(), &lData)
	csrf := lData["csrf_token"].(string)
	cookies := loginRec.Result().Cookies()

	doReq := func(method, path, body string) *httptest.ResponseRecorder {
		var rBody io.Reader
		if body != "" {
			rBody = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rBody)
		req.Header.Set("X-CSRF-Token", csrf)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	// 1. /api/v1/status exposes net_opt field
	stRec := doReq(http.MethodGet, "/api/v1/status", "")
	if stRec.Code != 200 {
		t.Fatalf("status failed: %d", stRec.Code)
	}
	var stBody map[string]any
	_ = json.Unmarshal(stRec.Body.Bytes(), &stBody)
	if _, hasNetOpt := stBody["net_opt"]; !hasNetOpt {
		t.Fatalf("expected net_opt field in /api/v1/status response, got %+v", stBody)
	}

	// 2. PUT /api/v1/system toggling auto_tune_sysctl & enable_flowtable triggers Reconcile
	sysRec := doReq(http.MethodPut, "/api/v1/system", `{"auto_tune_sysctl":false,"enable_flowtable":false}`)
	if sysRec.Code != 200 || !strings.Contains(sysRec.Body.String(), `"reconciled":true`) {
		t.Fatalf("expected reconciled=true when toggling net switches: %d %s", sysRec.Code, sysRec.Body.String())
	}
	loaded, _ := store.Load()
	if loaded.System.AutoTuneSysctl || loaded.System.EnableFlowtable {
		t.Fatalf("expected AutoTuneSysctl=false and EnableFlowtable=false, got %+v", loaded.System)
	}
	nftBytes, _ := os.ReadFile(filepath.Join(root, "etc", "dex", "generated", "nftables.conf"))
	if strings.Contains(string(nftBytes), "dex_flow") {
		t.Fatalf("expected dex_flow removed when enable_flowtable=false")
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "sysctl.d", "99-dex.conf")); !os.IsNotExist(err) {
		t.Fatalf("expected sysctl file absent when auto_tune_sysctl=false, err=%v", err)
	}
}
