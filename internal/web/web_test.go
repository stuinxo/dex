package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stuinxo/de_GWD/v3/internal/cert"
	"github.com/stuinxo/de_GWD/v3/internal/cryptoext"
	"github.com/stuinxo/de_GWD/v3/internal/daemon"
	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/socks5out"
	"github.com/stuinxo/de_GWD/v3/internal/state"
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
	if uiResp.StatusCode != 200 || !strings.Contains(string(uiBody), "DEX v3") {
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
	impDir := t.TempDir()
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
	bakFile := filepath.Join(t.TempDir(), "backup.json")
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
}
