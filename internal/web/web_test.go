package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/stuinxo/de_GWD/v3/internal/cryptoext"
	"github.com/stuinxo/de_GWD/v3/internal/daemon"
	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

type stubExec struct{}

func (stubExec) RunCommand(context.Context, []string, string, ...string) (string, error) { return "ok", nil }
func (stubExec) HasCommand(string) bool                                                { return false }
func (stubExec) DaemonReload(context.Context, string) error                            { return nil }
func (stubExec) ServiceEnableStart(context.Context, string, string) error              { return nil }
func (stubExec) ServiceRestart(context.Context, string, string) error                  { return nil }
func (stubExec) ServiceReload(context.Context, string, string) error                   { return nil }
func (stubExec) ServiceStopDisable(context.Context, string, string) error              { return nil }
func (stubExec) ServiceIsActive(context.Context, string, string) bool                  { return true }
func (stubExec) DetectInitSystem() string                                              { return "systemd" }
func (stubExec) DetectIsContainer() bool                                               { return false }
func (stubExec) DetectMemMB() int                                                      { return 512 }
func (stubExec) DetectPhysicalNICs() []string                                          { return []string{"eth0"} }
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
