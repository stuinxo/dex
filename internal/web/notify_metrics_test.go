package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/daemon"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/state"
)

func TestNotifyTestAndNodeMetricsEndpoints(t *testing.T) {
	store := state.NewStore(t.TempDir())
	st := state.NewDefaultState(state.RoleClient)
	st.Client.Nodes = []state.OutboundNode{{
		ID:       "n1",
		Name:     "HK",
		Protocol: "vless-xhttp",
		Address:  "hk.example.com",
		Port:     443,
		UUID:     "11111111-1111-4111-8111-111111111111",
	}}
	st.Client.ActiveNodeID = "n1"

	var receivedWebhook map[string]any
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedWebhook)
		w.WriteHeader(http.StatusOK)
	}))
	defer whSrv.Close()

	pwHash, err := cryptoext.HashPassword("testpass123")
	if err != nil {
		t.Fatal(err)
	}
	st.Auth.PasswordHash = pwHash
	st.System.Notify = state.NotifyConfig{
		Enabled:          true,
		WebhookURL:       whSrv.URL,
		TelegramBotToken: "123:ABC",
		TelegramChatID:   "456",
		NotifyFailover:   true,
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	hub := daemon.NewTaskHub(20)
	srv := NewServer(store, reconcile.OSExecutor{}, hub, daemon.NewCloudflareDDNS(hub), reconcile.ApplyOptions{})
	srv.Notifier.HTTPClient = whSrv.Client()
	srv.ProbeNodeFn = func(_ context.Context, n state.OutboundNode) daemon.ProbeNodeResult {
		return daemon.ProbeNodeResult{NodeID: n.ID, Healthy: true, StatusCode: 404, LatencyMS: 28}
	}

	// Authenticate via POST /api/v1/auth/login -> get session cookie + CSRF token
	recSess := httptest.NewRecorder()
	reqSess := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"password":"testpass123"}`))
	reqSess.RemoteAddr = "127.0.0.1:12345"
	srv.ServeHTTP(recSess, reqSess)
	if recSess.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", recSess.Code, recSess.Body.String())
	}
	var sessBody struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(recSess.Body.Bytes(), &sessBody)
	cookies := recSess.Result().Cookies()

	// 1. GET /api/v1/state must redact notify secrets
	recState := httptest.NewRecorder()
	reqState := httptest.NewRequest(http.MethodGet, "/api/v1/state", nil)
	reqState.RemoteAddr = "127.0.0.1:12345"
	for _, c := range cookies {
		reqState.AddCookie(c)
	}
	srv.ServeHTTP(recState, reqState)
	if recState.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/state failed: %d", recState.Code)
	}
	var stateResp struct {
		State   state.State     `json:"state"`
		Secrets map[string]bool `json:"secrets"`
	}
	_ = json.Unmarshal(recState.Body.Bytes(), &stateResp)
	if stateResp.State.System.Notify.WebhookURL != secretKeepSentinel || stateResp.State.System.Notify.TelegramBotToken != secretKeepSentinel {
		t.Fatalf("expected notify secrets redacted, got %+v", stateResp.State.System.Notify)
	}
	if !stateResp.Secrets["has_notify_webhook_url"] || !stateResp.Secrets["has_notify_telegram_token"] {
		t.Fatalf("expected secret flags set, got %+v", stateResp.Secrets)
	}

	// 2. POST /api/v1/nodes/probe feeds GET /api/v1/metrics/nodes
	recProbe := httptest.NewRecorder()
	reqProbe := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/probe", bytes.NewBufferString(`{}`))
	reqProbe.RemoteAddr = "127.0.0.1:12345"
	reqProbe.Header.Set("X-CSRF-Token", sessBody.CSRFToken)
	for _, c := range cookies {
		reqProbe.AddCookie(c)
	}
	srv.ServeHTTP(recProbe, reqProbe)
	if recProbe.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/nodes/probe failed: %d %s", recProbe.Code, recProbe.Body.String())
	}

	recMetrics := httptest.NewRecorder()
	reqMetrics := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/nodes", nil)
	reqMetrics.RemoteAddr = "127.0.0.1:12345"
	for _, c := range cookies {
		reqMetrics.AddCookie(c)
	}
	srv.ServeHTTP(recMetrics, reqMetrics)
	if recMetrics.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/metrics/nodes failed: %d %s", recMetrics.Code, recMetrics.Body.String())
	}
	var metricsResp struct {
		Nodes []daemon.NodeMetricsSummary `json:"nodes"`
	}
	_ = json.Unmarshal(recMetrics.Body.Bytes(), &metricsResp)
	if len(metricsResp.Nodes) != 1 || metricsResp.Nodes[0].SampleCount != 1 || metricsResp.Nodes[0].AvgLatencyMS != 28 {
		t.Fatalf("unexpected metrics response: %+v", metricsResp.Nodes)
	}

	// 3. POST /api/v1/notify/test sends webhook using stored webhook_url (clear tg to test webhook alone)
	_, _ = store.Update(state.RoleClient, func(cur *state.State) error {
		cur.System.Notify.TelegramBotToken = ""
		cur.System.Notify.TelegramChatID = ""
		return nil
	})
	recTest := httptest.NewRecorder()
	reqTest := httptest.NewRequest(http.MethodPost, "/api/v1/notify/test", bytes.NewBufferString(`{}`))
	reqTest.RemoteAddr = "127.0.0.1:12345"
	reqTest.Header.Set("X-CSRF-Token", sessBody.CSRFToken)
	for _, c := range cookies {
		reqTest.AddCookie(c)
	}
	srv.ServeHTTP(recTest, reqTest)
	if recTest.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/notify/test failed: %d %s", recTest.Code, recTest.Body.String())
	}
	if receivedWebhook["event"] != "test" {
		t.Fatalf("expected test webhook event, got %+v", receivedWebhook)
	}
}

func TestNodeMetricsDoesNotExposeRemovedNodes(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)
	srv.Metrics.Record(daemon.ProbeNodeResult{NodeID: "n1", Healthy: true, LatencyMS: 10})
	if _, err := store.Update(state.RoleClient, func(st *state.State) error {
		st.Client.Nodes = nil
		st.Client.ActiveNodeID = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.handleNodeMetrics(rec, httptest.NewRequest("GET", "/api/v1/metrics/nodes", nil), nil)
	if rec.Code != 200 {
		t.Fatalf("metrics returned %d", rec.Code)
	}
	var response struct {
		Nodes []daemon.NodeMetricsSummary `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Nodes) != 0 {
		t.Fatal("metrics endpoint returned removed nodes")
	}
}
