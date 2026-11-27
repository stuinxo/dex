package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stuinxo/dex/internal/state"
)

func TestNotifierWebhookAndTelegram(t *testing.T) {
	var (
		mu         sync.Mutex
		gotWebhook map[string]any
		gotTG      map[string]any
		gotTGPath  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/webhook" {
			gotWebhook = body
			w.WriteHeader(http.StatusOK)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/bot") {
			gotTGPath = r.URL.Path
			gotTG = body
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	hub := NewTaskHub(20)
	n := NewNotifier(hub)
	n.HTTPClient = srv.Client()
	n.TelegramAPIBase = srv.URL

	cfg := state.NotifyConfig{
		Enabled:          true,
		WebhookURL:       srv.URL + "/webhook",
		TelegramBotToken: "111:SECRET",
		TelegramChatID:   "999888",
	}
	err := n.Send(context.Background(), cfg, AlertEvent{
		Event:    "failover",
		Severity: "warn",
		Host:     "gw-home",
		Title:    "DEX Node Failover",
		Message:  "switched n1 -> n2",
	})
	if err != nil {
		t.Fatalf("Notifier.Send failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotWebhook["event"] != "failover" || gotWebhook["host"] != "gw-home" {
		t.Fatalf("unexpected webhook payload: %+v", gotWebhook)
	}
	if !strings.Contains(gotWebhook["text"].(string), "switched n1 -> n2") {
		t.Fatalf("unexpected webhook text: %v", gotWebhook["text"])
	}
	if gotTGPath != "/bot111:SECRET/sendMessage" || gotTG["chat_id"] != "999888" {
		t.Fatalf("unexpected telegram request: path=%q body=%+v", gotTGPath, gotTG)
	}
}

func TestFailoverEmitsAlertsAndRecordsMetrics(t *testing.T) {
	hub := NewTaskHub(50)
	st := state.NewDefaultState(state.RoleClient)
	st.System.Hostname = "gw-test"
	st.Client.FailoverEnabled = true
	st.Client.Nodes = []state.OutboundNode{
		{ID: "n1", Name: "Primary", Protocol: "vless-xhttp", Address: "1.1.1.1", Port: 443, UUID: "11111111-1111-4111-8111-111111111111"},
		{ID: "n2", Name: "Backup", Protocol: "vless-xhttp", Address: "2.2.2.2", Port: 443, UUID: "22222222-2222-4222-8222-222222222222"},
	}
	st.Client.ActiveNodeID = "n1"

	egressOK := false
	nodeHealthy := map[string]bool{"n1": false, "n2": false}
	var events []AlertEvent

	metrics := NewNodeMetricsTracker(10)
	fc := NewFailoverController(hub, func(ctx context.Context, id string) error {
		st.Client.ActiveNodeID = id
		return nil
	})
	fc.Metrics = metrics
	fc.OnEvent = func(_ context.Context, ev AlertEvent) {
		events = append(events, ev)
	}
	fc.ProbeEgress = func(context.Context) bool { return egressOK }
	fc.ProbeNode = func(_ context.Context, n state.OutboundNode) ProbeNodeResult {
		lat := int64(42)
		if !nodeHealthy[n.ID] {
			lat = 0
		}
		return ProbeNodeResult{NodeID: n.ID, Healthy: nodeHealthy[n.ID], LatencyMS: lat}
	}

	// 4 consecutive failures with all backups down -> emits all_down ONCE (no spam)
	for i := 0; i < 4; i++ {
		fc.Step(context.Background(), st)
	}
	if len(events) != 1 || events[0].Event != "all_down" {
		t.Fatalf("expected single all_down event, got %+v", events)
	}

	// Backup becomes healthy -> failover event emitted
	nodeHealthy["n2"] = true
	fc.Step(context.Background(), st)
	if st.Client.ActiveNodeID != "n2" {
		t.Fatalf("expected failover to n2, got %q", st.Client.ActiveNodeID)
	}
	if len(events) != 2 || events[1].Event != "failover" {
		t.Fatalf("expected failover event, got %+v", events)
	}

	// Primary recovers for 3 ticks -> failback event emitted
	egressOK = true
	nodeHealthy["n1"] = true
	for i := 0; i < 3; i++ {
		fc.Step(context.Background(), st)
	}
	if st.Client.ActiveNodeID != "n1" {
		t.Fatalf("expected failback to n1, got %q", st.Client.ActiveNodeID)
	}
	if len(events) != 3 || events[2].Event != "failback" {
		t.Fatalf("expected failback event, got %+v", events)
	}

	// Verify metrics summaries captured probe history for both nodes
	sums := metrics.Summaries(st.Client.Nodes)
	if len(sums) != 2 {
		t.Fatalf("expected 2 node summaries, got %d", len(sums))
	}
	if sums[0].NodeID != "n1" || sums[0].SampleCount != 3 || sums[0].LossPercent != 0 || sums[0].AvgLatencyMS != 42 {
		t.Fatalf("unexpected n1 metrics: %+v", sums[0])
	}
	if sums[1].NodeID != "n2" || sums[1].SampleCount != 3 || sums[1].SuccessCount != 1 || sums[1].LossPercent <= 0 {
		t.Fatalf("unexpected n2 metrics: %+v", sums[1])
	}
}
