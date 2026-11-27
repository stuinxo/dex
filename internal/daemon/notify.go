package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stuinxo/dex/internal/state"
)

// AlertEvent describes a lightweight operational event emitted by daemon controllers.
type AlertEvent struct {
	Event     string `json:"event"`    // failover | failback | all_down | ddns_updated | ddns_failed | test
	Severity  string `json:"severity"` // info | warn | error
	Host      string `json:"host"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// Notifier delivers alert events to configured Webhook and/or Telegram Bot channels.
type Notifier struct {
	HTTPClient      *http.Client
	TelegramAPIBase string
	Hub             *TaskHub
}

// NewNotifier creates a Notifier with a direct-routing HTTP client (bypasses client TPROXY loop).
func NewNotifier(hub *TaskHub) *Notifier {
	c := newDirectHTTPClient()
	c.Timeout = 8 * time.Second
	return &Notifier{
		HTTPClient:      c,
		TelegramAPIBase: "https://api.telegram.org",
		Hub:             hub,
	}
}

func (n *Notifier) client() *http.Client {
	if n != nil && n.HTTPClient != nil {
		return n.HTTPClient
	}
	c := newDirectHTTPClient()
	c.Timeout = 8 * time.Second
	return c
}

func (n *Notifier) tgBase() string {
	if n != nil && strings.TrimSpace(n.TelegramAPIBase) != "" {
		return strings.TrimRight(strings.TrimSpace(n.TelegramAPIBase), "/")
	}
	return "https://api.telegram.org"
}

func (n *Notifier) log(level, msg string) {
	if n != nil && n.Hub != nil {
		n.Hub.Log(level, "notify", msg)
	}
}

func defaultEventHost(st *state.State) string {
	if st != nil && strings.TrimSpace(st.System.Hostname) != "" {
		return strings.TrimSpace(st.System.Hostname)
	}
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return strings.TrimSpace(h)
	}
	return "dex"
}

// Send dispatches ev to all configured channels in cfg.
// Returns nil if all configured channels succeed; returns a joined error otherwise.
func (n *Notifier) Send(ctx context.Context, cfg state.NotifyConfig, ev AlertEvent) error {
	wh := strings.TrimSpace(cfg.WebhookURL)
	tgTok := strings.TrimSpace(cfg.TelegramBotToken)
	tgChat := strings.TrimSpace(cfg.TelegramChatID)
	if wh == "" && (tgTok == "" || tgChat == "") {
		return errors.New("no notification channel configured")
	}

	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if ev.Host == "" {
		ev.Host = defaultEventHost(nil)
	}
	if ev.Severity == "" {
		ev.Severity = "info"
	}

	textSummary := fmt.Sprintf("[%s][%s] %s: %s", strings.ToUpper(ev.Severity), ev.Host, ev.Title, ev.Message)
	var errs []error

	if wh != "" {
		payload := map[string]any{
			"event":     ev.Event,
			"severity":  ev.Severity,
			"host":      ev.Host,
			"title":     ev.Title,
			"message":   ev.Message,
			"timestamp": ev.Timestamp,
			"text":      textSummary,
		}
		if err := n.postJSON(ctx, wh, payload); err != nil {
			n.log("WARN", fmt.Sprintf("webhook notify (%s) failed: %v", ev.Event, err))
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		} else {
			n.log("INFO", fmt.Sprintf("webhook notify (%s) delivered", ev.Event))
		}
	}

	if tgTok != "" && tgChat != "" {
		tgURL := fmt.Sprintf("%s/bot%s/sendMessage", n.tgBase(), tgTok)
		payload := map[string]any{
			"chat_id":                  tgChat,
			"text":                     textSummary,
			"disable_web_page_preview": true,
		}
		if err := n.postJSON(ctx, tgURL, payload); err != nil {
			n.log("WARN", fmt.Sprintf("telegram notify (%s) failed: %v", ev.Event, err))
			errs = append(errs, fmt.Errorf("telegram: %w", err))
		} else {
			n.log("INFO", fmt.Sprintf("telegram notify (%s) delivered", ev.Event))
		}
	}

	return errors.Join(errs...)
}

func (n *Notifier) postJSON(ctx context.Context, targetURL string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dex-notifier/1")

	resp, err := n.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// NodeProbeSample captures one timestamped node health probe result.
type NodeProbeSample struct {
	Timestamp  string `json:"timestamp"`
	Healthy    bool   `json:"healthy"`
	LatencyMS  int64  `json:"latency_ms"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

// NodeMetricsSummary summarizes recent probe samples for a single node.
type NodeMetricsSummary struct {
	NodeID        string            `json:"node_id"`
	Name          string            `json:"name,omitempty"`
	Protocol      string            `json:"protocol,omitempty"`
	SampleCount   int               `json:"sample_count"`
	SuccessCount  int               `json:"success_count"`
	LossPercent   float64           `json:"loss_percent"`
	LastHealthy   bool              `json:"last_healthy"`
	LastLatencyMS int64             `json:"last_latency_ms"`
	AvgLatencyMS  int64             `json:"avg_latency_ms"`
	MinLatencyMS  int64             `json:"min_latency_ms"`
	MaxLatencyMS  int64             `json:"max_latency_ms"`
	LastCheckedAt string            `json:"last_checked_at,omitempty"`
	LastError     string            `json:"last_error,omitempty"`
	Recent        []NodeProbeSample `json:"recent,omitempty"`
}

// NodeMetricsTracker maintains a bounded in-memory ring buffer of probe samples per node.
type NodeMetricsTracker struct {
	mu      sync.RWMutex
	maxPer  int
	samples map[string][]NodeProbeSample
}

// NewNodeMetricsTracker constructs a tracker keeping up to maxPer samples per node (default 60).
func NewNodeMetricsTracker(maxPer int) *NodeMetricsTracker {
	if maxPer <= 0 {
		maxPer = 60
	}
	return &NodeMetricsTracker{
		maxPer:  maxPer,
		samples: make(map[string][]NodeProbeSample),
	}
}

// Record appends a probe result for a node.
func (m *NodeMetricsTracker) Record(res ProbeNodeResult) {
	if m == nil || strings.TrimSpace(res.NodeID) == "" {
		return
	}
	sample := NodeProbeSample{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Healthy:    res.Healthy,
		LatencyMS:  res.LatencyMS,
		StatusCode: res.StatusCode,
		Error:      res.Error,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	list := append(m.samples[res.NodeID], sample)
	if len(list) > m.maxPer {
		list = append([]NodeProbeSample(nil), list[len(list)-m.maxPer:]...)
	}
	m.samples[res.NodeID] = list
}

// Summaries computes per-node latency and packet-loss summaries.
// If nodes is non-empty, results follow the configured node order and include nodes with 0 samples.
func (m *NodeMetricsTracker) Summaries(nodes []state.OutboundNode) []NodeMetricsSummary {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	build := func(id, name, proto string, list []NodeProbeSample) NodeMetricsSummary {
		sum := NodeMetricsSummary{
			NodeID:      id,
			Name:        name,
			Protocol:    proto,
			SampleCount: len(list),
		}
		if len(list) == 0 {
			return sum
		}
		var totalLat int64
		var minLat, maxLat int64
		hasLat := false
		for _, s := range list {
			if s.Healthy {
				sum.SuccessCount++
				if !hasLat {
					minLat = s.LatencyMS
					maxLat = s.LatencyMS
					hasLat = true
				} else {
					if s.LatencyMS < minLat {
						minLat = s.LatencyMS
					}
					if s.LatencyMS > maxLat {
						maxLat = s.LatencyMS
					}
				}
				totalLat += s.LatencyMS
			}
		}
		last := list[len(list)-1]
		sum.LastHealthy = last.Healthy
		sum.LastLatencyMS = last.LatencyMS
		sum.LastCheckedAt = last.Timestamp
		sum.LastError = last.Error
		if sum.SuccessCount > 0 {
			sum.AvgLatencyMS = totalLat / int64(sum.SuccessCount)
			sum.MinLatencyMS = minLat
			sum.MaxLatencyMS = maxLat
		}
		failed := sum.SampleCount - sum.SuccessCount
		sum.LossPercent = float64(failed*1000/sum.SampleCount) / 10.0

		// Return up to the last 20 samples for compact sparkline/trend rendering.
		start := 0
		if len(list) > 20 {
			start = len(list) - 20
		}
		sum.Recent = append([]NodeProbeSample(nil), list[start:]...)
		return sum
	}

	if len(nodes) > 0 {
		out := make([]NodeMetricsSummary, 0, len(nodes))
		for _, n := range nodes {
			out = append(out, build(n.ID, n.Name, n.Protocol, m.samples[n.ID]))
		}
		return out
	}

	ids := make([]string, 0, len(m.samples))
	for id := range m.samples {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]NodeMetricsSummary, 0, len(ids))
	for _, id := range ids {
		out = append(out, build(id, "", "", m.samples[id]))
	}
	return out
}
