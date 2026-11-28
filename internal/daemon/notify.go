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
	"strings"
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
