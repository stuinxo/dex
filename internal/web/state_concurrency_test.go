package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stuinxo/dex/internal/state"
)

func TestPutStatePreservesSecretsUpdatedWhileWaiting(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)
	_, err := store.Update(state.RoleClient, func(st *state.State) error {
		st.System.Notify.TelegramBotToken = "previous-bot-token"
		st.System.Notify.TelegramChatID = "123"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	incoming, _ = redactStateForAPI(incoming)
	incoming.System.Notify.TelegramChatID = "123"
	body, err := json.Marshal(incoming)
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{}, 1)
	store.OnApplyLockWait = func() { waiting <- struct{}{} }
	done := make(chan struct{})
	rec := httptest.NewRecorder()
	err = store.WithApplyLock(context.Background(), func(locked *state.Store) error {
		go func() {
			defer close(done)
			req := httptest.NewRequest("PUT", "/api/v1/state", bytes.NewReader(body))
			srv.handlePutState(rec, req, nil)
		}()
		select {
		case <-waiting:
		case <-time.After(4 * time.Second):
			t.Error("request did not reach apply lock")
			return nil
		}
		_, err := locked.Update(state.RoleClient, func(st *state.State) error {
			st.Auth.PasswordHash = "concurrent-password-hash"
			st.Cert.CFToken = "concurrent-cert-token"
			st.Client.DDNS.CFToken = "concurrent-ddns-token"
			st.System.Notify.WebhookURL = "https://example.com/new-hook"
			st.System.Notify.TelegramBotToken = "concurrent-bot-token"
			st.System.Notify.TelegramChatID = "123"
			return nil
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("state request did not finish")
	}
	if rec.Code != 200 {
		t.Fatalf("PUT status %d: %s", rec.Code, rec.Body.String())
	}
	current, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if current.Auth.PasswordHash != "concurrent-password-hash" ||
		current.Cert.CFToken != "concurrent-cert-token" ||
		current.Client.DDNS.CFToken != "concurrent-ddns-token" ||
		current.System.Notify.WebhookURL != "https://example.com/new-hook" ||
		current.System.Notify.TelegramBotToken != "concurrent-bot-token" {
		t.Fatal("PUT restored pre-lock secrets over concurrent updates")
	}
}

func TestStateSecretMergeContract(t *testing.T) {
	for _, requested := range []string{"", secretKeepSentinel, "explicit-replacement"} {
		t.Run(requested, func(t *testing.T) {
			current := state.NewDefaultState(state.RoleClient)
			current.Auth.PasswordHash = "stored-hash"
			current.Cert.CFToken = "stored-value"
			current.Client.DDNS.CFToken = "stored-value"
			current.System.Notify.WebhookURL = "stored-value"
			current.System.Notify.TelegramBotToken = "stored-value"
			incoming := state.NewDefaultState(state.RoleClient)
			incoming.Auth.PasswordHash = "submitted-hash"
			incoming.Cert.CFToken = requested
			incoming.Client.DDNS.CFToken = requested
			incoming.System.Notify.WebhookURL = requested
			incoming.System.Notify.TelegramBotToken = requested
			preserveStateSecrets(incoming, current)
			want := "stored-value"
			if requested == "explicit-replacement" {
				want = requested
			}
			if incoming.Auth.PasswordHash != "stored-hash" ||
				incoming.Cert.CFToken != want ||
				incoming.Client.DDNS.CFToken != want ||
				incoming.System.Notify.WebhookURL != want ||
				incoming.System.Notify.TelegramBotToken != want {
				t.Fatal("secret ownership or replacement policy changed")
			}
			if current.Cert.CFToken != "stored-value" || current.Auth.PasswordHash != "stored-hash" {
				t.Fatal("merge changed stored snapshot")
			}
		})
	}
}

func TestPutStateDryRunLeavesSecretsUnchanged(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)
	current, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	incoming, _ := redactStateForAPI(current)
	incoming.Cert.CFToken = "explicit-preview-token"
	body, err := json.Marshal(incoming)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.handlePutState(rec, httptest.NewRequest("PUT", "/api/v1/state?dry_run=1", bytes.NewReader(body)), nil)
	if rec.Code != 200 {
		t.Fatalf("dry-run status %d: %s", rec.Code, rec.Body.String())
	}
	current, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry-run changed stored state")
	}
}

func TestPutStateOptimisticConcurrencyIfMatch(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)

	getRec := httptest.NewRecorder()
	srv.handleGetState(getRec, httptest.NewRequest("GET", "/api/v1/state", nil), nil)
	if getRec.Code != 200 {
		t.Fatalf("GET state failed: %d", getRec.Code)
	}
	var getResp struct {
		State    *state.State `json:"state"`
		Revision string       `json:"revision"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatal(err)
	}
	if len(getResp.Revision) != 32 {
		t.Fatalf("expected 32-char revision, got %q", getResp.Revision)
	}
	if gotETag := getRec.Header().Get("ETag"); gotETag != `"`+getResp.Revision+`"` {
		t.Fatalf("expected quoted ETag %q, got %q", `"`+getResp.Revision+`"`, gotETag)
	}

	// 1. PUT with matching If-Match succeeds and returns a new revision.
	getResp.State.System.Hostname = "tab-a"
	b1, _ := json.Marshal(getResp.State)
	req1 := httptest.NewRequest("PUT", "/api/v1/state", bytes.NewReader(b1))
	req1.Header.Set("If-Match", `"`+getResp.Revision+`"`)
	rec1 := httptest.NewRecorder()
	srv.handlePutState(rec1, req1, nil)
	if rec1.Code != 200 {
		t.Fatalf("expected 200 on matching If-Match, got %d: %s", rec1.Code, rec1.Body.String())
	}
	var putResp1 struct {
		Revision string `json:"revision"`
	}
	_ = json.Unmarshal(rec1.Body.Bytes(), &putResp1)
	if putResp1.Revision == "" || putResp1.Revision == getResp.Revision {
		t.Fatalf("expected updated revision != %q, got %q", getResp.Revision, putResp1.Revision)
	}

	// 2. PUT with stale If-Match fails with 409 Conflict without overwriting tab-a.
	getResp.State.System.Hostname = "tab-b-stale"
	b2, _ := json.Marshal(getResp.State)
	req2 := httptest.NewRequest("PUT", "/api/v1/state", bytes.NewReader(b2))
	req2.Header.Set("If-Match", getResp.Revision)
	rec2 := httptest.NewRecorder()
	srv.handlePutState(rec2, req2, nil)
	if rec2.Code != 409 {
		t.Fatalf("expected 409 Conflict on stale If-Match, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if cur, _ := store.Load(); cur.System.Hostname != "tab-a" {
		t.Fatalf("expected hostname tab-a preserved on conflict, got %q", cur.System.Hostname)
	}

	// 3. PUT with force=1 bypasses stale If-Match.
	req3 := httptest.NewRequest("PUT", "/api/v1/state?force=1", bytes.NewReader(b2))
	req3.Header.Set("If-Match", getResp.Revision)
	rec3 := httptest.NewRecorder()
	srv.handlePutState(rec3, req3, nil)
	if rec3.Code != 200 {
		t.Fatalf("expected force=1 to bypass If-Match, got %d: %s", rec3.Code, rec3.Body.String())
	}

	// 4. Omitting If-Match preserves backward compatibility for existing API callers.
	getResp.State.System.Hostname = "compat-no-if-match"
	b4, _ := json.Marshal(getResp.State)
	rec4 := httptest.NewRecorder()
	srv.handlePutState(rec4, httptest.NewRequest("PUT", "/api/v1/state", bytes.NewReader(b4)), nil)
	if rec4.Code != 200 {
		t.Fatalf("expected PUT without If-Match to succeed, got %d: %s", rec4.Code, rec4.Body.String())
	}
}
