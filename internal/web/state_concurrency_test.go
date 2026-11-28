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
