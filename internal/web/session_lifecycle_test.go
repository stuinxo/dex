package web

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/state"
)

func TestSessionInvalidatedByStoredPasswordChange(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)
	login := httptest.NewRecorder()
	srv.handleLogin(login, httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`)))
	if login.Code != 200 {
		t.Fatalf("login failed: %d", login.Code)
	}
	request := httptest.NewRequest("GET", "/api/v1/auth/session", nil)
	request.AddCookie(login.Result().Cookies()[0])
	if srv.getSession(request) == nil {
		t.Fatal("new session missing")
	}
	hash, err := cryptoext.HashPassword("replacement-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(state.RoleClient, func(st *state.State) error {
		st.Auth.PasswordHash = hash
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if srv.getSession(request) != nil {
		t.Fatal("session survived stored credential replacement")
	}
}

func TestLegacyLoginCannotOverwriteConcurrentPasswordChange(t *testing.T) {
	srv, store, _ := setupTestWeb(t, true)
	waiting := make(chan struct{}, 1)
	store.OnApplyLockWait = func() { waiting <- struct{}{} }
	done := make(chan struct{})
	login := httptest.NewRecorder()
	replacement, err := cryptoext.HashPassword("replacement-password")
	if err != nil {
		t.Fatal(err)
	}
	err = store.WithApplyLock(context.Background(), func(locked *state.Store) error {
		go func() {
			defer close(done)
			srv.handleLogin(login, httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`)))
		}()
		select {
		case <-waiting:
		case <-time.After(4 * time.Second):
			t.Error("login did not reach rehash write")
			return nil
		}
		_, err := locked.Update(state.RoleClient, func(st *state.State) error {
			st.Auth.PasswordHash = replacement
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
		t.Fatal("login did not resume")
	}
	current, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if current.Auth.PasswordHash != replacement {
		t.Fatal("legacy rehash replaced newer credentials")
	}
	if login.Code != 401 {
		t.Fatalf("stale login returned %d", login.Code)
	}
}

func TestPasswordChangePublishesSessionSnapshot(t *testing.T) {
	srv, _, _ := setupTestWeb(t, false)
	login := httptest.NewRecorder()
	srv.handleLogin(login, httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`)))
	request := httptest.NewRequest("GET", "/api/v1/auth/session", nil)
	request.AddCookie(login.Result().Cookies()[0])
	snapshot := srv.getSession(request)
	if snapshot == nil {
		t.Fatal("session missing")
	}
	previousCSRF := snapshot.csrfToken
	changed := httptest.NewRecorder()
	srv.handleChangePassword(changed, httptest.NewRequest("POST", "/api/v1/auth/password", strings.NewReader(`{"current_password":"myPass123","new_password":"replacement-password"}`)), snapshot)
	if changed.Code != 200 {
		t.Fatalf("change returned %d", changed.Code)
	}
	if snapshot.csrfToken != previousCSRF {
		t.Fatal("password change mutated an in-flight session snapshot")
	}
	current := srv.getSession(request)
	if current == nil || current.csrfToken == previousCSRF {
		t.Fatal("current session was lost or CSRF did not rotate")
	}
	current.csrfToken = "modified-snapshot"
	if srv.getSession(request).csrfToken == "modified-snapshot" {
		t.Fatal("request snapshot aliases stored session")
	}
}

func TestPasswordChangeRejectsConcurrentCredentialReplacement(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)
	login := httptest.NewRecorder()
	srv.handleLogin(login, httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"password":"myPass123"}`)))
	sessionReq := httptest.NewRequest("GET", "/api/v1/auth/session", nil)
	sessionReq.AddCookie(login.Result().Cookies()[0])
	snapshot := srv.getSession(sessionReq)
	replacement, err := cryptoext.HashPassword("concurrent-password")
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
			srv.handleChangePassword(rec, httptest.NewRequest("POST", "/api/v1/auth/password", strings.NewReader(`{"current_password":"myPass123","new_password":"stale-password"}`)), snapshot)
		}()
		select {
		case <-waiting:
		case <-time.After(4 * time.Second):
			t.Error("password change did not reach serialized write")
			return nil
		}
		_, err := locked.Update(state.RoleClient, func(st *state.State) error {
			st.Auth.PasswordHash = replacement
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
		t.Fatal("password change did not resume")
	}
	current, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec.Code != 401 || current.Auth.PasswordHash != replacement {
		t.Fatal("stale password change overwrote current credentials")
	}
}
