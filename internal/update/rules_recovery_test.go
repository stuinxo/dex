package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stuinxo/dex/internal/state"
)

func TestFailedRuleRecoveryRetainsBackup(t *testing.T) {
	t.Setenv("GH_PROXY", "")
	store := state.NewStore(t.TempDir())
	rulesDir := filepath.Join(store.Dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(rulesDir, "geoip.dat")
	if err := os.WriteFile(live, []byte("known-good"), 0o640); err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := os.Remove(live); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(live, 0o755); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer remote.Close()
	err := UpdateRules(context.Background(), store, nil, OpsConfig{Client: remote.Client(), GeoIPURL: remote.URL + "/geoip.dat"}, false, true, nil)
	if err == nil || !strings.Contains(err.Error(), "restore rules") {
		t.Errorf("recovery failure hidden: %v", err)
	}
	dirs, globErr := filepath.Glob(filepath.Join(rulesDir, ".rules-bak-*"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(dirs) != 1 {
		t.Fatalf("recovery backups removed: %v", dirs)
	}
	saved, readErr := os.ReadFile(filepath.Join(dirs[0], "geoip.dat"))
	if readErr != nil || string(saved) != "known-good" {
		t.Fatal("known-good backup unavailable")
	}
	if !strings.Contains(err.Error(), dirs[0]) {
		t.Fatal("recovery path missing from returned error")
	}
}

func TestRuleRestoreContinuesAndCanRetry(t *testing.T) {
	rulesDir := t.TempDir()
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if err := os.WriteFile(filepath.Join(rulesDir, name), []byte("original"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	backups, dir, err := backupRulesFiles(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	for _, b := range backups {
		if b.existed {
			if err := os.WriteFile(b.livePath, []byte("updated"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	firstBackup := filepath.Join(dir, "geoip.dat")
	if err := os.Remove(firstBackup); err != nil {
		t.Fatal(err)
	}
	err = restoreRulesFiles(backups)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing source error not retained: %v", err)
	}
	restored, err := os.ReadFile(filepath.Join(rulesDir, "geosite.dat"))
	if err != nil || string(restored) != "original" {
		t.Fatal("one failure prevented other file recovery")
	}
	if err := os.WriteFile(firstBackup, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := restoreRulesFiles(backups); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(rulesDir, "geoip.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatal("retry did not restore original permissions")
	}
}

func TestSuccessfulRuleRecoveryCleansBackup(t *testing.T) {
	t.Setenv("GH_PROXY", "")
	store := state.NewStore(t.TempDir())
	rulesDir := filepath.Join(store.Dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(rulesDir, "geoip.dat")
	if err := os.WriteFile(live, []byte("original"), 0o640); err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer remote.Close()
	err := UpdateRules(context.Background(), store, nil, OpsConfig{Client: remote.Client(), GeoIPURL: remote.URL}, false, true, nil)
	if err == nil || strings.Contains(err.Error(), "restore rules") {
		t.Fatalf("unexpected download/recovery outcome: %v", err)
	}
	dirs, err := filepath.Glob(filepath.Join(rulesDir, ".rules-bak-*"))
	if err != nil || len(dirs) != 0 {
		t.Fatalf("successful recovery left backups: %v", dirs)
	}
	restored, err := os.ReadFile(live)
	if err != nil || string(restored) != "original" {
		t.Fatal("original rules missing")
	}
}
