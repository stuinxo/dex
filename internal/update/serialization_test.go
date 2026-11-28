package update

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stuinxo/dex/internal/state"
)

func TestUpdatesWaitForApplyAndCancelWithoutDownloads(t *testing.T) {
	t.Setenv("GH_PROXY", "")
	for _, operation := range []string{"rules", "components"} {
		t.Run(operation, func(t *testing.T) {
			requests := make(chan struct{}, 8)
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- struct{}{}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer remote.Close()
			store := state.NewStore(t.TempDir())
			waiting := make(chan struct{}, 1)
			store.OnApplyLockWait = func() { waiting <- struct{}{} }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			cfg := OpsConfig{Client: remote.Client(), GeoIPURL: remote.URL + "/geoip", DexReleaseBase: remote.URL}
			run := func(ctx context.Context) error {
				if operation == "rules" {
					return UpdateRules(ctx, store, nil, cfg, false, true, nil)
				}
				return UpdateComponents(ctx, store, nil, cfg, "dex", "latest", nil)
			}
			err := store.WithApplyLock(context.Background(), func(_ *state.Store) error {
				go func() { done <- run(ctx) }()
				select {
				case <-waiting:
				case <-requests:
					t.Error("update downloaded while another apply owned the configuration")
				case <-time.After(4 * time.Second):
					t.Error("update neither waited nor attempted its work")
				}
				cancel()
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("update error %v, want cancellation", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled update did not finish")
			}
			select {
			case <-requests:
				t.Error("cancelled waiter attempted download")
			default:
			}
		})
	}
}

func TestComponentRulesUpdateReusesApplyScope(t *testing.T) {
	t.Setenv("GH_PROXY", "")
	files := map[string]string{
		"/geoip.dat": "geoip-data", "/geosite.dat": "geosite-data",
		"/IPchnroute": "1.0.0.0/8\n", "/domains": "example.com\n",
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(r.URL.Path, ".sha256sum")
		body, ok := files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".sha256sum") {
			sum := sha256.Sum256([]byte(body))
			fmt.Fprintf(w, "%x  %s\n", sum, filepath.Base(name))
			return
		}
		fmt.Fprint(w, body)
	}))
	defer remote.Close()
	store := state.NewStore(t.TempDir())
	cfg := OpsConfig{
		Client: remote.Client(), GeoIPURL: remote.URL + "/geoip.dat", GeoSiteURL: remote.URL + "/geosite.dat",
		ChnRouteURL: remote.URL + "/IPchnroute", DomainsChnURL: remote.URL + "/domains",
		DomainsAppleURL: remote.URL + "/domains", DomainsGamesURL: remote.URL + "/domains",
		MinChnRouteCIDR: 1, MinChnDomains: 1, MinAppleDomains: 1, MinGamesDomains: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := UpdateComponents(ctx, store, nil, cfg, "rules", "latest", nil); err != nil {
		t.Fatalf("nested rules update: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "rules", "geoip.dat")); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(state.NewDefaultState(state.RoleClient)); err != nil {
		t.Fatal(err)
	}
}
