package web

import (
	"encoding/json"
	"os"
	"sync"
	"testing"

	"github.com/stuinxo/dex/internal/state"
)

func TestDoHCacheTracksStateReplacement(t *testing.T) {
	for _, backup := range []bool{false, true} {
		name := "primary"
		if backup {
			name = "backup"
		}
		t.Run(name, func(t *testing.T) {
			srv, store, _ := setupTestWeb(t, false)
			st, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			st.Client.DNS.EnableDoHServer = true
			st.Client.DNS.DoHServerPath = "/dq-first"
			if err := store.Save(st); err != nil {
				t.Fatal(err)
			}
			source := store.StatePath()
			if backup {
				if err := store.Save(st); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(source, []byte("invalid primary"), 0o600); err != nil {
					t.Fatal(err)
				}
				source = store.BackupPath()
			}
			if srv.clientDoH.lookup(store, "/dq-first", srv.ClientDoHUpstreams) == nil {
				t.Fatal("initial route missing")
			}
			previous, err := os.Stat(source)
			if err != nil {
				t.Fatal(err)
			}
			st.Client.DNS.DoHServerPath = "/dq-other"
			if backup {
				bytes, err := json.MarshalIndent(st, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				bytes = append(bytes, '\n')
				if err := os.WriteFile(source+".replacement", bytes, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(source+".replacement", source); err != nil {
					t.Fatal(err)
				}
			} else if err := store.Save(st); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(source, previous.ModTime(), previous.ModTime()); err != nil {
				t.Fatal(err)
			}
			current, err := os.Stat(source)
			if err != nil {
				t.Fatal(err)
			}
			if current.Size() != previous.Size() {
				t.Fatal("fixture must preserve file size")
			}
			if srv.clientDoH.lookup(store, "/dq-first", srv.ClientDoHUpstreams) != nil || srv.clientDoH.lookup(store, "/dq-other", srv.ClientDoHUpstreams) == nil {
				t.Fatal("route cache ignored a replaced state source")
			}
		})
	}
}

func TestDoHCacheLifecycle(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)
	if _, err := store.Update("client", func(st *state.State) error {
		st.Client.DNS.EnableDoHServer = true
		st.Client.DNS.DoHServerPath = "/cache-route"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cache := &srv.clientDoH
	first := cache.lookup(store, "/cache-route", nil)
	if first == nil {
		t.Fatal("route missing")
	}
	if cache.lookup(store, "/cache-route", nil) != first {
		t.Fatal("unchanged route did not reuse handler")
	}
	cache.invalidate()
	if cache.lookup(store, "/cache-route", nil) != first {
		t.Fatal("reload changed an unchanged handler")
	}
	if cache.lookup(store, "/cache-route", []string{"127.0.0.1:5353"}) == first {
		t.Fatal("upstream change did not rebuild handler")
	}
	if _, err := store.Update("client", func(st *state.State) error {
		st.Client.DNS.EnableDoHServer = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if cache.lookup(store, "/cache-route", nil) != nil {
		t.Fatal("disabled route remains available")
	}
}

func TestDoHCacheConcurrentInvalidation(t *testing.T) {
	srv, store, _ := setupTestWeb(t, false)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 20; j++ {
				srv.clientDoH.lookup(store, "/cache-route", nil)
				srv.InvalidateDoHCache()
			}
		}()
	}
	workers.Wait()
	if _, err := store.Update("client", func(st *state.State) error {
		st.Client.DNS.EnableDoHServer = true
		st.Client.DNS.DoHServerPath = "/cache-route"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if srv.clientDoH.lookup(store, "/cache-route", nil) == nil {
		t.Fatal("fresh state unavailable after invalidation")
	}
}
