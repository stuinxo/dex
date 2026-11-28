package web

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/stuinxo/dex/internal/doh"
	"github.com/stuinxo/dex/internal/state"
)

// clientDoHCache owns route configuration and handler reuse. Its mutex also
// serializes reloads with invalidation so an older loader cannot republish state.
type clientDoHCache struct {
	mu           sync.Mutex
	sources      [2]os.FileInfo
	loaded       bool
	path         string
	upstreamsKey string
	handler      *doh.Handler
}

func (c *clientDoHCache) invalidate() {
	c.mu.Lock()
	c.loaded = false
	c.mu.Unlock()
}

func sameDoHSources(a, b [2]os.FileInfo) bool {
	for i, file := range a {
		other := b[i]
		if file == nil || other == nil {
			if file != nil || other != nil {
				return false
			}
			continue
		}
		if !os.SameFile(file, other) || file.Size() != other.Size() || !file.ModTime().Equal(other.ModTime()) {
			return false
		}
	}
	return true
}

func (c *clientDoHCache) lookup(store *state.Store, reqPath string, upstreams []string) *doh.Handler {
	if store == nil || reqPath == "" || reqPath == "/" || strings.HasPrefix(reqPath, "/api/") {
		return nil
	}
	if len(upstreams) == 0 {
		upstreams = []string{"127.0.0.1:53"}
	}
	upstreamsKey := strings.Join(upstreams, ",")

	c.mu.Lock()
	defer c.mu.Unlock()
	var sources [2]os.FileInfo
	sources[0], _ = os.Stat(store.StatePath())
	sources[1], _ = os.Stat(store.BackupPath())
	if !c.loaded || !sameDoHSources(c.sources, sources) || c.upstreamsKey != upstreamsKey {
		st, err := store.Load()
		if err != nil {
			c.loaded = false
			return nil
		}
		path := ""
		if st.Role == state.RoleClient && st.Client.DNS.EnableDoHServer {
			path = st.Client.DNS.EffectiveDoHPath()
		}
		if path != "" && (c.handler == nil || c.path != path || c.upstreamsKey != upstreamsKey) {
			c.handler = doh.NewHandler(doh.Config{
				Path:          path,
				Upstreams:     append([]string(nil), upstreams...),
				Timeout:       5 * time.Second,
				MaxConcurrent: 128,
			})
		}
		c.path = path
		c.sources = sources
		c.upstreamsKey = upstreamsKey
		c.loaded = true
	}
	if c.path != "" && reqPath == c.path {
		return c.handler
	}
	return nil
}
