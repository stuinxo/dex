package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/daemon"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/socks5out"
	"github.com/stuinxo/dex/internal/state"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ui/*
var embeddedUI embed.FS

const (
	sessionCookieName  = "dex_session"
	sessionTTL         = 12 * time.Hour
	rateLimitWindow    = 60 * time.Second
	rateLimitMaxFails  = 10
	maxActiveSessions  = 256
	maxFailureBuckets  = 4096
	secretKeepSentinel = "********"
)

type DoHProbeResult struct {
	URL       string `json:"url"`
	OK        bool   `json:"ok"`
	Status    int    `json:"status_code,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// Server serves the embedded Web UI and fail-closed REST/SSE API.
type Server struct {
	Store     *state.Store
	Exec      reconcile.SystemExecutor
	Hub       *daemon.TaskHub
	DDNS      *daemon.CloudflareDDNS
	Notifier  *daemon.Notifier
	Metrics   *daemon.NodeMetricsTracker
	ApplyOpts reconcile.ApplyOptions
	StartedAt time.Time

	ProbeNodeFn         func(ctx context.Context, n state.OutboundNode) daemon.ProbeNodeResult
	ProbeDoHFn          func(ctx context.Context, rawURL string) DoHProbeResult
	ProbeConnectivityFn func(ctx context.Context) (cn, global daemon.ConnectivityCheck)
	ProbeSocks5Fn       func(ctx context.Context, host string, port int, user, pass string, testURLs []string) (*socks5out.ProbeResult, error)
	UpdateRulesFn       func(ctx context.Context, includeAds bool, w io.Writer) error
	UpdateComponentsFn  func(ctx context.Context, component, ver string, w io.Writer) error
	ReloadCertFn        func(ctx context.Context)
	CertReloadCmd       string
	CertRunner          cert.ACMERunner
	ClientDoHUpstreams  []string

	sessMu   sync.RWMutex
	sessions map[string]*sessionRecord

	rlMu     sync.Mutex
	failures map[string][]time.Time

	clientDoH clientDoHCache

	handler http.Handler
}

// NewServer constructs an initialized Web control-plane Server.
func NewServer(store *state.Store, exec reconcile.SystemExecutor, hub *daemon.TaskHub, ddns *daemon.CloudflareDDNS, applyOpts reconcile.ApplyOptions) *Server {
	if exec == nil {
		exec = reconcile.OSExecutor{}
	}
	if hub == nil {
		hub = daemon.NewTaskHub(300)
	}
	if ddns == nil {
		ddns = daemon.NewCloudflareDDNS(hub)
	}
	s := &Server{
		Store:              store,
		Exec:               exec,
		Hub:                hub,
		DDNS:               ddns,
		Notifier:           daemon.NewNotifier(hub),
		Metrics:            daemon.NewNodeMetricsTracker(60),
		ApplyOpts:          applyOpts,
		StartedAt:          time.Now(),
		ClientDoHUpstreams: []string{"127.0.0.1:53"},
		ProbeNodeFn: func(ctx context.Context, n state.OutboundNode) daemon.ProbeNodeResult {
			return daemon.ProbeNodeHealth(ctx, n, 5*time.Second, false)
		},
		ProbeConnectivityFn: daemon.ProbeConnectivity,
		ProbeSocks5Fn:       socks5out.ProbeProfile,
		sessions:            make(map[string]*sessionRecord),
		failures:            make(map[string][]time.Time),
	}
	s.handler = s.buildRouter()
	return s
}

// InvalidateDoHCache forces the next DoH path lookup to reload stored state.
func (s *Server) InvalidateDoHCache() {
	s.clientDoH.invalidate()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := s.clientDoH.lookup(s.Store, r.URL.Path, s.ClientDoHUpstreams); h != nil {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		h.ServeHTTP(w, r)
		return
	}
	s.handler.ServeHTTP(w, r)
}

func (s *Server) buildRouter() http.Handler {
	mux := http.NewServeMux()

	// Auth endpoints
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("GET /api/v1/auth/session", s.handleSession)
	mux.HandleFunc("POST /api/v1/auth/logout", s.requireAuth(true, s.handleLogout))
	mux.HandleFunc("POST /api/v1/auth/password", s.requireAuth(true, s.handleChangePassword))

	// Protected API endpoints
	mux.HandleFunc("GET /api/v1/status", s.requireAuth(false, s.handleStatus))
	mux.HandleFunc("GET /api/v1/state", s.requireAuth(false, s.handleGetState))
	mux.HandleFunc("PUT /api/v1/state", s.requireAuth(true, s.handlePutState))
	mux.HandleFunc("POST /api/v1/nodes/select", s.requireAuth(true, s.handleSelectNode))
	mux.HandleFunc("POST /api/v1/nodes/probe", s.requireAuth(true, s.handleProbeNodes))
	mux.HandleFunc("GET /api/v1/metrics/nodes", s.requireAuth(false, s.handleNodeMetrics))
	mux.HandleFunc("POST /api/v1/notify/test", s.requireAuth(true, s.handleNotifyTest))
	mux.HandleFunc("POST /api/v1/nodes/parse-uri", s.requireAuth(true, s.handleParseNodeURI))
	mux.HandleFunc("POST /api/v1/connectivity", s.requireAuth(true, s.handleConnectivity))
	mux.HandleFunc("POST /api/v1/proxy/stop", s.requireAuth(true, s.handleProxyStop))
	mux.HandleFunc("POST /api/v1/proxy/restart", s.requireAuth(true, s.handleProxyRestart))
	mux.HandleFunc("POST /api/v1/socks5/test", s.requireAuth(true, s.handleTestSocks5))
	mux.HandleFunc("GET /api/v1/rules/status", s.requireAuth(false, s.handleRulesStatus))
	mux.HandleFunc("POST /api/v1/rules/update", s.requireAuth(true, s.handleRulesUpdate))
	mux.HandleFunc("POST /api/v1/update", s.requireAuth(true, s.handleUpdateComponents))
	mux.HandleFunc("POST /api/v1/cert/issue", s.requireAuth(true, s.handleCertIssue))
	mux.HandleFunc("POST /api/v1/cert/import", s.requireAuth(true, s.handleCertImport))
	mux.HandleFunc("POST /api/v1/cert/self-sign", s.requireAuth(true, s.handleCertSelfSign))
	mux.HandleFunc("POST /api/v1/wireguard/regen-server", s.requireAuth(true, s.handleRegenWGServer))
	mux.HandleFunc("POST /api/v1/wireguard/peers", s.requireAuth(true, s.handleAddWGPeer))
	mux.HandleFunc("POST /api/v1/wireguard/peers/{name}/regen", s.requireAuth(true, s.handleRegenWGPeer))
	mux.HandleFunc("GET /api/v1/wireguard/peers/{name}/config", s.requireAuth(false, s.handleWGPeerConfig))
	mux.HandleFunc("POST /api/v1/ddns/sync", s.requireAuth(true, s.handleDDNSSync))
	mux.HandleFunc("GET /api/v1/backup", s.requireAuth(false, s.handleBackup))
	mux.HandleFunc("POST /api/v1/migrate", s.requireAuth(true, s.handleMigrate))
	mux.HandleFunc("POST /api/v1/apply", s.requireAuth(true, s.handleApply))
	mux.HandleFunc("PUT /api/v1/system", s.requireAuth(true, s.handlePutSystem))
	mux.HandleFunc("POST /api/v1/system/reboot", s.requireAuth(true, s.handleSystemReboot))
	mux.HandleFunc("GET /api/v1/logs/stream", s.requireAuth(false, s.handleLogsStream))

	// Embedded UI static assets
	sub, err := fs.Sub(embeddedUI, "ui")
	if err != nil {
		panic(fmt.Errorf("embed ui: %w", err))
	}
	fileSrv := http.FileServer(http.FS(sub))
	mux.Handle("/", fileSrv)

	return withSecurityHeaders(mux)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func decodeJSONBody(r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	if r.Body == nil {
		return io.EOF
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > maxBytes {
		return errors.New("request body too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain a single JSON object")
		}
		return err
	}
	return nil
}

func validateAllowedPath(rawPath string, allowedPrefixes []string, allowRoot bool) (string, error) {
	p := strings.TrimSpace(rawPath)
	if p == "" {
		return "", nil
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("path must be absolute: %q", rawPath)
	}
	clean := filepath.Clean(p)
	if clean == "/" {
		if allowRoot {
			return "/", nil
		}
		return "", errors.New("root path is not allowed")
	}

	resolved := clean
	if eval, err := filepath.EvalSymlinks(clean); err == nil {
		resolved = eval
	} else if evalDir, derr := filepath.EvalSymlinks(filepath.Dir(clean)); derr == nil {
		resolved = filepath.Join(evalDir, filepath.Base(clean))
	}

	matchesAny := func(candidate string, resolvePrefix bool) bool {
		for _, pref := range allowedPrefixes {
			pref = strings.TrimSpace(pref)
			if pref == "" {
				continue
			}
			cp := filepath.Clean(pref)
			if resolvePrefix {
				if evalP, err := filepath.EvalSymlinks(cp); err == nil && evalP != "" {
					cp = evalP
				}
			}
			if candidate == cp || strings.HasPrefix(candidate, cp+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}

	if !matchesAny(clean, false) || !matchesAny(resolved, true) {
		return "", fmt.Errorf("path %q is outside allowed directories", clean)
	}
	return clean, nil
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func readHostUptimeSec(fallback time.Time) int64 {
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 0 {
			if f, ferr := strconv.ParseFloat(fields[0], 64); ferr == nil && f >= 0 {
				return int64(f)
			}
		}
	}
	return int64(time.Since(fallback).Seconds())
}

func (s *Server) scheduleDaemonRestart(reason string) {
	if s.Exec == nil {
		return
	}
	initSys := s.Exec.DetectInitSystem()
	if !s.Exec.ServiceIsActive(context.Background(), initSys, "dex-daemon") {
		return
	}
	s.Hub.Log("INFO", "daemon", reason+"; scheduling async dex-daemon restart")
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = s.Exec.ServiceRestart(context.Background(), initSys, "dex-daemon")
	}()
}

type hubLogWriter struct {
	hub *daemon.TaskHub
	tag string
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *hubLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			// Put partial line back for the next Write
			w.buf.WriteString(line)
			break
		}
		if t := strings.TrimSpace(line); t != "" {
			w.hub.Log("INFO", w.tag, t)
		}
	}
	return len(p), nil
}
