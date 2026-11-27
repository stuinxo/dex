package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/daemon"
	"github.com/stuinxo/dex/internal/doh"
	"github.com/stuinxo/dex/internal/migrate"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/socks5out"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/version"
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

type sessionRecord struct {
	id        string
	csrfToken string
	expiresAt time.Time
}

// DoHProbeResult reports reachability and RTT for a DoH/DoT/DoQ upstream URL.
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

	dohMu           sync.RWMutex
	dohStateModNano int64
	dohStateSize    int64
	dohLoaded       bool
	dohEnabled      bool
	dohPath         string
	dohUpstreamsKey string
	dohHandler      *doh.Handler

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

// InvalidateDoHCache forces the next DoH path lookup to reload state.json immediately.
func (s *Server) InvalidateDoHCache() {
	s.dohMu.Lock()
	s.dohLoaded = false
	s.dohMu.Unlock()
}

func (s *Server) matchClientDoH(reqPath string) *doh.Handler {
	if s.Store == nil || reqPath == "" || reqPath == "/" || strings.HasPrefix(reqPath, "/api/") {
		return nil
	}
	var modNano, fSize int64
	if fi, err := os.Stat(s.Store.StatePath()); err == nil {
		modNano = fi.ModTime().UnixNano()
		fSize = fi.Size()
	}
	ups := s.ClientDoHUpstreams
	if len(ups) == 0 {
		ups = []string{"127.0.0.1:53"}
	}
	upsKey := strings.Join(ups, ",")

	s.dohMu.RLock()
	if s.dohLoaded && s.dohStateModNano == modNano && s.dohStateSize == fSize && s.dohUpstreamsKey == upsKey {
		enabled := s.dohEnabled
		path := s.dohPath
		h := s.dohHandler
		s.dohMu.RUnlock()
		if enabled && reqPath == path {
			return h
		}
		return nil
	}
	s.dohMu.RUnlock()

	st, err := s.Store.Load()
	enabled := err == nil && st != nil && st.Role == state.RoleClient && st.Client.DNS.EnableDoHServer
	path := ""
	if enabled {
		path = st.Client.DNS.EffectiveDoHPath()
	}

	s.dohMu.Lock()
	if enabled && (s.dohHandler == nil || s.dohPath != path || s.dohUpstreamsKey != upsKey) {
		s.dohHandler = doh.NewHandler(doh.Config{
			Path:          path,
			Upstreams:     append([]string(nil), ups...),
			Timeout:       5 * time.Second,
			MaxConcurrent: 128,
		})
	}
	s.dohEnabled = enabled
	s.dohPath = path
	s.dohUpstreamsKey = upsKey
	s.dohStateModNano = modNano
	s.dohStateSize = fSize
	s.dohLoaded = true
	h := s.dohHandler
	s.dohMu.Unlock()

	if enabled && reqPath == path {
		return h
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := s.matchClientDoH(r.URL.Path); h != nil {
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

func isLoopbackRemote(remoteAddr string) bool {
	raw := strings.TrimSpace(remoteAddr)
	if raw == "" {
		return false
	}
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		host = raw
	}
	host = strings.Trim(host, "[]")
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func isHTTPSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return isLoopbackRemote(r.RemoteAddr) && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func clientIPKey(r *http.Request) string {
	if isLoopbackRemote(r.RemoteAddr) {
		if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
			if ip, err := netip.ParseAddr(strings.Trim(xri, "[]")); err == nil {
				return ip.String()
			}
		}
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			first = strings.TrimSpace(first)
			if ip, err := netip.ParseAddr(strings.Trim(first, "[]")); err == nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr == "" {
		return "local"
	}
	return r.RemoteAddr
}

func (s *Server) isRateLimited(ip string) bool {
	now := time.Now()
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	list := s.failures[ip]
	var recent []time.Time
	for _, t := range list {
		if now.Sub(t) < rateLimitWindow {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(s.failures, ip)
	} else {
		s.failures[ip] = recent
	}
	return len(recent) >= rateLimitMaxFails
}

func (s *Server) recordLoginFailure(ip string) {
	now := time.Now()
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	for k, tsList := range s.failures {
		var recent []time.Time
		for _, t := range tsList {
			if now.Sub(t) < rateLimitWindow {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(s.failures, k)
		} else {
			s.failures[k] = recent
		}
	}
	s.failures[ip] = append(s.failures[ip], now)
	for len(s.failures) > maxFailureBuckets {
		var oldestIP string
		var oldestTime time.Time
		first := true
		for k, tsList := range s.failures {
			if k == ip && len(s.failures) > 1 {
				continue
			}
			latest := tsList[len(tsList)-1]
			if first || latest.Before(oldestTime) {
				first = false
				oldestTime = latest
				oldestIP = k
			}
		}
		if oldestIP == "" {
			break
		}
		delete(s.failures, oldestIP)
	}
}

func (s *Server) clearLoginFailures(ip string) {
	s.rlMu.Lock()
	delete(s.failures, ip)
	s.rlMu.Unlock()
}

func randomHex32() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (s *Server) getSession(r *http.Request) *sessionRecord {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || strings.TrimSpace(c.Value) == "" {
		return nil
	}
	now := time.Now()
	s.sessMu.RLock()
	rec := s.sessions[c.Value]
	s.sessMu.RUnlock()
	if rec == nil || now.After(rec.expiresAt) {
		if rec != nil {
			s.sessMu.Lock()
			delete(s.sessions, c.Value)
			s.sessMu.Unlock()
		}
		return nil
	}
	return rec
}

func (s *Server) requireAuth(requireCSRF bool, fn func(http.ResponseWriter, *http.Request, *sessionRecord)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.getSession(r)
		if sess == nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if requireCSRF {
			provided := r.Header.Get("X-CSRF-Token")
			if provided == "" || subtle.ConstantTimeCompare([]byte(sess.csrfToken), []byte(provided)) != 1 {
				writeJSONError(w, http.StatusForbidden, "invalid CSRF token")
				return
			}
		}
		fn(w, r, sess)
	}
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIPKey(r)
	if s.isRateLimited(ip) {
		w.Header().Set("Retry-After", "60")
		writeJSONError(w, http.StatusTooManyRequests, "too many failed login attempts")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSONBody(r, &req, 4096); err != nil || req.Password == "" {
		s.recordLoginFailure(ip)
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	st, err := s.Store.Load()
	if err != nil || !cryptoext.IsValidStoredHash(st.Auth.PasswordHash) {
		// Fail closed if state cannot be read or password hash is empty/malformed.
		s.recordLoginFailure(ip)
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	ok, needsRehash := cryptoext.VerifyPassword(st.Auth.PasswordHash, req.Password)
	if !ok {
		s.recordLoginFailure(ip)
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.clearLoginFailures(ip)

	if needsRehash {
		if newHash, herr := cryptoext.HashPassword(req.Password); herr == nil {
			_, _ = s.Store.Update(st.Role, func(cur *state.State) error {
				cur.Auth.PasswordHash = newHash
				return nil
			})
			s.Hub.Log("INFO", "auth", "upgraded legacy v2 password hash to PBKDF2-SHA256")
		}
	}

	sid, err1 := randomHex32()
	csrf, err2 := randomHex32()
	if err1 != nil || err2 != nil {
		writeJSONError(w, http.StatusInternalServerError, "session generation failed")
		return
	}
	now := time.Now()
	rec := &sessionRecord{
		id:        sid,
		csrfToken: csrf,
		expiresAt: now.Add(sessionTTL),
	}
	s.sessMu.Lock()
	for id, existing := range s.sessions {
		if existing == nil || now.After(existing.expiresAt) {
			delete(s.sessions, id)
		}
	}
	for len(s.sessions) >= maxActiveSessions {
		var oldestID string
		var oldestExp time.Time
		first := true
		for id, existing := range s.sessions {
			if first || existing.expiresAt.Before(oldestExp) {
				first = false
				oldestExp = existing.expiresAt
				oldestID = id
			}
		}
		if oldestID == "" {
			break
		}
		delete(s.sessions, oldestID)
	}
	s.sessions[sid] = rec
	s.sessMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPSRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"csrf_token":    csrf,
		"role":          st.Role,
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(r)
	if sess == nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	role := ""
	if st, err := s.Store.Load(); err == nil {
		role = st.Role
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"csrf_token":    sess.csrfToken,
		"role":          role,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *sessionRecord) {
	s.sessMu.Lock()
	delete(s.sessions, sess.id)
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPSRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, sess *sessionRecord) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSONBody(r, &req, 4096); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.NewPassword) < 6 {
		writeJSONError(w, http.StatusBadRequest, "new password must be at least 6 characters")
		return
	}

	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok, _ := cryptoext.VerifyPassword(st.Auth.PasswordHash, req.CurrentPassword)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "current password incorrect")
		return
	}
	newHash, err := cryptoext.HashPassword(req.NewPassword)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := s.Store.Update(st.Role, func(cur *state.State) error {
		cur.Auth.PasswordHash = newHash
		return nil
	}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Rotate CSRF token and drop other sessions
	newCSRF, _ := randomHex32()
	s.sessMu.Lock()
	for id := range s.sessions {
		if id != sess.id {
			delete(s.sessions, id)
		}
	}
	if newCSRF != "" {
		sess.csrfToken = newCSRF
	}
	s.sessMu.Unlock()
	s.Hub.Log("INFO", "auth", "web UI password changed")

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf_token": sess.csrfToken})
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func buildExtraURI(st *state.State, ex state.ExtraInbound) string {
	host := strings.TrimSpace(ex.Domain)
	if host == "" && st != nil {
		host = st.Server.EffectiveConnectHost()
	}
	if host == "" {
		host = "node.example.com"
	}
	path := ex.Path
	if ex.Protocol == "vless-xhttp" || ex.Protocol == "vless-ws" || ex.Protocol == "vmess-ws" {
		path = render.NormalizePath(ex.Path, ex.UUID)
	}
	return render.BuildNodeURI(state.OutboundNode{
		Name:           ex.Tag,
		Protocol:       ex.Protocol,
		Address:        host,
		Port:           ex.ListenPort,
		UUID:           ex.UUID,
		TLSSNI:         firstNonEmptyStr(ex.RealitySNI, ex.Domain, host),
		Path:           path,
		RealityPubKey:  ex.RealityPubKey,
		RealityShortID: ex.RealityShortID,
		Username:       ex.SocksUser,
		Password:       ex.SocksPass,
	})
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

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	initSys := s.Exec.DetectInitSystem()
	wgUnit := "wg-quick@wg0"
	if initSys == "openrc" {
		wgUnit = "wg-quick.wg0"
	}
	checkSvc := func(unit string) bool {
		return s.Exec.ServiceIsActive(r.Context(), initSys, unit)
	}
	hasNFTForward := false
	hasHAProxyForward := false
	hasXrayForward := false
	for _, f := range st.Relay.Forwards {
		switch f.Engine {
		case "nft":
			hasNFTForward = true
		case "haproxy":
			hasHAProxyForward = true
		case "xray":
			hasXrayForward = true
		}
	}
	svcs := map[string]bool{
		"dex-daemon": checkSvc("dex-daemon"),
	}
	var proxyPaused bool
	if st.Role == state.RoleClient {
		svcs["dex-xray"] = checkSvc("dex-xray")
		svcs["dex-mosdns"] = checkSvc("dex-mosdns")
		svcs["dex-nft"] = checkSvc("dex-nft")
		if st.Client.WireGuard.Enabled || checkSvc(wgUnit) {
			svcs["wireguard"] = checkSvc(wgUnit)
		}
		if hasHAProxyForward || checkSvc("haproxy") {
			svcs["haproxy"] = checkSvc("haproxy")
		}
		for _, opt := range []string{"nginx", "dex-doh"} {
			if checkSvc(opt) {
				svcs[opt] = true
			}
		}
		proxyPaused = !svcs["dex-xray"] && !svcs["dex-nft"]
	} else {
		needsXray := st.Role == state.RoleServer || st.Role == state.RoleLanding ||
			hasXrayForward || st.RproxyS.Enabled || len(st.ExtraInbounds) > 0
		if needsXray || checkSvc("dex-xray") {
			svcs["dex-xray"] = checkSvc("dex-xray")
		}
		needsNginx := st.Role == state.RoleServer && st.Server.TLSMode == "nginx"
		for _, ex := range st.ExtraInbounds {
			if ex.ViaNginx {
				needsNginx = true
				break
			}
		}
		if needsNginx || checkSvc("nginx") {
			svcs["nginx"] = checkSvc("nginx")
		}
		if (st.Role == state.RoleServer && st.Server.TLSMode == "nginx" && st.Server.EnableDoH) || checkSvc("dex-doh") {
			svcs["dex-doh"] = checkSvc("dex-doh")
		}
		if hasNFTForward || checkSvc("dex-nft") {
			svcs["dex-nft"] = checkSvc("dex-nft")
		}
		if hasHAProxyForward || checkSvc("haproxy") {
			svcs["haproxy"] = checkSvc("haproxy")
		}
		switch {
		case needsXray && hasNFTForward:
			proxyPaused = !svcs["dex-xray"] && !svcs["dex-nft"]
		case needsXray:
			proxyPaused = !svcs["dex-xray"]
		case hasNFTForward:
			proxyPaused = !svcs["dex-nft"]
		default:
			proxyPaused = false
		}
	}

	var certSummary any
	certPath := s.Store.DefaultCert()
	keyPath := s.Store.DefaultKey()
	if st.Cert.Mode == "imported" && st.Cert.CertFile != "" && st.Cert.KeyFile != "" {
		certPath = st.Cert.CertFile
		keyPath = st.Cert.KeyFile
	}
	if cb, e1 := os.ReadFile(certPath); e1 == nil {
		if kb, e2 := os.ReadFile(keyPath); e2 == nil {
			if rep, e3 := cert.InspectPair(cb, kb); e3 == nil {
				certSummary = rep
			}
		}
	}

	nodeURIs := make(map[string]string, len(st.Client.Nodes))
	for _, n := range st.Client.Nodes {
		nodeURIs[n.ID] = render.BuildNodeURI(n)
	}
	extraURIs := make(map[string]string, len(st.ExtraInbounds))
	for _, ex := range st.ExtraInbounds {
		if u := buildExtraURI(st, ex); u != "" {
			extraURIs[ex.Tag] = u
		}
	}
	serverMainURI := ""
	if st.Role == state.RoleServer || st.Role == state.RoleLanding {
		serverMainURI = render.BuildServerMainURI(st)
	}
	hostname, _ := os.Hostname()
	dohURL := render.BuildDoHURL(st, hostname)

	kernelRel := ""
	if kb, kerr := os.ReadFile("/proc/sys/kernel/osrelease"); kerr == nil {
		kernelRel = strings.TrimSpace(string(kb))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":              version.Summary(),
		"role":                 st.Role,
		"hostname":             hostname,
		"device_alias":         st.System.Hostname,
		"arch":                 runtime.GOOS + "/" + runtime.GOARCH,
		"kernel":               kernelRel,
		"net_opt":              reconcile.ReadKernelNetOpt(),
		"mem_mb":               s.Exec.DetectMemMB(),
		"init_system":          initSys,
		"is_container":         s.Exec.DetectIsContainer(),
		"uptime_sec":           readHostUptimeSec(s.StartedAt),
		"proxy_paused":         proxyPaused,
		"services":             svcs,
		"active_node_id":       st.Client.ActiveNodeID,
		"node_uris":            nodeURIs,
		"extra_uris":           extraURIs,
		"fwd0_uri":             render.BuildFWDURI(st, "fwd0", ""),
		"fwd1_uri":             render.BuildFWDURI(st, "fwd1", ""),
		"doh_url":              dohURL,
		"server_main_uri":      serverMainURI,
		"client_bootstrap_cmd": render.BuildClientBootstrapCommand(st, hostname),
		"node_sm_services":     state.NodeSMServices,
		"cert":                 certSummary,
	})
}

func redactStateForAPI(st *state.State) (*state.State, map[string]bool) {
	clone, err := st.Clone()
	if err != nil {
		return st, nil
	}
	secrets := map[string]bool{
		"has_cert_cf_token":         clone.Cert.CFToken != "",
		"has_ddns_cf_token":         clone.Client.DDNS.CFToken != "",
		"has_notify_webhook_url":    clone.System.Notify.WebhookURL != "",
		"has_notify_telegram_token": clone.System.Notify.TelegramBotToken != "",
	}
	clone.Auth.PasswordHash = ""
	if clone.Cert.CFToken != "" {
		clone.Cert.CFToken = secretKeepSentinel
	}
	if clone.Client.DDNS.CFToken != "" {
		clone.Client.DDNS.CFToken = secretKeepSentinel
	}
	if clone.System.Notify.WebhookURL != "" {
		clone.System.Notify.WebhookURL = secretKeepSentinel
	}
	if clone.System.Notify.TelegramBotToken != "" {
		clone.System.Notify.TelegramBotToken = secretKeepSentinel
	}
	return clone, secrets
}

func (s *Server) handleGetState(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	redacted, secrets := redactStateForAPI(st)
	writeJSON(w, http.StatusOK, map[string]any{
		"state":   redacted,
		"secrets": secrets,
	})
}

func (s *Server) handlePutState(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var incoming state.State
	if err := decodeJSONBody(r, &incoming, 4<<20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid state JSON: "+err.Error())
		return
	}

	cur, err := s.Store.Load()
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Preserve sensitive stored secrets when masked or omitted in UI payload.
	if cur != nil {
		incoming.Auth.PasswordHash = cur.Auth.PasswordHash
		if incoming.Cert.CFToken == "" || incoming.Cert.CFToken == secretKeepSentinel {
			incoming.Cert.CFToken = cur.Cert.CFToken
		}
		if incoming.Client.DDNS.CFToken == "" || incoming.Client.DDNS.CFToken == secretKeepSentinel {
			incoming.Client.DDNS.CFToken = cur.Client.DDNS.CFToken
		}
		if incoming.System.Notify.WebhookURL == "" || incoming.System.Notify.WebhookURL == secretKeepSentinel {
			incoming.System.Notify.WebhookURL = cur.System.Notify.WebhookURL
		}
		if incoming.System.Notify.TelegramBotToken == "" || incoming.System.Notify.TelegramBotToken == secretKeepSentinel {
			incoming.System.Notify.TelegramBotToken = cur.System.Notify.TelegramBotToken
		}
	}
	for i := range incoming.ExtraInbounds {
		ex := &incoming.ExtraInbounds[i]
		if ex.Protocol == "vless-reality" {
			if strings.TrimSpace(ex.UUID) == "" {
				ex.UUID, _ = cryptoext.GenerateUUID()
			}
			if strings.TrimSpace(ex.RealityPrivKey) == "" {
				if priv, pub, kerr := cryptoext.GenerateRealityKeypair(); kerr == nil {
					ex.RealityPrivKey = priv
					ex.RealityPubKey = pub
				}
			}
			if strings.TrimSpace(ex.RealityShortID) == "" {
				ex.RealityShortID, _ = cryptoext.GenerateHexToken(4)
			}
			if strings.TrimSpace(ex.RealitySNI) == "" {
				ex.RealitySNI = "www.apple.com"
			}
			if strings.TrimSpace(ex.RealityDest) == "" {
				ex.RealityDest = ex.RealitySNI + ":443"
			}
		} else if (ex.Protocol == "vless-xhttp" || ex.Protocol == "vless-ws" || ex.Protocol == "vmess-ws") && strings.TrimSpace(ex.UUID) == "" {
			ex.UUID, _ = cryptoext.GenerateUUID()
		}
	}
	if incoming.Role == state.RoleClient && incoming.Client.WireGuard.Enabled {
		if strings.TrimSpace(incoming.Client.WireGuard.ServerPrivateKey) == "" || strings.TrimSpace(incoming.Client.WireGuard.ServerPublicKey) == "" {
			if priv, pub, kerr := cryptoext.GenerateWireGuardKeypair(); kerr == nil {
				incoming.Client.WireGuard.ServerPrivateKey = priv
				incoming.Client.WireGuard.ServerPublicKey = pub
			}
		}
	}
	if incoming.Role == state.RoleClient && incoming.Client.DNS.EnableDoHServer && strings.TrimSpace(incoming.Client.DNS.DoHServerPath) == "" {
		incoming.Client.DNS.DoHServerPath = state.GenerateDefaultClientDoHPath()
	}
	if incoming.Role != state.RoleServer {
		incoming.Server.EnableDoH = false
	}
	if incoming.Role != state.RoleClient {
		incoming.Client.DNS.EnableDoHServer = false
	}
	if err := incoming.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	opts := s.ApplyOpts
	if r.URL.Query().Get("force") == "1" {
		opts.Force = true
	}
	if r.URL.Query().Get("dry_run") == "1" {
		res, err := render.RenderAll(&incoming, opts.RenderOpts)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "files": len(res.Files)})
		return
	}

	listenChanged := cur != nil && strings.TrimSpace(cur.Auth.ListenAddr) != strings.TrimSpace(incoming.Auth.ListenAddr)
	updated, applyRes, err := reconcile.UpdateAndReconcile(r.Context(), s.Store, incoming.Role, s.Exec, opts, func(dst *state.State) error {
		*dst = incoming
		return nil
	})
	if err != nil {
		s.Hub.Log("ERROR", "apply", err.Error())
		writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.InvalidateDoHCache()
	s.Hub.Log("INFO", "apply", fmt.Sprintf("reconciled role=%s (%d files)", updated.Role, len(applyRes.FilesWritten)))
	if listenChanged {
		s.Hub.Log("INFO", "daemon", fmt.Sprintf("web listen_addr changed to %s; restarting dex-daemon", updated.Auth.ListenAddr))
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = s.Exec.ServiceRestart(context.Background(), s.Exec.DetectInitSystem(), "dex-daemon")
		}()
	}
	redacted, secrets := redactStateForAPI(updated)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"state":            redacted,
		"secrets":          secrets,
		"result":           applyRes,
		"restarted_daemon": listenChanged,
	})
}

func (s *Server) handleSelectNode(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := decodeJSONBody(r, &req, 4096); err != nil || strings.TrimSpace(req.NodeID) == "" {
		writeJSONError(w, http.StatusBadRequest, "node_id is required")
		return
	}
	updated, _, err := reconcile.UpdateAndReconcile(r.Context(), s.Store, state.RoleClient, s.Exec, s.ApplyOpts, func(cur *state.State) error {
		if cur.Client.FindNode(req.NodeID) == nil {
			return fmt.Errorf("unknown node_id %q", req.NodeID)
		}
		cur.Client.ActiveNodeID = req.NodeID
		return nil
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Hub.Log("INFO", "nodes", fmt.Sprintf("switched active node to %s", req.NodeID))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "active_node_id": updated.Client.ActiveNodeID})
}

func (s *Server) probeDoHURL(ctx context.Context, raw string) DoHProbeResult {
	if s.ProbeDoHFn != nil {
		return s.ProbeDoHFn(ctx, raw)
	}
	norm := strings.TrimSpace(raw)
	if norm == "" {
		return DoHProbeResult{URL: raw, Error: "empty URL"}
	}
	if !strings.Contains(norm, "://") {
		if strings.Contains(norm, "/") {
			norm = "https://" + norm
		} else {
			norm = "https://" + norm + "/dq"
		}
	}
	u, err := url.Parse(norm)
	if err != nil {
		return DoHProbeResult{URL: raw, Error: err.Error()}
	}
	start := time.Now()
	switch u.Scheme {
	case "http", "https":
		sep := "?"
		if strings.Contains(norm, "?") {
			sep = "&"
		}
		probeURL := norm + sep + "dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
		if rerr != nil {
			return DoHProbeResult{URL: raw, Error: rerr.Error(), LatencyMS: time.Since(start).Milliseconds()}
		}
		req.Header.Set("Accept", "application/dns-message")
		c := &http.Client{Timeout: 5 * time.Second}
		resp, derr := c.Do(req)
		lat := time.Since(start).Milliseconds()
		if derr != nil {
			return DoHProbeResult{URL: raw, LatencyMS: lat, Error: derr.Error()}
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		ok := resp.StatusCode >= 200 && resp.StatusCode < 500
		errStr := ""
		if !ok {
			errStr = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return DoHProbeResult{URL: raw, OK: ok, Status: resp.StatusCode, LatencyMS: lat, Error: errStr}
	case "tls", "quic", "h3", "tcp":
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			if u.Scheme == "tls" {
				port = "853"
			} else {
				port = "443"
			}
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		if u.Scheme == "tls" {
			conn, derr := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host})
			lat := time.Since(start).Milliseconds()
			if derr != nil {
				return DoHProbeResult{URL: raw, LatencyMS: lat, Error: derr.Error()}
			}
			_ = conn.Close()
			return DoHProbeResult{URL: raw, OK: true, LatencyMS: lat}
		}
		netProto := "tcp"
		if u.Scheme == "quic" || u.Scheme == "h3" {
			netProto = "udp"
		}
		conn, derr := dialer.DialContext(ctx, netProto, net.JoinHostPort(host, port))
		lat := time.Since(start).Milliseconds()
		if derr != nil {
			return DoHProbeResult{URL: raw, LatencyMS: lat, Error: derr.Error()}
		}
		_ = conn.Close()
		return DoHProbeResult{URL: raw, OK: true, LatencyMS: lat}
	default:
		return DoHProbeResult{URL: raw, Error: "unsupported scheme " + u.Scheme}
	}
}

func (s *Server) handleProbeNodes(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		NodeID     string `json:"node_id"`
		IncludeDoH bool   `json:"include_doh"`
	}
	_ = decodeJSONBody(r, &req, 4096)

	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var targets []state.OutboundNode
	if req.NodeID != "" {
		n := st.Client.FindNode(req.NodeID)
		if n == nil {
			writeJSONError(w, http.StatusNotFound, "node not found")
			return
		}
		targets = []state.OutboundNode{*n}
	} else {
		targets = append(targets, st.Client.Nodes...)
	}

	results := make([]daemon.ProbeNodeResult, len(targets))
	var wg sync.WaitGroup
	for i, n := range targets {
		wg.Add(1)
		go func(idx int, node state.OutboundNode) {
			defer wg.Done()
			results[idx] = s.ProbeNodeFn(r.Context(), node)
		}(i, n)
	}
	var dohResults []DoHProbeResult
	if req.IncludeDoH && len(st.Client.DNS.DoHServers) > 0 {
		dohResults = make([]DoHProbeResult, len(st.Client.DNS.DoHServers))
		for i, u := range st.Client.DNS.DoHServers {
			wg.Add(1)
			go func(idx int, raw string) {
				defer wg.Done()
				dohResults[idx] = s.probeDoHURL(r.Context(), raw)
			}(i, u)
		}
	}
	wg.Wait()
	if s.Metrics != nil {
		for _, r := range results {
			s.Metrics.Record(r)
		}
	}
	resp := map[string]any{"results": results}
	if req.IncludeDoH {
		resp["doh_results"] = dohResults
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleNodeMetrics(w http.ResponseWriter, _ *http.Request, _ *sessionRecord) {
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var nodes []state.OutboundNode
	if st.Role == state.RoleClient {
		nodes = st.Client.Nodes
	}
	var summaries []daemon.NodeMetricsSummary
	if s.Metrics != nil {
		summaries = s.Metrics.Summaries(nodes)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": summaries,
	})
}

func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		WebhookURL       string `json:"webhook_url"`
		TelegramBotToken string `json:"telegram_bot_token"`
		TelegramChatID   string `json:"telegram_chat_id"`
	}
	_ = decodeJSONBody(r, &req, 8192)

	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg := st.System.Notify
	if wh := strings.TrimSpace(req.WebhookURL); wh != "" && wh != secretKeepSentinel {
		cfg.WebhookURL = wh
	}
	if tok := strings.TrimSpace(req.TelegramBotToken); tok != "" && tok != secretKeepSentinel {
		cfg.TelegramBotToken = tok
	}
	if chat := strings.TrimSpace(req.TelegramChatID); chat != "" {
		cfg.TelegramChatID = chat
	}

	notifier := s.Notifier
	if notifier == nil {
		notifier = daemon.NewNotifier(s.Hub)
	}
	host := strings.TrimSpace(st.System.Hostname)
	if host == "" {
		host = st.Auth.ServerName
	}
	ev := daemon.AlertEvent{
		Event:    "test",
		Severity: "info",
		Host:     host,
		Title:    "DEX Test Notification",
		Message:  fmt.Sprintf("notification channel test succeeded (role=%s)", st.Role),
	}
	if err := notifier.Send(r.Context(), cfg, ev); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleParseNodeURI(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		URI string `json:"uri"`
	}
	if err := decodeJSONBody(r, &req, 16384); err != nil || strings.TrimSpace(req.URI) == "" {
		writeJSONError(w, http.StatusBadRequest, "uri is required")
		return
	}
	node, err := render.ParseNodeURI(req.URI)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "node": node})
}

func (s *Server) handleAddWGPeer(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		Name         string `json:"name"`
		EndpointHost string `json:"endpoint_host"`
		ListenPort   int    `json:"listen_port"`
		SubnetCIDR   string `json:"subnet_cidr"`
	}
	if err := decodeJSONBody(r, &req, 4096); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "peer name is required")
		return
	}

	priv, pub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var addedPeer state.WGPeer
	var updatedWG state.WireGuardConfig
	_, _, err = reconcile.UpdateAndReconcile(r.Context(), s.Store, state.RoleClient, s.Exec, s.ApplyOpts, func(cur *state.State) error {
		for _, p := range cur.Client.WireGuard.Peers {
			if p.Name == name {
				return fmt.Errorf("peer %q already exists", name)
			}
		}
		if strings.TrimSpace(cur.Client.WireGuard.ServerPrivateKey) == "" || strings.TrimSpace(cur.Client.WireGuard.ServerPublicKey) == "" {
			sp, spub, kerr := cryptoext.GenerateWireGuardKeypair()
			if kerr != nil {
				return kerr
			}
			cur.Client.WireGuard.ServerPrivateKey = sp
			cur.Client.WireGuard.ServerPublicKey = spub
		}
		if ep := strings.TrimSpace(req.EndpointHost); ep != "" && state.IsValidAddress(ep) {
			cur.Client.WireGuard.EndpointHost = ep
		}
		if req.ListenPort >= 1 && req.ListenPort <= 65535 {
			cur.Client.WireGuard.ListenPort = req.ListenPort
		}
		if sub := strings.TrimSpace(req.SubnetCIDR); sub != "" {
			if p, perr := netip.ParsePrefix(sub); perr == nil && p.Addr().Is4() {
				cur.Client.WireGuard.SubnetCIDR = sub
			}
		}
		if cur.Client.WireGuard.ListenPort == 0 {
			cur.Client.WireGuard.ListenPort = 51820
		}
		if cur.Client.WireGuard.SubnetCIDR == "" {
			cur.Client.WireGuard.SubnetCIDR = "172.16.66.1/24"
		}
		if cur.Client.WireGuard.EndpointHost == "" {
			if cur.Client.DDNS.Domain != "" {
				cur.Client.WireGuard.EndpointHost = cur.Client.DDNS.Domain
			} else if cur.Cert.Domain != "" {
				cur.Client.WireGuard.EndpointHost = cur.Cert.Domain
			} else {
				cur.Client.WireGuard.EndpointHost = "vpn.example.com"
			}
		}
		ip, iperr := render.NextAvailableWGIP(cur.Client.WireGuard.SubnetCIDR, cur.Client.WireGuard.Peers)
		if iperr != nil {
			return iperr
		}
		cur.Client.WireGuard.Enabled = true
		addedPeer = state.WGPeer{
			Name:       name,
			IP:         ip,
			PrivateKey: priv,
			PublicKey:  pub,
		}
		cur.Client.WireGuard.Peers = append(cur.Client.WireGuard.Peers, addedPeer)
		updatedWG = cur.Client.WireGuard
		return nil
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.Hub.Log("INFO", "wireguard", fmt.Sprintf("added WireGuard peer %s (%s)", addedPeer.Name, addedPeer.IP))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"peer":   addedPeer,
		"config": render.BuildWGPeerConfig(updatedWG, addedPeer),
	})
}

func (s *Server) handleRegenWGServer(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	priv, pub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, _, err := reconcile.UpdateAndReconcile(r.Context(), s.Store, state.RoleClient, s.Exec, s.ApplyOpts, func(cur *state.State) error {
		cur.Client.WireGuard.ServerPrivateKey = priv
		cur.Client.WireGuard.ServerPublicKey = pub
		return nil
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.Hub.Log("INFO", "wireguard", "regenerated WireGuard server keypair")
	redacted, secrets := redactStateForAPI(updated)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"server_public_key": pub,
		"state":             redacted,
		"secrets":           secrets,
	})
}

func (s *Server) handleRegenWGPeer(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	name := r.PathValue("name")
	priv, pub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var updatedPeer state.WGPeer
	var updatedWG state.WireGuardConfig
	_, _, err = reconcile.UpdateAndReconcile(r.Context(), s.Store, state.RoleClient, s.Exec, s.ApplyOpts, func(cur *state.State) error {
		for i := range cur.Client.WireGuard.Peers {
			if cur.Client.WireGuard.Peers[i].Name == name {
				cur.Client.WireGuard.Peers[i].PrivateKey = priv
				cur.Client.WireGuard.Peers[i].PublicKey = pub
				updatedPeer = cur.Client.WireGuard.Peers[i]
				updatedWG = cur.Client.WireGuard
				return nil
			}
		}
		return fmt.Errorf("peer %q not found", name)
	})
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	s.Hub.Log("INFO", "wireguard", fmt.Sprintf("regenerated WireGuard peer %s", name))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"peer":   updatedPeer,
		"config": render.BuildWGPeerConfig(updatedWG, updatedPeer),
	})
}

func (s *Server) handleWGPeerConfig(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	name := r.PathValue("name")
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, p := range st.Client.WireGuard.Peers {
		if p.Name == name {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if r.URL.Query().Get("download") == "1" {
				w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="wg-%s.conf"`, state.SanitizeSafeName(p.Name, "peer")))
			}
			_, _ = io.WriteString(w, render.BuildWGPeerConfig(st.Client.WireGuard, p))
			return
		}
	}
	writeJSONError(w, http.StatusNotFound, "peer not found")
}

func (s *Server) handleDDNSSync(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	res, err := s.DDNS.SyncOnceWithEmail(r.Context(), st.Client.DDNS.Domain, st.Client.DDNS.CFToken, st.Client.DDNS.CFEmail, st.Client.DDNS.EnableIPv6, true)
	if err != nil {
		s.Hub.Log("ERROR", "ddns", err.Error())
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sync": res})
}

func (s *Server) handleMigrate(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		Kind    string `json:"kind"` // v2_client | v2_server | des | dexs
		Path    string `json:"path"`
		RawJSON string `json:"raw_json"`
		Apply   bool   `json:"apply"`
	}
	if err := decodeJSONBody(r, &req, 4<<20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var imported *state.State
	var notes []string
	var err error

	if strings.TrimSpace(req.RawJSON) != "" {
		tmpDir, merr := os.MkdirTemp("", "dex-web-mig-*")
		if merr != nil {
			writeJSONError(w, http.StatusInternalServerError, merr.Error())
			return
		}
		defer os.RemoveAll(tmpDir)
		tmpFile := filepath.Join(tmpDir, "input.json")
		if werr := os.WriteFile(tmpFile, []byte(req.RawJSON), 0o600); werr != nil {
			writeJSONError(w, http.StatusInternalServerError, werr.Error())
			return
		}
		switch req.Kind {
		case "", "v2_client":
			imported, notes, err = migrate.ImportV2Client(tmpFile, "")
		case "des":
			imported, notes, err = migrate.ImportDES(tmpFile)
		case "dexs":
			imported, notes, err = migrate.ImportDEXS(tmpFile)
		case "v3_state":
			var restored state.State
			if uerr := json.Unmarshal([]byte(req.RawJSON), &restored); uerr != nil {
				err = fmt.Errorf("parse v3 backup JSON: %w", uerr)
			} else {
				if restored.Version == 0 {
					restored.Version = state.CurrentSchemaVersion
				}
				imported = &restored
				notes = append(notes, "restored full v3 state JSON")
			}
		default:
			writeJSONError(w, http.StatusBadRequest, "raw_json requires kind v2_client, des, dexs, or v3_state")
			return
		}
	} else {
		p := strings.TrimSpace(req.Path)
		if p != "" {
			allowed := []string{"/opt/de_GWD", "/etc/des", "/etc/vless-lite", "/etc/dex"}
			if s.Store != nil && s.Store.Dir != "" {
				allowed = append(allowed, s.Store.Dir)
			}
			cleaned, perr := validateAllowedPath(p, allowed, req.Kind == "v2_server")
			if perr != nil {
				writeJSONError(w, http.StatusBadRequest, perr.Error())
				return
			}
			p = cleaned
		}
		switch req.Kind {
		case "", "v2_client":
			if p == "" {
				p = "/opt/de_GWD/0conf"
			}
			imported, notes, err = migrate.ImportV2Client(p, filepath.Dir(p))
		case "v2_server":
			if p == "" {
				p = "/"
			}
			imported, notes, err = migrate.ImportV2Server(p)
		case "des":
			if p == "" {
				p = "/etc/des/state.json"
			}
			imported, notes, err = migrate.ImportDES(p)
		case "dexs":
			if p == "" {
				p = "/etc/vless-lite/state.json"
			}
			imported, notes, err = migrate.ImportDEXS(p)
		case "v3_state":
			if p == "" {
				p = "/etc/dex/state.json"
			}
			var raw []byte
			raw, err = os.ReadFile(p)
			if err == nil {
				var restored state.State
				if uerr := json.Unmarshal(raw, &restored); uerr != nil {
					err = fmt.Errorf("parse v3 backup JSON: %w", uerr)
				} else {
					if restored.Version == 0 {
						restored.Version = state.CurrentSchemaVersion
					}
					imported = &restored
					notes = append(notes, "restored full v3 state JSON from "+p)
				}
			}
		default:
			writeJSONError(w, http.StatusBadRequest, "unknown migration kind")
			return
		}
	}

	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Preserve existing v3 password hash if the imported source has none.
	if imported.Auth.PasswordHash == "" {
		if cur, cerr := s.Store.Load(); cerr == nil {
			imported.Auth.PasswordHash = cur.Auth.PasswordHash
		}
	}
	if err := imported.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "migrated state invalid: "+err.Error())
		return
	}

	if req.Apply {
		_, _, err = reconcile.UpdateAndReconcile(r.Context(), s.Store, imported.Role, s.Exec, s.ApplyOpts, func(dst *state.State) error {
			*dst = *imported
			return nil
		})
		if err != nil {
			writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	} else {
		if err := s.Store.Save(imported); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	s.Hub.Log("INFO", "migrate", fmt.Sprintf("imported %s configuration (%d notes)", req.Kind, len(notes)))
	redacted, secrets := redactStateForAPI(imported)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"notes":   notes,
		"state":   redacted,
		"secrets": secrets,
	})
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	opts := s.ApplyOpts
	var req struct {
		Force      bool `json:"force"`
		RestartAll bool `json:"restart_all"`
	}
	if err := decodeJSONBody(r, &req, 4096); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if r.URL.Query().Get("force") == "1" || req.Force {
		opts.Force = true
	}
	if r.URL.Query().Get("restart_all") == "1" || req.RestartAll {
		opts.RestartAll = true
	}
	res, err := reconcile.Reconcile(r.Context(), s.Store, s.Exec, opts)
	if err != nil {
		s.Hub.Log("ERROR", "apply", err.Error())
		writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.Hub.Log("INFO", "apply", fmt.Sprintf("applied %d generated files", len(res.FilesWritten)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": res})
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

func (s *Server) handleConnectivity(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		WithIPs bool `json:"with_ips"`
	}
	_ = decodeJSONBody(r, &req, 1024)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var cnCheck, globalCheck daemon.ConnectivityCheck
	var cnIP, globalIP string

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cnCheck, globalCheck = s.ProbeConnectivityFn(ctx)
	}()
	if req.WithIPs {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if s.DDNS != nil && s.DDNS.FetchPublic4 != nil {
				cnIP, _ = s.DDNS.FetchPublic4(ctx)
			} else {
				cnIP, _ = daemon.FetchCNPublicIP(ctx)
			}
		}()
		go func() {
			defer wg.Done()
			globalIP, _ = daemon.FetchGlobalPublicIP(ctx)
		}()
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"cn":        cnCheck,
		"global":    globalCheck,
		"cn_ip":     cnIP,
		"global_ip": globalIP,
	})
}

func (s *Server) handleProxyStop(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	initSys := s.Exec.DetectInitSystem()
	// On client gateway, keep dex-mosdns running so domestic DNS continues working while proxy is paused.
	targets := []string{"dex-xray", "dex-nft"}
	var stopped []string
	for _, svc := range targets {
		if s.Exec.ServiceIsActive(r.Context(), initSys, svc) {
			if err := s.Exec.ServiceStopDisable(r.Context(), initSys, svc); err != nil {
				writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("stop %s: %v", svc, err))
				return
			}
			stopped = append(stopped, svc)
		}
	}
	if st.Role == state.RoleClient && s.Exec.HasCommand("ip") {
		for _, family := range []string{"-4", "-6"} {
			for i := 0; i < 4; i++ {
				if _, err := s.Exec.RunCommand(r.Context(), nil, "ip", family, "rule", "del", "fwmark", "0x9", "table", "220"); err != nil {
					break
				}
			}
			_, _ = s.Exec.RunCommand(r.Context(), nil, "ip", family, "route", "flush", "table", "220")
		}
	}
	s.Hub.Log("INFO", "proxy", fmt.Sprintf("stopped proxy services: %v", stopped))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stopped": stopped})
}

func (s *Server) handleProxyRestart(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	opts := s.ApplyOpts
	opts.RestartAll = true
	res, err := reconcile.Reconcile(r.Context(), s.Store, s.Exec, opts)
	if err != nil {
		s.Hub.Log("ERROR", "proxy", err.Error())
		writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.Hub.Log("INFO", "proxy", fmt.Sprintf("restarted proxy services: %v", res.ServicesRestarted))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restarted": res.ServicesRestarted, "result": res})
}

func (s *Server) handleTestSocks5(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		ProfileName string `json:"profile_name"`
		Address     string `json:"address"`
		Port        int    `json:"port"`
		Username    string `json:"username"`
		Password    string `json:"password"`
	}
	if err := decodeJSONBody(r, &req, 4096); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	addr, port, user, pass := strings.TrimSpace(req.Address), req.Port, req.Username, req.Password
	if req.ProfileName != "" {
		st, err := s.Store.Load()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		found := false
		for _, p := range st.Server.Socks5Outbounds {
			if p.Name == req.ProfileName {
				addr = p.Address
				port = p.Port
				user = p.Username
				pass = p.Password
				found = true
				break
			}
		}
		if !found {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("profile %q not found", req.ProfileName))
			return
		}
	}
	if addr == "" || port <= 0 {
		writeJSONError(w, http.StatusBadRequest, "address and port (or valid profile_name) are required")
		return
	}
	res, err := s.ProbeSocks5Fn(r.Context(), addr, port, user, pass, nil)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ok := res.StatusCode >= 200 && res.StatusCode < 400
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": ok,
		"result": map[string]any{
			"status_code": res.StatusCode,
			"exit_ip":     res.ExitIP,
			"location":    res.Location,
			"latency_ms":  res.Latency.Milliseconds(),
		},
	})
}

func (s *Server) handleRulesStatus(w http.ResponseWriter, _ *http.Request, _ *sessionRecord) {
	rulesDir := filepath.Join(s.Store.Dir, "rules")
	names := state.ManagedRuleFiles
	type fileInfo struct {
		Name      string `json:"name"`
		Exists    bool   `json:"exists"`
		SizeBytes int64  `json:"size_bytes"`
		ModTime   string `json:"mod_time,omitempty"`
	}
	files := make([]fileInfo, 0, len(names))
	for _, n := range names {
		fi := fileInfo{Name: n}
		if info, err := os.Stat(filepath.Join(rulesDir, n)); err == nil {
			fi.Exists = true
			fi.SizeBytes = info.Size()
			fi.ModTime = info.ModTime().UTC().Format(time.RFC3339)
		}
		files = append(files, fi)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules_dir": rulesDir,
		"files":     files,
	})
}

func (s *Server) handleRulesUpdate(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	if s.UpdateRulesFn == nil {
		writeJSONError(w, http.StatusNotImplemented, "rules updater not configured")
		return
	}
	var req struct {
		IncludeAds bool `json:"include_ads"`
	}
	_ = decodeJSONBody(r, &req, 1024)
	wLog := &hubLogWriter{hub: s.Hub, tag: "rules"}
	if err := s.UpdateRulesFn(r.Context(), req.IncludeAds, wLog); err != nil {
		s.Hub.Log("ERROR", "rules", err.Error())
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Hub.Log("INFO", "rules", "rules update completed")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUpdateComponents(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	if s.UpdateComponentsFn == nil {
		writeJSONError(w, http.StatusNotImplemented, "component updater not configured")
		return
	}
	var req struct {
		Component string `json:"component"`
		Version   string `json:"version"`
	}
	_ = decodeJSONBody(r, &req, 1024)
	comp := strings.TrimSpace(req.Component)
	if comp == "" {
		comp = "all"
	}
	wLog := &hubLogWriter{hub: s.Hub, tag: "update"}
	if err := s.UpdateComponentsFn(r.Context(), comp, strings.TrimSpace(req.Version), wLog); err != nil {
		s.Hub.Log("ERROR", "update", err.Error())
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Hub.Log("INFO", "update", fmt.Sprintf("updated component=%s", comp))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "component": comp})
	if comp == "dex" || comp == "all" {
		s.scheduleDaemonRestart("dex binary updated")
	}
}

func (s *Server) handleCertIssue(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		Mode      string `json:"mode"`
		Domain    string `json:"domain"`
		CFToken   string `json:"cf_token"`
		CFEmail   string `json:"cf_email"`
		Webroot   string `json:"webroot"`
		AutoRenew *bool  `json:"auto_renew"`
	}
	if err := decodeJSONBody(r, &req, 16384); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dom := strings.TrimSpace(req.Domain)
	if dom == "" {
		dom = firstNonEmptyStr(st.Cert.Domain, st.Server.Domain)
	}
	tok := strings.TrimSpace(req.CFToken)
	if tok == "" || tok == secretKeepSentinel {
		tok = st.Cert.CFToken
	}
	email := strings.TrimSpace(req.CFEmail)
	if email == "" {
		email = st.Cert.CFEmail
	}
	autoRenew := st.Cert.AutoRenew
	if req.AutoRenew != nil {
		autoRenew = *req.AutoRenew
	} else {
		autoRenew = true
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "cf"
	}
	cfg := cert.ACMEConfig{
		Domain:    dom,
		CFToken:   tok,
		CFEmail:   email,
		Webroot:   strings.TrimSpace(req.Webroot),
		ListenV6:  st != nil && st.System.EnableIPv6,
		AutoRenew: autoRenew,
		CertPath:  s.Store.DefaultCert(),
		KeyPath:   s.Store.DefaultKey(),
		ReloadCmd: s.CertReloadCmd,
	}
	var rep *cert.CertReport
	switch mode {
	case "cf", "cloudflare", "dns":
		rep, err = cert.IssueCloudflareACME(r.Context(), s.CertRunner, cfg)
	case "http", "http-01":
		rep, err = cert.IssueHTTPACME(r.Context(), s.CertRunner, cfg)
	default:
		writeJSONError(w, http.StatusBadRequest, "mode must be 'cf' or 'http'")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	hadCustomExternal := (st.Cert.CertFile != "" && st.Cert.CertFile != s.Store.DefaultCert()) ||
		(st.Cert.KeyFile != "" && st.Cert.KeyFile != s.Store.DefaultKey())
	certMode := "acme_cf"
	if mode == "http" || mode == "http-01" {
		certMode = "acme_http"
	}
	if _, uerr := s.Store.Update(st.Role, func(cur *state.State) error {
		cur.Cert.Mode = certMode
		cur.Cert.Domain = dom
		cur.Cert.CertFile = ""
		cur.Cert.KeyFile = ""
		cur.Cert.AutoRenew = autoRenew
		if certMode == "acme_http" {
			// HTTP-01 does not touch CF token
		} else if autoRenew {
			cur.Cert.CFToken = tok
			cur.Cert.CFEmail = email
		} else {
			cur.Cert.CFToken = ""
			cur.Cert.CFEmail = ""
		}
		return nil
	}); uerr != nil {
		writeJSONError(w, http.StatusInternalServerError, uerr.Error())
		return
	}
	if hadCustomExternal {
		if _, rerr := reconcile.Reconcile(r.Context(), s.Store, s.Exec, s.ApplyOpts); rerr != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("reconcile after cert issue: %v", rerr))
			return
		}
	}
	if s.ReloadCertFn != nil {
		s.ReloadCertFn(r.Context())
	}
	s.Hub.Log("INFO", "cert", fmt.Sprintf("issued %s ACME cert for %s", mode, dom))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cert": rep})
	s.scheduleDaemonRestart("TLS certificate issued")
}

func (s *Server) handleCertImport(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		CertPath        string `json:"cert_path"`
		KeyPath         string `json:"key_path"`
		CertPEM         string `json:"cert_pem"`
		KeyPEM          string `json:"key_pem"`
		AllowSelfSigned bool   `json:"allow_self_signed"`
	}
	if err := decodeJSONBody(r, &req, 1<<20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	srcCert := strings.TrimSpace(req.CertPath)
	srcKey := strings.TrimSpace(req.KeyPath)
	if strings.TrimSpace(req.CertPEM) != "" || strings.TrimSpace(req.KeyPEM) != "" {
		if strings.TrimSpace(req.CertPEM) == "" || strings.TrimSpace(req.KeyPEM) == "" {
			writeJSONError(w, http.StatusBadRequest, "both cert_pem and key_pem are required")
			return
		}
		tmpDir, merr := os.MkdirTemp("", "dex-cert-imp-*")
		if merr != nil {
			writeJSONError(w, http.StatusInternalServerError, merr.Error())
			return
		}
		defer os.RemoveAll(tmpDir)
		srcCert = filepath.Join(tmpDir, "cert.pem")
		srcKey = filepath.Join(tmpDir, "key.pem")
		if werr := os.WriteFile(srcCert, []byte(req.CertPEM), 0o644); werr != nil {
			writeJSONError(w, http.StatusInternalServerError, werr.Error())
			return
		}
		if werr := os.WriteFile(srcKey, []byte(req.KeyPEM), 0o600); werr != nil {
			writeJSONError(w, http.StatusInternalServerError, werr.Error())
			return
		}
	} else {
		allowed := []string{"/etc/dex", "/var/www/ssl", "/opt/de_GWD", "/etc/ssl", "/etc/letsencrypt", "/root/.acme.sh"}
		if s.Store != nil && s.Store.Dir != "" {
			allowed = append(allowed, s.Store.Dir)
		}
		var perr error
		if srcCert, perr = validateAllowedPath(srcCert, allowed, false); perr != nil {
			writeJSONError(w, http.StatusBadRequest, "cert_path: "+perr.Error())
			return
		}
		if srcKey, perr = validateAllowedPath(srcKey, allowed, false); perr != nil {
			writeJSONError(w, http.StatusBadRequest, "key_path: "+perr.Error())
			return
		}
	}
	if srcCert == "" || srcKey == "" {
		writeJSONError(w, http.StatusBadRequest, "cert_path/key_path or cert_pem/key_pem are required")
		return
	}
	var checkDomains []string
	if d := firstNonEmptyStr(st.Cert.Domain, st.Server.Domain); d != "" {
		checkDomains = append(checkDomains, d)
	}
	rep, changed, err := cert.ImportPair(srcCert, srcKey, s.Store.DefaultCert(), s.Store.DefaultKey(), req.AllowSelfSigned, checkDomains)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	hadCustomExternal := (st.Cert.CertFile != "" && st.Cert.CertFile != s.Store.DefaultCert()) ||
		(st.Cert.KeyFile != "" && st.Cert.KeyFile != s.Store.DefaultKey())
	if _, uerr := s.Store.Update(st.Role, func(cur *state.State) error {
		cur.Cert.Mode = "imported"
		cur.Cert.CertFile = s.Store.DefaultCert()
		cur.Cert.KeyFile = s.Store.DefaultKey()
		return nil
	}); uerr != nil {
		writeJSONError(w, http.StatusInternalServerError, uerr.Error())
		return
	}
	if hadCustomExternal {
		if _, rerr := reconcile.Reconcile(r.Context(), s.Store, s.Exec, s.ApplyOpts); rerr != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("reconcile after cert import: %v", rerr))
			return
		}
	}
	if (changed || hadCustomExternal) && s.ReloadCertFn != nil {
		s.ReloadCertFn(r.Context())
	}
	s.Hub.Log("INFO", "cert", fmt.Sprintf("imported certificate CN=%s changed=%v", rep.CommonName, changed))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed, "cert": rep})
	if changed || hadCustomExternal {
		s.scheduleDaemonRestart("TLS certificate imported")
	}
}

func (s *Server) handleCertSelfSign(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		CN    string `json:"cn"`
		Force *bool  `json:"force"`
	}
	_ = decodeJSONBody(r, &req, 4096)
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cn := firstNonEmptyStr(req.CN, st.Cert.Domain, st.Server.Domain, "localhost")
	force := true
	if req.Force != nil {
		force = *req.Force
	}
	if force {
		err = cert.ForceSelfSigned(s.Store.DefaultCert(), s.Store.DefaultKey(), cn)
	} else {
		err = cert.EnsureSelfSigned(s.Store.DefaultCert(), s.Store.DefaultKey(), cn)
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hadCustomExternal := (st.Cert.CertFile != "" && st.Cert.CertFile != s.Store.DefaultCert()) ||
		(st.Cert.KeyFile != "" && st.Cert.KeyFile != s.Store.DefaultKey())
	if _, uerr := s.Store.Update(st.Role, func(cur *state.State) error {
		cur.Cert.Mode = "self_signed"
		cur.Cert.CertFile = ""
		cur.Cert.KeyFile = ""
		return nil
	}); uerr != nil {
		writeJSONError(w, http.StatusInternalServerError, uerr.Error())
		return
	}
	if hadCustomExternal {
		if _, rerr := reconcile.Reconcile(r.Context(), s.Store, s.Exec, s.ApplyOpts); rerr != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("reconcile after self-sign: %v", rerr))
			return
		}
	}
	if s.ReloadCertFn != nil {
		s.ReloadCertFn(r.Context())
	}
	cb, _ := os.ReadFile(s.Store.DefaultCert())
	kb, _ := os.ReadFile(s.Store.DefaultKey())
	rep, _ := cert.InspectPair(cb, kb)
	s.Hub.Log("INFO", "cert", fmt.Sprintf("generated self-signed cert CN=%s", cn))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cert": rep})
	s.scheduleDaemonRestart("self-signed TLS certificate regenerated")
}

func (s *Server) handleBackup(w http.ResponseWriter, _ *http.Request, _ *sessionRecord) {
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dex-backup-%s.json"`, time.Now().UTC().Format("20060102-150405")))
	_, _ = w.Write(b)
}

func (s *Server) handlePutSystem(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		Hostname        *string `json:"hostname"`
		EnableIPv6      *bool   `json:"enable_ipv6"`
		AutoUpdateCore  *bool   `json:"auto_update_core"`
		AutoTuneSysctl  *bool   `json:"auto_tune_sysctl"`
		EnableFlowtable *bool   `json:"enable_flowtable"`
	}
	if err := decodeJSONBody(r, &req, 4096); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid system JSON: "+err.Error())
		return
	}
	if req.Hostname != nil && len(strings.TrimSpace(*req.Hostname)) > 128 {
		writeJSONError(w, http.StatusBadRequest, "hostname too long (max 128)")
		return
	}
	cur, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mutate := func(dst *state.State) error {
		if req.Hostname != nil {
			h := strings.TrimSpace(*req.Hostname)
			if len(h) > 128 {
				return errors.New("hostname too long (max 128)")
			}
			dst.System.Hostname = h
		}
		if req.EnableIPv6 != nil {
			dst.System.EnableIPv6 = *req.EnableIPv6
		}
		if req.AutoUpdateCore != nil {
			dst.System.AutoUpdateCore = *req.AutoUpdateCore
		}
		if req.AutoTuneSysctl != nil {
			dst.System.AutoTuneSysctl = *req.AutoTuneSysctl
		}
		if req.EnableFlowtable != nil {
			dst.System.EnableFlowtable = *req.EnableFlowtable
		}
		return nil
	}
	needReconcile := (req.EnableIPv6 != nil && *req.EnableIPv6 != cur.System.EnableIPv6) ||
		(req.AutoUpdateCore != nil && *req.AutoUpdateCore != cur.System.AutoUpdateCore) ||
		(req.AutoTuneSysctl != nil && *req.AutoTuneSysctl != cur.System.AutoTuneSysctl) ||
		(req.EnableFlowtable != nil && *req.EnableFlowtable != cur.System.EnableFlowtable)
	var updated *state.State
	if needReconcile {
		updated, _, err = reconcile.UpdateAndReconcile(r.Context(), s.Store, cur.Role, s.Exec, s.ApplyOpts, mutate)
		if err != nil {
			s.Hub.Log("ERROR", "system", err.Error())
			writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	} else {
		updated, err = s.Store.Update(cur.Role, mutate)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	s.Hub.Log("INFO", "system", fmt.Sprintf("updated system settings (hostname=%q, auto_update_core=%v)", updated.System.Hostname, updated.System.AutoUpdateCore))
	redacted, secrets := redactStateForAPI(updated)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"reconciled": needReconcile,
		"state":      redacted,
		"secrets":    secrets,
	})
}

func (s *Server) handleSystemReboot(w http.ResponseWriter, _ *http.Request, _ *sessionRecord) {
	s.Hub.Log("INFO", "system", "system reboot requested via Web UI")
	go func() {
		time.Sleep(500 * time.Millisecond)
		_, _ = s.Exec.RunCommand(context.Background(), nil, "reboot")
	}()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "reboot scheduled"})
}

func (s *Server) handleLogsStream(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	if r.URL.Query().Get("snapshot") == "1" {
		writeJSON(w, http.StatusOK, map[string]any{"entries": s.Hub.Snapshot()})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	var sinceSeq uint64
	sinceStr := strings.TrimSpace(r.URL.Query().Get("since"))
	if sinceStr == "" {
		sinceStr = strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	}
	if sinceStr != "" {
		if parsed, err := strconv.ParseUint(sinceStr, 10, 64); err == nil {
			sinceSeq = parsed
		}
	}

	snap, ch, cancel := s.Hub.SubscribeWithSnapshot(sinceSeq)
	defer cancel()

	for _, entry := range snap {
		b, _ := json.Marshal(entry)
		_, _ = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", entry.Seq, b)
	}
	flusher.Flush()

	if r.URL.Query().Get("once") == "1" {
		return
	}

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case entry, open := <-ch:
			if !open {
				return
			}
			b, _ := json.Marshal(entry)
			_, _ = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", entry.Seq, b)
			flusher.Flush()
		case <-keepalive.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
