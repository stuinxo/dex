package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/stuinxo/de_GWD/v3/internal/cert"
	"github.com/stuinxo/de_GWD/v3/internal/cryptoext"
	"github.com/stuinxo/de_GWD/v3/internal/daemon"
	"github.com/stuinxo/de_GWD/v3/internal/migrate"
	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/render"
	"github.com/stuinxo/de_GWD/v3/internal/state"
	"github.com/stuinxo/de_GWD/v3/internal/version"
)

//go:embed ui/*
var embeddedUI embed.FS

const (
	sessionCookieName = "dex_session"
	sessionTTL        = 12 * time.Hour
	rateLimitWindow   = 60 * time.Second
	rateLimitMaxFails = 10
	secretKeepSentinel = "********"
)

type sessionRecord struct {
	id        string
	csrfToken string
	expiresAt time.Time
}

// Server serves the embedded Web UI and fail-closed REST/SSE API.
type Server struct {
	Store     *state.Store
	Exec      reconcile.SystemExecutor
	Hub       *daemon.TaskHub
	DDNS      *daemon.CloudflareDDNS
	ApplyOpts reconcile.ApplyOptions
	StartedAt time.Time

	ProbeNodeFn func(ctx context.Context, n state.OutboundNode) daemon.ProbeNodeResult

	sessMu   sync.RWMutex
	sessions map[string]*sessionRecord

	rlMu     sync.Mutex
	failures map[string][]time.Time

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
		Store:     store,
		Exec:      exec,
		Hub:       hub,
		DDNS:      ddns,
		ApplyOpts: applyOpts,
		StartedAt: time.Now(),
		ProbeNodeFn: func(ctx context.Context, n state.OutboundNode) daemon.ProbeNodeResult {
			return daemon.ProbeNodeHealth(ctx, n, 5*time.Second, false)
		},
		sessions: make(map[string]*sessionRecord),
		failures: make(map[string][]time.Time),
	}
	s.handler = s.buildRouter()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /api/v1/wireguard/peers", s.requireAuth(true, s.handleAddWGPeer))
	mux.HandleFunc("GET /api/v1/wireguard/peers/{name}/config", s.requireAuth(false, s.handleWGPeerConfig))
	mux.HandleFunc("POST /api/v1/ddns/sync", s.requireAuth(true, s.handleDDNSSync))
	mux.HandleFunc("POST /api/v1/migrate", s.requireAuth(true, s.handleMigrate))
	mux.HandleFunc("POST /api/v1/apply", s.requireAuth(true, s.handleApply))
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

func isHTTPSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func clientIPKey(r *http.Request) string {
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
	list := s.failures[ip]
	var recent []time.Time
	for _, t := range list {
		if now.Sub(t) < rateLimitWindow {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	s.failures[ip] = recent
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
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBytes))
	return dec.Decode(dst)
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
	rec := &sessionRecord{
		id:        sid,
		csrfToken: csrf,
		expiresAt: time.Now().Add(sessionTTL),
	}
	s.sessMu.Lock()
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

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	initSys := s.Exec.DetectInitSystem()
	svcs := map[string]bool{
		"dex-xray":   s.Exec.ServiceIsActive(r.Context(), initSys, "dex-xray"),
		"dex-mosdns": s.Exec.ServiceIsActive(r.Context(), initSys, "dex-mosdns"),
		"dex-nft":    s.Exec.ServiceIsActive(r.Context(), initSys, "dex-nft"),
		"dex-doh":    s.Exec.ServiceIsActive(r.Context(), initSys, "dex-doh"),
		"haproxy":    s.Exec.ServiceIsActive(r.Context(), initSys, "haproxy"),
		"nginx":      s.Exec.ServiceIsActive(r.Context(), initSys, "nginx"),
		"wireguard":  s.Exec.ServiceIsActive(r.Context(), initSys, "wg-quick@wg0"),
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
	serverMainURI := ""
	if st.Role == state.RoleServer || st.Role == state.RoleLanding {
		serverMainURI = render.BuildServerMainURI(st)
	}

	hostname, _ := os.Hostname()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":          version.Summary(),
		"role":             st.Role,
		"hostname":         hostname,
		"mem_mb":           s.Exec.DetectMemMB(),
		"init_system":      initSys,
		"is_container":     s.Exec.DetectIsContainer(),
		"uptime_sec":       int64(time.Since(s.StartedAt).Seconds()),
		"services":         svcs,
		"active_node_id":   st.Client.ActiveNodeID,
		"node_uris":        nodeURIs,
		"server_main_uri":  serverMainURI,
		"node_sm_services": state.NodeSMServices,
		"cert":             certSummary,
	})
}

func redactStateForAPI(st *state.State) (*state.State, map[string]bool) {
	clone, err := st.Clone()
	if err != nil {
		return st, nil
	}
	secrets := map[string]bool{
		"has_cert_cf_token": clone.Cert.CFToken != "",
		"has_ddns_cf_token": clone.Client.DDNS.CFToken != "",
	}
	clone.Auth.PasswordHash = ""
	if clone.Cert.CFToken != "" {
		clone.Cert.CFToken = secretKeepSentinel
	}
	if clone.Client.DDNS.CFToken != "" {
		clone.Client.DDNS.CFToken = secretKeepSentinel
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

	updated, applyRes, err := reconcile.UpdateAndReconcile(r.Context(), s.Store, incoming.Role, s.Exec, opts, func(dst *state.State) error {
		*dst = incoming
		return nil
	})
	if err != nil {
		s.Hub.Log("ERROR", "apply", err.Error())
		writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.Hub.Log("INFO", "apply", fmt.Sprintf("reconciled role=%s (%d files)", updated.Role, len(applyRes.FilesWritten)))
	redacted, secrets := redactStateForAPI(updated)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"state":   redacted,
		"secrets": secrets,
		"result":  applyRes,
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

func (s *Server) handleProbeNodes(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		NodeID string `json:"node_id"`
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
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func nextWireGuardPeerIP(wg state.WireGuardConfig) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(wg.SubnetCIDR))
	if err != nil {
		prefix = netip.MustParsePrefix("172.16.66.1/24")
	}
	used := map[netip.Addr]bool{prefix.Addr(): true}
	for _, p := range wg.Peers {
		raw := strings.TrimSpace(strings.Split(p.IP, "/")[0])
		if a, err := netip.ParseAddr(raw); err == nil {
			used[a] = true
		}
	}
	base4 := prefix.Addr().As4()
	for lastOctet := 11; lastOctet <= 254; lastOctet++ {
		cand := netip.AddrFrom4([4]byte{base4[0], base4[1], base4[2], byte(lastOctet)})
		if prefix.Contains(cand) && !used[cand] {
			return cand.String(), nil
		}
	}
	return "", errors.New("no free WireGuard peer IP available in subnet")
}

func (s *Server) handleAddWGPeer(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		Name string `json:"name"`
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
		if cur.Client.WireGuard.ServerPrivateKey == "" || cur.Client.WireGuard.ServerPublicKey == "" {
			sp, spub, kerr := cryptoext.GenerateWireGuardKeypair()
			if kerr != nil {
				return kerr
			}
			cur.Client.WireGuard.ServerPrivateKey = sp
			cur.Client.WireGuard.ServerPublicKey = spub
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
		ip, iperr := nextWireGuardPeerIP(cur.Client.WireGuard)
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
	res, err := s.DDNS.SyncOnce(r.Context(), st.Client.DDNS.Domain, st.Client.DDNS.CFToken, st.Client.DDNS.EnableIPv6, true)
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
		default:
			writeJSONError(w, http.StatusBadRequest, "raw_json requires kind v2_client, des, or dexs")
			return
		}
	} else {
		p := strings.TrimSpace(req.Path)
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
	if r.URL.Query().Get("force") == "1" {
		opts.Force = true
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

	ch, cancel := s.Hub.Subscribe()
	defer cancel()

	for _, entry := range s.Hub.Snapshot() {
		b, _ := json.Marshal(entry)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
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
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-keepalive.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
