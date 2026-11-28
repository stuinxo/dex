package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/state"
)

var errCredentialsChanged = errors.New("credentials changed during request")

type sessionRecord struct {
	credentialHash string
	id             string
	csrfToken      string
	expiresAt      time.Time
}

// DoHProbeResult reports reachability and RTT for a DoH/DoT/DoQ upstream URL.
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
	var snapshot sessionRecord
	if rec != nil {
		snapshot = *rec
	}
	s.sessMu.RUnlock()
	if rec == nil {
		return nil
	}
	st, loadErr := s.Store.Load()
	if now.After(snapshot.expiresAt) || loadErr != nil || snapshot.credentialHash != st.Auth.PasswordHash {
		s.sessMu.Lock()
		if s.sessions[c.Value] == rec {
			delete(s.sessions, c.Value)
		}
		s.sessMu.Unlock()
		return nil
	}
	return &snapshot
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
	if err := decodeJSONBody(w, r, &req, 4096); err != nil || req.Password == "" {
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
			updated, updateErr := s.Store.Update(st.Role, func(cur *state.State) error {
				if cur.Auth.PasswordHash != st.Auth.PasswordHash {
					return errCredentialsChanged
				}
				cur.Auth.PasswordHash = newHash
				return nil
			})
			if errors.Is(updateErr, errCredentialsChanged) {
				writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			if updateErr == nil {
				st = updated
				s.Hub.Log("INFO", "auth", "upgraded legacy v2 password hash to PBKDF2-SHA256")
			}
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
		credentialHash: st.Auth.PasswordHash,
		id:             sid,
		csrfToken:      csrf,
		expiresAt:      now.Add(sessionTTL),
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
	if err := decodeJSONBody(w, r, &req, 4096); err != nil {
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
	// Hold session publication across the credential write so concurrent readers
	// cannot remove the current session before its replacement is published.
	s.sessMu.Lock()
	if _, err := s.Store.Update(st.Role, func(cur *state.State) error {
		if cur.Auth.PasswordHash != st.Auth.PasswordHash {
			return errCredentialsChanged
		}
		cur.Auth.PasswordHash = newHash
		return nil
	}); err != nil {
		s.sessMu.Unlock()
		if errors.Is(err, errCredentialsChanged) {
			writeJSONError(w, http.StatusUnauthorized, "current password incorrect")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Rotate CSRF token and drop other sessions
	newCSRF, _ := randomHex32()
	for id := range s.sessions {
		if id != sess.id {
			delete(s.sessions, id)
		}
	}
	// Session values handed to requests are snapshots; publish a replacement.
	next := *sess
	next.credentialHash = newHash
	if newCSRF != "" {
		next.csrfToken = newCSRF
	}
	if _, exists := s.sessions[sess.id]; exists {
		s.sessions[sess.id] = &next
	}
	s.sessMu.Unlock()
	s.Hub.Log("INFO", "auth", "web UI password changed")

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf_token": next.csrfToken})
}
