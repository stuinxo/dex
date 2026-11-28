package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/stuinxo/dex/internal/reconcile"
)

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
	tok := strings.TrimSpace(req.CFToken)
	if tok == secretKeepSentinel {
		tok = ""
	}
	autoRenew := true
	if req.AutoRenew != nil {
		autoRenew = *req.AutoRenew
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "cf"
	}
	rep, dom, err := reconcile.IssueACMEAndSync(r.Context(), s.Store, s.Exec, s.ApplyOpts, s.CertRunner, reconcile.IssueACMEParams{
		Mode:          mode,
		Domain:        req.Domain,
		CFToken:       tok,
		CFEmail:       req.CFEmail,
		Webroot:       req.Webroot,
		AutoRenew:     &autoRenew,
		ReloadCmd:     s.CertReloadCmd,
		IncludeDaemon: false,
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.ReloadCertFn != nil {
		s.ReloadCertFn(r.Context())
	}
	_ = st
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
	if _, err := s.Store.Load(); err != nil {
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
	rep, changed, pathsChanged, err := reconcile.ImportCertAndSync(r.Context(), s.Store, s.Exec, s.ApplyOpts, srcCert, srcKey, req.AllowSelfSigned, false, nil)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if (changed || pathsChanged) && s.ReloadCertFn != nil {
		s.ReloadCertFn(r.Context())
	}
	s.Hub.Log("INFO", "cert", fmt.Sprintf("imported certificate CN=%s changed=%v", rep.CommonName, changed))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed, "cert": rep})
	if changed || pathsChanged {
		s.scheduleDaemonRestart("TLS certificate imported")
	}
}

func (s *Server) handleCertSelfSign(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		CN    string `json:"cn"`
		Force *bool  `json:"force"`
	}
	_ = decodeJSONBody(r, &req, 4096)
	force := true
	if req.Force != nil {
		force = *req.Force
	}
	rep, _, _, err := reconcile.SelfSignCertAndSync(r.Context(), s.Store, s.Exec, s.ApplyOpts, req.CN, force, false, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.ReloadCertFn != nil {
		s.ReloadCertFn(r.Context())
	}
	cn := ""
	if rep != nil {
		cn = rep.CommonName
	}
	s.Hub.Log("INFO", "cert", fmt.Sprintf("generated self-signed cert CN=%s", cn))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cert": rep})
	s.scheduleDaemonRestart("self-signed TLS certificate regenerated")
}
