package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/migrate"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/version"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	st, err := s.Store.Load()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	initSys := s.Exec.DetectInitSystem()
	wgUnit := render.WireGuardUnitName(initSys)
	plan := render.ComputeServicePlan(st)
	checkSvc := func(unit string) bool {
		return s.Exec.ServiceIsActive(r.Context(), initSys, unit)
	}
	svcs := map[string]bool{
		"dex-daemon": checkSvc("dex-daemon"),
	}
	var proxyPaused bool
	if st.Role == state.RoleClient {
		svcs["dex-xray"] = checkSvc("dex-xray")
		svcs["dex-mosdns"] = checkSvc("dex-mosdns")
		svcs["dex-nft"] = checkSvc("dex-nft")
		if plan.WireGuard || checkSvc(wgUnit) {
			svcs["wireguard"] = checkSvc(wgUnit)
		}
		if plan.HAProxy || checkSvc("haproxy") {
			svcs["haproxy"] = checkSvc("haproxy")
		}
		for _, opt := range []string{"nginx", "dex-doh"} {
			if checkSvc(opt) {
				svcs[opt] = true
			}
		}
		proxyPaused = !svcs["dex-xray"] && !svcs["dex-nft"]
	} else {
		if plan.Xray || checkSvc("dex-xray") {
			svcs["dex-xray"] = checkSvc("dex-xray")
		}
		if plan.Nginx || checkSvc("nginx") {
			svcs["nginx"] = checkSvc("nginx")
		}
		if plan.DoH || checkSvc("dex-doh") {
			svcs["dex-doh"] = checkSvc("dex-doh")
		}
		if plan.NFTNeeded() || checkSvc("dex-nft") {
			svcs["dex-nft"] = checkSvc("dex-nft")
		}
		if plan.HAProxy || checkSvc("haproxy") {
			svcs["haproxy"] = checkSvc("haproxy")
		}
		switch {
		case plan.Xray && plan.NFTRelay:
			proxyPaused = !svcs["dex-xray"] && !svcs["dex-nft"]
		case plan.Xray:
			proxyPaused = !svcs["dex-xray"]
		case plan.NFTRelay:
			proxyPaused = !svcs["dex-nft"]
		default:
			proxyPaused = false
		}
	}

	var certSummary any
	certPath, keyPath := reconcile.ResolveActiveCertPaths(s.Store, st)
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
		if u := render.BuildExtraURI(st, ex); u != "" {
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
	if err := incoming.EnsureGeneratedDefaults(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
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
