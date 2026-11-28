package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/stuinxo/dex/internal/daemon"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func (s *Server) handleSelectNode(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := decodeJSONBody(w, r, &req, 4096); err != nil || strings.TrimSpace(req.NodeID) == "" {
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
	norm := render.NormalizeDoHUpstream(raw)
	if norm == "" {
		return DoHProbeResult{URL: raw, Error: "empty URL"}
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
	_ = decodeJSONBody(w, r, &req, 4096)

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
	_ = decodeJSONBody(w, r, &req, 8192)

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
	if err := decodeJSONBody(w, r, &req, 16384); err != nil || strings.TrimSpace(req.URI) == "" {
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
	if err := decodeJSONBody(w, r, &req, 4096); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSONError(w, http.StatusBadRequest, "peer name is required")
		return
	}

	var addedPeer state.WGPeer
	var updatedWG state.WireGuardConfig
	_, _, err := reconcile.UpdateAndReconcile(r.Context(), s.Store, state.RoleClient, s.Exec, s.ApplyOpts, func(cur *state.State) error {
		peer, perr := cur.AddWireGuardPeer(name, req.EndpointHost, req.ListenPort, req.SubnetCIDR)
		if perr != nil {
			return perr
		}
		addedPeer = peer
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
	var pub string
	updated, _, err := reconcile.UpdateAndReconcile(r.Context(), s.Store, state.RoleClient, s.Exec, s.ApplyOpts, func(cur *state.State) error {
		var kerr error
		pub, kerr = cur.RegenerateWireGuardServerKeys()
		return kerr
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
	var updatedPeer state.WGPeer
	var updatedWG state.WireGuardConfig
	_, _, err := reconcile.UpdateAndReconcile(r.Context(), s.Store, state.RoleClient, s.Exec, s.ApplyOpts, func(cur *state.State) error {
		peer, perr := cur.RegenerateWireGuardPeer(name)
		if perr != nil {
			return perr
		}
		updatedPeer = peer
		updatedWG = cur.Client.WireGuard
		return nil
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

func (s *Server) handleConnectivity(w http.ResponseWriter, r *http.Request, _ *sessionRecord) {
	var req struct {
		WithIPs bool `json:"with_ips"`
	}
	_ = decodeJSONBody(w, r, &req, 1024)

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
	if st.Role == state.RoleClient {
		reconcile.CleanupTProxyPolicyRoutes(r.Context(), s.Exec)
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
	_ = decodeJSONBody(w, r, &req, 1024)
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
	_ = decodeJSONBody(w, r, &req, 1024)
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
