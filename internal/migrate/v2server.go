package migrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/stuinxo/dex/internal/state"
)

var (
	nginxServerNameRe = regexp.MustCompile(`(?m)^\s*server_name\s+([^;\s]+)\s*;`)
	nginxSSLPortRe    = regexp.MustCompile(`(?m)^\s*listen\s+(\d+)\s+.*ssl`)
)

// ImportV2Server reconstructs a v3 Server State from a v2 server installation rooted at rootDir
// (e.g. "/" on a live system or a fixture directory in tests).
func ImportV2Server(rootDir string) (*state.State, []string, error) {
	if rootDir == "" {
		rootDir = "/"
	}
	st := state.NewDefaultState(state.RoleServer)
	var notes []string

	// 1. Nginx main domain and port
	nginxConfPath := filepath.Join(rootDir, "etc", "nginx", "conf.d", "default.conf")
	if b, err := os.ReadFile(nginxConfPath); err == nil {
		txt := string(b)
		if m := nginxServerNameRe.FindStringSubmatch(txt); len(m) == 2 {
			st.Server.Domain = m[1]
			st.Cert.Domain = m[1]
		}
		if m := nginxSSLPortRe.FindStringSubmatch(txt); len(m) == 2 {
			if p, perr := strconv.Atoi(m[1]); perr == nil && p > 0 {
				st.Server.ListenPort = p
			}
		}
		if strings.Contains(txt, "location /dq") {
			st.Server.EnableDoH = true
		}
	} else {
		notes = append(notes, "default.conf not found; using server defaults unless specified")
	}

	// 2. Xray main inbound & extra protocols
	vtruiConfPath := filepath.Join(rootDir, "opt", "de_GWD", "vtrui", "config.json")
	if b, err := os.ReadFile(vtruiConfPath); err == nil {
		var xcfg map[string]any
		if err := json.Unmarshal(b, &xcfg); err != nil {
			return nil, nil, fmt.Errorf("parse vtrui config.json: %w", err)
		}
		if inbs, ok := xcfg["inbounds"].([]any); ok && len(inbs) > 0 {
			if first, ok := inbs[0].(map[string]any); ok {
				if settings, ok := first["settings"].(map[string]any); ok {
					if clients, ok := settings["clients"].([]any); ok {
						for _, c := range clients {
							if cm, ok := c.(map[string]any); ok {
								if id := strVal(cm["id"]); id != "" {
									st.Server.UUIDs = append(st.Server.UUIDs, id)
								}
							}
						}
					}
				}
				proto := strings.ToLower(strVal(first["protocol"]))
				if stream, ok := first["streamSettings"].(map[string]any); ok {
					netName := strings.ToLower(strVal(stream["network"]))
					switch {
					case proto == "vmess" && netName == "ws":
						st.Server.Protocol = "vmess-ws"
						if ws, ok := stream["wsSettings"].(map[string]any); ok {
							st.Server.Path = strVal(ws["path"])
						}
					case proto == "vless" && netName == "ws":
						st.Server.Protocol = "vless-ws"
						if ws, ok := stream["wsSettings"].(map[string]any); ok {
							st.Server.Path = strVal(ws["path"])
						}
					default:
						st.Server.Protocol = "vless-xhttp"
						if xs, ok := stream["xhttpSettings"].(map[string]any); ok {
							st.Server.Path = strVal(xs["path"])
						} else if ws, ok := stream["wsSettings"].(map[string]any); ok {
							st.Server.Path = strVal(ws["path"])
						}
					}
				}
			}
		}
		// Reuse extra_inbounds extraction if vtrui has inbound-* entries
		extraDir := filepath.Join(rootDir, "opt", "de_GWD")
		extraInbs, exNotes := importExtraFromVtrui(xcfg, extraDir)
		st.ExtraInbounds = append(st.ExtraInbounds, extraInbs...)
		notes = append(notes, exNotes...)
	}

	// 3. Certificate detection
	cerPath := filepath.Join(rootDir, "var", "www", "ssl", "de_GWD.cer")
	keyPath := filepath.Join(rootDir, "var", "www", "ssl", "de_GWD.key")
	if _, err := os.Stat(cerPath); err == nil {
		if _, err2 := os.Stat(keyPath); err2 == nil {
			st.Cert.Mode = "imported"
			st.Cert.CertFile = cerPath
			st.Cert.KeyFile = keyPath
		}
	}

	// 4. Option 35 SOCKS5 outbounds (both legacy single-object and profiles array)
	s5Path := filepath.Join(rootDir, "opt", "de_GWD", "socks5-outbound.json")
	if b, err := os.ReadFile(s5Path); err == nil {
		var s5doc map[string]any
		if err := json.Unmarshal(b, &s5doc); err == nil {
			parseProfile := func(m map[string]any, defaultName string) state.Socks5Profile {
				name := strVal(m["name"])
				if name == "" {
					name = defaultName
				}
				srv, _ := m["server"].(map[string]any)
				enabled, _ := m["enabled"].(bool)
				privBypass := true
				if pb, exists := m["privateBypass"].(bool); exists {
					privBypass = pb
				}
				return state.Socks5Profile{
					Name:          name,
					Enabled:       enabled,
					Address:       strVal(srv["address"]),
					Port:          intVal(srv["port"], 1080),
					Username:      strVal(srv["username"]),
					Password:      strVal(srv["password"]),
					Domains:       strSliceVal(m["domains"]),
					IPs:           strSliceVal(m["ips"]),
					PrivateBypass: privBypass,
				}
			}
			if arr, ok := s5doc["profiles"].([]any); ok {
				for _, item := range arr {
					if pm, ok := item.(map[string]any); ok {
						st.Server.Socks5Outbounds = append(st.Server.Socks5Outbounds, parseProfile(pm, "default"))
					}
				}
			} else if _, hasSrv := s5doc["server"]; hasSrv {
				st.Server.Socks5Outbounds = append(st.Server.Socks5Outbounds, parseProfile(s5doc, "default"))
			}
		}
	}

	// 5. Option 22 RproxyS settings
	rpsPath := filepath.Join(rootDir, "opt", "de_GWD", "RproxyS", "settings.json")
	if b, err := os.ReadFile(rpsPath); err == nil {
		var rpsDoc map[string]any
		if err := json.Unmarshal(b, &rpsDoc); err == nil {
			lp := intVal(rpsDoc["port"], 0)
			u := strVal(rpsDoc["uuid"])
			if lp > 0 && u != "" {
				var maps []state.RproxyServerMapping
				if arr, ok := rpsDoc["mapping"].([]any); ok {
					for _, item := range arr {
						if mm, ok := item.(map[string]any); ok {
							maps = append(maps, state.RproxyServerMapping{
								Port:  intVal(mm["port"], 0),
								Proto: normalizeProto(strVal(mm["protocol"])),
							})
						}
					}
				}
				st.RproxyS = state.RproxySConfig{
					Enabled:    true,
					Domain:     st.Server.Domain,
					ListenPort: lp,
					UUIDs:      []string{u},
					Mappings:   maps,
				}
			}
		}
	}

	// 6. Option 44 HAProxy forwards
	hapPath := filepath.Join(rootDir, "etc", "haproxy", "haproxy.cfg")
	if b, err := os.ReadFile(hapPath); err == nil {
		st.Relay.Forwards = append(st.Relay.Forwards, parseHAProxyRules(string(b))...)
	}

	return st, notes, nil
}

func importExtraFromVtrui(xcfg map[string]any, optDir string) ([]state.ExtraInbound, []string) {
	inbs, ok := xcfg["inbounds"].([]any)
	if !ok {
		return nil, nil
	}
	var filtered []map[string]any
	for _, raw := range inbs {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if strings.HasPrefix(strVal(m["tag"]), "inbound-") {
			filtered = append(filtered, m)
		}
	}
	if len(filtered) == 0 {
		return nil, nil
	}
	portsMap := readStringIntMap(filepath.Join(optDir, "extra_ports.json"))
	domainsMap := readStringMap(filepath.Join(optDir, "extra_domains.json"))
	return decodeExtraInbounds(filtered, portsMap, domainsMap, filepath.Join(optDir, "vtrui", "reality.info"))
}

func parseHAProxyRules(cfg string) []state.ForwardRule {
	var out []state.ForwardRule
	lines := strings.Split(cfg, "\n")
	curBind := 0
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "bind ") {
			fields := strings.Fields(t)
			if len(fields) >= 2 {
				hp := fields[1]
				if idx := strings.LastIndex(hp, ":"); idx >= 0 {
					if p, err := strconv.Atoi(hp[idx+1:]); err == nil && p > 0 {
						curBind = p
					}
				}
			}
		} else if strings.HasPrefix(t, "server ") && curBind > 0 {
			fields := strings.Fields(t)
			if len(fields) >= 3 {
				targetHost, targetPort := splitHostPort(fields[2], 443)
				if targetHost != "" && targetPort > 0 {
					out = append(out, state.ForwardRule{
						ID:         fmt.Sprintf("hap-%d", curBind),
						ListenPort: curBind,
						PublicPort: curBind,
						TargetHost: targetHost,
						TargetPort: targetPort,
						Proto:      "tcp",
						Engine:     "haproxy",
					})
					curBind = 0
				}
			}
		}
	}
	return out
}
