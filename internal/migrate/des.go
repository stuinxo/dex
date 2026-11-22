package migrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stuinxo/dex/internal/state"
)

// ImportDES migrates a /etc/des/state.json file (landing or relay role) to v3 State.
func ImportDES(statePath string) (*state.State, []string, error) {
	b, err := os.ReadFile(statePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read des state: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, nil, fmt.Errorf("parse des state: %w", err)
	}

	role := strVal(raw["role"])
	if role != state.RoleLanding && role != state.RoleRelay {
		return nil, nil, fmt.Errorf("unsupported des role %q", role)
	}

	st := state.NewDefaultState(role)
	var notes []string
	domain := strVal(raw["domain"])
	pubHost := strVal(raw["public_host"])

	baseDir := filepath.Dir(statePath)
	cer := filepath.Join(baseDir, "ssl", "cert.pem")
	key := filepath.Join(baseDir, "ssl", "key.pem")
	if _, err := os.Stat(cer); err == nil {
		if _, err2 := os.Stat(key); err2 == nil {
			st.Cert.Mode = "imported"
			st.Cert.CertFile = cer
			st.Cert.KeyFile = key
			st.Cert.Domain = domain
		}
	}

	if role == state.RoleLanding {
		landing, _ := raw["landing"].(map[string]any)
		st.Server = state.ServerConfig{
			TLSMode:     "direct",
			Domain:      domain,
			ConnectHost: pubHost,
			ListenPort:  intVal(landing["listen_port"], 443),
			PublicPort:  intVal(landing["public_port"], 0),
			UUIDs:       strSliceVal(landing["uuids"]),
			Path:        strVal(landing["path"]),
			EnableDoH:   false,
		}
		if extras, ok := raw["extras"].(map[string]any); ok {
			if r, ok := extras["reality"].(map[string]any); ok {
				st.ExtraInbounds = append(st.ExtraInbounds, state.ExtraInbound{
					Tag:            "inbound-vless-reality",
					Protocol:       "vless-reality",
					ListenPort:     intVal(r["listen_port"], 0),
					UUID:           strVal(r["uuid"]),
					RealitySNI:     strVal(r["sni"]),
					RealityDest:    strVal(r["dest"]),
					RealityPrivKey: strVal(r["private_key"]),
					RealityPubKey:  strVal(r["public_key"]),
					RealityShortID: strVal(r["short_id"]),
				})
			}
			if s5, ok := extras["socks"].(map[string]any); ok {
				st.ExtraInbounds = append(st.ExtraInbounds, state.ExtraInbound{
					Tag:        "inbound-socks5",
					Protocol:   "socks5",
					ListenPort: intVal(s5["listen_port"], 0),
					SocksUser:  strVal(s5["user"]),
					SocksPass:  strVal(s5["pass"]),
				})
			}
		}
		notes = append(notes, "Imported des landing configuration")
		return st, notes, nil
	}

	// Relay role
	if relay, ok := raw["relay"].(map[string]any); ok {
		if fwds, ok := relay["forwards"].([]any); ok {
			for i, item := range fwds {
				fm, ok := item.(map[string]any)
				if !ok {
					continue
				}
				engine := strVal(fm["engine"])
				if engine == "" {
					engine = "nft"
				}
				st.Relay.Forwards = append(st.Relay.Forwards, state.ForwardRule{
					ID:         fmt.Sprintf("des-fwd-%d", i+1),
					ListenPort: intVal(fm["listen"], 0),
					PublicPort: intVal(fm["public"], 0),
					TargetHost: strVal(fm["target_host"]),
					TargetPort: intVal(fm["target_port"], 443),
					Proto:      normalizeProto(strVal(fm["proto"])),
					Engine:     engine,
				})
			}
		}
		if rps, ok := relay["rproxys"].(map[string]any); ok {
			enabled, _ := rps["enabled"].(bool)
			var maps []state.RproxyServerMapping
			if arr, ok := rps["mappings"].([]any); ok {
				for _, item := range arr {
					if mm, ok := item.(map[string]any); ok {
						maps = append(maps, state.RproxyServerMapping{
							Port:  intVal(mm["port"], 0),
							Proto: normalizeProto(strVal(mm["proto"])),
						})
					}
				}
			}
			st.RproxyS = state.RproxySConfig{
				Enabled:    enabled,
				Domain:     strVal(rps["domain"]),
				ListenPort: intVal(rps["listen_port"], 0),
				UUIDs:      strSliceVal(rps["uuids"]),
				Mappings:   maps,
			}
		}
	}
	notes = append(notes, "Imported des relay configuration")
	return st, notes, nil
}

// ImportDEXS migrates a /etc/vless-lite/state.json file into v3 State.
func ImportDEXS(statePath string) (*state.State, []string, error) {
	b, err := os.ReadFile(statePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read dexs state: %w", err)
	}
	var doc struct {
		Version int    `json:"version"`
		Domain  string `json:"domain"`
		Nodes   []struct {
			Name string `json:"name"`
			Port int    `json:"port"`
			UUID string `json:"uuid"`
		} `json:"nodes"`
		Relays []struct {
			Name       string `json:"name"`
			Port       int    `json:"port"`
			Host       string `json:"host"`
			TargetPort int    `json:"target_port"`
			Network    string `json:"network"`
		} `json:"relays"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse dexs state: %w", err)
	}

	var notes []string
	role := state.RoleRelay
	if len(doc.Nodes) > 0 {
		role = state.RoleLanding
	}
	st := state.NewDefaultState(role)

	baseDir := filepath.Dir(statePath)
	cer := filepath.Join(baseDir, "tls", "fullchain.pem")
	key := filepath.Join(baseDir, "tls", "key.pem")
	if _, err := os.Stat(cer); err == nil {
		if _, err2 := os.Stat(key); err2 == nil {
			st.Cert.Mode = "imported"
			st.Cert.CertFile = cer
			st.Cert.KeyFile = key
			st.Cert.Domain = doc.Domain
		}
	}

	if len(doc.Nodes) > 0 {
		// Map each dexs VLESS+WS+TLS node cleanly to a direct TLS extra inbound so its original WS path (/UUIDlast6) and port are preserved,
		// while setting primary server port/UUID if main node uses standard WS or extra.
		first := doc.Nodes[0]
		st.Server = state.ServerConfig{
			TLSMode:    "direct",
			Domain:     doc.Domain,
			ListenPort: first.Port,
			UUIDs:      []string{first.UUID},
			Path:       "/" + first.UUID[max(0, len(first.UUID)-6):],
			EnableDoH:  false,
		}
		seenExtraTags := make(map[string]bool, len(doc.Nodes))
		for i := 1; i < len(doc.Nodes); i++ {
			n := doc.Nodes[i]
			name := strings.TrimSpace(n.Name)
			if name == "" {
				name = fmt.Sprintf("node-%d", i+1)
			}
			baseTag := "dexs-" + name
			tag := baseTag
			for suffix := 2; seenExtraTags[tag]; suffix++ {
				tag = fmt.Sprintf("%s-%d", baseTag, suffix)
			}
			seenExtraTags[tag] = true
			st.ExtraInbounds = append(st.ExtraInbounds, state.ExtraInbound{
				Tag:        tag,
				Protocol:   "vless-ws",
				ListenPort: n.Port,
				UUID:       n.UUID,
				Path:       "/" + n.UUID[max(0, len(n.UUID)-6):],
				Domain:     doc.Domain,
				ViaNginx:   false,
			})
		}
		notes = append(notes, fmt.Sprintf("Imported %d dexs node(s) (main + extra VLESS-WS-TLS)", len(doc.Nodes)))
	}

	seenRelayIDs := make(map[string]bool, len(doc.Relays))
	for idx, r := range doc.Relays {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = fmt.Sprintf("relay-%d", idx+1)
		}
		baseID := "dexs-" + name
		id := baseID
		for suffix := 2; seenRelayIDs[id]; suffix++ {
			id = fmt.Sprintf("%s-%d", baseID, suffix)
		}
		seenRelayIDs[id] = true
		st.Relay.Forwards = append(st.Relay.Forwards, state.ForwardRule{
			ID:         id,
			Name:       name,
			ListenPort: r.Port,
			TargetHost: r.Host,
			TargetPort: r.TargetPort,
			Proto:      normalizeProto(r.Network),
			Engine:     "xray",
		})
	}
	if len(doc.Relays) > 0 {
		notes = append(notes, fmt.Sprintf("Imported %d dexs relay(s)", len(doc.Relays)))
	}

	return st, notes, nil
}
