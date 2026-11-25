package render

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/stuinxo/dex/internal/socks5out"
	"github.com/stuinxo/dex/internal/state"
)

var xrayPrivateCIDRs = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

func freedomFinalRules() map[string]any {
	return map[string]any{
		"finalRules": []map[string]any{
			{"action": "allow", "ip": []string{"0.0.0.0/0", "::/0"}},
		},
	}
}

func serverDirectFreedomOutbound(tag string, mark int) map[string]any {
	settings := map[string]any{
		"finalRules": []map[string]any{
			{
				"action": "block",
				"ip": []string{
					"0.0.0.0/8",
					"127.0.0.0/8",
					"10.0.0.0/8",
					"100.64.0.0/10",
					"169.254.0.0/16",
					"172.16.0.0/12",
					"192.168.0.0/16",
					"224.0.0.0/4",
					"::1/128",
					"fc00::/7",
					"fe80::/10",
					"ff00::/8",
				},
			},
			{"action": "allow", "ip": []string{"0.0.0.0/0", "::/0"}},
		},
	}
	return buildFreedomOutboundWithSettings(tag, mark, settings)
}

func buildFreedomOutboundWithSettings(tag string, mark int, settings map[string]any) map[string]any {
	sockopt := map[string]any{
		"tcpFastOpen": true,
		"tcpNoDelay":  true,
	}
	if mark > 0 {
		sockopt["mark"] = mark
	}
	return map[string]any{
		"tag":      tag,
		"protocol": "freedom",
		"settings": settings,
		"streamSettings": map[string]any{
			"sockopt": sockopt,
		},
	}
}

func buildFreedomOutbound(tag string, mark int, redirect string) map[string]any {
	settings := freedomFinalRules()
	if redirect != "" {
		settings["redirect"] = redirect
	}
	return buildFreedomOutboundWithSettings(tag, mark, settings)
}

func buildClientOutbound(tag string, n state.OutboundNode, mark int) map[string]any {
	sockopt := map[string]any{
		"tcpFastOpen": true,
		"tcpNoDelay":  true,
	}
	if mark > 0 {
		sockopt["mark"] = mark
	}
	port := n.Port
	if port <= 0 {
		port = 443
	}
	sni := n.EffectiveSNI()

	switch n.Protocol {
	case "vless-reality":
		return map[string]any{
			"tag":      tag,
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []map[string]any{{
					"address": n.Address,
					"port":    port,
					"users": []map[string]any{{
						"id":         n.UUID,
						"flow":       "xtls-rprx-vision",
						"encryption": "none",
					}},
				}},
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"show":        false,
					"fingerprint": "chrome",
					"serverName":  sni,
					"publicKey":   n.RealityPubKey,
					"shortId":     n.RealityShortID,
					"spiderX":     "",
				},
				"sockopt": sockopt,
			},
		}
	case "vless-ws":
		return map[string]any{
			"tag":      tag,
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []map[string]any{{
					"address": n.Address,
					"port":    port,
					"users": []map[string]any{{
						"id":         n.UUID,
						"encryption": "none",
					}},
				}},
			},
			"streamSettings": map[string]any{
				"network":  "ws",
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName":    sni,
					"allowInsecure": false,
				},
				"wsSettings": map[string]any{
					"path": NormalizePath(n.Path, n.UUID),
					"headers": map[string]string{
						"Host": sni,
					},
				},
				"sockopt": sockopt,
			},
		}
	case "vmess-ws":
		return map[string]any{
			"tag":      tag,
			"protocol": "vmess",
			"settings": map[string]any{
				"vnext": []map[string]any{{
					"address": n.Address,
					"port":    port,
					"users": []map[string]any{{
						"id":       n.UUID,
						"alterId":  0,
						"security": "auto",
					}},
				}},
			},
			"streamSettings": map[string]any{
				"network":  "ws",
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName":    sni,
					"allowInsecure": false,
				},
				"wsSettings": map[string]any{
					"path": NormalizePath(n.Path, n.UUID),
					"headers": map[string]string{
						"Host": sni,
					},
				},
				"sockopt": sockopt,
			},
		}
	case "vmess-tcp":
		return map[string]any{
			"tag":      tag,
			"protocol": "vmess",
			"settings": map[string]any{
				"vnext": []map[string]any{{
					"address": n.Address,
					"port":    port,
					"users": []map[string]any{{
						"id":       n.UUID,
						"alterId":  0,
						"security": "auto",
					}},
				}},
			},
			"streamSettings": map[string]any{
				"network": "tcp",
				"sockopt": sockopt,
			},
		}
	case "socks5":
		srv := map[string]any{
			"address": n.Address,
			"port":    port,
		}
		if n.Username != "" {
			srv["users"] = []map[string]any{{
				"user": n.Username,
				"pass": n.Password,
			}}
		}
		return map[string]any{
			"tag":      tag,
			"protocol": "socks",
			"settings": map[string]any{
				"servers": []map[string]any{srv},
			},
			"streamSettings": map[string]any{
				"sockopt": sockopt,
			},
		}
	default: // vless-xhttp
		return map[string]any{
			"tag":      tag,
			"protocol": "vless",
			"settings": map[string]any{
				"vnext": []map[string]any{{
					"address": n.Address,
					"port":    port,
					"users": []map[string]any{{
						"id":         n.UUID,
						"encryption": "none",
					}},
				}},
			},
			"streamSettings": map[string]any{
				"network":  "xhttp",
				"security": "tls",
				"tlsSettings": map[string]any{
					"serverName":    sni,
					"alpn":          []string{"h2"},
					"allowInsecure": false,
				},
				"xhttpSettings": map[string]any{
					"path": NormalizePath(n.Path, n.UUID),
					"mode": "packet-up",
				},
				"sockopt": sockopt,
			},
		}
	}
}

func inboundWildcardListen(enableIPv6 bool) string {
	if enableIPv6 {
		return "::"
	}
	return "0.0.0.0"
}

func buildVMessTCPInbound(tag string, port int, uuids []string, listen string) map[string]any {
	clients := make([]map[string]any, 0, len(uuids))
	for _, u := range uuids {
		clients = append(clients, map[string]any{
			"id":      u,
			"alterId": 0,
		})
	}
	return map[string]any{
		"tag":      tag,
		"listen":   listen,
		"port":     port,
		"protocol": "vmess",
		"settings": map[string]any{
			"clients": clients,
		},
		"streamSettings": map[string]any{
			"network": "tcp",
		},
		"sniffing": map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
			"routeOnly":    true,
		},
	}
}

func buildTProxyInbound(tag, listen string, mark int) map[string]any {
	return map[string]any{
		"tag":      tag,
		"port":     9896,
		"listen":   listen,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"network": "tcp,udp", "followRedirect": true},
		"streamSettings": map[string]any{
			"sockopt": map[string]any{
				"tproxy":      "tproxy",
				"mark":        mark,
				"tcpFastOpen": false,
				"tcpMptcp":    true,
			},
		},
		"sniffing": map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
			"routeOnly":    true,
			"metadataOnly": false,
		},
	}
}

func normalizeXrayDomainRules(list []string) []string {
	var out []string
	for _, raw := range list {
		r := strings.TrimSpace(raw)
		if r == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(r, "*."); ok && rest != "" {
			r = "domain:" + rest
		}
		out = append(out, r)
	}
	return out
}

func buildMainServerInbound(s *state.State, opts RenderOptions) map[string]any {
	firstUUID := ""
	if len(s.Server.UUIDs) > 0 {
		firstUUID = s.Server.UUIDs[0]
	}
	proto := s.Server.EffectiveProtocol()
	path := NormalizePath(s.Server.Path, firstUUID)

	listen := inboundWildcardListen(s.System.EnableIPv6)
	port := s.Server.ListenPort
	if s.Server.TLSMode == "nginx" {
		listen = "127.0.0.1"
		port = 9890
	}

	netType := "xhttp"
	netKey := "xhttpSettings"
	netSettings := map[string]any{
		"path": path,
		"mode": "auto",
	}
	if proto == "vless-ws" || proto == "vmess-ws" {
		netType = "ws"
		netKey = "wsSettings"
		netSettings = map[string]any{
			"path": path,
		}
	}

	sockopt := map[string]any{
		"tcpFastOpen": true,
		"tcpNoDelay":  true,
	}
	if s.Server.TLSMode == "nginx" {
		sockopt = map[string]any{
			"tcpFastOpen": true,
			"tcpMptcp":    true,
		}
	}

	stream := map[string]any{
		"network": netType,
		netKey:    netSettings,
		"sockopt": sockopt,
	}
	if s.Server.TLSMode == "nginx" {
		stream["security"] = "none"
	} else {
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{
			"alpn":       []string{"h2", "http/1.1"},
			"minVersion": "1.2",
			"certificates": []map[string]any{{
				"certificateFile": opts.CertFile,
				"keyFile":         opts.KeyFile,
			}},
		}
	}

	sniff := map[string]any{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
		"routeOnly":    true,
	}

	if proto == "vmess-ws" {
		clients := make([]map[string]any, 0, len(s.Server.UUIDs))
		for _, u := range s.Server.UUIDs {
			clients = append(clients, map[string]any{"id": u, "alterId": 0})
		}
		return map[string]any{
			"tag":            "main",
			"listen":         listen,
			"port":           port,
			"protocol":       "vmess",
			"settings":       map[string]any{"clients": clients},
			"streamSettings": stream,
			"sniffing":       sniff,
		}
	}

	clients := make([]map[string]any, 0, len(s.Server.UUIDs))
	for _, u := range s.Server.UUIDs {
		clients = append(clients, map[string]any{"id": u})
	}
	return map[string]any{
		"tag":      "main",
		"listen":   listen,
		"port":     port,
		"protocol": "vless",
		"settings": map[string]any{
			"clients":    clients,
			"decryption": "none",
		},
		"streamSettings": stream,
		"sniffing":       sniff,
	}
}

func buildXHTTPDirectTLSInbound(tag string, port int, uuids []string, path, certFile, keyFile, listen string) map[string]any {
	clients := make([]map[string]any, 0, len(uuids))
	for _, u := range uuids {
		clients = append(clients, map[string]any{"id": u})
	}
	firstUUID := ""
	if len(uuids) > 0 {
		firstUUID = uuids[0]
	}
	return map[string]any{
		"tag":      tag,
		"listen":   listen,
		"port":     port,
		"protocol": "vless",
		"settings": map[string]any{
			"clients":    clients,
			"decryption": "none",
		},
		"streamSettings": map[string]any{
			"network":  "xhttp",
			"security": "tls",
			"tlsSettings": map[string]any{
				"alpn":       []string{"h2", "http/1.1"},
				"minVersion": "1.2",
				"certificates": []map[string]any{{
					"certificateFile": certFile,
					"keyFile":         keyFile,
				}},
			},
			"xhttpSettings": map[string]any{
				"path": NormalizePath(path, firstUUID),
				"mode": "auto",
			},
			"sockopt": map[string]any{
				"tcpFastOpen": true,
				"tcpNoDelay":  true,
			},
		},
		"sniffing": map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
			"routeOnly":    true,
		},
	}
}

func buildExtraInbound(ex state.ExtraInbound, viaNginxPort int, certFile, keyFile string, enableIPv6 bool) map[string]any {
	sniff := map[string]any{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
		"routeOnly":    true,
	}
	wildcardListen := inboundWildcardListen(enableIPv6)
	listen := wildcardListen
	bindPort := ex.ListenPort
	if ex.ViaNginx {
		listen = "127.0.0.1"
		if viaNginxPort > 0 {
			bindPort = viaNginxPort
		} else {
			bindPort = ExtraInternalPort(ex.ListenPort)
		}
	}

	switch ex.Protocol {
	case "vless-reality":
		return map[string]any{
			"tag":      ex.Tag,
			"listen":   wildcardListen,
			"port":     ex.ListenPort,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []map[string]any{{"id": ex.UUID, "flow": "xtls-rprx-vision"}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"show":        false,
					"dest":        ex.RealityDest,
					"xver":        0,
					"serverNames": []string{ex.RealitySNI},
					"privateKey":  ex.RealityPrivKey,
					"shortIds":    []string{ex.RealityShortID},
				},
				"sockopt": map[string]any{"tcpFastOpen": true, "tcpNoDelay": true},
			},
			"sniffing": sniff,
		}
	case "vless-xhttp", "vless-ws", "vmess-ws":
		netType := "ws"
		netSettingsKey := "wsSettings"
		netSettings := map[string]any{"path": NormalizePath(ex.Path, ex.UUID)}
		if ex.Protocol == "vless-xhttp" {
			netType = "xhttp"
			netSettingsKey = "xhttpSettings"
			netSettings["mode"] = "auto"
		}
		stream := map[string]any{
			"network":      netType,
			netSettingsKey: netSettings,
			"sockopt":      map[string]any{"tcpFastOpen": true, "tcpNoDelay": true},
		}
		if ex.ViaNginx {
			stream["security"] = "none"
		} else {
			stream["security"] = "tls"
			stream["tlsSettings"] = map[string]any{
				"alpn":       []string{"h2", "http/1.1"},
				"minVersion": "1.2",
				"certificates": []map[string]any{{
					"certificateFile": certFile,
					"keyFile":         keyFile,
				}},
			}
		}
		if ex.Protocol == "vmess-ws" {
			return map[string]any{
				"tag":            ex.Tag,
				"listen":         listen,
				"port":           bindPort,
				"protocol":       "vmess",
				"settings":       map[string]any{"clients": []map[string]any{{"id": ex.UUID, "alterId": 0}}},
				"streamSettings": stream,
				"sniffing":       sniff,
			}
		}
		return map[string]any{
			"tag":            ex.Tag,
			"listen":         listen,
			"port":           bindPort,
			"protocol":       "vless",
			"settings":       map[string]any{"clients": []map[string]any{{"id": ex.UUID}}, "decryption": "none"},
			"streamSettings": stream,
			"sniffing":       sniff,
		}
	case "socks5":
		settings := map[string]any{"udp": true}
		if ex.SocksUser != "" {
			settings["auth"] = "password"
			settings["accounts"] = []map[string]any{{"user": ex.SocksUser, "pass": ex.SocksPass}}
		} else {
			settings["auth"] = "noauth"
		}
		return map[string]any{
			"tag":      ex.Tag,
			"listen":   wildcardListen,
			"port":     ex.ListenPort,
			"protocol": "socks",
			"settings": settings,
		}
	case "dokodemo":
		netProto := strings.TrimSpace(ex.Network)
		if netProto == "" {
			netProto = "tcp,udp"
		}
		return map[string]any{
			"tag":      ex.Tag,
			"listen":   wildcardListen,
			"port":     ex.ListenPort,
			"protocol": "dokodemo-door",
			"settings": map[string]any{
				"address": ex.TargetAddr,
				"port":    ex.TargetPort,
				"network": netProto,
			},
		}
	default:
		return nil
	}
}

// RenderXray builds the unified single-process Xray configuration JSON and reports whether Xray is needed.
func RenderXray(s *state.State, opts RenderOptions) (data []byte, needed bool, err error) {
	opts = opts.WithDefaults()

	var (
		inbounds  []map[string]any
		outbounds []map[string]any
		rules     []map[string]any
	)
	domainStrategy := "AsIs"
	dnsServers := []string{"1.1.1.1", "8.8.8.8", "localhost"}
	if s.Role == state.RoleClient {
		dnsServers = []string{"tcp+local://127.0.0.1:53"}
	} else if s.System.EnableIPv6 {
		dnsServers = []string{"localhost", "2606:4700:4700::1111", "2001:4860:4860::8888", "1.1.1.1", "8.8.8.8"}
	}
	dnsCfg := map[string]any{
		"tag":           "dnsflow",
		"queryStrategy": "UseIP",
		"disableCache":  true,
		"servers":       dnsServers,
	}

	viaNginxPorts := AllocateViaNginxInternalPorts(s)
	wildcardListen := inboundWildcardListen(s.System.EnableIPv6)

	addCommonRelayAndExtra := func(mark int) {
		usedTags := make(map[string]bool, len(inbounds)+len(s.Relay.Forwards)+len(s.ExtraInbounds)+2)
		for _, inb := range inbounds {
			if t, ok := inb["tag"].(string); ok && t != "" {
				usedTags[t] = true
			}
		}
		for _, ex := range s.ExtraInbounds {
			if ex.Tag != "" {
				usedTags[ex.Tag] = true
			}
		}
		var fwdTags []string
		for _, fwd := range s.Relay.Forwards {
			if fwd.Engine != "xray" {
				continue
			}
			baseTag := strings.TrimSpace(fwd.ID)
			if baseTag == "" {
				baseTag = fmt.Sprintf("fwd-%d", fwd.ListenPort)
			} else if !strings.HasPrefix(baseTag, "fwd-") {
				baseTag = "fwd-" + baseTag
			}
			tag := baseTag
			for suffix := 2; usedTags[tag]; suffix++ {
				tag = fmt.Sprintf("%s-%d", baseTag, suffix)
			}
			usedTags[tag] = true
			fwdTags = append(fwdTags, tag)
			inbounds = append(inbounds, map[string]any{
				"tag":      tag,
				"listen":   wildcardListen,
				"port":     fwd.ListenPort,
				"protocol": "dokodemo-door",
				"settings": map[string]any{
					"address": fwd.TargetHost,
					"port":    fwd.TargetPort,
					"network": fwd.Proto,
				},
			})
		}
		if s.RproxyS.Enabled {
			rpsClients := make([]map[string]any, 0, len(s.RproxyS.UUIDs)+len(s.RproxyS.InUUIDs))
			seenRPS := make(map[string]struct{}, len(s.RproxyS.UUIDs))
			for _, u := range s.RproxyS.UUIDs {
				seenRPS[u] = struct{}{}
				rpsClients = append(rpsClients, map[string]any{
					"id":      u,
					"reverse": map[string]any{"tag": "portal"},
				})
			}
			for _, u := range s.RproxyS.InUUIDs {
				if _, exists := seenRPS[u]; exists {
					continue
				}
				seenRPS[u] = struct{}{}
				rpsClients = append(rpsClients, map[string]any{
					"id": u,
				})
			}
			rpsSec := strings.TrimSpace(s.RproxyS.Security)
			if rpsSec == "" {
				rpsSec = "tls"
			}
			rpsStream := map[string]any{
				"network":  "tcp",
				"security": rpsSec,
			}
			if rpsSec == "tls" {
				rpsStream["tlsSettings"] = map[string]any{
					"minVersion": "1.2",
					"certificates": []map[string]any{{
						"certificateFile": opts.CertFile,
						"keyFile":         opts.KeyFile,
					}},
				}
			}
			inbounds = append(inbounds, map[string]any{
				"tag":      "rps-tunnel",
				"listen":   wildcardListen,
				"port":     s.RproxyS.ListenPort,
				"protocol": "vless",
				"settings": map[string]any{
					"decryption": "none",
					"clients":    rpsClients,
				},
				"streamSettings": rpsStream,
			})
			var highPrioRules []map[string]any
			if len(s.RproxyS.InUUIDs) > 0 {
				highPrioRules = append(highPrioRules, map[string]any{
					"type":        "field",
					"inboundTag":  []string{"rps-tunnel"},
					"outboundTag": "portal",
				})
			}
			var rpsTags []string
			for _, m := range s.RproxyS.Mappings {
				tag := fmt.Sprintf("rps-map-%d", m.Port)
				rpsTags = append(rpsTags, tag)
				inbounds = append(inbounds, map[string]any{
					"tag":      tag,
					"listen":   wildcardListen,
					"port":     m.Port,
					"protocol": "dokodemo-door",
					"settings": map[string]any{
						"address": "127.0.0.1",
						"port":    m.Port,
						"network": m.Proto,
					},
				})
			}
			if len(rpsTags) > 0 {
				highPrioRules = append(highPrioRules, map[string]any{
					"type":        "field",
					"inboundTag":  rpsTags,
					"outboundTag": "portal",
				})
			}
			if len(highPrioRules) > 0 {
				rules = append(highPrioRules, rules...)
			}
		}

		var dokoTags []string
		for _, ex := range s.ExtraInbounds {
			if inb := buildExtraInbound(ex, viaNginxPorts[ex.Tag], opts.CertFile, opts.KeyFile, s.System.EnableIPv6); inb != nil {
				inbounds = append(inbounds, inb)
				if ex.Protocol == "dokodemo" {
					dokoTags = append(dokoTags, ex.Tag)
				}
			}
		}
		allDokoTags := append(append([]string(nil), dokoTags...), fwdTags...)
		if len(allDokoTags) > 0 {
			outbounds = append(outbounds, buildFreedomOutbound("outbound-dokodemo", mark, ""))
			rules = append([]map[string]any{{
				"type":        "field",
				"inboundTag":  allDokoTags,
				"outboundTag": "outbound-dokodemo",
			}}, rules...)
		}
	}

	switch s.Role {
	case state.RoleClient:
		needed = true
		const clientMark = 255
		// Pre-populate DNS hosts for configured node domains and Rproxy tunnel if resolved at apply time
		hostsMap := make(map[string]any)
		addHostEntry := func(addr string) {
			if ips := opts.ResolvedHostIPs[addr]; len(ips) > 0 {
				var strs []string
				for _, ip := range ips {
					if ip.Is4() || s.System.EnableIPv6 {
						strs = append(strs, ip.String())
					}
				}
				if len(strs) == 1 {
					hostsMap[addr] = strs[0]
				} else if len(strs) > 1 {
					hostsMap[addr] = strs
				}
			}
		}
		for _, n := range s.Client.Nodes {
			addHostEntry(n.Address)
		}
		if s.Client.RproxyC.Enabled && s.Client.RproxyC.TunnelAddress != "" {
			addHostEntry(s.Client.RproxyC.TunnelAddress)
		}
		if len(hostsMap) > 0 {
			dnsCfg["hosts"] = hostsMap
		}

		// Primary TPROXY inbound
		inbounds = append(inbounds, buildTProxyInbound("tproxy-in", "127.0.0.1", clientMark))
		if s.System.EnableIPv6 {
			inbounds = append(inbounds, buildTProxyInbound("tproxy-in-v6", "::1", clientMark))
		}

		// Primary default outbound
		if active := s.Client.ActiveNode(); active != nil {
			outbounds = append(outbounds, buildClientOutbound("default", *active, clientMark))
		} else {
			outbounds = append(outbounds, buildFreedomOutbound("default", clientMark, ""))
		}
		outbounds = append(outbounds,
			buildFreedomOutbound("direct", clientMark, ""),
			map[string]any{
				"tag":      "blocked",
				"protocol": "blackhole",
				"settings": map[string]any{"response": map[string]any{"type": "http"}},
			},
		)

		// Private LAN direct rule
		rules = append(rules, map[string]any{
			"type":        "field",
			"ip":          []string{"geoip:private"},
			"network":     "tcp,udp",
			"outboundTag": "direct",
		})

		// FWD0 inbound (routes into client default/routing pipeline)
		if s.Client.FWD0.Enabled {
			if s.Client.FWD0.EffectiveProtocol() == "vmess-tcp" {
				inbounds = append(inbounds, buildVMessTCPInbound("forward0", s.Client.FWD0.Port, s.Client.FWD0.UUIDs, wildcardListen))
			} else {
				inbounds = append(inbounds, buildXHTTPDirectTLSInbound(
					"forward0", s.Client.FWD0.Port, s.Client.FWD0.UUIDs, s.Client.FWD0.Path, opts.CertFile, opts.KeyFile, wildcardListen,
				))
			}
		}

		// FWD1 inbound + dedicated upstream outbound (always freedom/vless safe with finalRules)
		if s.Client.FWD1.Enabled {
			if s.Client.FWD1.EffectiveProtocol() == "vmess-tcp" {
				inbounds = append(inbounds, buildVMessTCPInbound("forward1", s.Client.FWD1.Port, s.Client.FWD1.UUIDs, wildcardListen))
			} else {
				inbounds = append(inbounds, buildXHTTPDirectTLSInbound(
					"forward1", s.Client.FWD1.Port, s.Client.FWD1.UUIDs, s.Client.FWD1.Path, opts.CertFile, opts.KeyFile, wildcardListen,
				))
			}
			var upNode *state.OutboundNode
			if s.Client.FWD1.UpstreamNodeID != "" {
				upNode = s.Client.FindNode(s.Client.FWD1.UpstreamNodeID)
			}
			if upNode == nil {
				upNode = s.Client.ActiveNode()
			}
			if upNode != nil {
				outbounds = append(outbounds, buildClientOutbound("fwd1-outbound", *upNode, clientMark))
			} else {
				outbounds = append(outbounds, buildFreedomOutbound("fwd1-outbound", clientMark, ""))
			}
			rules = append([]map[string]any{{
				"type":        "field",
				"inboundTag":  []string{"forward1"},
				"outboundTag": "fwd1-outbound",
			}}, rules...)
		}

		// NodeCU custom split routing
		if s.Client.Routing.Custom.Enabled {
			cNode := s.Client.FindNode(s.Client.Routing.Custom.NodeID)
			if cNode == nil {
				cNode = s.Client.ActiveNode()
			}
			if cNode != nil {
				outbounds = append(outbounds, buildClientOutbound("custom", *cNode, clientMark))
				if len(s.Client.Routing.Custom.Domains) > 0 {
					rules = append(rules, map[string]any{
						"type":        "field",
						"domain":      s.Client.Routing.Custom.Domains,
						"network":     "tcp,udp",
						"outboundTag": "custom",
					})
				}
				if len(s.Client.Routing.Custom.IPs) > 0 {
					domainStrategy = "IPIfNonMatch"
					rules = append(rules, map[string]any{
						"type":        "field",
						"ip":          s.Client.Routing.Custom.IPs,
						"network":     "tcp,udp",
						"outboundTag": "custom",
					})
				}
			}
		}

		// NodeSM 16 predefined services
		for _, svc := range state.NodeSMServices {
			nid := s.Client.Routing.ServiceMap[svc]
			if nid == "" {
				continue
			}
			node := s.Client.FindNode(nid)
			if node == nil {
				continue
			}
			tag := "nodeSM" + svc
			outbounds = append(outbounds, buildClientOutbound(tag, *node, clientMark))
			rules = append(rules, map[string]any{
				"type":        "field",
				"domain":      state.NodeSMDomainMap[svc],
				"network":     "tcp,udp",
				"outboundTag": tag,
			})
		}

		// Apple proxy override (when user picked a custom NodeSM node) stays with NodeSM before domain black/white lists;
		// default Apple/Steam direct rules come after domain black/white lists so blacklisted Apple/Steam domains can match default.
		appleProxied := false
		if s.Client.Routing.AppleNodeID != "" {
			if appleNode := s.Client.FindNode(s.Client.Routing.AppleNodeID); appleNode != nil {
				appleProxied = true
				outbounds = append(outbounds, buildClientOutbound("nodeSMapple", *appleNode, clientMark))
				rules = append(rules, map[string]any{
					"type":        "field",
					"domain":      state.AppleDirectDomains,
					"network":     "tcp,udp",
					"outboundTag": "nodeSMapple",
				})
			}
		}

		// DNS WhitelistDomains -> direct, BlacklistDomains -> default (after NodeCU/NodeSM, before default Apple/Steam direct)
		if whiteDomains := normalizeXrayDomainRules(s.Client.DNS.WhitelistDomains); len(whiteDomains) > 0 {
			rules = append(rules, map[string]any{
				"type":        "field",
				"domain":      whiteDomains,
				"network":     "tcp,udp",
				"outboundTag": "direct",
			})
		}
		if blackDomains := normalizeXrayDomainRules(s.Client.DNS.BlacklistDomains); len(blackDomains) > 0 {
			rules = append(rules, map[string]any{
				"type":        "field",
				"domain":      blackDomains,
				"network":     "tcp,udp",
				"outboundTag": "default",
			})
		}

		// Default Apple direct rule when no custom proxy node is selected
		if !appleProxied {
			rules = append(rules, map[string]any{
				"type":        "field",
				"domain":      state.AppleDirectDomains,
				"network":     "tcp,udp",
				"outboundTag": "direct",
			})
		}

		// Steam direct rule unless proxied
		if !s.Client.Routing.SteamProxy {
			rules = append(rules, map[string]any{
				"type":        "field",
				"domain":      state.SteamDirectDomains,
				"network":     "tcp,udp",
				"outboundTag": "direct",
			})
		}

		// NodeDT LAN source IP diversion
		if s.Client.Routing.Divert.Enabled {
			dNode := s.Client.FindNode(s.Client.Routing.Divert.NodeID)
			if dNode == nil {
				dNode = s.Client.ActiveNode()
			}
			var srcs []string
			srcs = append(srcs, s.Client.Routing.Divert.CHNProxyLANIPs...)
			srcs = append(srcs, s.Client.Routing.Divert.GlobalProxyLANIP...)
			if dNode != nil && len(srcs) > 0 {
				outbounds = append(outbounds, buildClientOutbound("divert", *dNode, clientMark))
				rules = append(rules, map[string]any{
					"type":        "field",
					"source":      srcs,
					"network":     "tcp,udp",
					"outboundTag": "divert",
				})
			}
		}

		// RproxyC reverse tunnel converged inside single client Xray
		if s.Client.RproxyC.Enabled {
			tPort := s.Client.RproxyC.TunnelPort
			if tPort <= 0 {
				tPort = 443
			}
			rpcSec := strings.TrimSpace(s.Client.RproxyC.Security)
			if rpcSec == "" {
				rpcSec = "tls"
			}
			rpcStream := map[string]any{
				"network":  "tcp",
				"security": rpcSec,
				"sockopt": map[string]any{
					"mark":        clientMark,
					"tcpFastOpen": true,
					"tcpNoDelay":  true,
				},
			}
			if rpcSec == "tls" {
				sni := strings.TrimSpace(s.Client.RproxyC.ServerName)
				if sni == "" {
					sni = s.Client.RproxyC.TunnelAddress
				}
				tlsCfg := map[string]any{
					"serverName": sni,
				}
				if pcs := strings.TrimSpace(s.Client.RproxyC.PinnedPeerCertSha256); pcs != "" {
					tlsCfg["pinnedPeerCertSha256"] = pcs
				}
				rpcStream["tlsSettings"] = tlsCfg
			}
			outbounds = append(outbounds, map[string]any{
				"tag":      "reverseTunnel",
				"protocol": "vless",
				"settings": map[string]any{
					"address":    s.Client.RproxyC.TunnelAddress,
					"port":       tPort,
					"id":         s.Client.RproxyC.TunnelUUID,
					"encryption": "none",
					"reverse":    map[string]any{"tag": "bridge"},
				},
				"streamSettings": rpcStream,
			})
			var bridgeRules []map[string]any
			for i, m := range s.Client.RproxyC.Mappings {
				mTag := fmt.Sprintf("mapping%d", i)
				outbounds = append(outbounds, buildFreedomOutbound(
					mTag,
					clientMark,
					socks5out.FormatEndpoint(m.IntIP, m.IntPort),
				))
				bridgeRules = append(bridgeRules, map[string]any{
					"type":        "field",
					"inboundTag":  []string{"bridge"},
					"ip":          []string{"127.0.0.1"},
					"port":        strconv.Itoa(m.ExtPort),
					"network":     m.Proto,
					"outboundTag": mTag,
				})
			}
			if s.Client.RproxyC.OutDirect {
				outbounds = append(outbounds, buildFreedomOutbound("directOut", clientMark, ""))
				bridgeRules = append(bridgeRules, map[string]any{
					"type":        "field",
					"inboundTag":  []string{"bridge"},
					"outboundTag": "directOut",
				})
			}
			if len(bridgeRules) > 0 {
				rules = append(bridgeRules, rules...)
			}
		}

		addCommonRelayAndExtra(clientMark)

	case state.RoleServer, state.RoleLanding:
		needed = true
		// Main inbound
		inbounds = append(inbounds, buildMainServerInbound(s, opts))

		// Outbounds: handle Option 35 SOCKS5 outbound global default vs direct
		directOb := serverDirectFreedomOutbound("direct", 0)
		blockedOb := map[string]any{
			"tag":      "blocked",
			"protocol": "blackhole",
			"settings": map[string]any{"response": map[string]any{"type": "http"}},
		}

		var globalDefaultOb map[string]any
		var socksRuleList []map[string]any
		var extraSocksObs []map[string]any
		hasIPRules := false

		for _, prof := range s.Server.Socks5Outbounds {
			if !prof.Enabled {
				continue
			}
			tag := "socks5-exit-" + prof.Name
			if prof.Name == "default" {
				tag = "socks5-exit"
			}
			srv := map[string]any{
				"address": prof.Address,
				"port":    prof.Port,
			}
			if prof.Username != "" {
				srv["users"] = []map[string]any{{
					"user": prof.Username,
					"pass": prof.Password,
				}}
			}
			ob := map[string]any{
				"tag":      tag,
				"protocol": "socks",
				"settings": map[string]any{
					"servers": []map[string]any{srv},
				},
				"streamSettings": map[string]any{
					"sockopt": map[string]any{
						"tcpFastOpen": true,
						"tcpNoDelay":  true,
					},
				},
			}
			if prof.Name == "default" && len(prof.Domains) == 0 && len(prof.IPs) == 0 {
				globalDefaultOb = ob
			} else {
				extraSocksObs = append(extraSocksObs, ob)
			}
			if len(prof.Domains) > 0 {
				socksRuleList = append(socksRuleList, map[string]any{
					"type":        "field",
					"ruleTag":     "socks5-domain-" + prof.Name,
					"domain":      prof.Domains,
					"outboundTag": tag,
				})
			}
			if len(prof.IPs) > 0 {
				hasIPRules = true
				socksRuleList = append(socksRuleList, map[string]any{
					"type":        "field",
					"ruleTag":     "socks5-ip-" + prof.Name,
					"ip":          prof.IPs,
					"outboundTag": tag,
				})
			}
		}

		if globalDefaultOb != nil {
			outbounds = append(outbounds, globalDefaultOb, directOb, blockedOb)
		} else {
			outbounds = append(outbounds, directOb, blockedOb)
		}
		outbounds = append(outbounds, extraSocksObs...)
		rules = append(rules, socksRuleList...)
		if hasIPRules {
			domainStrategy = "IPIfNonMatch"
		}

		addCommonRelayAndExtra(0)

		rules = append(rules,
			map[string]any{
				"type":        "field",
				"ruleTag":     "ssrf-block-private",
				"ip":          xrayPrivateCIDRs,
				"outboundTag": "blocked",
			},
			map[string]any{
				"type":        "field",
				"ruleTag":     "ssrf-block-localhost",
				"domain":      []string{"localhost"},
				"outboundTag": "blocked",
			},
		)

	case state.RoleRelay:
		outbounds = append(outbounds,
			serverDirectFreedomOutbound("direct", 0),
			map[string]any{
				"tag":      "blocked",
				"protocol": "blackhole",
				"settings": map[string]any{"response": map[string]any{"type": "http"}},
			},
		)
		addCommonRelayAndExtra(0)
		needed = len(inbounds) > 0
	}

	if !needed {
		return nil, false, nil
	}

	logLevel := "none"
	if s.Role == state.RoleLanding || s.Role == state.RoleRelay {
		logLevel = "warning"
	}

	bufKB := 512
	if opts.MemMB < 512 {
		bufKB = 64
	}

	cfg := map[string]any{
		"log": map[string]any{
			"access":   "none",
			"error":    "none",
			"loglevel": logLevel,
		},
		"policy": map[string]any{
			"levels": map[string]any{
				"0": map[string]any{
					"handshake":    4,
					"connIdle":     300,
					"uplinkOnly":   2,
					"downlinkOnly": 5,
					"bufferSize":   bufKB,
				},
			},
		},
		"dns": dnsCfg,
		"routing": map[string]any{
			"domainMatcher":  "hybrid",
			"domainStrategy": domainStrategy,
			"rules":          rules,
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
	}

	outBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("marshal xray config: %w", err)
	}
	outBytes = append(outBytes, '\n')
	return outBytes, true, nil
}
