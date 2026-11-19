package render

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/stuinxo/de_GWD/v3/internal/state"
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

func buildFreedomOutbound(tag string, mark int, redirect string) map[string]any {
	settings := freedomFinalRules()
	if redirect != "" {
		settings["redirect"] = redirect
	}
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

func buildXHTTPDirectTLSInbound(tag string, port int, uuids []string, path, certFile, keyFile string) map[string]any {
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
		"listen":   "0.0.0.0",
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

func buildExtraInbound(ex state.ExtraInbound, certFile, keyFile string) map[string]any {
	sniff := map[string]any{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
		"routeOnly":    true,
	}
	listen := "0.0.0.0"
	bindPort := ex.ListenPort
	if ex.ViaNginx {
		listen = "127.0.0.1"
		bindPort = ExtraInternalPort(ex.ListenPort)
	}

	switch ex.Protocol {
	case "vless-reality":
		return map[string]any{
			"tag":      ex.Tag,
			"listen":   "0.0.0.0",
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
			"listen":   "0.0.0.0",
			"port":     ex.ListenPort,
			"protocol": "socks",
			"settings": settings,
		}
	case "dokodemo":
		return map[string]any{
			"tag":      ex.Tag,
			"listen":   "0.0.0.0",
			"port":     ex.ListenPort,
			"protocol": "dokodemo-door",
			"settings": map[string]any{
				"address": ex.TargetAddr,
				"port":    ex.TargetPort,
				"network": "tcp,udp",
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
	}
	dnsCfg := map[string]any{
		"tag":           "dnsflow",
		"queryStrategy": "UseIP",
		"disableCache":  true,
		"servers":       dnsServers,
	}

	addCommonRelayAndExtra := func(mark int) {
		for _, fwd := range s.Relay.Forwards {
			if fwd.Engine != "xray" {
				continue
			}
			inbounds = append(inbounds, map[string]any{
				"tag":      fmt.Sprintf("fwd-%d", fwd.ListenPort),
				"listen":   "0.0.0.0",
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
			rpsClients := make([]map[string]any, 0, len(s.RproxyS.UUIDs))
			for _, u := range s.RproxyS.UUIDs {
				rpsClients = append(rpsClients, map[string]any{
					"id":      u,
					"reverse": map[string]any{"tag": "portal"},
				})
			}
			inbounds = append(inbounds, map[string]any{
				"tag":      "rps-tunnel",
				"listen":   "0.0.0.0",
				"port":     s.RproxyS.ListenPort,
				"protocol": "vless",
				"settings": map[string]any{
					"decryption": "none",
					"clients":    rpsClients,
				},
				"streamSettings": map[string]any{
					"network":  "tcp",
					"security": "tls",
					"tlsSettings": map[string]any{
						"minVersion": "1.2",
						"certificates": []map[string]any{{
							"certificateFile": opts.CertFile,
							"keyFile":         opts.KeyFile,
						}},
					},
				},
			})
			var rpsTags []string
			for _, m := range s.RproxyS.Mappings {
				tag := fmt.Sprintf("rps-map-%d", m.Port)
				rpsTags = append(rpsTags, tag)
				inbounds = append(inbounds, map[string]any{
					"tag":      tag,
					"listen":   "0.0.0.0",
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
				rules = append(rules, map[string]any{
					"type":        "field",
					"inboundTag":  rpsTags,
					"outboundTag": "portal",
				})
			}
		}

		hasDokodemo := false
		var dokoTags []string
		for _, ex := range s.ExtraInbounds {
			if inb := buildExtraInbound(ex, opts.CertFile, opts.KeyFile); inb != nil {
				inbounds = append(inbounds, inb)
				if ex.Protocol == "dokodemo" {
					hasDokodemo = true
					dokoTags = append(dokoTags, ex.Tag)
				}
			}
		}
		if hasDokodemo {
			outbounds = append(outbounds, buildFreedomOutbound("outbound-dokodemo", mark, ""))
			rules = append([]map[string]any{{
				"type":        "field",
				"inboundTag":  dokoTags,
				"outboundTag": "outbound-dokodemo",
			}}, rules...)
		}
	}

	switch s.Role {
	case state.RoleClient:
		needed = true
		const clientMark = 255
		// Pre-populate DNS hosts for configured node domains if resolved at apply time
		hostsMap := make(map[string]any)
		for _, n := range s.Client.Nodes {
			if ips := opts.ResolvedHostIPs[n.Address]; len(ips) > 0 {
				var strs []string
				for _, ip := range ips {
					if ip.Is4() || s.System.EnableIPv6 {
						strs = append(strs, ip.String())
					}
				}
				if len(strs) == 1 {
					hostsMap[n.Address] = strs[0]
				} else if len(strs) > 1 {
					hostsMap[n.Address] = strs
				}
			}
		}
		if len(hostsMap) > 0 {
			dnsCfg["hosts"] = hostsMap
		}

		// Primary TPROXY inbound
		inbounds = append(inbounds, map[string]any{
			"tag":      "tproxy-in",
			"port":     9896,
			"listen":   "127.0.0.1",
			"protocol": "dokodemo-door",
			"settings": map[string]any{"network": "tcp,udp", "followRedirect": true},
			"streamSettings": map[string]any{
				"sockopt": map[string]any{
					"tproxy":      "tproxy",
					"mark":        clientMark,
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
		})

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
			inbounds = append(inbounds, buildXHTTPDirectTLSInbound(
				"forward0", s.Client.FWD0.Port, s.Client.FWD0.UUIDs, s.Client.FWD0.Path, opts.CertFile, opts.KeyFile,
			))
		}

		// FWD1 inbound + dedicated upstream outbound (always freedom/vless safe with finalRules)
		if s.Client.FWD1.Enabled {
			inbounds = append(inbounds, buildXHTTPDirectTLSInbound(
				"forward1", s.Client.FWD1.Port, s.Client.FWD1.UUIDs, s.Client.FWD1.Path, opts.CertFile, opts.KeyFile,
			))
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

		// Apple rule: custom node if selected, otherwise direct
		if s.Client.Routing.AppleNodeID != "" {
			if appleNode := s.Client.FindNode(s.Client.Routing.AppleNodeID); appleNode != nil {
				outbounds = append(outbounds, buildClientOutbound("nodeSMapple", *appleNode, clientMark))
				rules = append(rules, map[string]any{
					"type":        "field",
					"domain":      state.AppleDirectDomains,
					"network":     "tcp,udp",
					"outboundTag": "nodeSMapple",
				})
			} else {
				rules = append(rules, map[string]any{
					"type":        "field",
					"domain":      state.AppleDirectDomains,
					"network":     "tcp,udp",
					"outboundTag": "direct",
				})
			}
		} else {
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
				"streamSettings": map[string]any{
					"network":  "tcp",
					"security": "tls",
					"tlsSettings": map[string]any{
						"serverName": s.Client.RproxyC.TunnelAddress,
					},
					"sockopt": map[string]any{
						"mark":        clientMark,
						"tcpFastOpen": true,
						"tcpNoDelay":  true,
					},
				},
			})
			for i, m := range s.Client.RproxyC.Mappings {
				mTag := fmt.Sprintf("mapping%d", i)
				outbounds = append(outbounds, buildFreedomOutbound(
					mTag,
					clientMark,
					fmt.Sprintf("%s:%d", m.IntIP, m.IntPort),
				))
				rules = append([]map[string]any{{
					"type":        "field",
					"inboundTag":  []string{"bridge"},
					"port":        strconv.Itoa(m.ExtPort),
					"network":     m.Proto,
					"outboundTag": mTag,
				}}, rules...)
			}
		}

		addCommonRelayAndExtra(clientMark)

	case state.RoleServer, state.RoleLanding:
		needed = true
		// Main inbound
		firstUUID := ""
		if len(s.Server.UUIDs) > 0 {
			firstUUID = s.Server.UUIDs[0]
		}
		if s.Server.TLSMode == "nginx" {
			clients := make([]map[string]any, 0, len(s.Server.UUIDs))
			for _, u := range s.Server.UUIDs {
				clients = append(clients, map[string]any{"id": u})
			}
			inbounds = append(inbounds, map[string]any{
				"tag":      "main",
				"listen":   "127.0.0.1",
				"port":     9890,
				"protocol": "vless",
				"settings": map[string]any{
					"clients":    clients,
					"decryption": "none",
				},
				"streamSettings": map[string]any{
					"network":  "xhttp",
					"security": "none",
					"xhttpSettings": map[string]any{
						"path": NormalizePath(s.Server.Path, firstUUID),
						"mode": "auto",
					},
					"sockopt": map[string]any{
						"tcpFastOpen": true,
						"tcpMptcp":    true,
					},
				},
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"routeOnly":    true,
				},
			})
		} else {
			inbounds = append(inbounds, buildXHTTPDirectTLSInbound(
				"main", s.Server.ListenPort, s.Server.UUIDs, s.Server.Path, opts.CertFile, opts.KeyFile,
			))
		}

		// Outbounds: handle Option 35 SOCKS5 outbound global default vs direct
		directOb := buildFreedomOutbound("direct", 0, "")
		blockedOb := map[string]any{
			"tag":      "blocked",
			"protocol": "blackhole",
			"settings": map[string]any{"response": map[string]any{"type": "http"}},
		}

		var globalDefaultOb map[string]any
		var globalPrivateBypass bool
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
				globalPrivateBypass = prof.PrivateBypass
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
		if globalDefaultOb != nil && globalPrivateBypass {
			rules = append(rules, map[string]any{
				"type":        "field",
				"ruleTag":     "socks5-exit-private-direct",
				"ip":          xrayPrivateCIDRs,
				"outboundTag": "direct",
			})
		}
		if hasIPRules {
			domainStrategy = "IPIfNonMatch"
		}

		addCommonRelayAndExtra(0)

	case state.RoleRelay:
		outbounds = append(outbounds,
			buildFreedomOutbound("direct", 0, ""),
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

	cfg := map[string]any{
		"log": map[string]any{
			"access":   "none",
			"error":    "none",
			"loglevel": logLevel,
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
