package migrate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/stuinxo/de_GWD/v3/internal/cryptoext"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

func strVal(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case int:
		return strconv.Itoa(x)
	default:
		return ""
	}
}

func intVal(v any, def int) int {
	switch x := v.(type) {
	case float64:
		if int(x) > 0 {
			return int(x)
		}
	case int:
		if x > 0 {
			return x
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func strSliceVal(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, item := range x {
			if s := strVal(item); s != "" && s != "null" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.Fields(x)
	default:
		return nil
	}
}

func splitHostPort(raw string, defPort int) (string, int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", defPort
	}
	if strings.HasPrefix(raw, "[") {
		if end := strings.IndexByte(raw, ']'); end > 0 {
			host := raw[1:end]
			rest := raw[end+1:]
			if strings.HasPrefix(rest, ":") {
				if p, err := strconv.Atoi(rest[1:]); err == nil && p >= 1 && p <= 65535 {
					return host, p
				}
			}
			return host, defPort
		}
	}
	if strings.Count(raw, ":") == 1 {
		host, pStr, _ := strings.Cut(raw, ":")
		if p, err := strconv.Atoi(pStr); err == nil && p >= 1 && p <= 65535 {
			return host, p
		}
		return host, defPort
	}
	return raw, defPort
}

func isEmptyJSONVal(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x) == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	default:
		return false
	}
}

func isVtruiVlessXHTTP(extraDir string) bool {
	if extraDir == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(extraDir, "vtrui", "config.json"))
	if err != nil {
		return false
	}
	var cfg struct {
		Outbounds []struct {
			Protocol       string `json:"protocol"`
			StreamSettings struct {
				Network string `json:"network"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil || len(cfg.Outbounds) == 0 {
		return false
	}
	return strings.EqualFold(cfg.Outbounds[0].Protocol, "vless") &&
		strings.EqualFold(cfg.Outbounds[0].StreamSettings.Network, "xhttp")
}

func inferV2NodeProtoAndPath(rawPath string, vtruiVlessXHTTP bool) (string, string) {
	p := strings.TrimSpace(rawPath)
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if vtruiVlessXHTTP {
		return "vless-xhttp", p
	}
	if p == "" {
		return "vmess-tcp", ""
	}
	return "vmess-ws", p
}

// ImportV2Client converts a v2 /opt/de_GWD/0conf (and optional extra_*.json in extraDir)
// into a validated v3 State along with human-readable migration notes.
func ImportV2Client(confPath, extraDir string) (*state.State, []string, error) {
	raw, err := os.ReadFile(confPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read v2 0conf: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse v2 0conf JSON: %w", err)
	}

	st := state.NewDefaultState(state.RoleClient)
	var notes []string

	// Address & Auth
	if addr, ok := doc["address"].(map[string]any); ok {
		if alias := strVal(addr["alias"]); alias != "" {
			st.System.Hostname = alias
		}
		if p := intVal(addr["webUIport"], 443); p > 0 {
			st.Auth.ListenAddr = fmt.Sprintf(":%d", p)
		}
		if sn := strVal(addr["serverName"]); sn != "" {
			st.Auth.ServerName = sn
		}
		if pwd := strVal(addr["PWD"]); pwd != "" {
			if formatted, err := cryptoext.FormatLegacyV2Hash(pwd); err == nil {
				st.Auth.PasswordHash = formatted
				notes = append(notes, "Imported v2 Web UI password hash (will auto-upgrade to PBKDF2 on first login)")
			} else {
				notes = append(notes, "Skipped invalid legacy password hash in 0conf")
			}
		}
		if lip := strVal(addr["localIP"]); lip != "" {
			if strings.Contains(lip, "/") {
				st.System.LANAddrCIDR = lip
			} else {
				st.System.LANAddrCIDR = lip + "/24"
			}
		}
	}

	vtruiVlessXHTTP := isVtruiVlessXHTTP(extraDir)

	// Nodes: .v2node[]
	domainToNodeID := make(map[string]string)
	if v2nodes, ok := doc["v2node"].([]any); ok {
		for i, item := range v2nodes {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			domRaw := strVal(m["domain"])
			host, port := splitHostPort(domRaw, 443)
			uuid := strVal(m["uuid"])
			if host == "" || uuid == "" {
				continue
			}
			id := fmt.Sprintf("v2node-%d", i+1)
			name := strVal(m["name"])
			if name == "" {
				name = domRaw
			}
			proto, normPath := inferV2NodeProtoAndPath(strVal(m["path"]), vtruiVlessXHTTP)
			node := state.OutboundNode{
				ID:       id,
				Name:     name,
				Protocol: proto,
				Address:  host,
				Port:     port,
				UUID:     uuid,
				TLSSNI:   strVal(m["tls"]),
				Path:     normPath,
			}
			st.Client.Nodes = append(st.Client.Nodes, node)
			domainToNodeID[domRaw] = id
			if _, exists := domainToNodeID[host]; !exists {
				domainToNodeID[host] = id
			}
		}
	}

	resolveNodeID := func(addr string) string {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return ""
		}
		if id, ok := domainToNodeID[addr]; ok {
			return id
		}
		host, _ := splitHostPort(addr, 443)
		return domainToNodeID[host]
	}

	// Active node from .update.v2node
	if upd, ok := doc["update"].(map[string]any); ok {
		if vn, ok := upd["v2node"].(map[string]any); ok {
			dom := strVal(vn["domain"])
			port := intVal(vn["port"], 443)
			if dom != "" {
				cand := dom
				if port != 443 {
					cand = fmt.Sprintf("%s:%d", dom, port)
				}
				if id := resolveNodeID(cand); id != "" {
					st.Client.ActiveNodeID = id
				} else if uuid := strVal(vn["uuid"]); uuid != "" {
					proto, normPath := inferV2NodeProtoAndPath(strVal(vn["path"]), vtruiVlessXHTTP)
					st.Client.Nodes = append([]state.OutboundNode{{
						ID:       "v2node-active",
						Name:     cand,
						Protocol: proto,
						Address:  dom,
						Port:     port,
						UUID:     uuid,
						TLSSNI:   strVal(vn["tls"]),
						Path:     normPath,
					}}, st.Client.Nodes...)
					st.Client.ActiveNodeID = "v2node-active"
				}
			}
		}
	}
	if st.Client.ActiveNodeID == "" && len(st.Client.Nodes) > 0 {
		st.Client.ActiveNodeID = st.Client.Nodes[0].ID
	}

	// v2nodeDIV: ss (Reality), failover, nodeDT, nodeCU, nodeSM
	if div, ok := doc["v2nodeDIV"].(map[string]any); ok {
		if fo, ok := div["failover"].(map[string]any); ok {
			st.Client.FailoverEnabled = strings.EqualFold(strVal(fo["status"]), "on")
		}
		if ss, ok := div["ss"].(map[string]any); ok {
			ssAddr, ssPort := splitHostPort(strVal(ss["ssAddress"]), intVal(ss["ssPort"], 443))
			ssUUID := strVal(ss["ssUUID"])
			ssPBK := strVal(ss["ssPBK"])
			if ssAddr != "" && ssUUID != "" && ssPBK != "" {
				rNode := state.OutboundNode{
					ID:             "reality-legacy",
					Name:           "Reality-" + ssAddr,
					Protocol:       "vless-reality",
					Address:        ssAddr,
					Port:           ssPort,
					UUID:           ssUUID,
					TLSSNI:         strVal(ss["ssSNI"]),
					RealityPubKey:  ssPBK,
					RealityShortID: strVal(ss["ssSID"]),
				}
				st.Client.Nodes = append(st.Client.Nodes, rNode)
				if strings.EqualFold(strVal(ss["status"]), "on") {
					st.Client.ActiveNodeID = rNode.ID
				}
			}
		}
		if dt, ok := div["nodeDT"].(map[string]any); ok {
			st.Client.Routing.Divert = state.DivertConfig{
				Enabled:          strings.EqualFold(strVal(dt["status"]), "on"),
				NodeID:           resolveNodeID(strVal(dt["address"])),
				CHNProxyLANIPs:   strSliceVal(dt["CHNlistProxyIP"]),
				GlobalProxyLANIP: strSliceVal(dt["globalProxyIP"]),
				DirectLANIPs:     strSliceVal(dt["directProxyIP"]),
			}
		}
		if cu, ok := div["nodeCU"].(map[string]any); ok {
			st.Client.Routing.Custom = state.CustomRouteConfig{
				Enabled: strings.EqualFold(strVal(cu["status"]), "on"),
				NodeID:  resolveNodeID(strVal(cu["address"])),
				Domains: strSliceVal(cu["rulesDomain"]),
				IPs:     strSliceVal(cu["rulesIP"]),
			}
		}
		if sm, ok := div["nodeSM"].(map[string]any); ok {
			if !strings.EqualFold(strVal(sm["status"]), "off") {
				for _, svc := range state.NodeSMServices {
					if target := strVal(sm[svc]); target != "" {
						if nid := resolveNodeID(target); nid != "" {
							st.Client.Routing.ServiceMap[svc] = nid
						}
					}
				}
				if appleTarget := strVal(sm["apple"]); appleTarget != "" {
					st.Client.Routing.AppleNodeID = resolveNodeID(appleTarget)
				}
				if strings.EqualFold(strVal(sm["steam"]), "proxy") {
					st.Client.Routing.SteamProxy = true
				}
			}
		}
	}

	// DNS
	if dnsObj, ok := doc["dns"].(map[string]any); ok {
		if ch := strSliceVal(dnsObj["china"]); len(ch) > 0 {
			st.Client.DNS.ChinaServers = ch
		}
		if doh := strSliceVal(dnsObj["doh"]); len(doh) > 0 {
			// Deduplicate legacy repeated [doh1, doh1] and normalize scheme/default /dq path
			seen := make(map[string]struct{})
			var clean []string
			for _, d := range doh {
				d = normalizeDoHURL(d)
				if d == "" {
					continue
				}
				if _, ok := seen[d]; !ok {
					seen[d] = struct{}{}
					clean = append(clean, d)
				}
			}
			st.Client.DNS.DoHServers = clean
		}
		if hosts, ok := dnsObj["hosts"].(map[string]any); ok {
			for k, v := range hosts {
				if ip := strVal(v); k != "" && ip != "" {
					st.Client.DNS.Hosts[k] = ip
				}
			}
		}
		st.Client.DNS.BlacklistDomains = strSliceVal(dnsObj["listB"])
		st.Client.DNS.WhitelistDomains = strSliceVal(dnsObj["listW"])
		if _, hasAds := dnsObj["adlists"]; hasAds {
			st.Client.DNS.BlockAds = true
			notes = append(notes, "Pi-hole/Docker replaced by single-core MosDNS; enabled MosDNS ad-blocking toggle")
		}
		if _, hasXDNS := dnsObj["xDNS"]; hasXDNS {
			notes = append(notes, "Ignored deprecated dns.xDNS section")
		}
		if dog, hasDog := dnsObj["dog"]; hasDog && !isEmptyJSONVal(dog) {
			notes = append(notes, "Ignored deprecated dns.dog (DNS over gRPC is not supported in v3; configure DoH instead)")
		}
	}

	// FORWARD: FWD0, FWD1, Rproxy, ACME CF token, block53, DoGs
	if fwd, ok := doc["FORWARD"].(map[string]any); ok {
		if dom := strVal(fwd["domain"]); dom != "" {
			st.Cert.Domain = dom
		}
		if email := strVal(fwd["email"]); email != "" {
			st.Cert.CFEmail = email
		}
		if tok := strVal(fwd["token"]); tok != "" {
			st.Cert.CFToken = tok
			st.Cert.Mode = "acme"
			st.Cert.AutoRenew = true
		} else if key := strVal(fwd["APIkey"]); key != "" {
			st.Cert.CFToken = key
			st.Cert.Mode = "acme"
		}
		if strings.EqualFold(strVal(fwd["block53"]), "on") {
			st.Client.DNS.BlockExternal53 = true
		}
		if dogs, hasDogs := fwd["DoGs"]; hasDogs && !isEmptyJSONVal(dogs) {
			notes = append(notes, "Ignored deprecated FORWARD.DoGs (DNS over gRPC server is not supported in v3)")
		}
		if f0, ok := fwd["FWD0"].(map[string]any); ok {
			var uuids []string
			if arr, ok := f0["uuid"].([]any); ok {
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						if u := strVal(m["FWD0uuid"]); u != "" {
							uuids = append(uuids, u)
						}
					} else if s := strVal(item); s != "" {
						uuids = append(uuids, s)
					}
				}
			}
			st.Client.FWD0 = state.FWD0Config{
				Enabled:  strings.EqualFold(strVal(f0["status"]), "on"),
				Protocol: "vmess-tcp",
				Port:     intVal(f0["port"], 0),
				Path:     strVal(f0["path"]),
				UUIDs:    uuids,
			}
			if st.Client.FWD0.Enabled {
				notes = append(notes, "Imported FWD0 with legacy vmess-tcp protocol (no TLS)")
			}
			if st.Client.FWD0.Enabled && st.Client.FWD0.Port > 0 && st.Auth.ListenAddr == fmt.Sprintf(":%d", st.Client.FWD0.Port) {
				nextPort := 8443
				if st.Client.FWD0.Port == 8443 {
					nextPort = 8444
				}
				st.Auth.ListenAddr = fmt.Sprintf(":%d", nextPort)
				notes = append(notes, fmt.Sprintf("Shifted Web UI port to :%d to avoid conflict with FWD0 port %d", nextPort, st.Client.FWD0.Port))
			}
		}
		if f1, ok := fwd["FWD1"].(map[string]any); ok {
			var uuids []string
			if arr, ok := f1["uuid"].([]any); ok {
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						if u := strVal(m["FWD1uuid"]); u != "" {
							uuids = append(uuids, u)
						}
					} else if s := strVal(item); s != "" {
						uuids = append(uuids, s)
					}
				}
			}
			st.Client.FWD1 = state.FWD1Config{
				Enabled:        strings.EqualFold(strVal(f1["status"]), "on"),
				Protocol:       "vmess-tcp",
				Port:           intVal(f1["port"], 0),
				Path:           strVal(f1["path"]),
				UUIDs:          uuids,
				UpstreamNodeID: resolveNodeID(strVal(f1["upstream"])),
			}
			if st.Client.FWD1.Enabled {
				notes = append(notes, "Imported FWD1 with legacy vmess-tcp protocol (no TLS)")
			}
		}
		if rp, ok := fwd["Rproxy"].(map[string]any); ok {
			if rc, ok := rp["client"].(map[string]any); ok {
				tun, _ := rc["tunnel"].(map[string]any)
				tAddr, tPort := splitHostPort(strVal(tun["address"]), 443)
				mapStatus := strings.ToLower(strVal(rc["mappingStatus"]))
				var maps []state.RproxyClientMapping
				if mapStatus != "off" {
					if arr, ok := rc["mapping"].([]any); ok {
						for _, item := range arr {
							m, ok := item.(map[string]any)
							if !ok {
								continue
							}
							extP := intVal(m["extPort"], 0)
							intP := intVal(m["intPort"], 0)
							intIP := strVal(m["intIP"])
							if extP <= 0 || intP <= 0 || intIP == "" {
								continue
							}
							maps = append(maps, state.RproxyClientMapping{
								ExtPort: extP,
								Proto:   normalizeProto(strVal(m["extProtocol"])),
								IntIP:   intIP,
								IntPort: intP,
							})
						}
					}
				}
				st.Client.RproxyC = state.RproxyCConfig{
					Enabled:       strings.EqualFold(strVal(rc["status"]), "on"),
					TunnelAddress: tAddr,
					TunnelPort:    tPort,
					TunnelUUID:    strVal(tun["uuid"]),
					OutDirect:     strings.EqualFold(strVal(rc["outStatus"]), "on"),
					Mappings:      maps,
				}
			}
			if rs, ok := rp["server"].(map[string]any); ok {
				tun, _ := rs["tunnel"].(map[string]any)
				lp := intVal(tun["port"], 0)
				tu := strVal(tun["uuid"])
				if lp > 0 && tu != "" {
					var inUUIDs []string
					if !strings.EqualFold(strVal(rs["inStatus"]), "off") {
						if arr, ok := rs["inUUID"].([]any); ok {
							for _, item := range arr {
								if m, ok := item.(map[string]any); ok {
									if u := strVal(m["RproxyS0uuid"]); u != "" {
										inUUIDs = append(inUUIDs, u)
									}
								} else if s := strVal(item); s != "" {
									inUUIDs = append(inUUIDs, s)
								}
							}
						}
					}
					var maps []state.RproxyServerMapping
					if !strings.EqualFold(strVal(rs["mappingStatus"]), "off") {
						if arr, ok := rs["mapping"].([]any); ok {
							for _, item := range arr {
								if m, ok := item.(map[string]any); ok {
									mp := intVal(m["port"], 0)
									if mp > 0 {
										maps = append(maps, state.RproxyServerMapping{
											Port:  mp,
											Proto: normalizeProto(strVal(m["protocol"])),
										})
									}
								}
							}
						}
					}
					st.RproxyS = state.RproxySConfig{
						Enabled:    !strings.EqualFold(strVal(rs["status"]), "off"),
						Domain:     st.Cert.Domain,
						ListenPort: lp,
						UUIDs:      []string{tu},
						InUUIDs:    inUUIDs,
						Mappings:   maps,
					}
				}
			}
		}
	}

	// WireGuard
	if wgObj, ok := doc["wireguard"].(map[string]any); ok {
		srv, _ := wgObj["server"].(map[string]any)
		addr := strVal(srv["WGaddress"])
		port := intVal(srv["WGport"], 51820)
		spriv := strVal(srv["sprivatekey"])
		spub := strVal(srv["spublickey"])
		wgEnabled := !strings.EqualFold(strVal(wgObj["status"]), "off") && !strings.EqualFold(strVal(srv["status"]), "off")
		var peers []state.WGPeer
		seenPeerNames := make(map[string]struct{})
		if arr, ok := wgObj["clients"].([]any); ok {
			for i, item := range arr {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				cp := strVal(m["cprivatekey"])
				cpu := strVal(m["cpublickey"])
				if cp == "" || cpu == "" {
					continue
				}
				pName := sanitizePeerName(strVal(m["mark"]))
				if pName == "" {
					pName = fmt.Sprintf("client%d", i+1)
				}
				baseName := pName
				for suffix := 2; ; suffix++ {
					if _, dup := seenPeerNames[pName]; !dup {
						seenPeerNames[pName] = struct{}{}
						break
					}
					pName = fmt.Sprintf("%s-%d", baseName, suffix)
				}
				peers = append(peers, state.WGPeer{
					Name:       pName,
					IP:         fmt.Sprintf("172.16.66.%d", i+11),
					PrivateKey: cp,
					PublicKey:  cpu,
				})
			}
		}
		if addr != "" && spriv != "" && spub != "" {
			st.Client.WireGuard = state.WireGuardConfig{
				Enabled:          wgEnabled,
				EndpointHost:     addr,
				ListenPort:       port,
				SubnetCIDR:       "172.16.66.1/24",
				ServerPrivateKey: spriv,
				ServerPublicKey:  spub,
				Peers:            peers,
			}
		}
	}

	// Cloudflare DDNS
	if ddnsObj, ok := doc["ddns"].(map[string]any); ok {
		if _, has3322 := ddnsObj["ddns3322"]; has3322 {
			notes = append(notes, "Ignored deprecated ddns.ddns3322 (only Cloudflare DDNS is supported in v3)")
		}
		if cf, ok := ddnsObj["ddnsCF"].(map[string]any); ok {
			dom := strVal(cf["cfDomain"])
			tok := strVal(cf["cfToken"])
			if tok == "" {
				tok = strVal(cf["cfAPIkey"])
			}
			email := strVal(cf["cfEmail"])
			if dom != "" && tok != "" {
				st.Client.DDNS = state.DDNSConfig{
					Enabled:  true,
					Provider: "cloudflare",
					Domain:   dom,
					CFToken:  tok,
					CFEmail:  email,
				}
			}
		}
	}

	if _, hasApp := doc["app"]; hasApp {
		notes = append(notes, "Ignored v2 app section (Jellyfin/Bitwarden/NFS removed in v3)")
	}

	if extraDir != "" {
		extraInbs, exNotes := importExtraInboundsDir(extraDir)
		st.ExtraInbounds = append(st.ExtraInbounds, extraInbs...)
		notes = append(notes, exNotes...)
	}

	return st, notes, nil
}

func normalizeDoHURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		return raw
	}
	if !strings.Contains(raw, "/") {
		return "https://" + raw + "/dq"
	}
	return "https://" + raw
}

func sanitizePeerName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	cleaned := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, raw)
	return strings.Trim(cleaned, "_")
}

func normalizeProto(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "tcp", "udp", "tcp,udp":
		return p
	default:
		return "tcp"
	}
}

func importExtraInboundsDir(dir string) ([]state.ExtraInbound, []string) {
	extraFile := filepath.Join(dir, "extra_inbounds.json")
	b, err := os.ReadFile(extraFile)
	if err != nil {
		return nil, nil
	}
	var rawList []map[string]any
	if err := json.Unmarshal(b, &rawList); err != nil {
		return nil, []string{fmt.Sprintf("Skipped invalid extra_inbounds.json: %v", err)}
	}
	portsMap := readStringIntMap(filepath.Join(dir, "extra_ports.json"))
	domainsMap := readStringMap(filepath.Join(dir, "extra_domains.json"))

	var out []state.ExtraInbound
	for _, inb := range rawList {
		tag := strVal(inb["tag"])
		proto := strVal(inb["protocol"])
		port := intVal(inb["port"], 0)
		if p, ok := portsMap[tag]; ok && p > 0 {
			port = p
		}
		settings, _ := inb["settings"].(map[string]any)
		stream, _ := inb["streamSettings"].(map[string]any)
		netName := strVal(stream["network"])
		sec := strVal(stream["security"])

		ex := state.ExtraInbound{
			Tag:        tag,
			ListenPort: port,
			Domain:     domainsMap[tag],
		}
		switch {
		case proto == "vless" && sec == "reality":
			ex.Protocol = "vless-reality"
			if cl, ok := settings["clients"].([]any); ok && len(cl) > 0 {
				if c0, ok := cl[0].(map[string]any); ok {
					ex.UUID = strVal(c0["id"])
				}
			}
			if rs, ok := stream["realitySettings"].(map[string]any); ok {
				ex.RealityDest = strVal(rs["dest"])
				if sns := strSliceVal(rs["serverNames"]); len(sns) > 0 {
					ex.RealitySNI = sns[0]
				}
				ex.RealityPrivKey = strVal(rs["privateKey"])
				ex.RealityPubKey = strVal(rs["publicKey"])
				if sids := strSliceVal(rs["shortIds"]); len(sids) > 0 {
					ex.RealityShortID = sids[0]
				}
			}
			if ex.RealityPubKey == "" {
				ex.RealityPubKey = readRealityPubKeyFromInfo(filepath.Join(dir, "vtrui", "reality.info"))
			}
			if ex.RealityPubKey == "" && ex.RealityPrivKey != "" {
				if derived, derr := cryptoext.DeriveRealityPublicKey(ex.RealityPrivKey); derr == nil {
					ex.RealityPubKey = derived
				}
			}
		case proto == "vless" && netName == "xhttp":
			ex.Protocol = "vless-xhttp"
			ex.ViaNginx = sec == "none"
			if cl, ok := settings["clients"].([]any); ok && len(cl) > 0 {
				if c0, ok := cl[0].(map[string]any); ok {
					ex.UUID = strVal(c0["id"])
				}
			}
			if xs, ok := stream["xhttpSettings"].(map[string]any); ok {
				ex.Path = strVal(xs["path"])
			}
		case proto == "vless" && netName == "ws":
			ex.Protocol = "vless-ws"
			ex.ViaNginx = sec == "none"
			if cl, ok := settings["clients"].([]any); ok && len(cl) > 0 {
				if c0, ok := cl[0].(map[string]any); ok {
					ex.UUID = strVal(c0["id"])
				}
			}
			if ws, ok := stream["wsSettings"].(map[string]any); ok {
				ex.Path = strVal(ws["path"])
			}
		case proto == "vmess" && netName == "ws":
			ex.Protocol = "vmess-ws"
			ex.ViaNginx = sec == "none"
			if cl, ok := settings["clients"].([]any); ok && len(cl) > 0 {
				if c0, ok := cl[0].(map[string]any); ok {
					ex.UUID = strVal(c0["id"])
				}
			}
			if ws, ok := stream["wsSettings"].(map[string]any); ok {
				ex.Path = strVal(ws["path"])
			}
		case proto == "socks":
			ex.Protocol = "socks5"
			if acc, ok := settings["accounts"].([]any); ok && len(acc) > 0 {
				if a0, ok := acc[0].(map[string]any); ok {
					ex.SocksUser = strVal(a0["user"])
					ex.SocksPass = strVal(a0["pass"])
				}
			}
		case proto == "dokodemo-door":
			ex.Protocol = "dokodemo"
			ex.TargetAddr = strVal(settings["address"])
			ex.TargetPort = intVal(settings["port"], 0)
		default:
			continue
		}
		out = append(out, ex)
	}
	return out, nil
}

func readRealityPubKeyFromInfo(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "PUBKEY="); ok {
			return strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Public key:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func readStringIntMap(path string) map[string]int {
	out := make(map[string]int)
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		for k, v := range m {
			if n := intVal(v, 0); n > 0 {
				out[k] = n
			}
		}
	}
	return out
}

func readStringMap(path string) map[string]string {
	out := make(map[string]string)
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}
