package state

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	uuidRe        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	profileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
	wgKeyRe       = regexp.MustCompile(`^[A-Za-z0-9+/]{42,44}=?$`)
	shortIDRe     = regexp.MustCompile(`^[0-9a-fA-F]{0,16}$`)
	pathRe        = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,128}$`)
	ifaceNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)
)

// Validate checks structural integrity, ports, syntax, self-loops, and cross-references.
func (s *State) Validate() error {
	if s == nil {
		return errors.New("state is nil")
	}
	switch s.Role {
	case RoleClient, RoleServer, RoleLanding, RoleRelay:
	default:
		return fmt.Errorf("unsupported role %q", s.Role)
	}
	if s.Version != 0 && s.Version != CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema version %d (expected %d)", s.Version, CurrentSchemaVersion)
	}

	portOwner := make(map[string]string) // "tcp:443" -> "label"
	claimPort := func(proto string, port int, owner string) error {
		if port < 1 || port > 65535 {
			return fmt.Errorf("%s: invalid port %d", owner, port)
		}
		for _, p := range strings.Split(proto, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			key := fmt.Sprintf("%s:%d", p, port)
			if prev, exists := portOwner[key]; exists {
				return fmt.Errorf("port conflict on %s: used by both %s and %s", key, prev, owner)
			}
			portOwner[key] = owner
		}
		return nil
	}

	if s.Auth.ListenAddr != "" {
		host, portStr, err := net.SplitHostPort(s.Auth.ListenAddr)
		if err != nil || portStr == "" {
			return fmt.Errorf("invalid auth.listen_addr %q", s.Auth.ListenAddr)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid auth.listen_addr %q", s.Auth.ListenAddr)
		}
		if host != "" && host != "localhost" {
			if ip, perr := netip.ParseAddr(host); perr != nil || ip.Zone() != "" {
				return fmt.Errorf("invalid auth.listen_addr %q", s.Auth.ListenAddr)
			}
		}
	}

	if err := validateCleanAbsPath("server.camouflage_dir", s.Server.CamouflageDir); err != nil {
		return err
	}
	if err := validateCleanAbsPath("cert.cert_file", s.Cert.CertFile); err != nil {
		return err
	}
	if err := validateCleanAbsPath("cert.key_file", s.Cert.KeyFile); err != nil {
		return err
	}
	if err := validateNotifyConfig(s.System.Notify); err != nil {
		return err
	}
	if err := validateHostFirewall(s); err != nil {
		return err
	}

	if err := forEachStaticPortClaim(s, false, claimPort); err != nil {
		return err
	}

	// Client-specific checks
	if s.Role == RoleClient {
		nodeIDs := make(map[string]struct{}, len(s.Client.Nodes))
		for i, n := range s.Client.Nodes {
			if n.ID == "" {
				return fmt.Errorf("client.nodes[%d]: empty id", i)
			}
			if _, dup := nodeIDs[n.ID]; dup {
				return fmt.Errorf("client.nodes: duplicate id %q", n.ID)
			}
			nodeIDs[n.ID] = struct{}{}
			if !IsValidAddress(n.Address) {
				return fmt.Errorf("client node %q: invalid address %q", n.ID, n.Address)
			}
			if ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(n.Address), "[]")); err == nil && IsRestrictedPeerIP(ip) {
				return fmt.Errorf("client node %q: restricted IP address %q", n.ID, n.Address)
			}
			if n.Port < 1 || n.Port > 65535 {
				return fmt.Errorf("client node %q: invalid port %d", n.ID, n.Port)
			}
			if err := validateOutboundProtocol("client node", n.ID, n, false); err != nil {
				return err
			}
		}

		if s.Client.ActiveNodeID != "" {
			if _, ok := nodeIDs[s.Client.ActiveNodeID]; !ok {
				return fmt.Errorf("client.active_node_id %q does not exist in client.nodes", s.Client.ActiveNodeID)
			}
		}

		for svc, nid := range s.Client.Routing.ServiceMap {
			if _, ok := NodeSMDomainMap[svc]; !ok {
				return fmt.Errorf("client.routing.service_map: unknown service %q", svc)
			}
			if nid != "" {
				if _, ok := nodeIDs[nid]; !ok {
					return fmt.Errorf("client.routing.service_map[%q]: unknown node %q", svc, nid)
				}
			}
		}
		if s.Client.Routing.AppleNodeID != "" {
			if _, ok := nodeIDs[s.Client.Routing.AppleNodeID]; !ok {
				return fmt.Errorf("client.routing.apple_node_id %q does not exist", s.Client.Routing.AppleNodeID)
			}
		}
		if s.Client.Routing.Divert.Enabled {
			if s.Client.Routing.Divert.NodeID != "" {
				if _, ok := nodeIDs[s.Client.Routing.Divert.NodeID]; !ok {
					return fmt.Errorf("client.routing.divert.node_id %q does not exist", s.Client.Routing.Divert.NodeID)
				}
			}
			for _, list := range [][]string{
				s.Client.Routing.Divert.CHNProxyLANIPs,
				s.Client.Routing.Divert.GlobalProxyLANIP,
				s.Client.Routing.Divert.DirectLANIPs,
			} {
				for _, rule := range list {
					if !IsValidIPRule(rule) {
						return fmt.Errorf("client.routing.divert: invalid IP/CIDR %q", rule)
					}
				}
			}
		}
		if s.Client.Routing.Custom.Enabled {
			if s.Client.Routing.Custom.NodeID != "" {
				if _, ok := nodeIDs[s.Client.Routing.Custom.NodeID]; !ok {
					return fmt.Errorf("client.routing.custom.node_id %q does not exist", s.Client.Routing.Custom.NodeID)
				}
			}
			for _, d := range s.Client.Routing.Custom.Domains {
				if !IsValidDomainRule(d) {
					return fmt.Errorf("client.routing.custom: invalid domain rule %q", d)
				}
			}
			for _, ipr := range s.Client.Routing.Custom.IPs {
				if !IsValidIPRule(ipr) {
					return fmt.Errorf("client.routing.custom: invalid IP rule %q", ipr)
				}
			}
		}

		for dom, ipStr := range s.Client.DNS.Hosts {
			if !isValidHostsKey(dom) {
				return fmt.Errorf("client.dns.hosts: invalid host %q", dom)
			}
			if _, err := netip.ParseAddr(ipStr); err != nil {
				return fmt.Errorf("client.dns.hosts[%q]: invalid IP %q", dom, ipStr)
			}
		}
		for _, r := range append(append([]string(nil), s.Client.DNS.BlacklistIPs...), s.Client.DNS.WhitelistIPs...) {
			if !IsValidIPRule(r) {
				return fmt.Errorf("client.dns IP list: invalid entry %q", r)
			}
		}
		for _, r := range append(append([]string(nil), s.Client.DNS.BlacklistDomains...), s.Client.DNS.WhitelistDomains...) {
			if !IsValidDomainRule(r) {
				return fmt.Errorf("client.dns domain list: invalid entry %q", r)
			}
		}
		if s.Client.DNS.EnableDoHServer || strings.TrimSpace(s.Client.DNS.DoHServerPath) != "" {
			p := s.Client.DNS.EffectiveDoHPath()
			if !pathRe.MatchString(p) {
				return fmt.Errorf("client.dns.doh_server_path: invalid path %q", s.Client.DNS.DoHServerPath)
			}
			if isReservedClientDoHPath(p) {
				return fmt.Errorf("client.dns.doh_server_path: reserved path %q conflicts with Web UI/API", p)
			}
		}

		if s.Client.FWD0.Enabled {
			switch s.Client.FWD0.Protocol {
			case "", "vless-xhttp", "vmess-tcp":
			default:
				return fmt.Errorf("client.fwd0.protocol must be vless-xhttp or vmess-tcp, got %q", s.Client.FWD0.Protocol)
			}
			if s.Client.FWD0.Path != "" && !pathRe.MatchString(s.Client.FWD0.Path) {
				return fmt.Errorf("client.fwd0.path: invalid %q", s.Client.FWD0.Path)
			}
			if len(s.Client.FWD0.UUIDs) == 0 {
				return errors.New("client.fwd0: at least one UUID is required when enabled")
			}
			for _, u := range s.Client.FWD0.UUIDs {
				if !uuidRe.MatchString(u) {
					return fmt.Errorf("client.fwd0: invalid UUID %q", u)
				}
			}
		}
		if s.Client.FWD1.Enabled {
			switch s.Client.FWD1.Protocol {
			case "", "vless-xhttp", "vmess-tcp":
			default:
				return fmt.Errorf("client.fwd1.protocol must be vless-xhttp or vmess-tcp, got %q", s.Client.FWD1.Protocol)
			}
			if s.Client.FWD1.Path != "" && !pathRe.MatchString(s.Client.FWD1.Path) {
				return fmt.Errorf("client.fwd1.path: invalid %q", s.Client.FWD1.Path)
			}
			if len(s.Client.FWD1.UUIDs) == 0 {
				return errors.New("client.fwd1: at least one UUID is required when enabled")
			}
			for _, u := range s.Client.FWD1.UUIDs {
				if !uuidRe.MatchString(u) {
					return fmt.Errorf("client.fwd1: invalid UUID %q", u)
				}
			}
			if s.Client.FWD1.UpstreamNodeID != "" {
				if _, ok := nodeIDs[s.Client.FWD1.UpstreamNodeID]; !ok {
					return fmt.Errorf("client.fwd1.upstream_node_id %q does not exist", s.Client.FWD1.UpstreamNodeID)
				}
			}
		}

		if s.Client.RproxyC.Enabled {
			if !IsValidAddress(s.Client.RproxyC.TunnelAddress) {
				return fmt.Errorf("client.rproxyc.tunnel_address: invalid %q", s.Client.RproxyC.TunnelAddress)
			}
			if ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(s.Client.RproxyC.TunnelAddress), "[]")); err == nil && IsRestrictedPeerIP(ip) {
				return fmt.Errorf("client.rproxyc.tunnel_address: restricted IP address %q", s.Client.RproxyC.TunnelAddress)
			}
			if s.Client.RproxyC.TunnelPort < 1 || s.Client.RproxyC.TunnelPort > 65535 {
				return fmt.Errorf("client.rproxyc.tunnel_port: invalid %d", s.Client.RproxyC.TunnelPort)
			}
			if !uuidRe.MatchString(s.Client.RproxyC.TunnelUUID) {
				return fmt.Errorf("client.rproxyc.tunnel_uuid: invalid %q", s.Client.RproxyC.TunnelUUID)
			}
			switch s.Client.RproxyC.Security {
			case "", "tls", "none":
			default:
				return fmt.Errorf("client.rproxyc.security must be tls or none, got %q", s.Client.RproxyC.Security)
			}
			if s.Client.RproxyC.ServerName != "" && !IsValidAddress(s.Client.RproxyC.ServerName) {
				return fmt.Errorf("client.rproxyc.server_name: invalid %q", s.Client.RproxyC.ServerName)
			}
			if hasControlChar(s.Client.RproxyC.PinnedPeerCertSha256) {
				return errors.New("client.rproxyc.pinned_peer_cert_sha256: invalid control character")
			}
			for i, m := range s.Client.RproxyC.Mappings {
				if m.ExtPort < 1 || m.ExtPort > 65535 || m.IntPort < 1 || m.IntPort > 65535 {
					return fmt.Errorf("client.rproxyc.mappings[%d]: invalid port", i)
				}
				if !isValidNetProto(m.Proto) {
					return fmt.Errorf("client.rproxyc.mappings[%d]: invalid proto %q", i, m.Proto)
				}
				if !IsValidAddress(m.IntIP) {
					return fmt.Errorf("client.rproxyc.mappings[%d]: invalid int_ip %q", i, m.IntIP)
				}
			}
		}

		if s.Client.WireGuard.Enabled {
			if !IsValidAddress(s.Client.WireGuard.EndpointHost) {
				return fmt.Errorf("client.wireguard.endpoint_host: invalid %q", s.Client.WireGuard.EndpointHost)
			}
			if !wgKeyRe.MatchString(s.Client.WireGuard.ServerPrivateKey) || !wgKeyRe.MatchString(s.Client.WireGuard.ServerPublicKey) {
				return errors.New("client.wireguard: invalid server keypair")
			}
			var wgServerAddr netip.Addr
			subRaw := strings.TrimSpace(s.Client.WireGuard.SubnetCIDR)
			if subRaw == "" {
				subRaw = DefaultWGSubnet
			}
			if pfx, err := netip.ParsePrefix(subRaw); err == nil {
				wgServerAddr = pfx.Addr()
			} else if a, err2 := netip.ParseAddr(subRaw); err2 == nil {
				wgServerAddr = a
			}
			srvPub := strings.TrimSpace(s.Client.WireGuard.ServerPublicKey)
			seenPeerNames := make(map[string]struct{}, len(s.Client.WireGuard.Peers))
			seenPeerPubs := make(map[string]struct{}, len(s.Client.WireGuard.Peers))
			seenPeerIPs := make(map[netip.Addr]struct{}, len(s.Client.WireGuard.Peers))
			for i, p := range s.Client.WireGuard.Peers {
				pName := strings.TrimSpace(p.Name)
				if pName == "" {
					return fmt.Errorf("client.wireguard.peers[%d]: empty name", i)
				}
				if _, dup := seenPeerNames[pName]; dup {
					return fmt.Errorf("client.wireguard.peers: duplicate name %q", pName)
				}
				seenPeerNames[pName] = struct{}{}

				if !wgKeyRe.MatchString(p.PrivateKey) || !wgKeyRe.MatchString(p.PublicKey) {
					return fmt.Errorf("client.wireguard.peers[%d]: invalid keypair", i)
				}
				pPub := strings.TrimSpace(p.PublicKey)
				if pPub == srvPub {
					return fmt.Errorf("client.wireguard.peers[%d]: public_key conflicts with server_public_key", i)
				}
				if _, dup := seenPeerPubs[pPub]; dup {
					return fmt.Errorf("client.wireguard.peers[%d]: duplicate public_key", i)
				}
				seenPeerPubs[pPub] = struct{}{}

				var peerAddr netip.Addr
				pIPRaw := strings.TrimSpace(p.IP)
				if pfx, err := netip.ParsePrefix(pIPRaw); err == nil {
					peerAddr = pfx.Addr()
				} else if a, err2 := netip.ParseAddr(pIPRaw); err2 == nil {
					peerAddr = a
				} else {
					return fmt.Errorf("client.wireguard.peers[%d]: invalid ip %q", i, p.IP)
				}
				if wgServerAddr.IsValid() && peerAddr == wgServerAddr {
					return fmt.Errorf("client.wireguard.peers[%d]: ip %q conflicts with server tunnel ip", i, peerAddr.String())
				}
				if _, dup := seenPeerIPs[peerAddr]; dup {
					return fmt.Errorf("client.wireguard.peers[%d]: duplicate ip %q", i, peerAddr.String())
				}
				seenPeerIPs[peerAddr] = struct{}{}
			}
		}

		if s.Client.DDNS.Enabled {
			if !IsValidAddress(s.Client.DDNS.Domain) || !strings.Contains(s.Client.DDNS.Domain, ".") {
				return fmt.Errorf("client.ddns.domain: invalid %q", s.Client.DDNS.Domain)
			}
			if strings.TrimSpace(s.Client.DDNS.CFToken) == "" || hasControlChar(s.Client.DDNS.CFToken) {
				return errors.New("client.ddns.cf_token: invalid or missing")
			}
		}
	}

	// Server / Landing main inbound checks
	if s.Role == RoleServer || s.Role == RoleLanding {
		switch s.Server.Protocol {
		case "", "vless-xhttp", "vmess-ws", "vless-ws":
		default:
			return fmt.Errorf("server.protocol must be vless-xhttp, vmess-ws, or vless-ws, got %q", s.Server.Protocol)
		}
		if s.Server.TLSMode != "direct" && s.Server.TLSMode != "nginx" {
			return fmt.Errorf("server.tls_mode must be direct or nginx, got %q", s.Server.TLSMode)
		}
		if s.Role == RoleLanding && s.Server.TLSMode != "direct" {
			return errors.New("landing role requires server.tls_mode=direct")
		}
		if s.Role == RoleLanding && s.Server.EnableDoH {
			return errors.New("landing role does not deploy DoH server (server.enable_doh must be false)")
		}
		if !IsValidAddress(s.Server.Domain) {
			return fmt.Errorf("server.domain: invalid %q", s.Server.Domain)
		}
		if len(s.Server.UUIDs) == 0 {
			return errors.New("server.uuids: at least one UUID is required")
		}
		for _, u := range s.Server.UUIDs {
			if !uuidRe.MatchString(u) {
				return fmt.Errorf("server.uuids: invalid UUID %q", u)
			}
		}
		if s.Server.Path != "" && !pathRe.MatchString(s.Server.Path) {
			return fmt.Errorf("server.path: invalid %q", s.Server.Path)
		}

		if err := validateServerExits(s); err != nil {
			return err
		}
	}

	// Relay rules (Option 44)
	seenFwdIDs := make(map[string]struct{}, len(s.Relay.Forwards))
	for i, fwd := range s.Relay.Forwards {
		if strings.TrimSpace(fwd.ID) == "" {
			return fmt.Errorf("relay.forwards[%d]: empty id", i)
		}
		if _, dup := seenFwdIDs[fwd.ID]; dup {
			return fmt.Errorf("relay.forwards: duplicate id %q", fwd.ID)
		}
		seenFwdIDs[fwd.ID] = struct{}{}
		if !isValidNetProto(fwd.Proto) {
			return fmt.Errorf("relay.forwards[%d]: invalid proto %q", i, fwd.Proto)
		}
		switch fwd.Engine {
		case "nft", "haproxy", "xray":
		default:
			return fmt.Errorf("relay.forwards[%d]: unsupported engine %q", i, fwd.Engine)
		}
		if fwd.Engine == "haproxy" && fwd.Proto != "tcp" {
			return fmt.Errorf("relay.forwards[%d]: haproxy engine supports tcp only", i)
		}
		if !IsValidAddress(fwd.TargetHost) {
			return fmt.Errorf("relay.forwards[%d]: invalid target_host %q", i, fwd.TargetHost)
		}
		if fwd.TargetPort < 1 || fwd.TargetPort > 65535 {
			return fmt.Errorf("relay.forwards[%d]: invalid target_port %d", i, fwd.TargetPort)
		}
	}

	// RproxyS (Option 22)
	if s.RproxyS.Enabled {
		switch s.RproxyS.Security {
		case "", "tls", "none":
		default:
			return fmt.Errorf("rproxys.security must be tls or none, got %q", s.RproxyS.Security)
		}
		if len(s.RproxyS.UUIDs) == 0 {
			return errors.New("rproxys.uuids: at least one UUID is required")
		}
		rpsUUIDSet := make(map[string]struct{}, len(s.RproxyS.UUIDs))
		for _, u := range s.RproxyS.UUIDs {
			if !uuidRe.MatchString(u) {
				return fmt.Errorf("rproxys.uuids: invalid UUID %q", u)
			}
			rpsUUIDSet[strings.ToLower(strings.TrimSpace(u))] = struct{}{}
		}
		for _, u := range s.RproxyS.InUUIDs {
			if !uuidRe.MatchString(u) {
				return fmt.Errorf("rproxys.in_uuids: invalid UUID %q", u)
			}
		}
		for i, m := range s.RproxyS.Mappings {
			if !isValidNetProto(m.Proto) {
				return fmt.Errorf("rproxys.mappings[%d]: invalid proto %q", i, m.Proto)
			}
			if m.Port == 53 || m.Port == 4711 {
				return fmt.Errorf("rproxys.mappings[%d]: port %d is reserved", i, m.Port)
			}
			if u := strings.TrimSpace(m.UUID); u != "" {
				if !uuidRe.MatchString(u) {
					return fmt.Errorf("rproxys.mappings[%d]: invalid uuid %q", i, m.UUID)
				}
				if _, ok := rpsUUIDSet[strings.ToLower(u)]; !ok {
					return fmt.Errorf("rproxys.mappings[%d]: uuid %q must be listed in rproxys.uuids", i, m.UUID)
				}
			}
		}
	}

	// Extra Inbounds (Option 55)
	extraTags := make(map[string]struct{}, len(s.ExtraInbounds))
	seenViaNginx := make(map[string]string) // "port|lowerDomain" -> tag
	mainNginxPort := 0
	mainNginxDomain := ""
	if (s.Role == RoleServer || s.Role == RoleLanding) && s.Server.TLSMode == "nginx" {
		mainNginxPort = s.Server.ListenPort
		mainNginxDomain = strings.ToLower(strings.TrimSpace(s.Server.Domain))
	}
	for i, ex := range s.ExtraInbounds {
		if ex.Tag == "" {
			return fmt.Errorf("extra_inbounds[%d]: empty tag", i)
		}
		if _, dup := extraTags[ex.Tag]; dup {
			return fmt.Errorf("extra_inbounds: duplicate tag %q", ex.Tag)
		}
		extraTags[ex.Tag] = struct{}{}
		if domTrim := strings.TrimSpace(ex.Domain); domTrim != "" {
			if !IsValidAddress(domTrim) {
				return fmt.Errorf("extra %q: invalid domain %q", ex.Tag, ex.Domain)
			}
		}
		if ex.Protocol == "dokodemo" && ex.Network != "" && !isValidNetProto(ex.Network) {
			return fmt.Errorf("extra %q: invalid network %q", ex.Tag, ex.Network)
		}
		if ex.ViaNginx {
			if s.Role == RoleClient || s.Role == RoleLanding {
				return fmt.Errorf("extra %q: via_nginx is not supported on %s role", ex.Tag, s.Role)
			}
			switch ex.Protocol {
			case "vless-xhttp", "vless-ws", "vmess-ws":
			default:
				return fmt.Errorf("extra %q: via_nginx is only supported for vless-xhttp, vless-ws, or vmess-ws (got %q)", ex.Tag, ex.Protocol)
			}
			if ex.ListenPort < 1 || ex.ListenPort > 65535 {
				return fmt.Errorf("extra_inbounds[%d]: invalid internal port %d", i, ex.ListenPort)
			}
			dom := strings.ToLower(strings.TrimSpace(ex.Domain))
			if dom == "" {
				dom = strings.ToLower(strings.TrimSpace(s.Server.Domain))
			}
			keyTCP := fmt.Sprintf("tcp:%d", ex.ListenPort)
			if owner, used := portOwner[keyTCP]; used {
				if owner != "server-main" || ex.ListenPort != mainNginxPort {
					return fmt.Errorf("port conflict on tcp:%d: used by both %s and extra:%s (via_nginx)", ex.ListenPort, owner, ex.Tag)
				}
			}
			if mainNginxPort > 0 && ex.ListenPort == mainNginxPort && dom == mainNginxDomain {
				return fmt.Errorf("extra %q: via_nginx port %d domain %q conflicts with main nginx server", ex.Tag, ex.ListenPort, dom)
			}
			vnKey := fmt.Sprintf("%d|%s", ex.ListenPort, dom)
			if prevTag, dup := seenViaNginx[vnKey]; dup {
				return fmt.Errorf("extra %q: via_nginx port %d domain %q conflicts with %s", ex.Tag, ex.ListenPort, dom, prevTag)
			}
			seenViaNginx[vnKey] = ex.Tag
		}
		switch ex.Protocol {
		case "vless-reality":
			if !uuidRe.MatchString(ex.UUID) {
				return fmt.Errorf("extra %q: invalid UUID", ex.Tag)
			}
			if ex.RealityPrivKey == "" || ex.RealityDest == "" || ex.RealitySNI == "" {
				return fmt.Errorf("extra %q: reality requires privkey, dest, and sni", ex.Tag)
			}
		case "vless-xhttp", "vless-ws", "vmess-ws":
			if !uuidRe.MatchString(ex.UUID) {
				return fmt.Errorf("extra %q: invalid UUID", ex.Tag)
			}
			if ex.Path != "" && !pathRe.MatchString(ex.Path) {
				return fmt.Errorf("extra %q: invalid path %q", ex.Tag, ex.Path)
			}
		case "socks5":
			if (ex.SocksUser == "") != (ex.SocksPass == "") || hasControlChar(ex.SocksUser) || hasControlChar(ex.SocksPass) {
				return fmt.Errorf("extra %q: invalid socks5 credentials", ex.Tag)
			}
		case "dokodemo":
			if !IsValidAddress(ex.TargetAddr) || ex.TargetPort < 1 || ex.TargetPort > 65535 {
				return fmt.Errorf("extra %q: invalid dokodemo target", ex.Tag)
			}
		default:
			return fmt.Errorf("extra %q: unsupported protocol %q", ex.Tag, ex.Protocol)
		}
	}

	viaNginxPorts := AllocateViaNginxInternalPorts(s)
	for _, ex := range s.ExtraInbounds {
		if !ex.ViaNginx {
			continue
		}
		if err := claimPort("tcp", viaNginxPorts[ex.Tag], "extra-internal:"+ex.Tag); err != nil {
			return err
		}
	}

	return nil
}

func validateHostFirewall(s *State) error {
	fw := s.System.Firewall
	if !fw.Enabled {
		return nil
	}
	if s.Role == RoleClient {
		return errors.New("system.firewall is only supported on server, landing, and relay roles")
	}
	if fw.SSHPort < 0 || fw.SSHPort > 65535 {
		return fmt.Errorf("system.firewall.ssh_port: invalid port %d", fw.SSHPort)
	}
	validIfaces := 0
	for i, iface := range fw.MgmtInterfaces {
		iface = strings.TrimSpace(iface)
		if !ifaceNameRe.MatchString(iface) {
			return fmt.Errorf("system.firewall.mgmt_interfaces[%d]: invalid interface name %q", i, iface)
		}
		validIfaces++
	}
	validSources := 0
	for i, src := range fw.MgmtSources {
		src = strings.TrimSpace(src)
		if _, err := netip.ParsePrefix(src); err != nil {
			if _, err2 := netip.ParseAddr(src); err2 != nil {
				return fmt.Errorf("system.firewall.mgmt_sources[%d]: invalid IP/CIDR %q", i, src)
			}
		}
		validSources++
	}
	if !fw.AllowPublicSSH && validIfaces == 0 && validSources == 0 {
		return errors.New("system.firewall: anti-lockout guard requires allow_public_ssh=true or at least one mgmt_interfaces/mgmt_sources entry")
	}
	return nil
}

func validateServerExits(s *State) error {
	names := make(map[string]struct{}, len(s.Server.Socks5Outbounds)+len(s.Server.UpstreamOutbounds))
	seenDomains := make(map[string]string)
	seenIPs := make(map[string]string)
	hasGlobalDefault := false

	var localSocksPorts []int
	var localDomains []string
	if s.Server.Domain != "" {
		localDomains = append(localDomains, strings.ToLower(s.Server.Domain))
	}
	for _, ex := range s.ExtraInbounds {
		if ex.Protocol == "socks5" || ex.Tag == "inbound-socks5" {
			localSocksPorts = append(localSocksPorts, ex.ListenPort)
			if ex.Domain != "" {
				localDomains = append(localDomains, strings.ToLower(ex.Domain))
			}
		}
	}

	checkSplitRules := func(kind, name string, domains, ips []string) error {
		if name == "default" && len(domains) == 0 && len(ips) == 0 {
			if hasGlobalDefault {
				return fmt.Errorf("%s %q: only one enabled global default exit is allowed across socks5_outbounds and upstream_outbounds", kind, name)
			}
			hasGlobalDefault = true
		}
		if name != "default" && len(domains) == 0 && len(ips) == 0 {
			return fmt.Errorf("%s %q: domain or IP rules are required for non-default exits", kind, name)
		}
		for _, d := range domains {
			if !IsValidDomainRule(d) {
				return fmt.Errorf("%s %q: invalid domain rule %q", kind, name, d)
			}
			if prev, exists := seenDomains[d]; exists {
				return fmt.Errorf("%s: duplicate domain rule %q across enabled profiles (%s, %s)", kind, d, prev, name)
			}
			seenDomains[d] = name
		}
		for _, ipr := range ips {
			if !IsValidIPRule(ipr) {
				return fmt.Errorf("%s %q: invalid IP rule %q", kind, name, ipr)
			}
			if prev, exists := seenIPs[ipr]; exists {
				return fmt.Errorf("%s: duplicate IP rule %q across enabled profiles (%s, %s)", kind, ipr, prev, name)
			}
			seenIPs[ipr] = name
		}
		return nil
	}

	for i, prof := range s.Server.Socks5Outbounds {
		if !profileNameRe.MatchString(prof.Name) {
			return fmt.Errorf("socks5_outbounds[%d]: invalid profile name %q", i, prof.Name)
		}
		if _, dup := names[prof.Name]; dup {
			return fmt.Errorf("socks5_outbounds: duplicate profile name %q", prof.Name)
		}
		names[prof.Name] = struct{}{}

		if !prof.Enabled {
			continue
		}
		if !IsValidAddress(prof.Address) {
			return fmt.Errorf("socks5 profile %q: invalid address %q", prof.Name, prof.Address)
		}
		if prof.Port < 1 || prof.Port > 65535 {
			return fmt.Errorf("socks5 profile %q: invalid port %d", prof.Name, prof.Port)
		}
		if (prof.Username == "") != (prof.Password == "") {
			return fmt.Errorf("socks5 profile %q: username and password must be provided together", prof.Name)
		}
		if hasControlChar(prof.Username) || hasControlChar(prof.Password) {
			return fmt.Errorf("socks5 profile %q: credentials contain control characters", prof.Name)
		}

		// Self-loop guard matching v2 socks5OutboundCheckSelfLoop
		lowerAddr := strings.ToLower(strings.Trim(prof.Address, "[]"))
		for _, lp := range localSocksPorts {
			if lp != prof.Port {
				continue
			}
			if isLoopbackOrZero(lowerAddr) {
				return fmt.Errorf("socks5 profile %q: self-loop detected (%s:%d points to local inbound-socks5)", prof.Name, prof.Address, prof.Port)
			}
			for _, ld := range localDomains {
				if lowerAddr == ld {
					return fmt.Errorf("socks5 profile %q: self-loop detected (%s:%d points to local domain)", prof.Name, prof.Address, prof.Port)
				}
			}
		}

		if err := checkSplitRules("socks5_outbounds", prof.Name, prof.Domains, prof.IPs); err != nil {
			return err
		}
	}

	for i, up := range s.Server.UpstreamOutbounds {
		if !profileNameRe.MatchString(up.Name) {
			return fmt.Errorf("upstream_outbounds[%d]: invalid profile name %q", i, up.Name)
		}
		if _, dup := names[up.Name]; dup {
			return fmt.Errorf("upstream_outbounds: duplicate profile name %q", up.Name)
		}
		names[up.Name] = struct{}{}

		if !up.Enabled {
			continue
		}
		if !IsValidAddress(up.Address) {
			return fmt.Errorf("upstream exit %q: invalid address %q", up.Name, up.Address)
		}
		if up.Port < 1 || up.Port > 65535 {
			return fmt.Errorf("upstream exit %q: invalid port %d", up.Name, up.Port)
		}
		if up.TLSSNI != "" && !IsValidAddress(up.TLSSNI) {
			return fmt.Errorf("upstream exit %q: invalid tls_sni %q", up.Name, up.TLSSNI)
		}

		// Self-loop guard against own server main inbound
		lowerAddr := strings.ToLower(strings.Trim(up.Address, "[]"))
		if up.Port == s.Server.ListenPort {
			if isLoopbackOrZero(lowerAddr) {
				return fmt.Errorf("upstream exit %q: self-loop detected (%s:%d points to local server)", up.Name, up.Address, up.Port)
			}
			for _, ld := range localDomains {
				if lowerAddr == ld {
					return fmt.Errorf("upstream exit %q: self-loop detected (%s:%d points to local domain)", up.Name, up.Address, up.Port)
				}
			}
		}

		if err := validateOutboundProtocol("upstream exit", up.Name, up.ToOutboundNode(), true); err != nil {
			return err
		}

		if err := checkSplitRules("upstream_outbounds", up.Name, up.Domains, up.IPs); err != nil {
			return err
		}
	}
	return nil
}

func validateOutboundProtocol(kind, name string, n OutboundNode, checkCredControl bool) error {
	switch n.Protocol {
	case "vless-xhttp", "vless-ws", "vmess-ws", "vmess-tcp":
		if !uuidRe.MatchString(n.UUID) {
			return fmt.Errorf("%s %q: invalid UUID %q", kind, name, n.UUID)
		}
		if n.Path != "" && !pathRe.MatchString(n.Path) {
			return fmt.Errorf("%s %q: invalid path %q", kind, name, n.Path)
		}
	case "vless-reality":
		if !uuidRe.MatchString(n.UUID) {
			return fmt.Errorf("%s %q: invalid UUID %q", kind, name, n.UUID)
		}
		if strings.TrimSpace(n.RealityPubKey) == "" {
			return fmt.Errorf("%s %q: missing reality_pubkey", kind, name)
		}
		if !shortIDRe.MatchString(n.RealityShortID) || len(n.RealityShortID)%2 != 0 {
			return fmt.Errorf("%s %q: invalid reality_shortid %q", kind, name, n.RealityShortID)
		}
	case "socks5":
		if (n.Username == "") != (n.Password == "") {
			return fmt.Errorf("%s %q: username and password must be set together or both empty", kind, name)
		}
		if checkCredControl && (hasControlChar(n.Username) || hasControlChar(n.Password)) {
			return fmt.Errorf("%s %q: credentials contain control characters", kind, name)
		}
	default:
		return fmt.Errorf("%s %q: unsupported protocol %q", kind, name, n.Protocol)
	}
	return nil
}

func isLoopbackOrZero(lowerAddr string) bool {
	if lowerAddr == "localhost" || strings.HasPrefix(lowerAddr, "localhost.") {
		return true
	}
	ip, err := netip.ParseAddr(lowerAddr)
	if err != nil {
		return false
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

func isValidHostsKey(dom string) bool {
	if dom == "" {
		return false
	}
	if rest, ok := strings.CutPrefix(dom, "domain:"); ok {
		return IsValidAddress(rest)
	}
	if rest, ok := strings.CutPrefix(dom, "full:"); ok {
		return IsValidAddress(rest)
	}
	if rest, ok := strings.CutPrefix(dom, "*."); ok {
		return rest != "" && IsValidAddress(rest)
	}
	return IsValidAddress(dom)
}

func isValidNetProto(proto string) bool {
	return proto == "tcp" || proto == "udp" || proto == "tcp,udp"
}

func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func validateNotifyConfig(cfg NotifyConfig) error {
	wh := strings.TrimSpace(cfg.WebhookURL)
	tgTok := strings.TrimSpace(cfg.TelegramBotToken)
	tgChat := strings.TrimSpace(cfg.TelegramChatID)

	if hasControlChar(wh) {
		return errors.New("system.notify.webhook_url: invalid control character")
	}
	if hasControlChar(tgTok) {
		return errors.New("system.notify.telegram_bot_token: invalid control character")
	}
	if hasControlChar(tgChat) {
		return errors.New("system.notify.telegram_chat_id: invalid control character")
	}
	if wh != "" {
		u, err := url.Parse(wh)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return fmt.Errorf("system.notify.webhook_url: invalid HTTP(S) URL %q", cfg.WebhookURL)
		}
	}
	if (tgTok == "") != (tgChat == "") {
		return errors.New("system.notify: telegram_bot_token and telegram_chat_id must both be set")
	}
	if cfg.Enabled && wh == "" && (tgTok == "" || tgChat == "") {
		return errors.New("system.notify: at least one channel (webhook_url or telegram) is required when enabled")
	}
	return nil
}

func isReservedClientDoHPath(p string) bool {
	switch p {
	case "", "/", "/api", "/index.html", "/app.js", "/style.css", "/favicon.ico":
		return true
	}
	return strings.HasPrefix(p, "/api/")
}

// forEachStaticPortClaim iterates all non-ViaNginx host ports owned by s.
// Both Validate() and AllocateViaNginxInternalPorts() share this single enumeration source.
func forEachStaticPortClaim(s *State, allRolesAuth bool, claim func(proto string, port int, owner string) error) error {
	if s.Auth.ListenAddr != "" {
		if _, portStr, err := net.SplitHostPort(s.Auth.ListenAddr); err == nil {
			if p, perr := strconv.Atoi(portStr); perr == nil && p >= 1 && p <= 65535 {
				if allRolesAuth || s.Role == RoleClient || s.Role == RoleServer {
					if err := claim("tcp", p, "web-ui"); err != nil {
						return err
					}
				}
			}
		}
	}
	switch s.Role {
	case RoleClient:
		if err := claim("tcp,udp", DefaultLocalDNSPort, "mosdns"); err != nil {
			return err
		}
		if err := claim("tcp,udp", DefaultTProxyPort, "xray-tproxy"); err != nil {
			return err
		}
		if s.Client.FWD0.Enabled {
			if err := claim("tcp", s.Client.FWD0.Port, "client.fwd0"); err != nil {
				return err
			}
		}
		if s.Client.FWD1.Enabled {
			if err := claim("tcp", s.Client.FWD1.Port, "client.fwd1"); err != nil {
				return err
			}
		}
		if s.Client.WireGuard.Enabled {
			if err := claim("udp", s.Client.WireGuard.ListenPort, "wireguard"); err != nil {
				return err
			}
		}
	case RoleServer, RoleLanding:
		if err := claim("tcp", s.Server.ListenPort, "server-main"); err != nil {
			return err
		}
		if s.Server.TLSMode == "nginx" {
			if err := claim("tcp", DefaultServerXrayPort, "xray-nginx-upstream"); err != nil {
				return err
			}
			if s.Server.EnableDoH {
				if err := claim("tcp", DefaultServerDoHPort, "dex-doh"); err != nil {
					return err
				}
			}
		}
	}
	for _, fwd := range s.Relay.Forwards {
		proto := fwd.Proto
		if proto == "" {
			proto = "tcp"
		}
		if err := claim(proto, fwd.ListenPort, fmt.Sprintf("relay.forward(%s)", fwd.ID)); err != nil {
			return err
		}
	}
	if s.RproxyS.Enabled {
		if err := claim("tcp", s.RproxyS.ListenPort, "rproxys.tunnel"); err != nil {
			return err
		}
		for _, m := range s.RproxyS.Mappings {
			proto := m.Proto
			if proto == "" {
				proto = "tcp"
			}
			if err := claim(proto, m.Port, fmt.Sprintf("rproxys.mapping:%d", m.Port)); err != nil {
				return err
			}
		}
	}
	for _, ex := range s.ExtraInbounds {
		if ex.ViaNginx {
			continue
		}
		protoNet := "tcp"
		if ex.Protocol == "dokodemo" {
			protoNet = ex.Network
			if protoNet == "" {
				protoNet = "tcp,udp"
			}
		}
		if err := claim(protoNet, ex.ListenPort, "extra:"+ex.Tag); err != nil {
			return err
		}
	}
	return nil
}

// ExtraInternalPort returns the preferred loopback port Xray binds to when an ExtraInbound is fronted by Nginx.
func ExtraInternalPort(listenPort int) int {
	if listenPort+10000 <= 65535 {
		return listenPort + 10000
	}
	return listenPort - 10000
}

// AllocateViaNginxInternalPorts deterministically assigns collision-free loopback ports
// (1024..65535) for all ViaNginx ExtraInbounds keyed by ex.Tag.
func AllocateViaNginxInternalPorts(s *State) map[string]int {
	out := make(map[string]int)
	if s == nil {
		return out
	}

	used := make(map[int]bool)
	_ = forEachStaticPortClaim(s, true, func(proto string, port int, _ string) error {
		if port > 0 && strings.Contains(proto, "tcp") {
			used[port] = true
		}
		return nil
	})

	for _, ex := range s.ExtraInbounds {
		if !ex.ViaNginx {
			continue
		}
		start := ExtraInternalPort(ex.ListenPort)
		if start < 1024 || start > 65535 {
			start = 1024
		}
		chosen := 0
		for p := start; p <= 65535; p++ {
			if !used[p] {
				chosen = p
				break
			}
		}
		if chosen == 0 {
			for p := 1024; p < start; p++ {
				if !used[p] {
					chosen = p
					break
				}
			}
		}
		if chosen == 0 {
			chosen = start
		}
		used[chosen] = true
		out[ex.Tag] = chosen
	}
	return out
}

func validateCleanAbsPath(field, p string) error {
	if p == "" {
		return nil
	}
	if len(p) > 256 {
		return fmt.Errorf("%s: too long (%d > 256)", field, len(p))
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return fmt.Errorf("%s: must be a clean absolute path other than / (got %q)", field, p)
	}
	if hasControlChar(p) || strings.ContainsAny(p, " \t\r\n;{}\"'$\\#") {
		return fmt.Errorf("%s: contains disallowed whitespace or nginx characters (%q)", field, p)
	}
	for _, r := range p {
		if unicode.IsSpace(r) {
			return fmt.Errorf("%s: contains whitespace (%q)", field, p)
		}
	}
	return nil
}
