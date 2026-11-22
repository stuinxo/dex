package state

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/stuinxo/de_GWD/v3/internal/socks5out"
)

var (
	uuidRe        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	profileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
	wgKeyRe       = regexp.MustCompile(`^[A-Za-z0-9+/]{42,44}=?$`)
	shortIDRe     = regexp.MustCompile(`^[0-9a-fA-F]{0,16}$`)
	pathRe        = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,128}$`)
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
	if s.Version == 0 {
		s.Version = CurrentSchemaVersion
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
		if s.Role == RoleClient || s.Role == RoleServer {
			if err := claimPort("tcp", p, "web-ui"); err != nil {
				return err
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

	// Client-specific checks
	if s.Role == RoleClient {
		if err := claimPort("tcp,udp", 53, "mosdns"); err != nil {
			return err
		}
		if err := claimPort("tcp,udp", 9896, "xray-tproxy"); err != nil {
			return err
		}

		nodeIDs := make(map[string]struct{}, len(s.Client.Nodes))
		for i, n := range s.Client.Nodes {
			if n.ID == "" {
				return fmt.Errorf("client.nodes[%d]: empty id", i)
			}
			if _, dup := nodeIDs[n.ID]; dup {
				return fmt.Errorf("client.nodes: duplicate id %q", n.ID)
			}
			nodeIDs[n.ID] = struct{}{}
			if !socks5out.IsValidAddress(n.Address) {
				return fmt.Errorf("client node %q: invalid address %q", n.ID, n.Address)
			}
			if ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(n.Address), "[]")); err == nil && isRestrictedNodeIP(ip) {
				return fmt.Errorf("client node %q: restricted IP address %q", n.ID, n.Address)
			}
			if n.Port < 1 || n.Port > 65535 {
				return fmt.Errorf("client node %q: invalid port %d", n.ID, n.Port)
			}
			switch n.Protocol {
			case "vless-xhttp", "vless-ws", "vmess-ws":
				if !uuidRe.MatchString(n.UUID) {
					return fmt.Errorf("client node %q: invalid UUID %q", n.ID, n.UUID)
				}
				if n.Path != "" && !pathRe.MatchString(n.Path) {
					return fmt.Errorf("client node %q: invalid path %q", n.ID, n.Path)
				}
			case "vmess-tcp":
				if !uuidRe.MatchString(n.UUID) {
					return fmt.Errorf("client node %q: invalid UUID %q", n.ID, n.UUID)
				}
				if n.Path != "" && !pathRe.MatchString(n.Path) {
					return fmt.Errorf("client node %q: invalid path %q", n.ID, n.Path)
				}
			case "vless-reality":
				if !uuidRe.MatchString(n.UUID) {
					return fmt.Errorf("client node %q: invalid UUID %q", n.ID, n.UUID)
				}
				if strings.TrimSpace(n.RealityPubKey) == "" {
					return fmt.Errorf("client node %q: missing reality_pubkey", n.ID)
				}
				if !shortIDRe.MatchString(n.RealityShortID) || len(n.RealityShortID)%2 != 0 {
					return fmt.Errorf("client node %q: invalid reality_shortid %q", n.ID, n.RealityShortID)
				}
			case "socks5":
				if (n.Username == "") != (n.Password == "") {
					return fmt.Errorf("client node %q: socks5 username and password must both be set or both empty", n.ID)
				}
			default:
				return fmt.Errorf("client node %q: unsupported protocol %q", n.ID, n.Protocol)
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
					if !socks5out.IsValidIPRule(rule) {
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
				if !socks5out.IsValidDomainRule(d) {
					return fmt.Errorf("client.routing.custom: invalid domain rule %q", d)
				}
			}
			for _, ipr := range s.Client.Routing.Custom.IPs {
				if !socks5out.IsValidIPRule(ipr) {
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
			if !socks5out.IsValidIPRule(r) {
				return fmt.Errorf("client.dns IP list: invalid entry %q", r)
			}
		}
		for _, r := range append(append([]string(nil), s.Client.DNS.BlacklistDomains...), s.Client.DNS.WhitelistDomains...) {
			if !socks5out.IsValidDomainRule(r) {
				return fmt.Errorf("client.dns domain list: invalid entry %q", r)
			}
		}

		if s.Client.FWD0.Enabled {
			if err := claimPort("tcp", s.Client.FWD0.Port, "client.fwd0"); err != nil {
				return err
			}
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
			if err := claimPort("tcp", s.Client.FWD1.Port, "client.fwd1"); err != nil {
				return err
			}
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
			if !socks5out.IsValidAddress(s.Client.RproxyC.TunnelAddress) {
				return fmt.Errorf("client.rproxyc.tunnel_address: invalid %q", s.Client.RproxyC.TunnelAddress)
			}
			if ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(s.Client.RproxyC.TunnelAddress), "[]")); err == nil && isRestrictedNodeIP(ip) {
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
			if s.Client.RproxyC.ServerName != "" && !socks5out.IsValidAddress(s.Client.RproxyC.ServerName) {
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
				if !socks5out.IsValidAddress(m.IntIP) {
					return fmt.Errorf("client.rproxyc.mappings[%d]: invalid int_ip %q", i, m.IntIP)
				}
			}
		}

		if s.Client.WireGuard.Enabled {
			if err := claimPort("udp", s.Client.WireGuard.ListenPort, "wireguard"); err != nil {
				return err
			}
			if !socks5out.IsValidAddress(s.Client.WireGuard.EndpointHost) {
				return fmt.Errorf("client.wireguard.endpoint_host: invalid %q", s.Client.WireGuard.EndpointHost)
			}
			if !wgKeyRe.MatchString(s.Client.WireGuard.ServerPrivateKey) || !wgKeyRe.MatchString(s.Client.WireGuard.ServerPublicKey) {
				return errors.New("client.wireguard: invalid server keypair")
			}
			var wgServerAddr netip.Addr
			subRaw := strings.TrimSpace(s.Client.WireGuard.SubnetCIDR)
			if subRaw == "" {
				subRaw = "172.16.66.1/24"
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
			if !socks5out.IsValidAddress(s.Client.DDNS.Domain) || !strings.Contains(s.Client.DDNS.Domain, ".") {
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
		if !socks5out.IsValidAddress(s.Server.Domain) {
			return fmt.Errorf("server.domain: invalid %q", s.Server.Domain)
		}
		if err := claimPort("tcp", s.Server.ListenPort, "server-main"); err != nil {
			return err
		}
		if s.Server.TLSMode == "nginx" {
			if err := claimPort("tcp", 9890, "xray-nginx-upstream"); err != nil {
				return err
			}
			if s.Server.EnableDoH {
				if err := claimPort("tcp", 9853, "dex-doh"); err != nil {
					return err
				}
			}
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

		if err := validateSocks5Outbounds(s); err != nil {
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
		if err := claimPort(fwd.Proto, fwd.ListenPort, fmt.Sprintf("relay.forward(%s)", fwd.ID)); err != nil {
			return err
		}
		if !socks5out.IsValidAddress(fwd.TargetHost) {
			return fmt.Errorf("relay.forwards[%d]: invalid target_host %q", i, fwd.TargetHost)
		}
		if fwd.TargetPort < 1 || fwd.TargetPort > 65535 {
			return fmt.Errorf("relay.forwards[%d]: invalid target_port %d", i, fwd.TargetPort)
		}
	}

	// RproxyS (Option 22)
	if s.RproxyS.Enabled {
		if err := claimPort("tcp", s.RproxyS.ListenPort, "rproxys.tunnel"); err != nil {
			return err
		}
		switch s.RproxyS.Security {
		case "", "tls", "none":
		default:
			return fmt.Errorf("rproxys.security must be tls or none, got %q", s.RproxyS.Security)
		}
		if len(s.RproxyS.UUIDs) == 0 {
			return errors.New("rproxys.uuids: at least one UUID is required")
		}
		for _, u := range s.RproxyS.UUIDs {
			if !uuidRe.MatchString(u) {
				return fmt.Errorf("rproxys.uuids: invalid UUID %q", u)
			}
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
			if err := claimPort(m.Proto, m.Port, fmt.Sprintf("rproxys.mapping:%d", m.Port)); err != nil {
				return err
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
			if !socks5out.IsValidAddress(domTrim) {
				return fmt.Errorf("extra %q: invalid domain %q", ex.Tag, ex.Domain)
			}
		}
		protoNet := "tcp"
		if ex.Protocol == "dokodemo" {
			if ex.Network != "" && !isValidNetProto(ex.Network) {
				return fmt.Errorf("extra %q: invalid network %q", ex.Tag, ex.Network)
			}
			protoNet = ex.Network
			if protoNet == "" {
				protoNet = "tcp,udp"
			}
		}
		if !ex.ViaNginx {
			if err := claimPort(protoNet, ex.ListenPort, "extra:"+ex.Tag); err != nil {
				return err
			}
		} else {
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
			if !socks5out.IsValidAddress(ex.TargetAddr) || ex.TargetPort < 1 || ex.TargetPort > 65535 {
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

func validateSocks5Outbounds(s *State) error {
	names := make(map[string]struct{}, len(s.Server.Socks5Outbounds))
	seenDomains := make(map[string]string)
	seenIPs := make(map[string]string)

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
		if !socks5out.IsValidAddress(prof.Address) {
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

		if prof.Name != "default" && len(prof.Domains) == 0 && len(prof.IPs) == 0 {
			return fmt.Errorf("socks5 profile %q: domain or IP rules are required for non-default exits", prof.Name)
		}
		for _, d := range prof.Domains {
			if !socks5out.IsValidDomainRule(d) {
				return fmt.Errorf("socks5 profile %q: invalid domain rule %q", prof.Name, d)
			}
			if prev, exists := seenDomains[d]; exists {
				return fmt.Errorf("socks5_outbounds: duplicate domain rule %q across enabled profiles (%s, %s)", d, prev, prof.Name)
			}
			seenDomains[d] = prof.Name
		}
		for _, ipr := range prof.IPs {
			if !socks5out.IsValidIPRule(ipr) {
				return fmt.Errorf("socks5 profile %q: invalid IP rule %q", prof.Name, ipr)
			}
			if prev, exists := seenIPs[ipr]; exists {
				return fmt.Errorf("socks5_outbounds: duplicate IP rule %q across enabled profiles (%s, %s)", ipr, prev, prof.Name)
			}
			seenIPs[ipr] = prof.Name
		}
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
		return socks5out.IsValidAddress(rest)
	}
	if rest, ok := strings.CutPrefix(dom, "full:"); ok {
		return socks5out.IsValidAddress(rest)
	}
	if rest, ok := strings.CutPrefix(dom, "*."); ok {
		return rest != "" && socks5out.IsValidAddress(rest)
	}
	return socks5out.IsValidAddress(dom)
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

func isRestrictedNodeIP(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast()
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
	if s.Auth.ListenAddr != "" {
		if _, portStr, err := net.SplitHostPort(s.Auth.ListenAddr); err == nil {
			if p, perr := strconv.Atoi(portStr); perr == nil && p >= 1 && p <= 65535 {
				used[p] = true
			}
		}
	}
	switch s.Role {
	case RoleClient:
		used[53] = true
		used[9896] = true
		if s.Client.FWD0.Enabled && s.Client.FWD0.Port > 0 {
			used[s.Client.FWD0.Port] = true
		}
		if s.Client.FWD1.Enabled && s.Client.FWD1.Port > 0 {
			used[s.Client.FWD1.Port] = true
		}
	case RoleServer, RoleLanding:
		if s.Server.ListenPort > 0 {
			used[s.Server.ListenPort] = true
		}
		if s.Server.TLSMode == "nginx" {
			used[9890] = true
			if s.Server.EnableDoH {
				used[9853] = true
			}
		}
	}
	for _, fwd := range s.Relay.Forwards {
		if fwd.ListenPort > 0 && strings.Contains(fwd.Proto, "tcp") {
			used[fwd.ListenPort] = true
		}
	}
	if s.RproxyS.Enabled {
		if s.RproxyS.ListenPort > 0 {
			used[s.RproxyS.ListenPort] = true
		}
		for _, m := range s.RproxyS.Mappings {
			if m.Port > 0 && strings.Contains(m.Proto, "tcp") {
				used[m.Port] = true
			}
		}
	}
	for _, ex := range s.ExtraInbounds {
		if ex.ViaNginx || ex.ListenPort <= 0 {
			continue
		}
		if ex.Protocol != "dokodemo" || ex.Network == "" || strings.Contains(ex.Network, "tcp") {
			used[ex.ListenPort] = true
		}
	}

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
