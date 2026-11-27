package render

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/socks5out"
	"github.com/stuinxo/dex/internal/state"
)

// RenderOptions supplies environment and runtime-resolved inputs to pure renderers.
type RenderOptions struct {
	StateDir           string
	GeneratedDir       string
	CertFile           string
	KeyFile            string
	XrayBin            string
	MosDNSBin          string
	DexBin             string
	InitSystem         string // systemd | openrc
	IsContainer        bool
	MemMB              int
	ResolvedHostIPs    map[string][]netip.Addr
	PhysicalNICs       []string
	ChnRoutePath       string
	DomainsChnPath     string
	DomainsGamesPath   string
	DomainsApplePath   string
	DomainsAppleExists bool
	DomainsGamesExists bool
	NginxLegacyHTTP2   bool
	ChnRouteCIDRs      []string
}

// WithDefaults fills omitted path/runtime defaults in RenderOptions.
func (o RenderOptions) WithDefaults() RenderOptions {
	if o.StateDir == "" {
		o.StateDir = "/etc/dex"
	}
	if o.GeneratedDir == "" {
		o.GeneratedDir = filepath.Join(o.StateDir, "generated")
	}
	if o.CertFile == "" {
		o.CertFile = filepath.Join(o.StateDir, "ssl", "dex.cer")
	}
	if o.KeyFile == "" {
		o.KeyFile = filepath.Join(o.StateDir, "ssl", "dex.key")
	}
	if o.XrayBin == "" {
		o.XrayBin = "/usr/local/bin/xray"
	}
	if o.MosDNSBin == "" {
		o.MosDNSBin = "/usr/local/bin/mosdns"
	}
	if o.DexBin == "" {
		o.DexBin = "/usr/local/bin/dex"
	}
	if o.InitSystem == "" {
		o.InitSystem = "systemd"
	}
	if o.MemMB <= 0 {
		o.MemMB = 512
	}
	if o.ChnRoutePath == "" {
		o.ChnRoutePath = filepath.Join(o.StateDir, "rules", "IPchnroute")
	}
	if o.DomainsChnPath == "" {
		o.DomainsChnPath = filepath.Join(o.StateDir, "rules", "Domains.chn.txt")
	}
	if o.DomainsGamesPath == "" {
		o.DomainsGamesPath = filepath.Join(o.StateDir, "rules", "Domains.games.txt")
	}
	if o.DomainsApplePath == "" {
		o.DomainsApplePath = filepath.Join(o.StateDir, "rules", "Domains.apple.txt")
	}
	return o
}

// GoMemLimit computes GOMEMLIMIT string: clamp(MemMB*35/100, 24, 1024) + "MiB".
func (o RenderOptions) GoMemLimit() string {
	g := o.MemMB * 35 / 100
	if g < 24 {
		g = 24
	}
	if g > 1024 {
		g = 1024
	}
	return fmt.Sprintf("%dMiB", g)
}

// RenderedFile represents one declaratively generated target file.
type RenderedFile struct {
	RelName      string
	TargetPath   string
	Content      []byte
	Mode         os.FileMode
	ValidateKind string // xray | nft | haproxy | nginx | json | yaml | ""
}

// RenderBundle holds all rendered files and active subsystem flags for reconciliation.
type RenderBundle struct {
	Files                 []RenderedFile
	XrayNeeded            bool
	NFTClientNeeded       bool
	NFTRelayNeeded        bool
	NFTHostFWNeeded       bool
	MosDNSNeeded          bool
	HAProxyNeeded         bool
	NginxNeeded           bool
	DoHNeeded             bool
	WireGuardNeeded       bool
	DaemonNeeded          bool
	RulesTimerNeeded      bool
	RefreshTimerNeeded    bool
	RefreshInterval       string // "5min" | "4h"
	CoreUpdateTimerNeeded bool
}

// ExtractDoHHost extracts a hostname or IP from a DoH endpoint (with or without scheme).
func ExtractDoHHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return ""
}

// NormalizeDoHUpstream normalizes a bare DoH domain/path while preserving explicit schemes (https/quic/h3/tls/tcp/udp).
func NormalizeDoHUpstream(raw string) string {
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

// ExtractDomainHost strips domain:/full:/*. prefixes from a routing domain rule and returns a resolvable host if valid.
func ExtractDomainHost(rule string) string {
	r := strings.TrimSpace(rule)
	if r == "" {
		return ""
	}
	for _, skip := range []string{"regexp:", "keyword:", "geosite:", "ext:"} {
		if strings.HasPrefix(r, skip) {
			return ""
		}
	}
	r = strings.TrimPrefix(r, "domain:")
	r = strings.TrimPrefix(r, "full:")
	r = strings.TrimPrefix(r, "*.")
	r = strings.Trim(r, "[]")
	if socks5out.IsValidAddress(r) {
		return r
	}
	return ""
}

// NormalizePath ensures path starts with "/" and defaults from UUID if empty.
func NormalizePath(path, uuid string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		p = cryptoext.UUIDToDefaultPath(uuid)
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// ExtraInternalPort returns the loopback port Xray binds to when an ExtraInbound is fronted by Nginx.
func ExtraInternalPort(listenPort int) int {
	return state.ExtraInternalPort(listenPort)
}

// AllocateViaNginxInternalPorts deterministically assigns collision-free loopback ports
// for all ViaNginx ExtraInbounds keyed by ex.Tag.
func AllocateViaNginxInternalPorts(s *state.State) map[string]int {
	return state.AllocateViaNginxInternalPorts(s)
}

// BuildNodeURI formats a standard client share URI for an OutboundNode.
func BuildNodeURI(n state.OutboundNode) string {
	host := n.Address
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	port := n.Port
	if port <= 0 {
		port = 443
	}
	label := n.Name
	if label == "" {
		label = fmt.Sprintf("%s:%d", host, port)
	}
	sni := n.EffectiveSNI()

	switch n.Protocol {
	case "vless-xhttp":
		path := NormalizePath(n.Path, n.UUID)
		return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=xhttp&path=%s&mode=packet-up#%s",
			url.PathEscape(n.UUID), host, port,
			url.QueryEscape(sni), url.QueryEscape(path), url.PathEscape(label))
	case "vless-ws":
		path := NormalizePath(n.Path, n.UUID)
		return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&type=ws&host=%s&sni=%s&path=%s#%s",
			url.PathEscape(n.UUID), host, port,
			url.QueryEscape(sni), url.QueryEscape(sni), url.QueryEscape(path), url.PathEscape(label))
	case "vless-reality":
		return fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s",
			url.PathEscape(n.UUID), host, port,
			url.QueryEscape(sni), url.QueryEscape(n.RealityPubKey), url.QueryEscape(n.RealityShortID), url.PathEscape(label))
	case "vmess-ws":
		path := NormalizePath(n.Path, n.UUID)
		payload := map[string]any{
			"v":    "2",
			"ps":   label,
			"add":  n.Address,
			"port": port,
			"id":   n.UUID,
			"aid":  0,
			"scy":  "auto",
			"net":  "ws",
			"type": "none",
			"host": sni,
			"path": path,
			"tls":  "tls",
			"sni":  sni,
		}
		b, _ := json.Marshal(payload)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "vmess-tcp":
		payload := map[string]any{
			"v":    "2",
			"ps":   label,
			"add":  n.Address,
			"port": port,
			"id":   n.UUID,
			"aid":  0,
			"scy":  "auto",
			"net":  "tcp",
			"type": "none",
			"host": "",
			"path": "",
			"tls":  "",
		}
		b, _ := json.Marshal(payload)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "socks5":
		if n.Username != "" {
			return fmt.Sprintf("socks5://%s@%s:%d#%s",
				url.UserPassword(n.Username, n.Password).String(), host, port, url.PathEscape(label))
		}
		return fmt.Sprintf("socks5://%s:%d#%s", host, port, url.PathEscape(label))
	default:
		return ""
	}
}

// BuildServerMainURI returns the primary share URI for server or landing roles.
func BuildServerMainURI(s *state.State) string {
	if s == nil || len(s.Server.UUIDs) == 0 {
		return ""
	}
	uuid := s.Server.UUIDs[0]
	return BuildNodeURI(state.OutboundNode{
		Name:     fmt.Sprintf("%s:%d", s.Server.EffectiveConnectHost(), s.Server.EffectivePublicPort()),
		Protocol: s.Server.EffectiveProtocol(),
		Address:  s.Server.EffectiveConnectHost(),
		Port:     s.Server.EffectivePublicPort(),
		UUID:     uuid,
		TLSSNI:   s.Server.Domain,
		Path:     NormalizePath(s.Server.Path, uuid),
	})
}

func formatHTTPSAuthority(rawHost string, port int) string {
	h := strings.Trim(strings.TrimSpace(rawHost), "[]")
	if h == "" {
		h = "localhost"
	}
	if ip, err := netip.ParseAddr(h); err == nil && ip.Is6() {
		h = "[" + ip.String() + "]"
	}
	if port <= 0 || port == 443 {
		return h
	}
	return fmt.Sprintf("%s:%d", h, port)
}

// BuildDoHURL returns the external RFC 8484 DoH endpoint URL when enabled for server or client roles,
// and always returns "" for landing and relay roles.
func BuildDoHURL(s *state.State, fallbackHost string) string {
	if s == nil {
		return ""
	}
	switch s.Role {
	case state.RoleServer:
		if s.Server.TLSMode != "nginx" || !s.Server.EnableDoH {
			return ""
		}
		host := ""
		for _, cand := range []string{s.Server.Domain, s.Server.EffectiveConnectHost(), fallbackHost, "localhost"} {
			if strings.TrimSpace(cand) != "" {
				host = strings.TrimSpace(cand)
				break
			}
		}
		return "https://" + formatHTTPSAuthority(host, s.Server.EffectivePublicPort()) + "/dq"

	case state.RoleClient:
		if !s.Client.DNS.EnableDoHServer {
			return ""
		}
		listenHost := ""
		listenPort := 443
		if strings.TrimSpace(s.Auth.ListenAddr) != "" {
			if h, pStr, err := net.SplitHostPort(strings.TrimSpace(s.Auth.ListenAddr)); err == nil {
				if p, perr := strconv.Atoi(pStr); perr == nil && p >= 1 && p <= 65535 {
					listenPort = p
				}
				hTrim := strings.Trim(strings.TrimSpace(h), "[]")
				if hTrim != "" && hTrim != "0.0.0.0" && hTrim != "::" {
					listenHost = hTrim
				}
			}
		}
		lanIP := ""
		if strings.TrimSpace(s.System.LANAddrCIDR) != "" {
			if p, err := netip.ParsePrefix(strings.TrimSpace(s.System.LANAddrCIDR)); err == nil {
				lanIP = p.Addr().String()
			}
		}
		serverName := strings.TrimSpace(s.Auth.ServerName)
		if serverName == "dex" {
			serverName = ""
		}
		host := ""
		for _, cand := range []string{
			s.Cert.Domain,
			s.Client.DDNS.Domain,
			s.Client.WireGuard.EndpointHost,
			serverName,
			listenHost,
			lanIP,
			fallbackHost,
			"localhost",
		} {
			if strings.TrimSpace(cand) != "" {
				host = strings.TrimSpace(cand)
				break
			}
		}
		return "https://" + formatHTTPSAuthority(host, listenPort) + s.Client.DNS.EffectiveDoHPath()

	default:
		return ""
	}
}

func shellSingleQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'"
}

// DeriveServerDoHFromNode derives a default self-hosted Server DoH URL ("https://<host>[:port]/dq")
// from an OutboundNode when the node uses a TLS-terminated server protocol (vless-xhttp, vless-ws, vmess-ws).
// Returns "" for vless-reality and socks5.
func DeriveServerDoHFromNode(n state.OutboundNode) string {
	switch n.Protocol {
	case "vless-xhttp", "vless-ws", "vmess-ws":
	default:
		return ""
	}
	host := strings.TrimSpace(n.EffectiveSNI())
	if host == "" {
		host = strings.TrimSpace(n.Address)
	}
	if host == "" {
		return ""
	}
	return "https://" + formatHTTPSAuthority(host, n.Port) + "/dq"
}

// BuildClientBootstrapCommand returns the one-line client install command pre-populated
// with this server's primary node URI (Client auto-derives https://<sni>[:port]/dq when Server DoH is enabled).
func BuildClientBootstrapCommand(s *state.State, fallbackHost string) string {
	if s == nil || (s.Role != state.RoleServer && s.Role != state.RoleLanding) {
		return ""
	}
	mainURI := BuildServerMainURI(s)
	if mainURI == "" {
		return ""
	}
	if dohURL := BuildDoHURL(s, fallbackHost); dohURL != "" {
		if parsed, err := ParseNodeURI(mainURI); err == nil && DeriveServerDoHFromNode(parsed) == dohURL {
			return fmt.Sprintf("curl -Lso- dex.stuinx.net | sh -s -- -c %s", shellSingleQuote(mainURI))
		}
		return fmt.Sprintf("curl -Lso- dex.stuinx.net | sh -s -- -c %s --doh %s",
			shellSingleQuote(mainURI), shellSingleQuote(dohURL))
	}
	return fmt.Sprintf("curl -Lso- dex.stuinx.net | sh -s -- -c %s --doh '<自建DoH地址>'",
		shellSingleQuote(mainURI))
}

// BuildClientInitCommand returns the 'dex -c ...' command for an already-installed client binary
// (top-level '-c' automatically applies configuration on the host).
func BuildClientInitCommand(s *state.State, fallbackHost string) string {
	if s == nil || (s.Role != state.RoleServer && s.Role != state.RoleLanding) {
		return ""
	}
	mainURI := BuildServerMainURI(s)
	if mainURI == "" {
		return ""
	}
	if dohURL := BuildDoHURL(s, fallbackHost); dohURL != "" {
		if parsed, err := ParseNodeURI(mainURI); err == nil && DeriveServerDoHFromNode(parsed) == dohURL {
			return fmt.Sprintf("dex -c %s", shellSingleQuote(mainURI))
		}
		return fmt.Sprintf("dex -c %s --doh %s",
			shellSingleQuote(mainURI), shellSingleQuote(dohURL))
	}
	return fmt.Sprintf("dex -c %s --doh '<自建DoH地址>'",
		shellSingleQuote(mainURI))
}

// BuildFWDURI returns a client share URI for FWD0 ("fwd0") or FWD1 ("fwd1").
func BuildFWDURI(s *state.State, fwdKind, uuid string) string {
	if s == nil {
		return ""
	}
	var (
		port  int
		path  string
		proto string
		uuids []string
	)
	switch strings.ToLower(strings.TrimSpace(fwdKind)) {
	case "fwd0":
		port = s.Client.FWD0.Port
		path = s.Client.FWD0.Path
		proto = s.Client.FWD0.EffectiveProtocol()
		uuids = s.Client.FWD0.UUIDs
	case "fwd1":
		port = s.Client.FWD1.Port
		path = s.Client.FWD1.Path
		proto = s.Client.FWD1.EffectiveProtocol()
		uuids = s.Client.FWD1.UUIDs
	default:
		return ""
	}
	if uuid == "" && len(uuids) > 0 {
		uuid = uuids[0]
	}
	if uuid == "" || port <= 0 {
		return ""
	}
	host := ""
	for _, cand := range []string{s.Cert.Domain, s.Client.DDNS.Domain, s.Client.WireGuard.EndpointHost} {
		if strings.TrimSpace(cand) != "" {
			host = strings.TrimSpace(cand)
			break
		}
	}
	if host == "" && strings.TrimSpace(s.Auth.ServerName) != "" && strings.TrimSpace(s.Auth.ServerName) != "dex" {
		host = strings.TrimSpace(s.Auth.ServerName)
	}
	if host == "" && strings.TrimSpace(s.System.LANAddrCIDR) != "" {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s.System.LANAddrCIDR)); err == nil {
			host = p.Addr().String()
		}
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return BuildNodeURI(state.OutboundNode{
		Name:     fmt.Sprintf("%s-%s:%d", strings.ToLower(strings.TrimSpace(fwdKind)), host, port),
		Protocol: proto,
		Address:  host,
		Port:     port,
		UUID:     uuid,
		TLSSNI:   host,
		Path:     path,
	})
}

// ParseNodeURI parses a standard vless://, vmess://, or socks5:// share link into an OutboundNode.
func ParseNodeURI(raw string) (state.OutboundNode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return state.OutboundNode{}, errors.New("empty node URI")
	}
	idHex, _ := cryptoext.GenerateHexToken(4)
	genID := "node-" + idHex

	if strings.HasPrefix(strings.ToLower(raw), "vmess://") {
		payloadB64 := strings.TrimSpace(raw[len("vmess://"):])
		var decoded []byte
		var decErr error
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			if b, err := enc.DecodeString(payloadB64); err == nil {
				decoded = b
				decErr = nil
				break
			} else {
				decErr = err
			}
		}
		if decErr != nil {
			return state.OutboundNode{}, fmt.Errorf("invalid vmess base64: %w", decErr)
		}
		var m map[string]any
		if err := json.Unmarshal(decoded, &m); err != nil {
			return state.OutboundNode{}, fmt.Errorf("invalid vmess JSON: %w", err)
		}
		strField := func(k string) string {
			v, _ := m[k].(string)
			return strings.TrimSpace(v)
		}
		addr := strField("add")
		uuid := strField("id")
		if addr == "" || uuid == "" {
			return state.OutboundNode{}, errors.New("vmess URI missing add or id")
		}
		port := 443
		switch pv := m["port"].(type) {
		case float64:
			if int(pv) > 0 {
				port = int(pv)
			}
		case string:
			if p, err := strconv.Atoi(strings.TrimSpace(pv)); err == nil && p > 0 {
				port = p
			}
		}
		netType := strings.ToLower(strField("net"))
		proto := "vmess-tcp"
		if netType == "ws" {
			proto = "vmess-ws"
		} else if netType != "" && netType != "tcp" {
			return state.OutboundNode{}, fmt.Errorf("unsupported vmess net %q", netType)
		}
		name := strField("ps")
		if name == "" {
			name = fmt.Sprintf("%s:%d", addr, port)
		}
		sni := strField("sni")
		if sni == "" {
			sni = strField("host")
		}
		path := strField("path")
		if path != "" && !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return state.OutboundNode{
			ID:       genID,
			Name:     name,
			Protocol: proto,
			Address:  addr,
			Port:     port,
			UUID:     uuid,
			TLSSNI:   sni,
			Path:     path,
		}, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return state.OutboundNode{}, fmt.Errorf("invalid URI: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return state.OutboundNode{}, errors.New("missing host in URI")
	}
	label := strings.TrimSpace(u.Fragment)

	switch scheme {
	case "vless":
		port := 443
		if ps := u.Port(); ps != "" {
			p, perr := strconv.Atoi(ps)
			if perr != nil || p < 1 || p > 65535 {
				return state.OutboundNode{}, fmt.Errorf("invalid port %q", ps)
			}
			port = p
		}
		if label == "" {
			label = fmt.Sprintf("%s:%d", host, port)
		}
		uuid := ""
		if u.User != nil {
			uuid = strings.TrimSpace(u.User.Username())
		}
		if uuid == "" {
			return state.OutboundNode{}, errors.New("vless URI missing UUID")
		}
		q := u.Query()
		sec := strings.ToLower(strings.TrimSpace(q.Get("security")))
		netType := strings.ToLower(strings.TrimSpace(q.Get("type")))
		sni := strings.TrimSpace(q.Get("sni"))
		if sni == "" {
			sni = strings.TrimSpace(q.Get("host"))
		}
		path := strings.TrimSpace(q.Get("path"))
		if path != "" && !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		var proto string
		switch {
		case sec == "reality":
			proto = "vless-reality"
			pbk := strings.TrimSpace(q.Get("pbk"))
			if pbk == "" {
				return state.OutboundNode{}, errors.New("vless reality URI missing pbk")
			}
			return state.OutboundNode{
				ID:             genID,
				Name:           label,
				Protocol:       proto,
				Address:        host,
				Port:           port,
				UUID:           uuid,
				TLSSNI:         sni,
				RealityPubKey:  pbk,
				RealityShortID: strings.TrimSpace(q.Get("sid")),
			}, nil
		case netType == "ws":
			proto = "vless-ws"
		case netType == "xhttp", netType == "splithttp", netType == "":
			proto = "vless-xhttp"
		default:
			return state.OutboundNode{}, fmt.Errorf("unsupported vless transport %q", netType)
		}
		return state.OutboundNode{
			ID:       genID,
			Name:     label,
			Protocol: proto,
			Address:  host,
			Port:     port,
			UUID:     uuid,
			TLSSNI:   sni,
			Path:     path,
		}, nil

	case "socks5", "socks5h", "socks":
		port := 1080
		if ps := u.Port(); ps != "" {
			p, perr := strconv.Atoi(ps)
			if perr != nil || p < 1 || p > 65535 {
				return state.OutboundNode{}, fmt.Errorf("invalid port %q", ps)
			}
			port = p
		}
		if label == "" {
			label = fmt.Sprintf("%s:%d", host, port)
		}
		var user, pass string
		if u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}
		return state.OutboundNode{
			ID:       genID,
			Name:     label,
			Protocol: "socks5",
			Address:  host,
			Port:     port,
			Username: user,
			Password: pass,
		}, nil

	default:
		return state.OutboundNode{}, fmt.Errorf("unsupported URI scheme %q", scheme)
	}
}
