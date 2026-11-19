package render

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/stuinxo/de_GWD/v3/internal/cryptoext"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

// RenderOptions supplies environment and runtime-resolved inputs to pure renderers.
type RenderOptions struct {
	StateDir         string
	GeneratedDir     string
	CertFile         string
	KeyFile          string
	XrayBin          string
	MosDNSBin        string
	DexBin           string
	InitSystem       string // systemd | openrc
	IsContainer      bool
	MemMB            int
	ResolvedHostIPs  map[string][]netip.Addr
	PhysicalNICs     []string
	ChnRoutePath     string
	DomainsChnPath   string
	DomainsGamesPath string
	DomainsApplePath string
	ChnRouteCIDRs    []string
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

// GoMemLimit computes GOMEMLIMIT string matching des logic: clamp(MemMB*35/100, 24, 256) + "MiB".
func (o RenderOptions) GoMemLimit() string {
	g := o.MemMB * 35 / 100
	if g < 24 {
		g = 24
	}
	if g > 256 {
		g = 256
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
	Files           []RenderedFile
	XrayNeeded      bool
	NFTClientNeeded bool
	NFTRelayNeeded  bool
	MosDNSNeeded    bool
	HAProxyNeeded   bool
	NginxNeeded     bool
	DoHNeeded       bool
	WireGuardNeeded bool
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
	if listenPort+10000 <= 65535 {
		return listenPort + 10000
	}
	return listenPort - 10000
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

// BuildServerMainURI returns the primary VLESS+XHTTP+TLS URI for server or landing roles.
func BuildServerMainURI(s *state.State) string {
	if len(s.Server.UUIDs) == 0 {
		return ""
	}
	uuid := s.Server.UUIDs[0]
	return BuildNodeURI(state.OutboundNode{
		Name:     fmt.Sprintf("%s:%d", s.Server.EffectiveConnectHost(), s.Server.EffectivePublicPort()),
		Protocol: "vless-xhttp",
		Address:  s.Server.EffectiveConnectHost(),
		Port:     s.Server.EffectivePublicPort(),
		UUID:     uuid,
		TLSSNI:   s.Server.Domain,
		Path:     NormalizePath(s.Server.Path, uuid),
	})
}
