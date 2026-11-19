package render

import (
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stuinxo/de_GWD/v3/internal/state"
)

// RenderMosDNS generates the single-core MosDNS v5 config and companion rule text files
// for the client gateway (replacing Pi-hole + SmartDNS + CoreDNS).
func RenderMosDNS(s *state.State, opts RenderOptions) ([]RenderedFile, bool, error) {
	opts = opts.WithDefaults()
	if s.Role != state.RoleClient {
		return nil, false, nil
	}

	mosDir := filepath.Join(opts.GeneratedDir, "mosdns")
	hostsPath := filepath.Join(mosDir, "hosts.txt")
	blackPath := filepath.Join(mosDir, "domains_black.txt")
	whitePath := filepath.Join(mosDir, "domains_white.txt")
	nodesPath := filepath.Join(mosDir, "domains_nodes.txt")

	// Build hosts entries (localhost + DoH domain bootstrap IPs + user hosts)
	var hostLines []string
	hostLines = append(hostLines, "localhost 127.0.0.1")

	seenDoHDomain := make(map[string]struct{})
	for _, rawURL := range s.Client.DNS.DoHServers {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		dom := parsed.Hostname()
		if _, err := netip.ParseAddr(dom); err == nil {
			continue
		}
		if _, ok := seenDoHDomain[dom]; ok {
			continue
		}
		seenDoHDomain[dom] = struct{}{}
		if ips := opts.ResolvedHostIPs[dom]; len(ips) > 0 {
			for _, ip := range ips {
				if ip.Is4() {
					hostLines = append(hostLines, fmt.Sprintf("%s %s", dom, ip.String()))
					break
				}
			}
		}
	}

	hostKeys := make([]string, 0, len(s.Client.DNS.Hosts))
	for dom := range s.Client.DNS.Hosts {
		hostKeys = append(hostKeys, dom)
	}
	sort.Strings(hostKeys)
	for _, dom := range hostKeys {
		hostLines = append(hostLines, fmt.Sprintf("%s %s", dom, s.Client.DNS.Hosts[dom]))
	}

	// Build node domain list so proxy server domains resolve cleanly via encrypted global DNS
	seenNode := make(map[string]struct{})
	var nodeLines []string
	addNodeDomain := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		if _, err := netip.ParseAddr(strings.Trim(addr, "[]")); err == nil {
			return
		}
		if _, ok := seenNode[addr]; ok {
			return
		}
		seenNode[addr] = struct{}{}
		nodeLines = append(nodeLines, addr)
	}
	for _, n := range s.Client.Nodes {
		addNodeDomain(n.Address)
	}
	if s.Client.RproxyC.Enabled {
		addNodeDomain(s.Client.RproxyC.TunnelAddress)
	}

	blackContent := strings.Join(s.Client.DNS.BlacklistDomains, "\n")
	if blackContent != "" {
		blackContent += "\n"
	}
	whiteContent := strings.Join(s.Client.DNS.WhitelistDomains, "\n")
	if whiteContent != "" {
		whiteContent += "\n"
	}
	nodesContent := strings.Join(nodeLines, "\n")
	if nodesContent != "" {
		nodesContent += "\n"
	}

	chinaServers := s.Client.DNS.ChinaServers
	if len(chinaServers) == 0 {
		chinaServers = state.DefaultChinaDNS
	}
	dohServers := s.Client.DNS.DoHServers
	if len(dohServers) == 0 {
		dohServers = state.DefaultDoHServers
	}

	var yaml strings.Builder
	yaml.WriteString("log:\n  level: error\n\nplugins:\n")
	yaml.WriteString("  - tag: cache\n    type: cache\n    args:\n      size: 16384\n      lazy_cache_ttl: 86400\n\n")
	yaml.WriteString("  - tag: hosts\n    type: hosts\n    args:\n      files:\n")
	fmt.Fprintf(&yaml, "        - %q\n\n", hostsPath)

	yaml.WriteString("  - tag: forward_chn\n    type: forward\n    args:\n      concurrent: 2\n      upstreams:\n")
	for _, srv := range chinaServers {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		if !strings.Contains(srv, "://") && !strings.Contains(srv, ":") {
			srv = srv + ":53"
		}
		fmt.Fprintf(&yaml, "        - addr: %q\n", srv)
	}

	yaml.WriteString("\n  - tag: forward_global\n    type: forward\n    args:\n      concurrent: 2\n      upstreams:\n")
	for _, srv := range dohServers {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		if !strings.HasPrefix(srv, "https://") && !strings.HasPrefix(srv, "tls://") && !strings.HasPrefix(srv, "tcp://") {
			srv = "https://" + srv
		}
		fmt.Fprintf(&yaml, "        - addr: %q\n", srv)
		if parsed, err := url.Parse(srv); err == nil && parsed.Hostname() != "" {
			if ips := opts.ResolvedHostIPs[parsed.Hostname()]; len(ips) > 0 {
				for _, ip := range ips {
					if ip.Is4() {
						fmt.Fprintf(&yaml, "          dial_addr: %q\n", ip.String())
						break
					}
				}
			}
		}
	}

	yaml.WriteString("\n  - tag: chn_sequence\n    type: sequence\n    args:\n")
	yaml.WriteString("      - exec: $forward_chn\n")
	fmt.Fprintf(&yaml, "      - matches: resp_ip &%q\n", opts.ChnRoutePath)
	yaml.WriteString("        exec: accept\n")
	yaml.WriteString("      - exec: drop_resp\n\n")

	yaml.WriteString("  - tag: global_sequence\n    type: sequence\n    args:\n")
	yaml.WriteString("      - exec: $forward_global\n")
	yaml.WriteString("      - exec: accept\n\n")

	yaml.WriteString("  - tag: fallback\n    type: fallback\n    args:\n")
	yaml.WriteString("      primary: chn_sequence\n")
	yaml.WriteString("      secondary: global_sequence\n")
	yaml.WriteString("      threshold: 100\n")
	yaml.WriteString("      always_standby: true\n\n")

	yaml.WriteString("  - tag: has_resp_sequence\n    type: sequence\n    args:\n")
	yaml.WriteString("      - matches: has_resp\n")
	yaml.WriteString("        exec: accept\n\n")

	yaml.WriteString("  - tag: main_sequence\n    type: sequence\n    args:\n")
	if !s.System.EnableIPv6 {
		yaml.WriteString("      - matches: qtype 28 65\n        exec: reject 0\n")
	}
	yaml.WriteString("      - exec: $hosts\n      - exec: jump has_resp_sequence\n")
	yaml.WriteString("      - exec: $cache\n      - exec: jump has_resp_sequence\n")
	if s.Client.DNS.BlockAds {
		adsPath := filepath.Join(opts.StateDir, "rules", "Domains.ads.txt")
		fmt.Fprintf(&yaml, "      - matches: qname &%q\n        exec: reject 3\n", adsPath)
	}
	fmt.Fprintf(&yaml, "      - matches: qname &%q\n        exec: goto global_sequence\n", blackPath)
	fmt.Fprintf(&yaml, "      - matches: qname &%q\n        exec: $forward_chn\n      - exec: jump has_resp_sequence\n", whitePath)
	fmt.Fprintf(&yaml, "      - matches: qname &%q\n        exec: goto global_sequence\n", nodesPath)
	fmt.Fprintf(&yaml, "      - matches: qname &%q\n        exec: $fallback\n      - exec: jump has_resp_sequence\n", opts.DomainsChnPath)
	yaml.WriteString("      - exec: goto global_sequence\n\n")

	yaml.WriteString("  - type: udp_server\n    args:\n      entry: main_sequence\n      listen: 0.0.0.0:53\n\n")
	yaml.WriteString("  - type: tcp_server\n    args:\n      entry: main_sequence\n      listen: 0.0.0.0:53\n")

	files := []RenderedFile{
		{
			RelName:    "mosdns/hosts.txt",
			TargetPath: hostsPath,
			Content:    []byte(strings.Join(hostLines, "\n") + "\n"),
			Mode:       0o644,
		},
		{
			RelName:    "mosdns/domains_black.txt",
			TargetPath: blackPath,
			Content:    []byte(blackContent),
			Mode:       0o644,
		},
		{
			RelName:    "mosdns/domains_white.txt",
			TargetPath: whitePath,
			Content:    []byte(whiteContent),
			Mode:       0o644,
		},
		{
			RelName:    "mosdns/domains_nodes.txt",
			TargetPath: nodesPath,
			Content:    []byte(nodesContent),
			Mode:       0o644,
		},
		{
			RelName:      "mosdns/mosdns.yaml",
			TargetPath:   filepath.Join(mosDir, "mosdns.yaml"),
			Content:      []byte(yaml.String()),
			Mode:         0o644,
			ValidateKind: "yaml",
		},
	}
	return files, true, nil
}
