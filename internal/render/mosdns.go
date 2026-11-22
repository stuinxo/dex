package render

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stuinxo/dex/internal/state"
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
	dohPath := filepath.Join(mosDir, "domains_doh.txt")
	blackPath := filepath.Join(mosDir, "domains_black.txt")
	whitePath := filepath.Join(mosDir, "domains_white.txt")
	nodesPath := filepath.Join(mosDir, "domains_nodes.txt")

	chinaServers := s.Client.DNS.ChinaServers
	if len(chinaServers) == 0 {
		chinaServers = state.DefaultChinaDNS
	}
	dohServers := s.Client.DNS.DoHServers
	if len(dohServers) == 0 {
		dohServers = state.DefaultDoHServers
	}

	// Build hosts entries (localhost + DoH domain bootstrap IPs + user hosts) and domains_doh.txt
	var hostLines []string
	hostLines = append(hostLines, "localhost 127.0.0.1")

	seenDoHDomain := make(map[string]struct{})
	var dohDomains []string
	for _, rawURL := range dohServers {
		dom := ExtractDoHHost(rawURL)
		if dom == "" {
			continue
		}
		if _, err := netip.ParseAddr(strings.Trim(dom, "[]")); err == nil {
			continue
		}
		if _, ok := seenDoHDomain[dom]; ok {
			continue
		}
		seenDoHDomain[dom] = struct{}{}
		dohDomains = append(dohDomains, dom)
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
		hostKey := dom
		if rest, ok := strings.CutPrefix(dom, "*."); ok && rest != "" {
			hostKey = "domain:" + rest
		}
		hostLines = append(hostLines, fmt.Sprintf("%s %s", hostKey, s.Client.DNS.Hosts[dom]))
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

	dohContent := strings.Join(dohDomains, "\n")
	if dohContent != "" {
		dohContent += "\n"
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
		if !strings.Contains(srv, "://") {
			if ip, err := netip.ParseAddr(strings.Trim(srv, "[]")); err == nil {
				srv = net.JoinHostPort(ip.String(), "53")
			} else if _, _, err := net.SplitHostPort(srv); err != nil {
				srv = net.JoinHostPort(srv, "53")
			}
		}
		fmt.Fprintf(&yaml, "        - addr: %q\n", srv)
	}

	yaml.WriteString("\n  - tag: forward_global\n    type: forward\n    args:\n      concurrent: 2\n      upstreams:\n")
	for _, srv := range dohServers {
		srv = NormalizeDoHUpstream(srv)
		if srv == "" {
			continue
		}
		fmt.Fprintf(&yaml, "        - addr: %q\n", srv)
		if parsed, err := url.Parse(srv); err == nil && parsed.Hostname() != "" {
			if ips := opts.ResolvedHostIPs[parsed.Hostname()]; len(ips) > 0 {
				for _, ip := range ips {
					if ip.Is4() {
						dialAddr := ip.String()
						if port := parsed.Port(); port != "" {
							dialAddr = net.JoinHostPort(dialAddr, port)
						}
						fmt.Fprintf(&yaml, "          dial_addr: %q\n", dialAddr)
						break
					}
				}
			}
		}
	}

	yaml.WriteString("\n  - tag: chn_sequence\n    type: sequence\n    args:\n")
	yaml.WriteString("      - exec: $forward_chn\n")
	fmt.Fprintf(&yaml, "      - matches: resp_ip &%s\n", opts.ChnRoutePath)
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

	yaml.WriteString("  - tag: node_fallback\n    type: fallback\n    args:\n")
	yaml.WriteString("      primary: global_sequence\n")
	yaml.WriteString("      secondary: forward_chn\n")
	yaml.WriteString("      threshold: 1500\n")
	yaml.WriteString("      always_standby: false\n\n")

	yaml.WriteString("  - tag: has_resp_sequence\n    type: sequence\n    args:\n")
	yaml.WriteString("      - matches: has_resp\n")
	yaml.WriteString("        exec: accept\n\n")

	yaml.WriteString("  - tag: main_sequence\n    type: sequence\n    args:\n")
	if !s.System.EnableIPv6 {
		yaml.WriteString("      - matches: qtype 28 65\n        exec: reject 0\n")
	}
	yaml.WriteString("      - exec: $hosts\n      - exec: jump has_resp_sequence\n")
	yaml.WriteString("      - exec: $cache\n      - exec: jump has_resp_sequence\n")
	fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: $forward_chn\n      - exec: jump has_resp_sequence\n", whitePath)
	fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: $forward_chn\n      - exec: jump has_resp_sequence\n", dohPath)
	if s.Client.DNS.BlockAds {
		adsPath := filepath.Join(opts.StateDir, "rules", "Domains.ads.txt")
		fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: reject 3\n", adsPath)
	}
	fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: goto global_sequence\n", blackPath)
	fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: $node_fallback\n      - exec: jump has_resp_sequence\n", nodesPath)
	if opts.DomainsAppleExists {
		if s.Client.Routing.AppleNodeID != "" {
			fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: goto global_sequence\n", opts.DomainsApplePath)
		} else {
			fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: $chn_sequence\n      - exec: jump has_resp_sequence\n", opts.DomainsApplePath)
		}
	}
	if opts.DomainsGamesExists {
		if s.Client.Routing.SteamProxy {
			fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: goto global_sequence\n", opts.DomainsGamesPath)
		} else {
			fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: $chn_sequence\n      - exec: jump has_resp_sequence\n", opts.DomainsGamesPath)
		}
	}
	fmt.Fprintf(&yaml, "      - matches: qname &%s\n        exec: $fallback\n      - exec: jump has_resp_sequence\n", opts.DomainsChnPath)
	yaml.WriteString("      - exec: goto global_sequence\n\n")

	yaml.WriteString("  - type: udp_server\n    args:\n      entry: main_sequence\n      listen: 0.0.0.0:53\n\n")
	yaml.WriteString("  - type: tcp_server\n    args:\n      entry: main_sequence\n      listen: 0.0.0.0:53\n")
	if s.System.EnableIPv6 {
		yaml.WriteString("\n  - type: udp_server\n    args:\n      entry: main_sequence\n      listen: \"[::]:53\"\n\n")
		yaml.WriteString("  - type: tcp_server\n    args:\n      entry: main_sequence\n      listen: \"[::]:53\"\n")
	}

	files := []RenderedFile{
		{
			RelName:    "mosdns/hosts.txt",
			TargetPath: hostsPath,
			Content:    []byte(strings.Join(hostLines, "\n") + "\n"),
			Mode:       0o644,
		},
		{
			RelName:    "mosdns/domains_doh.txt",
			TargetPath: dohPath,
			Content:    []byte(dohContent),
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
