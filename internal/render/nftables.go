package render

import (
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/stuinxo/de_GWD/v3/internal/state"
)

var baseReservedIPv4 = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"114.114.114.114/32",
	"114.114.115.115/32",
	"119.29.29.29/32",
	"119.28.28.28/32",
	"180.76.76.76/32",
	"223.5.5.5/32",
	"223.6.6.6/32",
}

var baseReservedIPv6 = []string{
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

func splitIPsByFamily(entries []string) (v4 []string, v6 []string) {
	seen4 := make(map[string]struct{})
	seen6 := make(map[string]struct{})
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			s := p.Masked().String()
			if p.Addr().Is4() {
				if _, ok := seen4[s]; !ok {
					seen4[s] = struct{}{}
					v4 = append(v4, s)
				}
			} else {
				if _, ok := seen6[s]; !ok {
					seen6[s] = struct{}{}
					v6 = append(v6, s)
				}
			}
			continue
		}
		if ip, err := netip.ParseAddr(raw); err == nil {
			s := ip.String()
			if ip.Is4() {
				if _, ok := seen4[s]; !ok {
					seen4[s] = struct{}{}
					v4 = append(v4, s)
				}
			} else {
				if _, ok := seen6[s]; !ok {
					seen6[s] = struct{}{}
					v6 = append(v6, s)
				}
			}
		}
	}
	return v4, v6
}

func formatNFTElements(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return "        elements = { " + strings.Join(items, ", ") + " }\n"
}

func writeNFTSet(b *strings.Builder, name, nftType string, elems []string, interval bool) {
	fmt.Fprintf(b, "    set %s {\n", name)
	fmt.Fprintf(b, "        type %s\n", nftType)
	if interval {
		b.WriteString("        flags interval\n")
		b.WriteString("        auto-merge\n")
	}
	if len(elems) > 0 {
		b.WriteString(formatNFTElements(elems))
	}
	b.WriteString("    }\n")
}

// RenderNFTables generates dual-stack nftables rulesets for dex_client and dex_relay tables
// without wiping unrelated system tables (`flush ruleset` is intentionally avoided).
func RenderNFTables(s *state.State, opts RenderOptions) (data []byte, clientNeeded bool, relayNeeded bool, err error) {
	opts = opts.WithDefaults()
	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n\n")

	if s.Role == state.RoleClient {
		clientNeeded = true

		reserved4 := append([]string(nil), baseReservedIPv4...)
		if s.System.LANAddrCIDR != "" {
			if p, perr := netip.ParsePrefix(s.System.LANAddrCIDR); perr == nil {
				netCIDR := p.Masked().String()
				if p.Addr().Is4() {
					reserved4 = append(reserved4, netCIDR)
				}
			}
		}
		reserved4, reserved6 := splitIPsByFamily(append(reserved4, baseReservedIPv6...))

		// Collect GlobalDNS IPs from DoH URLs; when client proxy nodes exist, exclude public Anycast DoH IPs
		// blocked in mainland China so fallback DoH and client probes to 1.1.1.1/8.8.8.8 traverse Xray instead.
		hasNodes := len(s.Client.Nodes) > 0
		blockedPublicDoHIPs := map[string]struct{}{
			"1.1.1.1":              {},
			"1.0.0.1":              {},
			"8.8.8.8":              {},
			"8.8.4.4":              {},
			"9.9.9.9":              {},
			"2606:4700:4700::1111": {},
			"2606:4700:4700::1001": {},
			"2001:4860:4860::8888": {},
			"2001:4860:4860::8844": {},
			"2620:fe::fe":          {},
		}
		var globalDNSRaw []string
		for _, u := range s.Client.DNS.DoHServers {
			host := u
			if parsed, perr := url.Parse(u); perr == nil && parsed.Hostname() != "" {
				host = parsed.Hostname()
			}
			if ip, ipErr := netip.ParseAddr(host); ipErr == nil {
				sIP := ip.String()
				if _, blocked := blockedPublicDoHIPs[sIP]; !hasNodes || !blocked {
					globalDNSRaw = append(globalDNSRaw, sIP)
				}
			} else if ips := opts.ResolvedHostIPs[host]; len(ips) > 0 {
				for _, ip := range ips {
					sIP := ip.String()
					if _, blocked := blockedPublicDoHIPs[sIP]; !hasNodes || !blocked {
						globalDNSRaw = append(globalDNSRaw, sIP)
					}
				}
			}
		}
		globalDNS4, globalDNS6 := splitIPsByFamily(globalDNSRaw)

		// Collect all proxy node endpoint IPs into V2NODE bypass sets
		var v2nodeRaw []string
		for _, n := range s.Client.Nodes {
			if _, ipErr := netip.ParseAddr(n.Address); ipErr == nil {
				v2nodeRaw = append(v2nodeRaw, n.Address)
			} else if ips := opts.ResolvedHostIPs[n.Address]; len(ips) > 0 {
				for _, ip := range ips {
					v2nodeRaw = append(v2nodeRaw, ip.String())
				}
			}
		}
		if s.Client.RproxyC.Enabled && s.Client.RproxyC.TunnelAddress != "" {
			addr := s.Client.RproxyC.TunnelAddress
			if _, ipErr := netip.ParseAddr(addr); ipErr == nil {
				v2nodeRaw = append(v2nodeRaw, addr)
			} else if ips := opts.ResolvedHostIPs[addr]; len(ips) > 0 {
				for _, ip := range ips {
					v2nodeRaw = append(v2nodeRaw, ip.String())
				}
			}
		}
		v2node4, v2node6 := splitIPsByFamily(v2nodeRaw)

		chn4, _ := splitIPsByFamily(opts.ChnRouteCIDRs)
		listB4, listB6 := splitIPsByFamily(s.Client.DNS.BlacklistIPs)
		listW4, listW6 := splitIPsByFamily(s.Client.DNS.WhitelistIPs)

		var lanProxyRaw, lanDirectRaw []string
		if s.Client.Routing.Divert.Enabled {
			lanProxyRaw = s.Client.Routing.Divert.GlobalProxyLANIP
			lanDirectRaw = s.Client.Routing.Divert.DirectLANIPs
		}
		lanProxy4, lanProxy6 := splitIPsByFamily(lanProxyRaw)
		lanDirect4, lanDirect6 := splitIPsByFamily(lanDirectRaw)

		// Optional flowtable acceleration for WireGuard/LAN forwarding
		if s.System.EnableFlowtable && len(opts.PhysicalNICs) > 0 {
			var nics []string
			for _, nic := range opts.PhysicalNICs {
				nic = strings.TrimSpace(nic)
				if nic != "" {
					nics = append(nics, nic)
				}
			}
			if len(nics) > 0 {
				b.WriteString("table inet dex_flow {}\ndelete table inet dex_flow\ntable inet dex_flow {\n")
				fmt.Fprintf(&b, "    flowtable acceleration {\n        hook ingress priority filter; devices = { %s };\n    }\n", strings.Join(nics, ", "))
				b.WriteString("    chain forward {\n        type filter hook forward priority filter; policy accept;\n")
				if s.Client.WireGuard.Enabled {
					b.WriteString("        ct state established ip daddr 172.16.66.0/24 flow offload @acceleration\n")
					b.WriteString("        ct state established ip saddr 172.16.66.0/24 flow offload @acceleration\n")
				}
				b.WriteString("    }\n}\n\n")
			}
		}

		// Filter + NAT table for WireGuard, MSS clamping, and QUIC UDP/443 rejection
		b.WriteString("table inet dex_filter {}\ndelete table inet dex_filter\ntable inet dex_filter {\n")
		b.WriteString("    chain input {\n        type filter hook input priority 0; policy accept;\n")
		b.WriteString("        iifname \"lo\" accept\n")
		if s.Client.WireGuard.Enabled {
			b.WriteString("        iifname \"wg0\" accept\n")
		}
		b.WriteString("        ct state established,related accept\n")
		b.WriteString("        ct state invalid counter drop\n")
		b.WriteString("    }\n")

		b.WriteString("    chain forward {\n        type filter hook forward priority 0; policy accept;\n")
		b.WriteString("        # Reject proxied QUIC (UDP 443) immediately so clients fall back to TCP without blackhole delay\n")
		b.WriteString("        meta mark 0x8 meta l4proto udp th dport 443 counter reject\n")
		b.WriteString("        tcp flags & (syn|rst) == syn tcp option maxseg size set rt mtu\n")
		if s.Client.WireGuard.Enabled {
			b.WriteString("        iifname \"wg0\" accept\n")
			b.WriteString("        oifname \"wg0\" accept\n")
		}
		b.WriteString("    }\n")

		b.WriteString("    chain output {\n        type filter hook output priority 0; policy accept;\n")
		b.WriteString("        meta mark 0x8 meta l4proto udp th dport 443 counter reject\n")
		b.WriteString("        oifname != \"lo\" tcp flags & (syn|rst) == syn tcp option maxseg size set rt mtu\n")
		b.WriteString("    }\n")
		b.WriteString("}\n\n")

		lanIf := strings.TrimSpace(s.System.LANInterface)
		if lanIf == "" && len(opts.PhysicalNICs) > 0 {
			lanIf = strings.TrimSpace(opts.PhysicalNICs[0])
		}
		if s.Client.WireGuard.Enabled && lanIf != "" {
			b.WriteString("table inet dex_nat {}\ndelete table inet dex_nat\ntable inet dex_nat {\n")
			b.WriteString("    chain postrouting {\n        type nat hook postrouting priority srcnat; policy accept;\n")
			fmt.Fprintf(&b, "        oifname %q ip saddr 172.16.66.0/24 masquerade\n", lanIf)
			b.WriteString("    }\n}\n\n")
		}

		// Main TPROXY routing table (dual-stack inet)
		b.WriteString("table inet dex_client {}\ndelete table inet dex_client\ntable inet dex_client {\n")
		writeNFTSet(&b, "reserved_v4", "ipv4_addr", reserved4, true)
		writeNFTSet(&b, "reserved_v6", "ipv6_addr", reserved6, true)
		writeNFTSet(&b, "global_dns_v4", "ipv4_addr", globalDNS4, true)
		writeNFTSet(&b, "global_dns_v6", "ipv6_addr", globalDNS6, true)
		writeNFTSet(&b, "v2node_v4", "ipv4_addr", v2node4, true)
		writeNFTSet(&b, "v2node_v6", "ipv6_addr", v2node6, true)
		writeNFTSet(&b, "chnroute_v4", "ipv4_addr", chn4, true)
		writeNFTSet(&b, "list_b_v4", "ipv4_addr", listB4, true)
		writeNFTSet(&b, "list_b_v6", "ipv6_addr", listB6, true)
		writeNFTSet(&b, "list_w_v4", "ipv4_addr", listW4, true)
		writeNFTSet(&b, "list_w_v6", "ipv6_addr", listW6, true)
		writeNFTSet(&b, "lan_proxy_v4", "ipv4_addr", lanProxy4, true)
		writeNFTSet(&b, "lan_proxy_v6", "ipv6_addr", lanProxy6, true)
		writeNFTSet(&b, "lan_direct_v4", "ipv4_addr", lanDirect4, true)
		writeNFTSet(&b, "lan_direct_v6", "ipv6_addr", lanDirect6, true)

		// prerouting
		b.WriteString("    chain prerouting {\n        type filter hook prerouting priority mangle; policy accept;\n")
		b.WriteString("        fib daddr type local meta l4proto { tcp, udp } th dport != 9896 accept\n")
		b.WriteString("        meta l4proto udp th dport { 53, 5341, 9896, 67, 68, 1900, 5350, 5351, 5353 } accept\n")
		b.WriteString("        meta l4proto tcp th dport { 53, 5341, 9896, 2195, 2196, 2197, 3689, 5223, 5297 } accept\n")
		b.WriteString("        ip daddr @global_dns_v4 accept\n")
		b.WriteString("        ip6 daddr @global_dns_v6 accept\n")
		b.WriteString("        ip daddr @reserved_v4 accept\n")
		b.WriteString("        ip6 daddr @reserved_v6 accept\n")
		b.WriteString("        ip saddr @lan_proxy_v4 meta l4proto udp th dport 443 meta mark set 0x8 accept\n")
		b.WriteString("        ip saddr @lan_proxy_v4 meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:9896 meta mark set 0x9\n")
		b.WriteString("        ip saddr @lan_direct_v4 accept\n")
		b.WriteString("        ip daddr @list_b_v4 meta l4proto udp th dport 443 meta mark set 0x8 accept\n")
		b.WriteString("        ip daddr @list_b_v4 meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:9896 meta mark set 0x9\n")
		b.WriteString("        ip daddr @list_w_v4 accept\n")
		b.WriteString("        ip daddr @v2node_v4 accept\n")
		b.WriteString("        ip daddr @chnroute_v4 accept\n")
		if s.System.EnableIPv6 {
			b.WriteString("        ip6 saddr @lan_proxy_v6 meta l4proto udp th dport 443 meta mark set 0x8 accept\n")
			b.WriteString("        ip6 saddr @lan_proxy_v6 meta l4proto { tcp, udp } tproxy ip6 to [::1]:9896 meta mark set 0x9\n")
			b.WriteString("        ip6 saddr @lan_direct_v6 accept\n")
			b.WriteString("        ip6 daddr @list_b_v6 meta l4proto udp th dport 443 meta mark set 0x8 accept\n")
			b.WriteString("        ip6 daddr @list_b_v6 meta l4proto { tcp, udp } tproxy ip6 to [::1]:9896 meta mark set 0x9\n")
			b.WriteString("        ip6 daddr @list_w_v6 accept\n")
			b.WriteString("        ip6 daddr @v2node_v6 accept\n")
		}
		b.WriteString("        meta l4proto udp th dport 443 meta mark set 0x8 accept\n")
		b.WriteString("        meta nfproto ipv4 meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:9896 meta mark set 0x9\n")
		if s.System.EnableIPv6 {
			b.WriteString("        meta nfproto ipv6 meta l4proto { tcp, udp } tproxy ip6 to [::1]:9896 meta mark set 0x9\n")
		}
		b.WriteString("    }\n")

		// output
		b.WriteString("    chain output {\n        type route hook output priority mangle; policy accept;\n")
		b.WriteString("        ct direction reply accept\n")
		b.WriteString("        meta l4proto udp th dport { 53, 5341, 9896, 67, 68, 1900, 5350, 5351, 5353 } accept\n")
		b.WriteString("        meta l4proto tcp th dport { 53, 5341, 9896, 2195, 2196, 2197, 3689, 5223, 5297 } accept\n")
		b.WriteString("        meta mark 0xff accept\n")
		b.WriteString("        ip daddr @global_dns_v4 accept\n")
		b.WriteString("        ip6 daddr @global_dns_v6 accept\n")
		b.WriteString("        ip daddr @reserved_v4 accept\n")
		b.WriteString("        ip6 daddr @reserved_v6 accept\n")
		b.WriteString("        ip daddr @list_b_v4 meta l4proto udp th dport 443 meta mark set 0x8 accept\n")
		b.WriteString("        ip daddr @list_b_v4 meta l4proto { tcp, udp } meta mark set 0x9\n")
		b.WriteString("        ip daddr @list_w_v4 accept\n")
		b.WriteString("        ip daddr @v2node_v4 accept\n")
		b.WriteString("        ip daddr @chnroute_v4 accept\n")
		if s.System.EnableIPv6 {
			b.WriteString("        ip6 daddr @list_b_v6 meta l4proto udp th dport 443 meta mark set 0x8 accept\n")
			b.WriteString("        ip6 daddr @list_b_v6 meta l4proto { tcp, udp } meta mark set 0x9\n")
			b.WriteString("        ip6 daddr @list_w_v6 accept\n")
			b.WriteString("        ip6 daddr @v2node_v6 accept\n")
		}
		b.WriteString("        meta l4proto udp th dport 443 meta mark set 0x8 accept\n")
		b.WriteString("        meta nfproto ipv4 meta l4proto { tcp, udp } meta mark set 0x9\n")
		if s.System.EnableIPv6 {
			b.WriteString("        meta nfproto ipv6 meta l4proto { tcp, udp } meta mark set 0x9\n")
		}
		b.WriteString("    }\n}\n\n")
	}

	// Relay rules (Option 44 nft engine) — dual-stack table inet dex_relay
	var preRules, outRules, postRules []string
	var forwardsSorted []state.ForwardRule
	for _, f := range s.Relay.Forwards {
		if f.Engine == "nft" {
			forwardsSorted = append(forwardsSorted, f)
		}
	}
	sort.Slice(forwardsSorted, func(i, j int) bool {
		return forwardsSorted[i].ListenPort < forwardsSorted[j].ListenPort
	})

	for _, fwd := range forwardsSorted {
		var targetIP netip.Addr
		if ip, perr := netip.ParseAddr(strings.Trim(fwd.TargetHost, "[]")); perr == nil {
			targetIP = ip
		} else if ips := opts.ResolvedHostIPs[fwd.TargetHost]; len(ips) > 0 {
			for _, candidate := range ips {
				if candidate.Is4() {
					targetIP = candidate
					break
				}
			}
			if !targetIP.IsValid() {
				targetIP = ips[0]
			}
		}
		if !targetIP.IsValid() {
			return nil, clientNeeded, relayNeeded, fmt.Errorf("cannot resolve target %q for nft forward rule %q", fwd.TargetHost, fwd.ID)
		}

		for _, proto := range strings.Split(fwd.Proto, ",") {
			proto = strings.TrimSpace(proto)
			if proto == "" {
				continue
			}
			if targetIP.Is4() {
				preRules = append(preRules, fmt.Sprintf("        %s dport %d dnat ip to %s:%d", proto, fwd.ListenPort, targetIP.String(), fwd.TargetPort))
				outRules = append(outRules, fmt.Sprintf("        %s dport %d dnat ip to %s:%d", proto, fwd.ListenPort, targetIP.String(), fwd.TargetPort))
				postRules = append(postRules, fmt.Sprintf("        ip daddr %s %s dport %d masquerade", targetIP.String(), proto, fwd.TargetPort))
			} else {
				preRules = append(preRules, fmt.Sprintf("        %s dport %d dnat ip6 to [%s]:%d", proto, fwd.ListenPort, targetIP.String(), fwd.TargetPort))
				outRules = append(outRules, fmt.Sprintf("        %s dport %d dnat ip6 to [%s]:%d", proto, fwd.ListenPort, targetIP.String(), fwd.TargetPort))
				postRules = append(postRules, fmt.Sprintf("        ip6 daddr %s %s dport %d masquerade", targetIP.String(), proto, fwd.TargetPort))
			}
		}
	}

	if len(preRules) > 0 {
		relayNeeded = true
		b.WriteString("table inet dex_relay {}\ndelete table inet dex_relay\ntable inet dex_relay {\n")
		b.WriteString("    chain prerouting {\n        type nat hook prerouting priority -100; policy accept;\n")
		for _, r := range preRules {
			b.WriteString(r + "\n")
		}
		b.WriteString("    }\n    chain output {\n        type nat hook output priority -100; policy accept;\n")
		for _, r := range outRules {
			b.WriteString(r + "\n")
		}
		b.WriteString("    }\n    chain forward {\n        type filter hook forward priority 0; policy accept;\n    }\n")
		b.WriteString("    chain postrouting {\n        type nat hook postrouting priority 100; policy accept;\n")
		for _, r := range postRules {
			b.WriteString(r + "\n")
		}
		b.WriteString("    }\n}\n")
	}

	if !clientNeeded && !relayNeeded {
		return nil, false, false, nil
	}
	return []byte(b.String()), clientNeeded, relayNeeded, nil
}
