package state

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

var (
	domainLabelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)
	geoRuleRe     = regexp.MustCompile(`^geoip:!?[A-Za-z0-9_-]+$`)
	extRuleRe     = regexp.MustCompile(`^ext:[A-Za-z0-9._-]+:[A-Za-z0-9!_-]+$`)
)

// IsValidAddress reports whether addr is a valid IPv4, IPv6, or hostname/domain.
func IsValidAddress(addr string) bool {
	if addr == "" || strings.ContainsAny(addr, " \t\r\n") {
		return false
	}
	if ip, err := netip.ParseAddr(addr); err == nil && ip.Zone() == "" {
		return true
	}
	// If it looks purely numeric/dotted, do not treat invalid IPv4 as hostname.
	isNumericDotted := true
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if (c < '0' || c > '9') && c != '.' {
			isNumericDotted = false
			break
		}
	}
	if isNumericDotted {
		return false
	}
	if strings.Contains(addr, ":") {
		return false
	}
	return len(addr) <= 253 && domainLabelRe.MatchString(addr)
}

// IsValidIPRule validates a routing IP/CIDR/geoip/ext rule entry.
func IsValidIPRule(rule string) bool {
	if rule == "" || strings.ContainsAny(rule, " \t\r\n") {
		return false
	}
	if geoRuleRe.MatchString(rule) || extRuleRe.MatchString(rule) {
		return true
	}
	if strings.Contains(rule, "/") {
		p, err := netip.ParsePrefix(rule)
		return err == nil && p.Addr().Zone() == ""
	}
	ip, err := netip.ParseAddr(rule)
	return err == nil && ip.Zone() == ""
}

// IsValidDomainRule validates a routing domain rule entry (domain:, full:, regexp:, keyword:, geosite:, ext:, or bare domain).
func IsValidDomainRule(rule string) bool {
	if rule == "" {
		return false
	}
	for i := 0; i < len(rule); i++ {
		b := rule[i]
		if b <= 0x20 || b == 0x7f {
			return false
		}
	}
	return true
}

// FormatEndpoint formats address and port for display (bracketing IPv6 addresses).
func FormatEndpoint(address string, port int) string {
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
		return fmt.Sprintf("[%s]:%d", address, port)
	}
	return fmt.Sprintf("%s:%d", address, port)
}

// IsRestrictedPeerIP reports whether ip is a loopback, unspecified, link-local unicast, or multicast address
// that must never be used as an external proxy/tunnel endpoint or TPROXY bypass IP.
func IsRestrictedPeerIP(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast()
}

// SanitizeSafeName converts an arbitrary label (e.g. a WireGuard peer name) into a filename-safe
// token consisting solely of ASCII alphanumerics, '-', and '_', returning fallback if empty.
func SanitizeSafeName(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	cleaned := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, raw)
	cleaned = strings.Trim(cleaned, "_")
	if cleaned == "" {
		return fallback
	}
	return cleaned
}
