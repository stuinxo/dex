package socks5out

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Endpoint describes a parsed SOCKS5 upstream endpoint.
type Endpoint struct {
	Kind     string `json:"kind"` // uri | tuple4 | hostport | host
	Address  string `json:"address"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	HasAuth  bool   `json:"has_auth"`
}

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

func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

func pctDecodeStrict(s string) (string, error) {
	if !strings.Contains(s, "%") {
		if hasControlByte(s) {
			return "", errors.New("control characters not allowed")
		}
		return s, nil
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err == nil {
				b := byte(v)
				if b == 0 || b < 0x20 || b == 0x7f {
					return "", errors.New("encoded control character not allowed")
				}
				out = append(out, b)
				i += 2
				continue
			}
		}
		if s[i] < 0x20 || s[i] == 0x7f {
			return "", errors.New("control character not allowed")
		}
		out = append(out, s[i])
	}
	return string(out), nil
}

func decodeBase64UserInfo(raw string) (string, bool) {
	s := strings.NewReplacer("-", "+", "_", "/").Replace(raw)
	if mod := len(s) % 4; mod != 0 {
		s += strings.Repeat("=", 4-mod)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", false
	}
	dec := string(b)
	if hasControlByte(dec) {
		return "", false
	}
	return dec, true
}

func parsePortStrict(raw string) (int, error) {
	if raw == "" {
		return 0, errors.New("empty port")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, fmt.Errorf("invalid port %q", raw)
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	p, err := strconv.Atoi(raw)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("port out of range: %q", raw)
	}
	return p, nil
}

// ParseEndpoint parses socks5/socks5h/socks URIs, host:port:user:pass tuples,
// [ipv6]:port[:user:pass], host:port, or bare host/IPv6.
func ParseEndpoint(raw string) (*Endpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty endpoint")
	}

	ep := &Endpoint{}
	if idx := strings.Index(raw, "://"); idx >= 0 {
		scheme := strings.ToLower(raw[:idx])
		if scheme != "socks5" && scheme != "socks5h" && scheme != "socks" {
			return nil, fmt.Errorf("unsupported scheme %q", scheme)
		}
		rest := raw[idx+3:]
		if cut := strings.IndexAny(rest, "#?/"); cut >= 0 {
			rest = rest[:cut]
		}
		if rest == "" {
			return nil, errors.New("missing host in URI")
		}
		userinfo := ""
		hostport := rest
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			userinfo = rest[:at]
			hostport = rest[at+1:]
		}
		if userinfo != "" {
			if colon := strings.IndexByte(userinfo, ':'); colon >= 0 {
				u, err := pctDecodeStrict(userinfo[:colon])
				if err != nil {
					return nil, err
				}
				p, err := pctDecodeStrict(userinfo[colon+1:])
				if err != nil {
					return nil, err
				}
				ep.Username = u
				ep.Password = p
				ep.HasAuth = true
			} else {
				dec, err := pctDecodeStrict(userinfo)
				if err != nil {
					return nil, err
				}
				if c2 := strings.IndexByte(dec, ':'); c2 >= 0 {
					ep.Username = dec[:c2]
					ep.Password = dec[c2+1:]
					ep.HasAuth = true
				} else if b64, ok := decodeBase64UserInfo(dec); ok && strings.Contains(b64, ":") {
					c3 := strings.IndexByte(b64, ':')
					ep.Username = b64[:c3]
					ep.Password = b64[c3+1:]
					ep.HasAuth = true
				} else {
					return nil, errors.New("userinfo must contain username and password")
				}
			}
			if ep.Username == "" || ep.Password == "" {
				return nil, errors.New("username and password must both be non-empty")
			}
		}

		if strings.HasPrefix(hostport, "[") {
			closeBr := strings.IndexByte(hostport, ']')
			if closeBr < 0 {
				return nil, errors.New("unclosed IPv6 bracket")
			}
			ep.Address = hostport[1:closeBr]
			tail := hostport[closeBr+1:]
			if tail != "" {
				if !strings.HasPrefix(tail, ":") {
					return nil, errors.New("invalid trailing characters after IPv6 address")
				}
				p, err := parsePortStrict(tail[1:])
				if err != nil {
					return nil, err
				}
				ep.Port = p
			}
		} else if strings.Count(hostport, ":") > 1 {
			return nil, errors.New("unbracketed IPv6 in URI")
		} else if colon := strings.IndexByte(hostport, ':'); colon >= 0 {
			ep.Address = hostport[:colon]
			p, err := parsePortStrict(hostport[colon+1:])
			if err != nil {
				return nil, err
			}
			ep.Port = p
		} else {
			ep.Address = hostport
		}
		var err error
		ep.Address, err = pctDecodeStrict(ep.Address)
		if err != nil {
			return nil, err
		}
		ep.Kind = "uri"
	} else {
		if strings.HasPrefix(raw, "[") {
			closeBr := strings.IndexByte(raw, ']')
			if closeBr < 0 {
				return nil, errors.New("unclosed IPv6 bracket")
			}
			ep.Address = raw[1:closeBr]
			tail := raw[closeBr+1:]
			switch {
			case tail == "":
				ep.Kind = "host"
			case strings.HasPrefix(tail, ":"):
				parts := strings.SplitN(tail[1:], ":", 3)
				switch len(parts) {
				case 1:
					p, err := parsePortStrict(parts[0])
					if err != nil {
						return nil, err
					}
					ep.Port = p
					ep.Kind = "hostport"
				case 3:
					p, err := parsePortStrict(parts[0])
					if err != nil {
						return nil, err
					}
					ep.Port = p
					ep.Username = parts[1]
					ep.Password = parts[2]
					ep.HasAuth = true
					ep.Kind = "tuple4"
				default:
					return nil, errors.New("invalid IPv6 endpoint tuple")
				}
			default:
				return nil, errors.New("invalid trailing characters after IPv6 bracket")
			}
		} else if ip, err := netip.ParseAddr(raw); err == nil && ip.Is6() && ip.Zone() == "" {
			ep.Kind = "host"
			ep.Address = raw
		} else {
			parts := strings.SplitN(raw, ":", 4)
			switch len(parts) {
			case 1:
				ep.Kind = "host"
				ep.Address = parts[0]
			case 2:
				p, err := parsePortStrict(parts[1])
				if err != nil {
					return nil, err
				}
				ep.Kind = "hostport"
				ep.Address = parts[0]
				ep.Port = p
			case 4:
				p, err := parsePortStrict(parts[1])
				if err != nil {
					return nil, err
				}
				ep.Kind = "tuple4"
				ep.Address = parts[0]
				ep.Port = p
				ep.Username = parts[2]
				ep.Password = parts[3]
				ep.HasAuth = true
			default:
				return nil, errors.New("invalid endpoint format")
			}
		}
	}

	if !IsValidAddress(ep.Address) {
		return nil, fmt.Errorf("invalid address %q", ep.Address)
	}
	if ep.HasAuth && (ep.Username == "" || ep.Password == "" || hasControlByte(ep.Username) || hasControlByte(ep.Password)) {
		return nil, errors.New("invalid SOCKS5 credentials")
	}
	return ep, nil
}

// ExpandPresetRules expands comma-separated domain or IP rules with preset tokens
// (@ai, @stream, @tg for domain; @tg for ip) and preserves order while deduplicating.
func ExpandPresetRules(kind, csvInput string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	add := func(items ...string) {
		for _, it := range items {
			if _, ok := seen[it]; ok {
				continue
			}
			seen[it] = struct{}{}
			out = append(out, it)
		}
	}

	for _, tok := range strings.Split(csvInput, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "@") {
			lower := strings.ToLower(tok)
			if kind == "domain" {
				switch lower {
				case "@ai":
					add("geosite:openai", "geosite:anthropic", "domain:claude.ai", "domain:chatgpt.com", "domain:gemini.google.com", "domain:perplexity.ai", "domain:x.ai", "domain:grok.com")
				case "@stream":
					add("geosite:netflix", "geosite:disney", "geosite:youtube", "geosite:spotify", "geosite:tiktok", "geosite:hulu")
				case "@tg":
					add("geosite:telegram")
				default:
					return nil, fmt.Errorf("unknown domain preset %q (supported: @ai, @stream, @tg)", tok)
				}
			} else {
				switch lower {
				case "@tg":
					add("geoip:telegram")
				default:
					return nil, fmt.Errorf("unknown IP preset %q (supported: @tg)", tok)
				}
			}
			continue
		}
		if kind == "domain" {
			if !IsValidDomainRule(tok) {
				return nil, fmt.Errorf("invalid domain rule %q", tok)
			}
		} else {
			if !IsValidIPRule(tok) {
				return nil, fmt.Errorf("invalid IP/CIDR rule %q", tok)
			}
		}
		add(tok)
	}
	return out, nil
}

// FormatEndpoint formats address and port for display (bracketing IPv6 addresses).
func FormatEndpoint(address string, port int) string {
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
		return fmt.Sprintf("[%s]:%d", address, port)
	}
	return fmt.Sprintf("%s:%d", address, port)
}
