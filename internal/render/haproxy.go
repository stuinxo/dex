package render

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/stuinxo/dex/internal/state"
)

// RenderHAProxy generates a low-memory L4 TCP forwarding configuration with dynamic DNS resolution
// and health checks for relay forwards configured with engine="haproxy".
func RenderHAProxy(s *state.State) (data []byte, needed bool, err error) {
	var rules []state.ForwardRule
	for _, fwd := range s.Relay.Forwards {
		if fwd.Engine == "haproxy" {
			rules = append(rules, fwd)
		}
	}
	if len(rules) == 0 {
		return nil, false, nil
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ListenPort < rules[j].ListenPort
	})

	resolverDNS := `resolvers dex_dns
  nameserver dns1 1.1.1.1:53
  nameserver dns2 8.8.8.8:53
  nameserver dns3 223.5.5.5:53`
	if s.System.EnableIPv6 {
		resolverDNS = `resolvers dex_dns
  nameserver dns1 [2606:4700:4700::1111]:53
  nameserver dns2 [2001:4860:4860::8888]:53
  nameserver dns3 1.1.1.1:53
  nameserver dns4 8.8.8.8:53`
	}

	var b strings.Builder
	b.WriteString(`global
  maxconn 65535

defaults
  mode tcp
  option splice-auto
  option dontlognull
  timeout connect    5s
  timeout client     30m
  timeout server     30m
  timeout client-fin 30s
  timeout server-fin 30s
  timeout tunnel     1h
  timeout check      10s

` + resolverDNS + `
  resolve_retries 3
  timeout retry   3s
  hold valid      10s
`)

	for _, r := range rules {
		rawHost := strings.TrimSpace(r.TargetHost)
		unbracketed := strings.Trim(rawHost, "[]")
		host := rawHost
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
		bindSpec := fmt.Sprintf(":%d", r.ListenPort)
		if s.System.EnableIPv6 {
			bindSpec = fmt.Sprintf(":::%d v4v6", r.ListenPort)
		}
		if _, err := netip.ParseAddr(unbracketed); err == nil {
			fmt.Fprintf(&b, "\nfrontend ft_%d\n  bind %s\n  default_backend bk_%d\n\nbackend bk_%d\n  server srv1 %s:%d check\n",
				r.ListenPort, bindSpec, r.ListenPort, r.ListenPort, host, r.TargetPort)
		} else {
			fmt.Fprintf(&b, "\nfrontend ft_%d\n  bind %s\n  default_backend bk_%d\n\nbackend bk_%d\n  server srv1 %s:%d check resolvers dex_dns init-addr libc,none\n",
				r.ListenPort, bindSpec, r.ListenPort, r.ListenPort, host, r.TargetPort)
		}
	}
	return []byte(b.String()), true, nil
}
