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

	var b strings.Builder
	b.WriteString(`global
  maxconn 4096

defaults
  mode tcp
  timeout connect 10s
  timeout client  1h
  timeout server  1h
  timeout check   10s

resolvers dex_dns
  nameserver dns1 1.1.1.1:53
  nameserver dns2 8.8.8.8:53
  nameserver dns3 223.5.5.5:53
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
		if _, err := netip.ParseAddr(unbracketed); err == nil {
			fmt.Fprintf(&b, "\nfrontend ft_%d\n  bind :%d\n  default_backend bk_%d\n\nbackend bk_%d\n  server srv1 %s:%d check\n",
				r.ListenPort, r.ListenPort, r.ListenPort, r.ListenPort, host, r.TargetPort)
		} else {
			fmt.Fprintf(&b, "\nfrontend ft_%d\n  bind :%d\n  default_backend bk_%d\n\nbackend bk_%d\n  server srv1 %s:%d check resolvers dex_dns init-addr libc,none\n",
				r.ListenPort, r.ListenPort, r.ListenPort, r.ListenPort, host, r.TargetPort)
		}
	}
	return []byte(b.String()), true, nil
}
