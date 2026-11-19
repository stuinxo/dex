package render

import (
	"fmt"
	"strings"

	"github.com/stuinxo/de_GWD/v3/internal/state"
)

// RenderSysctl renders minimal, safe kernel tuning for routing/forwarding, BBR, and CAKE.
// Returns needed=false inside containers or when AutoTuneSysctl is disabled.
func RenderSysctl(s *state.State, opts RenderOptions) (RenderedFile, bool) {
	if !s.System.AutoTuneSysctl || opts.IsContainer {
		return RenderedFile{}, false
	}

	rpFilter := 1
	if s.Role == state.RoleClient {
		rpFilter = 0 // Asymmetric TPROXY / policy routing requires loose/disabled rp_filter
	}

	var b strings.Builder
	b.WriteString("# Managed declaratively by dex v3.\n")
	b.WriteString("vm.swappiness = 10\n")
	b.WriteString("fs.file-max = 1000000\n")
	b.WriteString("net.core.default_qdisc = cake\n")
	b.WriteString("net.ipv4.tcp_congestion_control = bbr\n")
	b.WriteString("net.ipv4.ip_forward = 1\n")
	b.WriteString("net.ipv4.conf.all.forwarding = 1\n")
	b.WriteString("net.ipv4.conf.default.forwarding = 1\n")
	b.WriteString("net.ipv4.conf.all.route_localnet = 1\n")
	fmt.Fprintf(&b, "net.ipv4.conf.all.rp_filter = %d\n", rpFilter)
	fmt.Fprintf(&b, "net.ipv4.conf.default.rp_filter = %d\n", rpFilter)
	b.WriteString("net.ipv4.conf.all.accept_redirects = 0\n")
	b.WriteString("net.ipv4.conf.all.send_redirects = 0\n")
	b.WriteString("net.core.somaxconn = 65535\n")
	b.WriteString("net.ipv4.tcp_fastopen = 3\n")
	b.WriteString("net.ipv4.tcp_slow_start_after_idle = 0\n")
	if s.System.EnableIPv6 {
		b.WriteString("net.ipv6.conf.all.forwarding = 1\n")
	}

	return RenderedFile{
		RelName:    "sysctl-99-dex.conf",
		TargetPath: "/etc/sysctl.d/99-dex.conf",
		Content:    []byte(b.String()),
		Mode:       0o644,
	}, true
}
