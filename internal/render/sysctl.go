package render

import (
	"fmt"
	"strings"

	"github.com/stuinxo/dex/internal/state"
)

// RenderSysctl renders memory-adaptive, safe kernel tuning for routing/forwarding,
// BBR, CAKE, BDP socket buffers, low-latency TCP, and conntrack limits.
// Returns needed=false inside containers or when AutoTuneSysctl is disabled.
func RenderSysctl(s *state.State, opts RenderOptions) (RenderedFile, bool) {
	if !s.System.AutoTuneSysctl || opts.IsContainer {
		return RenderedFile{}, false
	}
	opts = opts.WithDefaults()

	maxBuf := 33554432
	ctMax := 1048576
	switch {
	case opts.MemMB < 256:
		maxBuf = 4194304
		ctMax = 65536
	case opts.MemMB < 1024:
		maxBuf = 16777216
		ctMax = 262144
	}

	rpFilter := 1
	if s.Role == state.RoleClient {
		rpFilter = 0 // Asymmetric TPROXY / policy routing requires loose/disabled rp_filter
	}

	var b strings.Builder
	b.WriteString("# Managed declaratively by dex v4.\n")

	// Base & file descriptors
	b.WriteString("vm.swappiness = 10\n")
	b.WriteString("fs.file-max = 1000000\n")
	b.WriteString("fs.inotify.max_user_instances = 8192\n")
	b.WriteString("fs.inotify.max_user_watches = 65536\n")

	// Queuing & congestion control:
	// - Client bypass gateway uses CAKE (with fq fallback) to combat LAN bufferbloat.
	// - VPS roles (server/landing/relay) use fq, BBR's native pacing qdisc, for lower CPU overhead and higher high-BDP throughput.
	b.WriteString("net.core.default_qdisc = fq\n")
	if s.Role == state.RoleClient {
		b.WriteString("net.core.default_qdisc = cake\n")
	}
	b.WriteString("net.ipv4.tcp_congestion_control = bbr\n")
	b.WriteString("net.core.somaxconn = 65535\n")
	b.WriteString("net.core.netdev_max_backlog = 65536\n")
	b.WriteString("net.core.netdev_budget = 600\n")
	b.WriteString("net.core.netdev_budget_usecs = 8000\n")

	// High-BDP socket buffers (memory-adaptive ceiling, moderate initial buffers)
	fmt.Fprintf(&b, "net.core.rmem_max = %d\n", maxBuf)
	fmt.Fprintf(&b, "net.core.wmem_max = %d\n", maxBuf)
	b.WriteString("net.core.optmem_max = 262144\n")
	fmt.Fprintf(&b, "net.ipv4.tcp_rmem = 4096 131072 %d\n", maxBuf)
	fmt.Fprintf(&b, "net.ipv4.tcp_wmem = 4096 65536 %d\n", maxBuf)
	b.WriteString("net.ipv4.udp_rmem_min = 16384\n")
	b.WriteString("net.ipv4.udp_wmem_min = 16384\n")

	// TCP low-latency & loss-resilience
	b.WriteString("net.ipv4.tcp_fastopen = 3\n")
	b.WriteString("net.ipv4.tcp_slow_start_after_idle = 0\n")
	b.WriteString("net.ipv4.tcp_mtu_probing = 1\n")
	b.WriteString("net.ipv4.tcp_notsent_lowat = 131072\n")
	b.WriteString("net.ipv4.tcp_max_syn_backlog = 32768\n")
	b.WriteString("net.ipv4.tcp_max_tw_buckets = 262144\n")
	b.WriteString("net.ipv4.tcp_tw_reuse = 1\n")
	b.WriteString("net.ipv4.tcp_fin_timeout = 15\n")
	b.WriteString("net.ipv4.tcp_keepalive_time = 600\n")
	b.WriteString("net.ipv4.tcp_keepalive_intvl = 30\n")
	b.WriteString("net.ipv4.tcp_keepalive_probes = 5\n")
	b.WriteString("net.ipv4.tcp_syncookies = 1\n")
	b.WriteString("net.ipv4.tcp_rfc1337 = 1\n")
	b.WriteString("net.ipv4.ip_local_port_range = 10240 65535\n")
	b.WriteString("net.mptcp.enabled = 1\n")

	// Routing, forwarding & security
	b.WriteString("net.ipv4.ip_forward = 1\n")
	b.WriteString("net.ipv4.conf.all.forwarding = 1\n")
	b.WriteString("net.ipv4.conf.default.forwarding = 1\n")
	b.WriteString("net.ipv4.conf.all.route_localnet = 1\n")
	fmt.Fprintf(&b, "net.ipv4.conf.all.rp_filter = %d\n", rpFilter)
	fmt.Fprintf(&b, "net.ipv4.conf.default.rp_filter = %d\n", rpFilter)
	b.WriteString("net.ipv4.conf.all.accept_redirects = 0\n")
	b.WriteString("net.ipv4.conf.default.accept_redirects = 0\n")
	b.WriteString("net.ipv4.conf.all.send_redirects = 0\n")
	b.WriteString("net.ipv4.conf.default.send_redirects = 0\n")
	b.WriteString("net.ipv4.conf.all.secure_redirects = 0\n")
	b.WriteString("net.ipv4.conf.default.secure_redirects = 0\n")
	if s.System.EnableIPv6 {
		b.WriteString("net.ipv6.conf.all.forwarding = 1\n")
		b.WriteString("net.ipv6.conf.default.forwarding = 1\n")
	} else {
		b.WriteString("net.ipv6.conf.all.forwarding = 0\n")
		b.WriteString("net.ipv6.conf.default.forwarding = 0\n")
	}

	// Conntrack capacity & timeout tuning
	fmt.Fprintf(&b, "net.netfilter.nf_conntrack_max = %d\n", ctMax)
	b.WriteString("net.netfilter.nf_conntrack_tcp_be_liberal = 1\n")
	b.WriteString("net.netfilter.nf_conntrack_tcp_timeout_established = 7200\n")
	b.WriteString("net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30\n")
	b.WriteString("net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30\n")
	b.WriteString("net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30\n")
	b.WriteString("net.netfilter.nf_conntrack_udp_timeout = 30\n")
	b.WriteString("net.netfilter.nf_conntrack_udp_timeout_stream = 180\n")

	return RenderedFile{
		RelName:    "sysctl-99-dex.conf",
		TargetPath: "/etc/sysctl.d/99-dex.conf",
		Content:    []byte(b.String()),
		Mode:       0o644,
	}, true
}

// RenderModulesLoad renders persistent kernel module loading for BBR, CAKE, and conntrack.
// Returns needed=false inside containers or when AutoTuneSysctl is disabled.
func RenderModulesLoad(s *state.State, opts RenderOptions) (RenderedFile, bool) {
	if !s.System.AutoTuneSysctl || opts.IsContainer {
		return RenderedFile{}, false
	}
	mods := "tcp_bbr\nnf_conntrack\n"
	if s.Role == state.RoleClient {
		mods = "tcp_bbr\nsch_cake\nnf_conntrack\n"
	}
	return RenderedFile{
		RelName:    "modules-99-dex.conf",
		TargetPath: "/etc/modules-load.d/99-dex.conf",
		Content:    []byte(mods),
		Mode:       0o644,
	}, true
}
