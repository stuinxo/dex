package render

import (
	"fmt"
	"path/filepath"

	"github.com/stuinxo/dex/internal/state"
)

// RenderUnits renders systemd units or OpenRC init scripts for active dex v3 services.
func RenderUnits(s *state.State, opts RenderOptions, b *RenderBundle) []RenderedFile {
	opts = opts.WithDefaults()
	var out []RenderedFile

	xrayConf := filepath.Join(opts.GeneratedDir, "xray.json")
	mosdnsConf := filepath.Join(opts.GeneratedDir, "mosdns", "mosdns.yaml")
	nftConf := filepath.Join(opts.GeneratedDir, "nftables.conf")
	memLimit := opts.GoMemLimit()

	dohUpstreams := "1.1.1.1:53,8.8.8.8:53,127.0.0.53:53,127.0.0.1:53"
	if s.System.EnableIPv6 {
		dohUpstreams = "[2606:4700:4700::1111]:53,[2001:4860:4860::8888]:53,1.1.1.1:53,8.8.8.8:53,127.0.0.53:53,127.0.0.1:53"
	}

	if opts.InitSystem == "openrc" {
		if b.XrayNeeded {
			caps := "cap_net_bind_service"
			if s.Role == state.RoleClient {
				caps = "cap_net_bind_service,cap_net_admin,cap_net_raw"
			}
			_ = caps
			script := fmt.Sprintf(`#!/sbin/openrc-run
description="DEX Xray Core"
command="%s"
command_args="run -c %s"
command_background=true
pidfile="/run/dex-xray.pid"
rc_ulimit="-n 1000000"
output_log="/var/log/dex-xray.log"
error_log="/var/log/dex-xray.log"

depend() {
  need net
}

start_pre() {
  [ -s %s ] || return 1
  export GOMEMLIMIT="%s"
  export XRAY_LOCATION_ASSET="%s/rules"
}
`, opts.XrayBin, xrayConf, xrayConf, memLimit, opts.StateDir)
			out = append(out, RenderedFile{
				RelName:    "openrc/dex-xray",
				TargetPath: "/etc/init.d/dex-xray",
				Content:    []byte(script),
				Mode:       0o755,
			})
		}

		if b.MosDNSNeeded {
			script := fmt.Sprintf(`#!/sbin/openrc-run
description="DEX MosDNS Split Resolver"
command="%s"
command_args="start -c %s"
command_background=true
pidfile="/run/dex-mosdns.pid"
rc_ulimit="-n 65535"
output_log="/var/log/dex-mosdns.log"
error_log="/var/log/dex-mosdns.log"

depend() {
  need net
}

start_pre() {
  [ -s %s ] || return 1
  export GOMEMLIMIT="%s"
}
`, opts.MosDNSBin, mosdnsConf, mosdnsConf, memLimit)
			out = append(out, RenderedFile{
				RelName:    "openrc/dex-mosdns",
				TargetPath: "/etc/init.d/dex-mosdns",
				Content:    []byte(script),
				Mode:       0o755,
			})
		}

		if b.NFTClientNeeded || b.NFTRelayNeeded {
			tproxyStart := ""
			tproxyStop := ""
			if b.NFTClientNeeded {
				tproxyStart = `
  ip route replace local default dev lo scope host table 220
  ip rule list priority 100 | grep -Fq "fwmark 0x9 lookup 220" || ip rule add fwmark 0x9 table 220 priority 100`
				if s.System.EnableIPv6 {
					tproxyStart += `
  ip -6 route replace local default dev lo table 220
  ip -6 rule list priority 100 | grep -Fq "fwmark 0x9 lookup 220" || ip -6 rule add fwmark 0x9 table 220 priority 100`
				}
				tproxyStop = `
  ip rule del fwmark 0x9 table 220 priority 100 2>/dev/null || true
  ip route del local default dev lo table 220 2>/dev/null || true
  ip -6 rule del fwmark 0x9 table 220 priority 100 2>/dev/null || true
  ip -6 route del local default dev lo table 220 2>/dev/null || true`
			}
			script := fmt.Sprintf(`#!/sbin/openrc-run
description="DEX nftables Rules"
depend() {
  need net
}
start() {
  ebegin "Loading dex nftables"
  [ -s %s ] && nft -f %s%s
  eend $?
}
stop() {
  ebegin "Stopping dex nftables"
  nft delete table inet dex_client 2>/dev/null || true
  nft delete table inet dex_filter 2>/dev/null || true
  nft delete table inet dex_nat 2>/dev/null || true
  nft delete table inet dex_flow 2>/dev/null || true
  nft delete table inet dex_relay 2>/dev/null || true%s
  eend 0
}
`, nftConf, nftConf, tproxyStart, tproxyStop)
			out = append(out, RenderedFile{
				RelName:    "openrc/dex-nft",
				TargetPath: "/etc/init.d/dex-nft",
				Content:    []byte(script),
				Mode:       0o755,
			})
		}

		if b.DoHNeeded {
			script := fmt.Sprintf(`#!/sbin/openrc-run
description="DEX RFC 8484 DoH Server"
command="%s"
command_args="serve-doh --listen 127.0.0.1:9853 --upstream %s --path /dq"
command_background=true
pidfile="/run/dex-doh.pid"
rc_ulimit="-n 65535"
depend() { need net; }
`, opts.DexBin, dohUpstreams)
			out = append(out, RenderedFile{
				RelName:    "openrc/dex-doh",
				TargetPath: "/etc/init.d/dex-doh",
				Content:    []byte(script),
				Mode:       0o755,
			})
		}

		if s.Role == state.RoleClient || s.Role == state.RoleServer {
			script := fmt.Sprintf(`#!/sbin/openrc-run
description="DEX Control Plane Daemon"
command="%s"
command_args="--state-dir %s daemon"
command_background=true
pidfile="/run/dex-daemon.pid"
rc_ulimit="-n 65535"
output_log="/var/log/dex-daemon.log"
error_log="/var/log/dex-daemon.log"
depend() { need net; }
`, opts.DexBin, opts.StateDir)
			out = append(out, RenderedFile{
				RelName:    "openrc/dex-daemon",
				TargetPath: "/etc/init.d/dex-daemon",
				Content:    []byte(script),
				Mode:       0o755,
			})
		}
		return out
	}

	// Default: systemd units
	if b.XrayNeeded {
		caps := "CAP_NET_BIND_SERVICE"
		if s.Role == state.RoleClient {
			caps = "CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW"
		}
		if opts.IsContainer {
			caps = ""
		}
		capLines := ""
		if caps != "" {
			capLines = fmt.Sprintf("AmbientCapabilities=%s\nCapabilityBoundingSet=%s\n", caps, caps)
		}
		unit := fmt.Sprintf(`[Unit]
Description=DEX Xray Core
After=network-online.target nss-lookup.target
Wants=network-online.target
ConditionFileNotEmpty=%s

[Service]
Type=simple
Environment="GOMEMLIMIT=%s"
Environment="XRAY_LOCATION_ASSET=%s/rules"
ExecStart=%s run -c %s
Restart=on-failure
RestartSec=2
RestartPreventExitStatus=23
%sNoNewPrivileges=true
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
`, xrayConf, memLimit, opts.StateDir, opts.XrayBin, xrayConf, capLines)
		out = append(out, RenderedFile{
			RelName:    "systemd/dex-xray.service",
			TargetPath: "/etc/systemd/system/dex-xray.service",
			Content:    []byte(unit),
			Mode:       0o644,
		})
	}

	if b.MosDNSNeeded {
		unit := fmt.Sprintf(`[Unit]
Description=DEX MosDNS Split Resolver
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=%s

[Service]
Type=simple
Environment="GOMEMLIMIT=%s"
ExecStart=%s start -c %s
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, mosdnsConf, memLimit, opts.MosDNSBin, mosdnsConf)
		out = append(out, RenderedFile{
			RelName:    "systemd/dex-mosdns.service",
			TargetPath: "/etc/systemd/system/dex-mosdns.service",
			Content:    []byte(unit),
			Mode:       0o644,
		})
	}

	if b.NFTClientNeeded || b.NFTRelayNeeded {
		tproxyStart := ""
		tproxyStop := ""
		if b.NFTClientNeeded {
			tproxyStart = "\nExecStart=/usr/sbin/ip route replace local default dev lo scope host table 220\nExecStart=/bin/sh -c '/usr/sbin/ip rule list priority 100 | grep -Fq \"fwmark 0x9 lookup 220\" || /usr/sbin/ip rule add fwmark 0x9 table 220 priority 100'"
			if s.System.EnableIPv6 {
				tproxyStart += "\nExecStart=/usr/sbin/ip -6 route replace local default dev lo table 220\nExecStart=/bin/sh -c '/usr/sbin/ip -6 rule list priority 100 | grep -Fq \"fwmark 0x9 lookup 220\" || /usr/sbin/ip -6 rule add fwmark 0x9 table 220 priority 100'"
				tproxyStop = "\nExecStop=/bin/sh -c '/usr/sbin/ip rule del fwmark 0x9 table 220 priority 100 2>/dev/null || true; /usr/sbin/ip route del local default dev lo table 220 2>/dev/null || true; /usr/sbin/ip -6 rule del fwmark 0x9 table 220 priority 100 2>/dev/null || true; /usr/sbin/ip -6 route del local default dev lo table 220 2>/dev/null || true'"
			} else {
				tproxyStop = "\nExecStop=/bin/sh -c '/usr/sbin/ip rule del fwmark 0x9 table 220 priority 100 2>/dev/null || true; /usr/sbin/ip route del local default dev lo table 220 2>/dev/null || true'"
			}
		}
		unit := fmt.Sprintf(`[Unit]
Description=DEX nftables Rules
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=%s

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f %s%s
ExecStop=/bin/sh -c 'nft delete table inet dex_client 2>/dev/null || true; nft delete table inet dex_filter 2>/dev/null || true; nft delete table inet dex_nat 2>/dev/null || true; nft delete table inet dex_flow 2>/dev/null || true; nft delete table inet dex_relay 2>/dev/null || true'%s

[Install]
WantedBy=multi-user.target
`, nftConf, nftConf, tproxyStart, tproxyStop)
		out = append(out, RenderedFile{
			RelName:    "systemd/dex-nft.service",
			TargetPath: "/etc/systemd/system/dex-nft.service",
			Content:    []byte(unit),
			Mode:       0o644,
		})
	}

	if b.DoHNeeded {
		unit := fmt.Sprintf(`[Unit]
Description=DEX RFC 8484 DoH Server
After=network.target

[Service]
Type=simple
ExecStart=%s serve-doh --listen 127.0.0.1:9853 --upstream %s --path /dq
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, opts.DexBin, dohUpstreams)
		out = append(out, RenderedFile{
			RelName:    "systemd/dex-doh.service",
			TargetPath: "/etc/systemd/system/dex-doh.service",
			Content:    []byte(unit),
			Mode:       0o644,
		})
	}

	if s.Role == state.RoleClient || s.Role == state.RoleServer {
		unit := fmt.Sprintf(`[Unit]
Description=DEX Control Plane & Web UI Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s --state-dir %s daemon
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, opts.DexBin, opts.StateDir)
		out = append(out, RenderedFile{
			RelName:    "systemd/dex-daemon.service",
			TargetPath: "/etc/systemd/system/dex-daemon.service",
			Content:    []byte(unit),
			Mode:       0o644,
		})
	}

	if b.NginxNeeded {
		out = append(out, RenderedFile{
			RelName:    "systemd/nginx-limits.conf",
			TargetPath: "/etc/systemd/system/nginx.service.d/dex-limits.conf",
			Content:    []byte("[Service]\nLimitNOFILE=1000000\n"),
			Mode:       0o644,
		})
	}

	if b.HAProxyNeeded {
		out = append(out, RenderedFile{
			RelName:    "systemd/haproxy-limits.conf",
			TargetPath: "/etc/systemd/system/haproxy.service.d/dex-limits.conf",
			Content:    []byte("[Service]\nLimitNOFILE=1000000\n"),
			Mode:       0o644,
		})
	}

	if b.RefreshTimerNeeded {
		interval := b.RefreshInterval
		if interval == "" {
			interval = "5min"
		}
		desc := "DEX Dynamic DNS Refresh"
		timerDesc := fmt.Sprintf("Refresh DEX DNS every %s", interval)
		svc := fmt.Sprintf(`[Unit]
Description=%s

[Service]
Type=oneshot
ExecStart=%s --state-dir %s refresh
`, desc, opts.DexBin, opts.StateDir)
		timer := fmt.Sprintf(`[Unit]
Description=%s

[Timer]
OnActiveSec=%s
OnUnitActiveSec=%s

[Install]
WantedBy=timers.target
`, timerDesc, interval, interval)
		out = append(out,
			RenderedFile{
				RelName:    "systemd/dex-refresh.service",
				TargetPath: "/etc/systemd/system/dex-refresh.service",
				Content:    []byte(svc),
				Mode:       0o644,
			},
			RenderedFile{
				RelName:    "systemd/dex-refresh.timer",
				TargetPath: "/etc/systemd/system/dex-refresh.timer",
				Content:    []byte(timer),
				Mode:       0o644,
			},
		)
	}

	if b.CoreUpdateTimerNeeded {
		svc := fmt.Sprintf(`[Unit]
Description=DEX Weekly Core Components Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s --state-dir %s update --component all
`, opts.DexBin, opts.StateDir)
		timer := `[Unit]
Description=Weekly DEX Core Update Timer

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
`
		out = append(out,
			RenderedFile{
				RelName:    "systemd/dex-core-update.service",
				TargetPath: "/etc/systemd/system/dex-core-update.service",
				Content:    []byte(svc),
				Mode:       0o644,
			},
			RenderedFile{
				RelName:    "systemd/dex-core-update.timer",
				TargetPath: "/etc/systemd/system/dex-core-update.timer",
				Content:    []byte(timer),
				Mode:       0o644,
			},
		)
	}

	if b.RulesTimerNeeded {
		svc := fmt.Sprintf(`[Unit]
Description=DEX Weekly GeoIP/Domain Rules Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s --state-dir %s rules update
`, opts.DexBin, opts.StateDir)
		timer := `[Unit]
Description=Weekly DEX Rules Update Timer

[Timer]
OnCalendar=weekly
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
`
		out = append(out,
			RenderedFile{
				RelName:    "systemd/dex-rules-update.service",
				TargetPath: "/etc/systemd/system/dex-rules-update.service",
				Content:    []byte(svc),
				Mode:       0o644,
			},
			RenderedFile{
				RelName:    "systemd/dex-rules-update.timer",
				TargetPath: "/etc/systemd/system/dex-rules-update.timer",
				Content:    []byte(timer),
				Mode:       0o644,
			},
		)
	}

	return out
}
