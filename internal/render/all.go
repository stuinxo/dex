package render

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/stuinxo/dex/internal/state"
)

func clientHasDomainTargets(s *state.State) bool {
	if s.Role != state.RoleClient {
		return false
	}
	isDomain := func(addr string) bool {
		addr = strings.Trim(strings.TrimSpace(addr), "[]")
		if addr == "" {
			return false
		}
		_, err := netip.ParseAddr(addr)
		return err != nil
	}
	for _, n := range s.Client.Nodes {
		if isDomain(n.Address) {
			return true
		}
	}
	if s.Client.RproxyC.Enabled && isDomain(s.Client.RproxyC.TunnelAddress) {
		return true
	}
	for _, rawDoH := range s.Client.DNS.DoHServers {
		if host := ExtractDoHHost(rawDoH); isDomain(host) {
			return true
		}
	}
	return false
}

// RenderAll deterministically compiles State into the full set of target config files and service flags.
func RenderAll(s *state.State, opts RenderOptions) (*RenderBundle, error) {
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("invalid state: %w", err)
	}
	opts = opts.WithDefaults()
	bundle := &RenderBundle{}

	if xrayBytes, needed, err := RenderXray(s, opts); err != nil {
		return nil, fmt.Errorf("render xray: %w", err)
	} else if needed {
		bundle.XrayNeeded = true
		bundle.Files = append(bundle.Files, RenderedFile{
			RelName:      "xray.json",
			TargetPath:   filepath.Join(opts.GeneratedDir, "xray.json"),
			Content:      xrayBytes,
			Mode:         0o640,
			ValidateKind: "xray",
		})
	}

	if nftBytes, cNeed, rNeed, fwNeed, err := RenderNFTables(s, opts); err != nil {
		return nil, fmt.Errorf("render nftables: %w", err)
	} else if cNeed || rNeed || fwNeed {
		bundle.NFTClientNeeded = cNeed
		bundle.NFTRelayNeeded = rNeed
		bundle.NFTHostFWNeeded = fwNeed
		bundle.Files = append(bundle.Files, RenderedFile{
			RelName:      "nftables.conf",
			TargetPath:   filepath.Join(opts.GeneratedDir, "nftables.conf"),
			Content:      nftBytes,
			Mode:         0o644,
			ValidateKind: "nft",
		})
	}

	if mosFiles, needed, err := RenderMosDNS(s, opts); err != nil {
		return nil, fmt.Errorf("render mosdns: %w", err)
	} else if needed {
		bundle.MosDNSNeeded = true
		bundle.Files = append(bundle.Files, mosFiles...)
	}

	if hapBytes, needed, err := RenderHAProxy(s); err != nil {
		return nil, fmt.Errorf("render haproxy: %w", err)
	} else if needed {
		bundle.HAProxyNeeded = true
		bundle.Files = append(bundle.Files, RenderedFile{
			RelName:      "haproxy.cfg",
			TargetPath:   "/etc/haproxy/haproxy.cfg",
			Content:      hapBytes,
			Mode:         0o644,
			ValidateKind: "haproxy",
		})
	}

	if ngBytes, needed, err := RenderNginx(s, opts); err != nil {
		return nil, fmt.Errorf("render nginx: %w", err)
	} else if needed {
		bundle.NginxNeeded = true
		bundle.Files = append(bundle.Files, RenderedFile{
			RelName:      "nginx-dex.conf",
			TargetPath:   "/etc/nginx/conf.d/dex-server.conf",
			Content:      ngBytes,
			Mode:         0o644,
			ValidateKind: "nginx",
		})
	}

	if s.Role == state.RoleServer && s.Server.TLSMode == "nginx" && s.Server.EnableDoH {
		bundle.DoHNeeded = true
	}
	bundle.DaemonNeeded = s.Role == state.RoleClient || s.Role == state.RoleServer
	bundle.RulesTimerNeeded = s.Role == state.RoleClient && s.System.AutoUpdateRules
	if bundle.NFTRelayNeeded {
		bundle.RefreshTimerNeeded = true
		bundle.RefreshInterval = "5min"
	} else if clientHasDomainTargets(s) {
		bundle.RefreshTimerNeeded = true
		bundle.RefreshInterval = "4h"
	}
	bundle.CoreUpdateTimerNeeded = s.System.AutoUpdateCore

	if wgFiles, needed, err := RenderWireGuard(s, opts); err != nil {
		return nil, fmt.Errorf("render wireguard: %w", err)
	} else if needed {
		bundle.WireGuardNeeded = true
		bundle.Files = append(bundle.Files, wgFiles...)
	}

	if sysctlFile, needed := RenderSysctl(s, opts); needed {
		bundle.Files = append(bundle.Files, sysctlFile)
	}
	if modFile, needed := RenderModulesLoad(s, opts); needed {
		bundle.Files = append(bundle.Files, modFile)
	}

	bundle.Files = append(bundle.Files, RenderUnits(s, opts, bundle)...)
	return bundle, nil
}
