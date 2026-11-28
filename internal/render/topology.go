package render

import "github.com/stuinxo/dex/internal/state"

// ManagedNFTTables is the authoritative list of inet nftables tables owned by dex.
var ManagedNFTTables = []string{
	"dex_client",
	"dex_filter",
	"dex_nat",
	"dex_flow",
	"dex_relay",
	"dex_host_fw",
}

// WireGuardUnitName returns the service unit name for WireGuard on initSystem ("systemd" or "openrc").
func WireGuardUnitName(initSystem string) string {
	if initSystem == "openrc" {
		return "wg-quick.wg0"
	}
	return "wg-quick@wg0"
}

// ServicePlan is the Single Source of Truth for which subsystems and systemd/OpenRC units
// a declarative State activates across render, reconcile, CLI status, and Web UI status.
type ServicePlan struct {
	Xray            bool
	NFTClient       bool
	NFTRelay        bool
	NFTHostFW       bool
	MosDNS          bool
	HAProxy         bool
	Nginx           bool
	DoH             bool
	WireGuard       bool
	Daemon          bool
	RulesTimer      bool
	RefreshTimer    bool
	RefreshInterval string // "5min" | "4h"
	CoreUpdateTimer bool
}

// NFTNeeded reports whether any dex nftables table (client, relay, or host firewall) is active.
func (p ServicePlan) NFTNeeded() bool {
	return p.NFTClient || p.NFTRelay || p.NFTHostFW
}

// ComputeServicePlan derives the exact active subsystem plan from s.
func ComputeServicePlan(s *state.State) ServicePlan {
	var p ServicePlan
	if s == nil {
		return p
	}

	hasXrayForward := false
	for _, fwd := range s.Relay.Forwards {
		switch fwd.Engine {
		case "nft":
			p.NFTRelay = true
		case "haproxy":
			p.HAProxy = true
		case "xray":
			hasXrayForward = true
		}
	}

	if s.Role == state.RoleClient {
		p.Xray = true
		p.NFTClient = true
		p.MosDNS = true
		p.WireGuard = s.Client.WireGuard.Enabled
	} else {
		p.Xray = s.Role == state.RoleServer || s.Role == state.RoleLanding ||
			hasXrayForward || s.RproxyS.Enabled || len(s.ExtraInbounds) > 0
		p.NFTHostFW = s.System.Firewall.Enabled
	}

	if s.Role == state.RoleServer && s.Server.TLSMode == "nginx" {
		p.Nginx = true
		if s.Server.EnableDoH {
			p.DoH = true
		}
	}
	for _, ex := range s.ExtraInbounds {
		if ex.ViaNginx {
			p.Nginx = true
			break
		}
	}

	p.Daemon = s.Role == state.RoleClient || s.Role == state.RoleServer
	p.RulesTimer = s.Role == state.RoleClient && s.System.AutoUpdateRules
	if p.NFTRelay {
		p.RefreshTimer = true
		p.RefreshInterval = "5min"
	} else if clientHasDomainTargets(s) {
		p.RefreshTimer = true
		p.RefreshInterval = "4h"
	}
	p.CoreUpdateTimer = s.System.AutoUpdateCore
	return p
}

// ManagedServiceUnits returns the ordered slice of core runtime service units expected for s.
func (p ServicePlan) ManagedServiceUnits(s *state.State, initSystem string) []string {
	var svcs []string
	if s == nil {
		return svcs
	}
	if s.Role == state.RoleClient {
		svcs = append(svcs, "dex-xray", "dex-mosdns", "dex-nft")
		if p.HAProxy {
			svcs = append(svcs, "haproxy")
		}
		if p.WireGuard {
			svcs = append(svcs, WireGuardUnitName(initSystem))
		}
	} else {
		if p.Xray {
			svcs = append(svcs, "dex-xray")
		}
		if p.NFTNeeded() {
			svcs = append(svcs, "dex-nft")
		}
		if p.HAProxy {
			svcs = append(svcs, "haproxy")
		}
		if p.Nginx {
			svcs = append(svcs, "nginx")
		}
		if p.DoH {
			svcs = append(svcs, "dex-doh")
		}
	}
	if p.Daemon {
		svcs = append(svcs, "dex-daemon")
	}
	return svcs
}
