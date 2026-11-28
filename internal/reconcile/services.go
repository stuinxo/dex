package reconcile

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stuinxo/dex/internal/fsutil"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
)

type fileServiceRule struct {
	matches func(relName, targetPath string) bool
	service func(wgUnit string) string // "" means managed without triggering service restart
}

var managedFileServiceRules = []fileServiceRule{
	{
		matches: func(rel, dst string) bool {
			b := filepath.Base(dst)
			return rel == "xray.json" || rel == "systemd/dex-xray.service" || rel == "openrc/dex-xray" ||
				b == "xray.json" || b == "dex-xray.service" || dst == "/etc/init.d/dex-xray"
		},
		service: func(string) string { return "dex-xray" },
	},
	{
		matches: func(rel, dst string) bool {
			b := filepath.Base(dst)
			return rel == "nftables.conf" || rel == "systemd/dex-nft.service" || rel == "openrc/dex-nft" ||
				b == "nftables.conf" || b == "dex-nft.service" || dst == "/etc/init.d/dex-nft"
		},
		service: func(string) string { return "dex-nft" },
	},
	{
		matches: func(rel, dst string) bool {
			b := filepath.Base(dst)
			s := filepath.ToSlash(dst)
			return strings.HasPrefix(rel, "mosdns/") || rel == "systemd/dex-mosdns.service" || rel == "openrc/dex-mosdns" ||
				strings.Contains(s, "/mosdns/") || b == "dex-mosdns.service" || dst == "/etc/init.d/dex-mosdns"
		},
		service: func(string) string { return "dex-mosdns" },
	},
	{
		matches: func(rel, dst string) bool {
			return rel == "haproxy.cfg" || rel == "systemd/haproxy-limits.conf" ||
				dst == "/etc/haproxy/haproxy.cfg" || dst == "/etc/systemd/system/haproxy.service.d/dex-limits.conf"
		},
		service: func(string) string { return "haproxy" },
	},
	{
		matches: func(rel, dst string) bool {
			return rel == "nginx-dex.conf" || rel == "systemd/nginx-limits.conf" ||
				dst == "/etc/nginx/conf.d/dex-server.conf" || dst == "/etc/systemd/system/nginx.service.d/dex-limits.conf"
		},
		service: func(string) string { return "nginx" },
	},
	{
		matches: func(rel, dst string) bool {
			return rel == "wg0.conf" || dst == "/etc/wireguard/wg0.conf"
		},
		service: func(wgUnit string) string { return wgUnit },
	},
	{
		matches: func(rel, dst string) bool {
			return strings.HasPrefix(rel, "wg-peers/") || strings.Contains(filepath.ToSlash(dst), "/wg-peers/")
		},
		service: func(string) string { return "" },
	},
	{
		matches: func(rel, dst string) bool {
			b := filepath.Base(dst)
			return rel == "systemd/dex-doh.service" || rel == "openrc/dex-doh" ||
				b == "dex-doh.service" || dst == "/etc/init.d/dex-doh"
		},
		service: func(string) string { return "dex-doh" },
	},
	{
		matches: func(rel, dst string) bool {
			b := filepath.Base(dst)
			return rel == "systemd/dex-daemon.service" || rel == "openrc/dex-daemon" ||
				b == "dex-daemon.service" || dst == "/etc/init.d/dex-daemon"
		},
		service: func(string) string { return "dex-daemon" },
	},
	{
		matches: func(rel, dst string) bool {
			b := filepath.Base(dst)
			return rel == "systemd/dex-refresh.timer" || rel == "systemd/dex-refresh.service" ||
				b == "dex-refresh.timer" || b == "dex-refresh.service"
		},
		service: func(string) string { return "dex-refresh.timer" },
	},
	{
		matches: func(rel, dst string) bool {
			b := filepath.Base(dst)
			return rel == "systemd/dex-rules-update.timer" || rel == "systemd/dex-rules-update.service" ||
				b == "dex-rules-update.timer" || b == "dex-rules-update.service"
		},
		service: func(string) string { return "dex-rules-update.timer" },
	},
	{
		matches: func(rel, dst string) bool {
			b := filepath.Base(dst)
			return rel == "systemd/dex-core-update.timer" || rel == "systemd/dex-core-update.service" ||
				b == "dex-core-update.timer" || b == "dex-core-update.service"
		},
		service: func(string) string { return "dex-core-update.timer" },
	},
	{
		matches: func(rel, dst string) bool {
			return rel == "sysctl-99-dex.conf" || rel == "modules-99-dex.conf" ||
				dst == "/etc/sysctl.d/99-dex.conf" || dst == "/etc/modules-load.d/99-dex.conf"
		},
		service: func(string) string { return "" },
	},
}

// servicesForFile maps a rendered or removed managed file to the service(s) affected by it.
// Returns (nil, true) for files that intentionally do not trigger a service restart (e.g. sysctl,
// exported WireGuard client peer profiles). Returns (nil, false) for unmapped files so callers can
// conservatively restart active managed services.
func servicesForFile(relName, targetPath, wgUnit string) ([]string, bool) {
	for _, r := range managedFileServiceRules {
		if r.matches(relName, targetPath) {
			if svc := r.service(wgUnit); svc != "" {
				return []string{svc}, true
			}
			return nil, true
		}
	}
	return nil, false
}

func hasNFTTable(bundle *render.RenderBundle, tableName string) bool {
	if bundle == nil {
		return false
	}
	needle := []byte("table inet " + tableName + " {")
	for _, f := range bundle.Files {
		if f.RelName == "nftables.conf" {
			return bytes.Contains(f.Content, needle)
		}
	}
	return false
}

type touchedService struct {
	name      string
	wasActive bool
}

type svcSpec struct {
	name   string
	active bool
	probe  bool
}

type serviceOrchestrator struct {
	ctx                   context.Context
	store                 *state.Store
	exec                  SystemExecutor
	opts                  ApplyOptions
	st                    *state.State
	ropts                 render.RenderOptions
	bundle                *render.RenderBundle
	changedFiles          []changedFile
	obsoleteUnitPaths     []string
	certCreated           bool
	isOS                  bool
	wasResolvedActive     bool
	nftWasActive          bool
	prevNFTBytes          []byte
	touchedSvcs           []touchedService
	orderedSpecs          []svcSpec
	stoppedActiveSet      map[string]bool
	stoppedEnabledOnlySet map[string]bool
	res                   *ApplyResult
}

func newServiceOrchestrator(
	ctx context.Context,
	store *state.Store,
	exec SystemExecutor,
	opts ApplyOptions,
	st *state.State,
	ropts render.RenderOptions,
	bundle *render.RenderBundle,
	changedFiles []changedFile,
	obsoleteUnitPaths []string,
	certCreated bool,
	isOS bool,
	res *ApplyResult,
) *serviceOrchestrator {
	so := &serviceOrchestrator{
		ctx:                   ctx,
		store:                 store,
		exec:                  exec,
		opts:                  opts,
		st:                    st,
		ropts:                 ropts,
		bundle:                bundle,
		changedFiles:          changedFiles,
		obsoleteUnitPaths:     obsoleteUnitPaths,
		certCreated:           certCreated,
		isOS:                  isOS,
		nftWasActive:          exec.ServiceIsActive(ctx, ropts.InitSystem, "dex-nft"),
		stoppedActiveSet:      make(map[string]bool),
		stoppedEnabledOnlySet: make(map[string]bool),
		res:                   res,
	}
	for _, f := range bundle.Files {
		if f.RelName == "nftables.conf" {
			// Read previous nftables.conf backup (if any) before service switches so rollback can
			// distinguish newly introduced dex_* tables from pre-existing ones.
			diskNFT := fsutil.MapRootPrefix(opts.RootPrefix, f.TargetPath)
			so.prevNFTBytes, _ = os.ReadFile(diskNFT + ".prev")
			break
		}
	}
	return so
}

func (so *serviceOrchestrator) recordStoppedUnit(name string) {
	if so.exec.ServiceIsActive(so.ctx, so.ropts.InitSystem, name) {
		so.stoppedActiveSet[name] = true
		return
	}
	if so.isOS && so.ropts.InitSystem == "systemd" {
		if _, err := so.exec.RunCommand(so.ctx, nil, "systemctl", "is-enabled", "--quiet", name); err == nil {
			so.stoppedEnabledOnlySet[name] = true
		}
	}
}

func (so *serviceOrchestrator) applySysctlIfNeeded() {
	if !so.st.System.AutoTuneSysctl || so.ropts.IsContainer {
		return
	}
	if so.exec.HasCommand("modprobe") {
		for _, mod := range []string{"tcp_bbr", "nf_conntrack", "sch_cake"} {
			_, _ = so.exec.RunCommand(so.ctx, nil, "modprobe", mod)
		}
	}
	sysctlDisk := fsutil.MapRootPrefix(so.opts.RootPrefix, "/etc/sysctl.d/99-dex.conf")
	if _, err := os.Stat(sysctlDisk); err == nil && so.exec.HasCommand("sysctl") {
		_, _ = so.exec.RunCommand(so.ctx, nil, "sysctl", "-e", "-p", sysctlDisk)
		if qdiscOut, qerr := so.exec.RunCommand(so.ctx, nil, "sysctl", "-n", "net.core.default_qdisc"); qerr == nil {
			curQdisc := strings.TrimSpace(qdiscOut)
			if curQdisc != "" && curQdisc != "cake" && curQdisc != "fq" {
				_, _ = so.exec.RunCommand(so.ctx, nil, "sysctl", "-w", "net.core.default_qdisc=fq")
			}
		}
	}
}

func (so *serviceOrchestrator) apply() error {
	so.applySysctlIfNeeded()

	// Read original DNS config BEFORE stopping systemd-resolved so /run/systemd/resolve/resolv.conf is still available if /etc/resolv.conf is a 127.0.0.53 stub.
	var backupResolvBytes []byte
	if so.isOS && so.bundle.MosDNSNeeded {
		backupResolvBytes = readOriginalResolvConf(so.opts.RootPrefix)
	}

	// Stop/disable systemd-resolved on systemd hosts so it neither holds :53 nor bypasses /etc/resolv.conf via nss-resolve.
	if so.isOS && so.bundle.MosDNSNeeded && so.ropts.InitSystem == "systemd" {
		_ = os.Remove(fsutil.MapRootPrefix(so.opts.RootPrefix, "/etc/systemd/resolved.conf.d/99-dex.conf"))
		if so.exec.ServiceIsActive(so.ctx, "systemd", "systemd-resolved") {
			so.wasResolvedActive = true
			_ = so.exec.ServiceStopDisable(so.ctx, "systemd", "systemd-resolved")
		}
	}

	wgUnit := render.WireGuardUnitName(so.ropts.InitSystem)
	changedServices := make(map[string]bool)
	restartAllFallback := false
	nginxDropinChanged := false
	for _, cf := range so.changedFiles {
		if cf.relName == "systemd/nginx-limits.conf" || cf.targetPath == "/etc/systemd/system/nginx.service.d/dex-limits.conf" {
			nginxDropinChanged = true
		}
		svcs, known := servicesForFile(cf.relName, cf.targetPath, wgUnit)
		if !known {
			restartAllFallback = true
			continue
		}
		for _, svc := range svcs {
			changedServices[svc] = true
		}
	}
	if so.certCreated {
		changedServices["dex-xray"] = true
		changedServices["nginx"] = true
	}

	nftActive := so.bundle.NFTClientNeeded || so.bundle.NFTRelayNeeded || so.bundle.NFTHostFWNeeded
	specs := []svcSpec{
		{name: "dex-nft", active: nftActive, probe: nftActive},
		{name: "dex-mosdns", active: so.bundle.MosDNSNeeded, probe: so.bundle.MosDNSNeeded},
		{name: "dex-xray", active: so.bundle.XrayNeeded, probe: so.bundle.XrayNeeded},
		{name: "dex-doh", active: so.bundle.DoHNeeded, probe: so.bundle.DoHNeeded},
		{name: "haproxy", active: so.bundle.HAProxyNeeded, probe: so.bundle.HAProxyNeeded},
		{name: "nginx", active: so.bundle.NginxNeeded, probe: so.bundle.NginxNeeded},
		{name: wgUnit, active: so.bundle.WireGuardNeeded, probe: so.bundle.WireGuardNeeded},
	}
	if so.ropts.InitSystem == "systemd" {
		specs = append(specs,
			svcSpec{name: "dex-refresh.timer", active: so.bundle.RefreshTimerNeeded, probe: false},
			svcSpec{name: "dex-rules-update.timer", active: so.bundle.RulesTimerNeeded, probe: false},
			svcSpec{name: "dex-core-update.timer", active: so.bundle.CoreUpdateTimerNeeded, probe: false},
		)
	}
	so.orderedSpecs = specs

	// Stop/disable unneeded units (timers first) BEFORE deleting obsolete unit files or running daemon-reload.
	for i := len(specs) - 1; i >= 0; i-- {
		sp := specs[i]
		if !sp.active {
			so.recordStoppedUnit(sp.name)
			_ = so.exec.ServiceStopDisable(so.ctx, so.ropts.InitSystem, sp.name)
			so.res.ServicesOff = append(so.res.ServicesOff, sp.name)
		}
	}

	for _, oldUnit := range so.obsoleteUnitPaths {
		diskPath := fsutil.MapRootPrefix(so.opts.RootPrefix, oldUnit)
		_ = os.Remove(diskPath)
		if dir := filepath.Dir(diskPath); strings.HasSuffix(dir, ".service.d") {
			_ = os.Remove(dir)
		}
		so.res.FilesRemoved = append(so.res.FilesRemoved, oldUnit)
	}

	if err := so.exec.DaemonReload(so.ctx, so.ropts.InitSystem); err != nil {
		return fmt.Errorf("daemon reload: %w", err)
	}

	for _, sp := range specs {
		if !sp.active {
			continue
		}
		wasActive := so.exec.ServiceIsActive(so.ctx, so.ropts.InitSystem, sp.name)
		if so.opts.RestartAll || restartAllFallback || changedServices[sp.name] || !wasActive {
			so.touchedSvcs = append(so.touchedSvcs, touchedService{name: sp.name, wasActive: wasActive})
			if sp.name == "nginx" && wasActive && !so.opts.RestartAll && !nginxDropinChanged {
				if rerr := so.exec.ServiceReload(so.ctx, so.ropts.InitSystem, sp.name); rerr != nil {
					if err := so.exec.ServiceEnableStart(so.ctx, so.ropts.InitSystem, sp.name); err != nil {
						return err
					}
				}
			} else {
				if err := so.exec.ServiceEnableStart(so.ctx, so.ropts.InitSystem, sp.name); err != nil {
					return err
				}
			}
			so.res.ServicesRestarted = append(so.res.ServicesRestarted, sp.name)
		}
		so.res.ServicesOn = append(so.res.ServicesOn, sp.name)
	}

	if so.exec.HasCommand("nft") {
		for _, tbl := range render.ManagedNFTTables {
			if !hasNFTTable(so.bundle, tbl) {
				_, _ = so.exec.RunCommand(so.ctx, nil, "nft", "delete", "table", "inet", tbl)
			}
		}
	}
	if !so.bundle.NFTClientNeeded && so.isOS {
		CleanupTProxyPolicyRoutes(so.ctx, so.exec)
	}

	// Manage dex-daemon carefully: start if inactive, avoid self-restarting when already active (e.g. Web UI apply).
	if so.bundle.DaemonNeeded {
		if !so.exec.ServiceIsActive(so.ctx, so.ropts.InitSystem, "dex-daemon") {
			so.touchedSvcs = append(so.touchedSvcs, touchedService{name: "dex-daemon", wasActive: false})
			if err := so.exec.ServiceEnableStart(so.ctx, so.ropts.InitSystem, "dex-daemon"); err != nil {
				return err
			}
		}
		so.res.ServicesOn = append(so.res.ServicesOn, "dex-daemon")
	} else {
		so.recordStoppedUnit("dex-daemon")
		_ = so.exec.ServiceStopDisable(so.ctx, so.ropts.InitSystem, "dex-daemon")
		so.res.ServicesOff = append(so.res.ServicesOff, "dex-daemon")
	}

	if err := so.pollServicesActive(specs); err != nil {
		return err
	}

	if so.isOS && so.bundle.MosDNSNeeded {
		return switchToLocalResolvConf(so.ctx, so.opts.RootPrefix, so.store.Dir, backupResolvBytes)
	} else if so.isOS && !so.bundle.MosDNSNeeded {
		resolvPath := fsutil.MapRootPrefix(so.opts.RootPrefix, "/etc/resolv.conf")
		origPath := filepath.Join(so.store.Dir, "resolv.conf.orig")
		if rerr := restoreResolvConfIfNeeded(resolvPath, origPath); rerr != nil {
			so.res.Warnings = append(so.res.Warnings, fmt.Sprintf("restore /etc/resolv.conf: %v", rerr))
		}
	}
	return nil
}

func (so *serviceOrchestrator) pollServicesActive(specs []svcSpec) error {
	checkAllActive := func() error {
		for _, sp := range specs {
			if sp.active && sp.probe {
				if !so.exec.ServiceIsActive(so.ctx, so.ropts.InitSystem, sp.name) {
					return fmt.Errorf("service %s failed health check after start", sp.name)
				}
			}
		}
		if so.bundle.DaemonNeeded && !so.exec.ServiceIsActive(so.ctx, so.ropts.InitSystem, "dex-daemon") {
			return fmt.Errorf("service dex-daemon failed health check after start")
		}
		return nil
	}

	if !so.isOS {
		return checkAllActive()
	}
	deadline := time.Now().Add(2 * time.Second)
	time.Sleep(500 * time.Millisecond)
	for {
		if err := checkAllActive(); err == nil {
			time.Sleep(500 * time.Millisecond)
			return checkAllActive()
		} else if !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func (so *serviceOrchestrator) rollback(backups []fileBackup) {
	// 1. Stop/disable newly started services in reverse order BEFORE restoring unit files.
	for i := len(so.touchedSvcs) - 1; i >= 0; i-- {
		ts := so.touchedSvcs[i]
		if !ts.wasActive {
			_ = so.exec.ServiceStopDisable(so.ctx, so.ropts.InitSystem, ts.name)
		}
	}
	// Remove any dex_* nftables tables introduced by this failed apply.
	if so.exec.HasCommand("nft") {
		for _, tbl := range render.ManagedNFTTables {
			if !hasNFTTable(so.bundle, tbl) {
				continue
			}
			existedBefore := so.nftWasActive && bytes.Contains(so.prevNFTBytes, []byte("table inet "+tbl+" {"))
			if !existedBefore {
				_, _ = so.exec.RunCommand(so.ctx, nil, "nft", "delete", "table", "inet", tbl)
			}
		}
	}

	// 2. Restore backed-up config/unit files and reload init daemon.
	rollbackFileBackups(backups)
	_ = so.exec.DaemonReload(so.ctx, so.ropts.InitSystem)
	if so.wasResolvedActive {
		_ = so.exec.ServiceEnableStart(so.ctx, "systemd", "systemd-resolved")
	}

	// 3. Re-enable and start previously active services in forward dependency order.
	restoreStoppedUnit := func(name string) {
		if so.stoppedActiveSet[name] {
			_ = so.exec.ServiceEnableStart(so.ctx, so.ropts.InitSystem, name)
			return
		}
		if so.stoppedEnabledOnlySet[name] && so.ropts.InitSystem == "systemd" {
			_, _ = so.exec.RunCommand(so.ctx, nil, "systemctl", "enable", name)
		}
	}
	for _, sp := range so.orderedSpecs {
		if !strings.HasSuffix(sp.name, ".timer") {
			restoreStoppedUnit(sp.name)
		}
	}
	restoreStoppedUnit("dex-daemon")
	for _, sp := range so.orderedSpecs {
		if strings.HasSuffix(sp.name, ".timer") {
			restoreStoppedUnit(sp.name)
		}
	}

	// 4. Restart services that were already active before this apply and were restarted.
	for _, ts := range so.touchedSvcs {
		if ts.wasActive {
			_ = so.exec.ServiceRestart(so.ctx, so.ropts.InitSystem, ts.name)
		}
	}
}
