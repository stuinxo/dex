package reconcile

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stuinxo/de_GWD/v3/internal/cert"
	"github.com/stuinxo/de_GWD/v3/internal/render"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

// ApplyOptions controls transactional reconciliation behavior.
type ApplyOptions struct {
	Force       bool
	DryRun      bool
	RestartAll  bool                 // force restarting all active managed services regardless of file diffs
	PreserveTxn bool                 // caller already opened BeginTxn before mutating state
	RootPrefix  string               // optional directory prefix (primarily for isolated tests)
	RenderOpts  render.RenderOptions // overrides for rendered paths/runtime
}

// UpdateAndReconcile atomically snapshots state.json, runs mutator, saves state, and reconciles;
// any failure rolls back both rendered config files and state.json to the pre-mutator snapshot.
func UpdateAndReconcile(
	ctx context.Context,
	store *state.Store,
	defaultRole string,
	exec SystemExecutor,
	opts ApplyOptions,
	mutator func(*state.State) error,
) (*state.State, *ApplyResult, error) {
	var (
		updated *state.State
		res     *ApplyResult
	)
	err := store.WithApplyLock(ctx, func() error {
		if err := store.BeginTxn(); err != nil {
			return fmt.Errorf("begin txn: %w", err)
		}
		var uerr error
		updated, uerr = store.Update(defaultRole, mutator)
		if uerr != nil {
			_, _ = store.RollbackTxn()
			return uerr
		}
		opts.PreserveTxn = true
		var rerr error
		res, rerr = reconcileUnlocked(ctx, store, exec, opts)
		return rerr
	})
	if err != nil {
		return nil, nil, err
	}
	return updated, res, nil
}

// ApplyResult summarizes the outcome of Reconcile.
type ApplyResult struct {
	Bundle            *render.RenderBundle
	FilesWritten      []string
	FilesRemoved      []string
	ServicesOn        []string
	ServicesRestarted []string
	ServicesOff       []string
	Warnings          []string
}

type changedFile struct {
	relName    string
	targetPath string
}

// servicesForFile maps a rendered or removed managed file to the service(s) affected by it.
// Returns (nil, true) for files that intentionally do not trigger a service restart (e.g. sysctl,
// exported WireGuard client peer profiles). Returns (nil, false) for unmapped files so callers can
// conservatively restart active managed services.
// Note: if a prior apply crashed after promoting files onto disk but before restarting services,
// the next apply will see matching file contents and skip restarts unless --restart-all is passed.
func servicesForFile(relName, targetPath, wgUnit string) ([]string, bool) {
	switch {
	case relName == "xray.json" || relName == "systemd/dex-xray.service" || relName == "openrc/dex-xray":
		return []string{"dex-xray"}, true
	case relName == "nftables.conf" || relName == "systemd/dex-nft.service" || relName == "openrc/dex-nft":
		return []string{"dex-nft"}, true
	case strings.HasPrefix(relName, "mosdns/") || relName == "systemd/dex-mosdns.service":
		return []string{"dex-mosdns"}, true
	case relName == "haproxy.cfg":
		return []string{"haproxy"}, true
	case relName == "nginx-dex.conf":
		return []string{"nginx"}, true
	case relName == "wg0.conf":
		return []string{wgUnit}, true
	case strings.HasPrefix(relName, "wg-peers/"):
		// Client peer profiles are only exported artifacts; wg0.conf drives wg-quick@wg0.
		return nil, true
	case relName == "systemd/dex-doh.service" || relName == "openrc/dex-doh":
		return []string{"dex-doh"}, true
	case relName == "systemd/dex-daemon.service" || relName == "openrc/dex-daemon":
		return []string{"dex-daemon"}, true
	case relName == "systemd/dex-refresh.timer" || relName == "systemd/dex-refresh.service":
		return []string{"dex-refresh.timer"}, true
	case relName == "systemd/dex-rules-update.timer" || relName == "systemd/dex-rules-update.service":
		return []string{"dex-rules-update.timer"}, true
	case relName == "sysctl-99-dex.conf":
		return nil, true
	}

	// Fallback by TargetPath (used primarily for obsolete files removed from prevManifest).
	base := filepath.Base(targetPath)
	slash := filepath.ToSlash(targetPath)
	switch {
	case base == "xray.json" || base == "dex-xray.service" || targetPath == "/etc/init.d/dex-xray":
		return []string{"dex-xray"}, true
	case base == "nftables.conf" || base == "dex-nft.service" || targetPath == "/etc/init.d/dex-nft":
		return []string{"dex-nft"}, true
	case strings.Contains(slash, "/mosdns/") || base == "dex-mosdns.service":
		return []string{"dex-mosdns"}, true
	case targetPath == "/etc/haproxy/haproxy.cfg":
		return []string{"haproxy"}, true
	case targetPath == "/etc/nginx/conf.d/dex-server.conf":
		return []string{"nginx"}, true
	case targetPath == "/etc/wireguard/wg0.conf":
		return []string{wgUnit}, true
	case strings.Contains(slash, "/wg-peers/"):
		return nil, true
	case base == "dex-doh.service" || targetPath == "/etc/init.d/dex-doh":
		return []string{"dex-doh"}, true
	case base == "dex-daemon.service" || targetPath == "/etc/init.d/dex-daemon":
		return []string{"dex-daemon"}, true
	case base == "dex-refresh.timer" || base == "dex-refresh.service":
		return []string{"dex-refresh.timer"}, true
	case base == "dex-rules-update.timer" || base == "dex-rules-update.service":
		return []string{"dex-rules-update.timer"}, true
	case targetPath == "/etc/sysctl.d/99-dex.conf":
		return nil, true
	default:
		// Unknown file ownership: conservatively restart active managed services.
		return nil, false
	}
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

type fileBackup struct {
	diskPath string
	prevPath string
	existed  bool
	mode     os.FileMode
}

func mapTargetPath(rootPrefix, targetPath string) string {
	if rootPrefix == "" {
		return targetPath
	}
	clean := strings.TrimPrefix(filepath.Clean(targetPath), string(filepath.Separator))
	return filepath.Join(rootPrefix, clean)
}

func readChnRouteFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func populateRenderOptions(ctx context.Context, st *state.State, store *state.Store, exec SystemExecutor, opts ApplyOptions) (render.RenderOptions, []string) {
	ropts := opts.RenderOpts
	if ropts.StateDir == "" {
		ropts.StateDir = store.Dir
	}
	if ropts.GeneratedDir == "" {
		ropts.GeneratedDir = store.GeneratedDir()
	}
	if ropts.CertFile == "" {
		ropts.CertFile = store.DefaultCert()
	}
	if ropts.KeyFile == "" {
		ropts.KeyFile = store.DefaultKey()
	}
	ropts = ropts.WithDefaults()

	if ropts.InitSystem == "" || opts.RenderOpts.InitSystem == "" {
		ropts.InitSystem = exec.DetectInitSystem()
	}
	if !opts.RenderOpts.IsContainer {
		ropts.IsContainer = exec.DetectIsContainer()
	}
	if opts.RenderOpts.MemMB <= 0 {
		ropts.MemMB = exec.DetectMemMB()
	}
	if len(ropts.PhysicalNICs) == 0 {
		ropts.PhysicalNICs = exec.DetectPhysicalNICs()
	}
	if len(ropts.ChnRouteCIDRs) == 0 {
		ropts.ChnRouteCIDRs = readChnRouteFile(ropts.ChnRoutePath)
	}
	if ropts.ResolvedHostIPs == nil {
		ropts.ResolvedHostIPs = make(map[string][]netip.Addr)
	}

	var warnings []string
	resolveHost := func(h string) {
		h = strings.Trim(strings.TrimSpace(h), "[]")
		if h == "" {
			return
		}
		if _, exists := ropts.ResolvedHostIPs[h]; exists {
			return
		}
		if ip, err := netip.ParseAddr(h); err == nil {
			ropts.ResolvedHostIPs[h] = []netip.Addr{ip}
			return
		}
		ips, err := exec.ResolveHostIPs(ctx, h)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("resolve %s: %v", h, err))
			return
		}
		if len(ips) > 0 {
			ropts.ResolvedHostIPs[h] = ips
		}
	}

	if st.Role == state.RoleClient {
		for _, n := range st.Client.Nodes {
			resolveHost(n.Address)
		}
		if st.Client.RproxyC.Enabled {
			resolveHost(st.Client.RproxyC.TunnelAddress)
		}
		for _, rawDoH := range st.Client.DNS.DoHServers {
			if host := render.ExtractDoHHost(rawDoH); host != "" {
				resolveHost(host)
			}
		}
	}
	for _, fwd := range st.Relay.Forwards {
		if fwd.Engine == "nft" {
			resolveHost(fwd.TargetHost)
		}
	}

	return ropts, warnings
}

func writeBytesExact(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func probeLocalDNS(ctx context.Context, addr string) error {
	// Minimal DNS A query for "localhost." with TXID 0x4458 ("DX")
	var pkt []byte
	pkt = binary.BigEndian.AppendUint16(pkt, 0x4458)
	pkt = binary.BigEndian.AppendUint16(pkt, 0x0100) // RD=1
	pkt = binary.BigEndian.AppendUint16(pkt, 1)      // QDCOUNT=1
	pkt = append(pkt, 0, 0, 0, 0, 0, 0)
	pkt = append(pkt, 9)
	pkt = append(pkt, []byte("localhost")...)
	pkt = append(pkt, 0, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN

	dctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := dctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(pkt); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n < 12 || binary.BigEndian.Uint16(buf[:2]) != 0x4458 {
		return fmt.Errorf("invalid DNS probe reply (%d bytes)", n)
	}
	return nil
}

func preflightValidate(ctx context.Context, exec SystemExecutor, ropts render.RenderOptions, stagedPaths map[string]string, files []render.RenderedFile) error {
	for _, f := range files {
		staged := stagedPaths[f.TargetPath]
		switch f.ValidateKind {
		case "xray":
			if exec.HasCommand(ropts.XrayBin) {
				env := []string{"XRAY_LOCATION_ASSET=" + filepath.Join(ropts.StateDir, "rules")}
				if out, err := exec.RunCommand(ctx, env, ropts.XrayBin, "run", "-test", "-format", "json", "-c", staged); err != nil {
					return fmt.Errorf("xray config validation failed: %w (%s)", err, strings.TrimSpace(out))
				}
			}
		case "nft":
			if exec.HasCommand("nft") {
				if out, err := exec.RunCommand(ctx, nil, "nft", "-c", "-f", staged); err != nil {
					return fmt.Errorf("nftables validation failed: %w (%s)", err, strings.TrimSpace(out))
				}
			}
		case "haproxy":
			if exec.HasCommand("haproxy") {
				if out, err := exec.RunCommand(ctx, nil, "haproxy", "-c", "-f", staged); err != nil {
					return fmt.Errorf("haproxy validation failed: %w (%s)", err, strings.TrimSpace(out))
				}
			}
		}
	}
	return nil
}

// Reconcile executes the full declarative transaction:
// BeginTxn -> Resolve -> Render -> CheckManifest -> Stage & PreFlight -> Backup & AtomicSwap -> Sysctl & Services -> Probe -> Commit/Rollback.
func Reconcile(ctx context.Context, store *state.Store, exec SystemExecutor, opts ApplyOptions) (*ApplyResult, error) {
	if opts.DryRun || opts.PreserveTxn {
		return reconcileUnlocked(ctx, store, exec, opts)
	}
	var res *ApplyResult
	err := store.WithApplyLock(ctx, func() error {
		var rerr error
		res, rerr = reconcileUnlocked(ctx, store, exec, opts)
		return rerr
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func reconcileUnlocked(ctx context.Context, store *state.Store, exec SystemExecutor, opts ApplyOptions) (*ApplyResult, error) {
	if exec == nil {
		exec = OSExecutor{}
	}
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	if err := st.Validate(); err != nil {
		return nil, fmt.Errorf("validate state: %w", err)
	}

	ropts, warnings := populateRenderOptions(ctx, st, store, exec, opts)

	// Ensure a self-signed fallback cert exists whenever TLS is referenced before ACME/import.
	certCreated := false
	if !opts.DryRun {
		certTarget := ropts.CertFile
		keyTarget := ropts.KeyFile
		if st.Cert.Mode == "imported" && st.Cert.CertFile != "" && st.Cert.KeyFile != "" {
			certTarget = st.Cert.CertFile
			keyTarget = st.Cert.KeyFile
		}
		if _, err := os.Stat(certTarget); os.IsNotExist(err) {
			cn := st.Server.Domain
			if cn == "" {
				cn = st.Auth.ServerName
			}
			if cerr := cert.EnsureSelfSigned(certTarget, keyTarget, cn); cerr == nil {
				certCreated = true
			}
		}
	}

	bundle, err := render.RenderAll(st, ropts)
	if err != nil {
		return nil, err
	}

	res := &ApplyResult{
		Bundle:   bundle,
		Warnings: warnings,
	}
	if opts.DryRun {
		return res, nil
	}

	if !opts.PreserveTxn {
		if err := store.BeginTxn(); err != nil {
			return nil, fmt.Errorf("begin txn: %w", err)
		}
	}

	prevManifest, err := LoadManifest(store.ManifestPath())
	if err != nil {
		prevManifest = &Manifest{Files: make(map[string]ManifestEntry)}
	}
	if !opts.Force {
		if err := CheckUnmanagedEdits(prevManifest, bundle.Files, func(p string) string {
			return mapTargetPath(opts.RootPrefix, p)
		}); err != nil {
			_, _ = store.RollbackTxn()
			return nil, err
		}
	}

	// Stage all files to .new
	stagedPaths := make(map[string]string, len(bundle.Files))
	cleanupStaged := func() {
		for _, sp := range stagedPaths {
			_ = os.Remove(sp)
		}
	}
	for _, f := range bundle.Files {
		diskTarget := mapTargetPath(opts.RootPrefix, f.TargetPath)
		staged := diskTarget + ".new"
		if strings.HasSuffix(diskTarget, ".json") {
			staged = strings.TrimSuffix(diskTarget, ".json") + ".new.json"
		}
		if err := writeBytesExact(staged, f.Content, f.Mode); err != nil {
			cleanupStaged()
			_, _ = store.RollbackTxn()
			return nil, fmt.Errorf("stage %s: %w", f.TargetPath, err)
		}
		stagedPaths[f.TargetPath] = staged
	}

	_, isOS := exec.(OSExecutor)

	// Install haproxy automatically on real OS before pre-flight if a relay rule needs it.
	if bundle.HAProxyNeeded && isOS && !exec.HasCommand("haproxy") {
		var ierr error
		var out string
		if exec.HasCommand("apt-get") {
			out, ierr = exec.RunCommand(ctx, []string{"DEBIAN_FRONTEND=noninteractive"}, "sh", "-c", "apt-get update -qq && apt-get install -y -qq --no-install-recommends haproxy")
		} else if exec.HasCommand("apk") {
			out, ierr = exec.RunCommand(ctx, nil, "apk", "add", "--no-cache", "haproxy")
		}
		if ierr != nil {
			cleanupStaged()
			_, _ = store.RollbackTxn()
			return nil, fmt.Errorf("auto-install haproxy failed: %w (%s)", ierr, strings.TrimSpace(out))
		}
	}

	// Pre-flight validation before replacing any live files
	if err := preflightValidate(ctx, exec, ropts, stagedPaths, bundle.Files); err != nil {
		cleanupStaged()
		_, _ = store.RollbackTxn()
		return nil, err
	}

	// Build backup list for both updated files and obsolete managed files
	newTargets := make(map[string]struct{}, len(bundle.Files))
	for _, f := range bundle.Files {
		newTargets[f.TargetPath] = struct{}{}
	}

	var backups []fileBackup
	backupOne := func(targetPath string) error {
		diskPath := mapTargetPath(opts.RootPrefix, targetPath)
		prevPath := diskPath + ".prev"
		info, statErr := os.Stat(diskPath)
		if os.IsNotExist(statErr) {
			backups = append(backups, fileBackup{diskPath: diskPath, prevPath: prevPath, existed: false})
			return nil
		}
		if statErr != nil {
			return statErr
		}
		oldBytes, rerr := os.ReadFile(diskPath)
		if rerr != nil {
			return rerr
		}
		if werr := writeBytesExact(prevPath, oldBytes, info.Mode().Perm()); werr != nil {
			return werr
		}
		backups = append(backups, fileBackup{
			diskPath: diskPath,
			prevPath: prevPath,
			existed:  true,
			mode:     info.Mode().Perm(),
		})
		return nil
	}

	rollbackFiles := func() {
		for _, b := range backups {
			if b.existed {
				_ = os.Rename(b.prevPath, b.diskPath)
			} else {
				_ = os.Remove(b.diskPath)
				_ = os.Remove(b.prevPath)
			}
		}
	}

	for _, f := range bundle.Files {
		if err := backupOne(f.TargetPath); err != nil {
			cleanupStaged()
			rollbackFiles()
			_, _ = store.RollbackTxn()
			return nil, fmt.Errorf("backup %s: %w", f.TargetPath, err)
		}
	}
	for oldTarget := range prevManifest.Files {
		if _, stillNeeded := newTargets[oldTarget]; stillNeeded {
			continue
		}
		if err := backupOne(oldTarget); err != nil {
			cleanupStaged()
			rollbackFiles()
			_, _ = store.RollbackTxn()
			return nil, fmt.Errorf("backup obsolete %s: %w", oldTarget, err)
		}
	}

	// Detect changed/added/removed files before promoting staged files onto disk.
	var changedFiles []changedFile
	for _, f := range bundle.Files {
		diskPath := mapTargetPath(opts.RootPrefix, f.TargetPath)
		diskBytes, rerr := os.ReadFile(diskPath)
		if rerr != nil || !bytes.Equal(diskBytes, f.Content) {
			changedFiles = append(changedFiles, changedFile{relName: f.RelName, targetPath: f.TargetPath})
		}
	}
	for oldTarget := range prevManifest.Files {
		if _, stillNeeded := newTargets[oldTarget]; !stillNeeded {
			changedFiles = append(changedFiles, changedFile{targetPath: oldTarget})
		}
	}

	// Atomically promote staged files into place
	for _, f := range bundle.Files {
		diskPath := mapTargetPath(opts.RootPrefix, f.TargetPath)
		if err := os.Rename(stagedPaths[f.TargetPath], diskPath); err != nil {
			cleanupStaged()
			rollbackFiles()
			_, _ = store.RollbackTxn()
			return nil, fmt.Errorf("promote %s: %w", f.TargetPath, err)
		}
		res.FilesWritten = append(res.FilesWritten, f.TargetPath)
	}
	var obsoleteUnitPaths []string
	for oldTarget := range prevManifest.Files {
		if _, stillNeeded := newTargets[oldTarget]; stillNeeded {
			continue
		}
		if strings.HasPrefix(oldTarget, "/etc/systemd/system/") || strings.HasPrefix(oldTarget, "/etc/init.d/") {
			obsoleteUnitPaths = append(obsoleteUnitPaths, oldTarget)
			continue
		}
		diskPath := mapTargetPath(opts.RootPrefix, oldTarget)
		_ = os.Remove(diskPath)
		res.FilesRemoved = append(res.FilesRemoved, oldTarget)
	}

	// Ensure Nginx camouflage root index exists on real OS before nginx validation/start
	if bundle.NginxNeeded && isOS {
		webRoot := strings.TrimSpace(st.Server.CamouflageDir)
		if webRoot == "" {
			webRoot = "/var/www/html"
		}
		indexDisk := mapTargetPath(opts.RootPrefix, filepath.Join(webRoot, "index.html"))
		if _, statErr := os.Stat(indexDisk); os.IsNotExist(statErr) {
			_ = writeBytesExact(indexDisk, []byte("<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Welcome</title></head><body><h1>Welcome</h1></body></html>\n"), 0o644)
		}
	}

	// Validate nginx globally once dex-server.conf is in conf.d
	if bundle.NginxNeeded && exec.HasCommand("nginx") {
		if out, err := exec.RunCommand(ctx, nil, "nginx", "-t"); err != nil {
			rollbackFiles()
			_, _ = store.RollbackTxn()
			return nil, fmt.Errorf("nginx -t failed (rolled back): %w (%s)", err, strings.TrimSpace(out))
		}
	}

	// Runtime sysctl & service orchestration
	wasResolvedActive := false
	type touchedService struct {
		name      string
		wasActive bool
	}
	var touchedSvcs []touchedService
	nftWasActive := exec.ServiceIsActive(ctx, ropts.InitSystem, "dex-nft")
	var prevNFTBytes []byte
	for _, f := range bundle.Files {
		if f.RelName == "nftables.conf" {
			// Read previous nftables.conf backup (if any) before applyServices runs so rollback can
			// distinguish newly introduced dex_* tables from pre-existing ones.
			diskNFT := mapTargetPath(opts.RootPrefix, f.TargetPath)
			prevNFTBytes, _ = os.ReadFile(diskNFT + ".prev")
			break
		}
	}
	applyServices := func() error {
		if st.System.AutoTuneSysctl && !ropts.IsContainer {
			sysctlDisk := mapTargetPath(opts.RootPrefix, "/etc/sysctl.d/99-dex.conf")
			if _, err := os.Stat(sysctlDisk); err == nil && exec.HasCommand("sysctl") {
				_, _ = exec.RunCommand(ctx, nil, "sysctl", "-p", sysctlDisk)
			}
		}

		// Stop/disable systemd-resolved on systemd hosts so it neither holds :53 nor bypasses /etc/resolv.conf via nss-resolve
		if isOS && bundle.MosDNSNeeded && ropts.InitSystem == "systemd" {
			_ = os.Remove(mapTargetPath(opts.RootPrefix, "/etc/systemd/resolved.conf.d/99-dex.conf"))
			if exec.ServiceIsActive(ctx, "systemd", "systemd-resolved") {
				wasResolvedActive = true
				_ = exec.ServiceStopDisable(ctx, "systemd", "systemd-resolved")
			}
		}

		// Determine desired states of managed services
		type svcSpec struct {
			name   string
			active bool
			probe  bool
		}
		wgUnit := "wg-quick@wg0"
		if ropts.InitSystem == "openrc" {
			wgUnit = "wg-quick.wg0"
		}

		changedServices := make(map[string]bool)
		restartAllFallback := false
		for _, cf := range changedFiles {
			svcs, known := servicesForFile(cf.relName, cf.targetPath, wgUnit)
			if !known {
				restartAllFallback = true
				continue
			}
			for _, svc := range svcs {
				changedServices[svc] = true
			}
		}
		if certCreated {
			changedServices["dex-xray"] = true
			changedServices["nginx"] = true
		}

		specs := []svcSpec{
			{name: "dex-nft", active: bundle.NFTClientNeeded || bundle.NFTRelayNeeded, probe: bundle.NFTClientNeeded || bundle.NFTRelayNeeded},
			{name: "dex-mosdns", active: bundle.MosDNSNeeded, probe: bundle.MosDNSNeeded},
			{name: "dex-xray", active: bundle.XrayNeeded, probe: bundle.XrayNeeded},
			{name: "dex-doh", active: bundle.DoHNeeded, probe: bundle.DoHNeeded},
			{name: "haproxy", active: bundle.HAProxyNeeded, probe: bundle.HAProxyNeeded},
			{name: "nginx", active: bundle.NginxNeeded, probe: bundle.NginxNeeded},
			{name: wgUnit, active: bundle.WireGuardNeeded, probe: bundle.WireGuardNeeded},
		}
		if ropts.InitSystem == "systemd" {
			specs = append(specs,
				svcSpec{name: "dex-refresh.timer", active: bundle.NFTRelayNeeded, probe: false},
				svcSpec{name: "dex-rules-update.timer", active: bundle.RulesTimerNeeded, probe: false},
			)
		}

		// Stop/disable unneeded units (timers first) BEFORE deleting obsolete unit
		// files or running daemon-reload, avoiding vanished-trigger failures
		// and dropped ExecStop hooks.
		for i := len(specs) - 1; i >= 0; i-- {
			sp := specs[i]
			if !sp.active {
				_ = exec.ServiceStopDisable(ctx, ropts.InitSystem, sp.name)
				res.ServicesOff = append(res.ServicesOff, sp.name)
			}
		}

		for _, oldUnit := range obsoleteUnitPaths {
			diskPath := mapTargetPath(opts.RootPrefix, oldUnit)
			_ = os.Remove(diskPath)
			res.FilesRemoved = append(res.FilesRemoved, oldUnit)
		}

		if err := exec.DaemonReload(ctx, ropts.InitSystem); err != nil {
			return fmt.Errorf("daemon reload: %w", err)
		}

		for _, sp := range specs {
			if !sp.active {
				continue
			}
			wasActive := exec.ServiceIsActive(ctx, ropts.InitSystem, sp.name)
			if opts.RestartAll || restartAllFallback || changedServices[sp.name] || !wasActive {
				touchedSvcs = append(touchedSvcs, touchedService{name: sp.name, wasActive: wasActive})
				if sp.name == "nginx" && wasActive && !opts.RestartAll {
					if rerr := exec.ServiceReload(ctx, ropts.InitSystem, sp.name); rerr != nil {
						if err := exec.ServiceEnableStart(ctx, ropts.InitSystem, sp.name); err != nil {
							return err
						}
					}
				} else {
					if err := exec.ServiceEnableStart(ctx, ropts.InitSystem, sp.name); err != nil {
						return err
					}
				}
				res.ServicesRestarted = append(res.ServicesRestarted, sp.name)
			}
			res.ServicesOn = append(res.ServicesOn, sp.name)
		}

		// Clean up orphaned nftables tables when a unit or table is omitted from nftables.conf
		// (removing unit files before daemon-reload drops ExecStop).
		if exec.HasCommand("nft") {
			for _, tbl := range []string{"dex_relay", "dex_nat", "dex_flow", "dex_client", "dex_filter"} {
				if !hasNFTTable(bundle, tbl) {
					_, _ = exec.RunCommand(ctx, nil, "nft", "delete", "table", "inet", tbl)
				}
			}
		}
		if !bundle.NFTClientNeeded && isOS && exec.HasCommand("ip") {
			for _, family := range []string{"-4", "-6"} {
				for i := 0; i < 4; i++ {
					if _, err := exec.RunCommand(ctx, nil, "ip", family, "rule", "del", "fwmark", "0x9", "table", "220"); err != nil {
						break
					}
				}
				_, _ = exec.RunCommand(ctx, nil, "ip", family, "route", "flush", "table", "220")
			}
		}

		// Manage dex-daemon carefully: start if inactive, avoid self-restarting when already active (e.g. Web UI apply)
		if bundle.DaemonNeeded {
			if !exec.ServiceIsActive(ctx, ropts.InitSystem, "dex-daemon") {
				touchedSvcs = append(touchedSvcs, touchedService{name: "dex-daemon", wasActive: false})
				if err := exec.ServiceEnableStart(ctx, ropts.InitSystem, "dex-daemon"); err != nil {
					return err
				}
			}
			res.ServicesOn = append(res.ServicesOn, "dex-daemon")
		} else {
			_ = exec.ServiceStopDisable(ctx, ropts.InitSystem, "dex-daemon")
			res.ServicesOff = append(res.ServicesOff, "dex-daemon")
		}

		// Poll health after start (up to 2s on real OS) to confirm services stay stable
		checkAllActive := func() error {
			for _, sp := range specs {
				if sp.active && sp.probe {
					if !exec.ServiceIsActive(ctx, ropts.InitSystem, sp.name) {
						return fmt.Errorf("service %s failed health check after start", sp.name)
					}
				}
			}
			if bundle.DaemonNeeded && !exec.ServiceIsActive(ctx, ropts.InitSystem, "dex-daemon") {
				return fmt.Errorf("service dex-daemon failed health check after start")
			}
			return nil
		}

		if isOS {
			deadline := time.Now().Add(2 * time.Second)
			time.Sleep(500 * time.Millisecond)
			for {
				if err := checkAllActive(); err == nil {
					// Wait another 500ms and re-verify to catch fast crash loops
					time.Sleep(500 * time.Millisecond)
					if err2 := checkAllActive(); err2 != nil {
						return err2
					}
					break
				} else if !time.Now().Before(deadline) {
					return err
				}
				time.Sleep(300 * time.Millisecond)
			}
		} else {
			if err := checkAllActive(); err != nil {
				return err
			}
		}

		// Verify MosDNS responds on 127.0.0.1:53 before backing up & switching /etc/resolv.conf
		if isOS && bundle.MosDNSNeeded {
			var probeErr error
			for attempt := 0; attempt < 4; attempt++ {
				if probeErr = probeLocalDNS(ctx, "127.0.0.1:53"); probeErr == nil {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
			if probeErr != nil {
				return fmt.Errorf("local DNS 127.0.0.1:53 readiness probe failed: %w", probeErr)
			}

			resolvPath := mapTargetPath(opts.RootPrefix, "/etc/resolv.conf")
			origPath := filepath.Join(store.Dir, "resolv.conf.orig")
			curResolvBytes, readResolvErr := os.ReadFile(resolvPath)
			curResolvLink, linkErr := os.Readlink(resolvPath)
			if _, statOrigErr := os.Stat(origPath); os.IsNotExist(statOrigErr) {
				if readResolvErr == nil && strings.TrimSpace(string(curResolvBytes)) != "nameserver 127.0.0.1" {
					_ = writeBytesExact(origPath, curResolvBytes, 0o644)
				}
			}
			if linkErr == nil {
				_ = os.Remove(resolvPath)
			}
			if werr := writeBytesExact(resolvPath, []byte("nameserver 127.0.0.1\n"), 0o644); werr != nil {
				// Best-effort restore before returning failure
				if linkErr == nil && curResolvLink != "" {
					_ = os.Remove(resolvPath)
					_ = os.Symlink(curResolvLink, resolvPath)
				} else if readResolvErr == nil {
					_ = writeBytesExact(resolvPath, curResolvBytes, 0o644)
				}
				return fmt.Errorf("update /etc/resolv.conf: %w", werr)
			}
		}
		return nil
	}

	if err := applyServices(); err != nil {
		// 1. Stop/disable newly started services in reverse order BEFORE rollbackFiles() removes unit files,
		// so ExecStop hooks remain intact and newly bound ports (e.g. :53) are released.
		for i := len(touchedSvcs) - 1; i >= 0; i-- {
			ts := touchedSvcs[i]
			if !ts.wasActive {
				_ = exec.ServiceStopDisable(ctx, ropts.InitSystem, ts.name)
			}
		}
		// Remove any dex_* nftables tables introduced by this failed apply.
		if exec.HasCommand("nft") {
			for _, tbl := range []string{"dex_relay", "dex_nat", "dex_flow", "dex_client", "dex_filter"} {
				if !hasNFTTable(bundle, tbl) {
					continue
				}
				existedBefore := nftWasActive && bytes.Contains(prevNFTBytes, []byte("table inet "+tbl+" {"))
				if !existedBefore {
					_, _ = exec.RunCommand(ctx, nil, "nft", "delete", "table", "inet", tbl)
				}
			}
		}

		// 2. Restore backed-up config/unit files and reload init daemon.
		rollbackFiles()
		_ = exec.DaemonReload(ctx, ropts.InitSystem)
		if wasResolvedActive {
			_ = exec.ServiceEnableStart(ctx, "systemd", "systemd-resolved")
		}

		// 3. Restart only services that were already active before this apply and were restarted.
		for _, ts := range touchedSvcs {
			if ts.wasActive {
				_ = exec.ServiceRestart(ctx, ropts.InitSystem, ts.name)
			}
		}
		_, _ = store.RollbackTxn()
		return nil, fmt.Errorf("apply services failed (rolled back): %w", err)
	}

	// Clean up backups and commit manifest + state transaction
	for _, b := range backups {
		_ = os.Remove(b.prevPath)
	}
	if err := SaveManifest(store.ManifestPath(), BuildManifest(bundle.Files)); err != nil {
		warnings = append(warnings, fmt.Sprintf("save manifest: %v", err))
		res.Warnings = warnings
	}
	if err := store.CommitTxn(); err != nil {
		warnings = append(warnings, fmt.Sprintf("commit txn: %v", err))
		res.Warnings = warnings
	}
	return res, nil
}
