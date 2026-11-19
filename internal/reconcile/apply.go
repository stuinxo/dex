package reconcile

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"net/url"
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
	if err := store.BeginTxn(); err != nil {
		return nil, nil, fmt.Errorf("begin txn: %w", err)
	}
	updated, err := store.Update(defaultRole, mutator)
	if err != nil {
		_, _ = store.RollbackTxn()
		return nil, nil, err
	}
	opts.PreserveTxn = true
	res, err := Reconcile(ctx, store, exec, opts)
	if err != nil {
		return nil, nil, err
	}
	return updated, res, nil
}

// ApplyResult summarizes the outcome of Reconcile.
type ApplyResult struct {
	Bundle       *render.RenderBundle
	FilesWritten []string
	FilesRemoved []string
	ServicesOn   []string
	ServicesOff  []string
	Warnings     []string
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
			if u, err := url.Parse(rawDoH); err == nil && u.Hostname() != "" {
				resolveHost(u.Hostname())
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
			_ = cert.EnsureSelfSigned(certTarget, keyTarget, cn)
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
	for oldTarget := range prevManifest.Files {
		if _, stillNeeded := newTargets[oldTarget]; stillNeeded {
			continue
		}
		diskPath := mapTargetPath(opts.RootPrefix, oldTarget)
		_ = os.Remove(diskPath)
		res.FilesRemoved = append(res.FilesRemoved, oldTarget)
	}

	// Ensure Nginx camouflage root index exists on real OS before nginx validation/start
	_, isOS := exec.(OSExecutor)
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

		if err := exec.DaemonReload(ctx, ropts.InitSystem); err != nil {
			return fmt.Errorf("daemon reload: %w", err)
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
			specs = append(specs, svcSpec{name: "dex-refresh.timer", active: bundle.NFTRelayNeeded, probe: false})
		}

		for _, sp := range specs {
			if sp.active {
				if err := exec.ServiceEnableStart(ctx, ropts.InitSystem, sp.name); err != nil {
					return err
				}
				res.ServicesOn = append(res.ServicesOn, sp.name)
			} else {
				_ = exec.ServiceStopDisable(ctx, ropts.InitSystem, sp.name)
				res.ServicesOff = append(res.ServicesOff, sp.name)
			}
		}

		// Manage dex-daemon carefully: start if inactive, avoid self-restarting when already active (e.g. Web UI apply)
		if bundle.DaemonNeeded {
			if !exec.ServiceIsActive(ctx, ropts.InitSystem, "dex-daemon") {
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
		rollbackFiles()
		_ = exec.DaemonReload(ctx, ropts.InitSystem)
		if wasResolvedActive {
			_ = exec.ServiceEnableStart(ctx, "systemd", "systemd-resolved")
		}
		// Best-effort restart previously running services
		for _, spName := range res.ServicesOn {
			_ = exec.ServiceRestart(ctx, ropts.InitSystem, spName)
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
