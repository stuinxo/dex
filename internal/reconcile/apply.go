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

	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
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
		if rerr != nil || opts.DryRun {
			_, _ = store.RollbackTxn()
		}
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
	case strings.HasPrefix(relName, "mosdns/") || relName == "systemd/dex-mosdns.service" || relName == "openrc/dex-mosdns":
		return []string{"dex-mosdns"}, true
	case relName == "haproxy.cfg" || relName == "systemd/haproxy-limits.conf":
		return []string{"haproxy"}, true
	case relName == "nginx-dex.conf" || relName == "systemd/nginx-limits.conf":
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
	case relName == "systemd/dex-core-update.timer" || relName == "systemd/dex-core-update.service":
		return []string{"dex-core-update.timer"}, true
	case relName == "sysctl-99-dex.conf" || relName == "modules-99-dex.conf":
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
	case strings.Contains(slash, "/mosdns/") || base == "dex-mosdns.service" || targetPath == "/etc/init.d/dex-mosdns":
		return []string{"dex-mosdns"}, true
	case targetPath == "/etc/haproxy/haproxy.cfg" || targetPath == "/etc/systemd/system/haproxy.service.d/dex-limits.conf":
		return []string{"haproxy"}, true
	case targetPath == "/etc/nginx/conf.d/dex-server.conf" || targetPath == "/etc/systemd/system/nginx.service.d/dex-limits.conf":
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
	case base == "dex-core-update.timer" || base == "dex-core-update.service":
		return []string{"dex-core-update.timer"}, true
	case targetPath == "/etc/sysctl.d/99-dex.conf" || targetPath == "/etc/modules-load.d/99-dex.conf":
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
	cleanRoot := filepath.Clean(rootPrefix)
	cleanTarget := filepath.Clean(targetPath)
	if cleanTarget == cleanRoot || strings.HasPrefix(cleanTarget, cleanRoot+string(filepath.Separator)) {
		return cleanTarget
	}
	clean := strings.TrimPrefix(cleanTarget, string(filepath.Separator))
	return filepath.Join(cleanRoot, clean)
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

func isNonEmptyFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

func isNginxLegacyHTTP2(versionOutput string) bool {
	idx := strings.Index(versionOutput, "nginx/")
	if idx < 0 {
		return false
	}
	rest := versionOutput[idx+len("nginx/"):]
	end := strings.IndexAny(rest, " \t\r\n")
	if end >= 0 {
		rest = rest[:end]
	}
	parts := strings.Split(rest, ".")
	if len(parts) < 2 {
		return false
	}
	var nums [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := fmt.Sscanf(parts[i], "%d", &nums[i])
		if err != nil || n != 1 {
			return false
		}
	}
	if nums[0] != 1 {
		return nums[0] < 1
	}
	if nums[1] != 25 {
		return nums[1] < 25
	}
	return nums[2] < 1
}

func stateNeedsNginx(st *state.State) bool {
	if st.Role == state.RoleServer && st.Server.TLSMode == "nginx" {
		return true
	}
	for _, ex := range st.ExtraInbounds {
		if ex.ViaNginx {
			return true
		}
	}
	return false
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
		if st.Cert.Mode == "imported" && st.Cert.CertFile != "" && st.Cert.KeyFile != "" {
			ropts.CertFile = st.Cert.CertFile
		} else {
			ropts.CertFile = store.DefaultCert()
		}
	}
	if ropts.KeyFile == "" {
		if st.Cert.Mode == "imported" && st.Cert.CertFile != "" && st.Cert.KeyFile != "" {
			ropts.KeyFile = st.Cert.KeyFile
		} else {
			ropts.KeyFile = store.DefaultKey()
		}
	}
	ropts = ropts.WithDefaults()

	if !ropts.DomainsAppleExists {
		ropts.DomainsAppleExists = isNonEmptyFile(mapTargetPath(opts.RootPrefix, ropts.DomainsApplePath))
	}
	if !ropts.DomainsGamesExists {
		ropts.DomainsGamesExists = isNonEmptyFile(mapTargetPath(opts.RootPrefix, ropts.DomainsGamesPath))
	}
	if !opts.RenderOpts.NginxLegacyHTTP2 && stateNeedsNginx(st) && exec != nil && exec.HasCommand("nginx") {
		if out, _ := exec.RunCommand(ctx, nil, "nginx", "-v"); out != "" {
			ropts.NginxLegacyHTTP2 = isNginxLegacyHTTP2(out)
		}
	}

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

	cachedHosts := loadHostsFileCache(mapTargetPath(opts.RootPrefix, filepath.Join(ropts.GeneratedDir, "mosdns", "hosts.txt")))

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
		if err != nil || len(ips) == 0 {
			if cached := cachedHosts[h]; len(cached) > 0 {
				ropts.ResolvedHostIPs[h] = cached
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("resolve %s: %v (using cached IP from hosts.txt)", h, err))
				} else {
					warnings = append(warnings, fmt.Sprintf("resolve %s: empty result (using cached IP from hosts.txt)", h))
				}
				return
			}
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("resolve %s: %v", h, err))
			}
			return
		}
		ropts.ResolvedHostIPs[h] = ips
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
		for _, dom := range st.Client.DNS.BlacklistDomains {
			if host := render.ExtractDomainHost(dom); host != "" {
				resolveHost(host)
			}
		}
		for _, dom := range st.Client.DNS.WhitelistDomains {
			if host := render.ExtractDomainHost(dom); host != "" {
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

func isCustomExternalCertState(st *state.State, store *state.Store) bool {
	return st.Cert.Mode == "imported" &&
		((st.Cert.CertFile != "" && st.Cert.CertFile != store.DefaultCert()) ||
			(st.Cert.KeyFile != "" && st.Cert.KeyFile != store.DefaultKey()))
}

func dryRunPreflight(ctx context.Context, exec SystemExecutor, store *state.Store, st *state.State, ropts render.RenderOptions, rootPrefix string, bundle *render.RenderBundle) error {
	dryDir, err := os.MkdirTemp("", "dex-dryrun-*")
	if err != nil {
		return fmt.Errorf("create dry-run temp dir: %w", err)
	}
	defer os.RemoveAll(dryDir)

	dryRopts := ropts
	dryFiles := bundle.Files
	if !isCustomExternalCertState(st, store) {
		certDisk := mapTargetPath(rootPrefix, ropts.CertFile)
		keyDisk := mapTargetPath(rootPrefix, ropts.KeyFile)
		_, errC := os.Stat(certDisk)
		_, errK := os.Stat(keyDisk)
		if os.IsNotExist(errC) || os.IsNotExist(errK) {
			dryCert := filepath.Join(dryDir, "dex.cer")
			dryKey := filepath.Join(dryDir, "dex.key")
			cn := st.Server.Domain
			if cn == "" {
				cn = st.Auth.ServerName
			}
			if cerr := cert.EnsureSelfSigned(dryCert, dryKey, cn); cerr != nil {
				return fmt.Errorf("dry-run self-signed cert: %w", cerr)
			}
			dryRopts.CertFile = dryCert
			dryRopts.KeyFile = dryKey
			dryBundle, rerr := render.RenderAll(st, dryRopts)
			if rerr != nil {
				return rerr
			}
			dryFiles = dryBundle.Files
		}
	}

	dryStagedPaths := make(map[string]string, len(dryFiles))
	for i, f := range dryFiles {
		name := fmt.Sprintf("%02d-%s", i, filepath.Base(f.TargetPath))
		if strings.HasSuffix(f.TargetPath, ".json") && !strings.HasSuffix(name, ".json") {
			name += ".json"
		}
		dst := filepath.Join(dryDir, name)
		if err := writeBytesExact(dst, f.Content, f.Mode); err != nil {
			return fmt.Errorf("stage dry-run %s: %w", f.TargetPath, err)
		}
		dryStagedPaths[f.TargetPath] = dst
	}
	if _, isOS := exec.(OSExecutor); isOS {
		if err := checkRequiredBinaries(exec, ropts, bundle, true); err != nil {
			return err
		}
	}
	return preflightValidate(ctx, exec, dryRopts, dryStagedPaths, dryFiles)
}

func checkRequiredBinaries(exec SystemExecutor, ropts render.RenderOptions, bundle *render.RenderBundle, dryRun bool) error {
	if bundle.XrayNeeded && !exec.HasCommand(ropts.XrayBin) {
		return fmt.Errorf("missing required xray binary %q (run 'dex update --component xray')", ropts.XrayBin)
	}
	if bundle.MosDNSNeeded && !exec.HasCommand(ropts.MosDNSBin) {
		return fmt.Errorf("missing required mosdns binary %q (run 'dex update --component mosdns')", ropts.MosDNSBin)
	}
	if (bundle.NFTClientNeeded || bundle.NFTRelayNeeded) && !exec.HasCommand("nft") {
		return fmt.Errorf("missing required binary \"nft\"")
	}
	if bundle.HAProxyNeeded && !exec.HasCommand("haproxy") {
		if !dryRun || (!exec.HasCommand("apt-get") && !exec.HasCommand("apk")) {
			return fmt.Errorf("missing required binary \"haproxy\"")
		}
	}
	if bundle.NginxNeeded && !exec.HasCommand("nginx") {
		return fmt.Errorf("missing required binary \"nginx\"")
	}
	if bundle.WireGuardNeeded && !exec.HasCommand("wg-quick") {
		return fmt.Errorf("missing required binary \"wg-quick\"")
	}
	return nil
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

	bundle, err := render.RenderAll(st, ropts)
	if err != nil {
		return nil, err
	}

	res := &ApplyResult{
		Bundle:   bundle,
		Warnings: warnings,
	}
	if opts.DryRun {
		if err := dryRunPreflight(ctx, exec, store, st, ropts, opts.RootPrefix, bundle); err != nil {
			return nil, err
		}
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

	// Ensure placeholder rules & self-signed fallback cert exist only after RenderAll & unmanaged checks pass.
	certCreated := false
	if st.Role == state.RoleClient && st.Client.DNS.BlockAds {
		adsDiskPath := mapTargetPath(opts.RootPrefix, filepath.Join(ropts.StateDir, "rules", "Domains.ads.txt"))
		if _, statErr := os.Stat(adsDiskPath); os.IsNotExist(statErr) {
			if werr := writeBytesExact(adsDiskPath, []byte{}, 0o644); werr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("create placeholder Domains.ads.txt: %v", werr))
			} else {
				res.Warnings = append(res.Warnings, "Domains.ads.txt missing; created empty placeholder (run 'dex rules update --ads' to populate)")
			}
		}
	}
	if !isCustomExternalCertState(st, store) {
		certDisk := mapTargetPath(opts.RootPrefix, ropts.CertFile)
		keyDisk := mapTargetPath(opts.RootPrefix, ropts.KeyFile)
		prevCert, errC := os.ReadFile(certDisk)
		prevKey, errK := os.ReadFile(keyDisk)
		cn := st.Server.Domain
		if cn == "" {
			cn = st.Auth.ServerName
		}
		if cerr := cert.EnsureSelfSigned(certDisk, keyDisk, cn); cerr == nil {
			afterCert, _ := os.ReadFile(certDisk)
			afterKey, _ := os.ReadFile(keyDisk)
			if errC != nil || errK != nil || !bytes.Equal(prevCert, afterCert) || !bytes.Equal(prevKey, afterKey) {
				certCreated = true
			}
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

	// Install haproxy automatically on real OS before binary check & pre-flight if a relay rule needs it.
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

	if isOS && !opts.DryRun {
		if err := checkRequiredBinaries(exec, ropts, bundle, false); err != nil {
			cleanupStaged()
			_, _ = store.RollbackTxn()
			return nil, err
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
	type svcSpec struct {
		name   string
		active bool
		probe  bool
	}
	var touchedSvcs []touchedService
	var orderedSpecs []svcSpec
	stoppedActiveSet := make(map[string]bool)
	stoppedEnabledOnlySet := make(map[string]bool)
	recordStoppedUnit := func(name string) {
		if exec.ServiceIsActive(ctx, ropts.InitSystem, name) {
			stoppedActiveSet[name] = true
			return
		}
		if isOS && ropts.InitSystem == "systemd" {
			if _, enErr := exec.RunCommand(ctx, nil, "systemctl", "is-enabled", "--quiet", name); enErr == nil {
				stoppedEnabledOnlySet[name] = true
			}
		}
	}
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
			if exec.HasCommand("modprobe") {
				for _, mod := range []string{"tcp_bbr", "nf_conntrack", "sch_cake"} {
					_, _ = exec.RunCommand(ctx, nil, "modprobe", mod)
				}
			}
			sysctlDisk := mapTargetPath(opts.RootPrefix, "/etc/sysctl.d/99-dex.conf")
			if _, err := os.Stat(sysctlDisk); err == nil && exec.HasCommand("sysctl") {
				_, _ = exec.RunCommand(ctx, nil, "sysctl", "-e", "-p", sysctlDisk)
				if qdiscOut, qerr := exec.RunCommand(ctx, nil, "sysctl", "-n", "net.core.default_qdisc"); qerr == nil {
					curQdisc := strings.TrimSpace(qdiscOut)
					if curQdisc != "" && curQdisc != "cake" && curQdisc != "fq" {
						_, _ = exec.RunCommand(ctx, nil, "sysctl", "-w", "net.core.default_qdisc=fq")
					}
				}
			}
		}

		// Read original DNS config BEFORE stopping systemd-resolved so /run/systemd/resolve/resolv.conf is still available if /etc/resolv.conf is a 127.0.0.53 stub.
		var backupResolvBytes []byte
		if isOS && bundle.MosDNSNeeded {
			resolvPath := mapTargetPath(opts.RootPrefix, "/etc/resolv.conf")
			if b, rerr := os.ReadFile(resolvPath); rerr == nil && hasNonLoopbackNameserver(b) {
				backupResolvBytes = b
			} else {
				runResolvePath := mapTargetPath(opts.RootPrefix, "/run/systemd/resolve/resolv.conf")
				if rb, rerr2 := os.ReadFile(runResolvePath); rerr2 == nil && hasNonLoopbackNameserver(rb) {
					backupResolvBytes = rb
				}
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
		wgUnit := "wg-quick@wg0"
		if ropts.InitSystem == "openrc" {
			wgUnit = "wg-quick.wg0"
		}

		changedServices := make(map[string]bool)
		restartAllFallback := false
		nginxDropinChanged := false
		for _, cf := range changedFiles {
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
				svcSpec{name: "dex-refresh.timer", active: bundle.RefreshTimerNeeded, probe: false},
				svcSpec{name: "dex-rules-update.timer", active: bundle.RulesTimerNeeded, probe: false},
				svcSpec{name: "dex-core-update.timer", active: bundle.CoreUpdateTimerNeeded, probe: false},
			)
		}
		orderedSpecs = specs

		// Stop/disable unneeded units (timers first) BEFORE deleting obsolete unit
		// files or running daemon-reload, avoiding vanished-trigger failures
		// and dropped ExecStop hooks.
		for i := len(specs) - 1; i >= 0; i-- {
			sp := specs[i]
			if !sp.active {
				recordStoppedUnit(sp.name)
				_ = exec.ServiceStopDisable(ctx, ropts.InitSystem, sp.name)
				res.ServicesOff = append(res.ServicesOff, sp.name)
			}
		}

		for _, oldUnit := range obsoleteUnitPaths {
			diskPath := mapTargetPath(opts.RootPrefix, oldUnit)
			_ = os.Remove(diskPath)
			if dir := filepath.Dir(diskPath); strings.HasSuffix(dir, ".service.d") {
				_ = os.Remove(dir)
			}
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
				if sp.name == "nginx" && wasActive && !opts.RestartAll && !nginxDropinChanged {
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
			recordStoppedUnit("dex-daemon")
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
			existingOrig, existingOrigErr := os.ReadFile(origPath)
			if existingOrigErr != nil || !hasNonLoopbackNameserver(existingOrig) {
				if len(backupResolvBytes) > 0 {
					_ = writeBytesExact(origPath, backupResolvBytes, 0o644)
				} else if readResolvErr == nil && hasNonLoopbackNameserver(curResolvBytes) {
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
		} else if isOS && !bundle.MosDNSNeeded {
			resolvPath := mapTargetPath(opts.RootPrefix, "/etc/resolv.conf")
			origPath := filepath.Join(store.Dir, "resolv.conf.orig")
			if rerr := restoreResolvConfIfNeeded(resolvPath, origPath); rerr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("restore /etc/resolv.conf: %v", rerr))
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

		// 3. Re-enable and start previously active services (or re-enable paused enabled-only services)
		// in forward dependency order (base services -> dex-daemon -> timers).
		restoreStoppedUnit := func(name string) {
			if stoppedActiveSet[name] {
				_ = exec.ServiceEnableStart(ctx, ropts.InitSystem, name)
				return
			}
			if stoppedEnabledOnlySet[name] && ropts.InitSystem == "systemd" {
				_, _ = exec.RunCommand(ctx, nil, "systemctl", "enable", name)
			}
		}
		for _, sp := range orderedSpecs {
			if !strings.HasSuffix(sp.name, ".timer") {
				restoreStoppedUnit(sp.name)
			}
		}
		restoreStoppedUnit("dex-daemon")
		for _, sp := range orderedSpecs {
			if strings.HasSuffix(sp.name, ".timer") {
				restoreStoppedUnit(sp.name)
			}
		}

		// 4. Restart only services that were already active before this apply and were restarted.
		for _, ts := range touchedSvcs {
			if ts.wasActive {
				_ = exec.ServiceRestart(ctx, ropts.InitSystem, ts.name)
			}
		}
		_, _ = store.RollbackTxn()
		return nil, fmt.Errorf("apply services failed (rolled back): %w", err)
	}

	// Clean up backups (including any stale .prev files left by prior crashes) and commit manifest + state transaction
	for _, b := range backups {
		_ = os.Remove(b.prevPath)
		if dir := filepath.Dir(b.diskPath); strings.HasSuffix(dir, ".service.d") {
			_ = os.Remove(dir)
		}
	}
	cleanupStalePrevFiles(opts.RootPrefix, ropts.GeneratedDir)
	if err := SaveManifest(store.ManifestPath(), BuildManifest(bundle.Files)); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("save manifest: %v", err))
	}
	if err := store.CommitTxn(); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("commit txn: %v", err))
	}
	return res, nil
}

func loadHostsFileCache(path string) map[string][]netip.Addr {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := make(map[string][]netip.Addr)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		host := strings.TrimSpace(fields[0])
		if host == "" || host == "localhost" || strings.HasPrefix(host, "domain:") || strings.HasPrefix(host, "full:") {
			continue
		}
		if ip, perr := netip.ParseAddr(strings.TrimSpace(fields[1])); perr == nil {
			out[host] = append(out[host], ip)
		}
	}
	return out
}

const fallbackPublicDNS = "nameserver 223.5.5.5\nnameserver 1.1.1.1\n"

func hasNonLoopbackNameserver(content []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ns := strings.Trim(strings.TrimSpace(fields[1]), "[]")
			if ns == "127.0.0.1" || ns == "127.0.0.53" || ns == "::1" {
				continue
			}
			if ip, err := netip.ParseAddr(ns); err == nil && ip.IsLoopback() {
				continue
			}
			if ns != "" {
				return true
			}
		}
	}
	return false
}

func restoreResolvConfIfNeeded(resolvPath, origPath string) error {
	curBytes, err := os.ReadFile(resolvPath)
	if err != nil {
		return nil
	}
	if strings.TrimSpace(string(curBytes)) != "nameserver 127.0.0.1" {
		return nil
	}
	origBytes, err := os.ReadFile(origPath)
	if err != nil || len(bytes.TrimSpace(origBytes)) == 0 || !hasNonLoopbackNameserver(origBytes) {
		return writeBytesExact(resolvPath, []byte(fallbackPublicDNS), 0o644)
	}
	return writeBytesExact(resolvPath, origBytes, 0o644)
}

func cleanupStalePrevFiles(rootPrefix, generatedDir string) {
	genDisk := mapTargetPath(rootPrefix, generatedDir)
	dirs := []string{
		genDisk,
		filepath.Join(genDisk, "mosdns"),
		filepath.Join(genDisk, "wg-peers"),
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".prev") {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	_ = os.Remove(mapTargetPath(rootPrefix, "/etc/wireguard/wg0.conf.prev"))
}
