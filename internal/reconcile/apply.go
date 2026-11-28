package reconcile

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/fsutil"
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
			return fsutil.MapRootPrefix(opts.RootPrefix, p)
		}); err != nil {
			_, _ = store.RollbackTxn()
			return nil, err
		}
	}

	certCreated := ensureRuntimeArtifacts(store, st, ropts, opts.RootPrefix, res)

	stagedPaths := make(map[string]string, len(bundle.Files))
	cleanupStaged := func() {
		for _, sp := range stagedPaths {
			_ = os.Remove(sp)
		}
	}
	for _, f := range bundle.Files {
		diskTarget := fsutil.MapRootPrefix(opts.RootPrefix, f.TargetPath)
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
	if err := ensureRequiredRuntimeTools(ctx, exec, ropts, bundle, isOS); err != nil {
		cleanupStaged()
		_, _ = store.RollbackTxn()
		return nil, err
	}

	if err := preflightValidate(ctx, exec, ropts, stagedPaths, bundle.Files); err != nil {
		cleanupStaged()
		_, _ = store.RollbackTxn()
		return nil, err
	}

	newTargets := make(map[string]struct{}, len(bundle.Files))
	for _, f := range bundle.Files {
		newTargets[f.TargetPath] = struct{}{}
	}

	var backups []fileBackup
	for _, f := range bundle.Files {
		if err := backupTargetFile(opts.RootPrefix, f.TargetPath, &backups); err != nil {
			cleanupStaged()
			rollbackFileBackups(backups)
			_, _ = store.RollbackTxn()
			return nil, fmt.Errorf("backup %s: %w", f.TargetPath, err)
		}
	}
	for oldTarget := range prevManifest.Files {
		if _, stillNeeded := newTargets[oldTarget]; stillNeeded {
			continue
		}
		if err := backupTargetFile(opts.RootPrefix, oldTarget, &backups); err != nil {
			cleanupStaged()
			rollbackFileBackups(backups)
			_, _ = store.RollbackTxn()
			return nil, fmt.Errorf("backup obsolete %s: %w", oldTarget, err)
		}
	}

	changedFiles := detectChangedFiles(opts.RootPrefix, bundle.Files, prevManifest, newTargets)

	for _, f := range bundle.Files {
		diskPath := fsutil.MapRootPrefix(opts.RootPrefix, f.TargetPath)
		if err := os.Rename(stagedPaths[f.TargetPath], diskPath); err != nil {
			cleanupStaged()
			rollbackFileBackups(backups)
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
		_ = os.Remove(fsutil.MapRootPrefix(opts.RootPrefix, oldTarget))
		res.FilesRemoved = append(res.FilesRemoved, oldTarget)
	}

	if bundle.NginxNeeded && isOS {
		webRoot := strings.TrimSpace(st.Server.CamouflageDir)
		if webRoot == "" {
			webRoot = "/var/www/html"
		}
		indexDisk := fsutil.MapRootPrefix(opts.RootPrefix, filepath.Join(webRoot, "index.html"))
		if _, statErr := os.Stat(indexDisk); os.IsNotExist(statErr) {
			_ = writeBytesExact(indexDisk, []byte("<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Welcome</title></head><body><h1>Welcome</h1></body></html>\n"), 0o644)
		}
	}

	if bundle.NginxNeeded && exec.HasCommand("nginx") {
		if out, err := exec.RunCommand(ctx, nil, "nginx", "-t"); err != nil {
			rollbackFileBackups(backups)
			_, _ = store.RollbackTxn()
			return nil, fmt.Errorf("nginx -t failed (rolled back): %w (%s)", err, strings.TrimSpace(out))
		}
	}

	orch := newServiceOrchestrator(ctx, store, exec, opts, st, ropts, bundle, changedFiles, obsoleteUnitPaths, certCreated, isOS, res)
	if err := orch.apply(); err != nil {
		orch.rollback(backups)
		_, _ = store.RollbackTxn()
		return nil, fmt.Errorf("apply services failed (rolled back): %w", err)
	}

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

func ensureRuntimeArtifacts(store *state.Store, st *state.State, ropts render.RenderOptions, rootPrefix string, res *ApplyResult) bool {
	if st.Role == state.RoleClient && st.Client.DNS.BlockAds {
		adsDiskPath := fsutil.MapRootPrefix(rootPrefix, filepath.Join(ropts.StateDir, "rules", "Domains.ads.txt"))
		if _, statErr := os.Stat(adsDiskPath); os.IsNotExist(statErr) {
			if werr := writeBytesExact(adsDiskPath, []byte{}, 0o644); werr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("create placeholder Domains.ads.txt: %v", werr))
			} else {
				res.Warnings = append(res.Warnings, "Domains.ads.txt missing; created empty placeholder (run 'dex rules update --ads' to populate)")
			}
		}
	}
	if HasCustomExternalCert(store, st) {
		return false
	}
	certDisk := fsutil.MapRootPrefix(rootPrefix, ropts.CertFile)
	keyDisk := fsutil.MapRootPrefix(rootPrefix, ropts.KeyFile)
	prevCert, errC := os.ReadFile(certDisk)
	prevKey, errK := os.ReadFile(keyDisk)
	cn := st.Server.Domain
	if cn == "" {
		cn = st.Auth.ServerName
	}
	if cerr := cert.EnsureSelfSigned(certDisk, keyDisk, cn); cerr == nil {
		afterCert, _ := os.ReadFile(certDisk)
		afterKey, _ := os.ReadFile(keyDisk)
		return errC != nil || errK != nil || !bytes.Equal(prevCert, afterCert) || !bytes.Equal(prevKey, afterKey)
	}
	return false
}

func ensureRequiredRuntimeTools(ctx context.Context, exec SystemExecutor, ropts render.RenderOptions, bundle *render.RenderBundle, isOS bool) error {
	if bundle.HAProxyNeeded && isOS && !exec.HasCommand("haproxy") {
		var (
			out  string
			ierr error
		)
		if exec.HasCommand("apt-get") {
			out, ierr = exec.RunCommand(ctx, []string{"DEBIAN_FRONTEND=noninteractive"}, "sh", "-c", "apt-get update -qq && apt-get install -y -qq --no-install-recommends haproxy")
		} else if exec.HasCommand("apk") {
			out, ierr = exec.RunCommand(ctx, nil, "apk", "add", "--no-cache", "haproxy")
		}
		if ierr != nil {
			return fmt.Errorf("auto-install haproxy failed: %w (%s)", ierr, strings.TrimSpace(out))
		}
	}
	if isOS {
		return checkRequiredBinaries(exec, ropts, bundle, false)
	}
	return nil
}

func detectChangedFiles(rootPrefix string, files []render.RenderedFile, prevManifest *Manifest, newTargets map[string]struct{}) []changedFile {
	var changed []changedFile
	for _, f := range files {
		diskPath := fsutil.MapRootPrefix(rootPrefix, f.TargetPath)
		diskBytes, rerr := os.ReadFile(diskPath)
		if rerr != nil || !bytes.Equal(diskBytes, f.Content) {
			changed = append(changed, changedFile{relName: f.RelName, targetPath: f.TargetPath})
		}
	}
	for oldTarget := range prevManifest.Files {
		if _, stillNeeded := newTargets[oldTarget]; !stillNeeded {
			changed = append(changed, changedFile{targetPath: oldTarget})
		}
	}
	return changed
}
