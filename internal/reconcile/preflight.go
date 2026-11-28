package reconcile

import (
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

type fileBackup struct {
	diskPath string
	prevPath string
	existed  bool
	mode     os.FileMode
}

type changedFile struct {
	relName    string
	targetPath string
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

func dryRunPreflight(ctx context.Context, exec SystemExecutor, store *state.Store, st *state.State, ropts render.RenderOptions, rootPrefix string, bundle *render.RenderBundle) error {
	dryDir, err := os.MkdirTemp("", "dex-dryrun-*")
	if err != nil {
		return fmt.Errorf("create dry-run temp dir: %w", err)
	}
	defer os.RemoveAll(dryDir)

	dryRopts := ropts
	dryFiles := bundle.Files
	if !HasCustomExternalCert(store, st) {
		certDisk := fsutil.MapRootPrefix(rootPrefix, ropts.CertFile)
		keyDisk := fsutil.MapRootPrefix(rootPrefix, ropts.KeyFile)
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
	if (bundle.NFTClientNeeded || bundle.NFTRelayNeeded || bundle.NFTHostFWNeeded) && !exec.HasCommand("nft") {
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

func backupTargetFile(rootPrefix, targetPath string, backups *[]fileBackup) error {
	diskPath := fsutil.MapRootPrefix(rootPrefix, targetPath)
	prevPath := diskPath + ".prev"
	info, statErr := os.Stat(diskPath)
	if os.IsNotExist(statErr) {
		*backups = append(*backups, fileBackup{diskPath: diskPath, prevPath: prevPath, existed: false})
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
	*backups = append(*backups, fileBackup{
		diskPath: diskPath,
		prevPath: prevPath,
		existed:  true,
		mode:     info.Mode().Perm(),
	})
	return nil
}

func rollbackFileBackups(backups []fileBackup) {
	for _, b := range backups {
		if b.existed {
			_ = os.Rename(b.prevPath, b.diskPath)
		} else {
			_ = os.Remove(b.diskPath)
			_ = os.Remove(b.prevPath)
		}
	}
}

func cleanupStalePrevFiles(rootPrefix, generatedDir string) {
	genDisk := fsutil.MapRootPrefix(rootPrefix, generatedDir)
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
	_ = os.Remove(fsutil.MapRootPrefix(rootPrefix, "/etc/wireguard/wg0.conf.prev"))
}
