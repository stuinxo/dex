package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/update"
)

func bootstrapRoleRuntimeDeps(ctx context.Context, store *state.Store, exec reconcile.SystemExecutor, role string, opsCfg update.OpsConfig, stdout io.Writer) error {
	if exec == nil {
		return nil
	}
	cfg := opsCfg.WithDefaults("latest")
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" && store != nil {
		if st, err := store.Load(); err == nil && st != nil {
			role = st.Role
		}
	}
	if role == "" {
		return nil
	}

	var missingPkgs []string
	switch role {
	case state.RoleClient:
		if !exec.HasCommand("wg-quick") {
			missingPkgs = append(missingPkgs, "wireguard-tools")
		}
	case state.RoleServer:
		if !exec.HasCommand("nginx") {
			missingPkgs = append(missingPkgs, "nginx")
		}
		if !exec.HasCommand("socat") {
			missingPkgs = append(missingPkgs, "socat")
		}
		if !exec.HasCommand("wg-quick") {
			missingPkgs = append(missingPkgs, "wireguard-tools")
		}
	case state.RoleRelay:
		if !exec.HasCommand("haproxy") {
			missingPkgs = append(missingPkgs, "haproxy")
		}
	}
	if len(missingPkgs) > 0 {
		if stdout != nil {
			fmt.Fprintf(stdout, "[*] Installing missing packages for %s (%s)...\n", role, strings.Join(missingPkgs, ", "))
		}
		if err := installSystemPackages(ctx, exec, missingPkgs); err != nil {
			return err
		}
	}
	if role == state.RoleServer {
		_ = os.Remove("/etc/nginx/sites-enabled/default")
	}

	if !exec.HasCommand(cfg.XrayBinPath) {
		if err := update.UpdateComponents(ctx, store, exec, cfg, "xray", "latest", stdout); err != nil {
			return fmt.Errorf("install xray: %w", err)
		}
	}

	rulesDir := "/etc/dex/rules"
	if store != nil {
		rulesDir = filepath.Join(store.Dir, "rules")
	}
	switch role {
	case state.RoleClient:
		if !exec.HasCommand(cfg.MosDNSBinPath) {
			if err := update.UpdateComponents(ctx, store, exec, cfg, "mosdns", "latest", stdout); err != nil {
				return fmt.Errorf("install mosdns: %w", err)
			}
		}
		if clientRulesMissing(store, rulesDir) {
			if err := update.UpdateRules(ctx, store, exec, cfg, false, true, stdout); err != nil {
				return fmt.Errorf("install client rules: %w", err)
			}
		}
	case state.RoleServer, state.RoleLanding, state.RoleRelay:
		if err := ensureGeoDatRules(ctx, cfg, rulesDir, stdout); err != nil {
			return err
		}
	}
	return nil
}

func installSystemPackages(ctx context.Context, exec reconcile.SystemExecutor, pkgs []string) error {
	if len(pkgs) == 0 {
		return nil
	}
	if exec.HasCommand("apk") {
		args := append([]string{"add", "--no-cache"}, pkgs...)
		if out, err := exec.RunCommand(ctx, nil, "apk", args...); err != nil {
			return fmt.Errorf("apk add %s: %w (%s)", strings.Join(pkgs, " "), err, strings.TrimSpace(out))
		}
		return nil
	}
	if exec.HasCommand("apt-get") {
		env := []string{"DEBIAN_FRONTEND=noninteractive"}
		_, _ = exec.RunCommand(ctx, env, "apt-get", "update", "-qq")
		args := append([]string{"install", "-y", "-qq", "--no-install-recommends"}, pkgs...)
		if out, err := exec.RunCommand(ctx, env, "apt-get", args...); err != nil {
			return fmt.Errorf("apt-get install %s: %w (%s)", strings.Join(pkgs, " "), err, strings.TrimSpace(out))
		}
		return nil
	}
	return nil
}

func clientRulesMissing(store *state.Store, rulesDir string) bool {
	required := append([]string(nil), state.RequiredClientBaseRuleFiles...)
	if store != nil {
		if st, err := store.Load(); err == nil && st != nil && st.Client.DNS.BlockAds {
			required = append(required, "Domains.ads.txt")
		}
	}
	for _, name := range required {
		info, err := os.Stat(filepath.Join(rulesDir, name))
		if err != nil || info.IsDir() || info.Size() == 0 {
			return true
		}
	}
	return false
}

func ensureGeoDatRules(ctx context.Context, cfg update.OpsConfig, rulesDir string, stdout io.Writer) error {
	targets := []struct {
		name string
		url  string
		dst  string
	}{
		{name: "geoip.dat", url: cfg.GeoIPURL, dst: filepath.Join(rulesDir, "geoip.dat")},
		{name: "geosite.dat", url: cfg.GeoSiteURL, dst: filepath.Join(rulesDir, "geosite.dat")},
	}
	var missingIdx []int
	for i, t := range targets {
		if info, err := os.Stat(t.dst); err != nil || info.IsDir() || info.Size() == 0 {
			missingIdx = append(missingIdx, i)
		}
	}
	if len(missingIdx) == 0 {
		return nil
	}
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}
	for _, i := range missingIdx {
		t := targets[i]
		if stdout != nil {
			fmt.Fprintf(stdout, "[*] Downloading %s (SHA256 verified)...\n", t.name)
		}
		if err := update.DownloadVerifiedFile(ctx, cfg.Client, t.url, t.url+".sha256sum", t.dst, false); err != nil {
			return fmt.Errorf("download %s: %w", t.name, err)
		}
	}
	return nil
}
