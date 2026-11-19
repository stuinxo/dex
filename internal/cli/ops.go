package cli

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

// OpsConfig configures remote sources and install targets for dex rules/update (overridable in tests).
type OpsConfig struct {
	Client          *http.Client
	GeoIPURL        string
	GeoSiteURL      string
	ChnRouteURL     string
	DomainsChnURL   string
	DomainsAdsURL   string
	DexRepo         string
	DexReleaseBase  string // optional override base URL instead of GitHub repo releases
	XrayReleaseBase string
	MosDNSBase      string
	DexBinPath      string
	XrayBinPath     string
	MosDNSBinPath   string
	GOARCH          string
	MinChnRouteCIDR int
	MinChnDomains   int
	MinAdsDomains   int
}

func (c OpsConfig) withDefaults(versionTag string) OpsConfig {
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 180 * time.Second}
	}
	if c.GeoIPURL == "" {
		c.GeoIPURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	}
	if c.GeoSiteURL == "" {
		c.GeoSiteURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
	}
	if c.ChnRouteURL == "" {
		c.ChnRouteURL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt"
	}
	if c.DomainsChnURL == "" {
		c.DomainsChnURL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt"
	}
	if c.DomainsAdsURL == "" {
		c.DomainsAdsURL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt"
	}
	if c.DexRepo == "" {
		c.DexRepo = strings.TrimSpace(os.Getenv("DEX_REPO"))
		if c.DexRepo == "" {
			c.DexRepo = "stuinxo/de_GWD"
		}
	}
	if c.DexReleaseBase == "" {
		if versionTag == "" || versionTag == "latest" {
			c.DexReleaseBase = fmt.Sprintf("https://github.com/%s/releases/latest/download", c.DexRepo)
		} else {
			c.DexReleaseBase = fmt.Sprintf("https://github.com/%s/releases/download/%s", c.DexRepo, versionTag)
		}
	}
	if c.XrayReleaseBase == "" {
		c.XrayReleaseBase = "https://github.com/XTLS/Xray-core/releases/latest/download"
	}
	if c.MosDNSBase == "" {
		c.MosDNSBase = "https://github.com/IrineSistiana/mosdns/releases/latest/download"
	}
	if c.DexBinPath == "" {
		c.DexBinPath = "/usr/local/bin/dex"
	}
	if c.XrayBinPath == "" {
		c.XrayBinPath = "/usr/local/bin/xray"
	}
	if c.MosDNSBinPath == "" {
		c.MosDNSBinPath = "/usr/local/bin/mosdns"
	}
	if c.GOARCH == "" {
		c.GOARCH = runtime.GOARCH
	}
	if c.MinChnRouteCIDR <= 0 {
		c.MinChnRouteCIDR = 1000
	}
	if c.MinChnDomains <= 0 {
		c.MinChnDomains = 10000
	}
	if c.MinAdsDomains <= 0 {
		c.MinAdsDomains = 1000
	}
	return c
}

func cmdRules(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "status" {
		return printRulesStatus(store, stdout)
	}
	switch args[0] {
	case "update":
		fs := flag.NewFlagSet("rules update", flag.ContinueOnError)
		fs.SetOutput(stderr)
		includeAds := fs.Bool("ads", false, "also download Domains.ads.txt reject-list")
		noApply := fs.Bool("no-apply", false, "skip reconcile apply after updating rules")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := UpdateRules(context.Background(), store, exec, OpsConfig{}, *includeAds, *noApply, stdout); err != nil {
			fmt.Fprintf(stderr, "rules update failed: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown rules subcommand %q\n", args[0])
		return 2
	}
}

func printRulesStatus(store *state.Store, stdout io.Writer) int {
	rulesDir := filepath.Join(store.Dir, "rules")
	fmt.Fprintf(stdout, "Rules Directory: %s\n", rulesDir)
	for _, name := range []string{"geoip.dat", "geosite.dat", "IPchnroute", "Domains.chn.txt", "Domains.ads.txt"} {
		p := filepath.Join(rulesDir, name)
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(stdout, "  %-16s missing\n", name)
			continue
		}
		fmt.Fprintf(stdout, "  %-16s %8d KB  (%s)\n", name, info.Size()/1024, info.ModTime().Format(time.RFC3339))
	}
	return 0
}

// UpdateRules downloads, checksum/syntax validates, atomically promotes route rules, and optionally reconciles.
func UpdateRules(ctx context.Context, store *state.Store, exec reconcile.SystemExecutor, cfg OpsConfig, includeAds, noApply bool, stdout io.Writer) error {
	cfg = cfg.withDefaults("")
	rulesDir := filepath.Join(store.Dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}

	st, stErr := store.Load()
	if stErr == nil && st != nil && st.Client.DNS.BlockAds {
		includeAds = true
	}

	if stdout != nil {
		fmt.Fprintf(stdout, "[*] Updating geoip.dat & geosite.dat (SHA256 verified)...\n")
	}
	if err := DownloadVerifiedFile(ctx, cfg.Client, cfg.GeoIPURL, cfg.GeoIPURL+".sha256sum", filepath.Join(rulesDir, "geoip.dat"), false); err != nil {
		return fmt.Errorf("update geoip.dat: %w", err)
	}
	if err := DownloadVerifiedFile(ctx, cfg.Client, cfg.GeoSiteURL, cfg.GeoSiteURL+".sha256sum", filepath.Join(rulesDir, "geosite.dat"), false); err != nil {
		return fmt.Errorf("update geosite.dat: %w", err)
	}

	if stdout != nil {
		fmt.Fprintf(stdout, "[*] Updating IPchnroute & Domains.chn.txt...\n")
	}
	if err := downloadAndValidateTextRule(ctx, cfg.Client, cfg.ChnRouteURL, filepath.Join(rulesDir, "IPchnroute"), func(path string) error {
		return validateChnRouteFile(path, cfg.MinChnRouteCIDR)
	}); err != nil {
		return fmt.Errorf("update IPchnroute: %w", err)
	}
	if err := downloadAndValidateTextRule(ctx, cfg.Client, cfg.DomainsChnURL, filepath.Join(rulesDir, "Domains.chn.txt"), func(path string) error {
		return validateDomainListFile(path, cfg.MinChnDomains)
	}); err != nil {
		return fmt.Errorf("update Domains.chn.txt: %w", err)
	}

	if includeAds {
		if stdout != nil {
			fmt.Fprintf(stdout, "[*] Updating Domains.ads.txt...\n")
		}
		if err := downloadAndValidateTextRule(ctx, cfg.Client, cfg.DomainsAdsURL, filepath.Join(rulesDir, "Domains.ads.txt"), func(path string) error {
			return validateDomainListFile(path, cfg.MinAdsDomains)
		}); err != nil {
			return fmt.Errorf("update Domains.ads.txt: %w", err)
		}
	}

	if stdout != nil {
		fmt.Fprintln(stdout, "[+] Rules updated cleanly.")
	}
	if !noApply && stErr == nil && st != nil {
		if _, err := reconcile.Reconcile(ctx, store, exec, reconcile.ApplyOptions{}); err != nil {
			return fmt.Errorf("reconcile after rules update: %w", err)
		}
		if stdout != nil {
			fmt.Fprintln(stdout, "[+] Applied updated rules.")
		}
	}
	return nil
}

func downloadAndValidateTextRule(ctx context.Context, client *http.Client, rawURL, dstPath string, validate func(string) error) error {
	stagePath := dstPath + ".stage"
	defer os.Remove(stagePath)
	if err := DownloadWithMirrors(ctx, client, rawURL, stagePath, nil); err != nil {
		return err
	}
	if err := validate(stagePath); err != nil {
		return err
	}
	if err := os.Chmod(stagePath, 0o644); err != nil {
		return err
	}
	return os.Rename(stagePath, dstPath)
}

func validateChnRouteFile(path string, minCIDRs int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(strings.ToLower(line), "<html") {
			return errors.New("downloaded IPchnroute looks like HTML")
		}
		if p, perr := netip.ParsePrefix(line); perr == nil && p.Addr().Is4() {
			count++
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if count < minCIDRs {
		return fmt.Errorf("IPchnroute validation failed: only %d IPv4 CIDRs (want >= %d)", count, minCIDRs)
	}
	return nil
}

func validateDomainListFile(path string, minLines int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "<html") || strings.Contains(low, "<!doctype html") {
			return errors.New("downloaded domain rule file looks like HTML")
		}
		count++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if count < minLines {
		return fmt.Errorf("domain list validation failed: only %d entries (want >= %d)", count, minLines)
	}
	return nil
}

func cmdUpdate(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	component := fs.String("component", "all", "all|dex|xray|mosdns|rules")
	ver := fs.String("version", "latest", "target dex version tag (e.g. latest or v3.0.0)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := UpdateComponents(context.Background(), store, exec, OpsConfig{}, *component, *ver, stdout); err != nil {
		fmt.Fprintf(stderr, "update failed: %v\n", err)
		return 1
	}
	return 0
}

// UpdateComponents upgrades dex, xray, mosdns, and/or rule datasets atomically with checksum & ELF checks.
func UpdateComponents(ctx context.Context, store *state.Store, exec reconcile.SystemExecutor, cfg OpsConfig, component, versionTag string, stdout io.Writer) error {
	cfg = cfg.withDefaults(versionTag)
	dexArch, xrayArch, mosArch, err := mapArch(cfg.GOARCH)
	if err != nil {
		return err
	}

	st, stErr := store.Load()
	hasBinary := func(p string) bool {
		info, serr := os.Stat(p)
		return serr == nil && !info.IsDir()
	}

	updateOne := func(comp string) error {
		switch comp {
		case "dex":
			return updateDexBinary(ctx, exec, cfg, dexArch, stdout)
		case "xray":
			return updateXrayBinary(ctx, exec, cfg, xrayArch, stdout)
		case "mosdns":
			return updateMosDNSBinary(ctx, exec, cfg, mosArch, stdout)
		case "rules":
			return UpdateRules(ctx, store, exec, cfg, false, false, stdout)
		default:
			return fmt.Errorf("unknown component %q (want all|dex|xray|mosdns|rules)", comp)
		}
	}

	if component != "all" {
		return updateOne(component)
	}

	if err := updateOne("dex"); err != nil {
		return err
	}
	if hasBinary(cfg.XrayBinPath) || (stErr == nil && st.Role != state.RoleRelay) {
		if err := updateOne("xray"); err != nil {
			return err
		}
	}
	if hasBinary(cfg.MosDNSBinPath) || (stErr == nil && st.Role == state.RoleClient) {
		if err := updateOne("mosdns"); err != nil {
			return err
		}
	}
	if _, rerr := os.Stat(filepath.Join(store.Dir, "rules")); rerr == nil || (stErr == nil && st.Role == state.RoleClient) {
		if err := updateOne("rules"); err != nil {
			return err
		}
	}
	return nil
}

func mapArch(goarch string) (dexArch, xrayArch, mosArch string, err error) {
	switch goarch {
	case "amd64":
		return "amd64", "64", "amd64", nil
	case "arm64":
		return "arm64", "arm64-v8a", "arm64", nil
	default:
		return "", "", "", fmt.Errorf("unsupported architecture: %s", goarch)
	}
}

func findSHA256Entry(sumsData []byte, assetName string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(string(sumsData)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == assetName {
			return NormalizeSHA256(fields[0])
		}
	}
	return "", fmt.Errorf("checksum entry for %s not found", assetName)
}

func parseXrayDigest(dgstData []byte) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(string(dgstData)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		for _, prefix := range []string{"SHA2-256=", "SHA256="} {
			if rest, ok := strings.CutPrefix(line, prefix); ok {
				return NormalizeSHA256(rest)
			}
		}
	}
	return "", errors.New("SHA2-256 digest not found in .dgst")
}

func installBinaryAtomic(srcPath, dstPath string) error {
	ok, err := IsELFBinary(srcPath)
	if err != nil || !ok {
		return fmt.Errorf("%s is not a valid Linux ELF binary", srcPath)
	}
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dstPath), ".dexupd.tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()
	in, err := os.Open(srcPath)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	_, copyErr := io.Copy(tmp, in)
	_ = in.Close()
	if copyErr != nil {
		_ = tmp.Close()
		return copyErr
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dstPath); err != nil {
		return err
	}
	success = true
	return nil
}

func extractZipBinary(zipPath, entryBase, dstPath string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip %s: %w", zipPath, err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.FileInfo().IsDir() || filepath.Base(f.Name) != entryBase {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(dstPath), ".zipext.tmp.*")
		if err != nil {
			_ = rc.Close()
			return err
		}
		tmpName := tmp.Name()
		_, copyErr := io.Copy(tmp, io.LimitReader(rc, 256<<20))
		_ = rc.Close()
		closeErr := tmp.Close()
		if copyErr != nil || closeErr != nil {
			_ = os.Remove(tmpName)
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		}
		err = installBinaryAtomic(tmpName, dstPath)
		_ = os.Remove(tmpName)
		return err
	}
	return fmt.Errorf("entry %q not found inside %s", entryBase, zipPath)
}

func updateDexBinary(ctx context.Context, exec reconcile.SystemExecutor, cfg OpsConfig, dexArch string, stdout io.Writer) error {
	if local := strings.TrimSpace(os.Getenv("DEX_BIN")); local != "" {
		if info, err := os.Stat(local); err == nil && !info.IsDir() {
			if err := installBinaryAtomic(local, cfg.DexBinPath); err != nil {
				return err
			}
			_ = os.Remove(filepath.Join(filepath.Dir(cfg.DexBinPath), "de_GWD"))
			_ = os.Symlink(cfg.DexBinPath, filepath.Join(filepath.Dir(cfg.DexBinPath), "de_GWD"))
			if stdout != nil {
				fmt.Fprintf(stdout, "[+] Updated dex from local DEX_BIN=%s\n", local)
			}
			restartIfActive(ctx, exec, "dex-doh", "dex-daemon")
			return nil
		}
	}

	asset := "dex-linux-" + dexArch
	binStage := cfg.DexBinPath + ".stage"
	sumStage := cfg.DexBinPath + ".sha256"
	defer os.Remove(binStage)
	defer os.Remove(sumStage)

	if stdout != nil {
		fmt.Fprintf(stdout, "[*] Downloading %s...\n", asset)
	}
	if err := DownloadWithMirrors(ctx, cfg.Client, strings.TrimRight(cfg.DexReleaseBase, "/")+"/"+asset, binStage, nil); err != nil {
		return err
	}
	if err := DownloadWithMirrors(ctx, cfg.Client, strings.TrimRight(cfg.DexReleaseBase, "/")+"/SHA256SUMS", sumStage, nil); err != nil {
		return err
	}
	sumsData, err := os.ReadFile(sumStage)
	if err != nil {
		return err
	}
	expectedHex, err := findSHA256Entry(sumsData, asset)
	if err != nil {
		return err
	}
	if err := VerifyFileSHA256(binStage, expectedHex); err != nil {
		return err
	}
	if err := installBinaryAtomic(binStage, cfg.DexBinPath); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(filepath.Dir(cfg.DexBinPath), "de_GWD"))
	_ = os.Symlink(cfg.DexBinPath, filepath.Join(filepath.Dir(cfg.DexBinPath), "de_GWD"))
	if stdout != nil {
		fmt.Fprintf(stdout, "[+] Updated %s cleanly.\n", cfg.DexBinPath)
	}
	restartIfActive(ctx, exec, "dex-doh", "dex-daemon")
	return nil
}

func updateXrayBinary(ctx context.Context, exec reconcile.SystemExecutor, cfg OpsConfig, xrayArch string, stdout io.Writer) error {
	zipName := fmt.Sprintf("Xray-linux-%s.zip", xrayArch)
	tmpDir, err := os.MkdirTemp("", "dex-xray-upd-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, zipName)
	dgstPath := zipPath + ".dgst"
	base := strings.TrimRight(cfg.XrayReleaseBase, "/")

	if stdout != nil {
		fmt.Fprintf(stdout, "[*] Downloading %s...\n", zipName)
	}
	if err := DownloadWithMirrors(ctx, cfg.Client, base+"/"+zipName, zipPath, nil); err != nil {
		return err
	}
	if err := DownloadWithMirrors(ctx, cfg.Client, base+"/"+zipName+".dgst", dgstPath, nil); err != nil {
		return err
	}
	dgstBytes, err := os.ReadFile(dgstPath)
	if err != nil {
		return err
	}
	expected, err := parseXrayDigest(dgstBytes)
	if err != nil {
		return err
	}
	if err := VerifyFileSHA256(zipPath, expected); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.XrayBinPath), 0o755); err != nil {
		return err
	}
	if err := extractZipBinary(zipPath, "xray", cfg.XrayBinPath); err != nil {
		return err
	}
	if stdout != nil {
		fmt.Fprintf(stdout, "[+] Updated %s cleanly.\n", cfg.XrayBinPath)
	}
	restartIfActive(ctx, exec, "dex-xray")
	return nil
}

func updateMosDNSBinary(ctx context.Context, exec reconcile.SystemExecutor, cfg OpsConfig, mosArch string, stdout io.Writer) error {
	zipName := fmt.Sprintf("mosdns-linux-%s.zip", mosArch)
	tmpDir, err := os.MkdirTemp("", "dex-mos-upd-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, zipName)
	base := strings.TrimRight(cfg.MosDNSBase, "/")
	if stdout != nil {
		fmt.Fprintf(stdout, "[*] Downloading %s...\n", zipName)
	}
	if err := DownloadWithMirrors(ctx, cfg.Client, base+"/"+zipName, zipPath, nil); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.MosDNSBinPath), 0o755); err != nil {
		return err
	}
	if err := extractZipBinary(zipPath, "mosdns", cfg.MosDNSBinPath); err != nil {
		return err
	}
	if stdout != nil {
		fmt.Fprintf(stdout, "[+] Updated %s cleanly.\n", cfg.MosDNSBinPath)
	}
	restartIfActive(ctx, exec, "dex-mosdns")
	return nil
}

func restartIfActive(ctx context.Context, exec reconcile.SystemExecutor, units ...string) {
	if exec == nil {
		return
	}
	initSys := exec.DetectInitSystem()
	for _, u := range units {
		if exec.ServiceIsActive(ctx, initSys, u) {
			_ = exec.ServiceRestart(ctx, initSys, u)
		}
	}
}

func cleanupLegacyV2(ctx context.Context, exec reconcile.SystemExecutor, stdout io.Writer) {
	initSys := exec.DetectInitSystem()
	for _, svc := range []string{"vtrui", "smartdns", "coredns", "mosdns", "RproxyC", "RproxyS", "doh-server", "nftables"} {
		_ = exec.ServiceStopDisable(ctx, initSys, svc)
	}
	if exec.HasCommand("docker") {
		_, _ = exec.RunCommand(ctx, nil, "docker", "rm", "-f", "pihole")
	}
	if exec.HasCommand("nft") {
		for _, family := range []string{"inet", "ip", "ip6"} {
			_, _ = exec.RunCommand(ctx, nil, "nft", "delete", "table", family, "de_GWD")
		}
	}
	if stdout != nil {
		fmt.Fprintln(stdout, "[+] Stopped and cleaned legacy v2 services / pihole container / de_GWD nft tables.")
	}
}
