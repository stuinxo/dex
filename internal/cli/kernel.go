package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/stuinxo/dex/internal/fsutil"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/state"
)

const (
	defaultZabblyRepoBase = "https://pkgs.zabbly.com/kernel/stable"
	defaultZabblyKeyURL   = "https://pkgs.zabbly.com/key.asc"
	zabblyKeyringSysPath  = "/etc/apt/keyrings/zabbly.asc"
	zabblySourcesSysPath  = "/etc/apt/sources.list.d/zabbly-kernel-stable.sources"
	defaultMinBootFreeMB  = uint64(200)
)

// KernelConfig configures kernel inspection and Zabbly mainline kernel installation.
type KernelConfig struct {
	Client         *http.Client
	RepoBaseURL    string
	KeyURL         string
	RootPrefix     string
	OSReleasePath  string
	ArchOverride   string
	BootFreeMBFn   func() (uint64, error)
	MinBootFreeMB  uint64
	SkipRootCheck  bool
	KernelRelease  string
	CongestionCtrl string
	DefaultQdisc   string
}

func (c KernelConfig) withDefaults() KernelConfig {
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 60 * time.Second}
	}
	if strings.TrimSpace(c.RepoBaseURL) == "" {
		c.RepoBaseURL = defaultZabblyRepoBase
	}
	c.RepoBaseURL = strings.TrimRight(strings.TrimSpace(c.RepoBaseURL), "/")
	if strings.TrimSpace(c.KeyURL) == "" {
		c.KeyURL = defaultZabblyKeyURL
	}
	if strings.TrimSpace(c.OSReleasePath) == "" {
		c.OSReleasePath = "/etc/os-release"
	}
	if c.BootFreeMBFn == nil {
		c.BootFreeMBFn = defaultBootFreeMB
	}
	if c.MinBootFreeMB == 0 {
		c.MinBootFreeMB = defaultMinBootFreeMB
	}
	return c
}

// KernelInfo describes the host kernel, OS compatibility, and Zabbly eligibility.
type KernelInfo struct {
	Release        string
	Arch           string
	DistroID       string
	Codename       string
	IsContainer    bool
	IsZabbly       bool
	CongestionCtrl string
	DefaultQdisc   string
	BootFreeMB     uint64
	BootFreeKnown  bool
	Eligible       bool
	BlockReason    string
}

func defaultBootFreeMB() (uint64, error) {
	path := "/boot"
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		path = "/"
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		if path != "/" {
			if err2 := syscall.Statfs("/", &st); err2 == nil {
				return uint64(st.Bavail) * uint64(st.Bsize) / (1024 * 1024), nil
			}
		}
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize) / (1024 * 1024), nil
}

func readTrimmedFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func parseOSRelease(content string) (id, idLike, codename string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		switch strings.TrimSpace(k) {
		case "ID":
			id = strings.ToLower(v)
		case "ID_LIKE":
			idLike = strings.ToLower(v)
		case "VERSION_CODENAME":
			codename = strings.ToLower(v)
		}
	}
	return id, idLike, codename
}

func isDebianOrUbuntu(id, idLike string) bool {
	if id == "debian" || id == "ubuntu" {
		return true
	}
	for _, f := range strings.Fields(idLike) {
		if f == "debian" || f == "ubuntu" {
			return true
		}
	}
	return false
}

func detectKernelArch(ctx context.Context, exec reconcile.SystemExecutor, cfg KernelConfig) string {
	if strings.TrimSpace(cfg.ArchOverride) != "" {
		return strings.TrimSpace(cfg.ArchOverride)
	}
	if exec != nil && exec.HasCommand("dpkg") {
		if out, err := exec.RunCommand(ctx, nil, "dpkg", "--print-architecture"); err == nil {
			a := strings.TrimSpace(out)
			if a != "" && !strings.ContainsAny(a, " \t\n") {
				return a
			}
		}
	}
	return runtime.GOARCH
}

// InspectKernel gathers active kernel, congestion control, OS codename, and Zabbly install eligibility.
func InspectKernel(ctx context.Context, exec reconcile.SystemExecutor, cfg KernelConfig) KernelInfo {
	cfg = cfg.withDefaults()
	var info KernelInfo

	if strings.TrimSpace(cfg.KernelRelease) != "" {
		info.Release = strings.TrimSpace(cfg.KernelRelease)
	} else if r := readTrimmedFile("/proc/sys/kernel/osrelease"); r != "" {
		info.Release = r
	} else if exec != nil && exec.HasCommand("uname") {
		if out, err := exec.RunCommand(ctx, nil, "uname", "-r"); err == nil {
			info.Release = strings.TrimSpace(out)
		}
	}
	info.IsZabbly = strings.Contains(strings.ToLower(info.Release), "zabbly")

	if strings.TrimSpace(cfg.CongestionCtrl) != "" {
		info.CongestionCtrl = strings.TrimSpace(cfg.CongestionCtrl)
	} else {
		info.CongestionCtrl = readTrimmedFile("/proc/sys/net/ipv4/tcp_congestion_control")
	}
	if strings.TrimSpace(cfg.DefaultQdisc) != "" {
		info.DefaultQdisc = strings.TrimSpace(cfg.DefaultQdisc)
	} else {
		info.DefaultQdisc = readTrimmedFile("/proc/sys/net/core/default_qdisc")
	}

	info.Arch = detectKernelArch(ctx, exec, cfg)
	if exec != nil {
		info.IsContainer = exec.DetectIsContainer()
	}

	var idLike string
	if rawOS, err := os.ReadFile(cfg.OSReleasePath); err == nil {
		info.DistroID, idLike, info.Codename = parseOSRelease(string(rawOS))
	}

	if freeMB, err := cfg.BootFreeMBFn(); err == nil {
		info.BootFreeMB = freeMB
		info.BootFreeKnown = true
	}

	switch {
	case info.IsContainer:
		info.BlockReason = "container environment detected (LXC/Docker shares host kernel; install Zabbly on KVM/bare-metal only)"
	case exec == nil || !exec.HasCommand("apt-get") || !exec.HasCommand("dpkg"):
		info.BlockReason = "requires Debian or Ubuntu with apt-get and dpkg"
	case !isDebianOrUbuntu(info.DistroID, idLike) || info.Codename == "":
		info.BlockReason = fmt.Sprintf("unsupported OS (%q / codename=%q); requires Debian or Ubuntu", info.DistroID, info.Codename)
	case info.Arch != "amd64" && info.Arch != "arm64":
		info.BlockReason = fmt.Sprintf("unsupported architecture %q (Zabbly supports amd64 and arm64)", info.Arch)
	case info.BootFreeKnown && info.BootFreeMB < cfg.MinBootFreeMB:
		info.BlockReason = fmt.Sprintf("insufficient free space on /boot (%d MiB available, require >= %d MiB)", info.BootFreeMB, cfg.MinBootFreeMB)
	default:
		info.Eligible = true
	}

	return info
}

func formatKernelSummaryLine(info KernelInfo) string {
	rel := info.Release
	if rel == "" {
		rel = "unknown"
	}
	var extras []string
	if info.CongestionCtrl != "" {
		netOpt := info.CongestionCtrl
		if info.DefaultQdisc != "" {
			netOpt += "+" + info.DefaultQdisc
		}
		extras = append(extras, netOpt)
	}
	if info.IsContainer {
		extras = append(extras, "container")
	}
	if len(extras) == 0 {
		return rel
	}
	return fmt.Sprintf("%s (%s)", rel, strings.Join(extras, ", "))
}

func checkZabblySuiteAvailable(ctx context.Context, client *http.Client, repoBase, codename string) error {
	relURL := fmt.Sprintf("%s/dists/%s/Release", strings.TrimRight(repoBase, "/"), codename)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, relURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("check Zabbly suite %q: %w", codename, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("Zabbly kernel repo does not publish suite %q (Debian 12/13 or Ubuntu 22.04/24.04+ required)", codename)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("check Zabbly suite %q failed: HTTP %d from %s", codename, resp.StatusCode, relURL)
	}
	return nil
}

func fetchZabblyKey(ctx context.Context, client *http.Client, keyURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download Zabbly GPG key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download Zabbly GPG key failed: HTTP %d from %s", resp.StatusCode, keyURL)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, fmt.Errorf("read Zabbly GPG key: %w", err)
	}
	text := string(body)
	lower := strings.ToLower(text)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
		return nil, errors.New("invalid Zabbly GPG key response (received HTML)")
	}
	if !strings.Contains(text, "-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
		!strings.Contains(text, "-----END PGP PUBLIC KEY BLOCK-----") {
		return nil, errors.New("invalid Zabbly GPG key response (missing PGP public key block)")
	}
	return body, nil
}

func renderZabblySources(repoBase, codename, arch string) string {
	return fmt.Sprintf(`Enabled: yes
Types: deb
URIs: %s
Suites: %s
Components: main
Architectures: %s
Signed-By: %s
`, strings.TrimRight(repoBase, "/"), codename, arch, zabblyKeyringSysPath)
}

// InstallZabblyKernel validates host eligibility and Zabbly repo support, configures
// DEB822 APT sources + GPG keyring, and installs linux-zabbly without purging stock kernels.
func InstallZabblyKernel(ctx context.Context, exec reconcile.SystemExecutor, cfg KernelConfig, dryRun bool, stdout io.Writer) error {
	cfg = cfg.withDefaults()
	if !cfg.SkipRootCheck && runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return errors.New("root privileges required to install kernel")
	}

	info := InspectKernel(ctx, exec, cfg)
	if !info.Eligible {
		return errors.New(info.BlockReason)
	}

	if err := checkZabblySuiteAvailable(ctx, cfg.Client, cfg.RepoBaseURL, info.Codename); err != nil {
		return err
	}

	sourcesContent := renderZabblySources(cfg.RepoBaseURL, info.Codename, info.Arch)
	keyDst := fsutil.MapRootPrefix(cfg.RootPrefix, zabblyKeyringSysPath)
	sourcesDst := fsutil.MapRootPrefix(cfg.RootPrefix, zabblySourcesSysPath)

	if dryRun {
		if stdout != nil {
			fmt.Fprintf(stdout, "[dry-run] Host eligible: %s %s (%s), current kernel %s\n", info.DistroID, info.Codename, info.Arch, info.Release)
			fmt.Fprintf(stdout, "[dry-run] Would download key: %s -> %s\n", cfg.KeyURL, keyDst)
			fmt.Fprintf(stdout, "[dry-run] Would write %s:\n%s", sourcesDst, sourcesContent)
			fmt.Fprintln(stdout, "[dry-run] Would run: apt-get update && apt-get install -y --no-install-recommends linux-zabbly")
		}
		return nil
	}

	keyData, err := fetchZabblyKey(ctx, cfg.Client, cfg.KeyURL)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(keyDst, keyData, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", keyDst, err)
	}
	if err := fsutil.WriteFileAtomic(sourcesDst, []byte(sourcesContent), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", sourcesDst, err)
	}

	if stdout != nil {
		fmt.Fprintf(stdout, "[*] Configured Zabbly repo (%s/%s) and updating apt...\n", info.Codename, info.Arch)
	}
	aptEnv := []string{"DEBIAN_FRONTEND=noninteractive"}
	if out, err := exec.RunCommand(ctx, aptEnv, "apt-get", "update"); err != nil {
		return fmt.Errorf("apt-get update: %w (%s)", err, strings.TrimSpace(out))
	}
	if stdout != nil {
		fmt.Fprintln(stdout, "[*] Installing linux-zabbly (keeping existing stock kernel for fallback)...")
	}
	if out, err := exec.RunCommand(ctx, aptEnv, "apt-get", "install", "-y", "--no-install-recommends", "linux-zabbly"); err != nil {
		return fmt.Errorf("apt-get install linux-zabbly: %w (%s)", err, strings.TrimSpace(out))
	}

	if stdout != nil {
		fmt.Fprintln(stdout, "[+] Installed linux-zabbly. Existing kernel packages were preserved as fallback.")
		fmt.Fprintln(stdout, "[!] Note: If UEFI Secure Boot is enabled in VM firmware, disable Secure Boot before rebooting.")
		fmt.Fprintln(stdout, "[*] Run 'reboot' (or pass --reboot) to boot into the Zabbly kernel.")
	}
	return nil
}

func printKernelStatus(info KernelInfo, w io.Writer) {
	fmt.Fprintf(w, "Kernel Release:  %s (Zabbly: %v)\n", firstNonEmpty(info.Release, "unknown"), info.IsZabbly)
	if info.CongestionCtrl != "" || info.DefaultQdisc != "" {
		fmt.Fprintf(w, "Network Tuning:  congestion=%s qdisc=%s\n",
			firstNonEmpty(info.CongestionCtrl, "unknown"), firstNonEmpty(info.DefaultQdisc, "unknown"))
	}
	fmt.Fprintf(w, "Platform:        os=%s codename=%s arch=%s container=%v\n",
		firstNonEmpty(info.DistroID, "unknown"), firstNonEmpty(info.Codename, "unknown"),
		firstNonEmpty(info.Arch, "unknown"), info.IsContainer)
	if info.BootFreeKnown {
		fmt.Fprintf(w, "/boot Free:      %d MiB\n", info.BootFreeMB)
	}
	if info.Eligible {
		fmt.Fprintln(w, "Zabbly Install:  eligible")
	} else {
		fmt.Fprintf(w, "Zabbly Install:  blocked (%s)\n", info.BlockReason)
	}
}

func cmdKernel(_ *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	return cmdKernelWithConfig(exec, KernelConfig{}, args, stdout, stderr)
}

func cmdKernelWithConfig(exec reconcile.SystemExecutor, cfg KernelConfig, args []string, stdout, stderr io.Writer) int {
	sub := "status"
	rest := args
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			fmt.Fprintln(stdout, "Usage:")
			fmt.Fprintln(stdout, "  dex kernel status                  Inspect active kernel and Zabbly compatibility")
			fmt.Fprintln(stdout, "  dex kernel zabbly [--dry-run] [--reboot]  Install Zabbly mainline kernel (Debian/Ubuntu non-container)")
			return 0
		default:
			sub = args[0]
			rest = args[1:]
		}
	}

	switch sub {
	case "status":
		info := InspectKernel(context.Background(), exec, cfg)
		printKernelStatus(info, stdout)
		return 0
	case "zabbly":
		fs := flag.NewFlagSet("kernel zabbly", flag.ContinueOnError)
		fs.SetOutput(stderr)
		dryRun := fs.Bool("dry-run", false, "check compatibility and print planned changes without modifying system")
		doReboot := fs.Bool("reboot", false, "reboot immediately after successful installation")
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if err := InstallZabblyKernel(context.Background(), exec, cfg, *dryRun, stdout); err != nil {
			fmt.Fprintf(stderr, "kernel zabbly failed: %v\n", err)
			return 1
		}
		if *doReboot && !*dryRun {
			if exec != nil && exec.HasCommand("systemctl") {
				if out, err := exec.RunCommand(context.Background(), nil, "systemctl", "reboot"); err != nil {
					fmt.Fprintf(stderr, "reboot failed: %v (%s)\n", err, strings.TrimSpace(out))
					return 1
				}
			} else if exec != nil && exec.HasCommand("reboot") {
				if out, err := exec.RunCommand(context.Background(), nil, "reboot"); err != nil {
					fmt.Fprintf(stderr, "reboot failed: %v (%s)\n", err, strings.TrimSpace(out))
					return 1
				}
			}
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown kernel subcommand %q (expected status|zabbly)\n", sub)
		return 2
	}
}
