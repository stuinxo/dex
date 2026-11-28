package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stuinxo/dex/internal/fsutil"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/update"
)

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
		if err := update.UpdateRules(context.Background(), store, exec, update.OpsConfig{}, *includeAds, *noApply, stdout); err != nil {
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
	for _, name := range state.ManagedRuleFiles {
		p := filepath.Join(rulesDir, name)
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(stdout, "  %-18s missing\n", name)
			continue
		}
		fmt.Fprintf(stdout, "  %-18s %8d KB  (%s)\n", name, info.Size()/1024, info.ModTime().Format(time.RFC3339))
	}
	return 0
}

func cmdUpdate(store *state.Store, exec reconcile.SystemExecutor, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	component := fs.String("component", "all", "all|dex|xray|mosdns|rules")
	ver := fs.String("version", "latest", "target dex version tag (e.g. latest or v0.0.5)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := update.UpdateComponents(context.Background(), store, exec, update.OpsConfig{}, *component, *ver, stdout); err != nil {
		fmt.Fprintf(stderr, "update failed: %v\n", err)
		return 1
	}
	return 0
}

// legacyV2Services lists systemd units managed by v2 (stuinxo-de_GWD-main).
// Intentionally excludes system "nftables" service because its ExecStop runs "nft flush ruleset".
var legacyV2Services = []string{
	"vtrui",
	"vtrui1",
	"smartdns",
	"coredns",
	"mosdns",
	"RproxyC",
	"RproxyS",
	"doh-server",
	"unbound",
	"php-fpm",
	"updateGWD",
}

// legacyV2NFTTables lists the nftables tables created by v2 scripts.
var legacyV2NFTTables = []struct {
	family string
	table  string
}{
	{family: "ip", table: "de_GWD"},
	{family: "inet", table: "bypassflow"},
	{family: "inet", table: "filter"},
	{family: "inet", table: "router"},
}

type nginxFileBackup struct {
	path    string
	content []byte
	mode    os.FileMode
}

type v2CleanupSnapshot struct {
	initSys          string
	activeServices   []string
	piholeWasRunning bool
	nftDir           string
	nginxBackups     []nginxFileBackup
}

func cleanupLegacyV2(ctx context.Context, exec reconcile.SystemExecutor, stdout io.Writer) *v2CleanupSnapshot {
	return cleanupLegacyV2WithPaths(ctx, exec, "/opt/de_GWD/nftables", "/etc/nginx/conf.d", stdout)
}

func cleanupLegacyV2WithPaths(ctx context.Context, exec reconcile.SystemExecutor, v2NFTDir, nginxConfDir string, stdout io.Writer) *v2CleanupSnapshot {
	initSys := exec.DetectInitSystem()
	snap := &v2CleanupSnapshot{
		initSys: initSys,
		nftDir:  v2NFTDir,
	}
	for _, svc := range legacyV2Services {
		if exec.ServiceIsActive(ctx, initSys, svc) {
			snap.activeServices = append(snap.activeServices, svc)
		}
	}
	for _, svc := range legacyV2Services {
		_ = exec.ServiceStopDisable(ctx, initSys, svc)
	}
	if exec.HasCommand("docker") {
		if out, err := exec.RunCommand(ctx, nil, "docker", "inspect", "-f", "{{.State.Running}}", "pihole"); err == nil && strings.TrimSpace(out) == "true" {
			snap.piholeWasRunning = true
			_, _ = exec.RunCommand(ctx, nil, "docker", "stop", "pihole")
		}
	}
	if exec.HasCommand("nft") {
		for _, t := range legacyV2NFTTables {
			_, _ = exec.RunCommand(ctx, nil, "nft", "delete", "table", t.family, t.table)
		}
	}
	if nginxConfDir != "" {
		for _, name := range []string{"default.conf", "80.conf"} {
			p := filepath.Join(nginxConfDir, name)
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				continue
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				continue
			}
			if bytes.Contains(b, []byte("de_GWD")) || bytes.Contains(b, []byte("9890")) || bytes.Contains(b, []byte("/dq")) {
				snap.nginxBackups = append(snap.nginxBackups, nginxFileBackup{
					path:    p,
					content: b,
					mode:    info.Mode().Perm(),
				})
				_ = os.Remove(p)
			}
		}
	}
	if stdout != nil {
		fmt.Fprintln(stdout, "[+] Stopped legacy v2 services, pihole container (if running), legacy nginx configs, and v2 nft tables.")
	}
	return snap
}

func (s *v2CleanupSnapshot) restore(ctx context.Context, exec reconcile.SystemExecutor, stdout io.Writer) {
	if s == nil {
		return
	}
	for _, nb := range s.nginxBackups {
		_ = fsutil.WriteFileAtomic(nb.path, nb.content, nb.mode)
	}
	if len(s.nginxBackups) > 0 && exec != nil && exec.ServiceIsActive(ctx, s.initSys, "nginx") {
		_ = exec.ServiceReload(ctx, s.initSys, "nginx")
	}
	for _, svc := range s.activeServices {
		_ = exec.ServiceEnableStart(ctx, s.initSys, svc)
	}
	if s.piholeWasRunning && exec.HasCommand("docker") {
		_, _ = exec.RunCommand(ctx, nil, "docker", "start", "pihole")
	}
	if exec.HasCommand("nft") && s.nftDir != "" {
		flowScript := filepath.Join(s.nftDir, "flowtable_eth.sh")
		if _, err := os.Stat(flowScript); err == nil {
			shell := "sh"
			if exec.HasCommand("bash") {
				shell = "bash"
			}
			_, _ = exec.RunCommand(ctx, nil, shell, flowScript)
		}
		clientNFT := filepath.Join(s.nftDir, "nftables")
		serverNFT := filepath.Join(s.nftDir, "default.nft")
		if _, err := os.Stat(clientNFT); err == nil {
			_, _ = exec.RunCommand(ctx, nil, "nft", "-f", clientNFT)
		} else if _, err := os.Stat(serverNFT); err == nil {
			_, _ = exec.RunCommand(ctx, nil, "nft", "-f", serverNFT)
		}
	}
	if stdout != nil {
		fmt.Fprintln(stdout, "[!] Restored previously active legacy v2 services / pihole / nft rules after apply failure.")
	}
}
