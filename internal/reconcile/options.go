package reconcile

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/stuinxo/dex/internal/fsutil"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
)

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

func populateRenderOptions(ctx context.Context, st *state.State, store *state.Store, exec SystemExecutor, opts ApplyOptions) (render.RenderOptions, []string) {
	ropts := opts.RenderOpts
	if ropts.StateDir == "" {
		ropts.StateDir = store.Dir
	}
	if ropts.GeneratedDir == "" {
		ropts.GeneratedDir = store.GeneratedDir()
	}
	if ropts.CertFile == "" {
		ropts.CertFile, _ = ResolveActiveCertPaths(store, st)
	}
	if ropts.KeyFile == "" {
		_, ropts.KeyFile = ResolveActiveCertPaths(store, st)
	}
	ropts = ropts.WithDefaults()

	if !ropts.DomainsAppleExists {
		ropts.DomainsAppleExists = isNonEmptyFile(fsutil.MapRootPrefix(opts.RootPrefix, ropts.DomainsApplePath))
	}
	if !ropts.DomainsGamesExists {
		ropts.DomainsGamesExists = isNonEmptyFile(fsutil.MapRootPrefix(opts.RootPrefix, ropts.DomainsGamesPath))
	}
	plan := render.ComputeServicePlan(st)
	if !opts.RenderOpts.NginxLegacyHTTP2 && plan.Nginx && exec != nil && exec.HasCommand("nginx") {
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

	cachedHosts := loadHostsFileCache(fsutil.MapRootPrefix(opts.RootPrefix, filepath.Join(ropts.GeneratedDir, "mosdns", "hosts.txt")))

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
