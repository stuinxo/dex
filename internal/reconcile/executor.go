package reconcile

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// SystemExecutor abstracts OS command execution, service lifecycle, and host inspection
// so reconciliation transactions can be unit-tested offline.
type SystemExecutor interface {
	RunCommand(ctx context.Context, env []string, name string, args ...string) (string, error)
	HasCommand(name string) bool
	DaemonReload(ctx context.Context, initSys string) error
	ServiceEnableStart(ctx context.Context, initSys, name string) error
	ServiceRestart(ctx context.Context, initSys, name string) error
	ServiceStopDisable(ctx context.Context, initSys, name string) error
	ServiceIsActive(ctx context.Context, initSys, name string) bool
	DetectInitSystem() string
	DetectIsContainer() bool
	DetectMemMB() int
	DetectPhysicalNICs() []string
	ResolveHostIPs(ctx context.Context, host string) ([]netip.Addr, error)
}

// OSExecutor is the production Linux/Unix SystemExecutor implementation.
type OSExecutor struct{}

func (OSExecutor) RunCommand(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (OSExecutor) HasCommand(name string) bool {
	if filepath.IsAbs(name) {
		info, err := os.Stat(name)
		return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
	}
	_, err := exec.LookPath(name)
	return err == nil
}

func (e OSExecutor) DaemonReload(ctx context.Context, initSys string) error {
	if initSys == "systemd" && e.HasCommand("systemctl") {
		_, err := e.RunCommand(ctx, nil, "systemctl", "daemon-reload")
		return err
	}
	return nil
}

func (e OSExecutor) ServiceEnableStart(ctx context.Context, initSys, name string) error {
	if initSys == "openrc" {
		_, _ = e.RunCommand(ctx, nil, "rc-update", "add", name, "default")
		out, err := e.RunCommand(ctx, nil, "rc-service", name, "restart")
		if err != nil {
			out, err = e.RunCommand(ctx, nil, "rc-service", name, "start")
		}
		if err != nil {
			return fmt.Errorf("openrc start %s: %w (%s)", name, err, strings.TrimSpace(out))
		}
		return nil
	}
	_, _ = e.RunCommand(ctx, nil, "systemctl", "enable", name)
	out, err := e.RunCommand(ctx, nil, "systemctl", "restart", name)
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	return nil
}

func (e OSExecutor) ServiceRestart(ctx context.Context, initSys, name string) error {
	if initSys == "openrc" {
		out, err := e.RunCommand(ctx, nil, "rc-service", name, "restart")
		if err != nil {
			return fmt.Errorf("openrc restart %s: %w (%s)", name, err, strings.TrimSpace(out))
		}
		return nil
	}
	out, err := e.RunCommand(ctx, nil, "systemctl", "restart", name)
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w (%s)", name, err, strings.TrimSpace(out))
	}
	return nil
}

func (e OSExecutor) ServiceStopDisable(ctx context.Context, initSys, name string) error {
	if initSys == "openrc" {
		_, _ = e.RunCommand(ctx, nil, "rc-service", name, "stop")
		_, _ = e.RunCommand(ctx, nil, "rc-update", "del", name, "default")
		return nil
	}
	_, _ = e.RunCommand(ctx, nil, "systemctl", "disable", "--now", name)
	return nil
}

func (e OSExecutor) ServiceIsActive(ctx context.Context, initSys, name string) bool {
	if initSys == "openrc" {
		_, err := e.RunCommand(ctx, nil, "rc-service", name, "status")
		return err == nil
	}
	_, err := e.RunCommand(ctx, nil, "systemctl", "is-active", "--quiet", name)
	return err == nil
}

func (e OSExecutor) DetectInitSystem() string {
	if info, err := os.Stat("/run/systemd/system"); err == nil && info.IsDir() {
		return "systemd"
	}
	if e.HasCommand("rc-service") {
		return "openrc"
	}
	return "systemd"
}

func (e OSExecutor) DetectIsContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	if e.HasCommand("systemd-detect-virt") {
		if _, err := e.RunCommand(context.Background(), nil, "systemd-detect-virt", "--container", "--quiet"); err == nil {
			return true
		}
	}
	return false
}

func (OSExecutor) DetectMemMB() int {
	totalMB := 512
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.Atoi(fields[1]); err == nil && kb > 0 {
						totalMB = kb / 1024
					}
				}
				break
			}
		}
	}
	for _, cgPath := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		b, err := os.ReadFile(cgPath)
		if err != nil {
			continue
		}
		raw := strings.TrimSpace(string(b))
		if raw == "" || raw == "max" {
			continue
		}
		if limitBytes, err := strconv.ParseInt(raw, 10, 64); err == nil && limitBytes > 0 {
			limitMB := int(limitBytes / 1048576)
			if limitMB > 0 && limitMB < totalMB {
				totalMB = limitMB
			}
		}
	}
	return totalMB
}

func (OSExecutor) DetectPhysicalNICs() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []string
	for _, ent := range entries {
		name := ent.Name()
		if name == "lo" ||
			strings.HasPrefix(name, "ifb") ||
			strings.HasPrefix(name, "wg") ||
			strings.HasPrefix(name, "docker") ||
			strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "tun") ||
			strings.HasPrefix(name, "tap") {
			continue
		}
		devLink, err := os.Readlink(filepath.Join("/sys/class/net", name))
		if err != nil {
			continue
		}
		if strings.Contains(devLink, "virtual") {
			continue
		}
		out = append(out, name)
	}
	return out
}

func lookupDNSWithServer(ctx context.Context, dnsAddr, host string) ([]netip.Addr, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(dctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dctx, "udp", dnsAddr)
		},
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return r.LookupNetIP(cctx, "ip", host)
}

func (OSExecutor) ResolveHostIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return nil, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(cctx, "ip", host)
	if err == nil && len(ips) > 0 {
		return ips, nil
	}
	for _, fallbackDNS := range []string{"223.5.5.5:53", "1.1.1.1:53"} {
		if fips, ferr := lookupDNSWithServer(ctx, fallbackDNS, host); ferr == nil && len(fips) > 0 {
			return fips, nil
		}
	}
	if err != nil {
		return nil, err
	}
	return ips, nil
}
