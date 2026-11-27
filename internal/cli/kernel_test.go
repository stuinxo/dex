package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stuinxo/dex/internal/fsutil"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/state"
)

type fakeKernelExec struct {
	reconcile.SystemExecutor
	isContainer bool
	hasApt      bool
	hasDpkg     bool
	cmds        []string
}

func (f *fakeKernelExec) HasCommand(name string) bool {
	switch name {
	case "apt-get":
		return f.hasApt
	case "dpkg":
		return f.hasDpkg
	case "uname", "systemctl":
		return true
	default:
		return false
	}
}

func (f *fakeKernelExec) RunCommand(_ context.Context, _ []string, name string, args ...string) (string, error) {
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	if name == "dpkg" && len(args) > 0 && args[0] == "--print-architecture" {
		return "amd64\n", nil
	}
	if name == "uname" {
		return "6.1.0-28-amd64\n", nil
	}
	return "ok\n", nil
}

func (f *fakeKernelExec) DetectInitSystem() string     { return "systemd" }
func (f *fakeKernelExec) DetectIsContainer() bool      { return f.isContainer }
func (f *fakeKernelExec) DetectMemMB() int             { return 2048 }
func (f *fakeKernelExec) DetectPhysicalNICs() []string { return []string{"eth0"} }
func (f *fakeKernelExec) ResolveHostIPs(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}
func (f *fakeKernelExec) DaemonReload(context.Context, string) error               { return nil }
func (f *fakeKernelExec) ServiceEnableStart(context.Context, string, string) error { return nil }
func (f *fakeKernelExec) ServiceRestart(context.Context, string, string) error     { return nil }
func (f *fakeKernelExec) ServiceReload(context.Context, string, string) error      { return nil }
func (f *fakeKernelExec) ServiceStopDisable(context.Context, string, string) error { return nil }
func (f *fakeKernelExec) ServiceIsActive(context.Context, string, string) bool     { return false }

func writeTestOSRelease(t *testing.T, dir, id, codename string) string {
	t.Helper()
	p := filepath.Join(dir, "os-release")
	content := "NAME=\"TestOS\"\nID=" + id + "\nVERSION_CODENAME=" + codename + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInstallZabblyKernelRefusesContainer(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeKernelExec{isContainer: true, hasApt: true, hasDpkg: true}
	cfg := KernelConfig{
		RootPrefix:     filepath.Join(dir, "root"),
		OSReleasePath:  writeTestOSRelease(t, dir, "debian", "bookworm"),
		BootFreeMBFn:   func() (uint64, error) { return 1024, nil },
		SkipRootCheck:  true,
		KernelRelease:  "4.18.0-el8",
		CongestionCtrl: "bbr",
		DefaultQdisc:   "fq",
	}
	err := InstallZabblyKernel(context.Background(), exec, cfg, false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "container") {
		t.Fatalf("expected container rejection, got %v", err)
	}
}

func TestInstallZabblyKernelRefusesUnsupportedOSAndSuite(t *testing.T) {
	dir := t.TempDir()
	// 1. Non-apt host (Alpine)
	alpineExec := &fakeKernelExec{isContainer: false, hasApt: false, hasDpkg: false}
	cfg := KernelConfig{
		RootPrefix:    filepath.Join(dir, "root"),
		OSReleasePath: writeTestOSRelease(t, dir, "alpine", "3.20"),
		BootFreeMBFn:  func() (uint64, error) { return 1024, nil },
		SkipRootCheck: true,
	}
	if err := InstallZabblyKernel(context.Background(), alpineExec, cfg, false, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "apt-get") {
		t.Fatalf("expected apt-get requirement error, got %v", err)
	}

	// 2. Debian bullseye 404 from Zabbly suite check
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	debExec := &fakeKernelExec{isContainer: false, hasApt: true, hasDpkg: true}
	cfg.Client = srv.Client()
	cfg.RepoBaseURL = srv.URL + "/kernel/stable"
	cfg.KeyURL = srv.URL + "/key.asc"
	cfg.OSReleasePath = writeTestOSRelease(t, dir, "debian", "bullseye")
	err := InstallZabblyKernel(context.Background(), debExec, cfg, false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "bullseye") {
		t.Fatalf("expected unsupported suite error for bullseye, got %v", err)
	}
}

func TestInstallZabblyKernelRefusesLowBootSpace(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeKernelExec{isContainer: false, hasApt: true, hasDpkg: true}
	cfg := KernelConfig{
		RootPrefix:    filepath.Join(dir, "root"),
		OSReleasePath: writeTestOSRelease(t, dir, "debian", "bookworm"),
		BootFreeMBFn:  func() (uint64, error) { return 80, nil },
		SkipRootCheck: true,
	}
	err := InstallZabblyKernel(context.Background(), exec, cfg, false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "insufficient free space") {
		t.Fatalf("expected low /boot space rejection, got %v", err)
	}
}

func TestInstallZabblyKernelRejectsInvalidKey(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kernel/stable/dists/bookworm/Release":
			_, _ = w.Write([]byte("Suite: bookworm\n"))
		case "/key.asc":
			_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	root := filepath.Join(dir, "root")
	exec := &fakeKernelExec{isContainer: false, hasApt: true, hasDpkg: true}
	cfg := KernelConfig{
		Client:        srv.Client(),
		RepoBaseURL:   srv.URL + "/kernel/stable",
		KeyURL:        srv.URL + "/key.asc",
		RootPrefix:    root,
		OSReleasePath: writeTestOSRelease(t, dir, "debian", "bookworm"),
		BootFreeMBFn:  func() (uint64, error) { return 1024, nil },
		SkipRootCheck: true,
	}
	err := InstallZabblyKernel(context.Background(), exec, cfg, false, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "HTML") {
		t.Fatalf("expected HTML key rejection, got %v", err)
	}
	if _, statErr := os.Stat(fsutil.MapRootPrefix(root, zabblySourcesSysPath)); !os.IsNotExist(statErr) {
		t.Fatalf("expected sources file not written on key error, statErr=%v", statErr)
	}
}

func TestInstallZabblyKernelDryRunAndFullSuccess(t *testing.T) {
	dir := t.TempDir()
	const fakeKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQGNBFtestkey\n-----END PGP PUBLIC KEY BLOCK-----\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kernel/stable/dists/trixie/Release":
			_, _ = w.Write([]byte("Suite: trixie\n"))
		case "/key.asc":
			_, _ = w.Write([]byte(fakeKey))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	root := filepath.Join(dir, "root")
	exec := &fakeKernelExec{isContainer: false, hasApt: true, hasDpkg: true}
	cfg := KernelConfig{
		Client:         srv.Client(),
		RepoBaseURL:    srv.URL + "/kernel/stable",
		KeyURL:         srv.URL + "/key.asc",
		RootPrefix:     root,
		OSReleasePath:  writeTestOSRelease(t, dir, "debian", "trixie"),
		BootFreeMBFn:   func() (uint64, error) { return 1024, nil },
		SkipRootCheck:  true,
		KernelRelease:  "6.12.1-amd64",
		CongestionCtrl: "bbr",
		DefaultQdisc:   "cake",
	}

	// 1. Dry-run prints plan without writing files or running apt-get
	var dryOut bytes.Buffer
	if err := InstallZabblyKernel(context.Background(), exec, cfg, true, &dryOut); err != nil {
		t.Fatalf("dry-run failed: %v", err)
	}
	if !strings.Contains(dryOut.String(), "Suites: trixie") || !strings.Contains(dryOut.String(), "linux-zabbly") {
		t.Fatalf("unexpected dry-run output:\n%s", dryOut.String())
	}
	if _, err := os.Stat(fsutil.MapRootPrefix(root, zabblySourcesSysPath)); !os.IsNotExist(err) {
		t.Fatalf("dry-run should not write sources file")
	}

	// 2. Full install writes keyring + DEB822 .sources and runs apt-get update + install
	var out bytes.Buffer
	if err := InstallZabblyKernel(context.Background(), exec, cfg, false, &out); err != nil {
		t.Fatalf("InstallZabblyKernel failed: %v", err)
	}
	keyBytes, err := os.ReadFile(fsutil.MapRootPrefix(root, zabblyKeyringSysPath))
	if err != nil || string(keyBytes) != fakeKey {
		t.Fatalf("keyring mismatch: err=%v got=%q", err, string(keyBytes))
	}
	srcBytes, err := os.ReadFile(fsutil.MapRootPrefix(root, zabblySourcesSysPath))
	if err != nil {
		t.Fatalf("read sources failed: %v", err)
	}
	src := string(srcBytes)
	if !strings.Contains(src, "Suites: trixie") || !strings.Contains(src, "Architectures: amd64") || !strings.Contains(src, "Signed-By: /etc/apt/keyrings/zabbly.asc") {
		t.Fatalf("unexpected .sources content:\n%s", src)
	}

	joinedCmds := strings.Join(exec.cmds, "\n")
	if !strings.Contains(joinedCmds, "apt-get update") || !strings.Contains(joinedCmds, "apt-get install -y --no-install-recommends linux-zabbly") {
		t.Fatalf("expected apt-get update and install linux-zabbly, got:\n%s", joinedCmds)
	}

	// 3. cmdKernel status + menu option 8 -> 1 check
	var statusOut, statusErr bytes.Buffer
	if code := cmdKernelWithConfig(exec, cfg, []string{"status"}, &statusOut, &statusErr); code != 0 {
		t.Fatalf("cmdKernel status failed: code=%d err=%s", code, statusErr.String())
	}
	if !strings.Contains(statusOut.String(), "Zabbly Install:  eligible") || !strings.Contains(statusOut.String(), "congestion=bbr qdisc=cake") {
		t.Fatalf("unexpected kernel status output:\n%s", statusOut.String())
	}

	// 3. Uninitialized menu has no migration item
	uninitStore := state.NewStore(filepath.Join(dir, "uninit-menu-state"))
	var uOut, uErr bytes.Buffer
	if code := runInteractiveMenu(uninitStore, exec, strings.NewReader("q\n"), &uOut, &uErr); code != 0 {
		t.Fatalf("uninit menu exited %d: %s", code, uErr.String())
	}
	if strings.Contains(uOut.String(), "旧版迁移") || !strings.Contains(uOut.String(), "2. 内核管理") {
		t.Fatalf("unexpected uninit menu output:\n%s", uOut.String())
	}

	// 4. Client role menu: kernel option 2->1 and no migration item
	menuDir := filepath.Join(dir, "menu-state")
	menuStore := state.NewStore(menuDir)
	_ = menuStore.Save(state.NewDefaultState(state.RoleClient))
	var mOut, mErr bytes.Buffer
	if code := runInteractiveMenu(menuStore, exec, strings.NewReader("2\n1\n0\nq\n"), &mOut, &mErr); code != 0 {
		t.Fatalf("menu exited %d: %s", code, mErr.String())
	}
	if strings.Contains(mOut.String(), "旧版迁移") || !strings.Contains(mOut.String(), "2. 内核管理") || !strings.Contains(mOut.String(), "Kernel Release:") {
		t.Fatalf("expected client classic menu and kernel status output, got:\n%s", mOut.String())
	}

	// 5. Server role menu: RproxyS human-readable status (option 22) + kernel option 2->1 + EOF exit + no migration item
	srvDir := filepath.Join(dir, "srv-menu-state")
	srvStore := state.NewStore(srvDir)
	srvSt := state.NewDefaultState(state.RoleServer)
	srvSt.Server.Domain = "srv.example.com"
	srvSt.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	_ = srvStore.Save(srvSt)
	var sOut, sErr bytes.Buffer
	if code := runInteractiveMenu(srvStore, exec, strings.NewReader("22\n0\n2\n1\n0\n"), &sOut, &sErr); code != 0 {
		t.Fatalf("server menu exited %d: %s", code, sErr.String())
	}
	if strings.Contains(sOut.String(), "旧版迁移") || !strings.Contains(sOut.String(), "反向代理 RproxyS (服务端)") || !strings.Contains(sOut.String(), "状态: 未启用") || !strings.Contains(sOut.String(), "22. 反向代理 (RproxyS)") {
		t.Fatalf("unexpected server menu output:\n%s", sOut.String())
	}
}
