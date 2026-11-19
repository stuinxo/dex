package reconcile

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stuinxo/de_GWD/v3/internal/render"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

type mockExecutor struct {
	cmds           []string
	hasCmd         map[string]bool
	failValidation string // "xray" | "nft" | "haproxy" | "nginx"
	failHealthSvc  string
	inactiveSvcs   map[string]bool
	startedSvcs    []string
	stoppedSvcs    []string
}

func (m *mockExecutor) RunCommand(ctx context.Context, env []string, name string, args ...string) (string, error) {
	full := name + " " + strings.Join(args, " ")
	m.cmds = append(m.cmds, full)
	if m.failValidation == "xray" && strings.Contains(full, "xray") && strings.Contains(full, "-test") {
		return "bad xray config", errors.New("exit 1")
	}
	if m.failValidation == "nft" && name == "nft" && strings.Contains(full, "-c") {
		return "bad nft syntax", errors.New("exit 1")
	}
	if m.failValidation == "haproxy" && name == "haproxy" {
		return "bad haproxy cfg", errors.New("exit 1")
	}
	if m.failValidation == "nginx" && name == "nginx" {
		return "nginx syntax err", errors.New("exit 1")
	}
	return "ok", nil
}

func (m *mockExecutor) HasCommand(name string) bool {
	if m.hasCmd == nil {
		return true
	}
	return m.hasCmd[name]
}

func (m *mockExecutor) DaemonReload(ctx context.Context, initSys string) error { return nil }
func (m *mockExecutor) ServiceEnableStart(ctx context.Context, initSys, name string) error {
	m.startedSvcs = append(m.startedSvcs, name)
	return nil
}
func (m *mockExecutor) ServiceRestart(ctx context.Context, initSys, name string) error {
	m.startedSvcs = append(m.startedSvcs, "restart:"+name)
	return nil
}
func (m *mockExecutor) ServiceStopDisable(ctx context.Context, initSys, name string) error {
	m.stoppedSvcs = append(m.stoppedSvcs, name)
	return nil
}
func (m *mockExecutor) ServiceIsActive(ctx context.Context, initSys, name string) bool {
	if m.failHealthSvc == name {
		return false
	}
	return !m.inactiveSvcs[name]
}
func (m *mockExecutor) DetectInitSystem() string  { return "systemd" }
func (m *mockExecutor) DetectIsContainer() bool   { return false }
func (m *mockExecutor) DetectMemMB() int          { return 256 }
func (m *mockExecutor) DetectPhysicalNICs() []string { return []string{"eth0"} }
func (m *mockExecutor) ResolveHostIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}

func TestReconcileLifecycleAndRollback(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	s := state.NewDefaultState(state.RoleLanding)
	s.Server.Domain = "land.example.com"
	s.Server.ListenPort = 20001
	s.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	if err := store.Save(s); err != nil {
		t.Fatalf("Save initial state: %v", err)
	}

	exec := &mockExecutor{}
	opts := ApplyOptions{
		RootPrefix: root,
		RenderOpts: render.RenderOptions{
			StateDir:     "/etc/dex",
			GeneratedDir: "/etc/dex/generated",
			CertFile:     filepath.Join(stateDir, "ssl", "dex.cer"),
			KeyFile:      filepath.Join(stateDir, "ssl", "dex.key"),
		},
	}

	// 1. Initial reconcile succeeds
	res, err := Reconcile(context.Background(), store, exec, opts)
	if err != nil {
		t.Fatalf("Reconcile initial failed: %v", err)
	}
	if len(res.FilesWritten) == 0 {
		t.Fatalf("expected files written")
	}
	xrayDisk := filepath.Join(root, "etc", "dex", "generated", "xray.json")
	origXray, err := os.ReadFile(xrayDisk)
	if err != nil || !strings.Contains(string(origXray), "20001") {
		t.Fatalf("xray.json missing port 20001 on disk: err=%v", err)
	}

	// 2. Manual modification guard rejects overwrite unless Force=true
	if err := os.WriteFile(xrayDisk, append(origXray, []byte("// manual edit\n")...), 0o640); err != nil {
		t.Fatalf("simulate manual edit: %v", err)
	}
	if _, err := Reconcile(context.Background(), store, exec, opts); !errors.Is(err, ErrManualModificationDetected) {
		t.Fatalf("expected ErrManualModificationDetected, got %v", err)
	}
	optsForce := opts
	optsForce.Force = true
	if _, err := Reconcile(context.Background(), store, exec, optsForce); err != nil {
		t.Fatalf("Reconcile with Force=true failed: %v", err)
	}

	// 3. Pre-flight xray -test failure leaves original config & state untouched
	exec.failValidation = "xray"
	if _, _, err := UpdateAndReconcile(context.Background(), store, state.RoleLanding, exec, opts, func(cur *state.State) error {
		cur.Server.ListenPort = 20002
		return nil
	}); err == nil {
		t.Fatalf("expected preflight failure")
	}
	afterPreflightFail, _ := os.ReadFile(xrayDisk)
	if !strings.Contains(string(afterPreflightFail), "20001") || strings.Contains(string(afterPreflightFail), "20002") {
		t.Fatalf("expected live xray.json untouched after preflight failure")
	}
	reloaded1, _ := store.Load()
	if reloaded1.Server.ListenPort != 20001 {
		t.Fatalf("expected state rolled back to 20001, got %d", reloaded1.Server.ListenPort)
	}

	// 4. Health probe failure rolls back both live files and state.json
	exec.failValidation = ""
	exec.failHealthSvc = "dex-xray"
	if _, _, err := UpdateAndReconcile(context.Background(), store, state.RoleLanding, exec, opts, func(cur *state.State) error {
		cur.Server.ListenPort = 20002
		return nil
	}); err == nil {
		t.Fatalf("expected health check failure")
	}
	afterHealthRollback, _ := os.ReadFile(xrayDisk)
	if !strings.Contains(string(afterHealthRollback), "20001") {
		t.Fatalf("expected rollback to port 20001 in xray.json, got:\n%s", string(afterHealthRollback))
	}
	reloaded2, _ := store.Load()
	if reloaded2.Server.ListenPort != 20001 {
		t.Fatalf("expected state rolled back to 20001 after health fail, got %d", reloaded2.Server.ListenPort)
	}
}
