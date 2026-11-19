package reconcile

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stuinxo/de_GWD/v3/internal/render"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

type mockExecutor struct {
	mu             sync.Mutex
	cmds           []string
	hasCmd         map[string]bool
	failValidation string // "xray" | "nft" | "haproxy" | "nginx"
	failHealthSvc  string
	inactiveSvcs   map[string]bool
	startedSvcs    []string
	stoppedSvcs    []string
	onServiceStart func(name string)
	onServiceStop  func(name string)
}

func (m *mockExecutor) RunCommand(ctx context.Context, env []string, name string, args ...string) (string, error) {
	full := name + " " + strings.Join(args, " ")
	m.mu.Lock()
	m.cmds = append(m.cmds, full)
	failVal := m.failValidation
	m.mu.Unlock()
	if failVal == "xray" && strings.Contains(full, "xray") && strings.Contains(full, "-test") {
		return "bad xray config", errors.New("exit 1")
	}
	if failVal == "nft" && name == "nft" && strings.Contains(full, "-c") {
		return "bad nft syntax", errors.New("exit 1")
	}
	if failVal == "haproxy" && name == "haproxy" {
		return "bad haproxy cfg", errors.New("exit 1")
	}
	if failVal == "nginx" && name == "nginx" {
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
	m.mu.Lock()
	m.startedSvcs = append(m.startedSvcs, name)
	cb := m.onServiceStart
	m.mu.Unlock()
	if cb != nil {
		cb(name)
	}
	return nil
}
func (m *mockExecutor) ServiceRestart(ctx context.Context, initSys, name string) error {
	m.mu.Lock()
	m.startedSvcs = append(m.startedSvcs, "restart:"+name)
	m.mu.Unlock()
	return nil
}
func (m *mockExecutor) ServiceStopDisable(ctx context.Context, initSys, name string) error {
	m.mu.Lock()
	m.stoppedSvcs = append(m.stoppedSvcs, name)
	cb := m.onServiceStop
	m.mu.Unlock()
	if cb != nil {
		cb(name)
	}
	return nil
}
func (m *mockExecutor) ServiceIsActive(ctx context.Context, initSys, name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
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

func TestReconcileRelayTeardownCleansNFTTable(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	s := state.NewDefaultState(state.RoleRelay)
	s.Relay.Forwards = []state.ForwardRule{
		{
			ID:         "fwd-1",
			Name:       "dns",
			ListenPort: 10001,
			TargetHost: "1.1.1.1",
			TargetPort: 53,
			Proto:      "tcp",
			Engine:     "nft",
		},
	}
	if err := store.Save(s); err != nil {
		t.Fatalf("Save initial relay state: %v", err)
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

	if _, err := Reconcile(context.Background(), store, exec, opts); err != nil {
		t.Fatalf("initial relay Reconcile failed: %v", err)
	}

	timerDisk := filepath.Join(root, "etc", "systemd", "system", "dex-refresh.timer")
	svcDisk := filepath.Join(root, "etc", "systemd", "system", "dex-refresh.service")
	stopChecked := false
	exec.onServiceStop = func(name string) {
		if name != "dex-refresh.timer" {
			return
		}
		stopChecked = true
		if _, err := os.Stat(timerDisk); err != nil {
			t.Errorf("expected %s to exist during ServiceStopDisable, got err=%v", timerDisk, err)
		}
		if _, err := os.Stat(svcDisk); err != nil {
			t.Errorf("expected %s to exist during ServiceStopDisable, got err=%v", svcDisk, err)
		}
	}

	exec.cmds = nil
	if _, _, err := UpdateAndReconcile(context.Background(), store, state.RoleRelay, exec, opts, func(cur *state.State) error {
		cur.Relay.Forwards = nil
		return nil
	}); err != nil {
		t.Fatalf("teardown UpdateAndReconcile failed: %v", err)
	}
	if !stopChecked {
		t.Fatalf("expected ServiceStopDisable callback for dex-refresh.timer")
	}
	if _, err := os.Stat(timerDisk); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed after teardown, got err=%v", timerDisk, err)
	}
	if _, err := os.Stat(svcDisk); !os.IsNotExist(err) {
		t.Fatalf("expected %s removed after teardown, got err=%v", svcDisk, err)
	}

	found := false
	for _, cmd := range exec.cmds {
		if cmd == "nft delete table inet dex_relay" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected nft delete table inet dex_relay command during teardown, got cmds=%v", exec.cmds)
	}
}

func TestConcurrentReconcileSerialized(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	s := state.NewDefaultState(state.RoleRelay)
	s.Relay.Forwards = []state.ForwardRule{
		{
			ID:         "fwd-1",
			Name:       "dns",
			ListenPort: 10001,
			TargetHost: "1.1.1.1",
			TargetPort: 53,
			Proto:      "tcp",
			Engine:     "nft",
		},
	}
	if err := store.Save(s); err != nil {
		t.Fatalf("Save initial relay state: %v", err)
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

	if _, err := Reconcile(context.Background(), store, exec, opts); err != nil {
		t.Fatalf("initial relay Reconcile failed: %v", err)
	}

	timerDisk := filepath.Join(root, "etc", "systemd", "system", "dex-refresh.timer")
	timerBytes, err := os.ReadFile(timerDisk)
	if err != nil {
		t.Fatalf("read rendered dex-refresh.timer: %v", err)
	}
	if !strings.Contains(string(timerBytes), "OnActiveSec=5min") || strings.Contains(string(timerBytes), "OnBootSec=") {
		t.Fatalf("unexpected dex-refresh.timer contents:\n%s", string(timerBytes))
	}

	entered := make(chan struct{})
	var once sync.Once
	exec.onServiceStart = func(name string) {
		if name == "dex-nft" {
			once.Do(func() {
				close(entered)
				time.Sleep(120 * time.Millisecond)
			})
		}
	}

	optsForce := opts
	optsForce.Force = true
	reconcileErrCh := make(chan error, 1)
	go func() {
		_, rerr := Reconcile(context.Background(), store, exec, optsForce)
		reconcileErrCh <- rerr
	}()

	<-entered
	if _, _, err := UpdateAndReconcile(context.Background(), store, state.RoleRelay, exec, opts, func(cur *state.State) error {
		cur.Relay.Forwards = nil
		return nil
	}); err != nil {
		t.Fatalf("concurrent UpdateAndReconcile failed: %v", err)
	}
	if rerr := <-reconcileErrCh; rerr != nil {
		t.Fatalf("concurrent Reconcile failed: %v", rerr)
	}

	finalSt, err := store.Load()
	if err != nil {
		t.Fatalf("Load final state: %v", err)
	}
	if len(finalSt.Relay.Forwards) != 0 {
		t.Fatalf("expected relay forwards cleared after serialized runs, got %+v", finalSt.Relay.Forwards)
	}
	if _, err := os.Stat(timerDisk); !os.IsNotExist(err) {
		t.Fatalf("expected dex-refresh.timer removed after teardown, stat err=%v", err)
	}
}
