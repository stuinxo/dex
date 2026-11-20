package reconcile

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stuinxo/de_GWD/v3/internal/cryptoext"
	"github.com/stuinxo/de_GWD/v3/internal/render"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

type mockExecutor struct {
	mu             sync.Mutex
	cmds           []string
	hasCmd         map[string]bool
	failValidation string // "xray" | "nft" | "haproxy" | "nginx"
	failHealthSvc  string
	failReloadSvc  string
	nginxVersion   string
	inactiveSvcs   map[string]bool
	startedSvcs    []string
	reloadedSvcs   []string
	stoppedSvcs    []string
	physicalNICs   []string
	physicalNICSet bool
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
	if name == "nginx" && len(args) == 1 && args[0] == "-v" && m.nginxVersion != "" {
		return m.nginxVersion, nil
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
func (m *mockExecutor) ServiceReload(ctx context.Context, initSys, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReloadSvc == name {
		return errors.New("reload unsupported")
	}
	m.reloadedSvcs = append(m.reloadedSvcs, name)
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
func (m *mockExecutor) DetectInitSystem() string { return "systemd" }
func (m *mockExecutor) DetectIsContainer() bool  { return false }
func (m *mockExecutor) DetectMemMB() int         { return 256 }
func (m *mockExecutor) DetectPhysicalNICs() []string {
	if m.physicalNICSet {
		return m.physicalNICs
	}
	return []string{"eth0"}
}
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
	optsForce.RestartAll = true
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
	optsForce.RestartAll = true
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

func TestReconcileSelectiveRestarts(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	s := state.NewDefaultState(state.RoleClient)
	s.Client.Nodes = []state.OutboundNode{{
		ID:       "n1",
		Name:     "node-1",
		Protocol: "vless-xhttp",
		Address:  "203.0.113.10",
		Port:     443,
		UUID:     "11111111-1111-4111-8111-111111111111",
		Path:     "/xhttp1",
	}}
	s.Client.ActiveNodeID = "n1"
	srvPriv, srvPub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair server: %v", err)
	}
	peerPriv, peerPub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair peer: %v", err)
	}
	s.Client.WireGuard.Enabled = true
	s.Client.WireGuard.ServerPrivateKey = srvPriv
	s.Client.WireGuard.ServerPublicKey = srvPub
	s.Client.WireGuard.EndpointHost = "vpn.example.com"
	s.Client.WireGuard.Peers = []state.WGPeer{{
		Name:       "laptop",
		IP:         "172.16.66.11",
		PrivateKey: peerPriv,
		PublicKey:  peerPub,
	}}
	if err := store.Save(s); err != nil {
		t.Fatalf("Save client state: %v", err)
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

	// 1. Initial apply starts all active services.
	res1, err := Reconcile(context.Background(), store, exec, opts)
	if err != nil {
		t.Fatalf("initial Reconcile failed: %v", err)
	}
	if len(res1.ServicesRestarted) == 0 || len(exec.startedSvcs) == 0 {
		t.Fatalf("expected services started on initial apply")
	}

	// 2. Second apply with no config changes restarts zero services.
	exec.mu.Lock()
	exec.startedSvcs = nil
	exec.reloadedSvcs = nil
	exec.mu.Unlock()

	res2, err := Reconcile(context.Background(), store, exec, opts)
	if err != nil {
		t.Fatalf("second Reconcile failed: %v", err)
	}
	if len(exec.startedSvcs) != 0 || len(exec.reloadedSvcs) != 0 || len(res2.ServicesRestarted) != 0 {
		t.Fatalf("expected zero restarts on no-op Reconcile, got started=%v reloaded=%v res=%v", exec.startedSvcs, exec.reloadedSvcs, res2.ServicesRestarted)
	}

	// 3. Changing only xray node UUID/path restarts only dex-xray.
	exec.mu.Lock()
	exec.startedSvcs = nil
	exec.mu.Unlock()
	if _, _, err := UpdateAndReconcile(context.Background(), store, state.RoleClient, exec, opts, func(cur *state.State) error {
		cur.Client.Nodes[0].UUID = "22222222-2222-4222-8222-222222222222"
		cur.Client.Nodes[0].Path = "/xhttp2"
		return nil
	}); err != nil {
		t.Fatalf("xray-only UpdateAndReconcile failed: %v", err)
	}
	if !reflect.DeepEqual(exec.startedSvcs, []string{"dex-xray"}) {
		t.Fatalf("expected only [dex-xray] restarted, got %v", exec.startedSvcs)
	}

	// 4. An inactive service is started even when no files changed.
	exec.mu.Lock()
	exec.startedSvcs = nil
	exec.inactiveSvcs = map[string]bool{"dex-mosdns": true}
	exec.onServiceStart = func(name string) {
		exec.mu.Lock()
		delete(exec.inactiveSvcs, name)
		exec.mu.Unlock()
	}
	exec.mu.Unlock()
	if _, err := Reconcile(context.Background(), store, exec, opts); err != nil {
		t.Fatalf("Reconcile with inactive dex-mosdns failed: %v", err)
	}
	if !reflect.DeepEqual(exec.startedSvcs, []string{"dex-mosdns"}) {
		t.Fatalf("expected only inactive [dex-mosdns] started, got %v", exec.startedSvcs)
	}

	// 5. RestartAll=true restarts all active managed services despite zero file changes.
	exec.mu.Lock()
	exec.startedSvcs = nil
	exec.inactiveSvcs = nil
	exec.onServiceStart = nil
	exec.mu.Unlock()
	optsRestart := opts
	optsRestart.RestartAll = true
	resAll, err := Reconcile(context.Background(), store, exec, optsRestart)
	if err != nil {
		t.Fatalf("Reconcile with RestartAll=true failed: %v", err)
	}
	wantAll := []string{"dex-nft", "dex-mosdns", "dex-xray", "wg-quick@wg0", "dex-refresh.timer", "dex-rules-update.timer"}
	if !reflect.DeepEqual(exec.startedSvcs, wantAll) || !reflect.DeepEqual(resAll.ServicesRestarted, wantAll) {
		t.Fatalf("expected RestartAll to restart %v, got started=%v res=%v", wantAll, exec.startedSvcs, resAll.ServicesRestarted)
	}
}

func TestReconcileNginxReloadAndFallback(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	s := state.NewDefaultState(state.RoleServer)
	s.Server.Domain = "srv.example.com"
	s.Server.TLSMode = "nginx"
	s.Server.EnableDoH = true
	s.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	s.Server.CamouflageDir = "/var/www/camo1"
	if err := store.Save(s); err != nil {
		t.Fatalf("Save server state: %v", err)
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
		t.Fatalf("initial server Reconcile failed: %v", err)
	}

	// Changing nginx-only field uses reload when active.
	exec.mu.Lock()
	exec.startedSvcs = nil
	exec.reloadedSvcs = nil
	exec.mu.Unlock()
	if _, _, err := UpdateAndReconcile(context.Background(), store, state.RoleServer, exec, opts, func(cur *state.State) error {
		cur.Server.CamouflageDir = "/var/www/camo2"
		return nil
	}); err != nil {
		t.Fatalf("nginx reload UpdateAndReconcile failed: %v", err)
	}
	if len(exec.startedSvcs) != 0 || !reflect.DeepEqual(exec.reloadedSvcs, []string{"nginx"}) {
		t.Fatalf("expected nginx reload without restarts, got started=%v reloaded=%v", exec.startedSvcs, exec.reloadedSvcs)
	}

	// Reload failure falls back to ServiceEnableStart(nginx).
	exec.mu.Lock()
	exec.startedSvcs = nil
	exec.reloadedSvcs = nil
	exec.failReloadSvc = "nginx"
	exec.mu.Unlock()
	if _, _, err := UpdateAndReconcile(context.Background(), store, state.RoleServer, exec, opts, func(cur *state.State) error {
		cur.Server.CamouflageDir = "/var/www/camo3"
		return nil
	}); err != nil {
		t.Fatalf("nginx reload fallback UpdateAndReconcile failed: %v", err)
	}
	if !reflect.DeepEqual(exec.startedSvcs, []string{"nginx"}) {
		t.Fatalf("expected fallback restart of [nginx], got %v", exec.startedSvcs)
	}
}

func TestReconcileNFTTableCleanupMatchesRendered(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	s := state.NewDefaultState(state.RoleClient)
	s.System.EnableFlowtable = true
	s.System.LANInterface = ""
	srvPriv, srvPub, err := cryptoext.GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair: %v", err)
	}
	s.Client.WireGuard.Enabled = true
	s.Client.WireGuard.ServerPrivateKey = srvPriv
	s.Client.WireGuard.ServerPublicKey = srvPub
	s.Client.WireGuard.EndpointHost = "vpn.example.com"
	s.Client.Nodes = []state.OutboundNode{{
		ID:       "n1",
		Name:     "node-1",
		Protocol: "vless-xhttp",
		Address:  "203.0.113.10",
		Port:     443,
		UUID:     "11111111-1111-4111-8111-111111111111",
	}}
	s.Client.ActiveNodeID = "n1"
	if err := store.Save(s); err != nil {
		t.Fatalf("Save state: %v", err)
	}

	// No physical NICs and empty LANInterface -> neither dex_flow nor dex_nat is rendered.
	exec := &mockExecutor{
		physicalNICSet: true,
		physicalNICs:   nil,
	}
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
		t.Fatalf("Reconcile failed: %v", err)
	}

	hasCmd := func(want string) bool {
		for _, c := range exec.cmds {
			if c == want {
				return true
			}
		}
		return false
	}
	if !hasCmd("nft delete table inet dex_flow") {
		t.Fatalf("expected dex_flow deleted when omitted from nftables.conf, cmds=%v", exec.cmds)
	}
	if !hasCmd("nft delete table inet dex_nat") {
		t.Fatalf("expected dex_nat deleted when omitted from nftables.conf, cmds=%v", exec.cmds)
	}
	if hasCmd("nft delete table inet dex_client") || hasCmd("nft delete table inet dex_filter") {
		t.Fatalf("did not expect dex_client/dex_filter deleted, cmds=%v", exec.cmds)
	}
}

func TestReconcileRollbackStopsNewlyStartedServicesBeforeDeletingUnits(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	s := state.NewDefaultState(state.RoleClient)
	s.Client.Nodes = []state.OutboundNode{{
		ID:       "n1",
		Name:     "node-1",
		Protocol: "vless-xhttp",
		Address:  "203.0.113.10",
		Port:     443,
		UUID:     "11111111-1111-4111-8111-111111111111",
	}}
	s.Client.ActiveNodeID = "n1"
	if err := store.Save(s); err != nil {
		t.Fatalf("Save state: %v", err)
	}

	// Simulate fresh machine / post-v2-cleanup: none of the dex services are running initially.
	exec := &mockExecutor{
		failHealthSvc: "dex-xray",
		inactiveSvcs: map[string]bool{
			"dex-nft":                true,
			"dex-mosdns":             true,
			"dex-xray":               true,
			"dex-daemon":             true,
			"dex-refresh.timer":      true,
			"dex-rules-update.timer": true,
		},
	}
	exec.onServiceStart = func(name string) {
		exec.mu.Lock()
		delete(exec.inactiveSvcs, name)
		exec.mu.Unlock()
	}

	unitExistsAtStop := make(map[string]bool)
	exec.onServiceStop = func(name string) {
		unitFile := name + ".service"
		if strings.HasSuffix(name, ".timer") {
			unitFile = name
		}
		unitDisk := filepath.Join(root, "etc", "systemd", "system", unitFile)
		if _, err := os.Stat(unitDisk); err == nil {
			unitExistsAtStop[name] = true
		}
	}

	opts := ApplyOptions{
		RootPrefix: root,
		RenderOpts: render.RenderOptions{
			StateDir:     "/etc/dex",
			GeneratedDir: "/etc/dex/generated",
			CertFile:     filepath.Join(stateDir, "ssl", "dex.cer"),
			KeyFile:      filepath.Join(stateDir, "ssl", "dex.key"),
		},
	}

	if _, err := Reconcile(context.Background(), store, exec, opts); err == nil {
		t.Fatalf("expected Reconcile to fail health check for dex-xray")
	}

	// All newly started services must be stopped/disabled before their unit files are deleted.
	expectedStopped := []string{"dex-nft", "dex-mosdns", "dex-xray", "dex-refresh.timer", "dex-rules-update.timer", "dex-daemon"}
	for _, svc := range expectedStopped {
		found := false
		for _, stopped := range exec.stoppedSvcs {
			if stopped == svc {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected newly started service %s to be stopped on rollback, stoppedSvcs=%v", svc, exec.stoppedSvcs)
		}
		if !unitExistsAtStop[svc] {
			t.Fatalf("expected unit file for %s to still exist during ServiceStopDisable (before rollbackFiles)", svc)
		}
		unitFile := svc + ".service"
		if strings.HasSuffix(svc, ".timer") {
			unitFile = svc
		}
		unitDisk := filepath.Join(root, "etc", "systemd", "system", unitFile)
		if _, err := os.Stat(unitDisk); !os.IsNotExist(err) {
			t.Fatalf("expected rolled back unit file %s removed after rollback, err=%v", unitDisk, err)
		}
	}

	// No ServiceRestart should be issued for services that were inactive before apply.
	for _, s := range exec.startedSvcs {
		if strings.HasPrefix(s, "restart:") {
			t.Fatalf("did not expect ServiceRestart on rollback for newly started services, got %v", exec.startedSvcs)
		}
	}

	// Newly introduced dex_* nftables tables must be deleted on rollback.
	for _, tbl := range []string{"dex_client", "dex_filter"} {
		wantCmd := "nft delete table inet " + tbl
		found := false
		for _, c := range exec.cmds {
			if c == wantCmd {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected %q on rollback, cmds=%v", wantCmd, exec.cmds)
		}
	}
}

func TestReconcileWave1ImportedCertBlockAdsAndNginxLegacy(t *testing.T) {
	// 1. Imported cert paths are passed through to renderers (without overwriting by store.DefaultCert).
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)
	customCert := filepath.Join(root, "var", "www", "ssl", "custom.cer")
	customKey := filepath.Join(root, "var", "www", "ssl", "custom.key")
	_ = os.MkdirAll(filepath.Dir(customCert), 0o755)
	_ = os.WriteFile(customCert, []byte("CERT"), 0o644)
	_ = os.WriteFile(customKey, []byte("KEY"), 0o600)

	srv := state.NewDefaultState(state.RoleServer)
	srv.Server.Domain = "srv.example.com"
	srv.Server.TLSMode = "nginx"
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	srv.Cert = state.CertConfig{
		Mode:     "imported",
		CertFile: customCert,
		KeyFile:  customKey,
	}
	if err := store.Save(srv); err != nil {
		t.Fatalf("Save server: %v", err)
	}

	exec := &mockExecutor{nginxVersion: "nginx version: nginx/1.22.1\n"}
	opts := ApplyOptions{
		RootPrefix: root,
		RenderOpts: render.RenderOptions{
			StateDir:     "/etc/dex",
			GeneratedDir: "/etc/dex/generated",
		},
	}
	if _, err := Reconcile(context.Background(), store, exec, opts); err != nil {
		t.Fatalf("Reconcile server failed: %v", err)
	}
	ngBytes, _ := os.ReadFile(filepath.Join(root, "etc", "nginx", "conf.d", "dex-server.conf"))
	ngStr := string(ngBytes)
	if !strings.Contains(ngStr, "ssl_certificate "+customCert+";") || !strings.Contains(ngStr, "ssl_certificate_key "+customKey+";") {
		t.Fatalf("expected imported cert/key in nginx config, got:\n%s", ngStr)
	}
	if !strings.Contains(ngStr, "listen 443 ssl http2;") {
		t.Fatalf("expected legacy http2 directive for nginx 1.22.1, got:\n%s", ngStr)
	}

	// 2. Client with block_ads=true creates empty Domains.ads.txt placeholder + warning when missing.
	cRoot := t.TempDir()
	cStateDir := filepath.Join(cRoot, "etc", "dex")
	cStore := state.NewStore(cStateDir)
	cli := state.NewDefaultState(state.RoleClient)
	cli.Client.DNS.BlockAds = true
	cli.Client.DNS.BlacklistDomains = []string{"bad.example.com"}
	if err := cStore.Save(cli); err != nil {
		t.Fatalf("Save client: %v", err)
	}
	// Pre-create non-empty Domains.apple.txt to verify auto-detection
	appleDisk := filepath.Join(cRoot, "etc", "dex", "rules", "Domains.apple.txt")
	_ = os.MkdirAll(filepath.Dir(appleDisk), 0o755)
	_ = os.WriteFile(appleDisk, []byte("apple.com\n"), 0o644)

	cRes, err := Reconcile(context.Background(), cStore, &mockExecutor{}, ApplyOptions{
		RootPrefix: cRoot,
		RenderOpts: render.RenderOptions{
			StateDir:     "/etc/dex",
			GeneratedDir: "/etc/dex/generated",
		},
	})
	if err != nil {
		t.Fatalf("Reconcile client failed: %v", err)
	}
	adsDisk := filepath.Join(cRoot, "etc", "dex", "rules", "Domains.ads.txt")
	if _, err := os.Stat(adsDisk); err != nil {
		t.Fatalf("expected placeholder Domains.ads.txt created, err=%v", err)
	}
	if !strings.Contains(strings.Join(cRes.Warnings, "\n"), "Domains.ads.txt") {
		t.Fatalf("expected warning about placeholder Domains.ads.txt, got %v", cRes.Warnings)
	}
	mosCfg, _ := os.ReadFile(filepath.Join(cRoot, "etc", "dex", "generated", "mosdns", "mosdns.yaml"))
	if !strings.Contains(string(mosCfg), "Domains.apple.txt") {
		t.Fatalf("expected non-empty Domains.apple.txt auto-detected in mosdns.yaml")
	}
	nftCfg, _ := os.ReadFile(filepath.Join(cRoot, "etc", "dex", "generated", "nftables.conf"))
	if !strings.Contains(string(nftCfg), "203.0.113.10") {
		t.Fatalf("expected BlacklistDomains resolved IP in nftables.conf")
	}
}
