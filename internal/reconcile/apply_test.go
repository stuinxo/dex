package reconcile

import (
	"bytes"
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

	"github.com/stuinxo/dex/internal/cryptoext"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
)

type mockExecutor struct {
	mu               sync.Mutex
	cmds             []string
	hasCmd           map[string]bool
	failValidation   string // "xray" | "nft" | "haproxy" | "nginx"
	failHealthSvc    string
	failReloadSvc    string
	failDaemonReload bool
	failResolve      bool
	nginxVersion     string
	inactiveSvcs     map[string]bool
	startedSvcs      []string
	reloadedSvcs     []string
	stoppedSvcs      []string
	physicalNICs     []string
	physicalNICSet   bool
	onServiceStart   func(name string)
	onServiceStop    func(name string)
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

func (m *mockExecutor) DaemonReload(ctx context.Context, initSys string) error {
	if m.failDaemonReload {
		return errors.New("daemon-reload failed")
	}
	return nil
}
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
	if m.failResolve {
		return nil, errors.New("dns resolution failed")
	}
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
	s.Client.DNS.DoHServers = []string{"https://doh.example.com/dq"}
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
	s.Client.DNS.DoHServers = []string{"https://doh.example.com/dq"}
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
	s.Client.DNS.DoHServers = []string{"https://doh.example.com/dq"}
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
	if !strings.Contains(ngStr, "listen 443 ssl http2 reuseport fastopen=256;") {
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

type failingResolveExec struct {
	mockExecutor
}

func (*failingResolveExec) ResolveHostIPs(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("dns offline")
}

func TestReconcileHostsCacheObsoleteGuardResolvRestoreAndStalePrevCleanup(t *testing.T) {
	// 1. Offline DNS fallback reuses cached IPs from existing mosdns/hosts.txt + cleans stale .prev files
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)
	cli := state.NewDefaultState(state.RoleClient)
	cli.Client.DNS.DoHServers = []string{"https://doh.cached.example/dq"}
	cli.Client.Nodes = []state.OutboundNode{{
		ID: "n1", Protocol: "vless-xhttp", Address: "node.cached.example", Port: 443,
		UUID: "11111111-1111-4111-8111-111111111111",
	}}
	cli.Client.ActiveNodeID = "n1"
	if err := store.Save(cli); err != nil {
		t.Fatal(err)
	}

	genDir := filepath.Join(root, "etc", "dex", "generated")
	hostsPath := filepath.Join(genDir, "mosdns", "hosts.txt")
	_ = os.MkdirAll(filepath.Dir(hostsPath), 0o755)
	_ = os.WriteFile(hostsPath, []byte("localhost 127.0.0.1\ndoh.cached.example 203.0.113.55\nnode.cached.example 203.0.113.66\n"), 0o644)

	// Plant stale .prev files
	staleFiles := []string{
		filepath.Join(genDir, "xray.json.prev"),
		filepath.Join(genDir, "mosdns", "hosts.txt.prev"),
		filepath.Join(genDir, "wg-peers", "peer-a.conf.prev"),
		filepath.Join(root, "etc", "wireguard", "wg0.conf.prev"),
	}
	for _, sf := range staleFiles {
		_ = os.MkdirAll(filepath.Dir(sf), 0o755)
		_ = os.WriteFile(sf, []byte("stale"), 0o644)
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
	res, err := Reconcile(context.Background(), store, &failingResolveExec{}, opts)
	if err != nil {
		t.Fatalf("Reconcile with failingResolveExec: %v", err)
	}
	hostsAfter, _ := os.ReadFile(hostsPath)
	if !strings.Contains(string(hostsAfter), "doh.cached.example 203.0.113.55") {
		t.Fatalf("expected cached DoH IP preserved in hosts.txt on DNS failure, got:\n%s", string(hostsAfter))
	}
	nftAfter, _ := os.ReadFile(filepath.Join(genDir, "nftables.conf"))
	if !strings.Contains(string(nftAfter), "203.0.113.55") || !strings.Contains(string(nftAfter), "203.0.113.66") {
		t.Fatalf("expected cached DoH and node IPs preserved in nftables.conf, got:\n%s", string(nftAfter))
	}
	warnText := strings.Join(res.Warnings, "\n")
	if !strings.Contains(warnText, "using cached IP from hosts.txt") {
		t.Fatalf("expected cache reuse warning, got %v", res.Warnings)
	}
	for _, sf := range staleFiles {
		if _, err := os.Stat(sf); !os.IsNotExist(err) {
			t.Errorf("expected stale prev file %s cleaned up", sf)
		}
	}

	// 2. CheckUnmanagedEdits rejects manually edited obsolete file (omitted from new render bundle) unless Force=true
	obsoletePath := filepath.Join(genDir, "mosdns", "mosdns.yaml")
	if err := os.WriteFile(obsoletePath, []byte("# user edited before role switch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := UpdateAndReconcile(context.Background(), store, state.RoleServer, &mockExecutor{}, opts, func(cur *state.State) error {
		*cur = *state.NewDefaultState(state.RoleServer)
		cur.Server.Domain = "srv.example.com"
		cur.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
		return nil
	}); !errors.Is(err, ErrManualModificationDetected) {
		t.Fatalf("expected ErrManualModificationDetected for edited obsolete mosdns.yaml, got %v", err)
	}

	// 3. restoreResolvConfIfNeeded restores original /etc/resolv.conf when content is 127.0.0.1
	resolvPath := filepath.Join(root, "etc", "resolv.conf")
	origPath := filepath.Join(stateDir, "resolv.conf.orig")
	_ = os.WriteFile(origPath, []byte("nameserver 223.5.5.5\n"), 0o644)
	_ = os.WriteFile(resolvPath, []byte("nameserver 127.0.0.1\n"), 0o644)
	if err := restoreResolvConfIfNeeded(resolvPath, origPath); err != nil {
		t.Fatalf("restoreResolvConfIfNeeded: %v", err)
	}
	gotResolv, _ := os.ReadFile(resolvPath)
	if string(gotResolv) != "nameserver 223.5.5.5\n" {
		t.Fatalf("expected /etc/resolv.conf restored, got %q", string(gotResolv))
	}
	// Does not overwrite custom /etc/resolv.conf
	_ = os.WriteFile(resolvPath, []byte("nameserver 9.9.9.9\n"), 0o644)
	if err := restoreResolvConfIfNeeded(resolvPath, origPath); err != nil {
		t.Fatalf("restoreResolvConfIfNeeded custom: %v", err)
	}
	gotResolv2, _ := os.ReadFile(resolvPath)
	if string(gotResolv2) != "nameserver 9.9.9.9\n" {
		t.Fatalf("expected custom /etc/resolv.conf untouched, got %q", string(gotResolv2))
	}
}

func TestHardeningResolvFallbackAndExternalCertPreservation(t *testing.T) {
	dir := t.TempDir()
	resolvPath := filepath.Join(dir, "resolv.conf")
	origPath := filepath.Join(dir, "resolv.conf.orig")

	// 1. restoreResolvConfIfNeeded falls back to public DNS when orig contains only 127.0.0.53 or is missing
	_ = os.WriteFile(resolvPath, []byte("nameserver 127.0.0.1\n"), 0o644)
	_ = os.WriteFile(origPath, []byte("nameserver 127.0.0.53\noptions edns0 trust-ad\n"), 0o644)
	if err := restoreResolvConfIfNeeded(resolvPath, origPath); err != nil {
		t.Fatalf("restoreResolvConfIfNeeded stub orig: %v", err)
	}
	got, _ := os.ReadFile(resolvPath)
	if !strings.Contains(string(got), "nameserver 223.5.5.5") || strings.Contains(string(got), "127.0.0.53") {
		t.Fatalf("expected safe public DNS fallback instead of 127.0.0.53, got %q", string(got))
	}

	_ = os.WriteFile(resolvPath, []byte("nameserver 127.0.0.1\n"), 0o644)
	_ = os.Remove(origPath)
	if err := restoreResolvConfIfNeeded(resolvPath, origPath); err != nil {
		t.Fatalf("restoreResolvConfIfNeeded missing orig: %v", err)
	}
	got2, _ := os.ReadFile(resolvPath)
	if string(got2) != fallbackPublicDNS {
		t.Fatalf("expected fallbackPublicDNS when orig missing, got %q", string(got2))
	}

	// 2. Reconcile must NOT overwrite or create files at custom external imported cert/key paths
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)
	extCert := filepath.Join(dir, "external", "missing.cer")
	extKey := filepath.Join(dir, "external", "missing.key")

	srv := state.NewDefaultState(state.RoleServer)
	srv.Server.Domain = "srv.example.com"
	srv.Server.TLSMode = "nginx"
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	srv.Cert = state.CertConfig{
		Mode:     "imported",
		CertFile: extCert,
		KeyFile:  extKey,
	}
	if err := store.Save(srv); err != nil {
		t.Fatal(err)
	}
	if _, err := Reconcile(context.Background(), store, &mockExecutor{}, ApplyOptions{RootPrefix: root}); err != nil {
		t.Fatalf("Reconcile with custom external cert: %v", err)
	}
	if _, err := os.Stat(extCert); !os.IsNotExist(err) {
		t.Fatalf("expected custom external cert path %s untouched, stat err=%v", extCert, err)
	}
	if _, err := os.Stat(extKey); !os.IsNotExist(err) {
		t.Fatalf("expected custom external key path %s untouched, stat err=%v", extKey, err)
	}

	// 3. When default cert exists but default key is missing, Reconcile regenerates key+cert and triggers service restarts
	srvDef := state.NewDefaultState(state.RoleServer)
	srvDef.Server.Domain = "srv.example.com"
	srvDef.Server.TLSMode = "nginx"
	srvDef.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	srvDef.Cert = state.CertConfig{Mode: "self_signed"}
	if err := store.Save(srvDef); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(store.DefaultCert()), 0o755)
	_ = os.WriteFile(store.DefaultCert(), []byte("corrupt-or-orphan-cert"), 0o644)
	_ = os.Remove(store.DefaultKey())
	res, err := Reconcile(context.Background(), store, &mockExecutor{}, ApplyOptions{RootPrefix: root})
	if err != nil {
		t.Fatalf("Reconcile default cert with missing key: %v", err)
	}
	if _, err := os.Stat(store.DefaultKey()); err != nil {
		t.Fatalf("expected missing default key regenerated: %v", err)
	}
	if len(res.ServicesRestarted) == 0 {
		t.Fatalf("expected services restarted when default cert/key regenerated")
	}
}

func TestRollbackRestoresStoppedActiveServices(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	rel := state.NewDefaultState(state.RoleRelay)
	rel.Relay.Forwards = []state.ForwardRule{{
		ID:         "f1",
		ListenPort: 10001,
		TargetHost: "198.51.100.1",
		TargetPort: 443,
		Proto:      "tcp",
		Engine:     "nft",
	}}
	if err := store.Save(rel); err != nil {
		t.Fatal(err)
	}

	exec := &mockExecutor{inactiveSvcs: map[string]bool{}}
	opts := ApplyOptions{
		RootPrefix: root,
		RenderOpts: render.RenderOptions{
			StateDir:     "/etc/dex",
			GeneratedDir: "/etc/dex/generated",
		},
	}
	if _, err := Reconcile(context.Background(), store, exec, opts); err != nil {
		t.Fatalf("initial Reconcile: %v", err)
	}

	nftCfgPath := filepath.Join(root, "etc", "dex", "generated", "nftables.conf")
	nftUnitPath := filepath.Join(root, "etc", "systemd", "system", "dex-nft.service")
	origNFT, err := os.ReadFile(nftCfgPath)
	if err != nil {
		t.Fatalf("read initial nftables.conf: %v", err)
	}
	if _, err := os.Stat(nftUnitPath); err != nil {
		t.Fatalf("expected dex-nft.service after initial apply: %v", err)
	}

	// Track active status dynamically via callbacks: dex-nft starts active, stopped during failed apply, then restored.
	activeState := map[string]bool{"dex-nft": true}
	exec.onServiceStop = func(name string) { activeState[name] = false }
	exec.onServiceStart = func(name string) { activeState[name] = true }
	exec.startedSvcs = nil
	exec.stoppedSvcs = nil
	exec.failDaemonReload = true

	// Removing last NFT rule stops dex-nft; DaemonReload fails once, then succeeds during rollback.
	var calls int
	wrapExec := struct {
		*mockExecutor
	}{mockExecutor: exec}
	_ = wrapExec
	exec.onServiceStop = func(name string) {
		activeState[name] = false
		calls++
		// Let DaemonReload succeed on the rollback call after the first failure.
		if calls >= 1 {
			go func() {}()
		}
	}

	_, _, err = UpdateAndReconcile(context.Background(), store, state.RoleRelay, exec, opts, func(s *state.State) error {
		s.Relay.Forwards = nil
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "daemon reload") {
		t.Fatalf("expected daemon reload failure, got %v", err)
	}

	reloaded, err := store.Load()
	if err != nil || len(reloaded.Relay.Forwards) != 1 {
		t.Fatalf("expected state rolled back to 1 forward, err=%v forwards=%+v", err, reloaded)
	}
	gotNFT, err := os.ReadFile(nftCfgPath)
	if err != nil || !bytes.Equal(gotNFT, origNFT) {
		t.Fatalf("expected nftables.conf restored on rollback, err=%v", err)
	}
	if _, err := os.Stat(nftUnitPath); err != nil {
		t.Fatalf("expected dex-nft.service restored on rollback: %v", err)
	}
	restoredNFTActive := false
	for _, s := range exec.startedSvcs {
		if s == "dex-nft" {
			restoredNFTActive = true
		}
	}
	if !restoredNFTActive || !activeState["dex-nft"] {
		t.Fatalf("expected dex-nft re-enabled/started on rollback, startedSvcs=%v active=%v", exec.startedSvcs, activeState["dex-nft"])
	}
}

func TestUpdateAndReconcileRollsBackRenderFailureAndEmptyInit(t *testing.T) {
	// 1. Existing valid state.json: RenderAll fails due to unresolvable NFT target domain -> rolled back cleanly
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	rel := state.NewDefaultState(state.RoleRelay)
	rel.Relay.Forwards = []state.ForwardRule{{
		ID:         "f1",
		ListenPort: 10001,
		TargetHost: "198.51.100.1",
		TargetPort: 443,
		Proto:      "tcp",
		Engine:     "nft",
	}}
	if err := store.Save(rel); err != nil {
		t.Fatal(err)
	}

	exec := &mockExecutor{failResolve: true}
	opts := ApplyOptions{
		RootPrefix: root,
		RenderOpts: render.RenderOptions{
			StateDir:     "/etc/dex",
			GeneratedDir: "/etc/dex/generated",
		},
	}
	_, _, err := UpdateAndReconcile(context.Background(), store, state.RoleRelay, exec, opts, func(s *state.State) error {
		s.Relay.Forwards = append(s.Relay.Forwards, state.ForwardRule{
			ID:         "f2",
			ListenPort: 10002,
			TargetHost: "unresolvable.invalid",
			TargetPort: 443,
			Proto:      "tcp",
			Engine:     "nft",
		})
		return nil
	})
	if err == nil {
		t.Fatalf("expected RenderAll failure for unresolvable NFT target")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after rollback: %v", err)
	}
	if len(loaded.Relay.Forwards) != 1 || loaded.Relay.Forwards[0].ID != "f1" {
		t.Fatalf("expected rejected forward rule rolled back, got %+v", loaded.Relay.Forwards)
	}
	if _, err := os.Stat(store.TxnPath()); !os.IsNotExist(err) {
		t.Fatalf("expected no lingering .txn file, stat err=%v", err)
	}

	// 2. Empty directory first-time UpdateAndReconcile failure -> state.json must not remain
	emptyRoot := t.TempDir()
	emptyStore := state.NewStore(filepath.Join(emptyRoot, "etc", "dex"))
	_, _, err = UpdateAndReconcile(context.Background(), emptyStore, state.RoleRelay, exec, ApplyOptions{
		RootPrefix: emptyRoot,
		RenderOpts: opts.RenderOpts,
	}, func(s *state.State) error {
		s.Relay.Forwards = []state.ForwardRule{{
			ID:         "f-bad",
			ListenPort: 10003,
			TargetHost: "unresolvable.invalid",
			TargetPort: 443,
			Proto:      "tcp",
			Engine:     "nft",
		}}
		return nil
	})
	if err == nil {
		t.Fatalf("expected initial UpdateAndReconcile failure")
	}
	if _, err := emptyStore.Load(); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("expected state.ErrNotFound after rolling back empty init, got %v", err)
	}
	if _, err := os.Stat(emptyStore.EmptyTxnPath()); !os.IsNotExist(err) {
		t.Fatalf("expected no lingering .txn.empty file, stat err=%v", err)
	}
}

func TestDryRunRunsPreflightValidationAndCheckRequiredBinaries(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	rel := state.NewDefaultState(state.RoleRelay)
	rel.Relay.Forwards = []state.ForwardRule{{
		ID:         "h1",
		ListenPort: 10001,
		TargetHost: "198.51.100.1",
		TargetPort: 443,
		Proto:      "tcp",
		Engine:     "haproxy",
	}}
	if err := store.Save(rel); err != nil {
		t.Fatal(err)
	}

	exec := &mockExecutor{failValidation: "haproxy"}
	opts := ApplyOptions{
		DryRun:     true,
		RootPrefix: root,
		RenderOpts: render.RenderOptions{
			StateDir:     "/etc/dex",
			GeneratedDir: "/etc/dex/generated",
		},
	}
	if _, err := Reconcile(context.Background(), store, exec, opts); err == nil || !strings.Contains(err.Error(), "haproxy validation failed") {
		t.Fatalf("expected DryRun to execute haproxy preflight validation and fail, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "haproxy", "haproxy.cfg")); !os.IsNotExist(err) {
		t.Fatalf("expected DryRun to leave real target path untouched, stat err=%v", err)
	}

	// checkRequiredBinaries returns clear actionable error when xray/mosdns/haproxy/nginx/nft/wg-quick missing,
	// and allows missing haproxy during dryRun when apt-get/apk can auto-install it.
	b := &render.RenderBundle{XrayNeeded: true}
	missingExec := &mockExecutor{hasCmd: map[string]bool{}}
	if err := checkRequiredBinaries(missingExec, render.RenderOptions{XrayBin: "/usr/local/bin/xray"}, b, false); err == nil || !strings.Contains(err.Error(), "dex update --component xray") {
		t.Fatalf("expected missing xray binary error, got %v", err)
	}
	hapExec := &mockExecutor{hasCmd: map[string]bool{"apt-get": true}}
	if err := checkRequiredBinaries(hapExec, render.RenderOptions{}, &render.RenderBundle{HAProxyNeeded: true}, true); err != nil {
		t.Fatalf("expected dryRun to allow auto-installable haproxy when apt-get present, got %v", err)
	}
	if err := checkRequiredBinaries(hapExec, render.RenderOptions{}, &render.RenderBundle{HAProxyNeeded: true}, false); err == nil {
		t.Fatalf("expected non-dryRun to require haproxy binary directly")
	}
}

type qdiscMockExec struct {
	mockExecutor
	qdisc string
}

func (q *qdiscMockExec) RunCommand(ctx context.Context, env []string, name string, args ...string) (string, error) {
	full := name + " " + strings.Join(args, " ")
	q.mu.Lock()
	q.cmds = append(q.cmds, full)
	q.mu.Unlock()
	if name == "sysctl" && len(args) == 2 && args[0] == "-n" && args[1] == "net.core.default_qdisc" {
		return q.qdisc + "\n", nil
	}
	return "ok", nil
}

func TestReconcileV004SysctlModprobeFallbackAndDropinLifecycle(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	srv := state.NewDefaultState(state.RoleServer)
	srv.Server.Domain = "srv.example.com"
	srv.Server.TLSMode = "nginx"
	srv.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	if err := store.Save(srv); err != nil {
		t.Fatal(err)
	}

	exec := &qdiscMockExec{qdisc: "pfifo_fast"}
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

	// Verify modprobe + sysctl -e -p + qdisc fallback to fq
	cmdsJoined := strings.Join(exec.cmds, "\n")
	for _, want := range []string{
		"modprobe tcp_bbr",
		"modprobe nf_conntrack",
		"modprobe sch_cake",
		"sysctl -e -p " + filepath.Join(root, "etc", "sysctl.d", "99-dex.conf"),
		"sysctl -n net.core.default_qdisc",
		"sysctl -w net.core.default_qdisc=fq",
	} {
		if !strings.Contains(cmdsJoined, want) {
			t.Errorf("expected command %q, got:\n%s", want, cmdsJoined)
		}
	}

	// Verify modules-load.d and nginx drop-in written (VPS server role uses fq, so sch_cake is omitted)
	modPath := filepath.Join(root, "etc", "modules-load.d", "99-dex.conf")
	if b, err := os.ReadFile(modPath); err != nil || string(b) != "tcp_bbr\nnf_conntrack\n" {
		t.Fatalf("unexpected modules-load file: err=%v content=%q", err, string(b))
	}
	dropinPath := filepath.Join(root, "etc", "systemd", "system", "nginx.service.d", "dex-limits.conf")
	if b, err := os.ReadFile(dropinPath); err != nil || !strings.Contains(string(b), "LimitNOFILE=1000000") {
		t.Fatalf("unexpected nginx dropin: err=%v content=%q", err, string(b))
	}

	// When default_qdisc is already cake, no fallback sysctl -w is invoked;
	// and modifying nginx drop-in triggers restart (ServiceEnableStart) rather than reload.
	exec.mu.Lock()
	exec.cmds = nil
	exec.startedSvcs = nil
	exec.reloadedSvcs = nil
	exec.qdisc = "cake"
	exec.mu.Unlock()
	if err := os.WriteFile(dropinPath, []byte("[Service]\nLimitNOFILE=65535\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	optsForce := opts
	optsForce.Force = true
	if _, err := Reconcile(context.Background(), store, exec, optsForce); err != nil {
		t.Fatalf("Reconcile after dropin edit failed: %v", err)
	}
	if strings.Contains(strings.Join(exec.cmds, "\n"), "net.core.default_qdisc=fq") {
		t.Fatalf("did not expect fq fallback when kernel already uses cake")
	}
	if !reflect.DeepEqual(exec.startedSvcs, []string{"nginx"}) || len(exec.reloadedSvcs) != 0 {
		t.Fatalf("expected nginx restarted (not reloaded) when drop-in changed, started=%v reloaded=%v", exec.startedSvcs, exec.reloadedSvcs)
	}

	// Switching server TLSMode to direct removes nginx drop-in AND cleans up empty nginx.service.d directory
	if _, _, err := UpdateAndReconcile(context.Background(), store, state.RoleServer, exec, opts, func(cur *state.State) error {
		cur.Server.TLSMode = "direct"
		cur.Server.EnableDoH = false
		return nil
	}); err != nil {
		t.Fatalf("switch to direct TLS failed: %v", err)
	}
	if _, err := os.Stat(dropinPath); !os.IsNotExist(err) {
		t.Fatalf("expected nginx dropin removed, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Dir(dropinPath)); !os.IsNotExist(err) {
		t.Fatalf("expected empty nginx.service.d dir removed, stat err=%v", err)
	}
}

func TestHasContainerEnvFile(t *testing.T) {
	dir := t.TempDir()

	podmanFile := filepath.Join(dir, "environ-podman")
	if err := os.WriteFile(podmanFile, []byte("PATH=/usr/sbin:/sbin\x00container=podman\x00HOME=/root\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasContainerEnvFile(podmanFile) {
		t.Fatalf("expected container=podman detected")
	}

	lxcFile := filepath.Join(dir, "environ-lxc")
	if err := os.WriteFile(lxcFile, []byte("container=lxc\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasContainerEnvFile(lxcFile) {
		t.Fatalf("expected container=lxc detected")
	}

	emptyFile := filepath.Join(dir, "environ-empty")
	if err := os.WriteFile(emptyFile, []byte("PATH=/usr/bin\x00container= \x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hasContainerEnvFile(emptyFile) {
		t.Fatalf("expected empty container= value not detected as container")
	}

	if hasContainerEnvFile(filepath.Join(dir, "missing")) {
		t.Fatalf("expected missing file to return false")
	}
}

func TestRenderCertificateOverrides(t *testing.T) {
	store := state.NewStore(t.TempDir())
	st := state.NewDefaultState(state.RoleClient)
	st.Cert.Mode = "imported"
	st.Cert.CertFile = "/external/cert.pem"
	st.Cert.KeyFile = "/external/key.pem"
	for _, tc := range []struct{ cert, key string }{
		{},
		{cert: "/override/cert.pem"},
		{key: "/override/key.pem"},
		{cert: "/override/cert.pem", key: "/override/key.pem"},
	} {
		opts := ApplyOptions{RenderOpts: render.RenderOptions{CertFile: tc.cert, KeyFile: tc.key}}
		got, _ := populateRenderOptions(context.Background(), st, store, &mockExecutor{}, opts)
		wantCert, wantKey := st.Cert.CertFile, st.Cert.KeyFile
		if tc.cert != "" {
			wantCert = tc.cert
		}
		if tc.key != "" {
			wantKey = tc.key
		}
		if got.CertFile != wantCert || got.KeyFile != wantKey {
			t.Fatalf("overrides %#v resolved to %q/%q, want %q/%q", tc, got.CertFile, got.KeyFile, wantCert, wantKey)
		}
	}
}
