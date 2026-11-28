package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
	"github.com/stuinxo/dex/internal/update"
)

type fakeOpsExec struct {
	reconcile.SystemExecutor
	cmds           []string
	stoppedSvcs    []string
	startedSvcs    []string
	restarted      []string
	reloaded       []string
	activeSvcs     map[string]bool
	failRestartSvc string
	failStartSvc   string
	piholeRunning  bool
	failValidation string
	failResolve    bool
}

func (f *fakeOpsExec) HasCommand(name string) bool {
	return name == "nft" || name == "docker" || name == "bash" || name == "xray"
}
func (f *fakeOpsExec) RunCommand(ctx context.Context, env []string, name string, args ...string) (string, error) {
	full := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, full)
	if name == "docker" && len(args) >= 4 && args[0] == "inspect" && args[3] == "pihole" {
		if f.piholeRunning {
			return "true\n", nil
		}
		return "", errors.New("no such container")
	}
	if f.failValidation == "nft" && name == "nft" && strings.Contains(full, "-c") {
		return "bad nft", errors.New("exit 1")
	}
	return "ok", nil
}
func (f *fakeOpsExec) DetectInitSystem() string     { return "systemd" }
func (f *fakeOpsExec) DetectIsContainer() bool      { return false }
func (f *fakeOpsExec) DetectMemMB() int             { return 512 }
func (f *fakeOpsExec) DetectPhysicalNICs() []string { return []string{"eth0"} }
func (f *fakeOpsExec) ResolveHostIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if f.failResolve {
		return nil, errors.New("dns resolution failed")
	}
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}
func (f *fakeOpsExec) DaemonReload(ctx context.Context, initSys string) error { return nil }
func (f *fakeOpsExec) ServiceEnableStart(ctx context.Context, initSys, name string) error {
	f.startedSvcs = append(f.startedSvcs, name)
	if f.failStartSvc == name {
		return fmt.Errorf("simulated start failure for %s", name)
	}
	return nil
}
func (f *fakeOpsExec) ServiceRestart(ctx context.Context, initSys, name string) error {
	f.restarted = append(f.restarted, name)
	if f.failRestartSvc == name {
		return fmt.Errorf("simulated restart failure for %s", name)
	}
	return nil
}
func (f *fakeOpsExec) ServiceReload(ctx context.Context, initSys, name string) error {
	f.reloaded = append(f.reloaded, name)
	return nil
}
func (f *fakeOpsExec) ServiceStopDisable(ctx context.Context, initSys, name string) error {
	f.stoppedSvcs = append(f.stoppedSvcs, name)
	return nil
}
func (f *fakeOpsExec) ServiceIsActive(ctx context.Context, initSys, name string) bool {
	if f.activeSvcs != nil {
		return f.activeSvcs[name]
	}
	return name == "dex-xray" || name == "dex-mosdns" || name == "dex-daemon"
}

func makeTestZip(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUpdateRulesAndHTMLRejection(t *testing.T) {
	geoip := []byte("geoip-bin")
	geosite := []byte("geosite-bin")
	geoipSum := sha256.Sum256(geoip)
	geositeSum := sha256.Sum256(geosite)

	chnCIDRs := "1.0.1.0/24\n1.0.2.0/23\n223.5.5.0/24\n"
	chnDomains := "qq.com\ntaobao.com\nbaidu.com\n"
	serveHTML := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geoip.dat":
			_, _ = w.Write(geoip)
		case "/geoip.dat.sha256sum":
			fmt.Fprintf(w, "%s  geoip.dat\n", hex.EncodeToString(geoipSum[:]))
		case "/geosite.dat":
			_, _ = w.Write(geosite)
		case "/geosite.dat.sha256sum":
			fmt.Fprintf(w, "%s  geosite.dat\n", hex.EncodeToString(geositeSum[:]))
		case "/cn.txt":
			if serveHTML {
				_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
				return
			}
			_, _ = w.Write([]byte(chnCIDRs))
		case "/direct.txt":
			_, _ = w.Write([]byte(chnDomains))
		case "/apple.txt":
			_, _ = w.Write([]byte("apple.com\nicloud.com\n"))
		case "/games.txt":
			_, _ = w.Write([]byte("steampowered.com\nsteamcontent.com\n"))
		case "/reject.txt":
			_, _ = w.Write([]byte("ads.example.com\ntracker.example.com\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := state.NewStore(filepath.Join(dir, "dex"))
	cfg := update.OpsConfig{
		Client:          srv.Client(),
		GeoIPURL:        srv.URL + "/geoip.dat",
		GeoSiteURL:      srv.URL + "/geosite.dat",
		ChnRouteURL:     srv.URL + "/cn.txt",
		DomainsChnURL:   srv.URL + "/direct.txt",
		DomainsAppleURL: srv.URL + "/apple.txt",
		DomainsGamesURL: srv.URL + "/games.txt",
		DomainsAdsURL:   srv.URL + "/reject.txt",
		MinChnRouteCIDR: 2,
		MinChnDomains:   2,
		MinAppleDomains: 2,
		MinGamesDomains: 2,
		MinAdsDomains:   2,
	}

	var out bytes.Buffer
	if err := update.UpdateRules(context.Background(), store, &fakeOpsExec{}, cfg, true, true, &out); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(store.Dir, "rules", "IPchnroute"))
	if err != nil || !strings.Contains(string(b), "223.5.5.0/24") {
		t.Fatalf("IPchnroute not written cleanly: err=%v", err)
	}

	// Ensure invalid HTML keeps previous good IPchnroute untouched
	serveHTML = true
	if err := update.UpdateRules(context.Background(), store, &fakeOpsExec{}, cfg, false, true, &out); err == nil {
		t.Fatalf("expected UpdateRules to reject HTML error page")
	}
	after, _ := os.ReadFile(filepath.Join(store.Dir, "rules", "IPchnroute"))
	if string(after) != chnCIDRs {
		t.Fatalf("expected previous good IPchnroute preserved on validation error")
	}
}

func TestUpdateComponentsAtomicAndCleanupV2(t *testing.T) {
	dexELF := []byte("\x7fELF\x02\x01\x01\x00new-dex")
	xrayELF := []byte("\x7fELF\x02\x01\x01\x00new-xray")
	mosELF := []byte("\x7fELF\x02\x01\x01\x00new-mos")

	xrayZip := makeTestZip(t, "xray", xrayELF)
	mosZip := makeTestZip(t, "subdir/mosdns", mosELF)

	dexSum := sha256.Sum256(dexELF)
	xrayZipSum := sha256.Sum256(xrayZip)
	mosZipSum := sha256.Sum256(mosZip)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dex/dex-linux-amd64":
			_, _ = w.Write(dexELF)
		case "/dex/SHA256SUMS":
			fmt.Fprintf(w, "%s  dex-linux-amd64\n", hex.EncodeToString(dexSum[:]))
		case "/xray/Xray-linux-64.zip":
			_, _ = w.Write(xrayZip)
		case "/xray/Xray-linux-64.zip.dgst":
			fmt.Fprintf(w, "MD5= 0000\nSHA2-256= %s\n", hex.EncodeToString(xrayZipSum[:]))
		case "/mosdns/mosdns-linux-amd64.zip":
			_, _ = w.Write(mosZip)
		case "/mosdns/release.json":
			fmt.Fprintf(w, `{"assets":[{"name":"mosdns-linux-amd64.zip","digest":"sha256:%s"}]}`, hex.EncodeToString(mosZipSum[:]))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	store := state.NewStore(filepath.Join(dir, "state"))
	_ = store.Save(state.NewDefaultState(state.RoleClient))

	exec := &fakeOpsExec{}
	cfg := update.OpsConfig{
		Client:              srv.Client(),
		DexReleaseBase:      srv.URL + "/dex",
		XrayReleaseBase:     srv.URL + "/xray",
		MosDNSBase:          srv.URL + "/mosdns",
		MosDNSReleaseAPIURL: srv.URL + "/mosdns/release.json",
		DexBinPath:          filepath.Join(binDir, "dex"),
		XrayBinPath:         filepath.Join(binDir, "xray"),
		MosDNSBinPath:       filepath.Join(binDir, "mosdns"),
		GOARCH:              "amd64",
	}

	var out bytes.Buffer
	for _, comp := range []string{"dex", "xray", "mosdns"} {
		if err := update.UpdateComponents(context.Background(), store, exec, cfg, comp, "latest", &out); err != nil {
			t.Fatalf("UpdateComponents(%s) failed: %v", comp, err)
		}
	}
	gotXray, _ := os.ReadFile(cfg.XrayBinPath)
	gotMos, _ := os.ReadFile(cfg.MosDNSBinPath)
	if !bytes.Equal(gotXray, xrayELF) || !bytes.Equal(gotMos, mosELF) {
		t.Fatalf("extracted binaries mismatch")
	}
	if len(exec.restarted) == 0 {
		t.Fatalf("expected active services restarted after binary update")
	}

	cleanupLegacyV2(context.Background(), exec, &out)
	if len(exec.stoppedSvcs) < 5 {
		t.Fatalf("expected legacy v2 services stopped: %v", exec.stoppedSvcs)
	}
	for _, svc := range exec.stoppedSvcs {
		if svc == "nftables" {
			t.Fatalf("cleanupLegacyV2 must never stop system nftables service")
		}
	}
	for _, cmd := range exec.cmds {
		if strings.Contains(cmd, "docker rm") {
			t.Fatalf("cleanupLegacyV2 must never run docker rm: %s", cmd)
		}
	}
}

func TestUpdateRulesRestoresBackupOnReconcileFailure(t *testing.T) {
	v1Geoip := []byte("geoip-v1")
	v1Geosite := []byte("geosite-v1")
	v2Geoip := []byte("geoip-v2")
	v2Geosite := []byte("geosite-v2")
	v1Chn := "1.0.1.0/24\n1.0.2.0/23\n"
	v2Chn := "2.0.1.0/24\n2.0.2.0/23\n"
	v1Dom := "qq.com\nbaidu.com\n"
	v2Dom := "jd.com\n163.com\n"

	useV2 := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geoip.dat":
			if useV2 {
				_, _ = w.Write(v2Geoip)
			} else {
				_, _ = w.Write(v1Geoip)
			}
		case "/geoip.dat.sha256sum":
			data := v1Geoip
			if useV2 {
				data = v2Geoip
			}
			sum := sha256.Sum256(data)
			fmt.Fprintf(w, "%s  geoip.dat\n", hex.EncodeToString(sum[:]))
		case "/geosite.dat":
			if useV2 {
				_, _ = w.Write(v2Geosite)
			} else {
				_, _ = w.Write(v1Geosite)
			}
		case "/geosite.dat.sha256sum":
			data := v1Geosite
			if useV2 {
				data = v2Geosite
			}
			sum := sha256.Sum256(data)
			fmt.Fprintf(w, "%s  geosite.dat\n", hex.EncodeToString(sum[:]))
		case "/cn.txt":
			if useV2 {
				_, _ = w.Write([]byte(v2Chn))
			} else {
				_, _ = w.Write([]byte(v1Chn))
			}
		case "/direct.txt":
			if useV2 {
				_, _ = w.Write([]byte(v2Dom))
			} else {
				_, _ = w.Write([]byte(v1Dom))
			}
		case "/apple.txt":
			_, _ = w.Write([]byte("apple.com\nicloud.com\n"))
		case "/games.txt":
			_, _ = w.Write([]byte("steampowered.com\nsteamcontent.com\n"))
		case "/reject.txt":
			_, _ = w.Write([]byte("ads.example.com\ntracker.example.com\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := state.NewStore(filepath.Join(dir, "dex"))
	st := state.NewDefaultState(state.RoleRelay)
	st.Relay.Forwards = []state.ForwardRule{{
		ID:         "f1",
		ListenPort: 10001,
		TargetHost: "unresolvable.invalid",
		TargetPort: 443,
		Proto:      "tcp",
		Engine:     "nft",
	}}
	if err := store.Save(st); err != nil {
		t.Fatalf("Save state: %v", err)
	}

	cfg := update.OpsConfig{
		Client:          srv.Client(),
		GeoIPURL:        srv.URL + "/geoip.dat",
		GeoSiteURL:      srv.URL + "/geosite.dat",
		ChnRouteURL:     srv.URL + "/cn.txt",
		DomainsChnURL:   srv.URL + "/direct.txt",
		DomainsAppleURL: srv.URL + "/apple.txt",
		DomainsGamesURL: srv.URL + "/games.txt",
		DomainsAdsURL:   srv.URL + "/reject.txt",
		MinChnRouteCIDR: 2,
		MinChnDomains:   2,
		MinAppleDomains: 2,
		MinGamesDomains: 2,
		MinAdsDomains:   2,
	}

	var out bytes.Buffer
	if err := update.UpdateRules(context.Background(), store, &fakeOpsExec{}, cfg, false, true, &out); err != nil {
		t.Fatalf("initial UpdateRules failed: %v", err)
	}

	// Second update with Reconcile failing must restore v1 rule files and remove newly added ads file.
	useV2 = true
	execFail := &fakeOpsExec{failResolve: true}
	if err := update.UpdateRules(context.Background(), store, execFail, cfg, true, false, &out); err == nil {
		t.Fatalf("expected UpdateRules to fail when Reconcile fails")
	}

	rulesDir := filepath.Join(store.Dir, "rules")
	if got, _ := os.ReadFile(filepath.Join(rulesDir, "geoip.dat")); !bytes.Equal(got, v1Geoip) {
		t.Fatalf("geoip.dat not restored, got %q", string(got))
	}
	if got, _ := os.ReadFile(filepath.Join(rulesDir, "IPchnroute")); string(got) != v1Chn {
		t.Fatalf("IPchnroute not restored, got %q", string(got))
	}
	if got, _ := os.ReadFile(filepath.Join(rulesDir, "Domains.chn.txt")); string(got) != v1Dom {
		t.Fatalf("Domains.chn.txt not restored, got %q", string(got))
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "Domains.ads.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected newly added Domains.ads.txt removed on rollback, err=%v", err)
	}
}

func TestMigrateCleanupV2OrderSafetyAndRestore(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	zeroConf := filepath.Join(dir, "0conf")
	_ = os.WriteFile(zeroConf, []byte(`{
  "address": {"webUIport": "8443"},
  "v2node": [{"domain": "hk.example.com:443", "name": "HK", "uuid": "11111111-1111-4111-8111-111111111111"}],
  "update": {"v2node": {"domain": "hk.example.com", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111"}}
}`), 0o600)

	v2NFTDir := filepath.Join(dir, "v2nft")
	_ = os.MkdirAll(v2NFTDir, 0o755)
	_ = os.WriteFile(filepath.Join(v2NFTDir, "flowtable_eth.sh"), []byte("#!/bin/bash\n"), 0o755)
	_ = os.WriteFile(filepath.Join(v2NFTDir, "nftables"), []byte("table ip de_GWD {}\n"), 0o644)

	nginxConfDir := filepath.Join(root, "etc", "nginx", "conf.d")
	_ = os.MkdirAll(nginxConfDir, 0o755)
	legacyDefault := filepath.Join(nginxConfDir, "default.conf")
	legacy80 := filepath.Join(nginxConfDir, "80.conf")
	unrelatedNginx := filepath.Join(nginxConfDir, "other.conf")
	_ = os.WriteFile(legacyDefault, []byte("server { location /dq { proxy_pass http://127.0.0.1:9853; } }\n"), 0o644)
	_ = os.WriteFile(legacy80, []byte("# de_GWD 80 redirect\nserver { listen 80; }\n"), 0o644)
	_ = os.WriteFile(unrelatedNginx, []byte("server { listen 8088; }\n"), 0o644)

	// 1. --cleanup-v2 without --apply is rejected without touching v2 services.
	execNoApply := &fakeOpsExec{
		piholeRunning: true,
		activeSvcs:    map[string]bool{"vtrui": true, "mosdns": true},
	}
	var out, errBuf bytes.Buffer
	code := runMigrateWithExec(store, execNoApply, v2NFTDir, reconcile.ApplyOptions{RootPrefix: root}, []string{
		"--kind", "v2_client", "--from", zeroConf, "--cleanup-v2",
	}, &out, &errBuf)
	if code == 0 || !strings.Contains(errBuf.String(), "--apply") {
		t.Fatalf("expected --cleanup-v2 without --apply to fail, code=%d err=%q", code, errBuf.String())
	}
	if len(execNoApply.stoppedSvcs) != 0 || len(execNoApply.cmds) != 0 {
		t.Fatalf("expected no v2 cleanup commands when --apply omitted, stopped=%v cmds=%v", execNoApply.stoppedSvcs, execNoApply.cmds)
	}

	// 2. --cleanup-v2 --apply catches nft preflight failure during dry-run BEFORE touching legacy v2.
	execDryFail := &fakeOpsExec{
		piholeRunning:  true,
		failValidation: "nft",
		activeSvcs: map[string]bool{
			"vtrui":  true,
			"mosdns": true,
		},
	}
	baseOpts := reconcile.ApplyOptions{
		RootPrefix: root,
		RenderOpts: render.RenderOptions{
			StateDir:     "/etc/dex",
			GeneratedDir: "/etc/dex/generated",
			CertFile:     filepath.Join(stateDir, "ssl", "dex.cer"),
			KeyFile:      filepath.Join(stateDir, "ssl", "dex.key"),
		},
	}
	out.Reset()
	errBuf.Reset()
	code = runMigrateWithExec(store, execDryFail, v2NFTDir, baseOpts, []string{
		"--kind", "v2_client", "--from", zeroConf, "--cleanup-v2", "--apply",
	}, &out, &errBuf)
	if code == 0 || !strings.Contains(errBuf.String(), "legacy v2 untouched") {
		t.Fatalf("expected dry-run nft validation failure leaving legacy v2 untouched, code=%d err=%q", code, errBuf.String())
	}
	if len(execDryFail.stoppedSvcs) != 0 {
		t.Fatalf("expected no v2 services stopped when dry-run preflight fails, stopped=%v", execDryFail.stoppedSvcs)
	}

	// 3. --cleanup-v2 --apply when formal Reconcile fails after cleanup (e.g. dex-nft start fails) restores active v2 services, pihole, and v2 nft rules.
	execFail := &fakeOpsExec{
		piholeRunning: true,
		failStartSvc:  "dex-nft",
		activeSvcs: map[string]bool{
			"vtrui":  true,
			"mosdns": true,
		},
	}
	out.Reset()
	errBuf.Reset()
	code = runMigrateWithExec(store, execFail, v2NFTDir, baseOpts, []string{
		"--kind", "v2_client", "--from", zeroConf, "--cleanup-v2", "--apply",
	}, &out, &errBuf)
	if code == 0 {
		t.Fatalf("expected migrate --cleanup-v2 --apply to fail on dex-nft start failure")
	}

	for _, svc := range execFail.stoppedSvcs {
		if svc == "nftables" {
			t.Fatalf("must never stop system nftables service, stopped=%v", execFail.stoppedSvcs)
		}
	}

	findCmdIdx := func(substr string) int {
		for i, c := range execFail.cmds {
			if strings.Contains(c, substr) {
				return i
			}
		}
		return -1
	}
	findLastCmdIdx := func(substr string) int {
		for i := len(execFail.cmds) - 1; i >= 0; i-- {
			if strings.Contains(execFail.cmds[i], substr) {
				return i
			}
		}
		return -1
	}
	for _, c := range execFail.cmds {
		if strings.Contains(c, "docker rm") {
			t.Fatalf("must never run docker rm, cmds=%v", execFail.cmds)
		}
	}

	stopPiholeIdx := findCmdIdx("docker stop pihole")
	delDeGWDIdx := findCmdIdx("nft delete table ip de_GWD")
	delBypassIdx := findCmdIdx("nft delete table inet bypassflow")
	delFilterIdx := findCmdIdx("nft delete table inet filter")
	delRouterIdx := findCmdIdx("nft delete table inet router")
	nftCheckIdx := findLastCmdIdx("nft -c -f")
	startPiholeIdx := findCmdIdx("docker start pihole")
	reloadFlowIdx := findCmdIdx("flowtable_eth.sh")
	reloadNFTIdx := findCmdIdx("nft -f " + filepath.Join(v2NFTDir, "nftables"))

	if stopPiholeIdx < 0 || delDeGWDIdx < 0 || delBypassIdx < 0 || delFilterIdx < 0 || delRouterIdx < 0 {
		t.Fatalf("missing expected v2 cleanup commands, cmds=%v", execFail.cmds)
	}
	if nftCheckIdx < 0 || delDeGWDIdx > nftCheckIdx || stopPiholeIdx > nftCheckIdx {
		t.Fatalf("expected v2 cleanup before formal Reconcile preflight, cmds=%v", execFail.cmds)
	}
	if startPiholeIdx < nftCheckIdx || reloadFlowIdx < nftCheckIdx || reloadNFTIdx < nftCheckIdx {
		t.Fatalf("expected v2 restore (docker start pihole + v2 nft reload) after Reconcile failure, cmds=%v", execFail.cmds)
	}
	if !strings.Contains(strings.Join(execFail.startedSvcs, ","), "vtrui") || !strings.Contains(strings.Join(execFail.startedSvcs, ","), "mosdns") {
		t.Fatalf("expected previously active v2 services restored, startedSvcs=%v", execFail.startedSvcs)
	}
	if b, err := os.ReadFile(legacyDefault); err != nil || !strings.Contains(string(b), "/dq") {
		t.Fatalf("expected legacy default.conf restored on Reconcile failure, err=%v", err)
	}
	if b, err := os.ReadFile(legacy80); err != nil || !strings.Contains(string(b), "de_GWD") {
		t.Fatalf("expected legacy 80.conf restored on Reconcile failure, err=%v", err)
	}
	if b, err := os.ReadFile(unrelatedNginx); err != nil || !strings.Contains(string(b), "8088") {
		t.Fatalf("expected unrelated nginx config untouched, err=%v", err)
	}

	// 3. Direct cleanupLegacyV2WithPaths removes legacy nginx files, keeps unrelated ones, and restore reloads active nginx
	snapExec := &fakeOpsExec{activeSvcs: map[string]bool{"nginx": true}}
	snap := cleanupLegacyV2WithPaths(context.Background(), snapExec, v2NFTDir, nginxConfDir, &out)
	if _, err := os.Stat(legacyDefault); !os.IsNotExist(err) {
		t.Fatalf("expected legacy default.conf removed during cleanup")
	}
	if _, err := os.Stat(legacy80); !os.IsNotExist(err) {
		t.Fatalf("expected legacy 80.conf removed during cleanup")
	}
	if _, err := os.Stat(unrelatedNginx); err != nil {
		t.Fatalf("expected unrelated nginx conf preserved during cleanup, err=%v", err)
	}
	snap.restore(context.Background(), snapExec, &out)
	if _, err := os.Stat(legacyDefault); err != nil {
		t.Fatalf("expected legacy default.conf restored by snap.restore, err=%v", err)
	}
	if strings.Join(snapExec.reloaded, ",") != "nginx" {
		t.Fatalf("expected active nginx reloaded after restoring legacy nginx configs, got %v", snapExec.reloaded)
	}
}

func TestUpdateRulesRestartsAffectedServices(t *testing.T) {
	geoip := []byte("geoip-v1")
	geosite := []byte("geosite-v1")
	chnCIDRs := "1.0.1.0/24\n1.0.2.0/23\n"
	chnDomains := "qq.com\nbaidu.com\n"
	appleDomains := "apple.com\nicloud.com\n"
	gamesDomains := "steampowered.com\nsteamcontent.com\n"
	adsDomains := "ads.example.com\ntracker.example.com\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geoip.dat":
			_, _ = w.Write(geoip)
		case "/geoip.dat.sha256sum":
			sum := sha256.Sum256(geoip)
			fmt.Fprintf(w, "%s  geoip.dat\n", hex.EncodeToString(sum[:]))
		case "/geosite.dat":
			_, _ = w.Write(geosite)
		case "/geosite.dat.sha256sum":
			sum := sha256.Sum256(geosite)
			fmt.Fprintf(w, "%s  geosite.dat\n", hex.EncodeToString(sum[:]))
		case "/cn.txt":
			_, _ = w.Write([]byte(chnCIDRs))
		case "/direct.txt":
			_, _ = w.Write([]byte(chnDomains))
		case "/apple.txt":
			_, _ = w.Write([]byte(appleDomains))
		case "/games.txt":
			_, _ = w.Write([]byte(gamesDomains))
		case "/reject.txt":
			_, _ = w.Write([]byte(adsDomains))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := state.NewStore(filepath.Join(dir, "dex"))
	st := state.NewDefaultState(state.RoleRelay)
	st.System.AutoTuneSysctl = false
	if err := store.Save(st); err != nil {
		t.Fatalf("Save state: %v", err)
	}

	cfg := update.OpsConfig{
		Client:          srv.Client(),
		GeoIPURL:        srv.URL + "/geoip.dat",
		GeoSiteURL:      srv.URL + "/geosite.dat",
		ChnRouteURL:     srv.URL + "/cn.txt",
		DomainsChnURL:   srv.URL + "/direct.txt",
		DomainsAppleURL: srv.URL + "/apple.txt",
		DomainsGamesURL: srv.URL + "/games.txt",
		DomainsAdsURL:   srv.URL + "/reject.txt",
		MinChnRouteCIDR: 2,
		MinChnDomains:   2,
		MinAppleDomains: 2,
		MinGamesDomains: 2,
		MinAdsDomains:   2,
	}

	exec := &fakeOpsExec{
		activeSvcs: map[string]bool{"dex-xray": true, "dex-mosdns": true},
	}
	var out bytes.Buffer

	// 1. Initial download creates all rule files -> restarts both dex-xray and dex-mosdns.
	if err := update.UpdateRules(context.Background(), store, exec, cfg, true, false, &out); err != nil {
		t.Fatalf("initial UpdateRules failed: %v", err)
	}
	if strings.Join(exec.restarted, ",") != "dex-xray,dex-mosdns" {
		t.Fatalf("expected both dex-xray and dex-mosdns restarted initially, got %v", exec.restarted)
	}

	// 2. Unchanged second run -> restarts neither.
	exec.restarted = nil
	if err := update.UpdateRules(context.Background(), store, exec, cfg, true, false, &out); err != nil {
		t.Fatalf("unchanged UpdateRules failed: %v", err)
	}
	if len(exec.restarted) != 0 {
		t.Fatalf("expected zero restarts when rules unchanged, got %v", exec.restarted)
	}

	// 3. Only Domains.chn.txt changed -> restarts only dex-mosdns.
	exec.restarted = nil
	chnDomains = "qq.com\nbaidu.com\ntaobao.com\n"
	if err := update.UpdateRules(context.Background(), store, exec, cfg, true, false, &out); err != nil {
		t.Fatalf("Domains.chn.txt UpdateRules failed: %v", err)
	}
	if strings.Join(exec.restarted, ",") != "dex-mosdns" {
		t.Fatalf("expected only [dex-mosdns] restarted on Domains.chn.txt change, got %v", exec.restarted)
	}

	// 4. Only Domains.apple.txt changed -> restarts only dex-mosdns.
	exec.restarted = nil
	appleDomains = "apple.com\nicloud.com\nmzstatic.com\n"
	if err := update.UpdateRules(context.Background(), store, exec, cfg, true, false, &out); err != nil {
		t.Fatalf("Domains.apple.txt UpdateRules failed: %v", err)
	}
	if strings.Join(exec.restarted, ",") != "dex-mosdns" {
		t.Fatalf("expected only [dex-mosdns] restarted on Domains.apple.txt change, got %v", exec.restarted)
	}

	// 5. Only Domains.games.txt changed -> restarts only dex-mosdns.
	exec.restarted = nil
	gamesDomains = "steampowered.com\nsteamcontent.com\nvalvesoftware.com\n"
	if err := update.UpdateRules(context.Background(), store, exec, cfg, true, false, &out); err != nil {
		t.Fatalf("Domains.games.txt UpdateRules failed: %v", err)
	}
	if strings.Join(exec.restarted, ",") != "dex-mosdns" {
		t.Fatalf("expected only [dex-mosdns] restarted on Domains.games.txt change, got %v", exec.restarted)
	}

	// 6. Only geoip.dat changed -> restarts only dex-xray.
	exec.restarted = nil
	geoip = []byte("geoip-v2")
	if err := update.UpdateRules(context.Background(), store, exec, cfg, true, false, &out); err != nil {
		t.Fatalf("geoip.dat UpdateRules failed: %v", err)
	}
	if strings.Join(exec.restarted, ",") != "dex-xray" {
		t.Fatalf("expected only [dex-xray] restarted on geoip.dat change, got %v", exec.restarted)
	}

	// 7. Only IPchnroute changed -> restarts only dex-mosdns.
	exec.restarted = nil
	chnCIDRs = "1.0.1.0/24\n223.5.5.0/24\n"
	if err := update.UpdateRules(context.Background(), store, exec, cfg, true, false, &out); err != nil {
		t.Fatalf("IPchnroute UpdateRules failed: %v", err)
	}
	if strings.Join(exec.restarted, ",") != "dex-mosdns" {
		t.Fatalf("expected only [dex-mosdns] restarted on IPchnroute change, got %v", exec.restarted)
	}
}

func TestMenuOption8RestartsDaemon(t *testing.T) {
	dir := t.TempDir()
	store := state.NewStore(dir)
	st := state.NewDefaultState(state.RoleClient)
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	exec := &fakeOpsExec{
		activeSvcs: map[string]bool{"dex-daemon": true},
	}
	var out, errBuf bytes.Buffer
	code := runInteractiveMenu(store, exec, strings.NewReader("8\n9443\nq\n"), &out, &errBuf)
	if code != 0 {
		t.Fatalf("menu exited %d: %s", code, errBuf.String())
	}
	loaded, _ := store.Load()
	if loaded.Auth.ListenAddr != ":9443" {
		t.Fatalf("expected ListenAddr :9443, got %q", loaded.Auth.ListenAddr)
	}
	if strings.Join(exec.restarted, ",") != "dex-daemon" {
		t.Fatalf("expected dex-daemon restarted after option 8 port change, got %v", exec.restarted)
	}
}

func TestUpdateMosDNSVerifySHA256AndRejectTamper(t *testing.T) {
	goodELF := []byte("\x7fELF\x02\x01\x01\x00good-mosdns")
	evilELF := []byte("\x7fELF\x02\x01\x01\x00evil-mosdns")
	goodZip := makeTestZip(t, "mosdns", goodELF)
	evilZip := makeTestZip(t, "mosdns", evilELF)
	goodSum := sha256.Sum256(goodZip)
	goodHex := hex.EncodeToString(goodSum[:])

	serveZip := goodZip
	serveShaSumFile := true
	serveReleaseAPI := true

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mosdns/mosdns-linux-amd64.zip":
			_, _ = w.Write(serveZip)
		case "/mosdns/mosdns-linux-amd64.zip.sha256sum":
			if !serveShaSumFile {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, "%s  mosdns-linux-amd64.zip\n", goodHex)
		case "/mosdns/release.json":
			if !serveReleaseAPI {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, `{"assets":[{"name":"mosdns-linux-amd64.zip","digest":"sha256:%s"}]}`, goodHex)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	binPath := filepath.Join(dir, "mosdns")
	store := state.NewStore(filepath.Join(dir, "state"))
	_ = store.Save(state.NewDefaultState(state.RoleClient))

	cfg := update.OpsConfig{
		Client:              srv.Client(),
		MosDNSBase:          srv.URL + "/mosdns",
		MosDNSReleaseAPIURL: srv.URL + "/mosdns/release.json",
		MosDNSBinPath:       binPath,
		GOARCH:              "amd64",
	}

	var out bytes.Buffer
	// 1. Succeeds via .sha256sum
	if err := update.UpdateComponents(context.Background(), store, &fakeOpsExec{}, cfg, "mosdns", "latest", &out); err != nil {
		t.Fatalf("mosdns update with .sha256sum failed: %v", err)
	}
	got, _ := os.ReadFile(binPath)
	if !bytes.Equal(got, goodELF) {
		t.Fatalf("unexpected binary after .sha256sum update")
	}

	// 2. Tampered zip rejected when verified via .sha256sum or Release API; existing binary preserved
	serveZip = evilZip
	if err := update.UpdateComponents(context.Background(), store, &fakeOpsExec{}, cfg, "mosdns", "latest", &out); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch for tampered zip (.sha256sum), got %v", err)
	}
	serveShaSumFile = false
	if err := update.UpdateComponents(context.Background(), store, &fakeOpsExec{}, cfg, "mosdns", "latest", &out); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch for tampered zip (release API), got %v", err)
	}
	afterTamper, _ := os.ReadFile(binPath)
	if !bytes.Equal(afterTamper, goodELF) {
		t.Fatalf("tampered zip overwrote existing mosdns binary")
	}

	// 3. Missing both .sha256sum and Release API metadata is rejected
	serveZip = goodZip
	serveReleaseAPI = false
	if err := update.UpdateComponents(context.Background(), store, &fakeOpsExec{}, cfg, "mosdns", "latest", &out); err == nil {
		t.Fatalf("expected error when neither .sha256sum nor release API is available")
	}
}

func TestUpdateComponentsRollsBackOnRestartFailure(t *testing.T) {
	oldELF := append([]byte("\x7fELF"), []byte("old-binary-v1")...)
	newELF := append([]byte("\x7fELF"), []byte("new-binary-v2")...)

	oldXraySum := sha256.Sum256(makeTestZip(t, "xray", oldELF))
	_ = oldXraySum

	newXrayZip := makeTestZip(t, "xray", newELF)
	newXrayHex := func() string {
		s := sha256.Sum256(newXrayZip)
		return hex.EncodeToString(s[:])
	}()

	newMosZip := makeTestZip(t, "mosdns", newELF)
	newMosHex := func() string {
		s := sha256.Sum256(newMosZip)
		return hex.EncodeToString(s[:])
	}()

	newDexSum := sha256.Sum256(newELF)
	newDexHex := hex.EncodeToString(newDexSum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/xray/Xray-linux-64.zip":
			_, _ = w.Write(newXrayZip)
		case "/xray/Xray-linux-64.zip.dgst":
			fmt.Fprintf(w, "SHA2-256=%s\n", newXrayHex)
		case "/mosdns/mosdns-linux-amd64.zip":
			_, _ = w.Write(newMosZip)
		case "/mosdns/mosdns-linux-amd64.zip.sha256sum":
			fmt.Fprintf(w, "%s  mosdns-linux-amd64.zip\n", newMosHex)
		case "/dex/dex-linux-amd64":
			_, _ = w.Write(newELF)
		case "/dex/SHA256SUMS":
			fmt.Fprintf(w, "%s  dex-linux-amd64\n", newDexHex)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := state.NewStore(filepath.Join(dir, "state"))
	_ = store.Save(state.NewDefaultState(state.RoleClient))

	xrayBin := filepath.Join(dir, "xray")
	mosBin := filepath.Join(dir, "mosdns")
	dexBin := filepath.Join(dir, "dex")
	_ = os.WriteFile(xrayBin, oldELF, 0o755)
	_ = os.WriteFile(mosBin, oldELF, 0o755)
	_ = os.WriteFile(dexBin, oldELF, 0o755)

	cfg := update.OpsConfig{
		Client:          srv.Client(),
		XrayReleaseBase: srv.URL + "/xray",
		MosDNSBase:      srv.URL + "/mosdns",
		DexReleaseBase:  srv.URL + "/dex",
		XrayBinPath:     xrayBin,
		MosDNSBinPath:   mosBin,
		DexBinPath:      dexBin,
		GOARCH:          "amd64",
	}

	// 1. Xray restart fails -> error returned, old xray binary restored, no "Updated ... cleanly"
	var out bytes.Buffer
	execXrayFail := &fakeOpsExec{activeSvcs: map[string]bool{"dex-xray": true}, failRestartSvc: "dex-xray"}
	if err := update.UpdateComponents(context.Background(), store, execXrayFail, cfg, "xray", "latest", &out); err == nil {
		t.Fatalf("expected UpdateComponents(xray) to fail on restart error")
	}
	if strings.Contains(out.String(), "Updated") {
		t.Fatalf("must not report Updated cleanly on failed restart, got %q", out.String())
	}
	if got, _ := os.ReadFile(xrayBin); !bytes.Equal(got, oldELF) {
		t.Fatalf("expected xray binary rolled back to oldELF, got %q", got)
	}

	// 2. MosDNS restart fails -> error returned, old mosdns binary restored
	out.Reset()
	execMosFail := &fakeOpsExec{activeSvcs: map[string]bool{"dex-mosdns": true}, failRestartSvc: "dex-mosdns"}
	if err := update.UpdateComponents(context.Background(), store, execMosFail, cfg, "mosdns", "latest", &out); err == nil {
		t.Fatalf("expected UpdateComponents(mosdns) to fail on restart error")
	}
	if strings.Contains(out.String(), "Updated") {
		t.Fatalf("must not report Updated cleanly on failed restart, got %q", out.String())
	}
	if got, _ := os.ReadFile(mosBin); !bytes.Equal(got, oldELF) {
		t.Fatalf("expected mosdns binary rolled back to oldELF, got %q", got)
	}

	// 3. DEX consumer (dex-doh) restart fails -> error returned, old dex binary restored
	out.Reset()
	execDohFail := &fakeOpsExec{activeSvcs: map[string]bool{"dex-doh": true, "dex-daemon": true}, failRestartSvc: "dex-doh"}
	if err := update.UpdateComponents(context.Background(), store, execDohFail, cfg, "dex", "latest", &out); err == nil {
		t.Fatalf("expected UpdateComponents(dex) to fail on dex-doh restart error")
	}
	if strings.Contains(out.String(), "Updated") {
		t.Fatalf("must not report Updated cleanly on failed restart, got %q", out.String())
	}
	if got, _ := os.ReadFile(dexBin); !bytes.Equal(got, oldELF) {
		t.Fatalf("expected dex binary rolled back to oldELF, got %q", got)
	}

	// 4. Explicit invalid DEX_BIN fails instead of silently downloading
	t.Setenv("DEX_BIN", filepath.Join(dir, "does-not-exist"))
	if err := update.UpdateComponents(context.Background(), store, &fakeOpsExec{}, cfg, "dex", "latest", &out); err == nil || !strings.Contains(err.Error(), "DEX_BIN") {
		t.Fatalf("expected explicit missing DEX_BIN error, got %v", err)
	}
}

func TestShortInstallerSyncAndRegularFile(t *testing.T) {
	installPath := filepath.Join("..", "..", "scripts", "install.sh")
	installInfo, err := os.Lstat(installPath)
	if err != nil {
		t.Fatalf("lstat %s: %v", installPath, err)
	}
	if installInfo.Mode()&os.ModeSymlink != 0 || !installInfo.Mode().IsRegular() {
		t.Fatalf("%s must be a regular non-symlink file", installPath)
	}
	installBytes, err := os.ReadFile(installPath)
	if err != nil {
		t.Fatalf("read %s: %v", installPath, err)
	}
	if !bytes.HasPrefix(installBytes, []byte("#!/bin/sh\n")) {
		t.Fatalf("%s must start with #!/bin/sh", installPath)
	}

	for _, name := range []string{"i", "dex"} {
		shortPath := filepath.Join("..", "..", name)
		shortInfo, err := os.Lstat(shortPath)
		if err != nil {
			t.Fatalf("lstat %s: %v", shortPath, err)
		}
		if shortInfo.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s must be a regular file, not a symlink", shortPath)
		}
		if !shortInfo.Mode().IsRegular() {
			t.Fatalf("%s must be a regular file, mode=%v", shortPath, shortInfo.Mode())
		}
		if shortInfo.Mode().Perm()&0o111 == 0 {
			t.Fatalf("%s must be executable, mode=%v", shortPath, shortInfo.Mode().Perm())
		}

		shortBytes, err := os.ReadFile(shortPath)
		if err != nil {
			t.Fatalf("read %s: %v", shortPath, err)
		}
		if !bytes.HasPrefix(shortBytes, []byte("#!/bin/sh\n")) {
			t.Fatalf("%s must start with #!/bin/sh", shortPath)
		}
		if !bytes.Equal(shortBytes, installBytes) {
			t.Fatalf("%s and %s must be byte-for-byte identical", shortPath, installPath)
		}
	}
}

type bootstrapMockExec struct {
	*fakeOpsExec
	hasCmd func(string) bool
}

func (b *bootstrapMockExec) HasCommand(name string) bool {
	if b.hasCmd != nil {
		return b.hasCmd(name)
	}
	return b.fakeOpsExec.HasCommand(name)
}

func TestBootstrapRoleRuntimeDeps(t *testing.T) {
	xrayELF := []byte("\x7fELF\x02\x01\x01\x00xray-boot")
	mosELF := []byte("\x7fELF\x02\x01\x01\x00mos-boot")
	xrayZip := makeTestZip(t, "xray", xrayELF)
	mosZip := makeTestZip(t, "mosdns", mosELF)
	xraySum := sha256.Sum256(xrayZip)
	mosSum := sha256.Sum256(mosZip)

	geoip := []byte("geoip-boot")
	geosite := []byte("geosite-boot")
	geoipSum := sha256.Sum256(geoip)
	geositeSum := sha256.Sum256(geosite)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/xray/Xray-linux-64.zip":
			_, _ = w.Write(xrayZip)
		case "/xray/Xray-linux-64.zip.dgst":
			fmt.Fprintf(w, "SHA2-256=%s\n", hex.EncodeToString(xraySum[:]))
		case "/mosdns/mosdns-linux-amd64.zip":
			_, _ = w.Write(mosZip)
		case "/mosdns/mosdns-linux-amd64.zip.sha256sum":
			fmt.Fprintf(w, "%s  mosdns-linux-amd64.zip\n", hex.EncodeToString(mosSum[:]))
		case "/geoip.dat":
			_, _ = w.Write(geoip)
		case "/geoip.dat.sha256sum":
			fmt.Fprintf(w, "%s  geoip.dat\n", hex.EncodeToString(geoipSum[:]))
		case "/geosite.dat":
			_, _ = w.Write(geosite)
		case "/geosite.dat.sha256sum":
			fmt.Fprintf(w, "%s  geosite.dat\n", hex.EncodeToString(geositeSum[:]))
		case "/cn.txt":
			_, _ = w.Write([]byte("1.0.1.0/24\n223.5.5.0/24\n"))
		case "/direct.txt":
			_, _ = w.Write([]byte("qq.com\nbaidu.com\n"))
		case "/apple.txt":
			_, _ = w.Write([]byte("apple.com\nicloud.com\n"))
		case "/games.txt":
			_, _ = w.Write([]byte("steampowered.com\nsteamcontent.com\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	newCfg := func(dir string) update.OpsConfig {
		return update.OpsConfig{
			Client:          srv.Client(),
			XrayReleaseBase: srv.URL + "/xray",
			MosDNSBase:      srv.URL + "/mosdns",
			GeoIPURL:        srv.URL + "/geoip.dat",
			GeoSiteURL:      srv.URL + "/geosite.dat",
			ChnRouteURL:     srv.URL + "/cn.txt",
			DomainsChnURL:   srv.URL + "/direct.txt",
			DomainsAppleURL: srv.URL + "/apple.txt",
			DomainsGamesURL: srv.URL + "/games.txt",
			XrayBinPath:     filepath.Join(dir, "xray"),
			MosDNSBinPath:   filepath.Join(dir, "mosdns"),
			GOARCH:          "amd64",
			MinChnRouteCIDR: 2,
			MinChnDomains:   2,
			MinAppleDomains: 2,
			MinGamesDomains: 2,
		}
	}

	t.Run("client_apt", func(t *testing.T) {
		dir := t.TempDir()
		store := state.NewStore(filepath.Join(dir, "dex"))
		if err := store.Save(state.NewDefaultState(state.RoleClient)); err != nil {
			t.Fatal(err)
		}
		cfg := newCfg(dir)
		base := &fakeOpsExec{activeSvcs: map[string]bool{}}
		exec := &bootstrapMockExec{
			fakeOpsExec: base,
			hasCmd: func(name string) bool {
				return name == "apt-get"
			},
		}
		var out bytes.Buffer
		if err := bootstrapRoleRuntimeDeps(context.Background(), store, exec, state.RoleClient, cfg, &out); err != nil {
			t.Fatalf("bootstrap client failed: %v", err)
		}
		joined := strings.Join(base.cmds, "\n")
		if !strings.Contains(joined, "apt-get install -y -qq --no-install-recommends wireguard-tools") {
			t.Fatalf("expected wireguard-tools installed via apt-get, cmds=%v", base.cmds)
		}
		if got, _ := os.ReadFile(cfg.XrayBinPath); !bytes.Equal(got, xrayELF) {
			t.Fatalf("expected xray binary installed")
		}
		if got, _ := os.ReadFile(cfg.MosDNSBinPath); !bytes.Equal(got, mosELF) {
			t.Fatalf("expected mosdns binary installed")
		}
		for _, f := range []string{"geoip.dat", "geosite.dat", "IPchnroute", "Domains.chn.txt", "Domains.apple.txt", "Domains.games.txt"} {
			if _, err := os.Stat(filepath.Join(store.Dir, "rules", f)); err != nil {
				t.Fatalf("expected client rule %s created: %v", f, err)
			}
		}
	})

	t.Run("server_apk", func(t *testing.T) {
		dir := t.TempDir()
		store := state.NewStore(filepath.Join(dir, "dex"))
		st := state.NewDefaultState(state.RoleServer)
		st.Server.Domain = "srv.example.com"
		st.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
		st.Server.Path = "/dex"
		if err := store.Save(st); err != nil {
			t.Fatal(err)
		}
		cfg := newCfg(dir)
		base := &fakeOpsExec{activeSvcs: map[string]bool{}}
		exec := &bootstrapMockExec{
			fakeOpsExec: base,
			hasCmd: func(name string) bool {
				return name == "apk"
			},
		}
		var out bytes.Buffer
		if err := bootstrapRoleRuntimeDeps(context.Background(), store, exec, state.RoleServer, cfg, &out); err != nil {
			t.Fatalf("bootstrap server failed: %v", err)
		}
		joined := strings.Join(base.cmds, "\n")
		if !strings.Contains(joined, "apk add --no-cache nginx socat wireguard-tools") {
			t.Fatalf("expected server packages installed via apk, cmds=%v", base.cmds)
		}
		if got, _ := os.ReadFile(cfg.XrayBinPath); !bytes.Equal(got, xrayELF) {
			t.Fatalf("expected xray binary installed")
		}
		if _, err := os.Stat(cfg.MosDNSBinPath); !os.IsNotExist(err) {
			t.Fatalf("server role must not install mosdns")
		}
		if got, _ := os.ReadFile(filepath.Join(store.Dir, "rules", "geoip.dat")); !bytes.Equal(got, geoip) {
			t.Fatalf("expected verified geoip.dat for server")
		}
		if got, _ := os.ReadFile(filepath.Join(store.Dir, "rules", "geosite.dat")); !bytes.Equal(got, geosite) {
			t.Fatalf("expected verified geosite.dat for server")
		}
	})

	t.Run("relay_partial_present", func(t *testing.T) {
		dir := t.TempDir()
		store := state.NewStore(filepath.Join(dir, "dex"))
		if err := store.Save(state.NewDefaultState(state.RoleRelay)); err != nil {
			t.Fatal(err)
		}
		rulesDir := filepath.Join(store.Dir, "rules")
		if err := os.MkdirAll(rulesDir, 0o755); err != nil {
			t.Fatal(err)
		}
		existingGeoip := []byte("existing-geoip")
		if err := os.WriteFile(filepath.Join(rulesDir, "geoip.dat"), existingGeoip, 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := newCfg(dir)
		base := &fakeOpsExec{activeSvcs: map[string]bool{}}
		exec := &bootstrapMockExec{
			fakeOpsExec: base,
			hasCmd: func(name string) bool {
				return name == "apt-get" || name == cfg.XrayBinPath
			},
		}
		var out bytes.Buffer
		if err := bootstrapRoleRuntimeDeps(context.Background(), store, exec, state.RoleRelay, cfg, &out); err != nil {
			t.Fatalf("bootstrap relay failed: %v", err)
		}
		joined := strings.Join(base.cmds, "\n")
		if !strings.Contains(joined, "apt-get install -y -qq --no-install-recommends haproxy") {
			t.Fatalf("expected haproxy installed via apt-get, cmds=%v", base.cmds)
		}
		if _, err := os.Stat(cfg.XrayBinPath); !os.IsNotExist(err) {
			t.Fatalf("expected xray download skipped when HasCommand reports present")
		}
		if got, _ := os.ReadFile(filepath.Join(rulesDir, "geoip.dat")); !bytes.Equal(got, existingGeoip) {
			t.Fatalf("expected existing geoip.dat preserved, got %q", got)
		}
		if got, _ := os.ReadFile(filepath.Join(rulesDir, "geosite.dat")); !bytes.Equal(got, geosite) {
			t.Fatalf("expected missing geosite.dat downloaded")
		}
	})

	t.Run("landing_minimal", func(t *testing.T) {
		dir := t.TempDir()
		store := state.NewStore(filepath.Join(dir, "dex"))
		st := state.NewDefaultState(state.RoleLanding)
		st.Server.Domain = "land.example.com"
		st.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
		st.Server.Path = "/dex"
		if err := store.Save(st); err != nil {
			t.Fatal(err)
		}
		cfg := newCfg(dir)
		base := &fakeOpsExec{activeSvcs: map[string]bool{}}
		exec := &bootstrapMockExec{
			fakeOpsExec: base,
			hasCmd:      func(string) bool { return false },
		}
		var out bytes.Buffer
		if err := bootstrapRoleRuntimeDeps(context.Background(), store, exec, state.RoleLanding, cfg, &out); err != nil {
			t.Fatalf("bootstrap landing failed: %v", err)
		}
		if len(base.cmds) != 0 {
			t.Fatalf("expected no OS packages installed for landing, cmds=%v", base.cmds)
		}
		if got, _ := os.ReadFile(cfg.XrayBinPath); !bytes.Equal(got, xrayELF) {
			t.Fatalf("expected xray binary installed for landing")
		}
		if got, _ := os.ReadFile(filepath.Join(store.Dir, "rules", "geoip.dat")); !bytes.Equal(got, geoip) {
			t.Fatalf("expected geoip.dat installed for landing")
		}
		if got, _ := os.ReadFile(filepath.Join(store.Dir, "rules", "geosite.dat")); !bytes.Equal(got, geosite) {
			t.Fatalf("expected geosite.dat installed for landing")
		}
	})
}
