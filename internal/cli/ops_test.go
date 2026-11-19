package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

type fakeOpsExec struct {
	reconcile.SystemExecutor
	cmds        []string
	stoppedSvcs []string
	restarted   []string
}

func (f *fakeOpsExec) HasCommand(name string) bool { return name == "nft" || name == "docker" }
func (f *fakeOpsExec) RunCommand(ctx context.Context, env []string, name string, args ...string) (string, error) {
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	return "ok", nil
}
func (f *fakeOpsExec) DetectInitSystem() string  { return "systemd" }
func (f *fakeOpsExec) DetectIsContainer() bool   { return false }
func (f *fakeOpsExec) DetectMemMB() int          { return 512 }
func (f *fakeOpsExec) DetectPhysicalNICs() []string { return []string{"eth0"} }
func (f *fakeOpsExec) ResolveHostIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}
func (f *fakeOpsExec) DaemonReload(ctx context.Context, initSys string) error { return nil }
func (f *fakeOpsExec) ServiceEnableStart(ctx context.Context, initSys, name string) error {
	return nil
}
func (f *fakeOpsExec) ServiceRestart(ctx context.Context, initSys, name string) error {
	f.restarted = append(f.restarted, name)
	return nil
}
func (f *fakeOpsExec) ServiceStopDisable(ctx context.Context, initSys, name string) error {
	f.stoppedSvcs = append(f.stoppedSvcs, name)
	return nil
}
func (f *fakeOpsExec) ServiceIsActive(ctx context.Context, initSys, name string) bool {
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
		case "/reject.txt":
			_, _ = w.Write([]byte("ads.example.com\ntracker.example.com\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := state.NewStore(filepath.Join(dir, "dex"))
	cfg := OpsConfig{
		Client:          srv.Client(),
		GeoIPURL:        srv.URL + "/geoip.dat",
		GeoSiteURL:      srv.URL + "/geosite.dat",
		ChnRouteURL:     srv.URL + "/cn.txt",
		DomainsChnURL:   srv.URL + "/direct.txt",
		DomainsAdsURL:   srv.URL + "/reject.txt",
		MinChnRouteCIDR: 2,
		MinChnDomains:   2,
		MinAdsDomains:   2,
	}

	var out bytes.Buffer
	if err := UpdateRules(context.Background(), store, &fakeOpsExec{}, cfg, true, true, &out); err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(store.Dir, "rules", "IPchnroute"))
	if err != nil || !strings.Contains(string(b), "223.5.5.0/24") {
		t.Fatalf("IPchnroute not written cleanly: err=%v", err)
	}

	// Ensure invalid HTML keeps previous good IPchnroute untouched
	serveHTML = true
	if err := UpdateRules(context.Background(), store, &fakeOpsExec{}, cfg, false, true, &out); err == nil {
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
	cfg := OpsConfig{
		Client:          srv.Client(),
		DexReleaseBase:  srv.URL + "/dex",
		XrayReleaseBase: srv.URL + "/xray",
		MosDNSBase:      srv.URL + "/mosdns",
		DexBinPath:      filepath.Join(binDir, "dex"),
		XrayBinPath:     filepath.Join(binDir, "xray"),
		MosDNSBinPath:   filepath.Join(binDir, "mosdns"),
		GOARCH:          "amd64",
	}

	var out bytes.Buffer
	for _, comp := range []string{"dex", "xray", "mosdns"} {
		if err := UpdateComponents(context.Background(), store, exec, cfg, comp, "latest", &out); err != nil {
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
}
