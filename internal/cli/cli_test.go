package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stuinxo/dex/internal/cert"
	"github.com/stuinxo/dex/internal/reconcile"
	"github.com/stuinxo/dex/internal/render"
	"github.com/stuinxo/dex/internal/state"
)

func TestCLISmokeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")

	exec := &fakeOpsExec{}
	run := func(args ...string) (int, string, string) {
		var out, errBuf bytes.Buffer
		full := append([]string{"--state-dir", stateDir}, args...)
		code := RunWithExecutor(full, exec, strings.NewReader(""), &out, &errBuf)
		return code, out.String(), errBuf.String()
	}

	// 1. version
	code, out, errOut := run("version")
	if code != 0 || !strings.Contains(out, "v0.") {
		t.Fatalf("version failed: code=%d out=%q err=%q", code, out, errOut)
	}

	// 2. init landing -> node show -> apply --dry-run
	code, out, errOut = run("init", "--role", "landing", "--domain", "land.example.com", "--port", "20001")
	if code != 0 || !strings.Contains(out, "Initial Web Password:") {
		t.Fatalf("init landing failed: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run("apply", "--dry-run")
	if code != 0 || !strings.Contains(out, "xray.json") {
		t.Fatalf("apply --dry-run failed: code=%d out=%q err=%q", code, out, errOut)
	}

	// 3. migrate from v2 0conf
	zeroConf := filepath.Join(dir, "0conf")
	_ = os.WriteFile(zeroConf, []byte(`{
  "address": {"webUIport": "8443"},
  "v2node": [{"domain": "hk.example.com:443", "name": "HK", "uuid": "11111111-1111-4111-8111-111111111111"}],
  "update": {"v2node": {"domain": "hk.example.com", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111"}}
}`), 0o600)
	code, out, errOut = run("migrate", "--kind", "v2_client", "--from", zeroConf)
	if code != 0 || !strings.Contains(out, "role=client") {
		t.Fatalf("migrate failed: code=%d out=%q err=%q", code, out, errOut)
	}

	// 4. wg peer-add + node show + apply --dry-run
	code, out, errOut = run("wg", "peer-add", "laptop")
	if code != 0 || !strings.Contains(out, "172.16.66.11/32") {
		t.Fatalf("wg peer-add failed: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run("node", "show")
	if code != 0 || !strings.Contains(out, "hk.example.com:443") {
		t.Fatalf("node show failed: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run("apply", "--dry-run")
	if code != 0 || !strings.Contains(out, "mosdns.yaml") || !strings.Contains(out, "wg0.conf") {
		t.Fatalf("client apply --dry-run failed: code=%d out=%q err=%q", code, out, errOut)
	}

	// 5. init client --doh writes custom DoH and dry-run renders it
	code, out, errOut = run("init", "--force", "--role", "client", "--doh", "https://vtw.example.com/dq")
	if code != 0 || !strings.Contains(out, "Initialized client state") {
		t.Fatalf("init client --doh failed: code=%d out=%q err=%q", code, out, errOut)
	}
	stateRaw, err := os.ReadFile(filepath.Join(stateDir, "state.json"))
	if err != nil || !strings.Contains(string(stateRaw), "https://vtw.example.com/dq") {
		t.Fatalf("expected custom DoH saved in state.json: err=%v data=%q", err, string(stateRaw))
	}
	code, out, errOut = run("apply", "--dry-run")
	if code != 0 || !strings.Contains(out, "mosdns.yaml") {
		t.Fatalf("client --doh apply --dry-run failed: code=%d out=%q err=%q", code, out, errOut)
	}

	// 6. rproxy client-set + client-map-add + rules status
	code, out, errOut = run("rproxy", "client-set", "--address", "srv.example.com", "--port", "20000", "--uuid", "11111111-1111-4111-8111-111111111111")
	if code != 0 {
		t.Fatalf("rproxy client-set failed: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run("rproxy", "client-map-add", "--ext-port", "20080", "--int", "10.0.0.10:80", "--proto", "tcp")
	if code != 0 {
		t.Fatalf("rproxy client-map-add failed: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run("rproxy", "show")
	if code != 0 || !strings.Contains(out, "C-Map :20080 (tcp) -> 10.0.0.10:80") {
		t.Fatalf("rproxy show mismatch: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run("rules", "status")
	if code != 0 || !strings.Contains(out, "geoip.dat") {
		t.Fatalf("rules status failed: code=%d out=%q err=%q", code, out, errOut)
	}

	// 7. server extra add-reality + rproxy set/map-add + del
	code, out, errOut = run("init", "--force", "--role", "server", "--domain", "srv.example.com")
	if code != 0 {
		t.Fatalf("init server failed: %q", errOut)
	}
	code, out, errOut = run("extra", "add-reality", "--port", "9443", "--sni", "www.apple.com")
	if code != 0 || !strings.Contains(out, "security=reality") {
		t.Fatalf("extra add-reality failed: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run("rproxy", "set", "--port", "20000", "--map-port", "20080", "--map-proto", "tcp")
	if code != 0 {
		t.Fatalf("rproxy set failed: %q", errOut)
	}
	code, out, errOut = run("apply", "--dry-run")
	if code != 0 || !strings.Contains(out, "xray.json") {
		t.Fatalf("server extra+rproxy dry-run failed: code=%d out=%q err=%q", code, out, errOut)
	}
	code, out, errOut = run("extra", "del", "9443")
	if code != 0 {
		t.Fatalf("extra del failed: %q", errOut)
	}
}

func TestCertImportReloadsConsumersAndRefreshRespectsManualGuard(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	store := state.NewStore(stateDir)
	s := state.NewDefaultState(state.RoleServer)
	s.Server.Domain = "srv.example.com"
	s.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	if err := store.Save(s); err != nil {
		t.Fatalf("Save state: %v", err)
	}

	srcCert := filepath.Join(dir, "src.cer")
	srcKey := filepath.Join(dir, "src.key")
	if err := cert.EnsureSelfSigned(srcCert, srcKey, "srv.example.com"); err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}

	exec := &fakeOpsExec{
		activeSvcs: map[string]bool{
			"nginx":      true,
			"dex-xray":   true,
			"dex-daemon": true,
		},
	}
	var out, errBuf bytes.Buffer
	code := cmdCert(store, exec, []string{"import", srcCert, srcKey, "--allow-self-signed"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("cmdCert import failed: code=%d err=%q", code, errBuf.String())
	}
	if !reflect.DeepEqual(exec.reloaded, []string{"nginx"}) {
		t.Fatalf("expected nginx reloaded on cert import, got %v", exec.reloaded)
	}
	if !reflect.DeepEqual(exec.restarted, []string{"dex-xray", "dex-daemon"}) {
		t.Fatalf("expected dex-xray & dex-daemon restarted on cert import, got %v", exec.restarted)
	}

	// Second identical import should skip reload/restart (changed=false).
	exec.reloaded = nil
	exec.restarted = nil
	code = cmdCert(store, exec, []string{"import", srcCert, srcKey, "--allow-self-signed"}, &out, &errBuf)
	if code != 0 || len(exec.reloaded) != 0 || len(exec.restarted) != 0 {
		t.Fatalf("expected no reload on unchanged cert import, got reloaded=%v restarted=%v", exec.reloaded, exec.restarted)
	}

	// dex refresh must NOT imply --force; manual edit to managed xray.json must fail.
	root := filepath.Join(dir, "root")
	xrayTarget := filepath.Join(store.GeneratedDir(), "xray.json")
	xrayOnRoot := filepath.Join(root, strings.TrimPrefix(filepath.Clean(xrayTarget), string(filepath.Separator)))
	_ = os.MkdirAll(filepath.Dir(xrayOnRoot), 0o755)
	_ = os.MkdirAll(store.GeneratedDir(), 0o755)
	_ = os.WriteFile(xrayOnRoot, []byte(`{"manual":true}`), 0o640)
	_ = os.WriteFile(store.ManifestPath(), []byte(`{"files":{"`+xrayTarget+`":{"target_path":"`+xrayTarget+`","sha256":"0000","mode":416}}}`), 0o600)

	var rOut, rErr bytes.Buffer
	code = Run([]string{"--state-dir", stateDir, "refresh", "--root-prefix", root}, strings.NewReader(""), &rOut, &rErr)
	if code == 0 || !strings.Contains(rErr.String(), "managed config modified outside dex") {
		t.Fatalf("expected refresh to reject manual edit without --force, code=%d err=%q", code, rErr.String())
	}

	// cert reload subcommand reloads active TLS consumers.
	exec.reloaded = nil
	exec.restarted = nil
	if c := cmdCert(store, exec, []string{"reload"}, &out, &errBuf); c != 0 {
		t.Fatalf("cmdCert reload failed: %q", errBuf.String())
	}
	if !reflect.DeepEqual(exec.reloaded, []string{"nginx"}) || !reflect.DeepEqual(exec.restarted, []string{"dex-xray", "dex-daemon"}) {
		t.Fatalf("unexpected cert reload actions: reloaded=%v restarted=%v", exec.reloaded, exec.restarted)
	}
}

func TestWave2ServerExtraNodeCertWGCommands(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")

	exec := &fakeOpsExec{}
	run := func(args ...string) (int, string, string) {
		var out, errBuf bytes.Buffer
		full := append([]string{"--state-dir", stateDir}, args...)
		code := RunWithExecutor(full, exec, strings.NewReader(""), &out, &errBuf)
		return code, out.String(), errBuf.String()
	}

	// 1. Server init + server set + server show
	if code, _, errOut := run("init", "--role", "server", "--domain", "s1.example.com", "--port", "443", "--tls-mode", "nginx"); code != 0 {
		t.Fatalf("server init failed: %s", errOut)
	}
	if code, _, errOut := run("server", "set", "--protocol", "vmess-ws", "--path", "/ws-custom", "--enable-doh"); code != 0 {
		t.Fatalf("server set failed: %s", errOut)
	}
	code, out, errOut := run("server", "show")
	if code != 0 || !strings.Contains(out, "vmess-ws") || !strings.Contains(out, "/ws-custom") || !strings.Contains(out, "vmess://") {
		t.Fatalf("server show mismatch: code=%d out=%q err=%q", code, out, errOut)
	}

	// 2. Extra protocols + disable-all
	if code, _, errOut := run("extra", "add-xhttp", "--port", "8446", "--domain", "x.example.com"); code != 0 {
		t.Fatalf("extra add-xhttp failed: %s", errOut)
	}
	if code, _, errOut := run("extra", "add-vless-ws", "--port", "8444", "--domain", "v.example.com"); code != 0 {
		t.Fatalf("extra add-vless-ws failed: %s", errOut)
	}
	if code, _, errOut := run("extra", "add-vmess-ws", "--port", "8445", "--domain", "m.example.com"); code != 0 {
		t.Fatalf("extra add-vmess-ws failed: %s", errOut)
	}
	if code, _, errOut := run("extra", "add-dokodemo", "--port", "10053", "--target", "1.1.1.1:53", "--network", "udp"); code != 0 {
		t.Fatalf("extra add-dokodemo failed: %s", errOut)
	}
	code, out, _ = run("extra", "list")
	if code != 0 || !strings.Contains(out, "vless-xhttp") || !strings.Contains(out, "dokodemo") || !strings.Contains(out, "1.1.1.1:53 (udp)") {
		t.Fatalf("extra list mismatch: %q", out)
	}
	if code, _, errOut := run("extra", "disable-all"); code != 0 {
		t.Fatalf("extra disable-all failed: %s", errOut)
	}

	// 3. Cert self-sign --force
	if code, _, errOut := run("cert", "self-sign", "--force", "forced.example.com"); code != 0 {
		t.Fatalf("cert self-sign --force failed: %s", errOut)
	}
	code, out, _ = run("cert", "inspect")
	if code != 0 || !strings.Contains(out, "forced.example.com") {
		t.Fatalf("expected forced CN in cert inspect, got %q", out)
	}

	// 4. Client role: node add --from-uri, edit, move, status, wg keygen-server & peer-regen
	clientDir := filepath.Join(dir, "client-state")
	runC := func(args ...string) (int, string, string) {
		var o, e bytes.Buffer
		full := append([]string{"--state-dir", clientDir}, args...)
		return Run(full, strings.NewReader(""), &o, &e), o.String(), e.String()
	}
	if code, _, errOut := runC("init", "--role", "client"); code != 0 {
		t.Fatalf("client init failed: %s", errOut)
	}
	if code, _, errOut := runC("node", "add", "--id", "n1", "--from-uri", "vless://11111111-1111-4111-8111-111111111111@hk1.example.com:443?type=xhttp&security=tls&sni=hk1.example.com&path=%2Fhk#HK1"); code != 0 {
		t.Fatalf("node add --from-uri failed: %s", errOut)
	}
	if code, _, errOut := runC("node", "add", "--id", "n2", "--proto", "socks5", "--address", "198.51.100.10", "--port", "1080", "--username", "u", "--password", "p"); code != 0 {
		t.Fatalf("node add socks5 failed: %s", errOut)
	}
	if code, _, errOut := runC("node", "edit", "n1", "--name", "HK-Renamed"); code != 0 {
		t.Fatalf("node edit failed: %s", errOut)
	}
	if code, _, errOut := runC("node", "move", "n2", "up"); code != 0 {
		t.Fatalf("node move up failed: %s", errOut)
	}
	_, out, _ = runC("node", "list")
	if strings.Index(out, "[n2]") > strings.Index(out, "[n1]") {
		t.Fatalf("expected n2 moved before n1, got:\n%s", out)
	}
	if code, _, errOut := runC("wg", "peer-add", "phone"); code != 0 {
		t.Fatalf("wg peer-add failed: %s", errOut)
	}
	if code, out, errOut := runC("wg", "peer-regen", "phone"); code != 0 || !strings.Contains(out, "[Interface]") {
		t.Fatalf("wg peer-regen failed: code=%d out=%q err=%s", code, out, errOut)
	}
	if code, _, errOut := runC("wg", "keygen-server"); code != 0 {
		t.Fatalf("wg keygen-server failed: %s", errOut)
	}
	code, stOut, _ := runC("status")
	if code != 0 || !strings.Contains(stOut, "Services:") || !strings.Contains(stOut, "Certificate:") || !strings.Contains(stOut, "Sysctl:") || !strings.Contains(stOut, "Flowtable:") {
		t.Fatalf("expected Services, Certificate, Sysctl and Flowtable summary in dex status, got:\n%s", stOut)
	}

	// 5. dex extra del rejects ambiguous shared port and deletes by exact tag only
	ambDir := filepath.Join(dir, "extra-amb-state")
	runA := func(args ...string) (int, string, string) {
		var o, e bytes.Buffer
		full := append([]string{"--state-dir", ambDir}, args...)
		return Run(full, strings.NewReader(""), &o, &e), o.String(), e.String()
	}
	if code, _, errOut := runA("init", "--role", "server", "--domain", "main.example.com"); code != 0 {
		t.Fatalf("server init failed: %s", errOut)
	}
	if code, _, errOut := runA("extra", "add-xhttp", "--tag", "vn-a", "--port", "443", "--domain", "a.example.com", "--via-nginx"); code != 0 {
		t.Fatalf("extra add-xhttp vn-a failed: %s", errOut)
	}
	if code, _, errOut := runA("extra", "add-vless-ws", "--tag", "vn-b", "--port", "443", "--domain", "b.example.com", "--via-nginx"); code != 0 {
		t.Fatalf("extra add-vless-ws vn-b failed: %s", errOut)
	}
	if code, _, errOut := runA("extra", "del", "443"); code == 0 || !strings.Contains(errOut, "vn-a") || !strings.Contains(errOut, "vn-b") {
		t.Fatalf("expected ambiguous port 443 delete rejected listing vn-a and vn-b, got code=%d err=%q", code, errOut)
	}
	if code, _, errOut := runA("extra", "del", "vn-a"); code != 0 {
		t.Fatalf("expected exact tag delete vn-a to succeed, got code=%d err=%q", code, errOut)
	}
	if code, listOut, _ := runA("extra", "list"); code != 0 || strings.Contains(listOut, "vn-a") || !strings.Contains(listOut, "vn-b") {
		t.Fatalf("expected only vn-b remaining after deleting vn-a, got:\n%s", listOut)
	}
}

func TestHTTPSRedirectHandler(t *testing.T) {
	cases := []struct {
		name      string
		httpsPort string
		host      string
		target    string
		wantLoc   string
	}{
		{
			name:      "default 443 omits port",
			httpsPort: "443",
			host:      "10.0.0.230",
			target:    "/",
			wantLoc:   "https://10.0.0.230/",
		},
		{
			name:      "empty port omits port and strips :80",
			httpsPort: "",
			host:      "gw.example.com:80",
			target:    "/api/v1/status?a=1&b=2",
			wantLoc:   "https://gw.example.com/api/v1/status?a=1&b=2",
		},
		{
			name:      "custom 8443 preserves port and path+query",
			httpsPort: "8443",
			host:      "10.0.0.230:80",
			target:    "/nodes?tab=1",
			wantLoc:   "https://10.0.0.230:8443/nodes?tab=1",
		},
		{
			name:      "ipv6 host with 443",
			httpsPort: "443",
			host:      "[fd00::1]:80",
			target:    "/check?x=1",
			wantLoc:   "https://[fd00::1]/check?x=1",
		},
		{
			name:      "ipv6 host with 8443",
			httpsPort: "8443",
			host:      "[fd00::1]:80",
			target:    "/check?x=1",
			wantLoc:   "https://[fd00::1]:8443/check?x=1",
		},
		{
			name:      "prevent //evil.com open redirect",
			httpsPort: "443",
			host:      "10.0.0.230",
			target:    "//evil.com/phish?x=1",
			wantLoc:   "https://10.0.0.230/evil.com/phish?x=1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHTTPSRedirectHandler(tc.httpsPort)
			req := httptest.NewRequest(http.MethodGet, "http://placeholder"+tc.target, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusMovedPermanently {
				t.Fatalf("status = %d, want 301", rec.Code)
			}
			loc := rec.Header().Get("Location")
			if loc != tc.wantLoc {
				t.Fatalf("Location = %q, want %q", loc, tc.wantLoc)
			}
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("parse Location %q: %v", loc, err)
			}
			if u.Scheme != "https" || strings.HasPrefix(u.Path, "//") {
				t.Fatalf("unsafe redirect target %q", loc)
			}
		})
	}
}

func TestCmdCertSyncsStateAndReconcilesExternalPaths(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	stateDir := filepath.Join(root, "etc", "dex")
	store := state.NewStore(stateDir)

	extCert := filepath.Join(dir, "ext.cer")
	extKey := filepath.Join(dir, "ext.key")
	if err := cert.EnsureSelfSigned(extCert, extKey, "srv.example.com"); err != nil {
		t.Fatal(err)
	}

	s := state.NewDefaultState(state.RoleServer)
	s.Server.Domain = "srv.example.com"
	s.Server.TLSMode = "nginx"
	s.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	s.Cert.Mode = "imported"
	s.Cert.CertFile = extCert
	s.Cert.KeyFile = extKey
	if err := store.Save(s); err != nil {
		t.Fatal(err)
	}

	exec := &fakeOpsExec{
		activeSvcs: map[string]bool{"nginx": true, "dex-xray": true, "dex-doh": true, "dex-daemon": true},
	}
	opts := reconcile.ApplyOptions{RootPrefix: root}
	var out, errBuf bytes.Buffer

	// 1. self-sign --force clears external paths, sets Mode="self_signed", and reconciles nginx config back to DefaultCert()
	if code := cmdCertWithOpts(store, exec, opts, []string{"self-sign", "--force", "srv.example.com"}, &out, &errBuf); code != 0 {
		t.Fatalf("cmdCert self-sign failed: code=%d err=%q", code, errBuf.String())
	}
	stAfterSelf, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if stAfterSelf.Cert.Mode != "self_signed" || stAfterSelf.Cert.CertFile != "" || stAfterSelf.Cert.KeyFile != "" {
		t.Fatalf("unexpected cert state after self-sign: %+v", stAfterSelf.Cert)
	}
	nginxConf, err := os.ReadFile(filepath.Join(root, "etc", "nginx", "conf.d", "dex-server.conf"))
	if err != nil || !strings.Contains(string(nginxConf), store.DefaultCert()) {
		t.Fatalf("expected nginx config reconciled to default cert path %q, err=%v", store.DefaultCert(), err)
	}

	// 2. import updates Mode="imported", CertFile=DefaultCert, KeyFile=DefaultKey, and reconciles when previous paths were external
	_, _ = store.Update(state.RoleServer, func(cur *state.State) error {
		cur.Cert.CertFile = extCert
		cur.Cert.KeyFile = extKey
		return nil
	})
	out.Reset()
	errBuf.Reset()
	if code := cmdCertWithOpts(store, exec, opts, []string{"import", extCert, extKey, "--allow-self-signed"}, &out, &errBuf); code != 0 {
		t.Fatalf("cmdCert import failed: code=%d err=%q", code, errBuf.String())
	}
	stAfterImp, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if stAfterImp.Cert.Mode != "imported" || stAfterImp.Cert.CertFile != store.DefaultCert() || stAfterImp.Cert.KeyFile != store.DefaultKey() {
		t.Fatalf("unexpected cert state after import: %+v", stAfterImp.Cert)
	}
}

func TestHardeningCLIInitForceDLModeNodeDelMenuPortRelayAndServices(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	exec := &fakeOpsExec{}
	run := func(args ...string) (int, string, string) {
		var out, errBuf bytes.Buffer
		full := append([]string{"--state-dir", stateDir}, args...)
		code := RunWithExecutor(full, exec, strings.NewReader(""), &out, &errBuf)
		return code, out.String(), errBuf.String()
	}

	// 1. dex init refuses overwrite without --force, succeeds with --force
	if code, _, errOut := run("init", "--role", "client"); code != 0 {
		t.Fatalf("initial init failed: %s", errOut)
	}
	if code, _, errOut := run("init", "--role", "server", "--domain", "x.example.com"); code == 0 || !strings.Contains(errOut, "--force") {
		t.Fatalf("expected init without --force rejected with --force hint, got code=%d err=%q", code, errOut)
	}
	if code, _, errOut := run("init", "--force", "--role", "client"); code != 0 {
		t.Fatalf("init --force failed: %s", errOut)
	}

	// 2. DownloadVerifiedFile sets 0644 when !requireELF
	payload := []byte("geoip-dat-content")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	dlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer dlSrv.Close()
	dlDst := filepath.Join(dir, "rules", "geoip.dat")
	if err := DownloadVerifiedFile(context.Background(), dlSrv.Client(), dlSrv.URL+"/geoip.dat", hexSum, dlDst, false); err != nil {
		t.Fatalf("DownloadVerifiedFile failed: %v", err)
	}
	info, err := os.Stat(dlDst)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("expected 0644 perm on non-ELF download, got %v err=%v", info.Mode().Perm(), err)
	}

	// 3. dex node del prunes all dangling references so Validate() remains valid
	store := state.NewStore(stateDir)
	_, err = store.Update(state.RoleClient, func(cur *state.State) error {
		cur.Client.Nodes = []state.OutboundNode{
			{ID: "n1", Name: "N1", Protocol: "vless-xhttp", Address: "1.1.1.1", Port: 443, UUID: "11111111-1111-4111-8111-111111111111"},
			{ID: "n2", Name: "N2", Protocol: "vless-xhttp", Address: "2.2.2.2", Port: 443, UUID: "22222222-2222-4222-8222-222222222222"},
		}
		cur.Client.ActiveNodeID = "n1"
		cur.Client.Routing.ServiceMap = map[string]string{"openai": "n1", "telegram": "n2"}
		cur.Client.Routing.AppleNodeID = "n1"
		cur.Client.Routing.Divert = state.DivertConfig{Enabled: true, NodeID: "n1"}
		cur.Client.Routing.Custom = state.CustomRouteConfig{Enabled: true, NodeID: "n1"}
		cur.Client.FWD1 = state.FWD1Config{Enabled: true, Port: 9801, UUIDs: []string{"33333333-3333-4333-8333-333333333333"}, UpstreamNodeID: "n1"}
		return nil
	})
	if err != nil {
		t.Fatalf("seed client refs: %v", err)
	}
	if code, _, errOut := run("node", "del", "n1"); code != 0 {
		t.Fatalf("dex node del n1 failed: %s", errOut)
	}
	stAfterDel, _ := store.Load()
	if stAfterDel.Client.ActiveNodeID != "n2" || len(stAfterDel.Client.Routing.ServiceMap) != 1 ||
		stAfterDel.Client.Routing.AppleNodeID != "" || stAfterDel.Client.Routing.Divert.NodeID != "" ||
		stAfterDel.Client.Routing.Custom.NodeID != "" || stAfterDel.Client.FWD1.UpstreamNodeID != "" {
		t.Fatalf("expected all n1 references pruned after del, got %+v", stAfterDel.Client)
	}

	// 4. dex relay add on same port generates distinct IDs
	if code, _, errOut := run("relay", "add", "--listen", "10001", "--target-host", "1.1.1.1", "--target-port", "443", "--proto", "tcp"); code != 0 {
		t.Fatalf("relay add tcp failed: %s", errOut)
	}
	if code, out, errOut := run("relay", "add", "--listen", "10001", "--target-host", "1.1.1.1", "--target-port", "443", "--proto", "udp"); code != 0 || !strings.Contains(out, "fwd-udp-10001") {
		t.Fatalf("relay add udp failed or missing distinct ID: code=%d out=%q err=%s", code, out, errOut)
	}

	// 5. menu case "8" preserves loopback host on server role
	srvDir := filepath.Join(dir, "srv-state")
	srvStore := state.NewStore(srvDir)
	srvSt := state.NewDefaultState(state.RoleServer)
	srvSt.Server.Domain = "srv.example.com"
	srvSt.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	_ = srvStore.Save(srvSt)
	var mOut, mErr bytes.Buffer
	runInteractiveMenu(srvStore, &fakeOpsExec{}, strings.NewReader("8\n9443\nq\n"), &mOut, &mErr)
	srvReloaded, _ := srvStore.Load()
	if srvReloaded.Auth.ListenAddr != "127.0.0.1:9443" {
		t.Fatalf("expected server ListenAddr to preserve 127.0.0.1 host, got %q", srvReloaded.Auth.ListenAddr)
	}

	// 6. serviceNamesForState accuracy across roles
	relNFT := state.NewDefaultState(state.RoleRelay)
	relNFT.Relay.Forwards = []state.ForwardRule{{ID: "f1", ListenPort: 10001, TargetHost: "1.1.1.1", TargetPort: 443, Proto: "tcp", Engine: "nft"}}
	if got := serviceNamesForState(relNFT, "systemd"); !reflect.DeepEqual(got, []string{"dex-nft"}) {
		t.Fatalf("expected relay nft services=[dex-nft], got %v", got)
	}
	relHap := state.NewDefaultState(state.RoleRelay)
	relHap.Relay.Forwards = []state.ForwardRule{{ID: "f2", ListenPort: 10002, TargetHost: "1.1.1.1", TargetPort: 443, Proto: "tcp", Engine: "haproxy"}}
	if got := serviceNamesForState(relHap, "systemd"); !reflect.DeepEqual(got, []string{"haproxy"}) {
		t.Fatalf("expected relay haproxy services=[haproxy], got %v", got)
	}
	land := state.NewDefaultState(state.RoleLanding)
	if got := serviceNamesForState(land, "systemd"); !reflect.DeepEqual(got, []string{"dex-xray"}) {
		t.Fatalf("expected landing services=[dex-xray], got %v", got)
	}

	// 7. dex cert inspect uses resolveActiveCertPaths (reads external imported cert when configured)
	extDir := filepath.Join(dir, "ext-cert-inspect")
	extStore := state.NewStore(filepath.Join(extDir, "etc", "dex"))
	extCert := filepath.Join(dir, "ext-custom.cer")
	extKey := filepath.Join(dir, "ext-custom.key")
	if err := cert.EnsureSelfSigned(extCert, extKey, "ext-inspect.example.com"); err != nil {
		t.Fatal(err)
	}
	extSt := state.NewDefaultState(state.RoleServer)
	extSt.Server.Domain = "ext-inspect.example.com"
	extSt.Server.UUIDs = []string{"11111111-1111-4111-8111-111111111111"}
	extSt.Cert = state.CertConfig{Mode: "imported", CertFile: extCert, KeyFile: extKey}
	_ = extStore.Save(extSt)
	var ciOut, ciErr bytes.Buffer
	if code := cmdCertWithOpts(extStore, nil, reconcile.ApplyOptions{}, []string{"inspect"}, &ciOut, &ciErr); code != 0 || !strings.Contains(ciOut.String(), "ext-inspect.example.com") {
		t.Fatalf("expected cert inspect to read active external cert, code=%d out=%q err=%q", code, ciOut.String(), ciErr.String())
	}

	// 8. dex init --role landing --ipv6 enables System.EnableIPv6
	v6Dir := filepath.Join(dir, "v6-init")
	var v6Out, v6Err bytes.Buffer
	if code := RunWithExecutor([]string{"--state-dir", v6Dir, "init", "--role", "landing", "--domain", "v6.example.com", "--ipv6"}, &fakeOpsExec{}, strings.NewReader(""), &v6Out, &v6Err); code != 0 {
		t.Fatalf("dex init --ipv6 failed: code=%d err=%q", code, v6Err.String())
	}
	v6St, err := state.NewStore(v6Dir).Load()
	if err != nil || !v6St.System.EnableIPv6 {
		t.Fatalf("expected System.EnableIPv6=true after init --ipv6, err=%v st=%+v", err, v6St)
	}

	// 9. Role-based DoH CLI: client dns show/set works; landing/relay reject --enable-doh=true
	if code := RunWithExecutor([]string{"--state-dir", v6Dir, "server", "set", "--enable-doh=true"}, &fakeOpsExec{}, strings.NewReader(""), &v6Out, &v6Err); code == 0 {
		t.Fatalf("expected landing role to reject server set --enable-doh=true")
	}

	cliDoHDir := filepath.Join(dir, "cli-doh")
	var cdOut, cdErr bytes.Buffer
	if code := RunWithExecutor([]string{"--state-dir", cliDoHDir, "init", "--role", "client"}, &fakeOpsExec{}, strings.NewReader(""), &cdOut, &cdErr); code != 0 {
		t.Fatalf("client init failed: code=%d err=%q", code, cdErr.String())
	}
	cdOut.Reset()
	if code := RunWithExecutor([]string{"--state-dir", cliDoHDir, "dns", "show"}, &fakeOpsExec{}, strings.NewReader(""), &cdOut, &cdErr); code != 0 || !strings.Contains(cdOut.String(), "EnableDoHServer:  true") {
		t.Fatalf("expected dns show EnableDoHServer=true, code=%d out=%q err=%q", code, cdOut.String(), cdErr.String())
	}
	if code := RunWithExecutor([]string{"--state-dir", cliDoHDir, "dns", "set", "--doh-path", "/dq-myhome"}, &fakeOpsExec{}, strings.NewReader(""), &cdOut, &cdErr); code != 0 {
		t.Fatalf("dns set --doh-path failed: code=%d err=%q", code, cdErr.String())
	}
	cliDoHSt, _ := state.NewStore(cliDoHDir).Load()
	if cliDoHSt.Client.DNS.DoHServerPath != "/dq-myhome" {
		t.Fatalf("expected DoHServerPath=/dq-myhome, got %q", cliDoHSt.Client.DNS.DoHServerPath)
	}
	if code := RunWithExecutor([]string{"--state-dir", cliDoHDir, "dns", "set", "--regen-doh-path"}, &fakeOpsExec{}, strings.NewReader(""), &cdOut, &cdErr); code != 0 {
		t.Fatalf("dns set --regen-doh-path failed: code=%d err=%q", code, cdErr.String())
	}
	cliDoHSt2, _ := state.NewStore(cliDoHDir).Load()
	if cliDoHSt2.Client.DNS.DoHServerPath == "/dq-myhome" || !strings.HasPrefix(cliDoHSt2.Client.DNS.DoHServerPath, "/dq-") {
		t.Fatalf("expected regenerated /dq-xxxxxx path, got %q", cliDoHSt2.Client.DNS.DoHServerPath)
	}

	// 10. Client DoH shorthand normalization in init/dns set and menuInitWizard mandatory DoH prompt
	if code := RunWithExecutor([]string{"--state-dir", cliDoHDir, "dns", "set", "--doh", "lax.example.com:2096, https://dec.example.com:2087/dq"}, &fakeOpsExec{}, strings.NewReader(""), &cdOut, &cdErr); code != 0 {
		t.Fatalf("dns set --doh failed: code=%d err=%q", code, cdErr.String())
	}
	cliDoHSt3, _ := state.NewStore(cliDoHDir).Load()
	wantDoH := []string{"https://lax.example.com:2096/dq", "https://dec.example.com:2087/dq"}
	if !reflect.DeepEqual(cliDoHSt3.Client.DNS.DoHServers, wantDoH) {
		t.Fatalf("expected normalized DoHServers=%v, got %v", wantDoH, cliDoHSt3.Client.DNS.DoHServers)
	}

	wizStore := state.NewStore(filepath.Join(dir, "wiz-client-doh"))
	var wOut, wErr bytes.Buffer
	sampleSrvURI := "vless://11111111-1111-4111-8111-111111111111@lax.example.com:2096?encryption=none&security=tls&sni=lax.example.com&type=xhttp&path=%2Fabc12345&mode=packet-up#LAX"
	// Menu: 1 (init wizard) -> 1 (Client) -> "" (empty node rejected) -> sampleSrvURI (auto-extracts https://lax.example.com:2096/dq without second prompt!) -> q (exit)
	if code := runInteractiveMenu(wizStore, &fakeOpsExec{}, strings.NewReader("1\n1\n\n"+sampleSrvURI+"\nq\n"), &wOut, &wErr); code != 0 {
		t.Fatalf("wizard menu failed: code=%d err=%q", code, wErr.String())
	}
	wizSt, err := wizStore.Load()
	if err != nil || wizSt.Client.ActiveNode() == nil || wizSt.Client.ActiveNode().Address != "lax.example.com" || !reflect.DeepEqual(wizSt.Client.DNS.DoHServers, []string{"https://lax.example.com:2096/dq"}) {
		t.Fatalf("expected wizard client node+DoHServers=[https://lax.example.com:2096/dq], err=%v got=%+v out=%q", err, wizSt, wOut.String())
	}

	// 11. Role shorthand flags (-c, -s, -r, -l) + Server->Client bootstrap handoff
	scDirS := filepath.Join(dir, "short-s")
	var sInitOut bytes.Buffer
	if code := RunWithExecutor([]string{"--state-dir", scDirS, "-s", "srv.example.com", "--port", "2096"}, &fakeOpsExec{}, strings.NewReader(""), &sInitOut, &wErr); code != 0 {
		t.Fatalf("dex -s shorthand failed: code=%d err=%q", code, wErr.String())
	}
	stS, err := state.NewStore(scDirS).Load()
	if err != nil || stS.Role != state.RoleServer || stS.Server.Domain != "srv.example.com" || stS.Server.ListenPort != 2096 {
		t.Fatalf("unexpected dex -s state: err=%v st=%+v", err, stS)
	}
	sOutStr := sInitOut.String()
	if !strings.Contains(sOutStr, "Main Node URI:") || !strings.Contains(sOutStr, "https://srv.example.com:2096/dq") || !strings.Contains(sOutStr, "wget -qO- dex.stuinx.net/client | sh") || !strings.Contains(sOutStr, "Client Quick:   dex 'vless://") || strings.Contains(sOutStr, "sh -s --") {
		t.Fatalf("expected bench.sh-style Client Install and 'dex vless://' Client Quick without 'sh -s --', got:\n%s", sOutStr)
	}
	if !shouldAutoApplyInit(reconcile.OSExecutor{}, true, false, false, false) {
		t.Fatalf("expected top-level -c/-s/-r/-l to auto-apply on OSExecutor by default")
	}
	if shouldAutoApplyInit(reconcile.OSExecutor{}, true, false, false, true) || shouldAutoApplyInit(reconcile.OSExecutor{}, true, true, false, false) {
		t.Fatalf("expected --no-apply or --apply=false to skip auto-apply")
	}
	if shouldAutoApplyInit(reconcile.OSExecutor{}, false, false, false, false) {
		t.Fatalf("expected explicit 'dex init' without --apply to stay opt-in")
	}

	// Feed Server's generated Main Node URI directly into 'dex -c' (auto-deriving DoH) and with explicit --doh
	srvMainURI := render.BuildServerMainURI(stS)
	scDirC := filepath.Join(dir, "short-c")
	if code := RunWithExecutor([]string{"--state-dir", scDirC, "-c", "--node", srvMainURI, "--doh", "https://srv.example.com:2096/dq"}, &fakeOpsExec{}, strings.NewReader(""), &wOut, &wErr); code != 0 {
		t.Fatalf("dex -c --node --doh failed: code=%d err=%q", code, wErr.String())
	}
	if stC, err := state.NewStore(scDirC).Load(); err != nil || stC.Role != state.RoleClient || stC.Client.ActiveNode() == nil || stC.Client.ActiveNode().UUID != stS.Server.UUIDs[0] || !reflect.DeepEqual(stC.Client.DNS.DoHServers, []string{"https://srv.example.com:2096/dq"}) {
		t.Fatalf("unexpected dex -c state: err=%v st=%+v", err, stC)
	}

	scDirCAuto := filepath.Join(dir, "short-c-auto-doh")
	if code := RunWithExecutor([]string{"--state-dir", scDirCAuto, srvMainURI}, &fakeOpsExec{}, strings.NewReader(""), &wOut, &wErr); code != 0 {
		t.Fatalf("dex bare URI failed: code=%d err=%q", code, wErr.String())
	}
	if stCA, err := state.NewStore(scDirCAuto).Load(); err != nil || stCA.Client.ActiveNode() == nil || !reflect.DeepEqual(stCA.Client.DNS.DoHServers, []string{"https://srv.example.com:2096/dq"}) {
		t.Fatalf("expected auto-derived DoH from bare 'dex vless://...' URI, err=%v st=%+v", err, stCA)
	}

	// Pasting vless:// directly at uninitialized 'dex' menu ('wget -qO- dex.stuinx.net | sh') initializes Client in 1 step
	uninitPasteDir := filepath.Join(dir, "uninit-paste-uri")
	if code := runInteractiveMenu(state.NewStore(uninitPasteDir), &fakeOpsExec{}, strings.NewReader(srvMainURI+"\nq\n"), &wOut, &wErr); code != 0 {
		t.Fatalf("uninit menu direct URI paste failed: code=%d err=%q", code, wErr.String())
	}
	if stUP, err := state.NewStore(uninitPasteDir).Load(); err != nil || stUP.Role != state.RoleClient || stUP.Client.ActiveNode() == nil || !reflect.DeepEqual(stUP.Client.DNS.DoHServers, []string{"https://srv.example.com:2096/dq"}) {
		t.Fatalf("expected Client initialized from menu URI paste, err=%v st=%+v", err, stUP)
	}

	scDirL := filepath.Join(dir, "short-l")
	if code := RunWithExecutor([]string{"--state-dir", scDirL, "init", "-l", "--domain", "land.example.com"}, &fakeOpsExec{}, strings.NewReader(""), &wOut, &wErr); code != 0 {
		t.Fatalf("dex init -l shorthand failed: code=%d err=%q", code, wErr.String())
	}
	if stL, err := state.NewStore(scDirL).Load(); err != nil || stL.Role != state.RoleLanding || stL.Server.Domain != "land.example.com" {
		t.Fatalf("unexpected dex init -l state: err=%v st=%+v", err, stL)
	}

	scDirR := filepath.Join(dir, "short-r")
	if code := RunWithExecutor([]string{"--state-dir", scDirR, "-r"}, &fakeOpsExec{}, strings.NewReader("n\n"), &wOut, &wErr); code != 0 {
		t.Fatalf("dex -r interactive wizard failed: code=%d err=%q", code, wErr.String())
	}
	if stR, err := state.NewStore(scDirR).Load(); err != nil || stR.Role != state.RoleRelay {
		t.Fatalf("unexpected dex -r state: err=%v st=%+v", err, stR)
	}

	scDirWizC := filepath.Join(dir, "short-wiz-c")
	hkURI := "vless://22222222-2222-4222-8222-222222222222@hk.example.com:443?encryption=none&security=tls&sni=hk.example.com&type=xhttp&path=%2Fhk123456#HK"
	if code := RunWithExecutor([]string{"--state-dir", scDirWizC, "-c"}, &fakeOpsExec{}, strings.NewReader(hkURI+"\n"), &wOut, &wErr); code != 0 {
		t.Fatalf("dex -c interactive wizard failed: code=%d err=%q", code, wErr.String())
	}
	if stWC, err := state.NewStore(scDirWizC).Load(); err != nil || stWC.Client.ActiveNode() == nil || !reflect.DeepEqual(stWC.Client.DNS.DoHServers, []string{"https://hk.example.com/dq"}) {
		t.Fatalf("unexpected dex -c wizard state: err=%v st=%+v", err, stWC)
	}

	// Reality URI in wizard has no TLS /dq -> prompts explicitly for self-hosted DoH
	scDirWizR := filepath.Join(dir, "short-wiz-reality")
	realURI := "vless://33333333-3333-4333-8333-333333333333@203.0.113.9:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=abcd1234&sid=0102&type=tcp#REAL"
	if code := RunWithExecutor([]string{"--state-dir", scDirWizR, "-c"}, &fakeOpsExec{}, strings.NewReader(realURI+"\nsrv.example.com:2096\n"), &wOut, &wErr); code != 0 {
		t.Fatalf("dex -c reality wizard failed: code=%d err=%q", code, wErr.String())
	}
	if stWR, err := state.NewStore(scDirWizR).Load(); err != nil || !reflect.DeepEqual(stWR.Client.DNS.DoHServers, []string{"https://srv.example.com:2096/dq"}) {
		t.Fatalf("unexpected dex -c reality wizard state: err=%v st=%+v", err, stWR)
	}

	var conflictErr bytes.Buffer
	if code := RunWithExecutor([]string{"--state-dir", filepath.Join(dir, "conflict"), "init", "-s", "-c"}, &fakeOpsExec{}, strings.NewReader(""), &wOut, &conflictErr); code == 0 {
		t.Fatalf("expected conflicting role flags to fail")
	}
}
