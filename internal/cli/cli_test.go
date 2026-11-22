package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stuinxo/de_GWD/v3/internal/cert"
	"github.com/stuinxo/de_GWD/v3/internal/reconcile"
	"github.com/stuinxo/de_GWD/v3/internal/state"
)

func TestCLISmokeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")

	run := func(args ...string) (int, string, string) {
		var out, errBuf bytes.Buffer
		full := append([]string{"--state-dir", stateDir}, args...)
		code := Run(full, strings.NewReader(""), &out, &errBuf)
		return code, out.String(), errBuf.String()
	}

	// 1. version
	code, out, errOut := run("version")
	if code != 0 || !strings.Contains(out, "v3.") {
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
	code, out, errOut = run("init", "--role", "client", "--doh", "https://vtw.example.com/dq")
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
	code, out, errOut = run("init", "--role", "server", "--domain", "srv.example.com")
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

	run := func(args ...string) (int, string, string) {
		var out, errBuf bytes.Buffer
		full := append([]string{"--state-dir", stateDir}, args...)
		code := Run(full, strings.NewReader(""), &out, &errBuf)
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
	if code, _, errOut := runC("node", "add", "--id", "n2", "--proto", "socks5", "--address", "127.0.0.1", "--port", "1080", "--username", "u", "--password", "p"); code != 0 {
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
	if code != 0 || !strings.Contains(stOut, "Services:") || !strings.Contains(stOut, "Certificate:") {
		t.Fatalf("expected Services and Certificate summary in dex status, got:\n%s", stOut)
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
