package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
