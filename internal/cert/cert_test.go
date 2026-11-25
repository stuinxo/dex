package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func genTestCert(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPEM, keyPEM []byte, cert *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
	}
	if ca == nil {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		ca = tmpl
		caKey = priv
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(priv)
	cPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return cPEM, kPEM, parsed, priv
}

func TestBuildWildcardSANs(t *testing.T) {
	cases := []struct {
		domain   string
		wantMain string
		wantSANs []string
	}{
		{"example.com", "example.com", []string{"example.com", "*.example.com"}},
		{"hk.example.com", "example.com", []string{"example.com", "*.example.com", "*.hk.example.com"}},
		{"example.co.uk", "example.co.uk", []string{"example.co.uk", "*.example.co.uk"}},
		{"sub.example.co.uk", "example.co.uk", []string{"example.co.uk", "*.example.co.uk", "*.sub.example.co.uk"}},
		{"sub.example.eu.org", "example.eu.org", []string{"example.eu.org", "*.example.eu.org", "*.sub.example.eu.org"}},
		{"node.example.com.cn", "example.com.cn", []string{"example.com.cn", "*.example.com.cn", "*.node.example.com.cn"}},
	}
	for _, tc := range cases {
		mainDom, sans, err := BuildWildcardSANs(tc.domain)
		if err != nil {
			t.Fatalf("BuildWildcardSANs(%q): %v", tc.domain, err)
		}
		if mainDom != tc.wantMain || !reflect.DeepEqual(sans, tc.wantSANs) {
			t.Errorf("BuildWildcardSANs(%q) = (%q, %v), want (%q, %v)", tc.domain, mainDom, sans, tc.wantMain, tc.wantSANs)
		}
	}
	if _, _, err := BuildWildcardSANs("1.2.3.4"); err == nil {
		t.Fatalf("expected IP address to be rejected")
	}
}

func TestInspectPairAndCoversDomain(t *testing.T) {
	now := time.Now()
	caPEM, _, caCert, caKey := genTestCert(t, "Test CA", nil, now.Add(-time.Hour), now.Add(365*24*time.Hour), nil, nil)
	leafPEM, leafKey, _, _ := genTestCert(t, "example.com", []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(5*24*time.Hour), caCert, caKey)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	report, err := inspectPairAt(append(leafPEM, caPEM...), leafKey, now, roots)
	if err != nil {
		t.Fatalf("inspectPairAt valid chain: %v", err)
	}
	if report.SelfSigned || !report.ChainValid || !report.ExpiringSoon {
		t.Fatalf("unexpected report flags: %+v", report)
	}
	if !CoversDomain(report, "example.com") || !CoversDomain(report, "a.example.com") || CoversDomain(report, "a.b.example.com") {
		t.Fatalf("wildcard matching mismatch for %v", report.SANs)
	}

	// Mismatched key
	_, otherKey, _, _ := genTestCert(t, "other", nil, now.Add(-time.Hour), now.Add(time.Hour), nil, nil)
	if _, err := InspectPair(leafPEM, otherKey); err == nil {
		t.Fatalf("expected mismatched key error")
	}

	// Expired cert
	expPEM, expKey, _, _ := genTestCert(t, "expired.com", []string{"expired.com"}, now.Add(-48*time.Hour), now.Add(-time.Hour), nil, nil)
	if _, err := InspectPair(expPEM, expKey); err == nil {
		t.Fatalf("expected expired certificate error")
	}
}

func TestImportPairAndSelfSigned(t *testing.T) {
	dir := t.TempDir()
	cer := filepath.Join(dir, "dex.cer")
	key := filepath.Join(dir, "dex.key")
	if err := EnsureSelfSigned(cer, key, "router.local"); err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}
	info, err := os.Stat(key)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("expected key perm 0600, got %v (err=%v)", info.Mode().Perm(), err)
	}

	// Reject self-signed when allowSelfSigned=false
	dstCer := filepath.Join(dir, "dst.cer")
	dstKey := filepath.Join(dir, "dst.key")
	if _, _, err := ImportPair(cer, key, dstCer, dstKey, false, []string{"router.local"}); err == nil {
		t.Fatalf("expected ImportPair to reject self-signed cert")
	}

	rep, changed, err := ImportPair(cer, key, dstCer, dstKey, true, []string{"router.local"})
	if err != nil || !changed || !rep.SelfSigned {
		t.Fatalf("ImportPair first import = (%+v, %v, %v)", rep, changed, err)
	}
	_, changed2, err := ImportPair(cer, key, dstCer, dstKey, true, []string{"router.local"})
	if err != nil || changed2 {
		t.Fatalf("ImportPair second identical import should return changed=false, got (%v, %v)", changed2, err)
	}
}

type fakeACMERunner struct {
	t         *testing.T
	calls     [][]string
	envs      [][]string
	mainDom   string
	certBytes []byte
	keyBytes  []byte
}

func (f *fakeACMERunner) Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	f.envs = append(f.envs, append([]string(nil), env...))
	for i := 0; i < len(args); i++ {
		if args[i] == "--issue" {
			var home string
			for j := 0; j+1 < len(args); j++ {
				if args[j] == "--home" {
					home = args[j+1]
				}
			}
			eccDir := filepath.Join(home, f.mainDom+"_ecc")
			_ = os.MkdirAll(eccDir, 0o755)
			_ = os.WriteFile(filepath.Join(eccDir, "fullchain.cer"), f.certBytes, 0o644)
			_ = os.WriteFile(filepath.Join(eccDir, f.mainDom+".key"), f.keyBytes, 0o600)
			_ = os.WriteFile(filepath.Join(home, "account.conf"), []byte("SAVED_CF_Token='secret-tok'\nSAVED_CF_Key='legacy'\n"), 0o600)
		}
	}
	return []byte("ok"), nil
}

func TestIssueCloudflareACMEAndTokenScrub(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	cPEM, kPEM, _, _ := genTestCert(t, "example.com", []string{"example.com", "*.example.com", "*.sub.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), nil, nil)

	runner := &fakeACMERunner{
		t:         t,
		mainDom:   "example.com",
		certBytes: cPEM,
		keyBytes:  kPEM,
	}
	acmeHome := filepath.Join(dir, "acme")
	_ = os.MkdirAll(acmeHome, 0o755)

	rep, err := IssueCloudflareACME(context.Background(), runner, ACMEConfig{
		Domain:    "sub.example.com",
		CFToken:   "tok-123",
		AutoRenew: false,
		AcmeBin:   filepath.Join(acmeHome, "acme.sh"),
		AcmeHome:  acmeHome,
		CertPath:  filepath.Join(dir, "dex.cer"),
		KeyPath:   filepath.Join(dir, "dex.key"),
	})
	if err != nil {
		t.Fatalf("IssueCloudflareACME: %v", err)
	}
	if !CoversDomain(rep, "other.sub.example.com") {
		t.Fatalf("expected issued cert to cover *.sub.example.com")
	}
	accData, err := os.ReadFile(filepath.Join(acmeHome, "account.conf"))
	if err != nil {
		t.Fatalf("read account.conf: %v", err)
	}
	if strings.Contains(string(accData), "CF_Token") || strings.Contains(string(accData), "CF_Key") {
		t.Fatalf("expected CF credentials scrubbed when AutoRenew=false, got %q", string(accData))
	}

	// Verify scrubLegacyKeys removes stale CF_Token / CF_Key / CF_Email while preserving unrelated keys
	legacyConf := filepath.Join(dir, "legacy-account.conf")
	_ = os.WriteFile(legacyConf, []byte("SAVED_CF_Token='stale-tok'\nSAVED_CF_Key='stale-key'\nSAVED_CF_Email='old@example.com'\nOTHER_KEY='keep'\n"), 0o600)
	scrubLegacyKeys(legacyConf)
	scrubbed, err := os.ReadFile(legacyConf)
	if err != nil {
		t.Fatalf("read legacyConf: %v", err)
	}
	if strings.Contains(string(scrubbed), "CF_Token") || strings.Contains(string(scrubbed), "CF_Key") || strings.Contains(string(scrubbed), "CF_Email") || !strings.Contains(string(scrubbed), "OTHER_KEY='keep'") {
		t.Fatalf("expected stale CF_* scrubbed and OTHER_KEY preserved, got %q", string(scrubbed))
	}

	// Verify Global API Key (CFEmail != "") passes CF_Key + CF_Email and scrubs them when AutoRenew=false
	runnerEmail := &fakeACMERunner{
		t:         t,
		mainDom:   "example.com",
		certBytes: cPEM,
		keyBytes:  kPEM,
	}
	if _, err := IssueCloudflareACME(context.Background(), runnerEmail, ACMEConfig{
		Domain:    "sub.example.com",
		CFToken:   "global-key",
		CFEmail:   "owner@example.com",
		AutoRenew: false,
		AcmeBin:   filepath.Join(acmeHome, "acme.sh"),
		AcmeHome:  acmeHome,
		CertPath:  filepath.Join(dir, "dex2.cer"),
		KeyPath:   filepath.Join(dir, "dex2.key"),
	}); err != nil {
		t.Fatalf("IssueCloudflareACME with CFEmail: %v", err)
	}
	if len(runnerEmail.envs) == 0 || !strings.Contains(strings.Join(runnerEmail.envs[0], ","), "CF_Key=global-key") || !strings.Contains(strings.Join(runnerEmail.envs[0], ","), "CF_Email=owner@example.com") {
		t.Fatalf("expected CF_Key and CF_Email in acme env, got %+v", runnerEmail.envs)
	}
	accData2, _ := os.ReadFile(filepath.Join(acmeHome, "account.conf"))
	if strings.Contains(string(accData2), "CF_Token") || strings.Contains(string(accData2), "CF_Key") || strings.Contains(string(accData2), "CF_Email") {
		t.Fatalf("expected CF_Token/CF_Key/CF_Email scrubbed when AutoRenew=false, got %q", string(accData2))
	}
}

func TestWave2ForceSelfSignedAndIssueHTTPACME(t *testing.T) {
	dir := t.TempDir()
	certP := filepath.Join(dir, "dex.cer")
	keyP := filepath.Join(dir, "dex.key")

	if err := EnsureSelfSigned(certP, keyP, "first.example.com"); err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}
	if err := ForceSelfSigned(certP, keyP, "second.example.com"); err != nil {
		t.Fatalf("ForceSelfSigned: %v", err)
	}
	cb, _ := os.ReadFile(certP)
	kb, _ := os.ReadFile(keyP)
	rep, err := InspectPair(cb, kb)
	if err != nil || rep.CommonName != "second.example.com" {
		t.Fatalf("expected overwritten CN second.example.com, got rep=%+v err=%v", rep, err)
	}

	now := time.Now()
	cPEM, kPEM, _, _ := genTestCert(t, "http.example.com", []string{"http.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), nil, nil)
	acmeHome := filepath.Join(dir, "acme")
	_ = os.MkdirAll(acmeHome, 0o755)
	runner := &fakeACMERunner{
		t:         t,
		mainDom:   "http.example.com",
		certBytes: cPEM,
		keyBytes:  kPEM,
	}
	hRep, err := IssueHTTPACME(context.Background(), runner, ACMEConfig{
		Domain:   "http.example.com",
		Webroot:  "/var/www/html",
		AcmeBin:  filepath.Join(acmeHome, "acme.sh"),
		AcmeHome: acmeHome,
		CertPath: filepath.Join(dir, "http.cer"),
		KeyPath:  filepath.Join(dir, "http.key"),
	})
	if err != nil || !CoversDomain(hRep, "http.example.com") {
		t.Fatalf("IssueHTTPACME webroot failed: rep=%+v err=%v", hRep, err)
	}
	joined := strings.Join(runner.calls[1], " ")
	if !strings.Contains(joined, "--webroot /var/www/html") {
		t.Fatalf("expected --webroot in acme args, got %q", joined)
	}

	// Empty webroot uses --standalone
	runner2 := &fakeACMERunner{t: t, mainDom: "http.example.com", certBytes: cPEM, keyBytes: kPEM}
	if _, err := IssueHTTPACME(context.Background(), runner2, ACMEConfig{
		Domain:   "http.example.com",
		AcmeBin:  filepath.Join(acmeHome, "acme.sh"),
		AcmeHome: acmeHome,
		CertPath: filepath.Join(dir, "http2.cer"),
		KeyPath:  filepath.Join(dir, "http2.key"),
	}); err != nil {
		t.Fatalf("IssueHTTPACME standalone failed: %v", err)
	}
	if !strings.Contains(strings.Join(runner2.calls[1], " "), "--standalone") {
		t.Fatalf("expected --standalone when webroot empty, got %v", runner2.calls[1])
	}

	// Reject relative or flag-like webroot to avoid argument injection
	for _, badWR := range []string{"relative/path", "-webroot", "/tmp/bad\nline"} {
		if _, err := IssueHTTPACME(context.Background(), runner2, ACMEConfig{
			Domain:   "http.example.com",
			Webroot:  badWR,
			AcmeBin:  filepath.Join(acmeHome, "acme.sh"),
			AcmeHome: acmeHome,
			CertPath: filepath.Join(dir, "http3.cer"),
			KeyPath:  filepath.Join(dir, "http3.key"),
		}); err == nil {
			t.Fatalf("expected unsafe webroot %q rejected", badWR)
		}
	}
}

type failIssueRunner struct {
	failAction string // "issue" | "install"
	acmeHome   string
	mainDom    string
	certBytes  []byte
	keyBytes   []byte
}

func (f *failIssueRunner) Run(_ context.Context, _ []string, _ string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--issue") {
		_ = os.WriteFile(filepath.Join(f.acmeHome, "account.conf"), []byte("SAVED_CF_Token='secret-token'\nOTHER='1'\n"), 0o600)
		if f.failAction == "issue" {
			return []byte("simulated acme issue error"), os.ErrInvalid
		}
		d := filepath.Join(f.acmeHome, f.mainDom+"_ecc")
		_ = os.MkdirAll(d, 0o755)
		_ = os.WriteFile(filepath.Join(d, "fullchain.cer"), f.certBytes, 0o644)
		_ = os.WriteFile(filepath.Join(d, f.mainDom+".key"), f.keyBytes, 0o600)
	}
	if strings.Contains(joined, "--install-cert") && f.failAction == "install" {
		return []byte("simulated install-cert error"), os.ErrPermission
	}
	return []byte("ok"), nil
}

func TestHardeningCertIPSANsAndACMEErrorHandling(t *testing.T) {
	dir := t.TempDir()

	// 1. Self-signed cert includes 127.0.0.1 and ::1 IP SANs; IP CN goes to IPAddresses (not DNSNames)
	cIP := filepath.Join(dir, "ip.cer")
	kIP := filepath.Join(dir, "ip.key")
	if err := EnsureSelfSigned(cIP, kIP, "10.0.0.230"); err != nil {
		t.Fatalf("EnsureSelfSigned IP CN: %v", err)
	}
	cb, _ := os.ReadFile(cIP)
	kb, _ := os.ReadFile(kIP)
	rep, err := InspectPair(cb, kb)
	if err != nil {
		t.Fatalf("InspectPair IP CN: %v", err)
	}
	for _, wantSAN := range []string{"localhost", "127.0.0.1", "::1", "10.0.0.230"} {
		if !CoversDomain(rep, wantSAN) {
			t.Fatalf("expected IP self-signed cert to cover %q, SANs=%v", wantSAN, rep.SANs)
		}
	}
	block, _ := pem.Decode(cb)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range leaf.DNSNames {
		if d == "10.0.0.230" {
			t.Fatalf("IP CN must NOT be placed in DNSNames, got %v", leaf.DNSNames)
		}
	}

	// 2. IssueCloudflareACME scrubs CF token even when --issue fails and AutoRenew=false
	acmeHome := filepath.Join(dir, "acme-fail")
	_ = os.MkdirAll(acmeHome, 0o755)
	if _, err := IssueCloudflareACME(context.Background(), &failIssueRunner{failAction: "issue", acmeHome: acmeHome}, ACMEConfig{
		Domain:    "sub.example.com",
		CFToken:   "secret-token",
		AutoRenew: false,
		AcmeBin:   filepath.Join(acmeHome, "acme.sh"),
		AcmeHome:  acmeHome,
		CertPath:  filepath.Join(dir, "out.cer"),
		KeyPath:   filepath.Join(dir, "out.key"),
	}); err == nil {
		t.Fatalf("expected IssueCloudflareACME failure when --issue fails")
	}
	accRaw, _ := os.ReadFile(filepath.Join(acmeHome, "account.conf"))
	if strings.Contains(string(accRaw), "CF_Token") || !strings.Contains(string(accRaw), "OTHER='1'") {
		t.Fatalf("expected CF_Token scrubbed on failure, got %q", string(accRaw))
	}

	// 3. stageAndInstallACMECert returns error when --install-cert fails
	now := time.Now()
	cPEM, kPEM, _, _ := genTestCert(t, "example.com", []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), nil, nil)
	if _, err := IssueCloudflareACME(context.Background(), &failIssueRunner{
		failAction: "install",
		acmeHome:   acmeHome,
		mainDom:    "example.com",
		certBytes:  cPEM,
		keyBytes:   kPEM,
	}, ACMEConfig{
		Domain:    "sub.example.com",
		CFToken:   "secret-token",
		AutoRenew: false,
		AcmeBin:   filepath.Join(acmeHome, "acme.sh"),
		AcmeHome:  acmeHome,
		CertPath:  filepath.Join(dir, "out2.cer"),
		KeyPath:   filepath.Join(dir, "out2.key"),
	}); err == nil || !strings.Contains(err.Error(), "install-cert") {
		t.Fatalf("expected install-cert error propagated, got %v", err)
	}
}

type captureHTTPACMERunner struct {
	acmeHome  string
	domain    string
	certBytes []byte
	keyBytes  []byte
	calls     [][]string
}

func (c *captureHTTPACMERunner) Run(_ context.Context, _ []string, _ string, args ...string) ([]byte, error) {
	c.calls = append(c.calls, append([]string(nil), args...))
	if strings.Contains(strings.Join(args, " "), "--issue") {
		d := filepath.Join(c.acmeHome, c.domain+"_ecc")
		_ = os.MkdirAll(d, 0o755)
		_ = os.WriteFile(filepath.Join(d, "fullchain.cer"), c.certBytes, 0o644)
		_ = os.WriteFile(filepath.Join(d, c.domain+".key"), c.keyBytes, 0o600)
	}
	return []byte("ok"), nil
}

func TestIssueHTTPACMEListenV6Flag(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	cPEM, kPEM, _, _ := genTestCert(t, "v6.example.com", []string{"v6.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), nil, nil)

	for _, listenV6 := range []bool{true, false} {
		acmeHome := filepath.Join(dir, fmt.Sprintf("acme-%v", listenV6))
		_ = os.MkdirAll(acmeHome, 0o755)
		_ = os.WriteFile(filepath.Join(acmeHome, "acme.sh"), []byte("#!/bin/sh\n"), 0o755)
		runner := &captureHTTPACMERunner{
			acmeHome:  acmeHome,
			domain:    "v6.example.com",
			certBytes: cPEM,
			keyBytes:  kPEM,
		}
		if _, err := IssueHTTPACME(context.Background(), runner, ACMEConfig{
			Domain:   "v6.example.com",
			ListenV6: listenV6,
			AcmeBin:  filepath.Join(acmeHome, "acme.sh"),
			AcmeHome: acmeHome,
			CertPath: filepath.Join(dir, fmt.Sprintf("out-%v.cer", listenV6)),
			KeyPath:  filepath.Join(dir, fmt.Sprintf("out-%v.key", listenV6)),
		}); err != nil {
			t.Fatalf("IssueHTTPACME(ListenV6=%v): %v", listenV6, err)
		}
		var issueArgs string
		for _, call := range runner.calls {
			joined := strings.Join(call, " ")
			if strings.Contains(joined, "--issue") {
				issueArgs = joined
				break
			}
		}
		if !strings.Contains(issueArgs, "--standalone") {
			t.Fatalf("expected --standalone in issue args %q", issueArgs)
		}
		hasV6 := strings.Contains(issueArgs, "--listen-v6")
		if hasV6 != listenV6 {
			t.Fatalf("ListenV6=%v: has --listen-v6 = %v (args=%q)", listenV6, hasV6, issueArgs)
		}
	}
}
