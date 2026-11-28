package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeAndVerifyChecksumAndELF(t *testing.T) {
	dir := t.TempDir()
	elfPath := filepath.Join(dir, "test.bin")
	payload := []byte("\x7fELF\x02\x01\x01\x00hello-dex")
	if err := os.WriteFile(elfPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])

	norm, err := NormalizeSHA256(strings.ToUpper(hexSum) + "  dex-linux-amd64\n")
	if err != nil || norm != hexSum {
		t.Fatalf("NormalizeSHA256 = (%q, %v), want %q", norm, err, hexSum)
	}
	if _, err := NormalizeSHA256("<html>502 Bad Gateway</html>"); err == nil {
		t.Fatalf("expected HTML error page rejected as sha256")
	}
	if err := VerifyFileSHA256(elfPath, strings.ToUpper(hexSum)); err != nil {
		t.Fatalf("VerifyFileSHA256 failed: %v", err)
	}
	if err := VerifyFileSHA256(elfPath, strings.Repeat("0", 64)); err == nil {
		t.Fatalf("expected mismatch error")
	}

	ok, err := IsELFBinary(elfPath)
	if err != nil || !ok {
		t.Fatalf("IsELFBinary(elf) = (%v, %v), want true", ok, err)
	}
	htmlPath := filepath.Join(dir, "err.html")
	_ = os.WriteFile(htmlPath, []byte("<!DOCTYPE html>502"), 0o644)
	if ok, _ := IsELFBinary(htmlPath); ok {
		t.Fatalf("IsELFBinary should reject HTML")
	}
}

func TestDownloadMirrorFallbackAndVerification(t *testing.T) {
	payload := []byte("\x7fELF\x02\x01\x01\x00mirror-ok")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])

	directSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer directSrv.Close()

	mirrorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256sum") {
			_, _ = w.Write([]byte(hexSum + "  bin\n"))
			return
		}
		_, _ = w.Write(payload)
	}))
	defer mirrorSrv.Close()

	dst := filepath.Join(t.TempDir(), "dex")
	err := DownloadWithMirrors(context.Background(), directSrv.Client(), directSrv.URL+"/release/dex", dst, []string{mirrorSrv.URL + "/"})
	if err != nil {
		t.Fatalf("DownloadWithMirrors fallback failed: %v", err)
	}
	if err := VerifyFileSHA256(dst, hexSum); err != nil {
		t.Fatalf("VerifyFileSHA256 after mirror download: %v", err)
	}
	if ok, _ := IsELFBinary(dst); !ok {
		t.Fatalf("downloaded mirror binary missing ELF magic")
	}
}

func TestDownloadTrustAnchorNeverUsesDefaultMirrors(t *testing.T) {
	t.Setenv("GH_PROXY", "")

	// 1. Direct failure must NOT fall back to defaultMirrors (returns error immediately)
	directFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer directFail.Close()

	dst := filepath.Join(t.TempDir(), "SHA256SUMS")
	if err := DownloadTrustAnchor(context.Background(), directFail.Client(), directFail.URL+"/SHA256SUMS", dst); err == nil {
		t.Fatalf("expected DownloadTrustAnchor to fail when direct returns 502 and GH_PROXY is empty")
	}

	// 2. When GH_PROXY is explicitly set, direct is tried FIRST; only on direct failure does it fall back to GH_PROXY
	var order []string
	directOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "direct")
		_, _ = w.Write([]byte(strings.Repeat("a", 64) + "  dex-linux-amd64\n"))
	}))
	defer directOK.Close()

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "gh_proxy")
		_, _ = w.Write([]byte(strings.Repeat("b", 64) + "  dex-linux-amd64\n"))
	}))
	defer proxySrv.Close()

	t.Setenv("GH_PROXY", proxySrv.URL)
	if err := DownloadTrustAnchor(context.Background(), directOK.Client(), directOK.URL+"/SHA256SUMS", dst); err != nil {
		t.Fatalf("DownloadTrustAnchor direct+GH_PROXY failed: %v", err)
	}
	if len(order) != 1 || order[0] != "direct" {
		t.Fatalf("expected direct tried first without touching GH_PROXY on success, got order=%v", order)
	}

	// Now direct fails -> falls back to explicit GH_PROXY
	order = nil
	if err := DownloadTrustAnchor(context.Background(), directFail.Client(), directFail.URL+"/SHA256SUMS", dst); err != nil {
		t.Fatalf("DownloadTrustAnchor GH_PROXY fallback failed: %v", err)
	}
	if len(order) != 1 || order[0] != "gh_proxy" {
		t.Fatalf("expected explicit GH_PROXY fallback after direct failure, got order=%v", order)
	}
}
