package cli

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
