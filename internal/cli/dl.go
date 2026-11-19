package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	sha256HexRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	defaultMirrors = []string{
		"https://gh-proxy.com/",
		"https://ghproxy.net/",
		"https://ghfast.top/",
	}
)

// NormalizeSHA256 parses a sha256sum line ("<hex>  <filename>") or bare hex string
// and returns lowercase 64-char hex, rejecting HTML error pages or malformed strings.
func NormalizeSHA256(raw string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 {
		return "", errors.New("empty sha256 string")
	}
	cand := strings.ToLower(fields[0])
	if !sha256HexRe.MatchString(cand) {
		return "", fmt.Errorf("invalid sha256 digest %q", fields[0])
	}
	return cand, nil
}

// VerifyFileSHA256 checks that the SHA256 digest of path matches expectedRaw.
func VerifyFileSHA256(path, expectedRaw string) error {
	expected, err := NormalizeSHA256(expectedRaw)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expected {
		return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", path, actual, expected)
	}
	return nil
}

// IsELFBinary verifies the 4-byte Linux ELF magic header (\x7fELF).
func IsELFBinary(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var hdr [4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false, nil
	}
	return bytes.Equal(hdr[:], []byte{0x7f, 'E', 'L', 'F'}), nil
}

// FindLocalPackage checks an env override and common local directories for an offline package or binary.
func FindLocalPackage(envKey string, filenames []string) string {
	if envKey != "" {
		if p := strings.TrimSpace(os.Getenv(envKey)); p != "" {
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return p
			}
		}
	}
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	dirs = append(dirs, "/root", "/tmp")

	for _, dir := range dirs {
		for _, name := range filenames {
			cand := filepath.Join(dir, name)
			if info, err := os.Stat(cand); err == nil && !info.IsDir() && info.Size() > 0 {
				return cand
			}
		}
	}
	return ""
}

// DownloadWithMirrors downloads rawURL to dstPath atomically, falling back across GitHub mirrors.
func DownloadWithMirrors(ctx context.Context, client *http.Client, rawURL, dstPath string, mirrors []string) error {
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	if mirrors == nil {
		mirrors = defaultMirrors
	}

	var attempts []string
	if proxy := strings.TrimSpace(os.Getenv("GH_PROXY")); proxy != "" {
		attempts = append(attempts, strings.TrimRight(proxy, "/")+"/"+strings.TrimLeft(rawURL, "/"))
	} else {
		attempts = append(attempts, rawURL)
	}
	for _, m := range mirrors {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		attempts = append(attempts, strings.TrimRight(m, "/")+"/"+strings.TrimLeft(rawURL, "/"))
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}

	var lastErr error
	for _, targetURL := range attempts {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, targetURL)
			continue
		}
		tmp, err := os.CreateTemp(filepath.Dir(dstPath), ".dl.tmp.*")
		if err != nil {
			_ = resp.Body.Close()
			return err
		}
		tmpName := tmp.Name()
		n, copyErr := io.Copy(tmp, resp.Body)
		_ = resp.Body.Close()
		_ = tmp.Close()
		if copyErr != nil || n == 0 {
			_ = os.Remove(tmpName)
			lastErr = fmt.Errorf("download error from %s: %v", targetURL, copyErr)
			continue
		}
		if err := os.Rename(tmpName, dstPath); err != nil {
			_ = os.Remove(tmpName)
			return err
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("all download attempts failed")
	}
	return lastErr
}

// DownloadVerifiedFile downloads rawURL, verifies its SHA256 against expectedSum (literal or URL),
// and optionally checks for the Linux ELF header.
func DownloadVerifiedFile(ctx context.Context, client *http.Client, rawURL, expectedSumOrURL, dstPath string, requireELF bool) error {
	stagePath := dstPath + ".part"
	defer os.Remove(stagePath)

	if err := DownloadWithMirrors(ctx, client, rawURL, stagePath, nil); err != nil {
		return err
	}

	expected := expectedSumOrURL
	if strings.HasPrefix(expectedSumOrURL, "http://") || strings.HasPrefix(expectedSumOrURL, "https://") {
		sumFile := stagePath + ".sha256"
		defer os.Remove(sumFile)
		if err := DownloadWithMirrors(ctx, client, expectedSumOrURL, sumFile, nil); err != nil {
			return fmt.Errorf("fetch checksum: %w", err)
		}
		b, err := os.ReadFile(sumFile)
		if err != nil {
			return err
		}
		expected = string(b)
	}
	if expected != "" {
		if err := VerifyFileSHA256(stagePath, expected); err != nil {
			return err
		}
	}
	if requireELF {
		ok, err := IsELFBinary(stagePath)
		if err != nil || !ok {
			return fmt.Errorf("downloaded file %s is not a valid ELF binary", rawURL)
		}
		_ = os.Chmod(stagePath, 0o755)
	}
	return os.Rename(stagePath, dstPath)
}
