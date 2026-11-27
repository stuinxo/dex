package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicAndJSON(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "sub", "data.json")
	payload := map[string]string{"hello": "world"}

	if err := WriteJSONAtomic(dst, payload, 0o600); err != nil {
		t.Fatalf("WriteJSONAtomic: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600, got %o", info.Mode().Perm())
	}
	b, err := os.ReadFile(dst)
	if err != nil || len(b) == 0 || b[len(b)-1] != '\n' {
		t.Fatalf("expected trailing newline JSON, got %q err=%v", string(b), err)
	}

	copyDst := filepath.Join(dir, "copy", "data.copy")
	if err := CopyFileAtomic(dst, copyDst, 0o644); err != nil {
		t.Fatalf("CopyFileAtomic: %v", err)
	}
	copyInfo, err := os.Stat(copyDst)
	if err != nil || copyInfo.Mode().Perm() != 0o644 {
		t.Fatalf("expected 0644 on copy, got %v err=%v", copyInfo.Mode().Perm(), err)
	}
}

func TestMapRootPrefix(t *testing.T) {
	if got := MapRootPrefix("", "/etc/dex/state.json"); got != "/etc/dex/state.json" {
		t.Fatalf("empty root prefix: got %q", got)
	}
	if got := MapRootPrefix("/tmp/root", "/etc/dex/state.json"); got != "/tmp/root/etc/dex/state.json" {
		t.Fatalf("prefixed: got %q", got)
	}
	if got := MapRootPrefix("/tmp/root", "/tmp/root/etc/dex/state.json"); got != "/tmp/root/etc/dex/state.json" {
		t.Fatalf("already prefixed: got %q", got)
	}
}
