package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stuinxo/dex/internal/render"
)

var ErrManualModificationDetected = errors.New("managed config modified outside dex")

// ManifestEntry records the expected SHA256 digest of a file managed by dex.
type ManifestEntry struct {
	TargetPath string      `json:"target_path"`
	SHA256     string      `json:"sha256"`
	Mode       os.FileMode `json:"mode"`
}

// Manifest tracks all target files currently owned by dex.
type Manifest struct {
	Files map[string]ManifestEntry `json:"files"`
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// LoadManifest reads manifest.json if present; missing file yields an empty Manifest.
func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Manifest{Files: make(map[string]ManifestEntry)}, nil
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.Files == nil {
		m.Files = make(map[string]ManifestEntry)
	}
	return &m, nil
}

// SaveManifest atomically writes manifest.json.
func SaveManifest(path string, m *Manifest) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(dir, ".manifest.tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// CheckUnmanagedEdits verifies that previously managed files still match their last recorded SHA256
// (unless the file was removed or matches the newly rendered content), including obsolete files
// no longer present in the new render bundle.
func CheckUnmanagedEdits(prev *Manifest, files []render.RenderedFile, mapPath func(string) string) error {
	if prev == nil || len(prev.Files) == 0 {
		return nil
	}
	newTargets := make(map[string]struct{}, len(files))
	for _, f := range files {
		newTargets[f.TargetPath] = struct{}{}
		entry, managedBefore := prev.Files[f.TargetPath]
		if !managedBefore {
			continue
		}
		diskPath := mapPath(f.TargetPath)
		diskBytes, err := os.ReadFile(diskPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", diskPath, err)
		}
		diskHash := sha256Hex(diskBytes)
		newHash := sha256Hex(f.Content)
		if diskHash != entry.SHA256 && diskHash != newHash {
			return fmt.Errorf("%w: %s (use --force to overwrite)", ErrManualModificationDetected, f.TargetPath)
		}
	}
	for oldTarget, entry := range prev.Files {
		if _, kept := newTargets[oldTarget]; kept {
			continue
		}
		diskPath := mapPath(oldTarget)
		diskBytes, err := os.ReadFile(diskPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", diskPath, err)
		}
		if sha256Hex(diskBytes) != entry.SHA256 {
			return fmt.Errorf("%w: %s (use --force to overwrite)", ErrManualModificationDetected, oldTarget)
		}
	}
	return nil
}

// BuildManifest creates a Manifest from the rendered files.
func BuildManifest(files []render.RenderedFile) *Manifest {
	m := &Manifest{Files: make(map[string]ManifestEntry, len(files))}
	for _, f := range files {
		m.Files[f.TargetPath] = ManifestEntry{
			TargetPath: f.TargetPath,
			SHA256:     sha256Hex(f.Content),
			Mode:       f.Mode,
		}
	}
	return m
}
