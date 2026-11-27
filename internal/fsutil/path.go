package fsutil

import (
	"path/filepath"
	"strings"
)

// MapRootPrefix maps an absolute target path beneath rootPrefix when testing or staging
// against an alternate filesystem root, avoiding double-prefixing if already under rootPrefix.
func MapRootPrefix(rootPrefix, targetPath string) string {
	if strings.TrimSpace(rootPrefix) == "" {
		return targetPath
	}
	cleanRoot := filepath.Clean(rootPrefix)
	cleanTarget := filepath.Clean(targetPath)
	if cleanRoot == "/" {
		return cleanTarget
	}
	if cleanTarget == cleanRoot || strings.HasPrefix(cleanTarget, cleanRoot+string(filepath.Separator)) {
		return cleanTarget
	}
	clean := strings.TrimPrefix(cleanTarget, string(filepath.Separator))
	return filepath.Join(cleanRoot, clean)
}
