package arch_test

import (
	"bytes"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stuinxo/dex/internal/state"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository root (go.mod)")
		}
		dir = parent
	}
}

func TestLayeredDependencyDAG(t *testing.T) {
	root := repoRoot(t)
	const modPrefix = "github.com/stuinxo/dex/internal/"

	allowedInternal := map[string]map[string]bool{
		"arch":      {},
		"version":   {},
		"fsutil":    {},
		"cryptoext": {},
		"doh":       {},
		"state":     {"fsutil": true, "cryptoext": true},
		"cert":      {"fsutil": true, "cryptoext": true, "state": true},
		"socks5out": {"fsutil": true, "cryptoext": true, "state": true},
		"render":    {"fsutil": true, "cryptoext": true, "state": true},
		"migrate":   {"fsutil": true, "cryptoext": true, "state": true, "render": true},
		"reconcile": {"fsutil": true, "cryptoext": true, "state": true, "cert": true, "render": true},
		"update":    {"fsutil": true, "state": true, "reconcile": true},
		"daemon":    {"version": true, "fsutil": true, "cryptoext": true, "doh": true, "state": true, "cert": true, "socks5out": true, "render": true, "reconcile": true},
		"web":       {"version": true, "fsutil": true, "cryptoext": true, "doh": true, "state": true, "cert": true, "socks5out": true, "render": true, "migrate": true, "reconcile": true, "daemon": true},
		"cli":       {"version": true, "fsutil": true, "cryptoext": true, "doh": true, "state": true, "cert": true, "socks5out": true, "render": true, "migrate": true, "reconcile": true, "update": true, "daemon": true, "web": true},
	}

	fset := token.NewFileSet()
	internalRoot := filepath.Join(root, "internal")
	err := filepath.WalkDir(internalRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(internalRoot, path)
		pkgName := strings.Split(filepath.ToSlash(rel), "/")[0]
		allowed, knownPkg := allowedInternal[pkgName]
		if !knownPkg {
			t.Errorf("unregistered internal package %q at %s (add it to TestLayeredDependencyDAG)", pkgName, rel)
			return nil
		}

		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Errorf("parse %s: %v", rel, perr)
			return nil
		}
		for _, imp := range f.Imports {
			impPath := strings.Trim(imp.Path.Value, `"`)
			if pkgName == "render" && (impPath == "os/exec" || impPath == "net/http") {
				t.Errorf("pure compiler package render (%s) must not import %q", rel, impPath)
			}
			if depPkg, ok := strings.CutPrefix(impPath, modPrefix); ok {
				if !allowed[depPkg] {
					t.Errorf("layer violation: internal/%s (%s) must not import internal/%s", pkgName, rel, depPkg)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAtomicWriteCentralization(t *testing.T) {
	root := repoRoot(t)
	allowCreateTemp := map[string]bool{
		"internal/fsutil/atomic.go":    true,
		"internal/update/download.go":   true, // streaming HTTP download staging
		"internal/update/operations.go": true, // zip archive entry & rollback binary staging
	}

	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		relSlash := filepath.ToSlash(rel)
		if allowCreateTemp[relSlash] {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(b, []byte("os.CreateTemp(")) {
			t.Errorf("%s calls os.CreateTemp directly; use internal/fsutil.WriteFileAtomic or WriteJSONAtomic instead", relSlash)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNodeSMServiceCatalogParity(t *testing.T) {
	root := repoRoot(t)
	appJS, err := os.ReadFile(filepath.Join(root, "internal/web/ui/app.js"))
	if err != nil {
		t.Fatal(err)
	}
	blockRe := regexp.MustCompile(`(?s)var\s+NODESM_META\s*=\s*\{(.*?)\n\s*\};`)
	m := blockRe.FindSubmatch(appJS)
	if len(m) < 2 {
		t.Fatal("could not locate NODESM_META object in internal/web/ui/app.js")
	}
	keyRe := regexp.MustCompile(`(?m)^\s*([a-z0-9_]+)\s*:\s*\{`)
	matches := keyRe.FindAllSubmatch(m[1], -1)

	uiKeys := make(map[string]bool, len(matches))
	for _, km := range matches {
		uiKeys[string(km[1])] = true
	}
	stateKeys := make(map[string]bool, len(state.NodeSMServices))
	for _, svc := range state.NodeSMServices {
		stateKeys[svc] = true
		if !uiKeys[svc] {
			t.Errorf("service %q in state.NodeSMServices is missing from UI NODESM_META", svc)
		}
	}
	for k := range uiKeys {
		if !stateKeys[k] {
			t.Errorf("service %q in UI NODESM_META is missing from state.NodeSMServices", k)
		}
	}
}

func TestInstallerTripletAndSecurityInvariants(t *testing.T) {
	root := repoRoot(t)
	instBytes, err := os.ReadFile(filepath.Join(root, "scripts/install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(instBytes, []byte("#!/bin/sh\n")) {
		t.Error("scripts/install.sh must begin with #!/bin/sh")
	}
	if !strings.HasSuffix(strings.TrimSpace(string(instBytes)), `main "$@"`) {
		t.Error(`scripts/install.sh must end with 'main "$@"'`)
	}
	for _, alias := range []string{"dex", "i"} {
		b, rerr := os.ReadFile(filepath.Join(root, alias))
		if rerr != nil {
			t.Fatalf("read %s: %v", alias, rerr)
		}
		if !bytes.Equal(b, instBytes) {
			t.Errorf("%s is out of sync with scripts/install.sh", alias)
		}
	}

	// Build forbidden patterns dynamically so CI's literal grep checks never self-match this test file.
	forbiddenFlag := []byte("--no-check-" + "certificate")
	aptLockRe := regexp.MustCompile(`rm\s+(-rf|-f)\s+(/var/lib/(apt|dpkg)/.*lock|/var/cache/apt/archives/lock)`)

	for _, relDir := range []string{"dex", "i", "scripts", "internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, relDir), func(path string, d fs.DirEntry, werr error) error {
			if werr != nil || d.IsDir() {
				return werr
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if bytes.Contains(b, forbiddenFlag) {
				t.Errorf("%s contains forbidden TLS-skip wget flag", path)
			}
			if (relDir == "dex" || relDir == "i" || relDir == "scripts") && aptLockRe.Match(b) {
				t.Errorf("%s contains forbidden apt/dpkg lock deletion", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNoGodFiles(t *testing.T) {
	root := repoRoot(t)
	const maxLines = 1500
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			lines := bytes.Count(b, []byte{'\n'})
			if len(b) > 0 && b[len(b)-1] != '\n' {
				lines++
			}
			if lines > maxLines {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s has %d lines (> %d ceiling); decompose along domain boundaries", rel, lines, maxLines)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
