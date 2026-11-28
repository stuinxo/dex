package arch_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

// allowedInternalDeps encodes the strict minimal direct production dependency DAG.
// Any new internal package or edge requires explicit architectural review.
var allowedInternalDeps = map[string]string{
	"arch":      "",
	"version":   "",
	"fsutil":    "",
	"cryptoext": "",
	"doh":       "",
	"state":     "cryptoext fsutil",
	"cert":      "fsutil",
	"socks5out": "state",
	"render":    "cryptoext state",
	"migrate":   "cryptoext render state",
	"reconcile": "cert fsutil render state",
	"update":    "fsutil reconcile state",
	"daemon":    "reconcile render socks5out state",
	"web":       "cert cryptoext daemon doh migrate reconcile render socks5out state version",
	"cli":       "cert cryptoext daemon doh fsutil migrate reconcile render socks5out state update version web",
}

func checkInternalDependencies(internalRoot string) []string {
	const modPrefix = "github.com/stuinxo/dex/internal/"
	fset := token.NewFileSet()
	var violations []string

	err := filepath.WalkDir(internalRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(internalRoot, path)
		if err != nil {
			return err
		}
		pkgName := strings.Split(filepath.ToSlash(rel), "/")[0]
		permitted, known := allowedInternalDeps[pkgName]
		if !known {
			violations = append(violations, fmt.Sprintf("unregistered internal package %q at %s", pkgName, rel))
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			violations = append(violations, fmt.Sprintf("parse %s: %v", rel, err))
			return nil
		}
		for _, imp := range f.Imports {
			impPath, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				violations = append(violations, fmt.Sprintf("unquote import in %s: %v", rel, uerr))
				continue
			}
			if pkgName == "render" && (impPath == "os/exec" || impPath == "net/http") {
				violations = append(violations, fmt.Sprintf("pure compiler package render (%s) must not import %q", rel, impPath))
			}
			if depPkg, ok := strings.CutPrefix(impPath, modPrefix); ok {
				if !strings.Contains(" "+permitted+" ", " "+depPkg+" ") {
					violations = append(violations, fmt.Sprintf("layer violation: internal/%s (%s) must not import internal/%s", pkgName, rel, depPkg))
				}
			}
		}
		return nil
	})
	if err != nil {
		violations = append(violations, err.Error())
	}
	return violations
}

func TestLayeredDependencyDAG(t *testing.T) {
	internalRoot := filepath.Join(repoRoot(t), "internal")
	for _, v := range checkInternalDependencies(internalRoot) {
		t.Error(v)
	}
}

func TestDependencyGuardRejectsLayerViolation(t *testing.T) {
	tmpRoot := t.TempDir()
	stateDir := filepath.Join(tmpRoot, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	badFile := filepath.Join(stateDir, "invalid.go")
	if err := os.WriteFile(badFile, []byte("package state\nimport _ \"github.com/stuinxo/dex/internal/web\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	violations := checkInternalDependencies(tmpRoot)
	if len(violations) != 1 || !strings.Contains(violations[0], "must not import internal/web") {
		t.Fatalf("guard did not reject state -> web: %v", violations)
	}
}

func TestAtomicWriteCentralization(t *testing.T) {
	root := repoRoot(t)
	allowCreateTemp := map[string]bool{
		"internal/fsutil/atomic.go":     true,
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
			t.Errorf("%s calls os.CreateTemp directly; use internal/fsutil instead", relSlash)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertificateTransitionOwnership(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	for _, pkg := range []string{"cli", "web", "reconcile"} {
		files, err := filepath.Glob(filepath.Join(root, "internal", pkg, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assign.Lhs {
					field, ok := lhs.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					certSel, ok := field.X.(*ast.SelectorExpr)
					if !ok || certSel.Sel.Name != "Cert" {
						continue
					}
					switch field.Sel.Name {
					case "Mode", "CertFile", "KeyFile", "AutoRenew":
						t.Errorf("%s: certificate transition field assignment must use state.CertConfig methods", fset.Position(field.Pos()))
					}
				}
				return true
			})
		}
	}
}

func TestPortAllocationOwnership(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(root, "internal", "render", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && (fn.Name.Name == "ExtraInternalPort" || fn.Name.Name == "AllocateViaNginxInternalPorts") {
				t.Errorf("%s redeclares state-owned port allocation helper %s", filepath.Base(path), fn.Name.Name)
			}
		}
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
			t.Errorf("%s is out of sync with scripts/install.sh (run sh scripts/sync-install.sh)", alias)
		}
	}

	// Build forbidden pattern dynamically so CI's literal grep checks never self-match this test file.
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
