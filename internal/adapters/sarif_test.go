package adapters

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// sarifLog builds a minimal SARIF 2.1.0 log with one CodeQL-like run.
func sarifLog(t *testing.T, results ...map[string]any) string {
	t.Helper()
	doc := map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": "CodeQL", "semanticVersion": "2.19.0", "rules": []any{
				map[string]any{"id": "js/sql-injection", "shortDescription": map[string]any{"text": "Database query built from user-controlled sources"},
					"properties": map[string]any{"tags": []string{"security", "external/cwe/cwe-089"}, "security-severity": "8.8"}},
				map[string]any{"id": "js/log-injection", "defaultConfiguration": map[string]any{"level": "note"}},
			}}},
			"originalUriBaseIds": map[string]any{"SRC": map[string]any{"uri": "src/"}},
			"results":            results,
		}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sarifResultAt(rule string, idx int, uri, base string, line int, msg string) map[string]any {
	loc := map[string]any{"uri": uri}
	if base != "" {
		loc["uriBaseId"] = base
	}
	return map[string]any{"ruleId": rule, "ruleIndex": idx, "message": map[string]any{"text": msg},
		"locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": loc, "region": map[string]any{"startLine": line,
			"snippet": map[string]any{"text": "SNIPPET FROM SARIF"}}}}}}
}

func sarifContext(t *testing.T, root string) *Context {
	t.Helper()
	inv, err := inventory.Walk(root, inventory.Options{Exclude: []string{".pandaward"}, MaxFileBytes: 1 << 20, MaxFiles: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return &Context{Root: root, Inv: inv, Cfg: config.Default("x")}
}

func TestSARIFImportNormalizes(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/db.js", "const a = 1;\ndb.query('SELECT * FROM t WHERE id=' + req.query.id);\n")
	testfixture.Write(t, root, SARIFDir+"/codeql.sarif", sarifLog(t,
		sarifResultAt("js/sql-injection", 0, "db.js", "SRC", 2, "This query depends on a user-provided value."),
		sarifResultAt("js/log-injection", 1, "file:///"+filepath.ToSlash(filepath.Join(root, "src", "db.js")), "", 1, "note"),
		map[string]any{"ruleId": "js/sql-injection", "kind": "pass", "message": map[string]any{"text": "ok"}},
		map[string]any{"ruleId": "js/sql-injection", "message": map[string]any{"text": "s"}, "suppressions": []any{map[string]any{"kind": "inSource"}}},
	))
	res, run := sarifAdapter{}.Run(context.Background(), sarifContext(t, root))
	if run.ExitClass != model.ExitOK || len(res.Signals) != 2 {
		t.Fatalf("got %s %q with %d signals", run.ExitClass, run.Detail, len(res.Signals))
	}
	if !strings.Contains(run.ToolVersion, "CodeQL 2.19.0") || !strings.Contains(run.Detail, "CodeQL 2.19.0") || !strings.Contains(run.Detail, "skipped") {
		t.Errorf("run does not record the tool: %q / %q", run.ToolVersion, run.Detail)
	}
	s := res.Signals[0]
	if s.RuleID != "sarif.codeql.js-sql-injection" || s.ControlID != "R-002" || s.Confidence != model.Hypothesis || s.Severity != model.SevHigh || s.CWE != "CWE-89" {
		t.Errorf("unexpected signal: %+v", s)
	}
	if s.File != "src/db.js" || s.StartLine != 2 || !strings.Contains(s.Snippet, "db.query(") || strings.Contains(s.Snippet, "SNIPPET FROM SARIF") {
		t.Errorf("location or snippet not resolved from the real file: %s:%d %q", s.File, s.StartLine, s.Snippet)
	}
	if s2 := res.Signals[1]; s2.File != "src/db.js" || s2.Severity != model.SevLow || s2.RuleID != "sarif.codeql.js-log-injection" {
		t.Errorf("file URI or default level not handled: %+v", s2)
	}
}

func TestSARIFImportRejectsBadInput(t *testing.T) {
	cases := map[string]func(t *testing.T, root string, cfg *config.Config){
		"malformed json": func(t *testing.T, root string, cfg *config.Config) {
			testfixture.Write(t, root, SARIFDir+"/bad.sarif", `{"version":"2.1.0","runs":[`)
		},
		"wrong version": func(t *testing.T, root string, cfg *config.Config) {
			testfixture.Write(t, root, SARIFDir+"/old.sarif", `{"version":"1.0.0","runs":[]}`)
		},
		"no driver": func(t *testing.T, root string, cfg *config.Config) {
			testfixture.Write(t, root, SARIFDir+"/nodriver.sarif.json", `{"version":"2.1.0","runs":[{"results":[]}]}`)
		},
		"outside root": func(t *testing.T, root string, cfg *config.Config) {
			outside := filepath.Join(filepath.Dir(root), filepath.Base(root)+"-outside.sarif")
			if err := os.WriteFile(outside, []byte(sarifLog(t)), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Remove(outside) })
			cfg.Scan.SARIFFiles = []string{"../" + filepath.Base(outside)}
		},
		"absolute outside root": func(t *testing.T, root string, cfg *config.Config) {
			cfg.Scan.SARIFFiles = []string{filepath.Join(t.TempDir(), "x.sarif")}
		},
		"missing configured file": func(t *testing.T, root string, cfg *config.Config) {
			cfg.Scan.SARIFFiles = []string{"reports/codeql.sarif"}
		},
		"oversized": func(t *testing.T, root string, cfg *config.Config) {
			old := sarifMaxBytes
			sarifMaxBytes = 64
			t.Cleanup(func() { sarifMaxBytes = old })
			testfixture.Write(t, root, SARIFDir+"/big.sarif", sarifLog(t))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			c := sarifContext(t, root)
			setup(t, root, c.Cfg)
			res, run := sarifAdapter{}.Run(context.Background(), c)
			if run.ExitClass != model.ExitError || len(res.Signals) != 0 {
				t.Errorf("want ERROR without signals, got %s %q (%d signals)", run.ExitClass, run.Detail, len(res.Signals))
			}
		})
	}
}

func TestSARIFImportRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "real.sarif")
	if err := os.WriteFile(target, []byte(sarifLog(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".pandaward", "sarif"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".pandaward", "sarif", "link.sarif")); err != nil {
		t.Skip("symlinks not available:", err)
	}
	_, run := sarifAdapter{}.Run(context.Background(), sarifContext(t, root))
	if run.ExitClass != model.ExitError || !strings.Contains(run.Detail, "symlink") {
		t.Errorf("symlinked SARIF must be refused: %s %q", run.ExitClass, run.Detail)
	}
}

// A directory junction (Windows) must not lead the import out of the root.
func TestSARIFImportRejectsJunction(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junctions are a Windows feature")
	}
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x.sarif"), []byte(sarifLog(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".pandaward"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, ".pandaward", "sarif"), outside).CombinedOutput(); err != nil {
		t.Skipf("mklink /J failed: %v %s", err, out)
	}
	_, run := sarifAdapter{}.Run(context.Background(), sarifContext(t, root))
	if run.ExitClass != model.ExitError {
		t.Errorf("SARIF behind a junction must be refused: %s %q", run.ExitClass, run.Detail)
	}
}

func TestSARIFImportLocationsStayInRoot(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/a.js", "x\n")
	testfixture.Write(t, root, SARIFDir+"/t.sarif", sarifLog(t,
		sarifResultAt("js/sql-injection", 0, "../../etc/passwd", "SRC", 1, "m"),
		sarifResultAt("js/sql-injection", 0, "https://example.com/a.js", "", 1, "m"),
		sarifResultAt("js/sql-injection", 0, "a.js", "UNKNOWN_BASE", 1, "m"),
	))
	res, run := sarifAdapter{}.Run(context.Background(), sarifContext(t, root))
	if run.ExitClass != model.ExitOK || len(res.Signals) != 3 {
		t.Fatalf("got %s %q", run.ExitClass, run.Detail)
	}
	if f := res.Signals[0]; f.File != "(outside-root)" || f.Snippet != "" || f.StartLine != 0 {
		t.Errorf("escaping URI must not resolve: %+v", f)
	}
	if f := res.Signals[1]; f.File != "" {
		t.Errorf("non-file URI must not name a file: %q", f.File)
	}
	if f := res.Signals[2]; f.File != "a.js" {
		t.Errorf("unknown base must count as the root: %q", f.File)
	}
}

func TestSARIFImportRedactsMessages(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/db.js", "x\n")
	msg := "Hard-coded key " + testfixture.FakeStripe + " found\x1b[31m\x07 here"
	testfixture.Write(t, root, SARIFDir+"/s.sarif", sarifLog(t, sarifResultAt("js/sql-injection", 0, "db.js", "SRC", 1, msg)))
	res, run := sarifAdapter{}.Run(context.Background(), sarifContext(t, root))
	if run.ExitClass != model.ExitOK || len(res.Signals) != 1 {
		t.Fatalf("got %s %q", run.ExitClass, run.Detail)
	}
	m := res.Signals[0].Message
	if strings.Contains(m, testfixture.FakeStripe) || !strings.Contains(m, "REDACTED") || strings.ContainsAny(m, "\x1b\x07") {
		t.Errorf("message not redacted or sanitized: %q", m)
	}
}

func TestSARIFInputs(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, SARIFDir+"/b.sarif", "{}")
	testfixture.Write(t, root, SARIFDir+"/a.sarif.json", "{}")
	testfixture.Write(t, root, SARIFDir+"/notes.txt", "x")
	cfg := config.Default("x")
	cfg.Scan.SARIFFiles = []string{"out/x.sarif", "./.pandaward/sarif/b.sarif", " "}
	got := strings.Join(SARIFInputs(root, cfg), ",")
	if got != ".pandaward/sarif/a.sarif.json,.pandaward/sarif/b.sarif,out/x.sarif" {
		t.Errorf("inputs: %s", got)
	}
	if n := len(SARIFInputs(t.TempDir(), config.Default("x"))); n != 0 {
		t.Errorf("no inputs expected, got %d", n)
	}
}

func TestSARIFIDNormalization(t *testing.T) {
	for in, want := range map[string]string{"CodeQL": "codeql", "ESLint v9.x": "eslint-v9-x", "js/sql-injection": "js-sql-injection", "": "unknown", "../..": "unknown"} {
		if got := sarifID(in, in != "ESLint v9.x"); got != want {
			t.Errorf("sarifID(%q) = %q, want %q", in, got, want)
		}
	}
}
