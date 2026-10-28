package adapters

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// runOn writes files into a fresh directory, builds the inventory and runs
// one adapter on it.
func runOn(t *testing.T, a Adapter, files map[string]string) []model.Signal {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20, MaxFiles: 1000})
	if err != nil {
		t.Fatal(err)
	}
	res, run := a.Run(context.Background(), &Context{Root: root, Inv: inv})
	if run.ExitClass != model.ExitOK {
		t.Fatalf("%s did not complete: %s %s", a.Name(), run.ExitClass, run.Detail)
	}
	return res.Signals
}

func fired(sigs []model.Signal, rule string) bool {
	for _, s := range sigs {
		if s.RuleID == rule {
			return true
		}
	}
	return false
}

// The per-rule vulnerable and safe cases live in the benchmark corpus
// (internal/benchmark), whose test fails on any miss or false positive.

func TestCodeRulesSkipCommentsAndTests(t *testing.T) {
	sigs := runOn(t, codeAdapter{}, map[string]string{
		"src/a.js":       "// eval(userInput);\n",
		"test/a.test.js": "eval(userInput);\n",
	})
	if fired(sigs, "code.js-eval") {
		t.Fatal("comments and test files must not fire code rules")
	}
}
