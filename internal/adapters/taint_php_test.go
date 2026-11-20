package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// TestPHPInclude checks that what an included file sets reaches the sink of
// the file that includes it, and that the finding names the right file.
func TestPHPInclude(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("vuln/index.php", "<?php\n$page = 'x';\nrequire_once 'vuln/src/' . $file;\necho $html;\n")
	write("vuln/src/low.php", "<?php\n$html .= '<pre>' . $_GET['name'] . '</pre>';\n")
	write("vuln/src/high.php", "<?php\n$html .= '<pre>' . htmlspecialchars($_GET['name']) . '</pre>';\n")
	write("safe/index.php", "<?php\nrequire 'safe/lib.php';\necho $html;\n")
	write("safe/lib.php", "<?php\n$html = htmlspecialchars($_GET['name']);\n")
	cfg := config.Default("x")
	inv, err := inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles})
	if err != nil {
		t.Fatal(err)
	}
	res, run := taintAdapter{}.Run(context.Background(), &Context{Root: root, Inv: inv, Cfg: cfg})
	if run.ExitClass != model.ExitOK {
		t.Fatalf("%s: %s", run.ExitClass, run.Detail)
	}
	if len(res.Signals) != 1 {
		t.Fatalf("got %d signals: %+v", len(res.Signals), res.Signals)
	}
	s := res.Signals[0]
	if s.RuleID != "taint.php-xss" || s.File != "vuln/index.php" || s.StartLine != 4 {
		t.Errorf("got %s at %s:%d", s.RuleID, s.File, s.StartLine)
	}
	if !strings.Contains(s.Message, "vuln/src/low.php") {
		t.Errorf("the flow should name the included file: %s", s.Message)
	}
}

// TestPHPArithmeticIsNumeric checks that the result of arithmetic on request
// input is a number: it is not reported as markup, while concatenation is.
func TestPHPArithmeticIsNumeric(t *testing.T) {
	cases := []struct {
		name string
		code string
		want int
	}{
		{"concat", "<?php\n$n = $_GET['n'];\necho \"a\" . $n;\n", 1},
		{"subtract", "<?php\n$n = $_POST['n'];\n$s = ($n * 10) - $n + 1;\necho \"Showing $s\";\n", 0},
		{"compound", "<?php\n$s = 1;\n$s += $_GET['n'];\necho $s;\n", 0},
		{"concat-assign", "<?php\n$s = 'x';\n$s .= $_GET['n'];\necho $s;\n", 1},
		{"modulo", "<?php\n$s = $_GET['n'] % 7;\necho $s;\n", 0},
	}
	for _, c := range cases {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "a.php"), []byte(c.code), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := config.Default("x")
		inv, err := inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles})
		if err != nil {
			t.Fatal(err)
		}
		res, run := taintAdapter{}.Run(context.Background(), &Context{Root: root, Inv: inv, Cfg: cfg})
		if run.ExitClass != model.ExitOK {
			t.Fatalf("%s: %s: %s", c.name, run.ExitClass, run.Detail)
		}
		if len(res.Signals) != c.want {
			t.Errorf("%s: got %d signals, want %d: %+v", c.name, len(res.Signals), c.want, res.Signals)
		}
	}
}

// TestPHPFrameworkRequest checks that the accessors of a framework request
// object are sources, and that a cast of the value is not reported.
func TestPHPFrameworkRequest(t *testing.T) {
	cases := []struct {
		name string
		code string
		want int
	}{
		{"laravel-input", "<?php\nclass C {\n public function show(Request $request) {\n  $l = $request->input('locale');\n  echo $l;\n }\n}\n", 1},
		{"laravel-cast", "<?php\nclass C {\n public function show(Request $request) {\n  $l = (int) $request->input('locale');\n  echo $l;\n }\n}\n", 0},
		{"symfony-query", "<?php\nclass C {\n public function show(Request $request) {\n  $b = $request->query->get('bundle');\n  echo $b;\n }\n}\n", 1},
		{"symfony-escaped", "<?php\nclass C {\n public function show(Request $request) {\n  $b = $request->query->get('bundle');\n  echo htmlspecialchars($b);\n }\n}\n", 0},
		{"unrelated", "<?php\nclass C {\n public function show(Foo $foo) {\n  $b = $foo->get('bundle');\n  echo $b;\n }\n}\n", 0},
	}
	for _, c := range cases {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "a.php"), []byte(c.code), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := config.Default("x")
		inv, err := inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles})
		if err != nil {
			t.Fatal(err)
		}
		res, run := taintAdapter{}.Run(context.Background(), &Context{Root: root, Inv: inv, Cfg: cfg})
		if run.ExitClass != model.ExitOK {
			t.Fatalf("%s: %s: %s", c.name, run.ExitClass, run.Detail)
		}
		if len(res.Signals) != c.want {
			t.Errorf("%s: got %d signals, want %d", c.name, len(res.Signals), c.want)
		}
	}
}
