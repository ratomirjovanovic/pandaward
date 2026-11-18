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
