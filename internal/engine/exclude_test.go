package engine

import (
	"path/filepath"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// External tools walk the tree themselves; their signals in build output
// and other excluded directories are dropped like the built-in checks skip
// those files (#156).
func TestDropExcludedSignals(t *testing.T) {
	root := t.TempDir()
	e, _, err := Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	out := adapters.Result{Signals: []model.Signal{
		{RuleID: "gitleaks.generic-api-key", File: filepath.Join(root, ".next", "cache", ".rscinfo")},
		{RuleID: "gitleaks.generic-api-key", File: ".next/server/preview-props.json"},
		{RuleID: "gitleaks.generic-api-key", File: filepath.Join(root, "apps", "web", ".next", "prerender-manifest.json")},
		{RuleID: "gitleaks.stripe-access-token", File: filepath.Join(root, "src", "server.js")},
		{RuleID: "semgrep.x", File: "src/next.config.js"},
		{RuleID: "inventory.y", File: ""},
	}}
	if n := e.dropExcluded(&out); n != 3 {
		t.Fatalf("dropped %d, want 3", n)
	}
	if len(out.Signals) != 3 || out.Signals[0].RuleID != "gitleaks.stripe-access-token" || out.Signals[1].File != "src/next.config.js" || out.Signals[2].File != "" {
		t.Fatalf("kept %+v", out.Signals)
	}
}
