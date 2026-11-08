package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// runInventory writes files into a fresh directory and runs the inventory
// adapter on them.
func runInventory(t *testing.T, files map[string]string) Result {
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
	res, run := inventoryAdapter{}.Run(context.Background(), &Context{Root: root, Inv: inv})
	if run.ExitClass != model.ExitOK {
		t.Fatalf("inventory adapter did not complete: %s", run.Detail)
	}
	return res
}

func expressWithContract() map[string]string {
	return map[string]string{
		"package.json": `{"dependencies":{"express":"4.21.0"}}`,
		"openapi.yaml": "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n  /health:\n    get:\n      responses: {'200': {description: ok}}\n",
		"index.js":     "const express = require('express')\nconst app = express()\napp.get('/health', h)\n",
	}
}

// Routes started by test servers are not part of the contract, so they
// neither raise findings nor block A-003.
func TestA003IgnoresTestRoutes(t *testing.T) {
	files := expressWithContract()
	files["test/server.test.js"] = "const express = require('express')\nconst app = express()\napp.get('/mock-upstream', h)\n"
	d := decide(t, files, "A-003")
	if d.Status != model.StatusPass {
		t.Fatalf("A-003 = %s: %s", d.Status, d.Reason)
	}
	if !strings.Contains(d.Reason, "all 1 discovered routes") || !strings.Contains(d.Reason, "1 routes in test or fixture files not compared") {
		t.Fatalf("unexpected reason: %s", d.Reason)
	}
}

// An undocumented route in product code is still reported.
func TestA003ReportsUndeclaredProductRoute(t *testing.T) {
	files := expressWithContract()
	files["admin.js"] = "const express = require('express')\nconst app = express()\napp.post('/internal/reset', h)\n"
	files["test/server.test.js"] = "const express = require('express')\nconst app = express()\napp.get('/mock-upstream', h)\n"
	res := runInventory(t, files)
	var got []string
	for _, s := range res.Signals {
		if s.RuleID == "inventory.undeclared-route" {
			got = append(got, s.File)
		}
	}
	if len(got) != 1 || got[0] != "admin.js" {
		t.Fatalf("undeclared-route signals = %v, want only admin.js", got)
	}
	if d, ok := res.Decisions["A-003"]; ok && d.Status == model.StatusPass {
		t.Fatal("A-003 must not pass with an undeclared product route")
	}
}
