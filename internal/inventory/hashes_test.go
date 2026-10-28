package inventory_test

import (
	"context"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// Hashes must see exactly the files Walk analyzes, with the same hashes, or
// every status call would report phantom changes.
func TestHashesMatchWalk(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	testfixture.Write(t, root, "binary.js", string(make([]byte, 64)))              // binary: skipped by both
	testfixture.Write(t, root, "node_modules/x/index.js", "module.exports = 1;\n") // excluded
	opt := inventory.Options{Exclude: []string{"node_modules", ".git"}, MaxFileBytes: 1 << 20, MaxFiles: 1000}
	inv, err := inventory.Walk(root, opt)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := inventory.Hashes(context.Background(), root, opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != len(inv.Files) || len(hs) == 0 {
		t.Fatalf("Hashes saw %d files, Walk %d", len(hs), len(inv.Files))
	}
	for _, f := range inv.Files {
		if hs[f.Path] != f.SHA256 {
			t.Errorf("%s: hash %q, Walk %q", f.Path, hs[f.Path], f.SHA256)
		}
	}
	if _, ok := hs[".env"]; ok {
		t.Error("sensitive files must not be read")
	}
}

func TestHashesStopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inventory.Hashes(ctx, testfixture.VulnerableRepo(t), inventory.Options{MaxFileBytes: 1 << 20}); err == nil {
		t.Fatal("expected the context error")
	}
}
