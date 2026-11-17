package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ratomirjovanovic/pandaward/tools/internal/engines"
)

func TestParseHunks(t *testing.T) {
	diff := "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -3,2 +3,4 @@ func f\n+a\n@@ -10 +12 @@\n-b\n+c\n@@ -20,3 +22,0 @@\n-x\n@@ -30,0 +33,2 @@\n+y\n"
	want := [][2]int{{3, 6}, {12, 12}, {22, 22}, {33, 34}}
	if got := parseHunks(diff); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := parseHunks("Binary files differ"); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestTouches(t *testing.T) {
	r := [][2]int{{10, 12}}
	for _, c := range []struct {
		line, end int
		want      bool
	}{{10, 10, true}, {12, 12, true}, {9, 9, true}, {13, 13, true}, {8, 8, false}, {14, 14, false}, {5, 20, true}, {20, 0, false}} {
		if got := touches(r, c.line, c.end); got != c.want {
			t.Errorf("touches(%d,%d) = %v, want %v", c.line, c.end, got, c.want)
		}
	}
	if touches(nil, 1, 1) {
		t.Fatal("no ranges, no touch")
	}
}

func TestLabelFindingsSeparatesPatchedCode(t *testing.T) {
	c := cve(t)
	onPatch := engines.Finding{Rule: "code.html-sink", File: "lib/render.js", Line: 42, EndLine: 42}
	elsewhere := engines.Finding{Rule: "code.html-sink", File: "lib/render.js", Line: 200, EndLine: 200}
	pre := []engines.Finding{{Rule: "code.html-sink", File: "lib/render.js", Line: 42, EndLine: 42}}
	lf := LabelFindings(c, "builtin", pre, []engines.Finding{onPatch, elsewhere}, map[string][][2]int{"lib/render.js": {{41, 43}}})
	var got []string
	for _, f := range lf {
		if f.Side == "post" {
			got = append(got, f.Label)
		}
	}
	if !reflect.DeepEqual(got, []string{LabelFixedPatched, LabelFixed}) {
		t.Fatalf("%v", got)
	}
}

// PatchedRanges diffs two checkouts that have no shared history.
func TestPatchedRangesOnTwoCheckouts(t *testing.T) {
	pre, post := t.TempDir(), t.TempDir()
	write := func(dir, name, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(pre, "lib/render.js", "a\nb\nc\nd\ne\n")
	write(post, "lib/render.js", "a\nb\nC\nC2\nd\ne\n")
	c := cve(t) // weakness in lib/render.js
	got := PatchedRanges(context.Background(), pre, post, c)
	if !reflect.DeepEqual(got["lib/render.js"], [][2]int{{3, 4}}) {
		t.Fatalf("%v", got)
	}
	// A file that is identical has no patched lines.
	write(pre, "lib/render.js", "same\n")
	write(post, "lib/render.js", "same\n")
	if got := PatchedRanges(context.Background(), pre, post, c); len(got["lib/render.js"]) != 0 {
		t.Fatalf("%v", got)
	}
}
