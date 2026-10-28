package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func TestBar(t *testing.T) {
	for _, c := range []struct {
		done, total int
		ascii       bool
		want        string
	}{
		{0, 10, true, "----------"},
		{5, 10, true, "#####-----"},
		{10, 10, true, "##########"},
		{1, 100, true, "#---------"},
		{12, 10, true, "##########"},
		{3, 0, true, "##########"},
		{5, 10, false, "█████░░░░░"},
	} {
		if got := bar(c.done, c.total, 10, c.ascii); got != c.want {
			t.Errorf("bar(%d, %d) = %q, want %q", c.done, c.total, got, c.want)
		}
	}
}

// One command takes a fresh project to reports, and the output written to
// a pipe has no terminal control sequences.
func TestAssessFromScratch(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	var out bytes.Buffer
	if err := cmdAssess(context.Background(), []string{"--root", root, "--ascii"}, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"by Ratomir Jovanovic", "100%", "Decisive coverage", "Fix first", "Reports", "/pandaward:review"} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.ContainsAny(s, "\r\x1b") {
		t.Error("output for a pipe contains carriage returns or escape sequences")
	}
	if strings.Contains(s, testfixture.FakeStripe) {
		t.Error("secret value in the summary")
	}
	reports, _ := filepath.Glob(filepath.Join(root, ".pandaward", "reports", "*.html"))
	if len(reports) != 1 {
		t.Fatalf("expected one HTML report, got %v", reports)
	}
	if _, err := os.Stat(filepath.Join(root, ".pandaward", "config.yaml")); err != nil {
		t.Fatal("assess did not initialize the project")
	}
	out.Reset()
	if err := cmdAssess(context.Background(), []string{"--root", root, "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out.String()), "{") || strings.Contains(out.String(), "Ratomir") {
		t.Fatalf("--json must print only JSON: %.200s", out.String())
	}
}
