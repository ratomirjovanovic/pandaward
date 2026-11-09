package adapters

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/config"
)

// fakeTools puts empty executables with the given names on PATH.
func fakeTools(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		if runtime.GOOS == "windows" {
			n += ".exe"
		}
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
}

func semgrepTool(t *testing.T) *externalTool {
	t.Helper()
	tool, ok := semgrep().(*externalTool)
	if !ok {
		t.Fatal("semgrep adapter is not an external tool")
	}
	return tool
}

func semgrepArgs(t *testing.T, tool *externalTool, engine string) []string {
	t.Helper()
	cfg := config.Default("x")
	cfg.Scan.SemgrepEngine = engine
	c := &Context{Root: t.TempDir(), Cfg: cfg, ToolHome: t.TempDir()}
	tool.prefer = tool.choose(c)
	if _, err := tool.Lookup(); err != nil {
		t.Fatalf("lookup with engine %q: %v", engine, err)
	}
	args, err := tool.args(c, filepath.Join(t.TempDir(), "out.json"))
	if err != nil {
		t.Fatal(err)
	}
	return args
}

// Without a configured engine semgrep wins and opengrep is the fallback;
// opengrep runs with intra-file taint and without the --metrics flag it
// does not have.
func TestSemgrepEngineSelection(t *testing.T) {
	fakeTools(t, "semgrep", "opengrep")
	tool := semgrepTool(t)
	args := semgrepArgs(t, tool, "")
	if tool.found != "semgrep" || !slices.Contains(args, "--metrics=off") || slices.Contains(args, "--taint-intrafile") {
		t.Fatalf("default engine: found %q, args %v", tool.found, args)
	}
	args = semgrepArgs(t, tool, "opengrep")
	if tool.found != "opengrep" || slices.Contains(args, "--metrics=off") || !slices.Contains(args, "--taint-intrafile") {
		t.Fatalf("opengrep engine: found %q, args %v", tool.found, args)
	}

	fakeTools(t, "opengrep")
	tool = semgrepTool(t)
	semgrepArgs(t, tool, "")
	if tool.found != "opengrep" {
		t.Fatalf("fallback: found %q, want opengrep", tool.found)
	}

	tool.prefer = "semgrep"
	if _, err := tool.Lookup(); err == nil {
		t.Fatal("a configured engine that is not installed must not fall back")
	}
	if got := tool.binaries(); got != "semgrep" {
		t.Fatalf("binaries() = %q", got)
	}
}

func TestSemgrepEngineConfig(t *testing.T) {
	cfg := config.Default("x")
	cfg.Scan.SemgrepEngine = "codeql"
	if err := cfg.Validate(); err == nil {
		t.Fatal("an unknown engine must be rejected")
	}
}
