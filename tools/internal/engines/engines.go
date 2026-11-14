// Package engines runs PandaWard's detection engines in process for the
// benchmark tools: the built-in adapters, and the bundled Semgrep rules on
// Semgrep or Opengrep through the same adapter `pandaward scan` uses.
package engines

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/version"
)

// Names are the engines that can be measured.
var Names = []string{"builtin", "semgrep", "opengrep", "taint"}

// Finding is the part of a signal the benchmarks score.
type Finding struct {
	Rule    string
	CWE     string
	File    string
	Line    int
	EndLine int
}

// Run is one engine's output on one tree.
type Run struct {
	Engine  string
	Version string
	// NotRun says why the engine did not run (not installed, blocked). Such
	// an engine has no result, which is not a result of zero.
	NotRun   string
	Findings []Finding
}

// Parse reads a comma-separated engine list.
func Parse(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		known := false
		for _, n := range Names {
			known = known || n == e
		}
		if !known {
			return nil, fmt.Errorf("unknown engine %q; choose from %s", e, strings.Join(Names, ", "))
		}
		seen[e] = true
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no engine selected")
	}
	return out, nil
}

// Walk builds the inventory of a tree with the default scan settings.
func Walk(root string) (*inventory.Inventory, error) {
	cfg := config.Default("benchmark")
	return inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles, IncludeIgnored: cfg.Inventory.IncludeIgnored})
}

// Measure runs one engine on an inventoried tree.
func Measure(ctx context.Context, inv *inventory.Inventory, engine string) (Run, error) {
	switch engine {
	case "builtin":
		return builtin(ctx, inv)
	case "taint":
		return taintEngine(ctx, inv)
	}
	return semgrep(ctx, inv, engine)
}

func builtin(ctx context.Context, inv *inventory.Inventory) (Run, error) {
	r := Run{Engine: "builtin", Version: version.Version}
	actx := &adapters.Context{Root: inv.Root, Inv: inv, Cfg: config.Default("benchmark")}
	for _, a := range adapters.Registry() {
		// Only the built-in adapters; the Semgrep rules and the taint
		// engine are measured as engines of their own.
		if !strings.HasPrefix(a.Name(), "builtin-") || a.Name() == "builtin-taint" {
			continue
		}
		res, run := a.Run(ctx, actx)
		if run.ExitClass != model.ExitOK {
			return r, fmt.Errorf("%s did not complete: %s %s", a.Name(), run.ExitClass, run.Detail)
		}
		r.Findings = append(r.Findings, findings(res.Signals)...)
	}
	return r, nil
}

// taintEngine runs the built-in taint engine (#347) alone.
func taintEngine(ctx context.Context, inv *inventory.Inventory) (Run, error) {
	r := Run{Engine: "taint", Version: version.Version}
	actx := &adapters.Context{Root: inv.Root, Inv: inv, Cfg: config.Default("benchmark")}
	for _, a := range adapters.Registry() {
		if a.Name() != "builtin-taint" {
			continue
		}
		res, run := a.Run(ctx, actx)
		if run.ExitClass != model.ExitOK {
			return r, fmt.Errorf("%s did not complete: %s %s", a.Name(), run.ExitClass, run.Detail)
		}
		r.Findings = findings(res.Signals)
	}
	return r, nil
}

// semgrep runs the bundled Semgrep rules on the given engine through the
// same adapter `pandaward scan` uses, with no project rules and no network.
func semgrep(ctx context.Context, inv *inventory.Inventory, engine string) (Run, error) {
	r := Run{Engine: engine}
	var tool adapters.Adapter
	for _, a := range adapters.Registry() {
		if a.Name() == "semgrep" {
			tool = a
		}
	}
	if tool == nil {
		return r, fmt.Errorf("semgrep adapter not registered")
	}
	cfg := config.Default("benchmark")
	cfg.Scan.SemgrepEngine = engine
	work, err := os.MkdirTemp("", "pwbench-")
	if err != nil {
		return r, err
	}
	defer os.RemoveAll(work)
	actx := &adapters.Context{Root: inv.Root, Inv: inv, Cfg: cfg, RunDir: work, ToolHome: filepath.Join(work, "home"), Timeout: 3 * time.Hour}
	res, run := tool.Run(ctx, actx)
	r.Version = run.ToolVersion
	switch run.ExitClass {
	case model.ExitOK:
	case model.ExitBlocked, model.ExitUnsupported:
		r.NotRun = run.Detail
		return r, nil
	default:
		return r, fmt.Errorf("%s did not complete: %s %s", engine, run.ExitClass, run.Detail)
	}
	r.Findings = findings(res.Signals)
	return r, nil
}

func findings(sigs []model.Signal) []Finding {
	out := make([]Finding, 0, len(sigs))
	for _, s := range sigs {
		end := s.EndLine
		if end < s.StartLine {
			end = s.StartLine
		}
		out = append(out, Finding{Rule: s.RuleID, CWE: s.CWE, File: filepath.ToSlash(s.File), Line: s.StartLine, EndLine: end})
	}
	return out
}
