// Command owaspbench measures PandaWard on the OWASP Benchmark for Java
// (https://github.com/OWASP-Benchmark/BenchmarkJava). It walks a local
// checkout with the same inventory settings as `pandaward scan`, runs the
// selected engines in process (the built-in adapters, and the bundled Semgrep
// rules on Semgrep or Opengrep through the same adapter a scan uses), maps
// each finding to a test case by file name and to a Benchmark category by rule
// or CWE, and prints TP, FP, FN, TN, TPR, FPR and the Benchmark score
// (TPR - FPR) per category and engine.
//
// The checkout is treated as data: nothing in it is built or executed. Use
// tools/owaspbench/run.sh to fetch the pinned commit into a temporary
// directory and run the measurement.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/version"
	"github.com/ratomirjovanovic/pandaward/rules"
)

// PinnedCommit is the BenchmarkJava commit the published numbers refer to.
// run.sh checks out the same commit.
const PinnedCommit = "f40c618c5a709afce350ef06ed2899c85cf586e9"

const testCodeDir = "src/main/java/org/owasp/benchmark/testcode"

// engineNames are the engines that can be measured. "all" in the output
// merges the findings of every engine that ran, counting a test case once.
var engineNames = []string{"builtin", "semgrep", "opengrep"}

// Output is the JSON document printed with --json.
type Output struct {
	Benchmark        string         `json:"benchmark"`
	BenchmarkCommit  string         `json:"benchmark_commit"`
	PinnedCommit     string         `json:"pinned_commit"`
	PandawardVersion string         `json:"pandaward_version"`
	SemgrepRulesHash string         `json:"semgrep_rules_sha256"`
	ExpectedResults  string         `json:"expected_results"`
	TestCaseFiles    int            `json:"test_case_files"`
	TestPathExcluded int            `json:"test_case_files_excluded_as_test_paths"`
	Engines          []EngineResult `json:"engines"`
}

// EngineResult is the measurement of one engine, or of all of them merged.
type EngineResult struct {
	Engine string `json:"engine"`
	// Version is the engine's version; for builtin, PandaWard's.
	Version string `json:"version,omitempty"`
	// NotRun says why the engine was not measured. Such an engine has no
	// score, which is not a score of zero.
	NotRun string `json:"not_run,omitempty"`
	// RuleCounts counts every finding by rule, wherever it was reported.
	RuleCounts map[string]int `json:"findings_by_rule,omitempty"`
	Score
}

func main() {
	repo := flag.String("repo", "", "path to a BenchmarkJava checkout (required)")
	expected := flag.String("expected", "expectedresults-1.2.csv", "expected results file, relative to --repo")
	engines := flag.String("engine", "builtin", "comma-separated engines to measure: "+strings.Join(engineNames, ", "))
	asJSON := flag.Bool("json", false, "print JSON instead of a table")
	flag.Parse()
	if *repo == "" {
		fmt.Fprintln(os.Stderr, "usage: owaspbench --repo <BenchmarkJava checkout> [--engine builtin,semgrep,opengrep] [--json]")
		os.Exit(2)
	}
	sel, err := parseEngines(*engines)
	if err != nil {
		fmt.Fprintln(os.Stderr, "owaspbench:", err)
		os.Exit(2)
	}
	out, err := measure(context.Background(), *repo, *expected, sel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "owaspbench:", err)
		os.Exit(1)
	}
	if out.BenchmarkCommit != PinnedCommit {
		fmt.Fprintf(os.Stderr, "warning: checkout is at %q, published numbers refer to %s\n", out.BenchmarkCommit, PinnedCommit)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	printTable(out)
}

func parseEngines(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		known := false
		for _, n := range engineNames {
			known = known || n == e
		}
		if !known {
			return nil, fmt.Errorf("unknown engine %q; choose from %s", e, strings.Join(engineNames, ", "))
		}
		seen[e] = true
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no engine selected")
	}
	return out, nil
}

func measure(ctx context.Context, repo, expectedPath string, engines []string) (*Output, error) {
	f, err := os.Open(filepath.Join(repo, expectedPath))
	if err != nil {
		return nil, err
	}
	expected, err := ParseExpected(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", expectedPath, err)
	}
	if len(expected) == 0 {
		return nil, fmt.Errorf("%s has no test cases", expectedPath)
	}
	cfg := config.Default("BenchmarkJava")
	inv, err := inventory.Walk(repo, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles, IncludeIgnored: cfg.Inventory.IncludeIgnored})
	if err != nil {
		return nil, err
	}
	hash, err := rules.SemgrepHash()
	if err != nil {
		return nil, err
	}
	out := &Output{Benchmark: "OWASP Benchmark for Java", BenchmarkCommit: inv.GitCommit, PinnedCommit: PinnedCommit, PandawardVersion: version.Version, SemgrepRulesHash: hash, ExpectedResults: expectedPath}
	for _, file := range inv.Files {
		if strings.HasPrefix(file.Path, testCodeDir+"/") && TestCaseOf(file.Path) != "" {
			out.TestCaseFiles++
			if adapters.IsTestPath(file.Path) {
				out.TestPathExcluded++
			}
		}
	}
	if out.TestCaseFiles == 0 {
		return nil, fmt.Errorf("no test case files under %s; is %s a BenchmarkJava checkout?", testCodeDir, repo)
	}
	semgrepCovered, err := SemgrepCoverage()
	if err != nil {
		return nil, err
	}
	var all []Finding
	allCovered := map[string][]string{}
	ran := 0
	for _, eng := range engines {
		var findings []Finding
		var r EngineResult
		var covered map[string][]string
		if eng == "builtin" {
			findings, r, err = runBuiltin(ctx, inv, cfg)
			covered = CoveredCategories(adapters.RuleIDs())
		} else {
			findings, r, err = runSemgrep(ctx, inv, eng)
			covered = semgrepCovered
		}
		if err != nil {
			return nil, err
		}
		if r.NotRun == "" {
			r.Score = Compute(expected, findings, covered)
			all = append(all, findings...)
			for c, rs := range covered {
				for _, r := range rs {
					if !slices.Contains(allCovered[c], r) {
						allCovered[c] = append(allCovered[c], r)
					}
				}
			}
			ran++
		}
		out.Engines = append(out.Engines, r)
	}
	if ran > 1 {
		out.Engines = append(out.Engines, EngineResult{Engine: "all", Score: Compute(expected, all, allCovered)})
	}
	return out, nil
}

func runBuiltin(ctx context.Context, inv *inventory.Inventory, cfg *config.Config) ([]Finding, EngineResult, error) {
	r := EngineResult{Engine: "builtin", Version: version.Version, RuleCounts: map[string]int{}}
	var findings []Finding
	actx := &adapters.Context{Root: inv.Root, Inv: inv, Cfg: cfg}
	for _, a := range adapters.Registry() {
		// Only the built-in adapters here; the Semgrep rules are their own
		// engines.
		if !strings.HasPrefix(a.Name(), "builtin-") {
			continue
		}
		res, run := a.Run(ctx, actx)
		if run.ExitClass != model.ExitOK {
			return nil, r, fmt.Errorf("%s did not complete: %s %s", a.Name(), run.ExitClass, run.Detail)
		}
		for _, s := range res.Signals {
			findings = append(findings, Finding{Rule: s.RuleID, CWE: s.CWE, File: s.File, Line: s.StartLine})
			r.RuleCounts[s.RuleID]++
		}
	}
	return findings, r, nil
}

// runSemgrep runs the bundled Semgrep rules on the given engine through the
// same adapter `pandaward scan` uses, with no project rules and no network.
func runSemgrep(ctx context.Context, inv *inventory.Inventory, engine string) ([]Finding, EngineResult, error) {
	r := EngineResult{Engine: engine, RuleCounts: map[string]int{}}
	var tool adapters.Adapter
	for _, a := range adapters.Registry() {
		if a.Name() == "semgrep" {
			tool = a
		}
	}
	if tool == nil {
		return nil, r, fmt.Errorf("semgrep adapter not registered")
	}
	cfg := config.Default("BenchmarkJava")
	cfg.Scan.SemgrepEngine = engine
	work, err := os.MkdirTemp("", "owaspbench-")
	if err != nil {
		return nil, r, err
	}
	defer os.RemoveAll(work)
	actx := &adapters.Context{Root: inv.Root, Inv: inv, Cfg: cfg, RunDir: work, ToolHome: filepath.Join(work, "home"), Timeout: 3 * time.Hour}
	res, run := tool.Run(ctx, actx)
	r.Version = run.ToolVersion
	switch run.ExitClass {
	case model.ExitOK:
	case model.ExitBlocked, model.ExitUnsupported:
		r.NotRun = run.Detail
		return nil, r, nil
	default:
		return nil, r, fmt.Errorf("%s did not complete: %s %s", engine, run.ExitClass, run.Detail)
	}
	var findings []Finding
	for _, s := range res.Signals {
		findings = append(findings, Finding{Rule: s.RuleID, CWE: s.CWE, File: s.File, Line: s.StartLine})
		r.RuleCounts[s.RuleID]++
	}
	return findings, r, nil
}

func printTable(o *Output) {
	commit := o.BenchmarkCommit
	if commit == "" {
		commit = "unknown (not a git checkout)"
	}
	fmt.Printf("%s at %s\n", o.Benchmark, commit)
	fmt.Printf("PandaWard %s, bundled Semgrep rules sha256 %s\n", o.PandawardVersion, o.SemgrepRulesHash)
	fmt.Printf("%d test case files, %d of them excluded as test paths\n", o.TestCaseFiles, o.TestPathExcluded)
	for _, e := range o.Engines {
		fmt.Println()
		if e.NotRun != "" {
			fmt.Printf("== %s: not run (%s)\n", e.Engine, e.NotRun)
			continue
		}
		name := e.Engine
		if e.Version != "" {
			name += " " + e.Version
		}
		if e.Engine == "all" {
			name = "all engines merged (a test case counts once)"
		}
		fmt.Printf("== %s\n", name)
		fmt.Printf("%d labelled test cases; %d findings: %d in test cases (%d of another category), %d elsewhere\n\n", e.TestCases, e.Findings, e.FindingsInTests, e.OffCategory, e.FindingsElsewhere+e.UnknownTestCases)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "CATEGORY\tCWE\tREAL\tNOT REAL\tTP\tFP\tFN\tTN\tTPR\tFPR\tSCORE\tRULES")
		for _, r := range e.Categories {
			if !r.Covered {
				fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t-\t-\t-\t-\t-\t-\tnot covered\t-\n", r.Category, r.CWE, r.Real, r.NotReal)
				continue
			}
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%+.3f\t%s\n", r.Category, r.CWE, r.Real, r.NotReal, r.TP, r.FP, r.FN, r.TN, r.TPR, r.FPR, r.Score, strings.Join(r.Rules, ","))
		}
		tw.Flush()
		fmt.Printf("\naverage score over covered categories: %+.3f\n", e.AverageCovered)
		fmt.Printf("average score over all %d categories (not covered = 0, as the OWASP scorecard averages): %+.3f\n", len(e.Categories), e.AverageAll)
	}
}
