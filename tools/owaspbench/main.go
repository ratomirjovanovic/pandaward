// Command owaspbench measures PandaWard on the OWASP Benchmark for Java
// (https://github.com/OWASP-Benchmark/BenchmarkJava) or for Python
// (https://github.com/OWASP-Benchmark/BenchmarkPython). It walks a local
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

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/version"
	"github.com/ratomirjovanovic/pandaward/rules"
	"github.com/ratomirjovanovic/pandaward/tools/internal/engines"
)

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
	suiteKey := flag.String("suite", "java", "benchmark: java or python")
	repo := flag.String("repo", "", "path to a checkout of the benchmark (required)")
	expected := flag.String("expected", "", "expected results file, relative to --repo (default: the suite's)")
	engineList := flag.String("engine", "builtin", "comma-separated engines to measure: "+strings.Join(engines.Names, ", "))
	asJSON := flag.Bool("json", false, "print JSON instead of a table")
	flag.Parse()
	if *repo == "" {
		fmt.Fprintln(os.Stderr, "usage: owaspbench [--suite java|python] --repo <checkout> [--engine builtin,semgrep,opengrep] [--json]")
		os.Exit(2)
	}
	suite := Suites[*suiteKey]
	if suite == nil {
		fmt.Fprintf(os.Stderr, "owaspbench: unknown suite %q; choose java or python\n", *suiteKey)
		os.Exit(2)
	}
	if *expected == "" {
		*expected = suite.Expected
	}
	sel, err := engines.Parse(*engineList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "owaspbench:", err)
		os.Exit(2)
	}
	out, err := measure(context.Background(), suite, *repo, *expected, sel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "owaspbench:", err)
		os.Exit(1)
	}
	if out.BenchmarkCommit != suite.PinnedCommit {
		fmt.Fprintf(os.Stderr, "warning: checkout is at %q, published numbers refer to %s\n", out.BenchmarkCommit, suite.PinnedCommit)
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

func measure(ctx context.Context, suite *Suite, repo, expectedPath string, selected []string) (*Output, error) {
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
	cfg := config.Default("owasp-benchmark-" + suite.Key)
	inv, err := inventory.Walk(repo, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles, IncludeIgnored: cfg.Inventory.IncludeIgnored})
	if err != nil {
		return nil, err
	}
	hash, err := rules.SemgrepHash()
	if err != nil {
		return nil, err
	}
	out := &Output{Benchmark: suite.Title, BenchmarkCommit: inv.GitCommit, PinnedCommit: suite.PinnedCommit, PandawardVersion: version.Version, SemgrepRulesHash: hash, ExpectedResults: expectedPath}
	for _, file := range inv.Files {
		if strings.HasPrefix(file.Path, suite.TestCodeDir+"/") && suite.TestCaseOf(file.Path) != "" {
			out.TestCaseFiles++
			if adapters.IsTestPath(file.Path) {
				out.TestPathExcluded++
			}
		}
	}
	if out.TestCaseFiles == 0 {
		return nil, fmt.Errorf("no test case files under %s; is %s a checkout of the %s?", suite.TestCodeDir, repo, suite.Title)
	}
	semgrepCovered, err := suite.SemgrepCoverage()
	if err != nil {
		return nil, err
	}
	var all, builtinFindings []Finding
	allCovered := map[string][]string{}
	ran, semgrepRan := 0, false
	for _, eng := range selected {
		run, err := engines.Measure(ctx, inv, eng)
		if err != nil {
			return nil, err
		}
		r := EngineResult{Engine: run.Engine, Version: run.Version, NotRun: run.NotRun, RuleCounts: map[string]int{}}
		var findings []Finding
		for _, f := range run.Findings {
			findings = append(findings, Finding{Rule: f.Rule, CWE: f.CWE, File: f.File, Line: f.Line})
			r.RuleCounts[f.Rule]++
		}
		covered := semgrepCovered
		if eng == "builtin" {
			covered = suite.CoveredCategories(adapters.RuleIDs())
		}
		if r.NotRun == "" {
			r.Score = suite.Compute(expected, findings, covered)
			if eng == "builtin" {
				builtinFindings = findings
			} else {
				semgrepRan = true
				all = append(all, findings...)
			}
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
		// As in a scan: built-in heuristics a bundled rule replaces do not
		// count once a semgrep engine has run.
		if semgrepRan {
			builtinFindings, err = withoutSuperseded(builtinFindings, inv)
			if err != nil {
				return nil, err
			}
		}
		all = append(all, builtinFindings...)
		out.Engines = append(out.Engines, EngineResult{Engine: "all", Score: suite.Compute(expected, all, allCovered)})
	}
	return out, nil
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
		if e.Version != "" && !strings.HasPrefix(e.Version, e.Engine) {
			name += " " + e.Version
		} else if e.Version != "" {
			name = e.Version
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

// withoutSuperseded drops built-in findings that a bundled Semgrep rule
// replaces in the finding's file language (adapters.Supersessions).
func withoutSuperseded(fs []Finding, inv *inventory.Inventory) ([]Finding, error) {
	sup, err := adapters.LoadSupersessions()
	if err != nil {
		return nil, err
	}
	var kept []Finding
	for _, f := range fs {
		file := inv.FileByPath(f.File)
		if file != nil && sup.By(model.Signal{RuleID: f.Rule, Collector: "builtin-code"}, file.Lang) != "" {
			continue
		}
		kept = append(kept, f)
	}
	return kept, nil
}
