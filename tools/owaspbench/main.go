// Command owaspbench measures Pandaward's built-in rules on the OWASP Benchmark
// for Java (https://github.com/OWASP-Benchmark/BenchmarkJava). It walks a
// local checkout with the same inventory settings as `pandaward scan`, runs the
// built-in adapters in process, maps each finding to a test case by file name
// and to a Benchmark category by rule or CWE, and prints TP, FP, FN, TN, TPR,
// FPR and the Benchmark score (TPR - FPR) per category.
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
	"strings"
	"text/tabwriter"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/version"
)

// PinnedCommit is the BenchmarkJava commit the published numbers refer to.
// run.sh checks out the same commit.
const PinnedCommit = "f40c618c5a709afce350ef06ed2899c85cf586e9"

const testCodeDir = "src/main/java/org/owasp/benchmark/testcode"

// Output is the JSON document printed with --json.
type Output struct {
	Benchmark        string `json:"benchmark"`
	BenchmarkCommit  string `json:"benchmark_commit"`
	PinnedCommit     string `json:"pinned_commit"`
	PandawardVersion string `json:"pandaward_version"`
	ExpectedResults  string `json:"expected_results"`
	TestCaseFiles    int    `json:"test_case_files"`
	TestPathExcluded int    `json:"test_case_files_excluded_as_test_paths"`
	// RuleCounts counts every finding by rule, wherever it was reported.
	RuleCounts map[string]int `json:"findings_by_rule"`
	Score
}

func main() {
	repo := flag.String("repo", "", "path to a BenchmarkJava checkout (required)")
	expected := flag.String("expected", "expectedresults-1.2.csv", "expected results file, relative to --repo")
	asJSON := flag.Bool("json", false, "print JSON instead of a table")
	flag.Parse()
	if *repo == "" {
		fmt.Fprintln(os.Stderr, "usage: owaspbench --repo <BenchmarkJava checkout> [--json]")
		os.Exit(2)
	}
	out, err := measure(context.Background(), *repo, *expected)
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

func measure(ctx context.Context, repo, expectedPath string) (*Output, error) {
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
	inv, err := inventory.Walk(repo, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles})
	if err != nil {
		return nil, err
	}
	out := &Output{Benchmark: "OWASP Benchmark for Java", BenchmarkCommit: inv.GitCommit, PinnedCommit: PinnedCommit, PandawardVersion: version.Version, ExpectedResults: expectedPath}
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
	var findings []Finding
	out.RuleCounts = map[string]int{}
	actx := &adapters.Context{Root: inv.Root, Inv: inv, Cfg: cfg}
	for _, a := range adapters.Registry() {
		// Only the built-in adapters: optional third-party scanners are not
		// part of what this measures.
		if !strings.HasPrefix(a.Name(), "builtin-") {
			continue
		}
		res, run := a.Run(ctx, actx)
		if run.ExitClass != model.ExitOK {
			return nil, fmt.Errorf("%s did not complete: %s %s", a.Name(), run.ExitClass, run.Detail)
		}
		for _, s := range res.Signals {
			findings = append(findings, Finding{Rule: s.RuleID, CWE: s.CWE, File: s.File, Line: s.StartLine})
			out.RuleCounts[s.RuleID]++
		}
	}
	out.Score = Compute(expected, findings, CoveredCategories(adapters.RuleIDs()))
	return out, nil
}

func printTable(o *Output) {
	commit := o.BenchmarkCommit
	if commit == "" {
		commit = "unknown (not a git checkout)"
	}
	fmt.Printf("%s at %s\n", o.Benchmark, commit)
	fmt.Printf("Pandaward %s, built-in rules only\n", o.PandawardVersion)
	fmt.Printf("%d labelled test cases, %d test case files, %d of them excluded as test paths\n", o.TestCases, o.TestCaseFiles, o.TestPathExcluded)
	fmt.Printf("%d findings: %d in test cases (%d of another category), %d elsewhere\n\n", o.Findings, o.FindingsInTests, o.OffCategory, o.FindingsElsewhere+o.UnknownTestCases)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CATEGORY\tCWE\tREAL\tNOT REAL\tTP\tFP\tFN\tTN\tTPR\tFPR\tSCORE\tRULES")
	for _, r := range o.Categories {
		if !r.Covered {
			fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t-\t-\t-\t-\t-\t-\tnot covered\t-\n", r.Category, r.CWE, r.Real, r.NotReal)
			continue
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%+.3f\t%s\n", r.Category, r.CWE, r.Real, r.NotReal, r.TP, r.FP, r.FN, r.TN, r.TPR, r.FPR, r.Score, strings.Join(r.Rules, ","))
	}
	tw.Flush()
	fmt.Printf("\naverage score over covered categories: %+.3f\n", o.AverageCovered)
	fmt.Printf("average score over all %d categories (not covered = 0, as the OWASP scorecard averages): %+.3f\n", len(o.Categories), o.AverageAll)
}
