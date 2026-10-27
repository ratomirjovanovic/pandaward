package benchmark

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pensec/internal/adapters"
	"github.com/ratomirjovanovic/pensec/internal/catalog"
	"github.com/ratomirjovanovic/pensec/internal/inventory"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/version"
)

// Thresholds a rule must meet on the corpus to count as benchmarked. A
// precision of 1.0 on two cases says little, so a minimum sample per label
// applies as well; rules below it are reported with their numbers but stay
// implemented_unvalidated.
const (
	MinPrecision = 0.95
	MinRecall    = 0.95
	MinCases     = 3
)

// RuleResult is the confusion matrix of one rule on the corpus.
type RuleResult struct {
	Rule       string   `json:"rule"`
	Vulnerable int      `json:"vulnerable_cases"`
	Safe       int      `json:"safe_cases"`
	TP         int      `json:"tp"`
	FP         int      `json:"fp"`
	FN         int      `json:"fn"`
	TN         int      `json:"tn"`
	Skipped    int      `json:"skipped"`
	Precision  float64  `json:"precision"`
	Recall     float64  `json:"recall"`
	Maturity   string   `json:"maturity"`
	Failures   []string `json:"failures,omitempty"`
}

// Report is the outcome of one benchmark run. It contains no timestamps or
// paths, so the same code and corpus always produce the same report.
type Report struct {
	CorpusVersion  string       `json:"corpus_version"`
	PensecVersion  string       `json:"pensec_version"`
	CatalogVersion string       `json:"catalog_version"`
	MinPrecision   float64      `json:"min_precision"`
	MinRecall      float64      `json:"min_recall"`
	MinCases       int          `json:"min_cases_per_label"`
	Rules          []RuleResult `json:"rules"`
	Benchmarked    int          `json:"rules_benchmarked"`
	Note           string       `json:"note"`
}

// Run evaluates every case of the corpus. Cases that need git are skipped
// when git is not installed; a skipped case keeps its rule unbenchmarked.
func Run(ctx context.Context) (*Report, error) {
	results := map[string]*RuleResult{}
	for _, id := range adapters.RuleIDs() {
		results[id] = &RuleResult{Rule: id}
	}
	_, gitErr := exec.LookPath("git")
	for i, c := range Corpus() {
		r := results[c.Rule]
		if r == nil {
			return nil, fmt.Errorf("corpus case %d names unknown rule %s", i, c.Rule)
		}
		if c.Vulnerable {
			r.Vulnerable++
		} else {
			r.Safe++
		}
		if c.Git && gitErr != nil {
			r.Skipped++
			continue
		}
		hit, err := runCase(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("%s case %d: %w", c.Rule, i, err)
		}
		label := "safe"
		if c.Vulnerable {
			label = "vulnerable"
		}
		switch {
		case c.Vulnerable && hit:
			r.TP++
		case c.Vulnerable:
			r.FN++
			r.Failures = append(r.Failures, fmt.Sprintf("missed %s case %s", label, describe(c)))
		case hit:
			r.FP++
			r.Failures = append(r.Failures, fmt.Sprintf("fired on %s case %s", label, describe(c)))
		default:
			r.TN++
		}
	}
	rep := &Report{CorpusVersion: CorpusVersion, PensecVersion: version.Version, CatalogVersion: catalog.Version, MinPrecision: MinPrecision, MinRecall: MinRecall, MinCases: MinCases,
		Note: "Measured on PenSec's own small corpus of vulnerable and safe cases. The numbers describe behavior on these cases, not real-world precision or recall."}
	ids := make([]string, 0, len(results))
	for id := range results {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := results[id]
		if r.TP+r.FP > 0 {
			r.Precision = float64(r.TP) / float64(r.TP+r.FP)
		}
		if r.TP+r.FN > 0 {
			r.Recall = float64(r.TP) / float64(r.TP+r.FN)
		}
		r.Maturity = adapters.MaturityUnvalidated
		if r.Vulnerable >= MinCases && r.Safe >= MinCases && r.Skipped == 0 && r.Precision >= MinPrecision && r.Recall >= MinRecall {
			r.Maturity = adapters.MaturityBenchmarked
			rep.Benchmarked++
		}
		rep.Rules = append(rep.Rules, *r)
	}
	return rep, nil
}

func describe(c Case) string {
	var names []string
	for n := range c.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	s := strings.Join(names, ", ")
	if c.Note != "" {
		s += " (" + c.Note + ")"
	}
	return s
}

// runCase writes the case to a temporary directory and reports whether the
// case's adapter emitted its rule.
func runCase(ctx context.Context, c Case) (bool, error) {
	ad := adapters.ByName(c.Adapter)
	if ad == nil {
		return false, fmt.Errorf("unknown adapter %s", c.Adapter)
	}
	root, err := os.MkdirTemp("", "pensec-bench-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(root)
	for rel, content := range c.Files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return false, err
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return false, err
		}
	}
	if c.Git {
		for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}, {"-c", "user.email=bench@example.org", "-c", "user.name=bench", "-c", "commit.gpgsign=false", "commit", "-qm", "case"}} {
			cmd := exec.CommandContext(ctx, "git", args...)
			cmd.Dir = root
			cmd.Env = append(inventory.MinimalEnv(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
			if out, err := cmd.CombinedOutput(); err != nil {
				return false, fmt.Errorf("git %s: %v: %s", args[0], err, out)
			}
		}
	}
	inv, err := inventory.Walk(root, inventory.Options{MaxFileBytes: 1 << 20, MaxFiles: 1000})
	if err != nil {
		return false, err
	}
	res, run := ad.Run(ctx, &adapters.Context{Root: root, Inv: inv})
	if run.ExitClass != model.ExitOK {
		return false, fmt.Errorf("%s did not complete: %s %s", c.Adapter, run.ExitClass, run.Detail)
	}
	for _, s := range res.Signals {
		if s.RuleID == c.Rule {
			return true, nil
		}
	}
	return false, nil
}
