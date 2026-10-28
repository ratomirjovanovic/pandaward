package benchmark

import (
	"context"
	"os/exec"
	"reflect"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
)

// Every built-in rule has at least one vulnerable and one safe case, and on
// the corpus every rule fires exactly where it should.
func TestCorpusCoversEveryRuleAndPasses(t *testing.T) {
	rep, err := Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Rules) != len(adapters.RuleIDs()) {
		t.Fatalf("report has %d rules, adapters emit %d", len(rep.Rules), len(adapters.RuleIDs()))
	}
	_, gitErr := exec.LookPath("git")
	for _, r := range rep.Rules {
		if r.Vulnerable == 0 || r.Safe == 0 {
			t.Errorf("%s needs at least one vulnerable and one safe case (has %d/%d)", r.Rule, r.Vulnerable, r.Safe)
		}
		for _, f := range r.Failures {
			t.Errorf("%s: %s", r.Rule, f)
		}
		if r.Skipped > 0 && gitErr == nil {
			t.Errorf("%s: cases skipped although git is installed", r.Rule)
		}
	}
}

func TestReportIsReproducible(t *testing.T) {
	a, err := Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Run(context.Background())
	if !reflect.DeepEqual(a, b) {
		t.Fatal("two runs on the same corpus gave different reports")
	}
}

// Maturity follows the thresholds exactly, including the minimum sample.
func TestMaturityFollowsThresholds(t *testing.T) {
	rep, err := Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rep.Rules {
		want := adapters.MaturityUnvalidated
		if r.Vulnerable >= MinCases && r.Safe >= MinCases && r.Skipped == 0 && r.Precision >= MinPrecision && r.Recall >= MinRecall {
			want = adapters.MaturityBenchmarked
			n++
		}
		if r.Maturity != want {
			t.Errorf("%s: maturity %s, want %s", r.Rule, r.Maturity, want)
		}
	}
	if rep.Benchmarked != n {
		t.Errorf("benchmarked count %d, want %d", rep.Benchmarked, n)
	}
}
