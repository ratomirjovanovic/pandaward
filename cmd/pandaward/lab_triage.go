package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ratomirjovanovic/pandaward/research/agent-safety/asl"
)

// labTriage runs or scores the triage track: an agent judges labelled
// findings from an owaspbench --emit-findings file.
func labTriage(args []string, w io.Writer) error {
	if len(args) == 0 {
		return exitErr{2, "usage: pandaward lab triage run|score [flags]"}
	}
	mode, rest := args[0], args[1:]
	if mode == "-h" || mode == "--help" {
		mode, rest = "run", args
	}
	if mode != "run" && mode != "score" {
		return exitErr{2, "usage: pandaward lab triage run|score [flags]"}
	}
	fs := newFlagSet("lab triage " + mode)
	findings := fs.String("findings", "", "labelled findings (owaspbench --emit-findings)")
	checkout := fs.String("checkout", "", "checkout of the benchmark the findings come from")
	engine := fs.String("engine", "builtin", "engine whose findings are judged")
	held := fs.Bool("held-out", false, "use the held-out split (one case in five, fixed by the case name); keep it for the final run")
	n := fs.Int("n", 30, "findings per label")
	seed := fs.Int64("seed", 1, "sample seed")
	model := fs.String("model", "sonnet", "Claude Code model alias")
	claude := fs.String("claude", "claude", "claude executable")
	parallel := fs.Int("parallel", 3, "concurrent judgments")
	out := fs.String("out", "", "records file (JSON lines)")
	if _, err := parse(fs, rest); err != nil {
		return err
	}
	if *out == "" {
		return exitErr{2, "--out is required"}
	}
	if mode == "score" {
		recs, err := asl.LoadTriageRecords(*out)
		if err != nil {
			return err
		}
		arms, invalid := asl.ScoreTriage(recs)
		fmt.Fprintf(w, "Triage of %d findings (%d invalid, counted and never dropped)\n", len(recs), invalid)
		fmt.Fprintf(w, "%-24s %-26s %-26s %-26s\n", "arm", "precision of what is shown", "true findings still shown", "false positives removed")
		f := func(r asl.Rate) string {
			return fmt.Sprintf("%.0f%% [%.0f-%.0f%%] %d/%d", r.P*100, r.Lo*100, r.Hi*100, r.K, r.N)
		}
		for _, a := range arms {
			fmt.Fprintf(w, "%-24s %-26s %-26s %-26s\n", a.Name, f(a.Precision()), f(a.Recall()), f(a.FPRemoved()))
		}
		return nil
	}
	if *findings == "" || *checkout == "" {
		return exitErr{2, "--findings and --checkout are required"}
	}
	samples, err := asl.LoadTriageSamples(*findings, *engine, *held, *n, *seed)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Triage on the Claude Code subscription: %d findings (engine %s, %s split). Results are labeled cc.\n", len(samples), *engine, map[bool]string{false: "development", true: "held-out"}[*held])
	cfg := asl.TriageConfig{CC: asl.CCConfig{Claude: *claude, Model: *model, Timeout: 3 * time.Minute}, Checkout: *checkout, Out: *out, Parallel: *parallel}
	if err := asl.RunTriage(context.Background(), cfg, samples); err != nil {
		if errors.Is(err, asl.ErrUsageLimit) {
			return exitErr{3, "the subscription limit was reached; run the same command later to resume"}
		}
		return err
	}
	return nil
}
