package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/version"
	"github.com/ratomirjovanovic/pandaward/research/agent-safety/asl"
)

const defaultRuns = "research/agent-safety/runs"
const defaultLedger = "research/agent-safety/.local/budget.json"

func parseArms(s string) ([]asl.Arm, error) {
	var out []asl.Arm
	for _, p := range strings.Split(s, ",") {
		a := asl.Arm(strings.ToUpper(strings.TrimSpace(p)))
		switch a {
		case asl.ArmA, asl.ArmB, asl.ArmC, asl.ArmD:
			out = append(out, a)
		default:
			return nil, fmt.Errorf("unknown arm %q: use A, B, C or D", p)
		}
	}
	return out, nil
}

func labRun(args []string, w io.Writer) error {
	fs := newFlagSet("lab run")
	dir := fs.String("corpus", defaultCorpus, "corpus directory")
	out := fs.String("out", defaultRuns, "directory for run output")
	run := fs.String("run", "", "run id (required)")
	armsFlag := fs.String("arms", "A,B,C,D", "arms to run")
	reps := fs.Int("reps", 3, "repetitions of every scenario and arm")
	seed := fs.Int64("seed", 1, "seed for the episode order")
	split := fs.String("split", "all", "dev, heldout or all")
	provider := fs.String("provider", "mock", "mock (scripted agents) or api (a model, needs --live)")
	mock := fs.String("mock", "safe", "mock agent: safe or unsafe")
	model := fs.String("model", "claude-haiku-5-5", "model of the api provider")
	monitorModel := fs.String("monitor-model", "", "model of the arm D monitor (default: --model)")
	ledger := fs.String("ledger", defaultLedger, "budget ledger file (live runs)")
	keyFile := fs.String("key-file", "", "file with the API key (default: ~/.pandaward-lab/anthropic.key when ANTHROPIC_API_KEY is unset)")
	live := fs.Bool("live", false, "allow paid API calls; needs ANTHROPIC_API_KEY and the budget ledger")
	maxTurns := fs.Int("max-turns", 14, "model turns per episode")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *run == "" {
		return exitErr{2, "lab run needs --run ID"}
	}
	arms, err := parseArms(*armsFlag)
	if err != nil {
		return exitErr{2, err.Error()}
	}
	c, problems, err := asl.LoadCorpus(*dir)
	if err != nil {
		return exitErr{1, err.Error()}
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(w, "  "+p)
		}
		return exitErr{1, "the corpus is invalid: run pandaward lab validate"}
	}
	cfg := &asl.RunConfig{
		Corpus: c, Arms: arms, Reps: *reps, Seed: *seed, Split: *split, Provider: *provider, Mock: *mock,
		Model: *model, MonitorModel: *monitorModel, Run: *run, OutDir: *out,
		Limits: asl.DefaultEpisodeLimits(), MaxTurns: *maxTurns, Version: version.Version,
	}
	switch *provider {
	case asl.ProviderAPI:
		if !*live {
			return exitErr{2, "the api provider spends money: add --live to allow it (see research/agent-safety/BUDGET.md)"}
		}
		key, err := apiKey(*keyFile)
		if err != nil {
			return exitErr{2, err.Error()}
		}
		led, err := asl.OpenLedger(*ledger, asl.DefaultLimits())
		if err != nil {
			return exitErr{1, err.Error()}
		}
		cfg.Ledger, cfg.APIKey = led, key
		r := led.Report()
		fmt.Fprintf(w, "Live run on %s: %s spent of the %s cap so far.\n", *model, r.Spent.USD(), r.Cap.USD())
	case asl.ProviderMock:
		fmt.Fprintln(w, "Mock run: scripted agents, no model, no cost. Results are labeled mock.")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
	defer cancel()
	sum, err := asl.Execute(ctx, cfg)
	fmt.Fprintf(w, "Run %s: %d planned, %d already done, %d run now, %d invalid. Output: %s\n", *run, sum.Planned, sum.Done, sum.Ran, sum.Invalid, sum.Directory)
	if sum.Stopped != "" {
		fmt.Fprintln(w, "Stopped early: "+sum.Stopped)
	}
	if cfg.Ledger != nil {
		r := cfg.Ledger.Report()
		fmt.Fprintf(w, "Spent so far: %s of %s.\n", r.Spent.USD(), r.Cap.USD())
	}
	switch {
	case errors.Is(err, asl.ErrBudget):
		return exitErr{1, "the budget cap stopped the run; nothing was dropped. Report what was measured, or raise the ledger cap by editing that file on purpose"}
	case err != nil:
		return exitErr{1, err.Error()}
	}
	return nil
}

func labScore(args []string, w io.Writer) error {
	fs := newFlagSet("lab score")
	run := fs.String("run", "", "run directory (required)")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *run == "" {
		return exitErr{2, "lab score needs --run DIR"}
	}
	m, rs, err := asl.LoadRun(*run)
	if err != nil {
		return exitErr{1, err.Error()}
	}
	rep := asl.Score(rs)
	if *asJSON {
		return printJSON(w, struct {
			Manifest asl.Manifest `json:"manifest"`
			Report   asl.Report   `json:"report"`
		}{m, rep})
	}
	fmt.Fprintf(w, "Run %s (%s, %d of %d episodes)\n", m.Run, rep.Provider, len(rs), m.Planned)
	if rep.Provider == asl.ProviderMock {
		fmt.Fprintln(w, "MOCK results: scripted agents, they check the harness and say nothing about a model.")
	}
	fmt.Fprintf(w, "%-4s %9s %8s  %-28s %-28s %-28s\n", "arm", "episodes", "invalid", "attack success", "utility on controls", "false assurance")
	for _, a := range asl.Arms {
		c := rep.Arms[a]
		if c == nil {
			continue
		}
		fmt.Fprintf(w, "%-4s %9d %8d  %-28s %-28s %-28s\n", a, c.Total, c.Invalid, rateText(c.AttackSuccess), rateText(c.Utility), rateText(c.FalseAssurance))
	}
	return nil
}

func rateText(r asl.Rate) string {
	if r.N == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%% [%.0f-%.0f%%] %d/%d", 100*r.P, 100*r.Lo, 100*r.Hi, r.K, r.N)
}

func labReport(args []string, w io.Writer) error {
	fs := newFlagSet("lab report")
	run := fs.String("run", "", "run directory (required)")
	out := fs.String("out", "", "write the report to this file (default: stdout)")
	public := fs.Bool("public", false, "fail if the report contains anything that must not be published")
	ledger := fs.String("ledger", "", "budget ledger to report the spend from")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *run == "" {
		return exitErr{2, "lab report needs --run DIR"}
	}
	m, rs, err := asl.LoadRun(*run)
	if err != nil {
		return exitErr{1, err.Error()}
	}
	opt := asl.ReportOptions{Public: *public}
	if *ledger != "" {
		led, err := asl.OpenLedger(*ledger, asl.DefaultLimits())
		if err != nil {
			return exitErr{1, err.Error()}
		}
		r := led.Report()
		opt.Spend = &r
	}
	text, err := asl.Markdown(m, rs, opt)
	if err != nil {
		return exitErr{1, err.Error()}
	}
	if *out == "" {
		_, err = io.WriteString(w, text)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return exitErr{1, err.Error()}
	}
	if err := os.WriteFile(*out, []byte(text), 0o644); err != nil {
		return exitErr{1, err.Error()}
	}
	fmt.Fprintf(w, "Report written to %s\n", *out)
	return nil
}

// apiKey returns the API key for a live run: ANTHROPIC_API_KEY when set,
// else the key file. The value is never printed; errors name only the path.
func apiKey(path string) (string, error) {
	if k := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); k != "" {
		return checkKey(k, "ANTHROPIC_API_KEY")
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.New("no ANTHROPIC_API_KEY and no home directory for the key file; see research/agent-safety/BUDGET.md")
		}
		path = filepath.Join(home, ".pandaward-lab", "anthropic.key")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("no API key: ANTHROPIC_API_KEY is empty and the key file %s cannot be read; see research/agent-safety/BUDGET.md", path)
	}
	return checkKey(strings.TrimSpace(string(b)), "the key file "+path)
}

func checkKey(k, where string) (string, error) {
	if !strings.HasPrefix(k, "sk-ant-") || len(k) < 20 || strings.ContainsAny(k, " \t\r\n") {
		return "", fmt.Errorf("the API key in %s does not look like an Anthropic key (it should start with sk-ant-)", where)
	}
	return k, nil
}
