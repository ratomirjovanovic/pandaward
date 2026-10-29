// Command pandaward is the Pandaward CLI: local, evidence-based application
// security assessment. Passive local analysis is the default; anything that
// sends network traffic requires a scope manifest approved by a human in an
// interactive terminal.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/adversarial"
	"github.com/ratomirjovanovic/pandaward/internal/benchmark"
	"github.com/ratomirjovanovic/pandaward/internal/bundle"
	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/evidence"
	"github.com/ratomirjovanovic/pandaward/internal/feedback"
	"github.com/ratomirjovanovic/pandaward/internal/hooks"
	"github.com/ratomirjovanovic/pandaward/internal/mcp"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/report"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/store"
	"github.com/ratomirjovanovic/pandaward/internal/telemetry"
	"github.com/ratomirjovanovic/pandaward/internal/version"
	"github.com/ratomirjovanovic/pandaward/internal/zap"
)

const usage = `pandaward - local, evidence-based application security assessment

Usage: pandaward <command> [flags]

Assessment (local, no target network traffic):
  assess          Run the whole local assessment in one step: init if needed, scan with progress,
                  reports and a summary (start here)
  init            Create .pandaward/ (config, private ledger) in the project root
  plan            Show applicable controls, gates and missing prerequisites
  scan            Run the passive local scan (inventory, static checks, adapters)
  retest          Show files changed since the last scan, re-scan, show the delta
                  (--changed re-runs only adapters for impacted controls)
  status          Resumable state, coverage, blockers and next action
  findings        List/show findings; human triage: false-positive, accept-risk, reopen, confirm
  graph           Cross-domain edges (text or --format mermaid)
  routes          Discovered entrypoints (HTTP, GraphQL, gRPC, workers, cron) with file:line
  fix-plan        Ordered remediation plan from open findings
  report          Render HTML, Markdown, JSON, SARIF and CSV reports
  evidence        show <id> | verify
  diff            [FROM TO] findings new, reopened, remediated, stale, waived between assessments
  export          --bundle out.zip [--assessment ID] redacted evidence, report and SHA-256 manifest
  verify-bundle   <bundle.zip> recompute and check every hash in a bundle
  events          Recent audit events
  feedback        Report a false positive or a missed issue to the project (prints a prefilled issue link; sends nothing)

Network-active (human authorization required):
  scope           init | show | validate | approve --by <name> | revoke
  test            --profile production-observe  (passive header/TLS review of approved origins)
                  --profile staging-active      (ZAP spider and passive scan, active scan if the manifest allows)

Integration and tooling:
  doctor          Environment, optional scanners and their network needs
  capabilities    Control catalog with adapter maturity
  telemetry       Opt-in usage counters: status, on, off, show (off by default)
  benchmark       TP/FP/FN/TN per built-in rule on the bundled corpus (--json, --strict)
  selftest        Run the hostile-repository suite: can repository text steer Pandaward? (--json)
  mcp             Serve the MCP stdio interface
  hook <name>     Claude Code lifecycle hook (session-start, post-edit, pre-tool, pre-compact, stop)
  version         Print version

Global flag: --root <dir>  project directory (default: current directory or nearest parent with .pandaward/)
Exit codes: 0 ok, 1 error, 2 usage, 3 not authorized, 4 --fail-on threshold reached
`

type exitErr struct {
	code int
	msg  string
}

func (e exitErr) Error() string { return e.msg }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(stdout, "pandaward", version.Version, "catalog", catalog.Version)
	case "hook":
		if len(rest) != 1 {
			return 2
		}
		return hooks.Run(rest[0], stdin, stdout)
	case "mcp":
		err = cmdMCP(ctx, rest, stdin, stdout)
	case "assess":
		err = cmdAssess(ctx, rest, stdout)
	case "init":
		err = cmdInit(rest, stdout)
	case "plan":
		err = cmdPlan(rest, stdout)
	case "scan":
		err = cmdScan(ctx, rest, stdout, stderr, false)
	case "retest":
		err = cmdScan(ctx, rest, stdout, stderr, true)
	case "status":
		err = cmdStatus(rest, stdout)
	case "findings":
		err = cmdFindings(rest, stdout)
	case "graph":
		err = cmdGraph(rest, stdout)
	case "routes":
		err = cmdRoutes(rest, stdout)
	case "fix-plan":
		err = cmdFixPlan(rest, stdout)
	case "report":
		err = cmdReport(rest, stdout)
	case "evidence":
		err = cmdEvidence(rest, stdout)
	case "diff":
		err = cmdDiff(rest, stdout)
	case "export":
		err = cmdExport(rest, stdout)
	case "verify-bundle":
		err = cmdVerifyBundle(rest, stdout)
	case "events":
		err = cmdEvents(rest, stdout)
	case "feedback":
		err = cmdFeedback(rest, stdout)
	case "scope":
		err = cmdScope(rest, stdin, stdout)
	case "test":
		err = cmdTest(ctx, rest, stdout, stderr)
	case "doctor":
		err = cmdDoctor(ctx, rest, stdout)
	case "benchmark":
		err = cmdBenchmark(ctx, rest, stdout)
	case "selftest":
		err = cmdSelftest(ctx, rest, stdout)
	case "capabilities":
		err = cmdCapabilities(rest, stdout)
	case "telemetry":
		err = cmdTelemetry(rest, stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if cmd != "mcp" && cmd != "telemetry" {
		root, _ := engine.FindRoot(rootArg(rest))
		telemetry.Record("cli", cmd, root)
		telemetry.Flush(ctx)
	}
	if err != nil {
		var ee exitErr
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(stderr, "pandaward:", ee.msg)
			}
			return ee.code
		}
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "pandaward:", redact.Line(err.Error()))
		return 1
	}
	return 0
}

// parse parses flags that may be interspersed with positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func newFS(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	root := fs.String("root", "", "project directory")
	return fs, root
}

func openProject(root string) (*engine.Engine, error) {
	if root == "" {
		root = "."
	}
	r, err := engine.FindRoot(root)
	if err != nil {
		return nil, err
	}
	return engine.Open(r)
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func cmdMCP(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	fs, root := newFS("mcp")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	// Unresolved ${...} placeholders or missing directories fall back to the
	// working directory, which Claude Code sets to the project.
	r := "."
	for _, c := range []string{*root, config.Env("PROJECT_DIR"), os.Getenv("CLAUDE_PROJECT_DIR")} {
		if c == "" || strings.Contains(c, "${") {
			continue
		}
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			r = c
			break
		}
	}
	return (&mcp.Server{Root: r}).Serve(ctx, stdin, stdout)
}

func cmdInit(args []string, w io.Writer) error {
	fs, root := newFS("init")
	force := fs.Bool("force", false, "overwrite existing config.yaml")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	r := *root
	if r == "" {
		r = "."
	}
	e, created, err := engine.Init(r, *force)
	if err != nil {
		return err
	}
	defer e.Close()
	inv, err := e.Inventory()
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(w, "Initialized Pandaward in %s\n", filepath.Join(e.Root, config.Dir))
	} else {
		fmt.Fprintf(w, "Pandaward already initialized in %s\n", filepath.Join(e.Root, config.Dir))
	}
	fmt.Fprintf(w, "  config:   %s (safe to commit)\n  private:  %s (gitignored ledger and evidence)\n", config.Path(e.Root), config.PrivateDir(e.Root))
	fmt.Fprintf(w, "  profile:  local-passive (no network traffic to any target)\n\n")
	fmt.Fprintf(w, "Inventory: %d text files, %d assets", len(inv.Files), len(inv.Assets))
	if inv.GitCommit != "" {
		fmt.Fprintf(w, ", git %s", inv.GitCommit[:min(12, len(inv.GitCommit))])
		if inv.GitDirty {
			fmt.Fprint(w, " (dirty)")
		}
	}
	fmt.Fprintln(w)
	var langs []string
	for l, n := range inv.Languages {
		langs = append(langs, fmt.Sprintf("%s:%d", l, n))
	}
	sort.Strings(langs)
	fmt.Fprintf(w, "Languages: %s\n", strings.Join(langs, " "))
	var feats []string
	for f, p := range inv.Features {
		if f != "any" && f != "code" {
			feats = append(feats, fmt.Sprintf("%s(%d)", f, len(p)))
		}
	}
	sort.Strings(feats)
	fmt.Fprintf(w, "Detected: %s\n", strings.Join(feats, " "))
	if len(inv.SensitiveNames) > 0 {
		fmt.Fprintf(w, "Sensitive files recorded by name only (content not read): %d\n", len(inv.SensitiveNames))
	}
	if len(inv.Skipped) > 0 {
		fmt.Fprintf(w, "Skipped: %d (see `pandaward plan`)\n", len(inv.Skipped))
	}
	fmt.Fprintln(w, "\nNext: pandaward plan, then pandaward scan")
	return nil
}

func cmdPlan(args []string, w io.Writer) error {
	fs, root := newFS("plan")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	inv, err := e.Inventory()
	if err != nil {
		return err
	}
	plan := e.Plan(inv)
	edges := engine.BuildEdges(inv, nil)
	if *asJSON {
		return printJSON(w, map[string]any{"controls": plan, "candidate_edges": edges, "skipped_files": inv.Skipped})
	}
	counts := map[model.Status]int{}
	for _, p := range plan {
		counts[p.Status]++
	}
	fmt.Fprintf(w, "Plan for %s (catalog %s, profile local-passive)\n\n", e.Cfg.Project.Name, catalog.Version)
	cur := ""
	for _, p := range plan {
		if p.Control.Domain != cur {
			cur = p.Control.Domain
			fmt.Fprintf(w, "\n%s  %s\n", cur, catalog.DomainName(cur))
		}
		fmt.Fprintf(w, "  %-6s %-15s %s\n         %s\n", p.Control.ID, p.Status, p.Control.Title, p.Reason)
	}
	fmt.Fprintf(w, "\nSummary: %d planned, %d blocked (manual or authorization), %d unsupported (runtime not implemented), %d not applicable\n",
		counts["PLANNED"], counts[model.StatusBlocked], counts[model.StatusUnsupported], counts[model.StatusNotApplicable])
	fmt.Fprintf(w, "Candidate cross-domain edges (status decided after scan): ")
	var ids []string
	for _, e := range edges {
		ids = append(ids, e.ID)
	}
	fmt.Fprintln(w, strings.Join(ids, ", "))
	if len(inv.Skipped) > 0 {
		fmt.Fprintf(w, "\nInventory gaps (%d):\n", len(inv.Skipped))
		for i, s := range inv.Skipped {
			if i == 20 {
				fmt.Fprintf(w, "  ... %d more\n", len(inv.Skipped)-20)
				break
			}
			fmt.Fprintln(w, "  "+redact.Line(s))
		}
	}
	fmt.Fprintln(w, "\nNot-applicable decisions are automatic from the inventory; review them before relying on the report.")
	return nil
}

func failOn(e *engine.Engine, level string) error {
	if level == "" || level == "none" {
		return nil
	}
	min := model.SeverityRank(model.Severity(level))
	if min == 0 {
		return exitErr{2, "--fail-on must be critical, high, medium, low or none"}
	}
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		return err
	}
	n := 0
	for _, f := range fs {
		if f.Status.Active() && f.Confidence != model.Hypothesis && model.SeverityRank(f.Severity) >= min {
			n++
		}
	}
	if n > 0 {
		return exitErr{4, fmt.Sprintf("release gate: %d open confirmed finding(s) at or above %s", n, level)}
	}
	return nil
}

func cmdScan(ctx context.Context, args []string, w, ew io.Writer, retest bool) error {
	name := "scan"
	if retest {
		name = "retest"
	}
	fs, root := newFS(name)
	asJSON := fs.Bool("json", false, "JSON output")
	quiet := fs.Bool("quiet", false, "no progress output")
	failLevel := fs.String("fail-on", "", "exit 4 if open confirmed findings at or above this severity exist (critical|high|medium|low)")
	mode := fs.String("mode", "passive", "scan mode; only passive is supported here (use `pandaward test` for runtime profiles)")
	var onlyChanged *bool
	if retest {
		onlyChanged = fs.Bool("changed", false, "re-run only adapters whose inputs changed; carry over the rest")
	}
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *mode != "passive" {
		return exitErr{2, "scan supports --mode passive only; runtime profiles run through `pandaward test`"}
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	progress := func(m string) {
		if !*quiet && !*asJSON {
			fmt.Fprintln(ew, "·", m)
		}
	}
	var changed []string
	var res *engine.ScanResult
	if retest {
		changed, res, err = e.RetestChanged(ctx, progress, *onlyChanged)
	} else {
		res, err = e.Scan(ctx, progress)
	}
	if err != nil {
		return err
	}
	if retest && !*asJSON {
		fmt.Fprintf(w, "Files changed since the last assessment: %d\n", len(changed))
		for i, c := range changed {
			if i == 30 {
				fmt.Fprintf(w, "  ... %d more\n", len(changed)-30)
				break
			}
			fmt.Fprintln(w, "  "+redact.Line(c))
		}
		carried := 0
		for _, r := range res.Runs {
			if r.ExitClass == model.ExitCarried {
				carried++
			}
		}
		if carried > 0 {
			fmt.Fprintf(w, "Only the adapters for impacted controls were re-run; %d adapter(s) CARRIED from the previous assessment. Edges were recomputed.\n", carried)
		} else if *onlyChanged {
			fmt.Fprintln(w, "No adapter could be carried over, so every applicable adapter was re-run.")
		} else {
			fmt.Fprintln(w, "The full passive scan was re-run so dependent controls and edges were re-evaluated.")
		}
	}
	if *asJSON {
		out := map[string]any{"scan": res}
		if retest {
			out["changed_files"] = changed
		}
		if err := printJSON(w, out); err != nil {
			return err
		}
		return failOn(e, *failLevel)
	}
	fmt.Fprintf(w, "\nAssessment %s: %s\n", res.AssessmentID, res.Status)
	fmt.Fprintln(w, "Adapters:")
	for _, r := range res.Runs {
		fmt.Fprintf(w, "  %-18s %-10s %3d signals  %s\n", r.Adapter, r.ExitClass, r.SignalsCount, r.Detail)
	}
	var st []string
	for k, v := range res.Controls {
		st = append(st, fmt.Sprintf("%s %d", k, v))
	}
	sort.Strings(st)
	fmt.Fprintf(w, "Controls: %s\n", strings.Join(st, ", "))
	fmt.Fprintf(w, "Decisive coverage: %d/%d applicable controls (%.0f%%). Edges: %d (%d verified, %d failed, %d open)\n",
		res.Coverage.Decisive, res.Coverage.Applicable, res.Coverage.Ratio*100, res.Coverage.EdgesTotal, res.Coverage.EdgesVerified, res.Coverage.EdgesFailed, res.Coverage.EdgesOpen)
	fmt.Fprintf(w, "Findings: %d open (%d new, %d reopened, %d remediated in this run)\n", res.Open, res.New, res.Reopened, res.Remediated)
	if len(res.Errors) > 0 {
		fmt.Fprintln(w, "Errors (coverage is INCOMPLETE, not clean):")
		for _, e := range res.Errors {
			fmt.Fprintln(w, "  "+e)
		}
	}
	fmt.Fprintln(w, "\nBLOCKED/UNSUPPORTED/SUSPECTED controls are not secure; see `pandaward status` and `pandaward findings`.")
	return failOn(e, *failLevel)
}

func cmdStatus(args []string, w io.Writer) error {
	fs, root := newFS("status")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	s, err := e.Status()
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(w, s)
	}
	fmt.Fprintf(w, "Project: %s\n", s.Project)
	if s.Assessment == nil {
		fmt.Fprintln(w, "No completed assessment.")
	} else {
		fmt.Fprintf(w, "Latest assessment: %s (%s) started %s\n", s.Assessment.ID, s.Assessment.Status, s.Assessment.StartedAt)
		fmt.Fprintf(w, "Decisive coverage: %d/%d (%.0f%%); edges %d (%d verified, %d failed, %d open)\n", s.Coverage.Decisive, s.Coverage.Applicable, s.Coverage.Ratio*100,
			s.Coverage.EdgesTotal, s.Coverage.EdgesVerified, s.Coverage.EdgesFailed, s.Coverage.EdgesOpen)
		fmt.Fprintf(w, "Open findings: %d confirmed, %d suspected  %v\n", s.Confirmed, s.Suspected, s.Findings)
	}
	if len(s.StaleFiles) > 0 {
		outside := map[string]bool{}
		for _, f := range s.ChangedOutside {
			outside[f] = true
		}
		fmt.Fprintf(w, "Stale files (%d):\n", len(s.StaleFiles))
		for _, f := range s.StaleFiles {
			if outside[f] {
				fmt.Fprintln(w, "  "+redact.Line(f)+"  (changed outside Claude Code)")
			} else {
				fmt.Fprintln(w, "  "+redact.Line(f))
			}
		}
		if len(s.StaleControls) > 0 {
			fmt.Fprintf(w, "Stale controls (%d, not decisive until retest): %s\n", len(s.StaleControls), strings.Join(s.StaleControls, ", "))
		}
	}
	if s.ChangeCheck != "" {
		fmt.Fprintln(w, redact.Line(s.ChangeCheck))
	}
	if len(s.Blockers) > 0 {
		fmt.Fprintln(w, "Blockers:")
		for _, b := range s.Blockers {
			fmt.Fprintln(w, "  "+b)
		}
	}
	fmt.Fprintln(w, "Next:", s.NextAction)
	return nil
}

func cmdFindings(args []string, w io.Writer) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs, root := newFS("findings")
	asJSON := fs.Bool("json", false, "JSON output")
	all := fs.Bool("all", false, "include closed findings")
	by := fs.String("by", "", "reviewer name (triage)")
	note := fs.String("note", "", "justification (triage)")
	expires := fs.String("expires", "", "risk acceptance expiry YYYY-MM-DD")
	file := fs.String("file", "", "JSON file with a hypothesis (add) or a list of decisions (apply)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	switch sub {
	case "list":
		fsl, err := e.St.Findings(e.ProjectID)
		if err != nil {
			return err
		}
		var out []model.Finding
		for _, f := range fsl {
			if *all || f.Status.Active() {
				out = append(out, f)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return model.SeverityRank(out[i].Severity) > model.SeverityRank(out[j].Severity) })
		if *asJSON {
			return printJSON(w, out)
		}
		if len(out) == 0 {
			fmt.Fprintln(w, "No findings.")
			return nil
		}
		for _, f := range out {
			loc := f.File
			if f.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
			}
			stale := ""
			if f.Stale {
				stale = " STALE"
			}
			fmt.Fprintf(w, "%s  %-8s %-18s %-14s %s%s\n           %s  [%s]\n", f.ID, f.Severity, f.Confidence, f.Status, redact.Line(f.Title), stale, redact.Line(loc), f.ControlID)
		}
		return nil
	case "show":
		if len(pos) != 1 {
			return exitErr{2, "usage: pandaward findings show <PW-ID>"}
		}
		f, err := e.St.Finding(e.ProjectID, pos[0])
		if err != nil {
			return err
		}
		if f == nil {
			return fmt.Errorf("finding %s not found", pos[0])
		}
		return printJSON(w, f)
	case "add":
		if *file == "" {
			return exitErr{2, "usage: pandaward findings add --file hypothesis.json"}
		}
		b, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		var in engine.HypothesisInput
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			return err
		}
		f, err := e.RecordHypothesis(in)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "Recorded %s as HYPOTHESIS (%s)\n", f.ID, f.Title)
		return nil
	case "false-positive", "accept-risk", "reopen", "confirm":
		if len(pos) != 1 {
			return exitErr{2, "usage: pandaward findings " + sub + " <PW-ID> --by <name> --note <text>"}
		}
		var exp time.Time
		if *expires != "" {
			exp, err = time.Parse("2006-01-02", *expires)
			if err != nil {
				return exitErr{2, "--expires must be YYYY-MM-DD"}
			}
		}
		f, err := e.Triage(pos[0], sub, *by, *note, exp)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s is now %s / %s (reviewer %s)\n", f.ID, f.Status, f.Confidence, f.Reviewer)
		return nil
	case "apply":
		if *file == "" || len(pos) != 0 {
			return exitErr{2, "usage: pandaward findings apply --file decisions.json --by <name>"}
		}
		ds, err := engine.ReadTriageDecisions(*file)
		if err != nil {
			return err
		}
		out, err := e.TriageBatch(ds, *by)
		if err != nil {
			return err
		}
		for _, f := range out {
			fmt.Fprintf(w, "%s is now %s / %s (reviewer %s)\n", f.ID, f.Status, f.Confidence, f.Reviewer)
		}
		fmt.Fprintf(w, "Applied %d decision(s).\n", len(out))
		return nil
	}
	return exitErr{2, "findings subcommands: list, show, add, apply, false-positive, accept-risk, reopen, confirm"}
}

func cmdRoutes(args []string, w io.Writer) error {
	fs, root := newFS("routes")
	asJSON := fs.Bool("json", false, "JSON output")
	service := fs.String("service", "", "only entrypoints of this service root (e.g. services/api)")
	kind := fs.String("kind", "", "only one kind: "+strings.Join(engine.EntrypointKinds, ", "))
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	eps, a, err := e.Entrypoints(*service, *kind)
	if err != nil {
		return err
	}
	if a == nil {
		return errors.New("no completed assessment; run `pandaward scan` first")
	}
	if *asJSON {
		return printJSON(w, map[string]any{"assessment_id": a.ID, "entrypoints": eps})
	}
	fmt.Fprintf(w, "Entrypoints found by %s (heuristic; completeness is not proven):\n", a.ID)
	svc := "\x00"
	for _, ep := range eps {
		if ep.Meta["service"] != svc {
			svc = ep.Meta["service"]
			fmt.Fprintf(w, "\n%s\n", svc)
		}
		fmt.Fprintf(w, "  %-9s %-40s %s:%d  (%s, %s)\n", ep.Meta["method"], redact.Line(ep.Meta["path"]), redact.Line(ep.Locator), ep.Line, ep.Meta["framework"], ep.Kind)
	}
	if len(eps) == 0 {
		fmt.Fprintln(w, "  none")
	}
	return nil
}

func cmdGraph(args []string, w io.Writer) error {
	fs, root := newFS("graph")
	format := fs.String("format", "text", "text, mermaid or json")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	r, err := report.Build(e)
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		return printJSON(w, map[string]any{"domains": r.DomainSummary, "edges": r.Edges})
	case "mermaid":
		fmt.Fprintln(w, "graph LR")
		used := map[string]bool{}
		for _, ed := range r.Edges {
			used[ed.ID[:1]], used[ed.ID[1:2]] = true, true
		}
		for _, d := range catalog.Domains {
			if used[d.ID] {
				fmt.Fprintf(w, "  %s[\"%s: %s\"]\n", d.ID, d.ID, d.Name)
			}
		}
		for _, ed := range r.Edges {
			fmt.Fprintf(w, "  %s -- \"%s %s\" --> %s\n", ed.ID[:1], ed.ID, ed.Status, ed.ID[1:2])
		}
		return nil
	}
	fmt.Fprintf(w, "Domains (%s)\n", r.Assessment.ID)
	for _, d := range catalog.Domains {
		s := r.DomainSummary[d.ID]
		var parts []string
		for _, k := range []string{"FAIL", "SUSPECTED", "PASS", "BLOCKED", "UNSUPPORTED", "INCONCLUSIVE", "ERROR", "NOT_APPLICABLE"} {
			if s[k] > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", k, s[k]))
			}
		}
		fmt.Fprintf(w, "  %s %-50s %s\n", d.ID, d.Name, strings.Join(parts, ", "))
	}
	fmt.Fprintln(w, "\nCross-domain edges")
	if len(r.Edges) == 0 {
		fmt.Fprintln(w, "  none instantiated (no shared concrete assets)")
	}
	for _, ed := range r.Edges {
		fmt.Fprintf(w, "  %-4s %-12s %s\n       %s\n       provenance: %s\n", ed.ID, ed.Status, ed.Scenario, ed.Reason, redact.Line(strings.Join(ed.Provenance, ", ")))
	}
	return nil
}

func cmdFixPlan(args []string, w io.Writer) error {
	fs, root := newFS("fix-plan")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	r, err := report.Build(e)
	if err != nil {
		return err
	}
	conf, susp := r.Confirmed(), r.Suspected()
	type step struct {
		Order    int             `json:"order"`
		Control  string          `json:"control"`
		Title    string          `json:"title"`
		Severity model.Severity  `json:"max_severity"`
		Findings []model.Finding `json:"findings"`
	}
	groups := map[string]*step{}
	for _, f := range conf {
		k := f.ControlID + "|" + f.RuleID
		g := groups[k]
		if g == nil {
			g = &step{Control: f.ControlID, Title: f.Title}
			groups[k] = g
		}
		if model.SeverityRank(f.Severity) > model.SeverityRank(g.Severity) {
			g.Severity = f.Severity
		}
		g.Findings = append(g.Findings, f)
	}
	var steps []*step
	for _, g := range groups {
		steps = append(steps, g)
	}
	sort.Slice(steps, func(i, j int) bool {
		if model.SeverityRank(steps[i].Severity) != model.SeverityRank(steps[j].Severity) {
			return model.SeverityRank(steps[i].Severity) > model.SeverityRank(steps[j].Severity)
		}
		return len(steps[i].Findings) > len(steps[j].Findings)
	})
	for i := range steps {
		steps[i].Order = i + 1
	}
	if *asJSON {
		return printJSON(w, map[string]any{"steps": steps, "to_triage": susp, "untested_controls": r.Untested(), "note": "No patch is applied automatically."})
	}
	fmt.Fprintf(w, "Fix plan for %s (%s). Nothing is changed automatically.\n\n", r.Project, r.Assessment.ID)
	if len(steps) == 0 {
		fmt.Fprintln(w, "No open confirmed findings.")
	}
	for _, s := range steps {
		fmt.Fprintf(w, "%d. [%s] %s  (%s, %d location(s))\n", s.Order, s.Severity, redact.Line(s.Title), s.Control, len(s.Findings))
		fmt.Fprintf(w, "   Fix: %s\n", s.Findings[0].Fix)
		for i, f := range s.Findings {
			if i == 8 {
				fmt.Fprintf(w, "   ... %d more\n", len(s.Findings)-8)
				break
			}
			loc := f.File
			if f.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
			}
			fmt.Fprintf(w, "   - %s %s\n", f.ID, redact.Line(loc))
		}
		fmt.Fprintf(w, "   Retest: %s\n\n", s.Findings[0].Retest)
	}
	if len(susp) > 0 {
		fmt.Fprintf(w, "Triage first (%d suspected signals, not confirmed): use /pandaward:review triage or `pandaward findings false-positive <id> --by <name> --note <why>`\n", len(susp))
	}
	fmt.Fprintf(w, "Untested controls: %d (manual-assisted review or runtime profile needed; see `pandaward status`).\n", len(r.Untested()))
	return nil
}

func cmdReport(args []string, w io.Writer) error {
	fs, root := newFS("report")
	format := fs.String("format", "", "comma-separated: html,markdown,json,sarif,csv (default from config)")
	out := fs.String("out", "", "output directory (default .pandaward/reports)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	r, err := report.Build(e)
	if err != nil {
		return err
	}
	formats := e.Cfg.Report.Formats
	if *format != "" {
		formats = strings.Split(*format, ",")
	}
	dir := *out
	if dir == "" {
		dir = report.DefaultDir(e.Root)
	}
	paths, err := report.Write(r, dir, formats)
	if err != nil {
		return err
	}
	for _, p := range paths {
		fmt.Fprintln(w, p)
	}
	return nil
}

func cmdEvidence(args []string, w io.Writer) error {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	fs, root := newFS("evidence")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	switch sub {
	case "show":
		if len(pos) != 1 {
			return exitErr{2, "usage: pandaward evidence show <ev_id>"}
		}
		row, err := e.St.Evidence(pos[0])
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("evidence %s not found", pos[0])
		}
		b, err := evidence.Read(e.Private(), row)
		if err != nil {
			return err
		}
		_, err = w.Write(append(b, '\n'))
		return err
	case "verify":
		a, err := e.St.LatestAssessment(e.ProjectID)
		if err != nil || a == nil {
			return errors.New("no assessment")
		}
		cs, err := e.St.Controls(a.ID)
		if err != nil {
			return err
		}
		ok, bad, err := evidence.Verify(e.St, e.Private(), a.ID, evidence.Referenced(cs))
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%d verified, %d failed\n", ok, len(bad))
		if len(bad) > 0 {
			_ = e.St.SetControlStatus(e.ProjectID, a.ID, "R-001", model.StatusFail, "integrity failure: "+strings.Join(bad, ", "))
			return exitErr{1, "evidence integrity failure: " + strings.Join(bad, ", ")}
		}
		return nil
	}
	return exitErr{2, "evidence subcommands: show <id>, verify"}
}

func cmdEvents(args []string, w io.Writer) error {
	fs, root := newFS("events")
	n := fs.Int("n", 30, "number of events")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	evs, err := e.St.Events(e.ProjectID, *n)
	if err != nil {
		return err
	}
	for _, ev := range evs {
		fmt.Fprintf(w, "%5d %s %-30s %s -> %s  %s\n", ev.Seq, ev.TS, redact.Line(ev.Entity), ev.OldState, ev.NewState, redact.Line(ev.Reason))
	}
	return nil
}

// isInteractive reports whether stdin is a terminal. A variable so tests
// can take the terminal away.
var isInteractive = func() bool {
	st, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func cmdScope(args []string, stdin io.Reader, w io.Writer) error {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	fs, root := newFS("scope")
	by := fs.String("by", "", "approver name")
	hours := fs.Int("hours", 8, "approval validity in hours (max 72)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	switch sub {
	case "init":
		p := scope.Path(e.Root)
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists", p)
		}
		if err := os.WriteFile(p, []byte(scope.Template), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(w, "Wrote %s. Fill it in yourself; then run `pandaward scope approve --by \"<name>\"` in an interactive terminal.\n", p)
		return nil
	case "show", "validate":
		m, err := scope.Load(e.Root)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "Scope manifest sha256: %s\nEnvironment: %s\nTargets:\n", m.Hash(), m.Environment)
		for _, t := range m.Targets {
			fmt.Fprintln(w, "  "+redact.Line(t.URL))
		}
		probs := m.Validate(time.Now())
		if _, ap, _ := e.CheckScope(time.Now()); ap != nil {
			fmt.Fprintf(w, "Approval: %s by %s until %s\n", ap.ID, ap.ApprovedBy, ap.ExpiresAt)
		} else {
			fmt.Fprintln(w, "Approval: none valid for this exact manifest")
		}
		if len(probs) > 0 {
			fmt.Fprintln(w, "Problems:")
			for _, p := range probs {
				fmt.Fprintln(w, "  - "+p)
			}
			return exitErr{3, ""}
		}
		fmt.Fprintln(w, "Manifest is valid.")
		return nil
	case "approve":
		if !isInteractive() {
			return exitErr{3, "scope approval must be done by a human in an interactive terminal (stdin is not a TTY). Run it yourself in PowerShell, cmd or a Unix terminal."}
		}
		if strings.TrimSpace(*by) == "" {
			return exitErr{2, "--by <your name> is required"}
		}
		if *hours < 1 || *hours > 72 {
			return exitErr{2, "--hours must be between 1 and 72"}
		}
		m, err := scope.Load(e.Root)
		if err != nil {
			return err
		}
		if probs := m.Validate(time.Now()); len(probs) > 0 {
			return exitErr{3, "manifest invalid:\n  - " + strings.Join(probs, "\n  - ")}
		}
		fmt.Fprintf(w, "You are approving network tests against:\n")
		for _, t := range m.Targets {
			fmt.Fprintln(w, "  "+t.URL)
		}
		fmt.Fprintf(w, "Owner: %s\nReference: %s\nEnvironment: %s\nBudget: %d requests, %.1f req/s\n", m.Authorization.Owner, m.Authorization.Reference, m.Environment, m.Limits.MaxRequestsTotal, m.Limits.RequestsPerSecond)
		code := m.Hash()[:8]
		fmt.Fprintf(w, "\nI confirm I am authorized to test every target above. Type APPROVE %s to continue: ", code)
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(line) != "APPROVE "+code {
			return exitErr{3, "not approved"}
		}
		subject, err := e.ApprovalSubject(m, true)
		if err != nil {
			return err
		}
		idb := make([]byte, 6)
		_, _ = rand.Read(idb)
		ap := store.Approval{ID: "apr_" + hex.EncodeToString(idb), Kind: engine.ApprovalKind, SubjectHash: subject, ApprovedBy: redact.Line(*by),
			ApprovedAt: store.Now(), ExpiresAt: time.Now().Add(time.Duration(*hours) * time.Hour).UTC().Format(time.RFC3339)}
		if err := e.St.PutApproval(e.ProjectID, ap); err != nil {
			return err
		}
		fmt.Fprintf(w, "Approved %s until %s. Any edit to scope.yaml invalidates it.\n", ap.ID, ap.ExpiresAt)
		return nil
	case "revoke":
		n, err := e.St.RevokeApprovals(e.ProjectID, engine.ApprovalKind)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "Revoked %d approval(s).\n", n)
		return nil
	}
	return exitErr{2, "scope subcommands: init, show, validate, approve --by <name> [--hours N], revoke"}
}

func cmdTest(ctx context.Context, args []string, w, ew io.Writer) error {
	fs, root := newFS("test")
	profile := fs.String("profile", "", "production-observe | staging-active | local-runtime")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	switch *profile {
	case "production-observe", "staging-active":
	case "local-runtime":
		res, err := e.LocalRuntime(ctx, func(m string) {
			if !*asJSON {
				fmt.Fprintln(ew, "·", m)
			}
		})
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(w, res)
		}
		fmt.Fprintf(w, "local-runtime: K-003 %s, L-002 %s, %d finding signal(s)\n", res.Controls["K-003"], res.Controls["L-002"], res.Findings)
		for _, n := range res.Notes {
			fmt.Fprintln(w, "  note:", n)
		}
		return nil
	case "manual-assisted":
		return exitErr{3, "profile " + *profile + " is UNSUPPORTED in this release: no runtime adapter is implemented, so related controls stay UNSUPPORTED/BLOCKED in the report. Use /pandaward:review for manual-assisted analysis."}
	case "":
		return exitErr{2, "--profile is required"}
	default:
		return exitErr{2, "unknown profile " + *profile}
	}
	if _, _, err := e.CheckScope(time.Now()); err != nil {
		return exitErr{3, err.Error()}
	}
	progress := func(m string) {
		if !*asJSON {
			fmt.Fprintln(ew, "·", m)
		}
	}
	if *profile == "staging-active" {
		res, err := e.StagingActive(ctx, progress)
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(w, res)
		}
		ids := make([]string, 0, len(res.Controls))
		for id := range res.Controls {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var cs []string
		for _, id := range ids {
			cs = append(cs, id+" "+res.Controls[id])
		}
		fmt.Fprintf(w, "staging-active: %d/%d requests, %s, %d finding signal(s)\n", res.Requests, res.Budget, strings.Join(cs, ", "), res.Findings)
		refused := 0
		for _, n := range res.Refused {
			refused += n
		}
		if refused > 0 {
			fmt.Fprintf(w, "  scope guard refused %d request(s) outside the manifest\n", refused)
		}
		for _, n := range res.Notes {
			fmt.Fprintln(w, "  note:", n)
		}
		return nil
	}
	res, err := e.Observe(ctx, progress)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(w, res)
	}
	fmt.Fprintf(w, "production-observe: %d/%d requests, H-003 %s, %d finding signal(s)\n", res.Requests, res.Budget, res.Status, res.Findings)
	for _, e := range res.Errors {
		fmt.Fprintln(w, "  note:", e)
	}
	return nil
}

func cmdDoctor(ctx context.Context, args []string, w io.Writer) error {
	fs, root := newFS("doctor")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	tools := adapters.Tools(ctx)
	r := *root
	if r == "" {
		r = "."
	}
	initialized := true
	var cfg *config.Config
	projRoot, err := engine.FindRoot(r)
	if err != nil {
		initialized = false
	} else if cfg, _, err = config.Load(projRoot); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(w, map[string]any{"version": version.Version, "initialized": initialized, "tools": tools})
	}
	fmt.Fprintf(w, "pandaward %s (catalog %s)\n", version.Version, catalog.Version)
	if initialized {
		fmt.Fprintf(w, "Project: %s (initialized)\n", projRoot)
		fmt.Fprintf(w, "  allow_tool_network: %v\n", cfg.Scan.AllowToolNetwork)
	} else {
		fmt.Fprintln(w, "Project: not initialized here (run `pandaward init`)")
	}
	fmt.Fprintln(w, "\nBuilt-in adapters (always available, offline): inventory, secrets, code, cicd, infra, supply, mobile, sarif-import (for files in .pandaward/sarif or scan.sarif_files)")
	fmt.Fprintln(w, "Optional scanners (never installed or downloaded by Pandaward):")
	for _, t := range tools {
		state := "not installed"
		if t.Path != "" {
			state = "found " + t.Version
		}
		net := ""
		if t.Network {
			net = " [needs scan.allow_tool_network for its advisory DB]"
		}
		fmt.Fprintf(w, "  %-12s %s%s\n", t.Name, state, net)
	}
	zapPath := ""
	if cfg != nil {
		zapPath = cfg.Runtime.ZAPPath
	}
	if l, err := zap.Locate(zapPath); err == nil {
		fmt.Fprintf(w, "  %-12s found %s (%s) [runtime: pandaward test --profile staging-active]\n", "zap", zap.Version(l), l)
	} else {
		fmt.Fprintf(w, "  %-12s not installed [runtime: pandaward test --profile staging-active; needs Java 17+]\n", "zap")
	}
	mobsfURL := ""
	if cfg != nil {
		mobsfURL = cfg.Scan.MobSFURL
	}
	if _, err := adapters.MobSFURL(mobsfURL); mobsfURL == "" {
		fmt.Fprintf(w, "  %-12s not configured [set scan.mobsf_url to a MobSF server on this machine and %s]\n", "mobsf", adapters.MobSFKeyEnv)
	} else if err != nil {
		fmt.Fprintf(w, "  %-12s %v\n", "mobsf", err)
	} else if os.Getenv(adapters.MobSFKeyEnv) == "" {
		fmt.Fprintf(w, "  %-12s %s configured, %s not set\n", "mobsf", mobsfURL, adapters.MobSFKeyEnv)
	} else {
		fmt.Fprintf(w, "  %-12s %s configured (not contacted by doctor)\n", "mobsf", mobsfURL)
	}
	fmt.Fprintln(w, "\nMissing optional scanners make their controls BLOCKED with a reason; they never count as PASS.")
	if s := telemetry.Load(); s.Enabled && !telemetry.ForcedOff() {
		fmt.Fprintln(w, "Telemetry: on (`pandaward telemetry show` prints what is sent, `pandaward telemetry off` stops it)")
	} else {
		fmt.Fprintln(w, "Telemetry: off")
	}
	return nil
}

func cmdCapabilities(args []string, w io.Writer) error {
	fs, _ := newFS("capabilities")
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	maturity := map[string]string{}
	for _, a := range adapters.Registry() {
		maturity[a.Name()] = a.Maturity()
	}
	if *asJSON {
		return printJSON(w, map[string]any{"catalog_version": catalog.Version, "domains": catalog.Domains, "controls": catalog.Controls, "edges": catalog.Edges, "adapter_maturity": maturity})
	}
	for _, c := range catalog.Controls {
		m := maturity[c.Adapter]
		switch {
		case c.Method == catalog.MethodManual:
			m = "manual-assisted"
		case c.Adapter == "observe-headers" || c.Adapter == "zap" || c.Adapter == "authz" || c.Adapter == "local-runtime":
			m = MaturityObserve
		case m == "" && c.Method == catalog.MethodRuntime:
			m = "planned (not implemented)"
		case m == "":
			m = "builtin"
		}
		fmt.Fprintf(w, "%-6s %-9s %-28s %s\n", c.ID, c.Method, m, c.Title)
	}
	return nil
}

// MaturityObserve is the maturity of the runtime adapters (production-observe
// headers and ZAP).
const MaturityObserve = adapters.MaturityUnvalidated

func cmdSelftest(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	r, err := adversarial.Run(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		if err := printJSON(w, r); err != nil {
			return err
		}
	} else {
		for _, o := range r.Observations {
			st := "PASS"
			if !o.Passed {
				st = "FAIL"
			}
			fmt.Fprintf(w, "%s  %-28s %3d probes  %s\n", st, o.Case, o.Probes, o.Policy)
			if o.Detail != "" {
				fmt.Fprintln(w, "      "+o.Detail)
			}
		}
		fmt.Fprintf(w, "\n%d passed, %d failed. %s\n", r.Passed, r.Failed, r.Note)
	}
	if r.Failed > 0 {
		return exitErr{1, "Pandaward was steered by repository content in at least one case"}
	}
	return nil
}

func cmdDiff(args []string, w io.Writer) error {
	fs, root := newFS("diff")
	asJSON := fs.Bool("json", false, "JSON output")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	var d *engine.Delta
	switch len(pos) {
	case 0:
		a, err := e.St.LatestAssessment(e.ProjectID)
		if err != nil {
			return err
		}
		if a == nil {
			return errors.New("no completed assessment; run `pandaward scan` first")
		}
		if d, err = e.DeltaToPrevious(a.ID); err != nil {
			return err
		}
		if d == nil {
			return errors.New("no earlier assessment with observation tracking to compare with")
		}
	case 2:
		if d, err = e.Diff(pos[0], pos[1]); err != nil {
			return err
		}
	default:
		return exitErr{2, "usage: pandaward diff [FROM TO] [--json]"}
	}
	if *asJSON {
		return printJSON(w, d)
	}
	fmt.Fprintf(w, "%s -> %s: new %d, reopened %d, remediated %d, stale %d, waived %d, unchanged %d\n",
		d.From, d.To, len(d.New), len(d.Reopened), len(d.Remediated), len(d.Stale), len(d.Waived), d.Unchanged)
	for _, sec := range []struct {
		title string
		items []engine.DeltaItem
	}{{"new", d.New}, {"reopened", d.Reopened}, {"remediated", d.Remediated}, {"stale", d.Stale}, {"waived", d.Waived}} {
		for _, it := range sec.items {
			fmt.Fprintf(w, "  %-10s %s %-8s %s  %s:%d\n", sec.title, it.FindingID, it.Severity, redact.Line(it.Title), redact.Line(it.File), it.Line)
		}
	}
	fmt.Fprintln(w, d.Note)
	return nil
}

func cmdExport(args []string, w io.Writer) error {
	fs, root := newFS("export")
	out := fs.String("bundle", "", "path of the zip to create (must not exist)")
	id := fs.String("assessment", "", "assessment to export (default: latest)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return exitErr{2, "usage: pandaward export --bundle out.zip [--assessment ID]"}
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	var a *store.Assessment
	if *id == "" {
		a, err = e.St.LatestAssessment(e.ProjectID)
	} else {
		a, err = e.St.Assessment(e.ProjectID, *id)
	}
	if err != nil {
		return err
	}
	if a == nil {
		return errors.New("assessment not found; run `pandaward scan` first or check the ID")
	}
	r, err := report.BuildFor(e, a)
	if err != nil {
		return err
	}
	sum, n, err := bundle.Export(r, e.Private(), *out)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Wrote %s: %s with %d files (report and redacted evidence; no raw tool output).\n", *out, a.ID, n)
	fmt.Fprintf(w, "Manifest SHA-256: %s\nShare this value with the recipient through a separate channel; they run `pandaward verify-bundle %s`.\n", sum, filepath.Base(*out))
	return nil
}

func cmdVerifyBundle(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return exitErr{2, "usage: pandaward verify-bundle <bundle.zip>"}
	}
	m, sum, err := bundle.Verify(pos[0])
	if err != nil {
		return exitErr{1, "bundle verification FAILED: " + redact.Line(err.Error())}
	}
	fmt.Fprintf(w, "OK: %d files match the manifest (%s, %s).\nManifest SHA-256: %s\nCompare it with the value the sender gave you.\n", len(m.Files), redact.Line(m.Project), m.Assessment.ID, sum)
	return nil
}

func cmdBenchmark(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	strict := fs.Bool("strict", false, "exit 1 when any rule misses a vulnerable case or fires on a safe one")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	rep, err := benchmark.Run(ctx)
	if err != nil {
		return err
	}
	failed := 0
	for _, r := range rep.Rules {
		if r.FP+r.FN > 0 {
			failed++
		}
	}
	if *asJSON {
		if err := printJSON(w, rep); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(w, "Corpus %s, pandaward %s, catalog %s\n\n", rep.CorpusVersion, rep.PandawardVersion, rep.CatalogVersion)
		fmt.Fprintf(w, "%-36s %4s %4s %3s %3s %3s %3s %5s %6s  %s\n", "rule", "vuln", "safe", "TP", "FP", "FN", "TN", "prec", "recall", "maturity")
		for _, r := range rep.Rules {
			fmt.Fprintf(w, "%-36s %4d %4d %3d %3d %3d %3d %5.2f %6.2f  %s\n", r.Rule, r.Vulnerable, r.Safe, r.TP, r.FP, r.FN, r.TN, r.Precision, r.Recall, r.Maturity)
			for _, f := range r.Failures {
				fmt.Fprintln(w, "    "+f)
			}
		}
		fmt.Fprintf(w, "\n%d of %d rules benchmarked (precision >= %.2f and recall >= %.2f on at least %d vulnerable and %d safe cases).\n%s\n",
			rep.Benchmarked, len(rep.Rules), rep.MinPrecision, rep.MinRecall, rep.MinCases, rep.MinCases, rep.Note)
	}
	if *strict && failed > 0 {
		return exitErr{1, fmt.Sprintf("%d rule(s) missed a vulnerable case or fired on a safe one", failed)}
	}
	return nil
}

func cmdFeedback(args []string, w io.Writer) error {
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs, root := newFS("feedback")
	asJSON := fs.Bool("json", false, "JSON output")
	withPath := fs.Bool("include-path", false, "add the file path and line (redacted)")
	withSnippet := fs.Bool("include-snippet", false, "add up to 12 redacted lines of code")
	note := fs.String("note", "", "what happened, in your words (redacted)")
	rule := fs.String("rule", "", "false-negative: rule or control that should have fired (e.g. D-003)")
	file := fs.String("file", "", "false-negative: file with the missed issue")
	line := fs.Int("line", 0, "false-negative: line of the missed issue")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	e, err := openProject(*root)
	if err != nil {
		return err
	}
	defer e.Close()
	opts := feedback.Options{IncludePath: *withPath, IncludeSnippet: *withSnippet, Note: *note}
	var r feedback.Report
	switch sub {
	case feedback.FalsePositive:
		if len(pos) != 1 {
			return exitErr{2, "usage: pandaward feedback false-positive <PW-ID> [--note text] [--include-path] [--include-snippet]"}
		}
		f, err := e.St.Finding(e.ProjectID, pos[0])
		if err != nil {
			return err
		}
		if f == nil {
			return fmt.Errorf("finding %s not found", pos[0])
		}
		runs, err := e.St.Runs(f.AssessmentID)
		if err != nil {
			return err
		}
		r = feedback.FromFinding(e.Root, *f, runs, opts)
	case feedback.FalseNegative:
		if *rule == "" && *note == "" {
			return exitErr{2, "usage: pandaward feedback false-negative --rule <rule or control> [--file f --line n] --note text"}
		}
		r = feedback.Missed(e.Root, *rule, *file, *line, opts)
	case "summary":
		fsl, err := e.St.Findings(e.ProjectID)
		if err != nil {
			return err
		}
		sum := feedback.Summary(fsl)
		if *asJSON {
			return printJSON(w, sum)
		}
		if len(sum) == 0 {
			fmt.Fprintln(w, "No findings were closed as false positives in this project.")
			return nil
		}
		fmt.Fprintf(w, "%-40s %8s %6s\n", "Rule", "False+", "Open")
		for _, c := range sum {
			fmt.Fprintf(w, "%-40s %8d %6d\n", redact.Line(c.RuleID), c.FalsePositives, c.Open)
		}
		fmt.Fprintln(w, "\nReport a rule with: pandaward feedback false-positive <PW-ID>")
		return nil
	default:
		return exitErr{2, "feedback subcommands: false-positive <PW-ID>, false-negative --rule <id>, summary"}
	}
	if *asJSON {
		return printJSON(w, map[string]any{"report": r, "issue_url": r.IssueURL()})
	}
	fmt.Fprintln(w, "This report will be sent only if you open the link and submit the issue yourself.")
	if !*withPath && !*withSnippet {
		fmt.Fprintln(w, "It contains rule metadata and the file type only; add --include-path or --include-snippet to share more (redacted).")
	}
	fmt.Fprintln(w)
	fmt.Fprint(w, r.Markdown())
	fmt.Fprintln(w, "\nReview and submit:")
	fmt.Fprintln(w, r.IssueURL())
	fmt.Fprintln(w, "Already reported? Upvote the existing issue instead:", r.ExistingURL())
	if r.Kind == feedback.FalsePositive {
		fmt.Fprintln(w, "\nTo close it in this project as well: pandaward findings false-positive "+redact.Line(pos[0])+" --by <name> --note <why>")
	}
	return nil
}

// rootArg returns the --root value of a command line, or "." when there is
// none, so telemetry can tell which project a command ran on.
func rootArg(args []string) string {
	for i, a := range args {
		switch {
		case (a == "--root" || a == "-root") && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(a, "--root="):
			return strings.TrimPrefix(a, "--root=")
		case strings.HasPrefix(a, "-root="):
			return strings.TrimPrefix(a, "-root=")
		}
	}
	return "."
}

func cmdTelemetry(args []string, w io.Writer) error {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "status":
		s := telemetry.Load()
		switch {
		case telemetry.ForcedOff():
			fmt.Fprintln(w, "Telemetry: off (forced by PANDAWARD_TELEMETRY or DO_NOT_TRACK)")
		case s.Enabled:
			fmt.Fprintln(w, "Telemetry: on")
		default:
			fmt.Fprintln(w, "Telemetry: off (the default; nothing is recorded or sent)")
		}
		if telemetry.Endpoint == "" {
			fmt.Fprintln(w, "This build has no collector address, so nothing is ever sent.")
		}
		fmt.Fprintln(w, "`pandaward telemetry show` prints exactly what would be sent; docs/TELEMETRY.md lists every field.")
	case "on":
		// Consent is the person's, not an agent's: like scope approval it
		// needs a terminal. Turning it off works from anywhere.
		if !isInteractive() {
			return exitErr{3, "telemetry can only be turned on by a person in an interactive terminal (stdin is not a TTY). Run `pandaward telemetry on` yourself in PowerShell, cmd or a Unix terminal."}
		}
		s, err := telemetry.Enable()
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "Telemetry on. Pandaward counts, per day: which commands, MCP tools and hooks ran, the version, OS and")
		fmt.Fprintln(w, "architecture, and salted project IDs that cannot be turned back into paths. It never records arguments,")
		fmt.Fprintln(w, "paths, file names, findings or code. Finished days are sent at most once a day; `pandaward telemetry off`")
		fmt.Fprintln(w, "stops it and deletes what was not sent.")
		fmt.Fprintf(w, "Install ID: %s\n", s.InstallID)
		if telemetry.ForcedOff() {
			fmt.Fprintln(w, "Note: PANDAWARD_TELEMETRY or DO_NOT_TRACK is set in this environment, so nothing is recorded while it is.")
		}
	case "off":
		if err := telemetry.Disable(); err != nil {
			return err
		}
		fmt.Fprintln(w, "Telemetry off. Unsent counters and the install ID were deleted.")
	case "show":
		s := telemetry.Load()
		p, _ := telemetry.Pending(s)
		b, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(w, "Next payload, byte for byte:")
		fmt.Fprintln(w, string(b))
		if d := telemetry.Today(s); d != nil {
			b, _ := json.MarshalIndent(d, "", "  ")
			fmt.Fprintln(w, "Today so far (sent after the day ends):")
			fmt.Fprintln(w, string(b))
		}
	default:
		return exitErr{code: 2, msg: "usage: pandaward telemetry [status|on|off|show]"}
	}
	return nil
}
