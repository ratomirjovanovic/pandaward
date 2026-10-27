// Command pensec is the PenSec CLI: local, evidence-based application
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

	"github.com/ratomirjovanovic/pensec/internal/adapters"
	"github.com/ratomirjovanovic/pensec/internal/catalog"
	"github.com/ratomirjovanovic/pensec/internal/config"
	"github.com/ratomirjovanovic/pensec/internal/engine"
	"github.com/ratomirjovanovic/pensec/internal/evidence"
	"github.com/ratomirjovanovic/pensec/internal/hooks"
	"github.com/ratomirjovanovic/pensec/internal/mcp"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
	"github.com/ratomirjovanovic/pensec/internal/report"
	"github.com/ratomirjovanovic/pensec/internal/scope"
	"github.com/ratomirjovanovic/pensec/internal/store"
	"github.com/ratomirjovanovic/pensec/internal/version"
)

const usage = `pensec - local, evidence-based application security assessment

Usage: pensec <command> [flags]

Assessment (local, no target network traffic):
  init            Create .pensec/ (config, private ledger) in the project root
  plan            Show applicable controls, gates and missing prerequisites
  scan            Run the passive local scan (inventory, static checks, adapters)
  retest          Show files changed since the last scan, re-scan, show the delta
                  (--changed re-runs only adapters for impacted controls)
  status          Resumable state, coverage, blockers and next action
  findings        List/show findings; human triage: false-positive, accept-risk, reopen, confirm
  graph           Cross-domain edges (text or --format mermaid)
  fix-plan        Ordered remediation plan from open findings
  report          Render HTML, Markdown, JSON, SARIF and CSV reports
  evidence        show <id> | verify
  events          Recent audit events

Network-active (human authorization required):
  scope           init | show | validate | approve --by <name> | revoke
  test            --profile production-observe  (passive header/TLS review of approved origins)

Integration and tooling:
  doctor          Environment, optional scanners and their network needs
  capabilities    Control catalog with adapter maturity
  mcp             Serve the MCP stdio interface
  hook <name>     Claude Code lifecycle hook (session-start, post-edit, pre-tool, pre-compact)
  version         Print version

Global flag: --root <dir>  project directory (default: current directory or nearest parent with .pensec/)
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
		fmt.Fprintln(stdout, "pensec", version.Version, "catalog", catalog.Version)
	case "hook":
		if len(rest) != 1 {
			return 2
		}
		return hooks.Run(rest[0], stdin, stdout)
	case "mcp":
		err = cmdMCP(ctx, rest, stdin, stdout)
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
	case "fix-plan":
		err = cmdFixPlan(rest, stdout)
	case "report":
		err = cmdReport(rest, stdout)
	case "evidence":
		err = cmdEvidence(rest, stdout)
	case "events":
		err = cmdEvents(rest, stdout)
	case "scope":
		err = cmdScope(rest, stdin, stdout)
	case "test":
		err = cmdTest(ctx, rest, stdout, stderr)
	case "doctor":
		err = cmdDoctor(ctx, rest, stdout)
	case "capabilities":
		err = cmdCapabilities(rest, stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		var ee exitErr
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(stderr, "pensec:", ee.msg)
			}
			return ee.code
		}
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "pensec:", redact.Line(err.Error()))
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
	for _, c := range []string{*root, os.Getenv("PENSEC_PROJECT_DIR"), os.Getenv("CLAUDE_PROJECT_DIR")} {
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
		fmt.Fprintf(w, "Initialized PenSec in %s\n", filepath.Join(e.Root, config.Dir))
	} else {
		fmt.Fprintf(w, "PenSec already initialized in %s\n", filepath.Join(e.Root, config.Dir))
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
		fmt.Fprintf(w, "Skipped: %d (see `pensec plan`)\n", len(inv.Skipped))
	}
	fmt.Fprintln(w, "\nNext: pensec plan, then pensec scan")
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
	mode := fs.String("mode", "passive", "scan mode; only passive is supported here (use `pensec test` for runtime profiles)")
	var onlyChanged *bool
	if retest {
		onlyChanged = fs.Bool("changed", false, "re-run only adapters whose inputs changed; carry over the rest")
	}
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *mode != "passive" {
		return exitErr{2, "scan supports --mode passive only; runtime profiles run through `pensec test`"}
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
	fmt.Fprintln(w, "\nBLOCKED/UNSUPPORTED/SUSPECTED controls are not secure; see `pensec status` and `pensec findings`.")
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
		fmt.Fprintf(w, "Stale files (%d):\n", len(s.StaleFiles))
		for _, f := range s.StaleFiles {
			fmt.Fprintln(w, "  "+redact.Line(f))
		}
		if len(s.StaleControls) > 0 {
			fmt.Fprintf(w, "Stale controls (%d, not decisive until retest): %s\n", len(s.StaleControls), strings.Join(s.StaleControls, ", "))
		}
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
	file := fs.String("file", "", "JSON file with a hypothesis (add)")
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
			return exitErr{2, "usage: pensec findings show <PSEC-ID>"}
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
			return exitErr{2, "usage: pensec findings add --file hypothesis.json"}
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
			return exitErr{2, "usage: pensec findings " + sub + " <PSEC-ID> --by <name> --note <text>"}
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
	}
	return exitErr{2, "findings subcommands: list, show, add, false-positive, accept-risk, reopen, confirm"}
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
		fmt.Fprintf(w, "Triage first (%d suspected signals, not confirmed): use /pensec:review triage or `pensec findings false-positive <id> --by <name> --note <why>`\n", len(susp))
	}
	fmt.Fprintf(w, "Untested controls: %d (manual-assisted review or runtime profile needed; see `pensec status`).\n", len(r.Untested()))
	return nil
}

func cmdReport(args []string, w io.Writer) error {
	fs, root := newFS("report")
	format := fs.String("format", "", "comma-separated: html,markdown,json,sarif,csv (default from config)")
	out := fs.String("out", "", "output directory (default .pensec/reports)")
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
			return exitErr{2, "usage: pensec evidence show <ev_id>"}
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

func isInteractive() bool {
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
		fmt.Fprintf(w, "Wrote %s. Fill it in yourself; then run `pensec scope approve --by \"<name>\"` in an interactive terminal.\n", p)
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
		if ap, _ := e.St.ValidApproval(e.ProjectID, engine.ApprovalKind, m.Hash(), time.Now()); ap != nil {
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
		idb := make([]byte, 6)
		_, _ = rand.Read(idb)
		ap := store.Approval{ID: "apr_" + hex.EncodeToString(idb), Kind: engine.ApprovalKind, SubjectHash: m.Hash(), ApprovedBy: redact.Line(*by),
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
	case "production-observe":
	case "staging-active", "local-runtime", "manual-assisted":
		return exitErr{3, "profile " + *profile + " is UNSUPPORTED in this release: no runtime adapter is implemented, so related controls stay UNSUPPORTED/BLOCKED in the report. Use /pensec:review for manual-assisted analysis."}
	case "":
		return exitErr{2, "--profile is required"}
	default:
		return exitErr{2, "unknown profile " + *profile}
	}
	if _, _, err := e.CheckScope(time.Now()); err != nil {
		return exitErr{3, err.Error()}
	}
	res, err := e.Observe(ctx, func(m string) {
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
	fmt.Fprintf(w, "pensec %s (catalog %s)\n", version.Version, catalog.Version)
	if initialized {
		fmt.Fprintf(w, "Project: %s (initialized)\n", projRoot)
		fmt.Fprintf(w, "  allow_tool_network: %v\n", cfg.Scan.AllowToolNetwork)
	} else {
		fmt.Fprintln(w, "Project: not initialized here (run `pensec init`)")
	}
	fmt.Fprintln(w, "\nBuilt-in adapters (always available, offline): inventory, secrets, code, cicd, infra, supply, mobile")
	fmt.Fprintln(w, "Optional scanners (never installed or downloaded by PenSec):")
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
	fmt.Fprintln(w, "\nMissing optional scanners make their controls BLOCKED with a reason; they never count as PASS.")
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
		case c.Adapter == "observe-headers":
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

// MaturityObserve is the maturity of the production-observe adapter.
const MaturityObserve = adapters.MaturityUnvalidated
