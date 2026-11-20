// Package engines runs PandaWard's detection engines in process for the
// benchmark tools: the built-in adapters, and the bundled Semgrep rules on
// Semgrep or Opengrep through the same adapter `pandaward scan` uses.
package engines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
//
// semgrep and opengrep run PandaWard's bundled rules on that engine. The two
// *-default engines run the tool with its own standard rules instead, as a user
// who installs it and runs it would, so they say how the products compare, not
// only the execution engines.
var Names = []string{"builtin", "semgrep", "opengrep", "taint", "semgrep-default", "opengrep-default", CodeQL}

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
	case CodeQL:
		return codeql(ctx, inv)
	case "semgrep-default", "opengrep-default":
		return defaultRules(ctx, inv, engine)
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

// Environment variables that choose the standard rules of the *-default engines.
const (
	// SemgrepDefaultConfig is the Semgrep config of semgrep-default, p/default
	// when unset (the registry's default ruleset; it needs network access).
	SemgrepDefaultConfig = "PANDAWARD_SEMGREP_DEFAULT_CONFIG"
	// OpengrepRules is the directory of the Opengrep rules (a checkout of the
	// opengrep-rules repository at a pinned commit) that opengrep-default
	// runs. It must be set; without it the engine is not run.
	OpengrepRules = "PANDAWARD_OPENGREP_RULES"
)

// opengrepRuleDirs are the directories of the opengrep-rules repository that
// opengrep-default runs: the languages the benchmarks cover and the generic
// rules. The repository root is not a rule set (it holds YAML that is not a
// rule), so the tool refuses it with an invalid-configuration error.
var opengrepRuleDirs = []string{"java", "python", "javascript", "typescript", "generic"}

// fatalExit reports whether the exit code of semgrep or opengrep scan means the
// scan did not happen. 0 is a clean scan and 1 a scan with findings; anything
// else, such as 2 (fatal error) or 7 (invalid configuration), is not a result
// and must never be read as "no findings".
func fatalExit(code int) bool { return code != 0 && code != 1 }

// defaultRules runs Semgrep or Opengrep with the standard rules and no
// PandaWard rule, config or flag beyond reading the results as JSON: no
// metrics, no cache of the user, a clean home directory. It scans the whole
// tree, as the tool does.
func defaultRules(ctx context.Context, inv *inventory.Inventory, engine string) (Run, error) {
	r := Run{Engine: engine}
	bin, cfg := "semgrep", os.Getenv(SemgrepDefaultConfig)
	if cfg == "" {
		cfg = "p/default"
	}
	if engine == "opengrep-default" {
		bin, cfg = "opengrep", os.Getenv(OpengrepRules)
		if cfg == "" {
			r.NotRun = OpengrepRules + " is not set (a checkout of the opengrep-rules repository)"
			return r, nil
		}
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		r.NotRun = bin + " is not installed"
		return r, nil
	}
	work, err := os.MkdirTemp("", "pwdefault-")
	if err != nil {
		return r, err
	}
	defer os.RemoveAll(work)
	env := append(os.Environ(), "HOME="+filepath.Join(work, "home"), "USERPROFILE="+filepath.Join(work, "home"),
		"XDG_CACHE_HOME="+filepath.Join(work, "cache"), "SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0")
	vctx, cancel := context.WithTimeout(ctx, time.Minute)
	if out, err := exec.CommandContext(vctx, path, "--version").Output(); err == nil {
		r.Version = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	}
	cancel()
	rctx, cancel := context.WithTimeout(ctx, 3*time.Hour)
	defer cancel()
	args := []string{"scan"}
	if engine == "opengrep-default" {
		found := 0
		for _, d := range opengrepRuleDirs {
			dir := filepath.Join(cfg, d)
			if st, err := os.Stat(dir); err == nil && st.IsDir() {
				args = append(args, "--config", dir)
				found++
			}
		}
		if found == 0 {
			return r, fmt.Errorf("%s: none of %s exists in %s", engine, strings.Join(opengrepRuleDirs, ", "), cfg)
		}
	} else {
		args = append(args, "--config", cfg)
	}
	args = append(args, "--json", "--quiet", ".")
	cmd := exec.CommandContext(rctx, path, args...)
	cmd.Dir, cmd.Env = inv.Root, env
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) || fatalExit(ee.ExitCode()) || stdout.Len() == 0 {
			return r, fmt.Errorf("%s did not complete: %v %s", engine, err, firstLine(stderr.String()))
		}
	}
	fs, err := parseDefaultJSON(stdout.String())
	if err != nil {
		return r, fmt.Errorf("%s: %v", engine, err)
	}
	r.Findings = fs
	return r, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// parseDefaultJSON reads the JSON of semgrep or opengrep scan into findings.
// The CWE is the first of the rule's metadata cwe entries, as the tool reports
// it ("CWE-78: Improper ..."); a rule without one has none.
func parseDefaultJSON(out string) ([]Finding, error) {
	var d struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
			} `json:"end"`
			Extra struct {
				Metadata struct {
					CWE json.RawMessage `json:"cwe"`
				} `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		return nil, fmt.Errorf("the output is not JSON: %v", err)
	}
	fs := make([]Finding, 0, len(d.Results))
	for _, r := range d.Results {
		cwe := ""
		var one string
		var many []string
		switch {
		case json.Unmarshal(r.Extra.Metadata.CWE, &many) == nil && len(many) > 0:
			cwe = many[0]
		case json.Unmarshal(r.Extra.Metadata.CWE, &one) == nil:
			cwe = one
		}
		end := r.End.Line
		if end < r.Start.Line {
			end = r.Start.Line
		}
		fs = append(fs, Finding{Rule: r.CheckID, CWE: cwe, File: filepath.ToSlash(strings.TrimPrefix(filepath.ToSlash(r.Path), "./")), Line: r.Start.Line, EndLine: end})
	}
	return fs, nil
}
