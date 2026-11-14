package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/jsflow"
	"github.com/ratomirjovanovic/pandaward/internal/version"
)

// taintAdapter runs the built-in taint engine on JavaScript and TypeScript.
// It runs by default next to builtin-code; scan.taint_engine: false turns
// it off (#381).
type taintAdapter struct{}

// TaintAdapter is the name of the built-in taint engine adapter.
const TaintAdapter = "builtin-taint"

func (taintAdapter) Name() string { return TaintAdapter }

// Controls is empty: the taint engine owns no control. Its findings carry
// the controls of the weakness (D-001, D-002, D-003, D-006, H-001) and can
// only raise those controls, never decide them as passed: a file it could
// not follow is not evidence of safety.
func (taintAdapter) Controls() []string { return nil }

// Contributes lists the controls its findings carry.
func (taintAdapter) Contributes() []string {
	return []string{"D-001", "D-002", "D-003", "D-006", "H-001"}
}
func (taintAdapter) Maturity() string { return MaturityUnvalidated }
func (taintAdapter) Network() bool    { return false }

func (a taintAdapter) Run(ctx context.Context, c *Context) (Result, model.Run) {
	run := newRun(a.Name(), version.Version)
	res := Result{Decisions: map[string]Decision{}}
	spec, err := taint.Load("javascript")
	if err != nil {
		return res, finish(run, model.ExitError, err.Error(), 0)
	}
	library := isLibrary(c.Inv)
	var paths []string
	for _, f := range c.Inv.Files {
		if f.Lang != "javascript" && f.Lang != "typescript" || IsTestPath(f.Path) || strings.Contains(f.Path, ".min.") || strings.HasSuffix(f.Path, ".d.ts") {
			continue
		}
		if len(f.Lines) > 0 && len(f.Lines) < 5 && len(f.Lines[0]) > 2000 {
			continue // minified
		}
		paths = append(paths, f.Path)
	}
	// The files are analyzed as one project: a call of a function another
	// file exports follows that function, so a flow through a helper
	// module is found at its sink.
	src := func(p string) (string, bool) {
		f := c.Inv.FileByPath(p)
		if f == nil {
			return "", false
		}
		return strings.Join(f.Lines, "\n"), true
	}
	// Resolution depends on the directory of the importing file only;
	// aliases read the nearest tsconfig.json, so remember the answers.
	resolved := map[[2]string]string{}
	resolve := func(from, spec string) string {
		key := [2]string{path.Dir(from), spec}
		if r, ok := resolved[key]; ok {
			return r
		}
		r := ""
		if f := resolveLocal(c.Inv, from, spec); f != nil {
			r = f.Path
		}
		resolved[key] = r
		return r
	}
	proj := jsflow.NewProject(spec, jsflow.Options{Library: library}, paths, src, resolve)
	for _, p := range paths {
		if ctx.Err() != nil {
			return res, finish(run, model.ExitTimeout, "cancelled", len(res.Signals))
		}
		for _, fd := range proj.Analyze(p) {
			if f := c.Inv.FileByPath(fd.File); f != nil {
				res.Signals = append(res.Signals, taintSignal(fd, f, a.Name()))
			}
		}
	}
	files, parseErrors := len(paths), proj.ParseErrors
	detail := fmt.Sprintf("%d JavaScript/TypeScript files", files)
	if library {
		detail += "; library mode: parameters of exported functions are sources"
	}
	if parseErrors > 0 {
		detail += fmt.Sprintf("; %d with syntax the parser skipped", parseErrors)
	}
	return res, finish(run, model.ExitOK, detail, len(res.Signals))
}

// taintSignal turns a flow into a signal whose message shows the path.
func taintSignal(fd taint.Finding, f *inventory.File, collector string) model.Signal {
	k := fd.Sink
	sev, conf := model.SevHigh, model.StronglySupported
	if fd.Library {
		// The caller decides what reaches an exported function; whether
		// that is attacker input depends on the application using it.
		sev, conf = model.SevMedium, model.Hypothesis
	}
	// Each step is redacted on its own: the steps quote code, which may
	// hold secrets, and redacting the whole message would cut a long flow
	// across files short.
	var steps []string
	for _, s := range fd.Steps {
		what := redact.Line(s.What)
		if s.File != "" && s.File != f.Path {
			steps = append(steps, fmt.Sprintf("%s (%s line %d)", what, redact.Sanitize(s.File), s.Line))
			continue
		}
		steps = append(steps, fmt.Sprintf("%s (line %d)", what, s.Line))
	}
	snippet := ""
	if fd.Line >= 1 && fd.Line <= len(f.Lines) {
		snippet = redact.Line(strings.TrimSpace(f.Lines[fd.Line-1]))
	}
	return model.Signal{
		RuleID: k.ID, ControlID: k.Control, Title: k.Title, Severity: sev, Confidence: conf, CWE: k.CWE,
		File: f.Path, StartLine: fd.Line, EndLine: fd.EndLine, Snippet: snippet,
		Message: k.Message + " Flow: " + strings.Join(steps, " -> ") + ".", Fix: k.Fix, Collector: collector,
	}
}

// isLibrary reports a published npm package: a root package.json that is
// not private and names an entry point or has the default one, index.js.
func isLibrary(inv *inventory.Inventory) bool {
	f := inv.FileByPath("package.json")
	if f == nil {
		return false
	}
	var pkg struct {
		Name    string          `json:"name"`
		Version string          `json:"version"`
		Private bool            `json:"private"`
		Main    string          `json:"main"`
		Module  string          `json:"module"`
		Exports json.RawMessage `json:"exports"`
		Bin     json.RawMessage `json:"bin"`
	}
	if json.Unmarshal([]byte(strings.Join(f.Lines, "\n")), &pkg) != nil || pkg.Private {
		return false
	}
	if pkg.Main != "" || pkg.Module != "" || len(pkg.Exports) > 0 || len(pkg.Bin) > 0 {
		return true
	}
	// Without main, npm loads index.js: a named, versioned package with
	// one publishes it.
	return pkg.Name != "" && pkg.Version != "" && inv.FileByPath("index.js") != nil
}
