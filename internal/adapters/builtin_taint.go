package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/flow"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
	javaparse "github.com/ratomirjovanovic/pandaward/internal/taint/java"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
	"github.com/ratomirjovanovic/pandaward/internal/taint/jsflow"
	pyparse "github.com/ratomirjovanovic/pandaward/internal/taint/py"
	"github.com/ratomirjovanovic/pandaward/internal/version"
)

// taintAdapter runs the built-in taint engine on JavaScript, TypeScript and
// Python.
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
	var parseErrors int
	if os.Getenv("PANDAWARD_JS_ENGINE") == "jsflow" {
		// The AST engine, kept to compare against the IR engine.
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
		parseErrors = proj.ParseErrors
	} else {
		var err error
		if parseErrors, err = a.javascript(ctx, c, &res, paths, resolve, library); err != nil {
			return res, finish(run, model.ExitError, err.Error(), len(res.Signals))
		}
	}
	files := len(paths)
	pyFiles, pyErrors, err := a.python(ctx, c, &res)
	if err != nil {
		return res, finish(run, model.ExitError, err.Error(), len(res.Signals))
	}
	javaFiles, javaErrors, err := a.java(ctx, c, &res)
	if err != nil {
		return res, finish(run, model.ExitError, err.Error(), len(res.Signals))
	}
	if ctx.Err() != nil {
		return res, finish(run, model.ExitTimeout, "cancelled", len(res.Signals))
	}
	detail := fmt.Sprintf("%d JavaScript/TypeScript files", files)
	if library {
		detail += "; library mode: parameters of exported functions are sources"
	}
	if parseErrors > 0 {
		detail += fmt.Sprintf("; %d with syntax the parser skipped", parseErrors)
	}
	detail += fmt.Sprintf("; %d Python files", pyFiles)
	if pyErrors > 0 {
		detail += fmt.Sprintf(" (%d with syntax the parser skipped)", pyErrors)
	}
	detail += fmt.Sprintf("; %d Java files", javaFiles)
	if javaErrors > 0 {
		detail += fmt.Sprintf(" (%d with syntax the parser skipped)", javaErrors)
	}
	return res, finish(run, model.ExitOK, detail, len(res.Signals))
}

// javascript runs the IR engine (#406) on the JavaScript and TypeScript
// files as one project: a call of a function another file exports follows
// that function. The structural findings (prototype pollution, escaping)
// are found by shape, by the code jsflow keeps for them.
func (a taintAdapter) javascript(ctx context.Context, c *Context, res *Result, paths []string, resolve func(from, spec string) string, library bool) (parseErrors int, err error) {
	spec, err := taint.Load("jsir")
	if err != nil {
		return 0, err
	}
	// The engine splits qualified names at dots, so a module is named by
	// its path with the dots (of the extension, of "route.test") replaced.
	byName := map[string]string{}
	modName := func(p string) string {
		n := strings.ReplaceAll(p, ".", "_dot_")
		byName[n] = p
		return n
	}
	parsed := map[string]*ir.Module{}
	files := map[string]*js.File{}
	parse := func(p string) *js.File {
		if f, ok := files[p]; ok {
			return f
		}
		inv := c.Inv.FileByPath(p)
		if inv == nil {
			return nil
		}
		jf := js.Parse(inv.Path, strings.Join(inv.Lines, "\n"), js.OptionsFor(inv.Path))
		if len(jf.Errors) > 0 {
			parseErrors++
		}
		files[p] = jf
		return jf
	}
	proj := flow.New(spec).NewProject(func(name string) (*ir.Module, []string) {
		p, ok := byName[name]
		if !ok {
			return nil, nil
		}
		f := c.Inv.FileByPath(p)
		if m, ok := parsed[p]; ok {
			return m, f.Lines
		}
		jf := parse(p)
		if jf == nil {
			return nil, nil
		}
		m := js.Lower(jf, name, func(sp string) string {
			if r := resolve(p, sp); r != "" {
				return modName(r)
			}
			return ""
		})
		parsed[p] = m
		return m, f.Lines
	})
	proj.Library = library
	for _, p := range paths {
		if ctx.Err() != nil {
			return parseErrors, nil
		}
		fds := proj.Module(modName(p))
		if jf := parse(p); jf != nil {
			fds = append(fds, jsflow.Structural(jf, spec, jsflow.Options{Library: library})...)
		}
		for _, fd := range fds {
			if fd.File == "" {
				fd.File = p
			}
			if f := c.Inv.FileByPath(fd.File); f != nil && !IsTestPath(f.Path) {
				res.Signals = append(res.Signals, taintSignal(fd, f, a.Name()))
			}
		}
	}
	return parseErrors, nil
}

// python runs the IR engine (#406) on the Python files as one project: a
// call of a function or class another module of the project defines is
// followed into it. Test files are not analyzed on their own, but a module
// they hold can still be imported.
func (a taintAdapter) python(ctx context.Context, c *Context, res *Result) (files, parseErrors int, err error) {
	var paths []string
	for _, f := range c.Inv.Files {
		if f.Lang == "python" {
			paths = append(paths, f.Path)
		}
	}
	if len(paths) == 0 {
		return 0, 0, nil
	}
	spec, err := taint.Load("python")
	if err != nil {
		return 0, 0, err
	}
	index := pyparse.NewFiles(paths)
	// A module asked for under two names is the same module.
	parsed := map[string]*ir.Module{}
	proj := flow.New(spec).NewProject(func(name string) (*ir.Module, []string) {
		p := index.Lookup(name)
		f := c.Inv.FileByPath(p)
		if f == nil {
			return nil, nil
		}
		if m, ok := parsed[p]; ok {
			return m, f.Lines
		}
		pf := pyparse.Parse(f.Path, strings.Join(f.Lines, "\n"))
		if len(pf.Errors) > 0 {
			parseErrors++
		}
		mod, pkg := index.Name(f.Path)
		m := pyparse.Lower(pf, mod, pkg)
		parsed[p] = m
		return m, f.Lines
	})
	for _, p := range paths {
		if IsTestPath(p) {
			continue
		}
		if ctx.Err() != nil {
			return files, parseErrors, nil
		}
		files++
		name, _ := index.Name(p)
		for _, fd := range proj.Module(name) {
			if f := c.Inv.FileByPath(fd.File); f != nil && !IsTestPath(f.Path) {
				res.Signals = append(res.Signals, taintSignal(fd, f, a.Name()))
			}
		}
	}
	return files, parseErrors, nil
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

// java runs the IR engine (#406) on the Java files as one project, with
// the keys of the project's .properties files, which code reads through
// Properties.getProperty.
func (a taintAdapter) java(ctx context.Context, c *Context, res *Result) (files, parseErrors int, err error) {
	var paths []string
	props := map[string]string{}
	for _, f := range c.Inv.Files {
		switch f.Lang {
		case "java":
			paths = append(paths, f.Path)
		case "properties":
			readProperties(f.Lines, props)
		}
	}
	if len(paths) == 0 {
		return 0, 0, nil
	}
	spec, err := taint.Load("java")
	if err != nil {
		return 0, 0, err
	}
	index := javaparse.NewFiles(paths)
	parsed := map[string][]*ir.Module{}
	load := func(p string) []*ir.Module {
		if m, ok := parsed[p]; ok {
			return m
		}
		f := c.Inv.FileByPath(p)
		if f == nil {
			return nil
		}
		jf := javaparse.Parse(f.Path, strings.Join(f.Lines, "\n"))
		if len(jf.Errors) > 0 {
			parseErrors++
		}
		parsed[p] = javaparse.LowerWith(jf, spec.Classes())
		return parsed[p]
	}
	proj := flow.New(spec).NewProject(func(name string) (*ir.Module, []string) {
		p := index.Lookup(name)
		for _, m := range load(p) {
			if m.Name == name {
				return m, c.Inv.FileByPath(p).Lines
			}
		}
		return nil, nil
	})
	proj.SetProperties(props)
	for _, p := range paths {
		if IsTestPath(p) {
			continue
		}
		if ctx.Err() != nil {
			return files, parseErrors, nil
		}
		files++
		for _, m := range load(p) {
			for _, fd := range proj.Module(m.Name) {
				if f := c.Inv.FileByPath(fd.File); f != nil && !IsTestPath(f.Path) {
					res.Signals = append(res.Signals, taintSignal(fd, f, a.Name()))
				}
			}
		}
	}
	return files, parseErrors, nil
}

// readProperties adds the key=value lines of a .properties file; a key
// with two different values in the project is unknown ("").
func readProperties(lines []string, out map[string]string) {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if old, dup := out[k]; dup && old != v {
			out[k] = ""
			continue
		}
		out[k] = v
	}
}

var (
	taintSupersedeOnce sync.Once
	taintSupersede     map[string][]string // language -> bundled rule ids
)

// TaintReplaces returns the taint adapter's name when its engine replaces
// the bundled Semgrep rule ruleID in a file of that language: it analyzes
// every such file outside test paths, and its specification lists the
// rules it decides better (`supersedes`). It returns "" otherwise, also
// for rules a project adds itself.
func TaintReplaces(ruleID, lang, path string) string {
	taintSupersedeOnce.Do(func() {
		taintSupersede = map[string][]string{}
		for _, lang := range []string{"python", "java"} {
			if spec, err := taint.Load(lang); err == nil {
				taintSupersede[lang] = spec.Supersedes
			}
		}
	})
	if IsTestPath(path) {
		return ""
	}
	for _, id := range taintSupersede[lang] {
		if ruleID == id || strings.HasSuffix(ruleID, "."+id) {
			return TaintAdapter
		}
	}
	return ""
}
