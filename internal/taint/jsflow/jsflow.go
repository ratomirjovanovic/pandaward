// Package jsflow is the taint analysis for JavaScript and TypeScript. It
// interprets the AST of one file abstractly: values carry a trace when
// they come from a source, a set of kinds they were sanitized for, the
// module name they resolve to (child_process.exec) and the fields of
// object literals. Branches are analyzed separately and joined; loops run
// twice; a check that leaves the function on bad input sanitizes what it
// checked for the rest of the function.
//
// Calls to functions of the same file are not followed yet: their result
// carries the taint of their arguments.
package jsflow

import (
	"math/bits"
	"sort"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

// Options select the sources.
type Options struct {
	// Library treats the parameters of exported functions as sources.
	Library bool
}

// maxSteps bounds the statements interpreted per file.
const maxSteps = 200000

// Analyze returns the source-to-sink flows in f.
// Imports of other files are not followed; Project does that.
func Analyze(f *js.File, spec *taint.Spec, opt Options) []taint.Finding {
	a := newAnalyzer(f, spec, opt, nil)
	a.run(f)
	return a.out
}

func newAnalyzer(f *js.File, spec *taint.Spec, opt Options, proj *Project) *analyzer {
	a := &analyzer{spec: spec, file: f.Path, opt: opt, proj: proj, seen: map[string]bool{}, done: map[*js.Func]bool{},
		exportedFns: map[*js.Func]string{}, exportedNames: map[string]bool{}, exportedClasses: map[*js.Class]bool{},
		sums: map[*js.Func]*summary{}, protos: map[string]map[string]*js.Func{}, ctorOf: map[*js.Func]string{},
		methodOf: map[*js.Func]string{}, ctorThis: map[string]val{}, paramProps: map[*js.Func][]string{},
		exportVals: map[string]val{}}
	if proj != nil {
		// One finding per sink across the project: a sink reached from
		// two importers is one weakness.
		a.seen = proj.seen
	}
	return a
}

// run analyzes the file and leaves the flows in a.out.
func (a *analyzer) run(f *js.File) {
	a.index()
	a.collectClasses(f)
	// Export names also tell request handlers apart (GET, handler); their
	// parameters are sources only in library mode.
	a.collectExports(f)
	top := newScope(nil)
	a.top = top
	a.body(top, f.Stmts)
	for _, name := range a.exportLocal {
		if v, _, ok := top.lookup(name[0]); ok {
			a.exportVals[name[1]] = v
		}
	}
	// Prototype methods run after their constructors, so they see the
	// fields a constructor sets on this.
	for i := 0; i < len(a.pendingProto); i++ {
		p := a.pendingProto[i]
		a.function(p.env, p.fn, a.exportName(p.fn, p.fn.Name), nil)
	}
	a.protoPollution(f)
	if a.opt.Library {
		// A library cannot know its input: any incomplete escaping counts.
		// An application's own content is not attacker input; there only
		// tainted values count (see call).
		a.shapes(f)
	}
	sort.Slice(a.out, func(i, j int) bool {
		if a.out[i].File != a.out[j].File {
			return a.out[i].File < a.out[j].File
		}
		if a.out[i].Line != a.out[j].Line {
			return a.out[i].Line < a.out[j].Line
		}
		return a.out[i].Sink.ID < a.out[j].Sink.ID
	})
}

type analyzer struct {
	spec *taint.Spec
	file string
	opt  Options
	proj *Project
	top  *scope
	// exportVals are the values the module exports by name ("default"
	// for module.exports and export default); exportLocal the local names
	// of export { a as b } (local, exported), bound after the file runs.
	exportVals  map[string]val
	exportLocal [][2]string
	reexports   []reexport
	out         []taint.Finding
	seen        map[string]bool
	done        map[*js.Func]bool
	steps       int

	reqNames, reqProps, reqMethods map[string]bool
	weakNames                      map[string]bool
	handlerRecv, handlerMethods    map[string]bool
	handlerCalls, helperParams     map[string]bool
	events, socketRecv             map[string]bool
	pluginOptions                  map[string]bool
	globals                        map[string]bool

	exportedFns     map[*js.Func]string
	exportedNames   map[string]bool
	exportedClasses map[*js.Class]bool

	// storeEnd is the last line of the value being assigned.
	storeEnd int

	// Summaries of the functions of the file, computed on first call.
	sums map[*js.Func]*summary
	cur  *sumRun
	// fnNest counts the functions being interpreted, to tell a return of
	// the summarized function from one of a callback inside it.
	fnNest int

	// Prototype classes: methods by class, the class of each constructor
	// and prototype method, and the this fields constructors set.
	protos       map[string]map[string]*js.Func
	ctorOf       map[*js.Func]string
	methodOf     map[*js.Func]string
	ctorThis     map[string]val
	pendingProto []pendingFn
	// paramProps are the TypeScript parameter properties of constructors.
	paramProps map[*js.Func][]string
}

type pendingFn struct {
	fn  *js.Func
	env *scope
}

// summary says, for each parameter of a function, where its data goes: to
// the return value (with the kinds it was sanitized for on the way) and to
// which sinks inside the function.
type summary struct {
	ret   []retFlow
	sinks [][]sinkHit
	// other is what the function returns from sources of its own, such as
	// fields of this a constructor filled with caller data.
	other val
	// rest is the index of a rest parameter (...args), or -1.
	rest int
}

type retFlow struct {
	ok    bool
	safe  taint.Kind
	steps []taint.Step
}

type sinkHit struct {
	sink      *taint.Sink
	line, end int
	steps     []taint.Step
	// file is set for a sink in another file of the project.
	file string
}

// sumRun is the state of one summary computation: the placeholder trace
// of the parameter followed and what reached a return or a sink.
type sumRun struct {
	marker  *taint.Trace
	nest    int
	hits    []sinkHit
	hitSeen map[string]bool
	ret     retFlow
	other   val
}

func set(list []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range list {
		m[s] = true
	}
	return m
}

func (a *analyzer) index() {
	src := a.spec.Sources
	a.reqNames, a.reqProps, a.reqMethods = set(src.Request.Names), set(src.Request.Props), set(src.Request.Methods)
	a.weakNames = set(src.Request.Weak)
	a.handlerRecv, a.handlerMethods = set(src.Handlers.Receivers), set(src.Handlers.Methods)
	a.handlerCalls, a.helperParams, a.events = set(src.Handlers.Calls), set(src.HelperParams), set(src.Events)
	a.socketRecv = set(src.Sockets)
	a.pluginOptions = set(src.PluginOptions)
	a.globals = set(src.Globals)
}

// val is an abstract value.
type val struct {
	t    *taint.Trace
	safe taint.Kind
	// ref is the resolved name of a module, module member or global.
	ref    string
	fields map[string]val
	// req marks a request object, res a response object.
	req, res bool
	// shell marks an options object with shell: true.
	shell bool
	// env is the scope a function value was defined in.
	env *scope
	// ownURL marks the URL of the incoming request.
	ownURL bool
	// local marks a variable bound to a value computed here: a variable
	// named request that holds a call result is not the HTTP request.
	local bool
	fn    *js.Func
	// mod is the project file of a module object (require('./x')).
	mod string
	// owner is the analysis of the file that defines fn, when that is
	// another file of the project.
	owner *analyzer
}

func (v val) tainted() bool { return v.t != nil }

// taintFor returns the trace when v, or a field of it, is tainted and not
// sanitized for one of the kinds in k.
func (v val) taintFor(k taint.Kind, depth int) *taint.Trace {
	// Tainted unless sanitized for every kind in k.
	if v.t != nil && v.safe&k != k {
		return v.t
	}
	if depth < 3 {
		keys := make([]string, 0, len(v.fields))
		for key := range v.fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if t := v.fields[key].taintFor(k, depth+1); t != nil {
				return t
			}
		}
	}
	return nil
}

// anyTaint is the trace of v or of any of its fields.
func (v val) anyTaint() *taint.Trace { return v.taintFor(taint.All, 0) }

// join merges the taint of two values; the result is safe only for the
// kinds both are safe for.
func join(x, y val) val {
	switch {
	case x.t == nil && len(x.fields) == 0:
		return val{t: y.anyTaint(), safe: safeOf(y)}
	case y.t == nil && len(y.fields) == 0:
		return val{t: x.anyTaint(), safe: safeOf(x)}
	}
	tx, ty := x.anyTaint(), y.anyTaint()
	switch {
	case tx == nil:
		return val{t: ty, safe: safeOf(y)}
	case ty == nil:
		return val{t: tx, safe: safeOf(x)}
	}
	// Keep the trace of the part that is safe for fewer kinds: it is the
	// one a finding is about.
	sx, sy := safeOf(x), safeOf(y)
	t := tx
	if bits.OnesCount16(uint16(sy)) < bits.OnesCount16(uint16(sx)) {
		t = ty
	}
	return val{t: t, safe: sx & sy}
}

// safeOf is the kinds a value is safe for, counting its fields.
func safeOf(v val) taint.Kind {
	s := taint.All
	if v.t != nil {
		s &= v.safe
	}
	for _, f := range v.fields {
		if f.anyTaint() != nil {
			s &= safeOf(f)
		}
	}
	return s
}

// merge joins two values bound to the same variable on different paths,
// keeping fields and the resolved name when both agree.
func merge(x, y val) val {
	out := join(x, y)
	if x.ref == y.ref {
		out.ref = x.ref
	}
	out.req, out.res, out.shell = x.req || y.req, x.res || y.res, x.shell || y.shell
	if x.fn == y.fn {
		out.fn, out.env = x.fn, x.env
	}
	if x.mod == y.mod {
		out.mod = x.mod
	}
	if x.owner == y.owner {
		out.owner = x.owner
	}
	if len(x.fields) > 0 || len(y.fields) > 0 {
		out.fields = map[string]val{}
		for k, v := range x.fields {
			out.fields[k] = v
		}
		for k, v := range y.fields {
			if old, ok := out.fields[k]; ok {
				out.fields[k] = merge(old, v)
			} else {
				out.fields[k] = v
			}
		}
	}
	return out
}

// scope holds the variables of one function; closures see their parents.
type scope struct {
	vars   map[string]val
	parent *scope
}

func newScope(parent *scope) *scope { return &scope{vars: map[string]val{}, parent: parent} }

func (s *scope) lookup(name string) (val, *scope, bool) {
	for c := s; c != nil; c = c.parent {
		if v, ok := c.vars[name]; ok {
			return v, c, true
		}
	}
	return val{}, nil, false
}

// assign updates the variable where it is declared, or declares it here.
func (s *scope) assign(name string, v val) {
	if _, owner, ok := s.lookup(name); ok {
		owner.vars[name] = v
		return
	}
	s.vars[name] = v
}

func (s *scope) clone() *scope {
	c := &scope{vars: make(map[string]val, len(s.vars)), parent: s.parent}
	for k, v := range s.vars {
		c.vars[k] = v
	}
	return c
}

// mergeFrom sets s to the join of branches a and b, both clones of s.
func (s *scope) mergeFrom(x, y *scope) {
	keys := map[string]bool{}
	for k := range x.vars {
		keys[k] = true
	}
	for k := range y.vars {
		keys[k] = true
	}
	for k := range keys {
		vx, okx := x.vars[k]
		vy, oky := y.vars[k]
		switch {
		case okx && oky:
			s.vars[k] = merge(vx, vy)
		case okx:
			s.vars[k] = vx
		default:
			s.vars[k] = vy
		}
	}
}

// --- exports -------------------------------------------------------------

// collectExports marks the functions and classes a library exports.
func (a *analyzer) collectExports(f *js.File) {
	var markValue func(x js.Expr, name string)
	markValue = func(x js.Expr, name string) {
		switch x := x.(type) {
		case *js.Func:
			if name == "" {
				name = x.Name
			}
			a.exportedFns[x] = name
		case *js.Class:
			a.exportedClasses[x] = true
		case *js.Ident:
			a.exportedNames[x.Name] = true
		case *js.ObjectLit:
			for _, p := range x.Props {
				if p.Kind != "spread" {
					markValue(p.Value, p.Key)
				}
			}
		case *js.Assign:
			markValue(x.Value, name)
		case *js.Call:
			// module.exports = new Api(): the class is exported.
			if id, ok := x.Callee.(*js.Ident); ok && x.New {
				a.exportedNames[id.Name] = true
			}
			// module.exports = factory(...) or a wrapper: export the
			// functions given to it.
			for _, arg := range x.Args {
				if fn, ok := arg.(*js.Func); ok {
					a.exportedFns[fn] = name
				}
			}
		}
	}
	// Values bound to names, for `var api = {...}; module.exports = api`.
	bound := map[string][]js.Expr{}
	for _, s := range f.Stmts {
		js.Inspect(s, func(n js.Node) bool {
			switch n := n.(type) {
			case *js.VarDecl:
				for _, d := range n.Decls {
					if id, ok := d.Target.(*js.Ident); ok && d.Init != nil {
						bound[id.Name] = append(bound[id.Name], d.Init)
					}
				}
			case *js.Assign:
				if id, ok := n.Target.(*js.Ident); ok && n.Op == "=" {
					bound[id.Name] = append(bound[id.Name], n.Value)
				}
			}
			return true
		})
	}
	defer func() {
		// Follow exported names to the objects, functions and classes
		// bound to them, until nothing new is exported.
		done := map[string]bool{}
		for changed := true; changed; {
			changed = false
			for name := range a.exportedNames {
				if done[name] {
					continue
				}
				done[name] = true
				changed = true
				for _, x := range bound[name] {
					markValue(x, name)
				}
			}
		}
	}()
	for _, s := range f.Stmts {
		js.Inspect(s, func(n js.Node) bool {
			switch n := n.(type) {
			case *js.Assign:
				t := exprText(n.Target)
				switch {
				case t == "module.exports" || t == "exports":
					markValue(n.Value, "")
				case strings.HasPrefix(t, "module.exports.") || strings.HasPrefix(t, "exports."):
					markValue(n.Value, t[strings.LastIndexByte(t, '.')+1:])
				case strings.Contains(t, ".prototype.") || strings.HasSuffix(t, ".prototype"):
					markValue(n.Value, t[strings.LastIndexByte(t, '.')+1:])
				}
			case *js.Export:
				switch {
				case n.Default != nil:
					markValue(n.Default, "default")
				case n.Decl != nil:
					switch d := n.Decl.(type) {
					case *js.FuncDecl:
						a.exportedFns[d.Func] = d.Func.Name
					case *js.ClassDecl:
						a.exportedClasses[d.Class] = true
					case *js.VarDecl:
						for _, dc := range d.Decls {
							if id, ok := dc.Target.(*js.Ident); ok {
								markValue(dc.Init, id.Name)
							}
						}
					}
				case n.From == "":
					for _, sp := range n.Specs {
						a.exportedNames[sp.Local] = true
					}
				}
			}
			return true
		})
	}
}

// --- statements ----------------------------------------------------------

// body interprets a statement list, then the function declarations in it,
// which see the final state of the scope (they are hoisted and usually
// called later). It reports whether the list always leaves the function.
func (a *analyzer) body(s *scope, list []js.Stmt) bool {
	var decls []*js.Func
	var classes []*js.Class
	exits := false
	// Function declarations are hoisted: calls above them reach them.
	for _, st := range list {
		switch d := st.(type) {
		case *js.FuncDecl:
			s.vars[d.Func.Name] = val{fn: d.Func, env: s}
		case *js.Export:
			if fd, ok := d.Decl.(*js.FuncDecl); ok {
				s.vars[fd.Func.Name] = val{fn: fd.Func, env: s}
				if s == a.top {
					a.exportVals[fd.Func.Name] = s.vars[fd.Func.Name]
				}
			}
		}
	}
	for _, st := range list {
		switch d := st.(type) {
		case *js.FuncDecl:
			s.vars[d.Func.Name] = val{fn: d.Func, env: s}
			decls = append(decls, d.Func)
			continue
		case *js.Export:
			if fd, ok := d.Decl.(*js.FuncDecl); ok {
				s.vars[fd.Func.Name] = val{fn: fd.Func, env: s}
				decls = append(decls, fd.Func)
				continue
			}
		}
		if exits {
			break
		}
		if a.stmt(s, st, &classes) {
			exits = true
		}
	}
	for _, fn := range decls {
		a.function(s, fn, a.exportName(fn, fn.Name), nil)
	}
	for _, c := range classes {
		a.classBodies(s, c)
	}
	return exits
}

func (a *analyzer) exportName(fn *js.Func, binding string) string {
	if name, ok := a.exportedFns[fn]; ok {
		if name == "" {
			name = binding
		}
		if name == "" {
			name = "(anonymous)"
		}
		return name
	}
	if binding != "" && a.exportedNames[binding] {
		return binding
	}
	return ""
}

func (a *analyzer) stmt(s *scope, st js.Stmt, classes *[]*js.Class) bool {
	a.steps++
	if a.steps > maxSteps {
		return true
	}
	switch st := st.(type) {
	case *js.ExprStmt:
		a.expr(s, st.X)
		return isExit(st.X)
	case *js.VarDecl:
		for _, d := range st.Decls {
			v := val{}
			if d.Init != nil {
				v = a.expr(s, d.Init)
				if fn, ok := d.Init.(*js.Func); ok {
					v.fn = fn
				}
				if !v.req && !v.res {
					v.local = true
				}
			}
			a.bind(s, d.Target, v, true)
		}
	case *js.Return:
		if st.X != nil {
			a.returned(a.expr(s, st.X))
		}
		return true
	case *js.Throw:
		a.expr(s, st.X)
		return true
	case *js.Branch:
		return true
	case *js.If:
		return a.ifStmt(s, st, classes)
	case *js.Block:
		return a.block(s, st.List, classes)
	case *js.For:
		if st.Init != nil {
			a.stmt(s, st.Init, classes)
		}
		a.loop(s, func(ls *scope) {
			if st.Test != nil {
				a.expr(ls, st.Test)
			}
			a.stmt(ls, st.Body, classes)
			if st.Update != nil {
				a.expr(ls, st.Update)
			}
		})
	case *js.ForIn:
		right := a.expr(s, st.Right)
		elem := val{t: right.anyTaint(), safe: safeOf(right)}
		if elem.t != nil {
			elem.t = elem.t.Add(st.Line, "element")
		}
		a.loop(s, func(ls *scope) {
			switch l := st.Left.(type) {
			case *js.VarDecl:
				if len(l.Decls) > 0 {
					a.bind(ls, l.Decls[0].Target, elem, true)
				}
			case *js.ExprStmt:
				a.bind(ls, l.X, elem, false)
			}
			a.stmt(ls, st.Body, classes)
		})
	case *js.While:
		a.loop(s, func(ls *scope) {
			a.expr(ls, st.Test)
			a.stmt(ls, st.Body, classes)
		})
	case *js.Try:
		exits := a.block(s, st.Block.List, classes)
		if st.Handler != nil {
			hs := s.clone()
			if st.Param != nil {
				a.bind(hs, st.Param, val{}, true)
			}
			hExits := a.block(hs, st.Handler.List, classes)
			s.mergeFrom(s.clone(), hs)
			exits = exits && hExits
		}
		if st.Finally != nil {
			a.block(s, st.Finally.List, classes)
		}
		return exits
	case *js.Switch:
		a.expr(s, st.Disc)
		base := s.clone()
		acc := s.clone()
		for _, c := range st.Cases {
			cs := base.clone()
			if c.Test != nil {
				a.expr(cs, c.Test)
			}
			a.block(cs, c.Body, classes)
			acc.mergeFrom(acc.clone(), cs)
		}
		s.vars = acc.vars
	case *js.Labeled:
		return a.stmt(s, st.Body, classes)
	case *js.FuncDecl:
		s.vars[st.Func.Name] = val{fn: st.Func, env: s}
		a.function(s, st.Func, a.exportName(st.Func, st.Func.Name), nil)
	case *js.ClassDecl:
		if st.Class.Name != "" {
			s.vars[st.Class.Name] = val{}
		}
		*classes = append(*classes, st.Class)
	case *js.Import:
		mod := moduleName(st.Source)
		file := a.importFile(st.Source)
		for _, sp := range st.Specs {
			switch sp.Imported {
			case "*":
				s.vars[sp.Local] = val{ref: mod, mod: file}
			case "default":
				v := val{ref: mod}
				if file != "" {
					v = a.proj.moduleVal(st.Source, file)
				}
				s.vars[sp.Local] = v
			default:
				v := val{ref: mod + "." + sp.Imported}
				if file != "" {
					if ev, ok := a.proj.export(file, sp.Imported, 0); ok {
						ev.ref = v.ref
						v = ev
					}
				}
				s.vars[sp.Local] = v
			}
		}
	case *js.Export:
		if st.Decl != nil {
			exits := a.stmt(s, st.Decl, classes)
			if s == a.top {
				a.exportDecl(s, st.Decl)
			}
			return exits
		}
		if st.Default != nil {
			v := a.expr(s, st.Default)
			if s == a.top {
				a.exportVals["default"] = v
			}
		}
		if s == a.top {
			a.exportSpecs(st)
		}
	}
	return false
}

// importFile is the project file an import names, or "".
func (a *analyzer) importFile(spec string) string {
	if a.proj == nil {
		return ""
	}
	return a.proj.resolve(a.file, spec)
}

// exportDecl records the names `export <declaration>` exports.
func (a *analyzer) exportDecl(s *scope, d js.Stmt) {
	switch d := d.(type) {
	case *js.FuncDecl:
		a.exportVals[d.Func.Name] = s.vars[d.Func.Name]
	case *js.VarDecl:
		for _, dc := range d.Decls {
			if id, ok := dc.Target.(*js.Ident); ok {
				a.exportVals[id.Name] = s.vars[id.Name]
			}
		}
	}
}

// exportSpecs records export { a as b } and the re-exports of other files.
func (a *analyzer) exportSpecs(st *js.Export) {
	if st.From != "" {
		if st.All && len(st.Specs) == 0 {
			a.reexports = append(a.reexports, reexport{from: st.From, all: true})
		}
		for _, sp := range st.Specs {
			a.reexports = append(a.reexports, reexport{name: sp.Exported, imported: sp.Local, from: st.From})
		}
		return
	}
	for _, sp := range st.Specs {
		a.exportLocal = append(a.exportLocal, [2]string{sp.Local, sp.Exported})
	}
}

// block interprets a nested block in the same function scope.
func (a *analyzer) block(s *scope, list []js.Stmt, classes *[]*js.Class) bool {
	for _, st := range list {
		if fd, ok := st.(*js.FuncDecl); ok {
			s.vars[fd.Func.Name] = val{fn: fd.Func, env: s}
		}
	}
	for _, st := range list {
		if a.stmt(s, st, classes) {
			return true
		}
	}
	return false
}

// loop runs a loop body twice so values carried around the loop reach
// their uses, then joins with the state before the loop (zero iterations).
func (a *analyzer) loop(s *scope, body func(*scope)) {
	before := s.clone()
	ls := s.clone()
	body(ls)
	body(ls)
	s.mergeFrom(before, ls)
}

func (a *analyzer) ifStmt(s *scope, st *js.If, classes *[]*js.Class) bool {
	a.expr(s, st.Test)
	checked := guarded(st.Test)
	ts := s.clone()
	if !negated(st.Test) {
		// if (allowed.includes(x)) { use(x) }: x is checked inside.
		for _, p := range checked {
			sanitize(ts, p)
		}
	}
	thenExits := a.stmt(ts, st.Then, classes)
	es := s.clone()
	// if (bad(x)) { x = fallback } replaces what failed the check: the
	// other path keeps x only when it passed.
	for _, p := range checked {
		if assigns(st.Then, p) {
			sanitize(es, p)
		}
	}
	elseExits := false
	if st.Else != nil {
		elseExits = a.stmt(es, st.Else, classes)
	}
	switch {
	case thenExits && elseExits:
		return true
	case thenExits:
		// if (!valid(x)) return; ...: the rest of the function sees x checked.
		for _, p := range checked {
			sanitize(es, p)
		}
		s.vars = es.vars
	case elseExits:
		s.vars = ts.vars
	default:
		s.mergeFrom(ts, es)
	}
	return false
}

// assigns reports whether st assigns to the dotted path p.
func assigns(st js.Stmt, p string) bool {
	found := false
	js.Inspect(st, func(n js.Node) bool {
		if as, ok := n.(*js.Assign); ok && as.Op == "=" && exprText(as.Target) == p {
			found = true
		}
		_, isFn := n.(*js.Func)
		return !found && !isFn
	})
	return found
}

// isExit reports a call that ends the process.
func isExit(x js.Expr) bool {
	c, ok := x.(*js.Call)
	if !ok {
		return false
	}
	t := exprText(c.Callee)
	return t == "process.exit" || t == "process.abort"
}

// negated reports a test whose outermost operator is !.
func negated(x js.Expr) bool {
	u, ok := x.(*js.Unary)
	return ok && u.Op == "!"
}

// validators are method and function names that check a value.
var validatorPrefixes = []string{"is", "has", "valid", "check", "verify", "match", "test", "includes", "startsWith", "endsWith", "indexOf", "contains", "allow", "safe", "assert"}

// typeChecks test a value's type, not its content.
var typeChecks = set([]string{"isarray", "isstring", "isobject", "isplainobject", "isfunction", "isbuffer", "isundefined", "isnull", "isnil", "isdefined", "isempty", "isregexp", "isdate", "isarraylike", "hasownproperty", "has"})

func isValidatorName(name string) bool {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	l := strings.ToLower(name)
	if typeChecks[l] {
		return false
	}
	for _, p := range validatorPrefixes {
		if strings.HasPrefix(l, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// guarded returns the variables (dotted paths) a condition checks: values
// passed to or tested by a validator call, or compared with a constant.
func guarded(test js.Expr) []string {
	var out []string
	add := func(x js.Expr) {
		if p := exprText(x); p != "" && p != "this" {
			out = append(out, p)
		}
	}
	var walk func(js.Expr)
	walk = func(x js.Expr) {
		switch x := x.(type) {
		case *js.Unary:
			walk(x.X)
		case *js.Binary:
			switch x.Op {
			case "&&", "||":
				walk(x.L)
				walk(x.R)
			case "===", "!==", "==", "!=":
				// typeof x === 'number' leaves no text; 'string' checks nothing.
				if u, ok := x.L.(*js.Unary); ok && u.Op == "typeof" {
					if l, ok := x.R.(*js.Lit); ok && (l.Val == "number" || l.Val == "boolean" || l.Val == "bigint") {
						add(u.X)
					}
					return
				}
				walk(x.L)
				walk(x.R)
				if isConst(x.R) {
					add(x.L)
				} else if isConst(x.L) {
					add(x.R)
				}
			case "in", "instanceof":
				add(x.L)
			}
		case *js.Call:
			name := exprText(x.Callee)
			if m, ok := x.Callee.(*js.Member); ok {
				name = m.Prop
				if isValidatorName(name) || name == "search" {
					add(m.Obj)
				}
			}
			if isValidatorName(name) {
				for _, arg := range x.Args {
					add(arg)
				}
			}
		}
	}
	walk(test)
	return out
}

func isConst(x js.Expr) bool {
	switch x := x.(type) {
	case *js.Lit:
		return true
	case *js.Unary:
		return x.Op == "-" && isConst(x.X)
	case *js.Ident:
		return x.Name == "undefined"
	case *js.TemplateLit:
		return len(x.Exprs) == 0
	}
	return false
}

// sanitize marks the variable or field at a dotted path as checked.
func sanitize(s *scope, p string) {
	parts := strings.Split(p, ".")
	v, owner, ok := s.lookup(parts[0])
	if !ok {
		return
	}
	owner.vars[parts[0]] = sanitizePath(v, parts[1:])
	if owner != s {
		// A clone shares its parents; record the checked value locally.
		s.vars[parts[0]] = owner.vars[parts[0]]
	}
}

func sanitizePath(v val, rest []string) val {
	if len(rest) == 0 {
		v.safe = taint.All
		if len(v.fields) > 0 {
			f := make(map[string]val, len(v.fields))
			for k, fv := range v.fields {
				f[k] = sanitizePath(fv, nil)
			}
			v.fields = f
		}
		return v
	}
	f := make(map[string]val, len(v.fields)+1)
	for k, fv := range v.fields {
		f[k] = fv
	}
	inner, ok := f[rest[0]]
	if !ok {
		inner = val{t: v.t, safe: v.safe}
	}
	f[rest[0]] = sanitizePath(inner, rest[1:])
	v.fields = f
	return v
}

// --- functions -----------------------------------------------------------

// function analyzes a function body once, with the parameters given (nil
// means: sources for an exported function in library mode, request and
// response objects by name, clean otherwise).
func (a *analyzer) function(outer *scope, fn *js.Func, exported string, params []val) {
	if fn == nil || a.done[fn] {
		return
	}
	a.done[fn] = true
	a.fnNest++
	defer func() { a.fnNest-- }()
	s := newScope(outer)
	a.presetThis(s, fn)
	if cls := a.ctorOf[fn]; cls != "" && exported == "" && a.opt.Library && len(a.protos[cls]) > 0 && a.anyExported(cls) {
		// A class whose prototype methods are exported is public: its
		// constructor arguments come from the caller too.
		exported = cls
	}
	handler := isHandler(fn, exported)
	helper := a.takesRequest(fn)
	for i, p := range fn.Params {
		var v val
		name := patternName(p)
		switch {
		case i < len(params):
			v = params[i]
		case helper && a.helperParams[name]:
			v = val{t: taint.NewSource(fn.Line, "parameter "+name+" next to the request", false)}
		case a.weakNames[name] && !handler:
			// fetch(request.url) in an HTTP client is not client input.
			v = val{local: true}
		case exported != "" && a.opt.Library:
			if a.reqNames[name] {
				v = val{req: true}
				break
			}
			v = val{t: taint.NewSource(fn.Line, "parameter "+name+" of exported function "+exported, true)}
		}
		a.bindParam(s, p, v)
	}
	a.setParamProps(s, fn)
	if fn.ExprBody != nil {
		a.returned(a.expr(s, fn.ExprBody))
		return
	}
	a.body(s, fn.Body)
	if cls := a.ctorOf[fn]; cls != "" {
		a.ctorThis[cls] = s.vars["this"]
	}
}

// setParamProps copies constructor(public x) parameters into this.x.
func (a *analyzer) setParamProps(s *scope, fn *js.Func) {
	for _, name := range a.paramProps[fn] {
		v, _, _ := s.lookup(name)
		this := s.vars["this"]
		s.vars["this"] = setPath(this, []string{name}, v)
	}
}

// isSanitizerName reports a function named as a sanitizer or validator of
// its argument.
func isSanitizerName(n string) bool {
	l := strings.ToLower(n)
	for _, p := range []string{"safe", "sanitize", "escape", "encode", "quote", "clean", "validate", "allowlist", "whitelist"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// handlerExports are export names of request handlers (Next.js route
// handlers, serverless handlers).
var handlerExports = set([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "handler", "default", "middleware", "loader", "action"})

// isHandler reports a function that looks like it handles a request.
func isHandler(fn *js.Func, exported string) bool {
	if handlerExports[exported] {
		return true
	}
	if len(fn.Params) >= 2 {
		switch strings.ToLower(patternName(fn.Params[1])) {
		case "res", "response", "reply", "h":
			return true
		}
	}
	return false
}

// takesRequest reports a function with both a request and a response
// parameter, such as serveStatic(req, res, path).
func (a *analyzer) takesRequest(fn *js.Func) bool {
	req, res := false, false
	for _, p := range fn.Params {
		switch n := strings.ToLower(patternName(p)); {
		case n == "req" || n == "request":
			req = true
		case n == "res" || n == "response":
			res = true
		}
	}
	return req && res
}

// presetThis gives a constructor or method its this: the methods of its
// class, and for methods the fields the constructor set.
func (a *analyzer) presetThis(s *scope, fn *js.Func) {
	cls := a.ctorOf[fn]
	if cls == "" {
		cls = a.methodOf[fn]
	}
	if cls == "" {
		return
	}
	this := val{fields: map[string]val{}}
	for name, m := range a.protos[cls] {
		this.fields[name] = val{fn: m, env: s.parent}
	}
	if a.methodOf[fn] != "" {
		for k, v := range a.ctorThis[cls].fields {
			if _, isMethod := this.fields[k]; !isMethod {
				this.fields[k] = v
			}
		}
	}
	s.vars["this"] = this
}

func (a *analyzer) anyExported(cls string) bool {
	for _, m := range a.protos[cls] {
		if _, ok := a.exportedFns[m]; ok {
			return true
		}
	}
	return a.exportedNames[cls]
}

// collectClasses finds prototype classes, X.prototype.m = function and
// X.prototype = {...}, and ES classes, so this.m() can be resolved.
func (a *analyzer) collectClasses(f *js.File) {
	addMethod := func(cls, name string, x js.Expr) {
		fn, ok := x.(*js.Func)
		if !ok {
			return
		}
		if a.protos[cls] == nil {
			a.protos[cls] = map[string]*js.Func{}
		}
		a.protos[cls][name] = fn
		a.methodOf[fn] = cls
	}
	ctors := map[string]*js.Func{}
	for _, st := range f.Stmts {
		js.Inspect(st, func(n js.Node) bool {
			switch n := n.(type) {
			case *js.Assign:
				t := exprText(n.Target)
				if i := strings.Index(t, ".prototype."); i > 0 && !strings.Contains(t[i+11:], ".") {
					addMethod(t[:i], t[i+11:], n.Value)
				} else if strings.HasSuffix(t, ".prototype") {
					if o, ok := n.Value.(*js.ObjectLit); ok {
						for _, p := range o.Props {
							addMethod(strings.TrimSuffix(t, ".prototype"), p.Key, p.Value)
						}
					}
				} else if fn, ok := n.Value.(*js.Func); ok && !strings.Contains(t, ".") && t != "" {
					ctors[t] = fn
				}
			case *js.Class:
				// An ES class: its methods and constructor share this.
				cls := classKey(n)
				for _, m := range n.Members {
					fn, ok := m.Value.(*js.Func)
					if !ok || m.Kind == "field" || m.Static {
						continue
					}
					if m.Kind == "constructor" {
						a.ctorOf[fn] = cls
						a.paramProps[fn] = m.ParamProps
						if a.protos[cls] == nil {
							a.protos[cls] = map[string]*js.Func{}
						}
						continue
					}
					addMethod(cls, m.Key, fn)
				}
			case *js.FuncDecl:
				ctors[n.Func.Name] = n.Func
			case *js.VarDecl:
				for _, d := range n.Decls {
					if id, ok := d.Target.(*js.Ident); ok {
						if fn, ok := d.Init.(*js.Func); ok {
							ctors[id.Name] = fn
						}
					}
				}
			}
			return true
		})
	}
	for cls := range a.protos {
		if fn := ctors[cls]; fn != nil {
			a.ctorOf[fn] = cls
		}
	}
}

func (a *analyzer) bindParam(s *scope, p js.Expr, v val) {
	if as, ok := p.(*js.Assign); ok {
		def := a.expr(s, as.Value)
		if v.t == nil && !v.req && !v.res {
			v = def
		}
		p = as.Target
	}
	if sp, ok := p.(*js.Spread); ok {
		p = sp.X
	}
	a.bind(s, p, v, true)
}

func patternName(p js.Expr) string {
	switch p := p.(type) {
	case *js.Ident:
		return p.Name
	case *js.Assign:
		return patternName(p.Target)
	case *js.Spread:
		return patternName(p.X)
	case *js.ObjectLit:
		return "{...}"
	case *js.ArrayLit:
		return "[...]"
	}
	return "?"
}

// classKey names an ES class for the method tables.
func classKey(c *js.Class) string {
	if c.Name != "" {
		return c.Name
	}
	return "class@" + strconv.Itoa(c.Line)
}

// classBodies analyzes the methods of a class, the constructor first so
// the others see the fields it sets on this; in an exported class their
// parameters are sources in library mode.
func (a *analyzer) classBodies(s *scope, c *js.Class) {
	exported := a.exportedClasses[c] || c.Name != "" && a.exportedNames[c.Name]
	cs := newScope(s)
	members := append([]*js.ClassMember{}, c.Members...)
	sort.SliceStable(members, func(i, j int) bool { return members[i].Kind == "constructor" && members[j].Kind != "constructor" })
	for _, m := range members {
		switch m.Kind {
		case "block":
			var nested []*js.Class
			bs := newScope(cs)
			a.block(bs, m.Block, &nested)
			for _, nc := range nested {
				a.classBodies(bs, nc)
			}
		case "field":
			if m.Value != nil {
				a.expr(cs, m.Value)
			}
		default:
			fn, ok := m.Value.(*js.Func)
			if !ok {
				continue
			}
			name := ""
			if exported && !strings.HasPrefix(m.Key, "#") && !strings.HasPrefix(m.Key, "_") {
				name = c.Name + "." + m.Key
				if c.Name == "" {
					name = m.Key
				}
			}
			a.function(cs, fn, name, nil)
		}
	}
}

// --- expressions ---------------------------------------------------------

// exprText renders an identifier or member chain as a dotted path, or "".
func exprText(x js.Expr) string {
	switch x := x.(type) {
	case *js.Ident:
		return x.Name
	case *js.Member:
		if x.Computed != nil {
			if l, ok := x.Computed.(*js.Lit); ok && l.Kind == js.TString {
				if b := exprText(x.Obj); b != "" {
					return b + "." + l.Val
				}
			}
			return ""
		}
		if b := exprText(x.Obj); b != "" {
			return b + "." + x.Prop
		}
	}
	return ""
}

func moduleName(src string) string { return strings.TrimPrefix(src, "node:") }

func (a *analyzer) expr(s *scope, x js.Expr) val {
	switch x := x.(type) {
	case nil:
		return val{}
	case *js.Ident:
		return a.ident(s, x)
	case *js.Lit:
		return val{}
	case *js.TemplateLit:
		if x.Tag != nil {
			tag := a.expr(s, x.Tag)
			out := val{}
			for _, e := range x.Exprs {
				out = join(out, a.expr(s, e))
			}
			// sql`...` binds its substitutions as parameters, and what it
			// returns is the rows the database holds: a row found by a key
			// from the request does not hold that request's data.
			if isSQLTag(x.Tag, tag) {
				return val{}
			}
			return out
		}
		parts := make([]part, 0, 2*len(x.Exprs)+1)
		out := val{}
		for i, q := range x.Quasis {
			parts = append(parts, part{lit: q, isLit: true})
			if i < len(x.Exprs) {
				v := a.expr(s, x.Exprs[i])
				parts = append(parts, part{v: v})
				out = join(out, v)
			}
		}
		if out.t != nil && hostFixed(parts) {
			out.safe |= offsite
		}
		return out
	case *js.Member:
		return a.member(s, x)
	case *js.Call:
		return a.call(s, x)
	case *js.Binary:
		if x.Op == "+" {
			return a.concat(s, x)
		}
		l, r := a.expr(s, x.L), a.expr(s, x.R)
		switch x.Op {
		case "+", "||", "&&", "??":
			out := join(l, r)
			if out.t != nil && x.Op == "+" {
				out.t = out.t.Add(x.Line, "concatenation")
			}
			return out
		}
		return val{}
	case *js.Unary:
		v := a.expr(s, x.X)
		if x.Op == "await" {
			return v
		}
		return val{}
	case *js.Assign:
		return a.assignExpr(s, x)
	case *js.Cond:
		a.expr(s, x.Test)
		// cond ? x : fallback checks x for the branch that uses it.
		branch := func(e js.Expr, checked bool) val {
			if !checked {
				return a.expr(s, e)
			}
			cs := s.clone()
			for _, p := range guarded(x.Test) {
				sanitize(cs, p)
			}
			return a.expr(cs, e)
		}
		neg := negated(x.Test)
		return merge(branch(x.Then, !neg), branch(x.Else, neg))
	case *js.Seq:
		var v val
		for _, e := range x.List {
			v = a.expr(s, e)
		}
		return v
	case *js.ArrayLit:
		out := val{}
		for _, e := range x.Elems {
			out = join(out, a.expr(s, e))
		}
		return out
	case *js.ObjectLit:
		return a.object(s, x)
	case *js.Spread:
		return a.expr(s, x.X)
	case *js.Yield:
		return a.expr(s, x.X)
	case *js.Func:
		if a.methodOf[x] != "" && a.cur == nil {
			a.pendingProto = append(a.pendingProto, pendingFn{x, s})
		} else {
			a.function(s, x, a.exportName(x, x.Name), nil)
		}
		return val{fn: x, env: s}
	case *js.Class:
		a.classBodies(s, x)
		return val{}
	case *js.JSXElement:
		a.jsx(s, x)
		return val{}
	}
	return val{}
}

func (a *analyzer) ident(s *scope, x *js.Ident) val {
	v, _, ok := s.lookup(x.Name)
	if !ok {
		// An undeclared name is a global; it resolves to itself.
		v = val{ref: x.Name}
		if x.Name == "this" {
			v.ref = ""
		}
	}
	if a.reqNames[x.Name] && !v.local && v.t == nil && len(v.fields) == 0 && (v.ref == "" || v.ref == x.Name) {
		v.req = true
	}
	if (x.Name == "res" || x.Name == "response") && !v.local && v.t == nil {
		v.res = true
	}
	if g := x.Name; a.globals[g] && v.t == nil {
		return val{t: taint.NewSource(x.Line, g, false), ref: g}
	}
	return v
}

func (a *analyzer) member(s *scope, x *js.Member) val {
	base := a.expr(s, x.Obj)
	if x.Computed != nil {
		key := a.expr(s, x.Computed)
		if l, ok := x.Computed.(*js.Lit); ok && l.Kind == js.TString {
			return a.field(base, l.Val, x.Line, exprText(x))
		}
		_ = key
		out := val{t: base.anyTaint(), safe: safeOf(base)}
		if base.req {
			// req.query[name]: a property of the request chosen by name.
			out = val{req: true}
		}
		return out
	}
	return a.field(base, x.Prop, x.Line, exprText(x))
}

// field reads property prop of base.
func (a *analyzer) field(base val, prop string, line int, text string) val {
	if text != "" && a.globals[text] {
		return val{t: taint.NewSource(line, text, false), ref: text}
	}
	if text != "" && a.reqNames[text] {
		return val{req: true}
	}
	if a.opt.Library && domText[prop] && base.t == nil && !base.req {
		// Text of the page read back (node.textContent, el.getAttribute):
		// written again as HTML it turns escaped text into markup. Only in
		// libraries, which get pages they do not control; an application
		// reads its own markup.
		return val{t: taint.NewSource(line, "DOM text "+prop, true), safe: taint.All &^ taint.XSS}
	}
	if a.opt.Library && text != "" && a.pluginOptions[text] && base.t == nil {
		// Options a jQuery plugin takes from its caller or from data-*
		// attributes of the page.
		return val{t: taint.NewSource(line, text, true)}
	}
	if base.req {
		switch {
		case a.reqProps[prop]:
			what := text
			if what == "" {
				what = "request " + prop
			}
			v := val{t: taint.NewSource(line, what, false)}
			// The request's own URL. As a string it can be a path such as
			// //evil.example; parsed alone with new URL() it has this
			// server's origin (see call).
			v.ownURL = urlOwnOrigin[prop]
			return v
		case a.reqNames[prop] || prop == "request" || prop == "req":
			return val{req: true}
		}
	}
	if base.mod != "" && a.proj != nil {
		if v, ok := a.proj.export(base.mod, prop, 0); ok {
			if base.ref != "" {
				v.ref = base.ref + "." + prop
			}
			return v
		}
	}
	if f, ok := base.fields[prop]; ok {
		if f.owner == nil {
			// A function in an object another file exports is that
			// file's to analyze.
			f.owner = base.owner
		}
		return f
	}
	out := val{}
	if base.ref != "" {
		out.ref = base.ref + "." + prop
	}
	if t := base.anyTaint(); t != nil && prop != "length" {
		out.t, out.safe = t, safeOf(base)
		switch {
		case urlClientParts[prop]:
			out.safe &^= offsite
		case urlOriginParts[prop]:
			out.safe |= offsite
		}
	}
	return out
}

// part is one piece of a string concatenation or template.
type part struct {
	lit   string
	isLit bool
	v     val
}

// concat evaluates a + b + c, flattening the chain.
func (a *analyzer) concat(s *scope, x *js.Binary) val {
	var leaves []js.Expr
	var flatten func(e js.Expr)
	flatten = func(e js.Expr) {
		if b, ok := e.(*js.Binary); ok && b.Op == "+" {
			flatten(b.L)
			flatten(b.R)
			return
		}
		leaves = append(leaves, e)
	}
	flatten(x)
	parts := make([]part, 0, len(leaves))
	out := val{}
	for _, e := range leaves {
		if l, ok := e.(*js.Lit); ok && l.Kind == js.TString {
			parts = append(parts, part{lit: l.Val, isLit: true})
			continue
		}
		v := a.expr(s, e)
		parts = append(parts, part{v: v})
		out = join(out, v)
	}
	if out.t != nil {
		out.t = out.t.Add(x.Line, "concatenation")
		if hostFixed(parts) {
			out.safe |= offsite
		}
	}
	return out
}

// hostFixed reports a concatenation in which no client-chosen part can
// pick the host of a URL: each such part follows literal text that ends a
// host or starts a path, such as "/api/" or "?q=". A part at the start,
// right after another value (origin + next, where next = "@evil"), after a
// lone leading "/" or after "//" or ":" can still change the host.
func hostFixed(parts []part) bool {
	lit := ""
	before := false // anything precedes lit
	for _, p := range parts {
		if p.isLit {
			lit += p.lit
			continue
		}
		if t := p.v.t; t != nil && p.v.safe&offsite != offsite || len(p.v.fields) > 0 && p.v.taintFor(offsite, 0) != nil {
			switch {
			case lit == "",
				!before && (lit == "/" || lit == "\\"),
				strings.HasSuffix(lit, "//"), strings.HasSuffix(lit, ":"), strings.HasSuffix(lit, "\\"), strings.HasSuffix(lit, "@"):
				return false
			}
			return true
		}
		before = true
		lit = ""
	}
	return true
}

// offsite are the kinds that need the client to choose another host.
const offsite = taint.Redirect | taint.SSRF

var (
	// urlOwnOrigin are request properties holding this server's own URL.
	urlOwnOrigin = set([]string{"url", "originalUrl"})
	// urlClientParts of a URL are chosen by the client.
	urlClientParts = set([]string{"searchParams", "search", "hash", "query"})
	// urlOriginParts of a URL name its host.
	urlOriginParts = set([]string{"origin", "host", "hostname", "protocol", "port"})
	// urlPathParts can be assigned on a URL without changing its host.
	urlPathParts = set([]string{"search", "hash", "pathname", "searchParams"})
)

func (a *analyzer) object(s *scope, x *js.ObjectLit) val {
	out := val{fields: map[string]val{}}
	for _, p := range x.Props {
		switch p.Kind {
		case "spread":
			v := a.expr(s, p.Value)
			for k, f := range v.fields {
				out.fields[k] = f
			}
			if t := v.anyTaint(); t != nil && len(v.fields) == 0 {
				out.fields["..."] = val{t: t, safe: safeOf(v)}
			}
			continue
		}
		if p.Computed != nil {
			a.expr(s, p.Computed)
		}
		v := a.expr(s, p.Value)
		if p.Key == "shell" {
			if l, ok := p.Value.(*js.Lit); ok && (l.Val == "true" || l.Kind == js.TString && l.Val != "") {
				out.shell = true
			}
		}
		key := p.Key
		if p.Computed != nil {
			key = "[computed]"
		}
		out.fields[key] = v
	}
	return out
}

func (a *analyzer) jsx(s *scope, x *js.JSXElement) {
	for _, at := range x.Attrs {
		v := a.expr(s, at.Value)
		for _, k := range a.spec.Sinks {
			for _, path := range k.JSX {
				attr, field, _ := strings.Cut(path, ".")
				if at.Name != attr {
					continue
				}
				target := v
				if field != "" {
					target = v.fields[field]
				}
				a.report(k, target, at.Line, at.Line)
			}
		}
	}
	for _, c := range x.Children {
		a.expr(s, c)
	}
}

// bind assigns a value to a pattern.
func (a *analyzer) bind(s *scope, p js.Expr, v val, declare bool) {
	switch p := p.(type) {
	case *js.Ident:
		if v.t != nil {
			v.t = v.t.Add(p.Line, p.Name)
		}
		if declare {
			s.vars[p.Name] = v
		} else {
			s.assign(p.Name, v)
		}
	case *js.ObjectLit:
		for _, pr := range p.Props {
			if pr.Kind == "spread" {
				a.bind(s, pr.Value, v, declare)
				continue
			}
			key := pr.Key
			fv := a.field(v, key, pr.Line, "")
			target := pr.Value
			if as, ok := target.(*js.Assign); ok {
				fv = merge(fv, a.expr(s, as.Value))
				target = as.Target
			}
			a.bind(s, target, fv, declare)
		}
	case *js.ArrayLit:
		elem := val{t: v.anyTaint(), safe: safeOf(v)}
		for _, e := range p.Elems {
			if e != nil {
				a.bind(s, e, elem, declare)
			}
		}
	case *js.Assign:
		a.bind(s, p.Target, merge(v, a.expr(s, p.Value)), declare)
	case *js.Spread:
		a.bind(s, p.X, v, declare)
	case *js.Member:
		a.store(s, p, v)
	}
}

// pageURL are the whole URL of the page: navigating to it again goes
// nowhere new, while a part taken out of it (a split, a search parameter)
// can still be a target an attacker chose.
var pageURL = set([]string{"location", "window.location", "document.location", "location.href", "window.location.href", "document.location.href", "document.URL"})

// dropPageURL replaces the branches of x || y, x ?? y and c ? x : y that
// are the page URL unchanged with an empty string, or returns nil when x
// is that URL.
func dropPageURL(x js.Expr) js.Expr {
	if pageURL[exprText(x)] {
		return nil
	}
	empty := func(at js.Expr, e js.Expr) js.Expr {
		if e == nil {
			return &js.Lit{Pos: js.Pos{Line: at.Ln()}, Kind: js.TString}
		}
		return e
	}
	switch v := x.(type) {
	case *js.Binary:
		if v.Op == "||" || v.Op == "??" {
			l, r := dropPageURL(v.L), dropPageURL(v.R)
			if l != v.L || r != v.R {
				return &js.Binary{Pos: v.Pos, Op: v.Op, L: empty(v.L, l), R: empty(v.R, r)}
			}
		}
	case *js.Cond:
		t, e := dropPageURL(v.Then), dropPageURL(v.Else)
		if t != v.Then || e != v.Else {
			return &js.Cond{Pos: v.Pos, Test: v.Test, Then: empty(v.Then, t), Else: empty(v.Else, e)}
		}
	}
	return x
}

func (a *analyzer) assignExpr(s *scope, x *js.Assign) val {
	value := x.Value
	if x.Op == "=" && pageURL[exprText(x.Target)] {
		// location.href = x || location.href: staying on the page is no
		// redirect.
		value = dropPageURL(value)
	}
	var v val
	if value != nil {
		v = a.expr(s, value)
	}
	if fn, ok := x.Value.(*js.Func); ok {
		v.fn = fn
	}
	if x.Op != "=" {
		old := a.expr(s, x.Target)
		v = join(old, v)
	}
	a.storeEnd = lastLine(x.Value)
	a.bind(s, x.Target, v, false)
	a.storeEnd = 0
	if x.Op == "=" {
		switch t := exprText(x.Target); {
		case t == "module.exports" || t == "exports":
			a.exportVals["default"] = v
		case strings.HasPrefix(t, "module.exports.") && strings.Count(t, ".") == 2,
			strings.HasPrefix(t, "exports.") && strings.Count(t, ".") == 1:
			name := t[strings.LastIndexByte(t, '.')+1:]
			a.exportVals[name] = v
			// module.exports = {...}; module.exports.extra = fn
			if d, ok := a.exportVals["default"]; ok && d.fields != nil {
				d.fields[name] = v
			}
		}
	}
	return v
}

// lastLine is the last line an expression starts a node on: a finding
// on a multi-line argument covers all of it.
func lastLine(x js.Expr) int {
	end := 0
	if x == nil {
		return 0
	}
	js.Inspect(x, func(n js.Node) bool {
		if _, isFn := n.(*js.Func); isFn && n != js.Node(x) {
			return false
		}
		end = max(end, n.Ln())
		return true
	})
	return end
}

// store handles obj.prop = v: property sinks and fields of local objects.
func (a *analyzer) store(s *scope, m *js.Member, v val) {
	text := exprText(m)
	for _, k := range a.spec.Sinks {
		for _, p := range k.Props {
			if m.Computed == nil && (p == m.Prop || p == text) {
				a.report(k, v, m.Line, max(m.Line, a.storeEnd))
			}
		}
	}
	a.expr(s, m.Obj)
	if m.Computed != nil {
		a.expr(s, m.Computed)
	}
	if m.Computed == nil && urlPathParts[m.Prop] && v.t != nil {
		v.safe |= offsite // url.search = x keeps url's host
	}
	root := m.Obj
	var path []string
	if m.Computed == nil {
		path = []string{m.Prop}
	} else {
		path = []string{"[computed]"}
	}
	for {
		mm, ok := root.(*js.Member)
		if !ok || mm.Computed != nil {
			break
		}
		path = append([]string{mm.Prop}, path...)
		root = mm.Obj
	}
	id, ok := root.(*js.Ident)
	if !ok || len(path) > 4 {
		return
	}
	cur, owner, found := s.lookup(id.Name)
	if !found {
		if id.Name != "this" {
			return
		}
		owner = s
	}
	owner.vars[id.Name] = setPath(cur, path, v)
}

func setPath(base val, path []string, v val) val {
	f := make(map[string]val, len(base.fields)+1)
	for k, fv := range base.fields {
		f[k] = fv
	}
	if len(path) == 1 {
		f[path[0]] = v
	} else {
		f[path[0]] = setPath(f[path[0]], path[1:], v)
	}
	base.fields = f
	return base
}

// --- calls ---------------------------------------------------------------

// socketLifecycle events carry no message from a peer.
var socketLifecycle = set([]string{"connect", "connection", "disconnect", "close", "open", "error", "end", "reconnect", "ready", "listening"})

// domText properties hold text of the page.
var domText = set([]string{"nodeValue", "textContent", "innerText", "dataset"})

// responseChain methods return the response for chaining.
var responseChain = set([]string{"status", "set", "type", "header", "append", "cookie", "vary", "location", "links", "contentType", "code", "headers"})

// jqueryObject is the ref of a jQuery selection.
const jqueryObject = "jQuery()"

// booleanMethods return booleans or numbers, never input text.
var booleanMethods = set([]string{"test", "includes", "startsWith", "endsWith", "has", "indexOf", "lastIndexOf", "some", "every", "localeCompare", "exec_", "hasOwnProperty", "existsSync", "isArray", "isBuffer"})

// iterators pass the elements of their receiver to their callback.
var iterators = map[string]int{"forEach": 0, "map": 0, "filter": 0, "some": 0, "every": 0, "find": 0, "findIndex": 0, "flatMap": 0, "reduce": 1, "then": 0}

func (a *analyzer) call(s *scope, c *js.Call) val {
	var recv val
	var method, recvText string
	var callee val
	if m, ok := c.Callee.(*js.Member); ok && m.Computed == nil {
		recv = a.expr(s, m.Obj)
		method = m.Prop
		recvText = exprText(m.Obj)
		callee = a.field(recv, m.Prop, m.Line, exprText(m))
	} else {
		callee = a.expr(s, c.Callee)
	}
	name := callee.ref
	if c.New && name != "" {
		name = "new " + name
	}
	args := make([]val, len(c.Args))
	var anyArg *taint.Trace
	for i, arg := range c.Args {
		if _, isFn := arg.(*js.Func); isFn {
			continue // analyzed below with the right parameters
		}
		args[i] = a.expr(s, arg)
		if t := args[i].anyTaint(); t != nil {
			anyArg = t
		}
	}

	// Callbacks: route handlers get request and response; iterator
	// callbacks get the elements of a tainted receiver.
	handler := a.handlerRecv[recvText] && a.handlerMethods[method] || a.handlerCalls[name]
	// emitter.on('entry', function (entry) {...}): attacker-chosen data.
	event := ""
	if (method == "on" || method == "once" || method == "addListener") && len(c.Args) > 0 {
		if l, ok := c.Args[0].(*js.Lit); ok && l.Kind == js.TString && (a.events[l.Val] || a.socketRecv[shortName(recvText)] && !socketLifecycle[l.Val]) {
			event = l.Val
		}
	}
	for i, arg := range c.Args {
		fn, ok := arg.(*js.Func)
		if !ok {
			continue
		}
		var params []val
		switch {
		case handler:
			params = []val{{req: true}, {res: true}}
		case event != "":
			params = []val{{t: taint.NewSource(fn.Line, "'"+event+"' event data", false)}}
		case recv.anyTaint() != nil && i == 0:
			if idx, ok := iterators[method]; ok {
				params = make([]val, idx+1)
				params[idx] = val{t: recv.anyTaint().Add(c.Line, method), safe: safeOf(recv)}
			}
		}
		a.function(s, fn, a.exportName(fn, fn.Name), params)
		args[i] = val{fn: fn, env: s}
	}

	if name == "require" || name == "import" {
		if len(c.Args) > 0 {
			if l, ok := c.Args[0].(*js.Lit); ok && l.Kind == js.TString {
				if file := a.importFile(l.Val); file != "" {
					return a.proj.moduleVal(l.Val, file)
				}
				return val{ref: moduleName(l.Val)}
			}
		}
		return val{}
	}
	if (name == "promisify" || name == "util.promisify") && len(args) > 0 {
		return val{ref: args[0].ref}
	}
	if method == "bind" {
		return val{ref: recv.ref}
	}

	// new URL(path, base): the base only sets scheme and host, which the
	// path replaces when it is absolute; with a relative path the result
	// stays on the base's origin, so a request URL as base does not make
	// it an open redirect or a request to another host.
	// new URL(request.url) succeeds only for an absolute URL, which for
	// the request's own URL is this server's origin.
	if name == "new URL" && len(args) == 1 && args[0].ownURL {
		v := args[0]
		return val{t: v.t, safe: safeOf(v) | offsite}
	}
	if name == "new URL" && len(args) >= 2 {
		base := args[1]
		args = append([]val{}, args...)
		args[1] = val{t: base.anyTaint(), safe: safeOf(base) | taint.Redirect | taint.SSRF}
	}

	a.sinks(c, name, method, recvText, recv, args)

	// Functions named like sanitizers (safeNextPath, sanitizeName,
	// escapeArg) return a checked value.
	if n := shortName(exprText(c.Callee)); callee.fn == nil && isSanitizerName(n) && a.spec.Sanitizes(name) == 0 {
		return val{}
	}

	// A function of this file: follow it through its summary.
	if callee.fn != nil && !c.New {
		if out, ok := a.applySummary(c, callee, args); ok {
			return out
		}
	}
	if callee.fn != nil && c.New {
		a.applySummary(c, callee, args)
	}

	// The result.
	if k := a.sanitizes(name); k != 0 {
		if k == taint.All {
			return val{}
		}
		out := val{}
		for _, v := range args {
			out = join(out, v)
		}
		out.safe |= k
		return out
	}
	if method == "replace" && !a.opt.Library {
		a.shapeOnTainted(c, recv)
	}
	if method == "replace" || method == "replaceAll" {
		if len(c.Args) == 2 && stripsToSafe(c.Args[0], c.Args[1]) {
			return val{}
		}
		if len(c.Args) == 2 && stripsDotDot(c.Args[0], c.Args[1]) {
			out := recvTaint(recv, method)
			out.safe |= taint.Path
			return out
		}
	}
	if booleanMethods[method] || method != "" && isValidatorName(method) && method != "match" && !strings.HasPrefix(method, "matchAll") {
		return val{}
	}
	if a.opt.Library && method == "getAttribute" && recv.t == nil && !recv.req {
		return val{t: taint.NewSource(c.Line, "DOM attribute", true), safe: taint.All &^ taint.XSS}
	}
	if req := recv.req; req && a.reqMethods[method] {
		return val{t: taint.NewSource(c.Line, recvText+"."+method+"()", false)}
	}
	out := val{}
	for _, v := range args {
		out = join(out, v)
	}
	if method == "" && name != "" && name != "new URL" {
		// A function from another module: a value it derives is usually
		// checked or mapped (localizedPath(locale)), so it no longer
		// chooses a host. Text built from it is still followed.
		out.safe |= offsite
	}
	out = join(out, recvTaint(recv, method))
	if name == "$" || name == "jQuery" || recv.ref == jqueryObject {
		out.ref = jqueryObject
	}
	if recv.res && responseChain[method] {
		out.res = true // res.status(400).send(x)
	}
	if out.t != nil && anyArg != nil && name != "" {
		out.t = out.t.Add(c.Line, shortName(name)+"()")
	}
	return out
}

func recvTaint(recv val, method string) val {
	if method == "" {
		return val{}
	}
	return val{t: recv.anyTaint(), safe: safeOf(recv)}
}

func shortName(n string) string {
	if i := strings.LastIndexByte(n, '.'); i >= 0 && i < len(n)-1 {
		return n[i+1:]
	}
	return n
}

// sanitizes returns the kinds a call makes its result safe for.
func (a *analyzer) sanitizes(name string) taint.Kind {
	if name != "" {
		if k := a.spec.Sanitizes(name); k != 0 {
			return k
		}
		if k := a.spec.Sanitizes(strings.TrimPrefix(name, "new ")); k != 0 {
			return k
		}
	}
	return 0
}

// stripsToSafe reports x.replace(/[^a-z0-9]/g, ”): a negated character
// class removed everywhere leaves only the allowed characters.
func stripsToSafe(pattern, repl js.Expr) bool {
	re, ok := pattern.(*js.Lit)
	if !ok || re.Kind != js.TRegex || !strings.HasPrefix(re.Val, "/[^") {
		return false
	}
	end := strings.LastIndexByte(re.Val, '/')
	if end <= 0 || !strings.Contains(re.Val[end:], "g") || !strings.HasSuffix(re.Val[:end], "]") && !strings.HasSuffix(re.Val[:end], "]+") {
		return false
	}
	r, ok := repl.(*js.Lit)
	return ok && r.Kind == js.TString && r.Val == ""
}

// stripsDotDot reports x.replace(/\.\.\//g, ”): parent directory
// segments removed from a path.
func stripsDotDot(pattern, repl js.Expr) bool {
	re, ok := pattern.(*js.Lit)
	if !ok || re.Kind != js.TRegex || !strings.Contains(re.Val, `\.\.`) {
		return false
	}
	r, ok := repl.(*js.Lit)
	return ok && r.Kind == js.TString && r.Val == ""
}

// sinks reports tainted arguments of dangerous calls.
func (a *analyzer) sinks(c *js.Call, name, method, recvText string, recv val, args []val) {
	any := false
	for _, v := range args {
		if v.anyTaint() != nil {
			any = true
		}
	}
	if !any {
		return
	}
	for _, k := range a.spec.Sinks {
		if t, ok := k.Calls[name]; ok {
			a.reportArgs(k, c, args, t.Arg)
			continue
		}
		if t, ok := k.Calls[strings.TrimPrefix(name, "new ")]; ok && strings.HasPrefix(name, "new ") {
			a.reportArgs(k, c, args, t.Arg)
			continue
		}
		if t, ok := k.CallsWithShell[name]; ok {
			shell := false
			for _, v := range args {
				shell = shell || v.shell
			}
			if shell {
				a.reportArgs(k, c, args, t.Arg)
			}
			continue
		}
		if method == "" {
			continue
		}
		t, ok := k.Methods[method]
		if !ok {
			continue
		}
		if !a.receiverOK(k, method, recvText, recv) {
			continue
		}
		a.reportArgs(k, c, args, t.Arg)
	}
}

func (a *analyzer) receiverOK(k *taint.Sink, method, recvText string, recv val) bool {
	for _, n := range k.ReceiversNot {
		if recvText == n {
			return false
		}
	}
	allowed, restricted := k.MethodReceivers[method]
	if !restricted {
		return true
	}
	for _, n := range allowed {
		switch {
		case recvText == n, n == "res" && recv.res:
			return true
		case n == "$" && (recv.ref == jqueryObject || strings.HasPrefix(recvText, "$")):
			// "$" stands for a jQuery object: $(sel), $el, $(sel).find(x).
			return true
		}
	}
	return false
}

func (a *analyzer) reportArgs(k *taint.Sink, c *js.Call, args []val, idx int) {
	for i, v := range args {
		if idx >= 0 && i != idx {
			continue
		}
		end := c.Line
		if i < len(c.Args) {
			end = max(end, lastLine(c.Args[i]))
		}
		a.report(k, v, c.Line, end)
	}
}

func (a *analyzer) report(k *taint.Sink, v val, line, end int) {
	a.reportTrace(k, v.taintFor(k.Kind, 0), nil, "", line, end)
}

// reportTrace reports trace t reaching sink k at line, after the steps in
// tail (inside a called function). A placeholder trace of the function
// being summarized becomes part of its summary instead.
// file is the file of the sink when it is in another file of the project.
func (a *analyzer) reportTrace(k *taint.Sink, t *taint.Trace, tail []taint.Step, file string, line, end int) {
	if t == nil || k.RequestOnly && t.Library {
		return
	}
	if t.Param > 0 {
		run := a.cur
		if run == nil || t.Root() != run.marker {
			return // a placeholder of another summary
		}
		steps := append(append([]taint.Step{}, t.Steps()[1:]...), tail...)
		key := file + "|" + k.ID + "|" + strconv.Itoa(line)
		if !run.hitSeen[key] {
			run.hitSeen[key] = true
			run.hits = append(run.hits, sinkHit{sink: k, line: line, end: end, steps: steps, file: file})
		}
		return
	}
	if file == "" || file == a.file {
		file = ""
	}
	at := a.file
	if file != "" {
		at = file
	}
	key := at + "|" + k.ID + "|" + strconv.Itoa(line)
	if a.seen[key] {
		return
	}
	a.seen[key] = true
	steps := append(t.Steps(), tail...)
	if file != "" {
		// The steps of this file name it: the finding is in the other.
		for i := range steps {
			if steps[i].File == "" {
				steps[i].File = a.file
			} else if steps[i].File == file {
				steps[i].File = ""
			}
		}
	}
	steps = append(steps, taint.Step{Line: line, What: k.Title})
	a.out = append(a.out, taint.Finding{Sink: k, File: at, Line: line, EndLine: end, Steps: steps, Library: t.Library})
}

// inFile marks steps of another module m with its file.
func inFile(steps []taint.Step, m *analyzer) []taint.Step {
	if m == nil {
		return steps
	}
	out := make([]taint.Step, len(steps))
	for i, st := range steps {
		if st.File == "" {
			st.File = m.file
		}
		out[i] = st
	}
	return out
}

// returned records a return of the function being summarized.
func (a *analyzer) returned(v val) {
	run := a.cur
	if run == nil || a.fnNest != run.nest {
		return
	}
	t := v.anyTaint()
	if t == nil {
		return
	}
	if t.Param == 0 {
		run.other = join(run.other, v)
		return
	}
	if t.Root() != run.marker {
		return
	}
	if !run.ret.ok {
		run.ret.ok, run.ret.safe, run.ret.steps = true, safeOf(v), t.Steps()[1:]
		return
	}
	run.ret.safe &= safeOf(v)
}

// maxSummaryParams bounds the parameters followed per function.
const maxSummaryParams = 8

// summarize computes the summary of fn, defined in env, once per function:
// each parameter in turn carries a placeholder trace through the body. It
// returns nil for a function whose summary is being computed (recursion).
func (a *analyzer) summarize(fn *js.Func, env *scope) *summary {
	if sum, ok := a.sums[fn]; ok {
		return sum
	}
	a.sums[fn] = nil
	n := len(fn.Params)
	if n > maxSummaryParams {
		n = maxSummaryParams
	}
	sum := &summary{ret: make([]retFlow, n), sinks: make([][]sinkHit, n), rest: -1}
	if n > 0 {
		if _, ok := fn.Params[len(fn.Params)-1].(*js.Spread); ok && len(fn.Params) <= maxSummaryParams {
			sum.rest = len(fn.Params) - 1
		}
	}
	saveCur, saveDone, saveNest := a.cur, a.done, a.fnNest
	runs := n
	if runs == 0 {
		runs = 1 // still learn what it returns from its own sources
	}
	for i := 0; i < runs; i++ {
		run := &sumRun{marker: taint.NewMarker(fn.Line, i), hitSeen: map[string]bool{}}
		a.cur, a.done = run, map[*js.Func]bool{fn: true}
		a.fnNest++
		run.nest = a.fnNest
		s := newScope(env)
		a.presetThis(s, fn)
		for j, p := range fn.Params {
			v := val{}
			if j == i {
				v = val{t: run.marker}
			}
			a.bindParam(s, p, v)
		}
		if fn.ExprBody != nil {
			a.returned(a.expr(s, fn.ExprBody))
		} else {
			a.body(s, fn.Body)
		}
		a.fnNest = saveNest
		if i < n {
			sum.ret[i], sum.sinks[i] = run.ret, run.hits
		}
		if i == 0 {
			sum.other = run.other
		}
	}
	a.cur, a.done = saveCur, saveDone
	a.sums[fn] = sum
	return sum
}

// applySummary follows a call of a function of the file: arguments reach
// the sinks inside it and, where it returns them, the result.
func (a *analyzer) applySummary(c *js.Call, callee val, args []val) (val, bool) {
	// A function of another file is summarized by that file's analysis;
	// its steps and sinks are then marked with that file.
	owner, foreign := a, (*analyzer)(nil)
	if callee.owner != nil && callee.owner != a {
		owner, foreign = callee.owner, callee.owner
	}
	sum := owner.summarize(callee.fn, callee.env)
	if sum == nil {
		return val{}, false
	}
	name := callee.fn.Name
	if m, ok := c.Callee.(*js.Member); ok && m.Computed == nil {
		name = m.Prop
	}
	if name == "" {
		name = "function"
	}
	out := val{}
	if t := sum.other.anyTaint(); t != nil {
		if foreign != nil {
			t = taint.FromSteps(inFile(t.Steps(), foreign), t.Library)
		}
		out = val{t: t.Add(c.Line, name+"()"), safe: safeOf(sum.other)}
	}
	for j, v := range args {
		i := j
		if sum.rest >= 0 && i > sum.rest {
			i = sum.rest
		}
		if i >= len(sum.ret) {
			break
		}
		t := v.anyTaint()
		if t == nil {
			continue
		}
		via := t.Add(c.Line, name+"()")
		for _, h := range sum.sinks[i] {
			if tk := v.taintFor(h.sink.Kind, 0); tk != nil {
				file := h.file
				if file == "" && foreign != nil {
					file = foreign.file
				}
				a.reportTrace(h.sink, tk.Add(c.Line, name+"()"), inFile(h.steps, foreign), file, h.line, h.end)
			}
		}
		if r := sum.ret[i]; r.ok {
			rt := via
			for _, st := range inFile(r.steps, foreign) {
				rt = rt.AddStep(st)
			}
			out = join(out, val{t: rt, safe: safeOf(v) | r.safe})
		}
	}
	return out, true
}

// isSQLTag reports a template tag that builds a parameterized query: sql,
// db.sql, or a call returning the tag, as in sql()`...`.
func isSQLTag(x js.Expr, v val) bool {
	if c, ok := x.(*js.Call); ok {
		x = c.Callee
	}
	t := exprText(x)
	return t == "sql" || strings.HasSuffix(t, ".sql") || v.ref == "sql"
}
