package flow

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// Loader returns the module of a project with a dotted name and its source
// lines, or nil when the project has no such module (a library).
type Loader func(name string) (*ir.Module, []string)

// Bounds of the analysis of calls: how deep calls nest, and how many
// distinct calls the analysis of one module may add before the rest only
// pass taint through, and how much work (state entries handled) it may spend
// before the same happens. The work bound keeps the scan of a project of
// thousands of large pages in minutes. The bounds are per module, so the
// order in which modules are analyzed does not starve the last ones.
const (
	maxCallDepth = 4
	maxCalls     = 2000
	maxWork      = 500_000
	// maxCheckCalls is how many calls of checking functions are followed
	// after maxCalls is reached; maxCheckBlocks is the size of one.
	maxCheckCalls  = 2000
	maxCheckBlocks = 40
)

type callResult struct {
	ret, self *Value
	validates bool
}

// Project analyzes the modules of one project together: a call of a
// function or class another module defines is analyzed with the actual
// arguments, so data a helper returns and sinks a helper reaches are
// followed across files.
type Project struct {
	e     *Engine
	load  Loader
	runs  map[string]*run
	byMod map[*ir.Module]*run
	none  map[string]bool
	owner map[*ir.Function]*run
	// classes maps an instance's class name (module.Class) to the class
	// body.
	classes  map[string]*ir.Function
	findings map[string]taint.Finding
	order    []string
	// Library makes the parameters of exported functions sources, for a
	// published package (hypotheses).
	Library  bool
	handlers map[*ir.Function]bool
	memo     map[string]callResult
	active   map[*ir.Function]bool
	// invoked are the functions analyzed for a call (uncalled).
	invoked map[*ir.Function]bool
	depth   int
	calls   int
	// work counts the state entries the analysis of the current module has
	// handled, its own functions and the calls it followed.
	work int
}

// NewProject starts the analysis of a project whose modules load returns.
func (e *Engine) NewProject(load Loader) *Project {
	return &Project{e: e, load: load, runs: map[string]*run{}, byMod: map[*ir.Module]*run{}, none: map[string]bool{}, owner: map[*ir.Function]*run{},
		classes: map[string]*ir.Function{}, findings: map[string]taint.Finding{}, memo: map[string]callResult{}, active: map[*ir.Function]bool{}, handlers: map[*ir.Function]bool{},
		invoked: map[*ir.Function]bool{}}
}

// handler analyzes a function a route call registers, with the request
// and response the call gives it.
func (p *Project) handler(fn *ir.Function, rc taint.RouteCall) {
	owner := p.owner[fn]
	if owner == nil || p.handlers[fn] || p.depth >= maxCallDepth {
		return
	}
	p.handlers[fn] = true
	entry := State{}
	for i, prm := range fn.Params {
		switch i {
		case 0:
			entry[prm.Name] = &Value{Q: rc.Request}
		case 1:
			entry[prm.Name] = &Value{Inst: rc.Response}
		default:
			entry[prm.Name] = &Value{}
		}
	}
	p.depth++
	owner.function(fn, entry, false)
	p.depth--
}

// listener analyzes a function an event call registers, with the event's
// data in its parameters.
func (p *Project) listener(fn *ir.Function, t *taint.Trace) {
	owner := p.owner[fn]
	if owner == nil || p.handlers[fn] {
		return
	}
	p.handlers[fn] = true
	entry := State{}
	for _, prm := range fn.Params {
		entry[prm.Name] = &Value{T: t}
	}
	owner.function(fn, entry, false)
}

// exported analyzes the functions a module exports with their parameters
// as sources: in a published package the caller decides what they hold.
// Each exported function gets its own budget of calls, so that a large
// script of many does not starve the last ones.
func (p *Project) exported(r *run) {
	all := State{}
	for name, v := range r.stored {
		all[name] = v
	}
	for name, v := range r.exit {
		if r.mod.Exports == nil || r.mod.Exports[name] {
			all[name] = v
		}
	}
	// module.exports = obj exports the functions of the object.
	if v, ok := all["default"]; ok && v.Inst == "dict" {
		for k, fv := range v.Fields {
			if _, ok := all[k]; !ok && fv.Fn != nil && !strings.HasPrefix(k, ".") && !strings.HasPrefix(k, "#") {
				all[k] = fv
			}
		}
	}
	// exports.parser = { parse: function () {} }: the functions of an
	// exported object are exported with it.
	for _, name := range sortedKeys(all) {
		v := all[name]
		if name == "default" || v.Inst != "dict" {
			continue
		}
		for k, fv := range v.Fields {
			if _, ok := all[k]; !ok && fv.Fn != nil && !strings.HasPrefix(k, ".") && !strings.HasPrefix(k, "#") && !strings.HasPrefix(k, "$") {
				all[k] = fv
			}
		}
	}
	for _, name := range sortedKeys(all) {
		v := all[name]
		// module.exports = new Client(): the methods of the instance, as
		// the module built it.
		if class := p.classes[v.Inst]; v.Fn == nil && class != nil && p.owner[class] == r && !strings.HasPrefix(name, "$") {
			for _, m := range r.mod.Funcs {
				if m.Parent == class && !strings.HasSuffix(m.Name, ".__init__") && len(m.Params) > 0 {
					entry := State{m.Params[0].Name: v}
					p.calls, p.work = 0, 0
					r.function(m, p.exportedParams(r, m, name, entry), false)
				}
			}
			continue
		}
		if v.Fn == nil || strings.HasPrefix(name, "$") || p.owner[v.Fn] != r {
			continue
		}
		params := func(fn *ir.Function, entry State) State { return p.exportedParams(r, fn, name, entry) }
		if !isClass(v.Fn) {
			p.calls, p.work = 0, 0
			r.function(v.Fn, params(v.Fn, State{}), false)
			continue
		}
		// An exported class: built with arguments from the caller, then
		// each method called with arguments from the caller.
		class := v.Fn
		inst := &Value{Inst: className(r.mod, class)}
		if init := p.method(class, "__init__", 0); init != nil {
			p.calls, p.work = 0, 0
			if _, self, _ := r.analyzeFn(init, params(init, State{init.Params[0].Name: inst}), false); self != nil {
				inst = self.copy()
				inst.Inst = className(r.mod, class)
			}
		}
		for _, m := range r.mod.Funcs {
			if m.Parent == class && !strings.HasSuffix(m.Name, ".__init__") && len(m.Params) > 0 {
				entry := State{}
				if !decorated(m, "staticmethod") {
					entry[m.Params[0].Name] = inst
				}
				p.calls, p.work = 0, 0
				r.function(m, params(m, entry), false)
			}
		}
	}
}

// exportedParams sets the parameters of an exported function that entry
// does not set to sources: the caller of a published package decides
// what they hold.
func (p *Project) exportedParams(r *run, fn *ir.Function, name string, entry State) State {
	for _, prm := range fn.Params {
		if _, set := entry[prm.Name]; set {
			continue
		}
		t := taint.NewSource(prm.Pos.Line, "parameter "+prm.Name+" of exported "+name, true)
		t.File = r.mod.Path
		entry[prm.Name] = &Value{T: t}
	}
	return entry
}

// SetProperties gives the engine the keys and values of the project's
// .properties files, which Properties.getProperty(key, default) reads.
func (p *Project) SetProperties(props map[string]string) { p.e.props = props }

// AnalyzeOne analyzes a module that is not loaded by name, such as a
// single file.
func (p *Project) AnalyzeOne(m *ir.Module, lines []string) []taint.Finding {
	before := len(p.order)
	return p.analyze(p.add(m, lines), before)
}

// Module analyzes every function of a module and returns the flows found
// since the previous call, in this module or in the modules it calls.
func (p *Project) Module(name string) []taint.Finding {
	before := len(p.order)
	r := p.module(name)
	if r == nil {
		return nil
	}
	return p.analyze(r, before)
}

// analyze roots every function of a module and returns the findings
// recorded since before, which counts the ones loading the module made:
// add analyzes the module body, and with it the handlers it registers.
func (p *Project) analyze(r *run, before int) []taint.Finding {
	p.calls, p.work = 0, 0
	for _, fn := range r.mod.Funcs {
		r.root(fn)
	}
	if p.Library {
		p.exported(r)
	}
	keys := append([]string(nil), p.order[before:]...)
	sort.Strings(keys)
	out := make([]taint.Finding, 0, len(keys))
	for _, k := range keys {
		out = append(out, p.findings[k])
	}
	return out
}

// module returns the analysis of a module of the project, loading and
// setting it up on first use.
func (p *Project) module(name string) *run {
	if r, ok := p.runs[name]; ok {
		return r
	}
	if name == "" || p.none[name] {
		return nil
	}
	m, lines := p.load(name)
	if m == nil {
		p.none[name] = true
		return nil
	}
	if r, ok := p.byMod[m]; ok {
		// the same file under another name (with and without a source
		// root directory)
		p.runs[name] = r
		return r
	}
	return p.add(m, lines)
}

// add sets up a module: its body and class bodies run first, so that its
// names, classes and methods are known to callers.
func (p *Project) add(m *ir.Module, lines []string) *run {
	r := &run{e: p.e, p: p, mod: m, lines: lines, envs: map[*ir.Function]State{}, done: map[*ir.Function]bool{}}
	for _, fw := range p.e.spec.Sources.HTMLReturnFrameworks {
		r.html = r.html || imports(m.Init, fw)
	}
	p.byMod[m] = r
	if m.Name != "" {
		p.runs[m.Name] = r
	}
	for _, fn := range m.Funcs {
		p.owner[fn] = r
		if isClass(fn) {
			p.classes[className(m, fn)] = fn
		}
	}
	r.root(m.Init)
	for _, fn := range m.Funcs {
		if isClass(fn) {
			r.root(fn)
		}
	}
	return r
}

func isClass(fn *ir.Function) bool { return strings.HasPrefix(fn.Name, "<class ") }

// className is the name instances of a class are known by.
func className(m *ir.Module, fn *ir.Function) string {
	if m.Name == "" {
		return m.Path + ":" + fn.Class
	}
	if m.Name == fn.Class || strings.HasSuffix(m.Name, "."+fn.Class) {
		return m.Name // a module named after its class (Java)
	}
	return m.Name + "." + fn.Class
}

// resolve finds the function or class a qualified name refers to, through
// the modules of the project and the names they import.
func (p *Project) resolve(q string, hops int) *ir.Function {
	if hops > 4 {
		return nil
	}
	parts := strings.Split(q, ".")
	// A module named after its class (Java): the name is the class; a
	// module whose default export is a function (JavaScript
	// module.exports = fn).
	if r := p.module(q); r != nil {
		if v, ok := r.exit[parts[len(parts)-1]]; ok && v.Fn != nil {
			return v.Fn
		}
		if v, ok := r.exit["default"]; ok && v.Fn != nil {
			return v.Fn
		}
	}
	for i := len(parts) - 1; i >= 1; i-- {
		r := p.module(strings.Join(parts[:i], "."))
		if r == nil {
			continue
		}
		return p.member(r, parts[i:], hops)
	}
	return nil
}

// member finds the function or class path names in a module.
func (p *Project) member(r *run, path []string, hops int) *ir.Function {
	v, ok := r.exit[path[0]]
	if !ok {
		// a submodule of a package that its __init__ does not import
		return p.resolve(r.mod.Name+"."+strings.Join(path, "."), hops+1)
	}
	switch {
	case v.Fn != nil && len(path) == 1:
		return v.Fn
	case v.Fn != nil && len(path) == 2 && isClass(v.Fn):
		return p.method(v.Fn, path[1], 0)
	case v.Q != "":
		return p.resolve(strings.Join(append([]string{v.Q}, path[1:]...), "."), hops+1)
	}
	return nil
}

// method finds a method of a class or of its bases.
func (p *Project) method(class *ir.Function, name string, depth int) *ir.Function {
	r := p.owner[class]
	if r == nil || depth > 6 {
		return nil
	}
	want := class.Class + "." + name
	for _, fn := range r.mod.Funcs {
		if fn.Parent == class && fn.Name == want {
			return fn
		}
	}
	for _, b := range class.Bases {
		if base := p.classNamed(r, b); base != nil {
			if m := p.method(base, name, depth+1); m != nil {
				return m
			}
		}
	}
	return nil
}

// classNamed resolves a dotted name in a module to a class of the project.
func (p *Project) classNamed(r *run, name string) *ir.Function {
	parts := strings.Split(name, ".")
	v, ok := r.exit[parts[0]]
	if !ok {
		return nil
	}
	var fn *ir.Function
	switch {
	case v.Fn != nil && len(parts) == 1:
		fn = v.Fn
	case v.Q != "":
		fn = p.resolve(strings.Join(append([]string{v.Q}, parts[1:]...), "."), 0)
	}
	if fn != nil && isClass(fn) {
		return fn
	}
	return nil
}

// project analyzes a call of a function, class or method the project
// defines; ok is false for anything else.
func (f *fnRun) project(c *call, st State) (*Value, bool) {
	p := f.p
	in := c.in
	var fn *ir.Function
	var self *Value
	switch {
	case in.Name == "":
		callee := f.val(st, in.A)
		switch {
		case callee.Fn != nil:
			fn = callee.Fn
		case callee.Q != "":
			fn = p.resolve(callee.Q, 0)
		}
	case c.recv.Q != "":
		fn = p.resolve(c.recv.Q+"."+in.Name, 0)
	case c.recv.Inst != "":
		if class := p.classes[c.recv.Inst]; class != nil {
			fn = p.method(class, in.Name, 0)
			self = c.recv
		}
	case c.recv.Fn != nil && isClass(c.recv.Fn):
		fn = p.method(c.recv.Fn, in.Name, 0) // Class.method(...)
	}
	if fn == nil && in.Name != "" {
		// a method stored in an object: obj.m() with { m() {...} }
		for _, k := range []string{"." + in.Name, in.Name} {
			if v, ok := c.recv.Fields[k]; ok && v.Fn != nil {
				fn = v.Fn
				if len(fn.Params) > 0 && fn.Params[0].Name == "this" {
					self = c.recv
				}
				break
			}
		}
	}
	if fn == nil || decorated(fn, "abstract") {
		return nil, false
	}
	if isClass(fn) {
		return f.instantiate(fn, c), true
	}
	if decorated(fn, "staticmethod") {
		self = nil
	} else if decorated(fn, "classmethod") {
		self = &Value{}
	}
	ret, selfOut, validates, ok := f.invoke(fn, self, c)
	if !ok {
		return nil, false
	}
	if validates {
		// check(x) raised on what it rejects: x passed it.
		for _, a := range in.Args {
			if name := f.root(a); name != "" {
				if v, ok := st[name]; ok && v.T != nil {
					n := v.copy()
					n.Safe = taint.All
					st[name] = n
				}
			}
		}
	}
	if self != nil && selfOut != nil && in.A.Var != "" && c.recv.Inst != "" {
		// a method that sets attributes of self
		n := selfOut.copy()
		n.Inst = c.recv.Inst
		st[in.A.Var] = n
	}
	return ret, true
}

func decorated(fn *ir.Function, name string) bool {
	for _, d := range fn.Decorators {
		if d.Name == name {
			return true
		}
	}
	return false
}

// instantiate builds an instance of a class of the project, with the
// attributes its __init__ sets.
func (f *fnRun) instantiate(class *ir.Function, c *call) *Value {
	r := f.p.owner[class]
	inst := &Value{Inst: className(r.mod, class)}
	if init := f.p.method(class, "__init__", 0); init != nil {
		if _, selfOut, _, ok := f.invoke(init, inst, c); ok && selfOut != nil {
			inst = selfOut.copy()
			inst.Inst = className(r.mod, class)
		}
	}
	// The object as a whole carries what its attributes hold.
	for _, k := range sortedKeys(inst.Fields) {
		if v := inst.Fields[k]; v.T != nil {
			inst = mix(inst, &Value{T: v.T, Safe: v.Safe, Opaque: true})
		}
	}
	return inst
}

// invoke analyzes fn with the arguments of a call, once per distinct
// arguments.
func (f *fnRun) invoke(fn *ir.Function, self *Value, c *call) (ret, selfOut *Value, validates, ok bool) {
	p := f.p
	owner := p.owner[fn]
	if owner == nil || p.active[fn] || p.depth >= maxCallDepth {
		return nil, nil, false, false
	}
	entry := bind(fn, self, c)
	// A nested function also reads its enclosing scope, which the key does
	// not hold: it is analyzed again at each call.
	closure := fn.Parent != nil && fn.Parent != owner.mod.Init && !isClass(fn.Parent)
	key := memoKey(fn, entry)
	if r, ok := p.memo[key]; ok && !closure {
		return r.ret, r.self, r.validates, true
	}
	if p.calls >= maxCalls || p.work >= maxWork {
		// A check that raises on what it rejects is small and is what
		// makes the code after its call safe, so a call of one is followed
		// past the budget, up to a hard limit (#588).
		if p.calls >= maxCalls+maxCheckCalls || p.work >= maxWork*4 || !isRaiseOnly(fn) {
			return nil, nil, false, false
		}
	}
	p.calls++
	p.invoked[fn] = true
	p.active[fn] = true
	p.depth++
	ret, selfOut, validates = owner.analyzeFn(fn, entry, false)
	p.depth--
	delete(p.active, fn)
	if ret == nil {
		ret = &Value{}
	}
	p.memo[key] = callResult{ret, selfOut, validates}
	return ret, selfOut, validates, true
}

// bind sets the parameters of fn from the arguments of a call.
func bind(fn *ir.Function, self *Value, c *call) State {
	entry := State{}
	params := fn.Params
	if self != nil && len(params) > 0 && params[0].Kind == "" {
		entry[params[0].Name] = self
		params = params[1:]
	}
	pos := c.args
	for _, prm := range params {
		switch prm.Kind {
		case "*":
			rest := &Value{Known: true, Elems: []*Value{}}
			for _, a := range pos {
				rest.Elems = append(rest.Elems, a)
				rest = mix(rest, a)
			}
			pos = nil
			entry[prm.Name] = rest
		case "**":
			kw := &Value{Fields: map[string]*Value{}}
			for k, v := range c.kw {
				if _, named := entry[k]; !named {
					kw.Fields[k] = v
					kw = mix(kw, v)
				}
			}
			entry[prm.Name] = kw
		default:
			switch v, ok := c.kw[prm.Name]; {
			case len(pos) > 0:
				entry[prm.Name] = pos[0]
				pos = pos[1:]
			case ok:
				entry[prm.Name] = v
			case prm.Default != nil:
				entry[prm.Name] = constVal(prm.Default)
			default:
				entry[prm.Name] = &Value{}
			}
		}
	}
	return entry
}

// memoKey identifies a call by its function and what the engine knows
// about each argument, traces included, so that a flow keeps the steps of
// its own call.
func memoKey(fn *ir.Function, entry State) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%p", fn)
	for _, k := range sortedKeys(entry) {
		sb.WriteString("|" + k + "=")
		encode(&sb, entry[k], 0)
	}
	return sb.String()
}

func encode(sb *strings.Builder, v *Value, depth int) {
	if v == nil {
		return
	}
	if v.T != nil {
		fmt.Fprintf(sb, "t%p/%d/%t", v.T, v.Safe, v.Opaque)
	}
	if v.C != nil {
		fmt.Fprintf(sb, "c%d:%q", v.C.Kind, v.C.Val)
	}
	if v.Q != "" {
		sb.WriteString("q" + v.Q)
	}
	if v.Inst != "" {
		sb.WriteString("i" + v.Inst)
	}
	if v.Fn != nil {
		fmt.Fprintf(sb, "f%p", v.Fn)
	}
	if v.Norm {
		sb.WriteString("n")
	}
	if v.Pure {
		sb.WriteString("p")
	}
	if v.From != "" {
		sb.WriteString("u" + v.From)
	}
	if v.W != nil {
		fmt.Fprintf(sb, "w%p/%d", v.W, v.WK)
	}
	if depth >= 2 {
		return
	}
	if v.Known {
		sb.WriteString("[")
		for _, e := range v.Elems {
			encode(sb, e, depth+1)
			sb.WriteString(",")
		}
		sb.WriteString("]")
	}
	if len(v.Fields) > 0 {
		sb.WriteString("{")
		for _, k := range sortedKeys(v.Fields) {
			sb.WriteString(k + ":")
			encode(sb, v.Fields[k], depth+1)
			sb.WriteString(",")
		}
		sb.WriteString("}")
	}
}

// export records a function stored into the module's exports by code the
// lowering does not see as a module export: exports.f = fn inside a
// function, such as the (function () { ... })() a module wraps itself in,
// or f = exports.f = fn.
// prototypeMethod records a function stored as a method of a prototype,
// X.prototype.m = function () {...}: a library's callers reach its
// methods through the instances it hands out, so they count as exported.
func (f *fnRun) prototypeMethod(in *ir.Instr, v *Value) {
	d := f.fn.Defs[in.A.Var]
	if v.Fn == nil || d == nil || d.Op != ir.Load || d.Name != "prototype" {
		return
	}
	owner := f.receiverName(d)
	if owner == "" {
		owner = "?"
	}
	k := owner + ".prototype." + in.Name
	if f.stored == nil {
		f.stored = map[string]*Value{}
	}
	if _, ok := f.stored[k]; !ok {
		f.stored[k] = v
	}
}

func (f *fnRun) export(q, name string, v *Value) {
	var names map[string]*Value
	switch {
	case q == "exports" || q == "module.exports":
		names = map[string]*Value{name: v}
	case q == "module" && name == "exports":
		names = map[string]*Value{"default": v}
		for k, fv := range v.Fields {
			if v.Inst == "dict" {
				names[strings.TrimPrefix(k, ".")] = fv
			}
		}
	}
	for k, fv := range names {
		if fv.Fn == nil {
			continue
		}
		if f.stored == nil {
			f.stored = map[string]*Value{}
		}
		if _, ok := f.stored[k]; !ok {
			f.stored[k] = fv
		}
	}
}

// isRaiseOnly reports a small function that returns no value and raises on
// some path: a check such as validateRequest(req, name) that throws on what
// it rejects.
func isRaiseOnly(fn *ir.Function) bool {
	if len(fn.Blocks) > maxCheckBlocks {
		return false
	}
	raises := false
	for _, b := range fn.Blocks {
		switch b.Term.Kind {
		case ir.Raise:
			raises = true
		case ir.Return:
			if v := b.Term.Value; !v.IsZero() && !(v.Const != nil && v.Const.Kind == ir.None) {
				return false
			}
		}
	}
	return raises
}
