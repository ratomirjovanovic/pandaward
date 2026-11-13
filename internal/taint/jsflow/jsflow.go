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
func Analyze(f *js.File, spec *taint.Spec, opt Options) []taint.Finding {
	a := &analyzer{spec: spec, file: f.Path, opt: opt, seen: map[string]bool{}, done: map[*js.Func]bool{},
		exportedFns: map[*js.Func]string{}, exportedNames: map[string]bool{}, exportedClasses: map[*js.Class]bool{}}
	a.index()
	if opt.Library {
		a.collectExports(f)
	}
	top := newScope(nil)
	a.body(top, f.Stmts)
	sort.Slice(a.out, func(i, j int) bool {
		if a.out[i].Line != a.out[j].Line {
			return a.out[i].Line < a.out[j].Line
		}
		return a.out[i].Sink.ID < a.out[j].Sink.ID
	})
	return a.out
}

type analyzer struct {
	spec  *taint.Spec
	file  string
	opt   Options
	out   []taint.Finding
	seen  map[string]bool
	done  map[*js.Func]bool
	steps int

	reqNames, reqProps, reqMethods map[string]bool
	handlerRecv, handlerMethods    map[string]bool
	globals                        map[string]bool

	exportedFns     map[*js.Func]string
	exportedNames   map[string]bool
	exportedClasses map[*js.Class]bool
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
	a.handlerRecv, a.handlerMethods = set(src.Handlers.Receivers), set(src.Handlers.Methods)
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
	// local marks a variable bound to a value computed here: a variable
	// named request that holds a call result is not the HTTP request.
	local bool
	fn    *js.Func
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
	return val{t: tx, safe: safeOf(x) & safeOf(y)}
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
		out.fn = x.fn
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
	for _, st := range list {
		switch d := st.(type) {
		case *js.FuncDecl:
			s.vars[d.Func.Name] = val{fn: d.Func}
			decls = append(decls, d.Func)
			continue
		case *js.Export:
			if fd, ok := d.Decl.(*js.FuncDecl); ok {
				s.vars[fd.Func.Name] = val{fn: fd.Func}
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
			a.expr(s, st.X)
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
		s.vars[st.Func.Name] = val{fn: st.Func}
		a.function(s, st.Func, a.exportName(st.Func, st.Func.Name), nil)
	case *js.ClassDecl:
		if st.Class.Name != "" {
			s.vars[st.Class.Name] = val{}
		}
		*classes = append(*classes, st.Class)
	case *js.Import:
		mod := moduleName(st.Source)
		for _, sp := range st.Specs {
			switch sp.Imported {
			case "default", "*":
				s.vars[sp.Local] = val{ref: mod}
			default:
				s.vars[sp.Local] = val{ref: mod + "." + sp.Imported}
			}
		}
	case *js.Export:
		if st.Decl != nil {
			return a.stmt(s, st.Decl, classes)
		}
		if st.Default != nil {
			a.expr(s, st.Default)
		}
	}
	return false
}

// block interprets a nested block in the same function scope.
func (a *analyzer) block(s *scope, list []js.Stmt, classes *[]*js.Class) bool {
	for _, st := range list {
		if fd, ok := st.(*js.FuncDecl); ok {
			s.vars[fd.Func.Name] = val{fn: fd.Func}
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
var validatorPrefixes = []string{"is", "has", "valid", "check", "verify", "match", "test", "includes", "startsWith", "endsWith", "indexOf", "contains", "exists", "allow", "safe", "assert"}

func isValidatorName(name string) bool {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	l := strings.ToLower(name)
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
			if x.Op == "typeof" {
				add(x.X)
				return
			}
			walk(x.X)
		case *js.Binary:
			switch x.Op {
			case "&&", "||":
				walk(x.L)
				walk(x.R)
			case "===", "!==", "==", "!=":
				if isConst(x.R) {
					walk(x.L)
					add(x.L)
				} else if isConst(x.L) {
					walk(x.R)
					add(x.R)
				}
			case "in", "instanceof":
				add(x.L)
			}
		case *js.Call:
			name := exprText(x.Callee)
			if m, ok := x.Callee.(*js.Member); ok {
				name = m.Prop
				if isValidatorName(name) {
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
	s := newScope(outer)
	for i, p := range fn.Params {
		var v val
		switch {
		case i < len(params):
			v = params[i]
		case exported != "" && a.opt.Library:
			name := patternName(p)
			if a.reqNames[name] {
				v = val{req: true}
				break
			}
			v = val{t: taint.NewSource(fn.Line, "parameter "+name+" of exported function "+exported, true)}
		}
		a.bindParam(s, p, v)
	}
	if fn.ExprBody != nil {
		a.expr(s, fn.ExprBody)
		return
	}
	a.body(s, fn.Body)
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

// classBodies analyzes the methods of a class; in an exported class their
// parameters are sources in library mode.
func (a *analyzer) classBodies(s *scope, c *js.Class) {
	exported := a.exportedClasses[c] || c.Name != "" && a.exportedNames[c.Name]
	cs := newScope(s)
	for _, m := range c.Members {
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
			// sql`...` binds its substitutions as parameters.
			if t := exprText(x.Tag); t == "sql" || strings.HasSuffix(t, ".sql") || tag.ref == "sql" {
				out.safe |= taint.SQL
			}
			return out
		}
		out := val{}
		for _, e := range x.Exprs {
			out = join(out, a.expr(s, e))
		}
		return out
	case *js.Member:
		return a.member(s, x)
	case *js.Call:
		return a.call(s, x)
	case *js.Binary:
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
		return merge(a.expr(s, x.Then), a.expr(s, x.Else))
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
		a.function(s, x, a.exportName(x, x.Name), nil)
		return val{fn: x}
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
	if base.req {
		switch {
		case a.reqProps[prop]:
			what := text
			if what == "" {
				what = "request " + prop
			}
			return val{t: taint.NewSource(line, what, false)}
		case a.reqNames[prop] || prop == "request" || prop == "req":
			return val{req: true}
		}
	}
	if f, ok := base.fields[prop]; ok {
		return f
	}
	out := val{}
	if base.ref != "" {
		out.ref = base.ref + "." + prop
	}
	if t := base.anyTaint(); t != nil && prop != "length" {
		out.t, out.safe = t, safeOf(base)
	}
	return out
}

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

func (a *analyzer) assignExpr(s *scope, x *js.Assign) val {
	v := a.expr(s, x.Value)
	if fn, ok := x.Value.(*js.Func); ok {
		v.fn = fn
	}
	if x.Op != "=" {
		old := a.expr(s, x.Target)
		v = join(old, v)
	}
	a.bind(s, x.Target, v, false)
	return v
}

// store handles obj.prop = v: property sinks and fields of local objects.
func (a *analyzer) store(s *scope, m *js.Member, v val) {
	text := exprText(m)
	for _, k := range a.spec.Sinks {
		for _, p := range k.Props {
			if m.Computed == nil && (p == m.Prop || p == text) {
				a.report(k, v, m.Line, m.Line)
			}
		}
	}
	a.expr(s, m.Obj)
	if m.Computed != nil {
		a.expr(s, m.Computed)
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
	handler := a.handlerRecv[recvText] && a.handlerMethods[method]
	for i, arg := range c.Args {
		fn, ok := arg.(*js.Func)
		if !ok {
			continue
		}
		var params []val
		switch {
		case handler:
			params = []val{{req: true}, {res: true}}
		case recv.anyTaint() != nil && i == 0:
			if idx, ok := iterators[method]; ok {
				params = make([]val, idx+1)
				params[idx] = val{t: recv.anyTaint().Add(c.Line, method), safe: safeOf(recv)}
			}
		}
		a.function(s, fn, a.exportName(fn, fn.Name), params)
		args[i] = val{fn: fn}
	}

	if name == "require" || name == "import" {
		if len(c.Args) > 0 {
			if l, ok := c.Args[0].(*js.Lit); ok && l.Kind == js.TString {
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

	a.sinks(c, name, method, recvText, recv, args)

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
	if method == "replace" || method == "replaceAll" {
		if len(c.Args) == 2 && stripsToSafe(c.Args[0], c.Args[1]) {
			return val{}
		}
	}
	if booleanMethods[method] || method != "" && isValidatorName(method) && method != "match" && !strings.HasPrefix(method, "matchAll") {
		return val{}
	}
	if req := recv.req; req && a.reqMethods[method] {
		return val{t: taint.NewSource(c.Line, recvText+"."+method+"()", false)}
	}
	out := val{}
	for _, v := range args {
		out = join(out, v)
	}
	out = join(out, recvTaint(recv, method))
	if name == "$" || name == "jQuery" || recv.ref == jqueryObject {
		out.ref = jqueryObject
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
		if i < len(c.Args) && c.Args[i].Ln() > end {
			end = c.Args[i].Ln()
		}
		a.report(k, v, c.Line, end)
	}
}

func (a *analyzer) report(k *taint.Sink, v val, line, end int) {
	t := v.taintFor(k.Kind, 0)
	if t == nil || k.RequestOnly && t.Library {
		return
	}
	key := k.ID + "|" + strconv.Itoa(line)
	if a.seen[key] {
		return
	}
	a.seen[key] = true
	steps := t.Steps()
	steps = append(steps, taint.Step{Line: line, What: k.Title})
	a.out = append(a.out, taint.Finding{Sink: k, File: a.file, Line: line, EndLine: end, Steps: steps, Library: t.Library})
}
