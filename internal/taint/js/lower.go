package js

import (
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// Resolver maps an import specifier of a file to the module name of the
// project file it names, or "" for a package (fs, express), which keeps its
// specifier as its name.
type Resolver func(spec string) string

// Lower turns a parsed file into an IR module named name. Imports and
// require calls bind module names (packages by their specifier, project
// files by resolve); exports become names of the module body: a default
// export and module.exports are "default", named exports and exports.x
// their own names. Functions are lowered with their enclosing scope, class
// methods get "this" and constructors are named __init__.
func Lower(f *File, name string, resolve Resolver) *ir.Module {
	m := &ir.Module{Path: f.Path, Name: name}
	l := &lowerer{mod: m, resolve: resolve}
	if l.resolve == nil {
		l.resolve = func(string) string { return "" }
	}
	l.protos = prototypes(f.Stmts)
	m.Init = l.function("<module>", 1, nil, f.Stmts, nil, nil, "", true)
	return m
}

// prototypes collects the methods assigned to the prototype of a name in
// a statement list.
func prototypes(list []Stmt) map[string][]*Prop {
	out := map[string][]*Prop{}
	for _, s := range list {
		es, ok := s.(*ExprStmt)
		if !ok {
			continue
		}
		a, ok := es.X.(*Assign)
		if !ok || a.Op != "=" {
			continue
		}
		path := memberPath(a.Target)
		parts := strings.Split(path, ".")
		switch {
		case len(parts) == 3 && parts[1] == "prototype":
			if f, ok := a.Value.(*Func); ok {
				out[parts[0]] = append(out[parts[0]], &Prop{Pos: a.Pos, Key: parts[2], Value: f})
			}
		case len(parts) == 2 && parts[1] == "prototype":
			if obj, ok := a.Value.(*ObjectLit); ok {
				for _, p := range obj.Props {
					if _, ok := p.Value.(*Func); ok && p.Key != "" {
						out[parts[0]] = append(out[parts[0]], p)
					}
				}
			}
		}
	}
	return out
}

// isProtoAssign reports a statement that a prototype class consumed.
func (l *lowerer) isProtoAssign(s Stmt) bool {
	es, ok := s.(*ExprStmt)
	if !ok {
		return false
	}
	a, ok := es.X.(*Assign)
	if !ok || a.Op != "=" {
		return false
	}
	parts := strings.Split(memberPath(a.Target), ".")
	return len(parts) >= 2 && parts[1] == "prototype" && len(l.protos[parts[0]]) > 0
}

type loop struct {
	label      string
	head, exit *ir.Block
	isSwitch   bool
}

type lowerer struct {
	mod     *ir.Module
	resolve Resolver
	// protos holds the prototype methods of constructor functions:
	// F.prototype.m = function, F.prototype = { m() {} }.
	protos map[string][]*Prop

	fn       *ir.Function
	cur      *ir.Block
	ntemp    int
	locals   map[string]bool
	module   bool
	loops    []loop
	handlers [][]*ir.Block
	nfunc    int
}

func (l *lowerer) temp() string {
	l.ntemp++
	return "$" + strconv.Itoa(l.ntemp)
}

func at(line int) ir.Pos { return ir.Pos{Line: line} }

// moduleOf returns the module name an import specifier stands for.
func (l *lowerer) moduleOf(spec string) string {
	if r := l.resolve(spec); r != "" {
		return r
	}
	return strings.TrimPrefix(spec, "node:")
}

// function lowers a function body into a new Function.
func (l *lowerer) function(name string, line int, params []Expr, body []Stmt, exprBody Expr, parent *ir.Function, class string, module bool) *ir.Function {
	fn := &ir.Function{Name: name, Pos: at(line), Parent: parent, Class: class}
	if class != "" && !module {
		fn.Params = append(fn.Params, ir.Param{Name: "this", Pos: at(line), Ann: class})
	}
	for i, p := range params {
		pname := patternName(p)
		if pname == "" {
			pname = "$p" + strconv.Itoa(i)
		}
		kind := ""
		if _, ok := p.(*Spread); ok {
			kind = "*"
		}
		fn.Params = append(fn.Params, ir.Param{Name: pname, Kind: kind, Pos: at(p.Ln())})
	}
	l.mod.Funcs = append(l.mod.Funcs, fn)

	saved := *l
	l.fn, l.ntemp, l.loops, l.handlers, l.module = fn, 0, nil, nil, module
	l.locals = map[string]bool{}
	for _, p := range fn.Params {
		l.locals[p.Name] = true
	}
	collectLocals(body, l.locals)
	for _, p := range params {
		collectPattern(p, l.locals)
	}
	l.cur = fn.NewBlock()
	// destructuring parameters
	for i, p := range params {
		if patternName(p) == "" {
			l.assign(p, ir.V(fn.Params[i+len(fn.Params)-len(params)].Name), p.Ln())
		} else if a, ok := p.(*Assign); ok {
			// a default value: x = def
			_ = a
		}
	}
	if exprBody != nil {
		v := l.expr(exprBody)
		if l.cur == nil {
			l.cur = l.newBlock()
		}
		l.cur.Term = ir.Term{Kind: ir.Return, Pos: at(exprBody.Ln()), Value: v}
		l.cur = nil
	} else {
		l.stmts(body)
	}
	if l.cur != nil {
		l.cur.Term = ir.Term{Kind: ir.Return}
	}
	fn.Link()
	nfunc := l.nfunc
	*l = saved
	l.nfunc = nfunc
	return fn
}

// patternName returns the name a parameter binds when it is a plain name
// (with an optional default), or "" for a destructuring pattern.
func patternName(p Expr) string {
	switch p := p.(type) {
	case *Ident:
		return p.Name
	case *Assign:
		if id, ok := p.Target.(*Ident); ok {
			return id.Name
		}
	case *Spread:
		return patternName(p.X)
	}
	return ""
}

// collectPattern records the names a pattern binds.
func collectPattern(p Expr, out map[string]bool) {
	switch p := p.(type) {
	case *Ident:
		out[p.Name] = true
	case *Assign:
		collectPattern(p.Target, out)
	case *Spread:
		collectPattern(p.X, out)
	case *ArrayLit:
		for _, e := range p.Elems {
			if e != nil {
				collectPattern(e, out)
			}
		}
	case *ObjectLit:
		for _, pr := range p.Props {
			if pr.Kind == "spread" {
				collectPattern(pr.Value, out)
				continue
			}
			if pr.Value != nil {
				collectPattern(pr.Value, out)
			} else if pr.Key != "" {
				out[pr.Key] = true
			}
		}
	}
}

// collectLocals records the names declared in a function body, not in
// nested functions (var, let, const, function and class declarations,
// imports, catch parameters).
func collectLocals(list []Stmt, out map[string]bool) {
	var walk func(s Stmt)
	walk = func(s Stmt) {
		switch s := s.(type) {
		case *VarDecl:
			for _, d := range s.Decls {
				collectPattern(d.Target, out)
			}
		case *FuncDecl:
			if s.Func.Name != "" {
				out[s.Func.Name] = true
			}
		case *ClassDecl:
			if s.Class.Name != "" {
				out[s.Class.Name] = true
			}
		case *Import:
			for _, sp := range s.Specs {
				out[sp.Local] = true
			}
		case *Export:
			if s.Decl != nil {
				walk(s.Decl)
			}
		case *If:
			walk(s.Then)
			if s.Else != nil {
				walk(s.Else)
			}
		case *For:
			if s.Init != nil {
				walk(s.Init)
			}
			walk(s.Body)
		case *ForIn:
			walk(s.Left)
			walk(s.Body)
		case *While:
			walk(s.Body)
		case *Block:
			for _, x := range s.List {
				walk(x)
			}
		case *Try:
			walk(s.Block)
			if s.Param != nil {
				collectPattern(s.Param, out)
			}
			if s.Handler != nil {
				walk(s.Handler)
			}
			if s.Finally != nil {
				walk(s.Finally)
			}
		case *Switch:
			for _, c := range s.Cases {
				for _, x := range c.Body {
					walk(x)
				}
			}
		case *Labeled:
			walk(s.Body)
		}
	}
	for _, s := range list {
		walk(s)
	}
}

// ---- emitting ----

func (l *lowerer) emit(in *ir.Instr) {
	if l.cur == nil {
		l.cur = l.newBlock()
	}
	l.cur.Instrs = append(l.cur.Instrs, in)
}

func (l *lowerer) newBlock() *ir.Block {
	b := l.fn.NewBlock()
	if n := len(l.handlers); n > 0 {
		b.Handlers = l.handlers[n-1]
	}
	return b
}

func (l *lowerer) jump(b *ir.Block) {
	if l.cur != nil {
		l.cur.Term = ir.Term{Kind: ir.Jump, Succs: []*ir.Block{b}}
	}
	l.cur = nil
}

func (l *lowerer) branch(cond ir.Operand, line int, t, f *ir.Block) {
	if l.cur == nil {
		l.cur = l.newBlock()
	}
	l.cur.Term = ir.Term{Kind: ir.Branch, Pos: at(line), Cond: cond, Succs: []*ir.Block{t, f}}
	l.cur = nil
}

func (l *lowerer) value(op ir.Op, line int, name string, a, b ir.Operand) ir.Operand {
	t := l.temp()
	l.emit(&ir.Instr{Op: op, Pos: at(line), Dst: t, Name: name, A: a, B: b})
	return ir.V(t)
}

func (l *lowerer) bind(name string, in *ir.Instr) {
	in.Dst = name
	l.emit(in)
}

// ---- statements ----

func (l *lowerer) stmts(list []Stmt) {
	// function declarations are hoisted
	for _, s := range list {
		if fd, ok := s.(*FuncDecl); ok && fd.Func.Body != nil {
			l.funcDecl(fd.Func)
		}
		if ex, ok := s.(*Export); ok {
			if fd, ok := ex.Decl.(*FuncDecl); ok && fd.Func.Body != nil {
				l.funcDecl(fd.Func)
			}
		}
	}
	for _, s := range list {
		if l.module && l.isProtoAssign(s) {
			continue
		}
		l.stmt(s)
	}
}

func (l *lowerer) funcDecl(f *Func) {
	if l.module && len(l.protos[f.Name]) > 0 {
		// a constructor function with prototype methods: a class
		members := []*ClassMember{{Pos: f.Pos, Key: "constructor", Kind: "constructor", Value: f}}
		for _, p := range l.protos[f.Name] {
			members = append(members, &ClassMember{Pos: p.Pos, Key: p.Key, Kind: "method", Value: p.Value})
		}
		v := l.class(&Class{Pos: f.Pos, Name: f.Name, Members: members})
		l.bind(f.Name, &ir.Instr{Op: ir.Copy, Pos: at(f.Line), A: v})
		return
	}
	fn := l.function(f.Name, f.Line, f.Params, f.Body, f.ExprBody, l.fn, "", false)
	l.bind(f.Name, &ir.Instr{Op: ir.Func, Pos: at(f.Line), Fn: fn})
}

func (l *lowerer) stmt(s Stmt) {
	switch s := s.(type) {
	case *ExprStmt:
		l.exprStmt(s.X)
	case *VarDecl:
		for _, d := range s.Decls {
			v := ir.C(ir.None, "")
			if d.Init != nil {
				v = l.expr(d.Init)
			}
			l.assign(d.Target, v, d.Line)
		}
	case *FuncDecl:
		// hoisted in stmts
	case *ClassDecl:
		v := l.class(s.Class)
		l.bind(s.Class.Name, &ir.Instr{Op: ir.Copy, Pos: at(s.Line), A: v})
	case *Return:
		var v ir.Operand
		if s.X != nil {
			v = l.expr(s.X)
		}
		if l.cur == nil {
			l.cur = l.newBlock()
		}
		l.cur.Term = ir.Term{Kind: ir.Return, Pos: at(s.Line), Value: v}
		l.cur = nil
	case *If:
		then, els, after := l.newBlock(), l.newBlock(), l.newBlock()
		l.cond(s.Test, then, els)
		l.cur = then
		l.stmt(s.Then)
		l.jump(after)
		l.cur = els
		if s.Else != nil {
			l.stmt(s.Else)
		}
		l.jump(after)
		l.cur = after
	case *For:
		if s.Init != nil {
			l.stmt(s.Init)
		}
		head, body, next, exit := l.newBlock(), l.newBlock(), l.newBlock(), l.newBlock()
		l.jump(head)
		l.cur = head
		if s.Test != nil {
			l.cond(s.Test, body, exit)
		} else {
			l.jump(body)
		}
		l.cur = body
		l.loops = append(l.loops, loop{head: next, exit: exit})
		l.stmt(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.jump(next)
		l.cur = next
		if s.Update != nil {
			l.expr(s.Update)
		}
		l.jump(head)
		l.cur = exit
	case *ForIn:
		it := l.expr(s.Right)
		head, body, exit := l.newBlock(), l.newBlock(), l.newBlock()
		l.jump(head)
		l.cur = head
		l.branch(ir.Operand{}, s.Line, body, exit)
		l.cur = body
		x := l.value(ir.Iter, s.Line, "", it, ir.Operand{})
		if !s.Of {
			// for (k in obj): the keys
			x = l.value(ir.Call, s.Line, "", ir.V(l.free(s.Line, "Object.keys")), ir.Operand{})
			l.cur.Instrs[len(l.cur.Instrs)-1].Args = []ir.Operand{it}
			l.cur.Instrs[len(l.cur.Instrs)-1].Keys = []string{""}
			x = l.value(ir.Iter, s.Line, "", x, ir.Operand{})
		}
		switch left := s.Left.(type) {
		case *VarDecl:
			if len(left.Decls) > 0 {
				l.assign(left.Decls[0].Target, x, s.Line)
			}
		case *ExprStmt:
			l.assign(left.X, x, s.Line)
		}
		l.loops = append(l.loops, loop{head: head, exit: exit})
		l.stmt(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.jump(head)
		l.cur = exit
	case *While:
		head, body, exit := l.newBlock(), l.newBlock(), l.newBlock()
		if s.Do {
			l.jump(body)
		} else {
			l.jump(head)
		}
		l.cur = head
		l.cond(s.Test, body, exit)
		l.cur = body
		l.loops = append(l.loops, loop{head: head, exit: exit})
		l.stmt(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.jump(head)
		l.cur = exit
	case *Block:
		l.stmts(s.List)
	case *Try:
		l.try(s)
	case *Switch:
		l.switchStmt(s)
	case *Throw:
		l.expr(s.X)
		if l.cur == nil {
			l.cur = l.newBlock()
		}
		l.cur.Term = ir.Term{Kind: ir.Raise, Pos: at(s.Line)}
		l.cur = nil
	case *Branch:
		for i := len(l.loops) - 1; i >= 0; i-- {
			lp := l.loops[i]
			if s.Label != "" && lp.label != s.Label {
				continue
			}
			if s.Tok == "break" {
				l.jump(lp.exit)
				return
			}
			if !lp.isSwitch {
				l.jump(lp.head)
				return
			}
		}
	case *Labeled:
		exit := l.newBlock()
		l.loops = append(l.loops, loop{label: s.Label, head: exit, exit: exit})
		l.stmt(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.jump(exit)
		l.cur = exit
	case *Import:
		mod := l.moduleOf(s.Source)
		for _, sp := range s.Specs {
			name := mod
			switch sp.Imported {
			case "*":
			case "default":
				name = mod + ".default"
			default:
				name = mod + "." + sp.Imported
			}
			l.bind(sp.Local, &ir.Instr{Op: ir.Import, Pos: at(s.Line), Name: name})
		}
	case *Export:
		l.export(s)
	}
}

// export binds exported names in the module body.
func (l *lowerer) export(s *Export) {
	switch {
	case s.Decl != nil:
		l.stmt(s.Decl)
		switch d := s.Decl.(type) {
		case *FuncDecl:
			l.exportName(d.Func.Name, ir.V(d.Func.Name), s.Line)
		case *ClassDecl:
			l.exportName(d.Class.Name, ir.V(d.Class.Name), s.Line)
		case *VarDecl:
			names := map[string]bool{}
			for _, dc := range d.Decls {
				collectPattern(dc.Target, names)
			}
			for n := range names {
				l.exportName(n, ir.V(n), s.Line)
			}
		}
	case s.Default != nil:
		var v ir.Operand
		if f, ok := s.Default.(*Func); ok && f.Name != "" {
			l.funcDecl(f)
			v = ir.V(f.Name)
		} else {
			v = l.expr(s.Default)
		}
		l.exportName("default", v, s.Line)
	case s.From != "":
		mod := l.moduleOf(s.From)
		for _, sp := range s.Specs {
			name := mod + "." + sp.Local
			if sp.Local == "default" {
				name = mod + ".default"
			}
			l.bind(sp.Exported, &ir.Instr{Op: ir.Import, Pos: at(s.Line), Name: name})
		}
	default:
		for _, sp := range s.Specs {
			if sp.Exported != sp.Local {
				l.bind(sp.Exported, &ir.Instr{Op: ir.Copy, Pos: at(s.Line), A: l.name(sp.Local, s.Line)})
			}
		}
	}
}

func (l *lowerer) exportName(name string, v ir.Operand, line int) {
	if !l.module {
		return
	}
	if name != v.Var {
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(line), Dst: name, A: v})
	}
}

func (l *lowerer) try(s *Try) {
	after := l.newBlock()
	var hs []*ir.Block
	if s.Handler != nil {
		hs = append(hs, l.newBlock())
	}
	body := l.fn.NewBlock()
	body.Handlers = hs
	if len(hs) == 0 && len(l.handlers) > 0 {
		body.Handlers = l.handlers[len(l.handlers)-1]
	}
	l.jump(body)
	l.cur = body
	if len(hs) > 0 {
		l.handlers = append(l.handlers, hs)
	}
	l.stmts(s.Block.List)
	if len(hs) > 0 {
		l.handlers = l.handlers[:len(l.handlers)-1]
	}
	l.jump(after)
	if s.Handler != nil {
		l.cur = hs[0]
		if s.Param != nil {
			l.assign(s.Param, ir.C(ir.Other, "exception"), s.Line)
		}
		l.stmts(s.Handler.List)
		l.jump(after)
	}
	l.cur = after
	if s.Finally != nil {
		l.stmts(s.Finally.List)
	}
}

func (l *lowerer) switchStmt(s *Switch) {
	subj := l.expr(s.Disc)
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Copy, Pos: at(s.Line), Dst: t, A: subj})
	subj = ir.V(t)
	exit := l.newBlock()
	bodies := make([]*ir.Block, len(s.Cases))
	for i := range s.Cases {
		bodies[i] = l.newBlock()
	}
	var deflt *ir.Block
	for i, c := range s.Cases {
		if c.Test == nil {
			deflt = bodies[i]
			continue
		}
		next := l.newBlock()
		v := l.expr(c.Test)
		cv := l.value(ir.Bin, c.Line, "==", subj, v)
		l.branch(cv, c.Line, bodies[i], next)
		l.cur = next
	}
	if deflt != nil {
		l.jump(deflt)
	} else {
		l.jump(exit)
	}
	l.loops = append(l.loops, loop{head: exit, exit: exit, isSwitch: true})
	for i, c := range s.Cases {
		l.cur = bodies[i]
		l.stmts(c.Body)
		if i+1 < len(bodies) {
			l.jump(bodies[i+1])
		} else {
			l.jump(exit)
		}
	}
	l.loops = l.loops[:len(l.loops)-1]
	l.cur = exit
}

// exprStmt lowers an expression statement, with the module export forms.
func (l *lowerer) exprStmt(x Expr) {
	if a, ok := x.(*Assign); ok && a.Op == "=" {
		if path := memberPath(a.Target); path != "" && l.module {
			switch {
			case path == "module.exports":
				v := l.expr(a.Value)
				l.emit(&ir.Instr{Op: ir.Copy, Pos: at(a.Line), Dst: "default", A: v})
				l.exportObject(a.Value, v, a.Line)
				return
			case strings.HasPrefix(path, "module.exports.") && strings.Count(path, ".") == 2:
				v := l.expr(a.Value)
				l.emit(&ir.Instr{Op: ir.Copy, Pos: at(a.Line), Dst: path[len("module.exports."):], A: v})
				return
			case strings.HasPrefix(path, "exports.") && strings.Count(path, ".") == 1:
				v := l.expr(a.Value)
				l.emit(&ir.Instr{Op: ir.Copy, Pos: at(a.Line), Dst: path[len("exports."):], A: v})
				return
			}
		}
	}
	l.expr(x)
}

// exportObject binds the keys of module.exports = { a, b: c } as names.
func (l *lowerer) exportObject(x Expr, v ir.Operand, line int) {
	obj, ok := x.(*ObjectLit)
	if !ok {
		return
	}
	for _, p := range obj.Props {
		if p.Key != "" && p.Kind != "spread" && p.Computed == nil {
			l.emit(&ir.Instr{Op: ir.Load, Pos: at(line), Dst: p.Key, A: v, Name: p.Key})
		}
	}
}

// memberPath returns a.b.c for an identifier or member chain.
func memberPath(x Expr) string {
	switch x := x.(type) {
	case *Ident:
		return x.Name
	case *Member:
		if x.Computed != nil {
			if lit, ok := x.Computed.(*Lit); ok && lit.Kind == TString {
				if p := memberPath(x.Obj); p != "" {
					return p + "." + lit.Val
				}
			}
			return ""
		}
		if p := memberPath(x.Obj); p != "" {
			return p + "." + x.Prop
		}
	}
	return ""
}

// ---- conditions ----

func (l *lowerer) cond(e Expr, t, f *ir.Block) {
	switch e := e.(type) {
	case *Binary:
		if e.Op == "&&" || e.Op == "||" {
			next := l.newBlock()
			if e.Op == "&&" {
				l.cond(e.L, next, f)
			} else {
				l.cond(e.L, t, next)
			}
			l.cur = next
			l.cond(e.R, t, f)
			return
		}
	case *Unary:
		if e.Op == "!" {
			l.cond(e.X, f, t)
			return
		}
	}
	l.branch(l.expr(e), e.Ln(), t, f)
}

// ---- assignment ----

func (l *lowerer) assign(target Expr, v ir.Operand, line int) {
	switch t := target.(type) {
	case *Ident:
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(line), Dst: t.Name, A: v})
	case *Member:
		obj := l.expr(t.Obj)
		if t.Computed != nil {
			l.emit(&ir.Instr{Op: ir.SetIndex, Pos: at(line), A: obj, B: l.expr(t.Computed), C: v})
			return
		}
		l.emit(&ir.Instr{Op: ir.Store, Pos: at(line), A: obj, Name: t.Prop, B: v})
	case *Assign:
		// a default: [x = d] or {a = d}
		l.assign(t.Target, v, line)
	case *ArrayLit:
		for i, e := range t.Elems {
			if e == nil {
				continue
			}
			if sp, ok := e.(*Spread); ok {
				l.assign(sp.X, v, line)
				continue
			}
			l.assign(e, l.value(ir.Index, line, "", v, ir.C(ir.Int, strconv.Itoa(i))), line)
		}
	case *ObjectLit:
		for _, p := range t.Props {
			if p.Kind == "spread" {
				l.assign(p.Value, v, line)
				continue
			}
			var x ir.Operand
			if p.Computed != nil {
				x = l.value(ir.Index, line, "", v, l.expr(p.Computed))
			} else {
				x = l.value(ir.Load, line, p.Key, v, ir.Operand{})
			}
			if p.Value != nil {
				l.assign(p.Value, x, line)
			} else {
				l.emit(&ir.Instr{Op: ir.Copy, Pos: at(line), Dst: p.Key, A: x})
			}
		}
	case *Spread:
		l.assign(t.X, v, line)
	}
}

// ---- expressions ----

func (l *lowerer) free(line int, name string) string {
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Free, Pos: at(line), Dst: t, Name: name})
	return t
}

func (l *lowerer) name(n string, line int) ir.Operand {
	if n == "undefined" {
		return ir.C(ir.None, "")
	}
	if l.module || l.locals[n] {
		return ir.V(n)
	}
	return ir.V(l.free(line, n))
}

func lit(x *Lit) ir.Operand {
	switch x.Kind {
	case TString, TTemplate:
		return ir.C(ir.Str, x.Val)
	case TNumber:
		v := strings.ReplaceAll(x.Val, "_", "")
		if n, err := strconv.ParseInt(v, 0, 64); err == nil {
			return ir.C(ir.Int, strconv.FormatInt(n, 10))
		}
		return ir.C(ir.Float, v)
	case TRegex:
		return ir.C(ir.Other, x.Val)
	}
	switch x.Val {
	case "true":
		return ir.C(ir.Bool, "true")
	case "false":
		return ir.C(ir.Bool, "false")
	case "null", "undefined":
		return ir.C(ir.None, "")
	}
	return ir.C(ir.Other, x.Val)
}

func (l *lowerer) exprs(es []Expr) ([]ir.Operand, []string) {
	var out []ir.Operand
	var keys []string
	for _, e := range es {
		if sp, ok := e.(*Spread); ok {
			out = append(out, l.expr(sp.X))
			keys = append(keys, "*")
			continue
		}
		out = append(out, l.expr(e))
		keys = append(keys, "")
	}
	return out, keys
}

func (l *lowerer) expr(e Expr) ir.Operand {
	switch e := e.(type) {
	case nil:
		return ir.C(ir.None, "")
	case *Ident:
		if e.Name == "this" && !l.locals["this"] {
			// an arrow function's this is its enclosing function's
			return ir.V(l.free(e.Line, "this"))
		}
		return l.name(e.Name, e.Line)
	case *Lit:
		return lit(e)
	case *TemplateLit:
		var parts []ir.Operand
		for i, q := range e.Quasis {
			if q != "" {
				parts = append(parts, ir.C(ir.Str, q))
			}
			if i < len(e.Exprs) {
				parts = append(parts, l.expr(e.Exprs[i]))
			}
		}
		if e.Tag != nil {
			// a tagged template: tag(strings, ...values)
			tag := l.expr(e.Tag)
			args := []ir.Operand{ir.C(ir.Other, "strings")}
			keys := []string{""}
			for _, x := range e.Exprs {
				args = append(args, l.expr(x))
				keys = append(keys, "")
			}
			t := l.temp()
			l.emit(&ir.Instr{Op: ir.Call, Pos: at(e.Line), Dst: t, A: tag, Args: args, Keys: keys})
			return ir.V(t)
		}
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Line), Dst: t, Name: "str", Args: parts})
		return ir.V(t)
	case *Member:
		obj := l.expr(e.Obj)
		if e.Computed != nil {
			return l.value(ir.Index, e.Line, "", obj, l.expr(e.Computed))
		}
		if e.Prop == "length" {
			t := l.temp()
			l.emit(&ir.Instr{Op: ir.Call, Pos: at(e.Line), Dst: t, A: ir.V(l.free(e.Line, "len")), Args: []ir.Operand{obj}, Keys: []string{""}})
			return ir.V(t)
		}
		return l.value(ir.Load, e.Line, e.Prop, obj, ir.Operand{})
	case *Call:
		return l.call(e)
	case *Binary:
		switch e.Op {
		case "&&", "||", "??":
			t := l.temp()
			after, next := l.newBlock(), l.newBlock()
			x := l.expr(e.L)
			l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Line), Dst: t, A: x})
			cond := ir.V(t)
			if e.Op == "??" {
				cond = l.value(ir.Bin, e.Line, "is not", x, ir.C(ir.None, ""))
			}
			if e.Op == "&&" {
				l.branch(cond, e.Line, next, after)
			} else {
				l.branch(cond, e.Line, after, next)
			}
			l.cur = next
			l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Line), Dst: t, A: l.expr(e.R)})
			l.jump(after)
			l.cur = after
			return ir.V(t)
		}
		op := e.Op
		switch op {
		case "===":
			op = "=="
		case "!==":
			op = "!="
		case "instanceof":
			op = "instanceof"
		}
		return l.value(ir.Bin, e.Line, op, l.expr(e.L), l.expr(e.R))
	case *Unary:
		x := l.expr(e.X)
		switch e.Op {
		case "await", "void":
			if e.Op == "void" {
				return ir.C(ir.None, "")
			}
			return x
		case "typeof":
			return l.value(ir.Unary, e.Line, "typeof", x, ir.Operand{})
		case "delete":
			if m, ok := e.X.(*Member); ok && m.Computed == nil {
				l.emit(&ir.Instr{Op: ir.Del, Pos: at(e.Line), A: l.expr(m.Obj), Name: m.Prop})
			}
			return ir.C(ir.Bool, "true")
		case "++", "--":
			v := l.value(ir.Bin, e.Line, e.Op[:1], x, ir.C(ir.Int, "1"))
			l.assign(e.X, v, e.Line)
			if e.Postfix {
				return x
			}
			return v
		case "!":
			return l.value(ir.Unary, e.Line, "not", x, ir.Operand{})
		}
		return l.value(ir.Unary, e.Line, e.Op, x, ir.Operand{})
	case *Assign:
		var v ir.Operand
		switch e.Op {
		case "=":
			v = l.expr(e.Value)
		case "&&=", "||=", "??=":
			v = l.value(ir.Bin, e.Line, "or", l.expr(e.Target), l.expr(e.Value))
		default:
			v = l.value(ir.Bin, e.Line, strings.TrimSuffix(e.Op, "="), l.expr(e.Target), l.expr(e.Value))
		}
		l.assign(e.Target, v, e.Line)
		return v
	case *Cond:
		t := l.temp()
		then, els, after := l.newBlock(), l.newBlock(), l.newBlock()
		l.cond(e.Test, then, els)
		l.cur = then
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Line), Dst: t, A: l.expr(e.Then)})
		l.jump(after)
		l.cur = els
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Line), Dst: t, A: l.expr(e.Else)})
		l.jump(after)
		l.cur = after
		return ir.V(t)
	case *Seq:
		var v ir.Operand
		for _, x := range e.List {
			v = l.expr(x)
		}
		return v
	case *ArrayLit:
		var elts []ir.Operand
		for _, x := range e.Elems {
			if sp, ok := x.(*Spread); ok {
				elts = append(elts, l.expr(sp.X))
				continue
			}
			elts = append(elts, l.expr(x))
		}
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Line), Dst: t, Name: "list", Args: elts})
		return ir.V(t)
	case *ObjectLit:
		return l.object(e)
	case *Spread:
		return l.expr(e.X)
	case *Yield:
		if e.X != nil {
			l.expr(e.X)
		}
		return ir.C(ir.Other, "yield")
	case *Func:
		name := e.Name
		if name == "" {
			name = "<anonymous>"
		}
		fn := l.function(name, e.Line, e.Params, e.Body, e.ExprBody, l.fn, "", false)
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Func, Pos: at(e.Line), Dst: t, Fn: fn})
		return ir.V(t)
	case *Class:
		return l.class(e)
	case *JSXElement:
		return l.jsx(e)
	case *JSXText:
		return ir.C(ir.Str, e.Text)
	}
	return ir.C(ir.Other, "?")
}

// object lowers an object literal to a dict; methods and arrow functions
// are function values under their keys.
func (l *lowerer) object(e *ObjectLit) ir.Operand {
	var vals, keys []ir.Operand
	for _, p := range e.Props {
		switch {
		case p.Kind == "spread":
			vals = append(vals, l.expr(p.Value))
			keys = append(keys, ir.Operand{})
		case p.Computed != nil:
			k := l.expr(p.Computed)
			vals = append(vals, l.expr(p.Value))
			keys = append(keys, k)
		default:
			var v ir.Operand
			if p.Value == nil {
				v = l.name(p.Key, p.Line) // shorthand { a }
			} else if f, ok := p.Value.(*Func); ok && !f.Arrow {
				// a method: this is the object
				fn := l.function(p.Key, f.Line, f.Params, f.Body, f.ExprBody, l.fn, "<object>", false)
				t := l.temp()
				l.emit(&ir.Instr{Op: ir.Func, Pos: at(f.Line), Dst: t, Fn: fn})
				v = ir.V(t)
			} else {
				v = l.expr(p.Value)
			}
			vals = append(vals, v)
			keys = append(keys, ir.C(ir.Str, p.Key))
		}
	}
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Line), Dst: t, Name: "dict", Args: vals, Keys2: keys})
	return ir.V(t)
}

// call lowers a call: require("x") is an import, a member call has its
// receiver, new C(...) calls the class.
func (l *lowerer) call(e *Call) ir.Operand {
	if id, ok := e.Callee.(*Ident); ok && id.Name == "require" && len(e.Args) == 1 && !l.locals["require"] {
		if s, ok := e.Args[0].(*Lit); ok && s.Kind == TString {
			return l.value(ir.Import, e.Line, l.moduleOf(s.Val), ir.Operand{}, ir.Operand{})
		}
	}
	in := &ir.Instr{Op: ir.Call, Pos: at(e.Line)}
	if m, ok := e.Callee.(*Member); ok && m.Computed == nil {
		in.A = l.expr(m.Obj)
		in.Name = m.Prop
	} else {
		in.A = l.expr(e.Callee)
	}
	in.Args, in.Keys = l.exprs(e.Args)
	in.Dst = l.temp()
	l.emit(in)
	return ir.V(in.Dst)
}

// class lowers a class into a class body function holding its methods.
func (l *lowerer) class(c *Class) ir.Operand {
	l.nfunc++
	name := c.Name
	if name == "" {
		name = "$class" + strconv.Itoa(l.nfunc)
	}
	body := &ir.Function{Name: "<class " + name + ">", Pos: at(c.Line), Parent: l.fn, Class: name}
	if c.Super != nil {
		if p := memberPath(c.Super); p != "" {
			body.Bases = append(body.Bases, p)
		}
	}
	l.mod.Funcs = append(l.mod.Funcs, body)
	saved := *l
	l.fn, l.ntemp, l.loops, l.handlers, l.module = body, 0, nil, nil, false
	l.locals = map[string]bool{}
	l.cur = body.NewBlock()
	var fields []*ClassMember
	for _, m := range c.Members {
		if m.Kind == "field" && !m.Static {
			fields = append(fields, m)
		}
	}
	hasCtor := false
	for _, m := range c.Members {
		f, ok := m.Value.(*Func)
		if !ok || m.Kind == "field" {
			continue
		}
		mname := m.Key
		var stmts []Stmt
		if m.Kind == "constructor" || mname == "constructor" {
			mname = "__init__"
			hasCtor = true
			// field initializers and TypeScript parameter properties first
			for _, fld := range fields {
				if fld.Value != nil {
					stmts = append(stmts, &ExprStmt{Pos: fld.Pos, X: &Assign{Pos: fld.Pos, Op: "=", Target: &Member{Pos: fld.Pos, Obj: &Ident{Pos: fld.Pos, Name: "this"}, Prop: fld.Key}, Value: fld.Value}})
				}
			}
			for _, pp := range m.ParamProps {
				stmts = append(stmts, &ExprStmt{Pos: m.Pos, X: &Assign{Pos: m.Pos, Op: "=", Target: &Member{Pos: m.Pos, Obj: &Ident{Pos: m.Pos, Name: "this"}, Prop: pp}, Value: &Ident{Pos: m.Pos, Name: pp}}})
			}
		}
		stmts = append(stmts, f.Body...)
		fn := l.function(name+"."+mname, f.Line, f.Params, stmts, f.ExprBody, body, name, false)
		if m.Static {
			fn.Decorators = append(fn.Decorators, ir.Decorator{Name: "staticmethod"})
			fn.Params = fn.Params[1:]
		}
		l.emit(&ir.Instr{Op: ir.Func, Pos: at(f.Line), Dst: mname, Fn: fn})
	}
	if !hasCtor && len(fields) > 0 {
		var stmts []Stmt
		for _, fld := range fields {
			if fld.Value != nil {
				stmts = append(stmts, &ExprStmt{Pos: fld.Pos, X: &Assign{Pos: fld.Pos, Op: "=", Target: &Member{Pos: fld.Pos, Obj: &Ident{Pos: fld.Pos, Name: "this"}, Prop: fld.Key}, Value: fld.Value}})
			}
		}
		fn := l.function(name+".__init__", c.Line, nil, stmts, nil, body, name, false)
		l.emit(&ir.Instr{Op: ir.Func, Pos: at(c.Line), Dst: "__init__", Fn: fn})
	}
	if l.cur != nil {
		l.cur.Term = ir.Term{Kind: ir.Return}
	}
	body.Link()
	nfunc := l.nfunc
	*l = saved
	l.nfunc = nfunc
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Func, Pos: at(c.Line), Dst: t, Fn: body})
	return ir.V(t)
}

// jsx lowers an element to a call of the pseudo function "jsx" with the
// tag and a dict of attributes (children under "children"), so that
// specifications can name attributes such as dangerouslySetInnerHTML.
func (l *lowerer) jsx(e *JSXElement) ir.Operand {
	var vals, keys []ir.Operand
	for _, a := range e.Attrs {
		if a.Spread {
			vals = append(vals, l.expr(a.Value))
			keys = append(keys, ir.Operand{})
			continue
		}
		vals = append(vals, l.expr(a.Value))
		keys = append(keys, ir.C(ir.Str, a.Name))
	}
	var kids []ir.Operand
	for _, c := range e.Children {
		kids = append(kids, l.expr(c))
	}
	ch := l.temp()
	l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Line), Dst: ch, Name: "list", Args: kids})
	vals = append(vals, ir.V(ch))
	keys = append(keys, ir.C(ir.Str, "children"))
	attrs := l.temp()
	l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Line), Dst: attrs, Name: "dict", Args: vals, Keys2: keys})
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Call, Pos: at(e.Line), Dst: t, A: ir.V(l.free(e.Line, "jsx")), Args: []ir.Operand{ir.C(ir.Str, e.Tag), ir.V(attrs)}, Keys: []string{"", ""}})
	return ir.V(t)
}
