package java

import (
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// Lower turns a parsed compilation unit into IR modules, one per top-level
// type, named package.Type. Each module's body binds the type's simple
// name to its class body and each method name to the method, so that a
// qualified name such as org.acme.Utils.encode resolves to the method.
// Instance methods get an implicit first parameter "this" whose annotation
// is the class, constructors are named __init__, and declared types become
// the classes of values (Cast), resolved through the imports.
func Lower(f *File) []*ir.Module {
	var out []*ir.Module
	for _, c := range f.Types {
		name := c.Name
		if f.Package != "" {
			name = f.Package + "." + c.Name
		}
		m := &ir.Module{Path: f.Path, Name: name}
		l := &lowerer{mod: m, file: f, imports: map[string]string{}}
		for _, imp := range f.Imports {
			if !imp.Star && !imp.Static {
				l.imports[imp.Path[strings.LastIndexByte(imp.Path, '.')+1:]] = imp.Path
			}
			if imp.Static && !imp.Star {
				l.imports[imp.Path[strings.LastIndexByte(imp.Path, '.')+1:]] = imp.Path
			}
		}
		l.lowerModule(c)
		out = append(out, m)
	}
	return out
}

type scope struct {
	vars  map[string]string // local variable -> declared type
	outer *scope
}

func (s *scope) lookup(name string) (string, bool) {
	for c := s; c != nil; c = c.outer {
		if t, ok := c.vars[name]; ok {
			return t, true
		}
	}
	return "", false
}

type loop struct {
	label      string
	head, exit *ir.Block
	isSwitch   bool
}

// classInfo is what the lowering needs about a class: its qualified name,
// fields and methods.
type classInfo struct {
	decl    *ClassDecl
	qname   string
	fields  map[string]string // field -> type
	static  map[string]bool   // static fields and methods
	methods map[string]bool
	outer   *classInfo
}

type lowerer struct {
	mod     *ir.Module
	file    *File
	imports map[string]string

	fn       *ir.Function
	cur      *ir.Block
	ntemp    int
	sc       *scope
	loops    []loop
	handlers [][]*ir.Block
	class    *classInfo
	static   bool // in a static method or initializer
	nlambda  int
	yields   []yieldTarget
}

func (l *lowerer) temp() string {
	l.ntemp++
	return "$" + strconv.Itoa(l.ntemp)
}

func at(p Pos) ir.Pos { return ir.Pos{Line: p.Line, Col: p.Col} }

// typeName resolves a source type to the class name the specification
// uses: imported names to their qualified name, java.lang names as they
// are, arrays with [].
func (l *lowerer) typeName(t string) string {
	if t == "" {
		return ""
	}
	base, dims := t, ""
	if i := strings.IndexByte(t, '['); i >= 0 {
		base, dims = t[:i], t[i:]
	}
	first, rest, _ := strings.Cut(base, ".")
	if q, ok := l.imports[first]; ok {
		if rest != "" {
			return q + "." + rest + dims
		}
		return q + dims
	}
	if rest == "" && l.samePackageClass(first) && !primitiveTypes[first] {
		return l.file.Package + "." + base + dims
	}
	return base + dims
}

func (l *lowerer) newClassInfo(c *ClassDecl, qname string, outer *classInfo) *classInfo {
	ci := &classInfo{decl: c, qname: qname, fields: map[string]string{}, static: map[string]bool{}, methods: map[string]bool{}, outer: outer}
	for _, m := range c.Members {
		switch m := m.(type) {
		case *FieldDecl:
			for _, v := range m.Vars {
				ci.fields[v.Name] = l.typeName(m.Type)
				if has(m.Mods, "static") || c.Kind == "interface" {
					ci.static[v.Name] = true
				}
			}
		case *Method:
			if !m.Ctor {
				ci.methods[m.Name] = true
				if has(m.Mods, "static") {
					ci.static[m.Name] = true
				}
			}
		}
	}
	for _, p := range c.Components {
		ci.fields[p.Name] = l.typeName(p.Type)
	}
	for _, ec := range c.Consts {
		ci.fields[ec.Name] = qname
		ci.static[ec.Name] = true
	}
	return ci
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// lowerModule lowers a top-level type: the module body binds the class,
// its methods and static fields.
func (l *lowerer) lowerModule(c *ClassDecl) {
	init := &ir.Function{Name: "<module>", Pos: at(c.Pos)}
	l.mod.Init = init
	l.mod.Funcs = append(l.mod.Funcs, init)
	l.fn, l.ntemp = init, 0
	l.sc = &scope{vars: map[string]string{}}
	l.cur = init.NewBlock()
	for name, q := range l.imports {
		l.emit(&ir.Instr{Op: ir.Import, Pos: at(c.Pos), Dst: name, Name: q})
	}
	body := l.classBody(c, l.mod.Name, nil, init)
	l.emit(&ir.Instr{Op: ir.Func, Pos: at(c.Pos), Dst: c.Name, Fn: body})
	// Methods and static fields are reachable by their simple name too.
	for _, fn := range l.mod.Funcs {
		if fn.Parent == body && !strings.HasPrefix(fn.Name, "<") {
			name := fn.Name[strings.LastIndexByte(fn.Name, '.')+1:]
			if name != "__init__" {
				l.emit(&ir.Instr{Op: ir.Func, Pos: fn.Pos, Dst: name, Fn: fn})
			}
		}
	}
	if l.cur != nil {
		l.cur.Term = ir.Term{Kind: ir.Return}
	}
	init.Link()
}

// classBody lowers a class into a function holding its static field
// initializers and the definitions of its methods and nested classes.
func (l *lowerer) classBody(c *ClassDecl, qname string, outer *classInfo, parent *ir.Function) *ir.Function {
	ci := l.newClassInfo(c, qname, outer)
	fn := &ir.Function{Name: "<class " + c.Name + ">", Pos: at(c.Pos), Parent: parent, Class: c.Name}
	for _, e := range append(append([]string{}, c.Extends...), c.Implements...) {
		fn.Bases = append(fn.Bases, l.typeName(e))
	}
	l.mod.Funcs = append(l.mod.Funcs, fn)
	// The static fields and initializers of a top-level class run in the
	// module body, so that Class.FIELD reads their values.
	top := parent == l.mod.Init
	var instanceInit []Member
	statics := func() {
		for _, m := range c.Members {
			switch m := m.(type) {
			case *FieldDecl:
				if !ci.static[m.Vars[0].Name] {
					continue
				}
				for _, v := range m.Vars {
					val := ir.C(ir.None, "")
					if v.Init != nil {
						val = l.expr(v.Init)
					}
					l.emit(&ir.Instr{Op: ir.Copy, Pos: at(v.Pos), Dst: v.Name, A: val})
					if t := l.typeName(m.Type); t != "" {
						l.emit(&ir.Instr{Op: ir.Cast, Pos: at(v.Pos), Dst: v.Name, A: ir.V(v.Name), Name: t})
					}
				}
			case *Initializer:
				if m.Static {
					l.block(m.Body)
				}
			}
		}
	}
	for _, m := range c.Members {
		switch m := m.(type) {
		case *FieldDecl:
			if !ci.static[m.Vars[0].Name] {
				instanceInit = append(instanceInit, m)
			}
		case *Initializer:
			if !m.Static {
				instanceInit = append(instanceInit, m)
			}
		}
	}
	if top {
		savedClass, savedStatic := l.class, l.static
		l.class, l.static = ci, true
		statics()
		l.class, l.static = savedClass, savedStatic
	}
	saved := l.save()
	l.fn, l.ntemp, l.class, l.static = fn, 0, ci, true
	l.sc = &scope{vars: map[string]string{}}
	l.loops, l.handlers = nil, nil
	l.cur = fn.NewBlock()
	if !top {
		statics()
	}
	for _, ec := range c.Consts {
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(ec.Pos), Dst: ec.Name, A: ir.C(ir.Str, ec.Name)})
	}
	hasCtor := false
	for _, m := range c.Members {
		switch m := m.(type) {
		case *Method:
			hasCtor = hasCtor || m.Ctor
			mf := l.method(m, ci, fn, instanceInit)
			name := m.Name
			if m.Ctor {
				name = "__init__"
			}
			l.emit(&ir.Instr{Op: ir.Func, Pos: at(m.Pos), Dst: name, Fn: mf})
		case *ClassDecl:
			nested := l.classBody(m, qname+"."+m.Name, ci, fn)
			l.emit(&ir.Instr{Op: ir.Func, Pos: at(m.Pos), Dst: m.Name, Fn: nested})
		}
	}
	if !hasCtor && (len(instanceInit) > 0 || len(c.Components) > 0) {
		ctor := &Method{Pos: c.Pos, Name: "<init>", Ctor: true, Params: c.Components, Body: &Block{Pos: c.Pos}}
		for _, p := range c.Components {
			ctor.Body.Stmts = append(ctor.Body.Stmts, &ExprStmt{p.Pos, &Assign{Pos: p.Pos, Op: "=", L: &Field{p.Pos, &Name{p.Pos, "this"}, p.Name}, R: &Name{p.Pos, p.Name}}})
		}
		mf := l.method(ctor, ci, fn, instanceInit)
		l.emit(&ir.Instr{Op: ir.Func, Pos: at(c.Pos), Dst: "__init__", Fn: mf})
	}
	if l.cur != nil {
		l.cur.Term = ir.Term{Kind: ir.Return}
	}
	fn.Link()
	l.restore(saved)
	return fn
}

type savedState struct {
	fn       *ir.Function
	cur      *ir.Block
	ntemp    int
	sc       *scope
	loops    []loop
	handlers [][]*ir.Block
	class    *classInfo
	static   bool
}

func (l *lowerer) save() savedState {
	return savedState{l.fn, l.cur, l.ntemp, l.sc, l.loops, l.handlers, l.class, l.static}
}

func (l *lowerer) restore(s savedState) {
	l.fn, l.cur, l.ntemp, l.sc, l.loops, l.handlers, l.class, l.static = s.fn, s.cur, s.ntemp, s.sc, s.loops, s.handlers, s.class, s.static
}

// method lowers a method or constructor; a constructor first runs the
// instance field initializers.
func (l *lowerer) method(m *Method, ci *classInfo, classFn *ir.Function, instanceInit []Member) *ir.Function {
	name := m.Name
	if m.Ctor {
		name = "__init__"
	}
	fn := &ir.Function{Name: ci.decl.Name + "." + name, Pos: at(m.Pos), Parent: classFn, Class: ci.decl.Name}
	static := has(m.Mods, "static")
	if !static {
		fn.Params = append(fn.Params, ir.Param{Name: "this", Pos: at(m.Pos), Ann: ci.qname})
	} else {
		fn.Decorators = append(fn.Decorators, ir.Decorator{Name: "staticmethod"})
	}
	for _, a := range m.Annotations {
		fn.Decorators = append(fn.Decorators, annotation(a))
	}
	for _, p := range m.Params {
		kind := ""
		if p.Varargs {
			kind = "*"
		}
		prm := ir.Param{Name: p.Name, Kind: kind, Pos: at(p.Pos), Ann: l.typeName(p.Type)}
		for _, a := range p.Annotations {
			prm.Decorators = append(prm.Decorators, annotation(a))
		}
		fn.Params = append(fn.Params, prm)
	}
	l.mod.Funcs = append(l.mod.Funcs, fn)
	saved := l.save()
	l.fn, l.ntemp, l.class, l.static = fn, 0, ci, static
	l.sc = &scope{vars: map[string]string{}}
	for _, p := range fn.Params {
		l.sc.vars[p.Name] = p.Ann
	}
	l.loops, l.handlers = nil, nil
	l.cur = fn.NewBlock()
	if m.Ctor {
		for _, mm := range instanceInit {
			switch mm := mm.(type) {
			case *FieldDecl:
				for _, v := range mm.Vars {
					if v.Init != nil {
						val := l.expr(v.Init)
						l.emit(&ir.Instr{Op: ir.Store, Pos: at(v.Pos), A: ir.V("this"), Name: v.Name, B: val})
					}
				}
			case *Initializer:
				l.block(mm.Body)
			}
		}
	}
	if m.Body != nil {
		l.block(m.Body)
	}
	if l.cur != nil {
		l.cur.Term = ir.Term{Kind: ir.Return}
	}
	fn.Link()
	l.restore(saved)
	return fn
}

// annotation describes an annotation as a decorator: its simple name and
// constant string arguments (value first).
func annotation(a *Annotation) ir.Decorator {
	d := ir.Decorator{Name: a.Name, Call: len(a.Args) > 0}
	for _, arg := range a.Args {
		switch v := arg.Value.(type) {
		case *Literal:
			if v.Kind == LitString {
				d.Args = append(d.Args, v.Val)
			}
		case *ArrayInit:
			for _, e := range v.Elts {
				if lit, ok := e.(*Literal); ok && lit.Kind == LitString {
					d.Args = append(d.Args, lit.Val)
				}
			}
		}
		d.Keys = append(d.Keys, arg.Name)
	}
	return d
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

func (l *lowerer) branch(cond ir.Operand, pos Pos, t, f *ir.Block) {
	if l.cur == nil {
		l.cur = l.newBlock()
	}
	l.cur.Term = ir.Term{Kind: ir.Branch, Pos: at(pos), Cond: cond, Succs: []*ir.Block{t, f}}
	l.cur = nil
}

func (l *lowerer) value(op ir.Op, pos Pos, name string, a, b ir.Operand) ir.Operand {
	t := l.temp()
	l.emit(&ir.Instr{Op: op, Pos: at(pos), Dst: t, Name: name, A: a, B: b})
	return ir.V(t)
}

// ---- statements ----

func (l *lowerer) block(b *Block) {
	l.sc = &scope{vars: map[string]string{}, outer: l.sc}
	for _, s := range b.Stmts {
		l.stmt(s)
	}
	l.sc = l.sc.outer
}

func (l *lowerer) stmts(ss []Stmt) {
	for _, s := range ss {
		l.stmt(s)
	}
}

func (l *lowerer) declare(name, typ string, val ir.Operand, pos Pos) {
	t := l.typeName(typ)
	if t == "var" {
		t = ""
	}
	l.sc.vars[name] = t
	l.emit(&ir.Instr{Op: ir.Copy, Pos: at(pos), Dst: name, A: val})
	if t != "" {
		l.emit(&ir.Instr{Op: ir.Cast, Pos: at(pos), Dst: name, A: ir.V(name), Name: t})
	}
}

func (l *lowerer) stmt(s Stmt) {
	switch s := s.(type) {
	case *Block:
		l.block(s)
	case *LocalVar:
		for _, v := range s.Vars {
			val := ir.C(ir.None, "")
			if v.Init != nil {
				val = l.expr(v.Init)
			}
			typ := s.Type
			for i := 0; i < v.Dims; i++ {
				typ += "[]"
			}
			l.declare(v.Name, typ, val, v.Pos)
		}
	case *ExprStmt:
		l.expr(s.X)
	case *If:
		then, els, after := l.newBlock(), l.newBlock(), l.newBlock()
		l.cond(s.C, then, els)
		l.cur = then
		l.stmt(s.Then)
		l.jump(after)
		l.cur = els
		if s.Else != nil {
			l.stmt(s.Else)
		}
		l.jump(after)
		l.cur = after
	case *While:
		head, body, exit := l.newBlock(), l.newBlock(), l.newBlock()
		l.jump(head)
		l.cur = head
		l.cond(s.C, body, exit)
		l.cur = body
		l.loops = append(l.loops, loop{head: head, exit: exit})
		l.stmt(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.jump(head)
		l.cur = exit
	case *DoWhile:
		body, head, exit := l.newBlock(), l.newBlock(), l.newBlock()
		l.jump(body)
		l.cur = body
		l.loops = append(l.loops, loop{head: head, exit: exit})
		l.stmt(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.jump(head)
		l.cur = head
		l.cond(s.C, body, exit)
		l.cur = exit
	case *For:
		l.sc = &scope{vars: map[string]string{}, outer: l.sc}
		l.stmts(s.Init)
		head, body, next, exit := l.newBlock(), l.newBlock(), l.newBlock(), l.newBlock()
		l.jump(head)
		l.cur = head
		if s.C != nil {
			l.cond(s.C, body, exit)
		} else {
			l.jump(body)
		}
		l.cur = body
		l.loops = append(l.loops, loop{head: next, exit: exit})
		l.stmt(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.jump(next)
		l.cur = next
		for _, u := range s.Update {
			l.expr(u)
		}
		l.jump(head)
		l.cur = exit
		l.sc = l.sc.outer
	case *ForEach:
		it := l.expr(s.Iter)
		head, body, exit := l.newBlock(), l.newBlock(), l.newBlock()
		l.jump(head)
		l.cur = head
		l.branch(ir.Operand{}, s.Pos, body, exit)
		l.cur = body
		l.sc = &scope{vars: map[string]string{}, outer: l.sc}
		x := l.value(ir.Iter, s.Pos, "", it, ir.Operand{})
		l.declare(s.Name, s.Type, x, s.Pos)
		l.loops = append(l.loops, loop{head: head, exit: exit})
		l.stmt(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.sc = l.sc.outer
		l.jump(head)
		l.cur = exit
	case *Labeled:
		switch s.Body.(type) {
		case *While, *DoWhile, *For, *ForEach, *Switch:
			n := len(l.loops)
			l.stmt(s.Body)
			_ = n
		default:
			exit := l.newBlock()
			l.loops = append(l.loops, loop{label: s.Label, exit: exit, head: exit})
			l.stmt(s.Body)
			l.loops = l.loops[:len(l.loops)-1]
			l.jump(exit)
			l.cur = exit
		}
	case *Return:
		var v ir.Operand
		if s.X != nil {
			v = l.expr(s.X)
		}
		if l.cur == nil {
			l.cur = l.newBlock()
		}
		l.cur.Term = ir.Term{Kind: ir.Return, Pos: at(s.Pos), Value: v}
		l.cur = nil
	case *Throw:
		l.expr(s.X)
		if l.cur == nil {
			l.cur = l.newBlock()
		}
		l.cur.Term = ir.Term{Kind: ir.Raise, Pos: at(s.Pos)}
		l.cur = nil
	case *Break:
		for i := len(l.loops) - 1; i >= 0; i-- {
			if s.Label == "" || l.loops[i].label == s.Label {
				l.jump(l.loops[i].exit)
				return
			}
		}
	case *Continue:
		for i := len(l.loops) - 1; i >= 0; i-- {
			if !l.loops[i].isSwitch && (s.Label == "" || l.loops[i].label == s.Label) {
				l.jump(l.loops[i].head)
				return
			}
		}
	case *Yield:
		// handled by switchCases through the yield target
		v := l.expr(s.X)
		if n := len(l.yields); n > 0 {
			l.emit(&ir.Instr{Op: ir.Copy, Pos: at(s.Pos), Dst: l.yields[n-1].dst, A: v})
			l.jump(l.yields[n-1].exit)
		}
	case *Try:
		l.try(s)
	case *Switch:
		l.switchStmt(s.Pos, s.X, s.Cases, "")
	case *Sync:
		l.expr(s.X)
		l.block(s.Body)
	case *Assert:
		ok, fail := l.newBlock(), l.newBlock()
		l.cond(s.C, ok, fail)
		fail.Term = ir.Term{Kind: ir.Raise, Pos: at(s.Pos)}
		l.cur = ok
	case *LocalClass:
		body := l.classBody(s.Decl, l.mod.Name+"."+s.Decl.Name, l.class, l.fn)
		l.emit(&ir.Instr{Op: ir.Func, Pos: at(s.Pos), Dst: s.Decl.Name, Fn: body})
	}
}

func (l *lowerer) try(s *Try) {
	after := l.newBlock()
	l.sc = &scope{vars: map[string]string{}, outer: l.sc}
	var hs []*ir.Block
	for range s.Catches {
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
	for _, r := range s.Resources {
		l.stmt(r)
	}
	l.block(s.Body)
	if len(hs) > 0 {
		l.handlers = l.handlers[:len(l.handlers)-1]
	}
	l.jump(after)
	for i, c := range s.Catches {
		l.cur = hs[i]
		l.sc = &scope{vars: map[string]string{}, outer: l.sc}
		typ := ""
		if len(c.Types) == 1 {
			typ = c.Types[0]
		}
		l.declare(c.Name, typ, ir.C(ir.Other, "exception"), c.Pos)
		l.block(c.Body)
		l.sc = l.sc.outer
		l.jump(after)
	}
	l.cur = after
	l.sc = l.sc.outer
	if s.Finally != nil {
		l.block(s.Finally)
	}
}

type yieldTarget struct {
	dst  string
	exit *ir.Block
}

// switchStmt lowers a switch: each case label is tested in order against
// the subject; colon cases fall through to the next body unless they
// break. With dst set (a switch expression), arrow bodies and yield assign
// it.
func (l *lowerer) switchStmt(pos Pos, x Expr, cases []*Case, dst string) {
	subj := l.expr(x)
	if subj.Var != "" && !ir.IsTemp(subj.Var) || subj.Const != nil {
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(pos), Dst: t, A: subj})
		subj = ir.V(t)
	}
	exit := l.newBlock()
	bodies := make([]*ir.Block, len(cases))
	for i := range cases {
		bodies[i] = l.newBlock()
	}
	var deflt *ir.Block
	for i, c := range cases {
		if c.Default {
			deflt = bodies[i]
		}
		for _, lab := range c.Labels {
			next := l.newBlock()
			if io, ok := lab.(*InstanceOf); ok {
				if io.Bind != "" {
					l.declareIn(bodies[i], io.Bind, io.Type, subj, io.Pos)
				}
				l.branch(ir.Operand{}, io.Pos, bodies[i], next)
			} else {
				v := l.expr(lab)
				c := l.value(ir.Bin, lab.At(), "==", subj, v)
				l.branch(c, lab.At(), bodies[i], next)
			}
			l.cur = next
		}
	}
	if deflt != nil {
		l.jump(deflt)
	} else {
		l.jump(exit)
	}
	l.loops = append(l.loops, loop{exit: exit, head: exit, isSwitch: true})
	if dst != "" {
		l.yields = append(l.yields, yieldTarget{dst, exit})
	}
	for i, c := range cases {
		l.cur = bodies[i]
		l.sc = &scope{vars: map[string]string{}, outer: l.sc}
		if c.Guard != nil {
			ok := l.newBlock()
			next := exit
			if i+1 < len(bodies) {
				next = bodies[i+1]
			}
			l.cond(c.Guard, ok, next)
			l.cur = ok
		}
		l.stmts(c.Body)
		l.sc = l.sc.outer
		if c.Arrow || i+1 == len(cases) {
			l.jump(exit)
		} else {
			l.jump(bodies[i+1])
		}
	}
	if dst != "" {
		l.yields = l.yields[:len(l.yields)-1]
	}
	l.loops = l.loops[:len(l.loops)-1]
	l.cur = exit
}

// declareIn binds a pattern variable at the start of a case body.
func (l *lowerer) declareIn(b *ir.Block, name, typ string, val ir.Operand, pos Pos) {
	saved := l.cur
	l.cur = b
	l.declare(name, typ, val, pos)
	l.cur = saved
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
	l.branch(l.expr(e), e.At(), t, f)
}

// ---- expressions ----

func lit(x *Literal) ir.Operand {
	switch x.Kind {
	case LitString:
		return ir.C(ir.Str, x.Val)
	case LitChar:
		return ir.C(ir.Str, x.Val)
	case LitInt:
		v := strings.ReplaceAll(strings.TrimRight(x.Val, "lL"), "_", "")
		if n, err := strconv.ParseInt(v, 0, 64); err == nil {
			return ir.C(ir.Int, strconv.FormatInt(n, 10))
		}
		if strings.HasPrefix(v, "0b") || strings.HasPrefix(v, "0B") {
			if n, err := strconv.ParseInt(v[2:], 2, 64); err == nil {
				return ir.C(ir.Int, strconv.FormatInt(n, 10))
			}
		}
		return ir.C(ir.Other, x.Val)
	case LitFloat:
		return ir.C(ir.Float, strings.TrimRight(x.Val, "fFdD"))
	case LitTrue:
		return ir.C(ir.Bool, "true")
	case LitFalse:
		return ir.C(ir.Bool, "false")
	}
	return ir.C(ir.None, "")
}

// name reads a simple name: a local, a field of this class (through this
// or the class), or a name of the module or an import.
func (l *lowerer) name(n *Name) ir.Operand {
	if n.Id == "this" || n.Id == "super" {
		return ir.V("this")
	}
	if _, ok := l.sc.lookup(n.Id); ok {
		return ir.V(n.Id)
	}
	for ci := l.class; ci != nil; ci = ci.outer {
		if _, ok := ci.fields[n.Id]; ok {
			if ci.static[n.Id] || l.static || ci != l.class {
				break
			}
			return l.value(ir.Load, n.Pos, n.Id, ir.V("this"), ir.Operand{})
		}
	}
	if l.samePackageClass(n.Id) {
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Import, Pos: at(n.Pos), Dst: t, Name: l.file.Package + "." + n.Id})
		return ir.V(t)
	}
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Free, Pos: at(n.Pos), Dst: t, Name: n.Id})
	return ir.V(t)
}

// javaLang are the java.lang types code uses without an import.
var javaLang = map[string]bool{"String": true, "Object": true, "Integer": true, "Long": true, "Short": true, "Byte": true, "Double": true,
	"Float": true, "Boolean": true, "Character": true, "Math": true, "StrictMath": true, "System": true, "Runtime": true, "Thread": true,
	"StringBuilder": true, "StringBuffer": true, "Class": true, "Exception": true, "RuntimeException": true, "Error": true,
	"Throwable": true, "Number": true, "Enum": true, "Iterable": true, "CharSequence": true, "Process": true, "ProcessBuilder": true,
	"IllegalArgumentException": true, "IllegalStateException": true, "NullPointerException": true, "Void": true, "Override": true}

// samePackageClass reports a capitalized name that is not imported, not
// java.lang and not a nested class: a class of the file's package.
func (l *lowerer) samePackageClass(name string) bool {
	if l.file.Package == "" || name == "" || name[0] < 'A' || name[0] > 'Z' || javaLang[name] {
		return false
	}
	if _, ok := l.imports[name]; ok {
		return false
	}
	for ci := l.class; ci != nil; ci = ci.outer {
		if ci.decl.Name == name {
			return false
		}
		for _, m := range ci.decl.Members {
			if c, ok := m.(*ClassDecl); ok && c.Name == name {
				return false
			}
		}
	}
	return true
}

func (l *lowerer) exprs(es []Expr) []ir.Operand {
	out := make([]ir.Operand, 0, len(es))
	for _, e := range es {
		out = append(out, l.expr(e))
	}
	return out
}

func (l *lowerer) expr(e Expr) ir.Operand {
	switch e := e.(type) {
	case *Name:
		return l.name(e)
	case *Literal:
		return lit(e)
	case *Field:
		if e.Name == "length" {
			x := l.expr(e.X)
			return l.call(e.Pos, x, "", ir.V(l.freeName(e.Pos, "len")), []ir.Operand{x})
		}
		return l.value(ir.Load, e.Pos, e.Name, l.expr(e.X), ir.Operand{})
	case *Call:
		return l.callExpr(e)
	case *New:
		return l.newExpr(e)
	case *ArrayInit:
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Pos), Dst: t, Name: "list", Args: l.exprs(e.Elts)})
		return ir.V(t)
	case *Index:
		return l.value(ir.Index, e.Pos, "", l.expr(e.X), l.expr(e.Index))
	case *Binary:
		if e.Op == "&&" || e.Op == "||" {
			t := l.temp()
			after, next := l.newBlock(), l.newBlock()
			x := l.expr(e.L)
			l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Pos), Dst: t, A: x})
			if e.Op == "&&" {
				l.branch(ir.V(t), e.Pos, next, after)
			} else {
				l.branch(ir.V(t), e.Pos, after, next)
			}
			l.cur = next
			l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Pos), Dst: t, A: l.expr(e.R)})
			l.jump(after)
			l.cur = after
			return ir.V(t)
		}
		return l.value(ir.Bin, e.Pos, e.Op, l.expr(e.L), l.expr(e.R))
	case *Unary:
		x := l.expr(e.X)
		switch e.Op {
		case "++", "--":
			one := ir.C(ir.Int, "1")
			v := l.value(ir.Bin, e.Pos, e.Op[:1], x, one)
			l.assignTo(e.X, v, e.Pos)
			if e.Postfix {
				return x
			}
			return v
		case "!":
			return l.value(ir.Unary, e.Pos, "not", x, ir.Operand{})
		}
		return l.value(ir.Unary, e.Pos, e.Op, x, ir.Operand{})
	case *Assign:
		var v ir.Operand
		if e.Op == "=" {
			v = l.expr(e.R)
		} else {
			v = l.value(ir.Bin, e.Pos, strings.TrimSuffix(e.Op, "="), l.expr(e.L), l.expr(e.R))
		}
		l.assignTo(e.L, v, e.Pos)
		return v
	case *Cond:
		t := l.temp()
		then, els, after := l.newBlock(), l.newBlock(), l.newBlock()
		l.cond(e.C, then, els)
		l.cur = then
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.T.At()), Dst: t, A: l.expr(e.T)})
		l.jump(after)
		l.cur = els
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.F.At()), Dst: t, A: l.expr(e.F)})
		l.jump(after)
		l.cur = after
		return ir.V(t)
	case *Cast:
		x := l.expr(e.X)
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Cast, Pos: at(e.Pos), Dst: t, A: x, Name: l.typeName(e.Type)})
		return ir.V(t)
	case *InstanceOf:
		x := l.expr(e.X)
		if e.Bind != "" {
			l.declare(e.Bind, e.Type, x, e.Pos)
		}
		return l.value(ir.Bin, e.Pos, "instanceof", x, ir.C(ir.Str, l.typeName(e.Type)))
	case *Lambda:
		return l.lambda(e)
	case *MethodRef:
		l.expr(e.X)
		return ir.C(ir.Other, "methodref")
	case *ClassLit:
		return ir.C(ir.Other, "class")
	case *SwitchExpr:
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Pos), Dst: t, A: ir.C(ir.None, "")})
		l.switchStmt(e.Pos, e.X, e.Cases, t)
		return ir.V(t)
	case *TypeExpr:
		return ir.C(ir.Other, "type")
	}
	return ir.C(ir.Other, "?")
}

func (l *lowerer) freeName(pos Pos, name string) string {
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Free, Pos: at(pos), Dst: t, Name: name})
	return t
}

func (l *lowerer) assignTo(target Expr, v ir.Operand, pos Pos) {
	switch t := target.(type) {
	case *Name:
		if _, ok := l.sc.lookup(t.Id); ok {
			l.emit(&ir.Instr{Op: ir.Copy, Pos: at(pos), Dst: t.Id, A: v})
			return
		}
		if ci := l.class; ci != nil {
			if _, ok := ci.fields[t.Id]; ok && !ci.static[t.Id] && !l.static {
				l.emit(&ir.Instr{Op: ir.Store, Pos: at(pos), A: ir.V("this"), Name: t.Id, B: v})
				return
			}
		}
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(pos), Dst: t.Id, A: v})
	case *Field:
		l.emit(&ir.Instr{Op: ir.Store, Pos: at(pos), A: l.expr(t.X), Name: t.Name, B: v})
	case *Index:
		l.emit(&ir.Instr{Op: ir.SetIndex, Pos: at(pos), A: l.expr(t.X), B: l.expr(t.Index), C: v})
	}
}

func (l *lowerer) lambda(e *Lambda) ir.Operand {
	l.nlambda++
	fn := &ir.Function{Name: "<lambda>", Pos: at(e.Pos), Parent: l.fn, Class: l.fn.Class}
	for _, p := range e.Params {
		fn.Params = append(fn.Params, ir.Param{Name: p.Name, Pos: at(p.Pos), Ann: l.typeName(p.Type)})
	}
	l.mod.Funcs = append(l.mod.Funcs, fn)
	saved := l.save()
	outerScope := l.sc
	l.fn, l.ntemp = fn, 0
	l.sc = &scope{vars: map[string]string{}, outer: outerScope}
	for _, p := range fn.Params {
		l.sc.vars[p.Name] = p.Ann
	}
	l.loops, l.handlers = nil, nil
	l.cur = fn.NewBlock()
	switch b := e.Body.(type) {
	case *Block:
		l.block(b)
		if l.cur != nil {
			l.cur.Term = ir.Term{Kind: ir.Return}
		}
	case Expr:
		v := l.expr(b)
		if l.cur == nil {
			l.cur = l.newBlock()
		}
		l.cur.Term = ir.Term{Kind: ir.Return, Value: v}
	}
	fn.Link()
	l.restore(saved)
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Func, Pos: at(e.Pos), Dst: t, Fn: fn})
	return ir.V(t)
}

// call emits a call; with name set, recv is the receiver.
func (l *lowerer) call(pos Pos, recv ir.Operand, name string, callee ir.Operand, args []ir.Operand) ir.Operand {
	in := &ir.Instr{Op: ir.Call, Pos: at(pos), Dst: l.temp(), Name: name, Args: args, Keys: make([]string, len(args))}
	if name != "" {
		in.A = recv
	} else {
		in.A = callee
	}
	l.emit(in)
	return ir.V(in.Dst)
}

// collection types whose methods the lowering turns into list and dict
// operations, and StringBuilder methods that change the builder.
var (
	listTypes    = map[string]bool{"List": true, "ArrayList": true, "LinkedList": true, "Vector": true, "java.util.List": true, "java.util.ArrayList": true, "java.util.LinkedList": true, "java.util.Vector": true, "Collection": true, "java.util.Collection": true}
	mapTypes     = map[string]bool{"Map": true, "HashMap": true, "TreeMap": true, "LinkedHashMap": true, "Hashtable": true, "java.util.Map": true, "java.util.HashMap": true, "java.util.TreeMap": true, "java.util.LinkedHashMap": true, "java.util.Hashtable": true, "Properties": true, "java.util.Properties": true}
	builderTypes = map[string]bool{"StringBuilder": true, "StringBuffer": true, "java.lang.StringBuilder": true, "java.lang.StringBuffer": true}
)

// localType returns the declared type of a local receiver, without type
// arguments' effect (already dropped by the parser).
func (l *lowerer) localType(x Expr) (string, string) {
	if n, ok := x.(*Name); ok {
		if t, ok := l.sc.lookup(n.Id); ok {
			return n.Id, t
		}
	}
	return "", ""
}

func (l *lowerer) callExpr(e *Call) ir.Operand {
	if e.X == nil {
		switch e.Name {
		case "this", "super":
			// a constructor delegating to another: runs on the same object
			args := l.exprs(e.Args)
			return l.call(e.Pos, ir.V("this"), "__init__", ir.Operand{}, args)
		}
		args := l.exprs(e.Args)
		// a method of this class or an outer one
		for ci := l.class; ci != nil; ci = ci.outer {
			if ci.methods[e.Name] {
				if !ci.static[e.Name] && !l.static && ci == l.class {
					return l.call(e.Pos, ir.V("this"), e.Name, ir.Operand{}, args)
				}
				break
			}
		}
		return l.call(e.Pos, ir.Operand{}, "", ir.V(l.freeName(e.Pos, e.Name)), args)
	}
	if _, isSuper := e.X.(*Name); isSuper && e.X.(*Name).Id == "super" {
		args := l.exprs(e.Args)
		return l.call(e.Pos, ir.V("this"), e.Name, ir.Operand{}, args)
	}
	// collections and builders held in typed locals
	if v, t := l.localType(e.X); v != "" {
		base := strings.TrimSuffix(t, "[]")
		switch {
		case listTypes[base]:
			if r, ok := l.listCall(e, v); ok {
				return r
			}
		case mapTypes[base]:
			if r, ok := l.mapCall(e, v, base); ok {
				return r
			}
		case builderTypes[base]:
			if r, ok := l.builderCall(e, v); ok {
				return r
			}
		}
	}
	recv := l.expr(e.X)
	return l.call(e.Pos, recv, e.Name, ir.Operand{}, l.exprs(e.Args))
}

func (l *lowerer) listCall(e *Call, v string) (ir.Operand, bool) {
	args := e.Args
	switch {
	case e.Name == "add" && len(args) == 1:
		return l.call(e.Pos, ir.V(v), "append", ir.Operand{}, l.exprs(args)), true
	case e.Name == "add" && len(args) == 2:
		return l.call(e.Pos, ir.V(v), "insert", ir.Operand{}, l.exprs(args)), true
	case e.Name == "get" && len(args) == 1:
		return l.value(ir.Index, e.Pos, "", ir.V(v), l.expr(args[0])), true
	case e.Name == "remove" && len(args) == 1:
		a := l.expr(args[0])
		if a.Const != nil && a.Const.Kind == ir.Int {
			return l.call(e.Pos, ir.V(v), "pop", ir.Operand{}, []ir.Operand{a}), true
		}
		return l.call(e.Pos, ir.V(v), "remove", ir.Operand{}, []ir.Operand{a}), true
	case e.Name == "set" && len(args) == 2:
		k, x := l.expr(args[0]), l.expr(args[1])
		l.emit(&ir.Instr{Op: ir.SetIndex, Pos: at(e.Pos), A: ir.V(v), B: k, C: x})
		return ir.C(ir.None, ""), true
	}
	return ir.Operand{}, false
}

func (l *lowerer) mapCall(e *Call, v, typ string) (ir.Operand, bool) {
	args := e.Args
	props := strings.HasSuffix(typ, "Properties")
	switch {
	case (e.Name == "put" || e.Name == "setProperty") && len(args) == 2:
		k, x := l.expr(args[0]), l.expr(args[1])
		l.emit(&ir.Instr{Op: ir.SetIndex, Pos: at(e.Pos), A: ir.V(v), B: k, C: x})
		return ir.C(ir.None, ""), true
	case e.Name == "get" && len(args) == 1 && !props:
		return l.call(e.Pos, ir.V(v), "get", ir.Operand{}, l.exprs(args)), true
	}
	return ir.Operand{}, false
}

func (l *lowerer) builderCall(e *Call, v string) (ir.Operand, bool) {
	switch e.Name {
	case "append", "insert":
		args := l.exprs(e.Args)
		x := args[len(args)-1]
		nv := l.value(ir.Bin, e.Pos, "+", ir.V(v), x)
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Pos), Dst: v, A: nv})
		return ir.V(v), true
	case "toString":
		return ir.V(v), true
	case "replace":
		args := l.exprs(e.Args)
		if len(args) == 3 {
			nv := l.value(ir.Bin, e.Pos, "+", ir.V(v), args[2])
			l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Pos), Dst: v, A: nv})
			return ir.V(v), true
		}
	}
	return ir.Operand{}, false
}

// newExpr lowers new T(args): a call of the class (or its qualified name),
// an anonymous class, or an array.
func (l *lowerer) newExpr(e *New) ir.Operand {
	if e.Dims != nil || e.Init != nil || strings.HasSuffix(e.Type, "[]") {
		var elts []ir.Operand
		for _, d := range e.Dims {
			l.expr(d)
		}
		if e.Init != nil {
			elts = l.exprs(e.Init.Elts)
		}
		t := l.temp()
		name := "list"
		if e.Init == nil {
			name = "listcomp" // a sized array: unknown elements
		}
		l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Pos), Dst: t, Name: name, Args: elts})
		return ir.V(t)
	}
	args := l.exprs(e.Args)
	if e.Body != nil {
		l.nlambda++
		body := l.classBody(e.Body, l.mod.Name+"$"+strconv.Itoa(l.nlambda), l.class, l.fn)
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Func, Pos: at(e.Pos), Dst: t, Fn: body})
		return l.call(e.Pos, ir.Operand{}, "", ir.V(t), args)
	}
	typ := l.typeName(e.Type)
	callee := l.qualified(e.Pos, typ)
	return l.call(e.Pos, ir.Operand{}, "", callee, args)
}

var primitiveTypes = map[string]bool{"boolean": true, "byte": true, "char": true, "short": true, "int": true, "long": true, "float": true, "double": true, "void": true, "var": true}

// qualified loads a dotted class name: the first part from the scope or
// the module, the rest as attributes.
func (l *lowerer) qualified(pos Pos, name string) ir.Operand {
	parts := strings.Split(name, ".")
	var o ir.Operand
	if q, ok := l.imports[parts[0]]; ok && len(parts) == 1 {
		_ = q
	}
	o = ir.V(l.freeName(pos, parts[0]))
	for _, p := range parts[1:] {
		o = l.value(ir.Load, pos, p, o, ir.Operand{})
	}
	return o
}
