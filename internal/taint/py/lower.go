package py

import (
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// Lower turns a parsed module into the IR. name is the dotted module name
// (used to resolve relative imports) and pkg reports that the file is a
// package's __init__.py.
func Lower(f *File, name string, pkg bool) *ir.Module {
	m := &ir.Module{Path: f.Path, Name: name}
	l := &lowerer{mod: m, pkg: pkg}
	m.Init = l.function("<module>", Pos{1, 1}, nil, nil, f.Body, nil, "", true)
	return m
}

type loop struct{ head, exit *ir.Block }

type lowerer struct {
	mod *ir.Module
	pkg bool

	fn       *ir.Function
	cur      *ir.Block
	ntemp    int
	locals   map[string]bool
	module   bool
	loops    []loop
	handlers [][]*ir.Block
	// renames maps comprehension variables to their own names, innermost
	// last.
	renames []map[string]string
	ncomp   int
}

func (l *lowerer) temp() string {
	l.ntemp++
	return "$" + strconv.Itoa(l.ntemp)
}

func at(p Pos) ir.Pos { return ir.Pos{Line: p.Line, Col: p.Col} }

// function lowers a function body (or the module body) into a new Function.
func (l *lowerer) function(name string, pos Pos, params []*Param, decos []Expr, body []Stmt, parent *ir.Function, class string, module bool) *ir.Function {
	fn := &ir.Function{Name: name, Pos: at(pos), Parent: parent, Class: class}
	for _, p := range params {
		if p.Kind == "/" || p.Kind == "*marker" {
			continue
		}
		fn.Params = append(fn.Params, ir.Param{Name: p.Name, Kind: p.Kind, Pos: at(p.Pos), Ann: dotted(p.Ann)})
	}
	for _, d := range decos {
		fn.Decorators = append(fn.Decorators, decorator(d))
	}
	l.mod.Funcs = append(l.mod.Funcs, fn)

	saved := *l
	l.fn, l.ntemp, l.loops, l.handlers, l.renames, l.module = fn, 0, nil, nil, nil, module
	l.locals = map[string]bool{}
	for _, p := range fn.Params {
		l.locals[p.Name] = true
	}
	declared := map[string]bool{}
	collectLocals(body, l.locals, declared)
	for n := range declared {
		delete(l.locals, n)
	}
	l.cur = fn.NewBlock()
	l.stmts(body)
	if l.cur != nil {
		l.cur.Term = ir.Term{Kind: ir.Return}
	}
	fn.Link()
	ncomp := l.ncomp
	*l = saved
	l.ncomp = ncomp
	return fn
}

// collectLocals records the names a function body binds; declared gets the
// names declared global or nonlocal. Nested functions, classes and lambdas
// have scopes of their own; comprehension variables are renamed.
func collectLocals(body []Stmt, out, declared map[string]bool) {
	var target func(e Expr)
	target = func(e Expr) {
		switch e := e.(type) {
		case *Name:
			out[e.Id] = true
		case *Tuple:
			for _, x := range e.Elts {
				target(x)
			}
		case *List:
			for _, x := range e.Elts {
				target(x)
			}
		case *Starred:
			target(e.X)
		}
	}
	var walrus func(e Expr)
	walrus = func(e Expr) {
		Inspect(e, func(n Node) bool {
			switch n := n.(type) {
			case *NamedExpr:
				out[n.Target.Id] = true
			case *Lambda:
				return false
			}
			return true
		})
	}
	var pattern func(e Expr)
	pattern = func(e Expr) {
		Inspect(e, func(n Node) bool {
			switch n := n.(type) {
			case *MatchAs:
				if n.Name != "" && n.Name != "_" {
					out[n.Name] = true
				}
			case *Name:
				if n.Id != "_" {
					out[n.Id] = true
				}
			case *Attribute:
				return false // a value pattern, not a capture
			case *Starred:
				if nm, ok := n.X.(*Name); ok && nm.Id != "_" {
					out[nm.Id] = true
				}
				return false
			case *Call:
				for _, a := range n.Args {
					pattern(a.Value)
				}
				return false
			}
			return true
		})
	}
	var walk func(ss []Stmt)
	walk = func(ss []Stmt) {
		for _, s := range ss {
			switch s := s.(type) {
			case *ExprStmt:
				walrus(s.X)
			case *Assign:
				for _, t := range s.Targets {
					target(t)
				}
				walrus(s.Value)
			case *AugAssign:
				target(s.Target)
			case *AnnAssign:
				if s.Value != nil {
					target(s.Target)
				}
			case *FuncDef:
				out[s.Name] = true
			case *ClassDef:
				out[s.Name] = true
			case *Return:
				if s.X != nil {
					walrus(s.X)
				}
			case *If:
				walrus(s.Test)
				walk(s.Body)
				walk(s.Else)
			case *For:
				target(s.Target)
				walk(s.Body)
				walk(s.Else)
			case *While:
				walrus(s.Test)
				walk(s.Body)
				walk(s.Else)
			case *With:
				for _, it := range s.Items {
					if it.Target != nil {
						target(it.Target)
					}
				}
				walk(s.Body)
			case *Try:
				walk(s.Body)
				for _, h := range s.Handlers {
					if h.Name != "" {
						out[h.Name] = true
					}
					walk(h.Body)
				}
				walk(s.Else)
				walk(s.Finally)
			case *Import:
				for _, a := range s.Names {
					if a.AsName != "" {
						out[a.AsName] = true
					} else {
						out[strings.SplitN(a.Name, ".", 2)[0]] = true
					}
				}
			case *ImportFrom:
				for _, a := range s.Names {
					if a.Name == "*" {
						continue
					}
					if a.AsName != "" {
						out[a.AsName] = true
					} else {
						out[a.Name] = true
					}
				}
			case *Global:
				for _, n := range s.Names {
					declared[n] = true
				}
			case *Nonlocal:
				for _, n := range s.Names {
					declared[n] = true
				}
			case *Match:
				walrus(s.Subject)
				for _, c := range s.Cases {
					pattern(c.Pattern)
					walk(c.Body)
				}
			case *TypeAlias:
				if s.Name != nil {
					out[s.Name.Id] = true
				}
			}
		}
	}
	walk(body)
}

// decorator describes a decorator expression.
func decorator(e Expr) ir.Decorator {
	if c, ok := e.(*Call); ok {
		d := ir.Decorator{Name: dotted(c.Func), Call: true}
		for _, a := range c.Args {
			if k, ok := a.Value.(*Const); ok && a.Name == "" && a.Star == "" && k.Kind == ConstStr {
				d.Args = append(d.Args, k.Val)
			}
		}
		return d
	}
	return ir.Decorator{Name: dotted(e)}
}

// dotted returns a.b.c for a name or attribute chain, "" otherwise.
func dotted(e Expr) string {
	switch e := e.(type) {
	case *Name:
		return e.Id
	case *Attribute:
		if p := dotted(e.Obj); p != "" {
			return p + "." + e.Name
		}
	case *Subscript:
		return dotted(e.Obj) // Optional[str] names Optional
	}
	return ""
}

// ---- emitting ----

func (l *lowerer) emit(in *ir.Instr) {
	if l.cur == nil {
		// Code after return, break or raise: keep it in a block of its own
		// so it is still lowered, but nothing reaches it.
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

// jump ends the current block with a jump to b, unless it already ended.
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

func (l *lowerer) stmts(ss []Stmt) {
	for _, s := range ss {
		l.stmt(s)
	}
}

func (l *lowerer) stmt(s Stmt) {
	switch s := s.(type) {
	case *ExprStmt:
		l.expr(s.X)
	case *Assign:
		v := l.expr(s.Value)
		for _, t := range s.Targets {
			l.assign(t, v, s.Pos)
		}
	case *AugAssign:
		v := l.value(ir.Bin, s.Pos, s.Op, l.expr(s.Target), l.expr(s.Value))
		l.assign(s.Target, v, s.Pos)
	case *AnnAssign:
		if s.Value != nil {
			l.assign(s.Target, l.expr(s.Value), s.Pos)
		}
	case *FuncDef:
		for _, p := range s.Params {
			if p.Default != nil {
				l.expr(p.Default)
			}
		}
		name, class := s.Name, ""
		if l.fn.Class != "" && strings.HasPrefix(l.fn.Name, "<class ") {
			class = l.fn.Class
			name = class + "." + s.Name
		}
		fn := l.function(name, s.Pos, s.Params, s.Decorators, s.Body, l.fn, class, false)
		l.bind(s.Name, &ir.Instr{Op: ir.Func, Pos: at(s.Pos), Fn: fn}, s.Pos)
	case *ClassDef:
		for _, b := range s.Bases {
			l.expr(b.Value)
		}
		fn := l.function("<class "+s.Name+">", s.Pos, nil, s.Decorators, s.Body, l.fn, s.Name, false)
		for _, b := range s.Bases {
			if d := dotted(b.Value); d != "" && b.Name == "" && b.Star == "" {
				fn.Bases = append(fn.Bases, d)
			}
		}
		l.bind(s.Name, &ir.Instr{Op: ir.Func, Pos: at(s.Pos), Fn: fn}, s.Pos)
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
	case *Delete:
		for _, t := range s.Targets {
			switch t := t.(type) {
			case *Attribute:
				l.emit(&ir.Instr{Op: ir.Del, Pos: at(t.Pos), A: l.expr(t.Obj), Name: t.Name})
			case *Subscript:
				l.emit(&ir.Instr{Op: ir.Del, Pos: at(t.Pos), A: l.expr(t.Obj), B: l.expr(t.Index)})
			}
		}
	case *Break:
		if n := len(l.loops); n > 0 {
			l.jump(l.loops[n-1].exit)
		}
	case *Continue:
		if n := len(l.loops); n > 0 {
			l.jump(l.loops[n-1].head)
		}
	case *If:
		then, els, after := l.newBlock(), l.newBlock(), l.newBlock()
		l.cond(s.Test, then, els)
		l.cur = then
		l.stmts(s.Body)
		l.jump(after)
		l.cur = els
		l.stmts(s.Else)
		l.jump(after)
		l.cur = after
	case *For:
		it := l.expr(s.Iter)
		head, body, els, exit := l.newBlock(), l.newBlock(), l.newBlock(), l.newBlock()
		l.jump(head)
		l.cur = head
		l.branch(ir.Operand{}, s.Pos, body, els)
		l.cur = body
		x := l.value(ir.Iter, s.Pos, "", it, ir.Operand{})
		l.assign(s.Target, x, s.Pos)
		l.loops = append(l.loops, loop{head, exit})
		l.stmts(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.jump(head)
		l.cur = els
		l.stmts(s.Else)
		l.jump(exit)
		l.cur = exit
	case *While:
		head, body, els, exit := l.newBlock(), l.newBlock(), l.newBlock(), l.newBlock()
		l.jump(head)
		l.cur = head
		l.cond(s.Test, body, els)
		l.cur = body
		l.loops = append(l.loops, loop{head, exit})
		l.stmts(s.Body)
		l.loops = l.loops[:len(l.loops)-1]
		l.jump(head)
		l.cur = els
		l.stmts(s.Else)
		l.jump(exit)
		l.cur = exit
	case *With:
		for _, it := range s.Items {
			v := l.expr(it.Ctx)
			if it.Target != nil {
				l.assign(it.Target, v, s.Pos)
			}
		}
		l.stmts(s.Body)
	case *Raise:
		if s.Exc != nil {
			l.expr(s.Exc)
		}
		if l.cur == nil {
			l.cur = l.newBlock()
		}
		l.cur.Term = ir.Term{Kind: ir.Raise, Pos: at(s.Pos)}
		l.cur = nil
	case *Try:
		l.try(s)
	case *Assert:
		ok, fail := l.newBlock(), l.newBlock()
		l.cond(s.Test, ok, fail)
		fail.Term = ir.Term{Kind: ir.Raise, Pos: at(s.Pos)}
		l.cur = ok
	case *Import:
		for _, a := range s.Names {
			if a.AsName != "" {
				l.bind(a.AsName, &ir.Instr{Op: ir.Import, Pos: at(s.Pos), Name: a.Name}, s.Pos)
				continue
			}
			first := strings.SplitN(a.Name, ".", 2)[0]
			l.bind(first, &ir.Instr{Op: ir.Import, Pos: at(s.Pos), Name: first}, s.Pos)
		}
	case *ImportFrom:
		mod := l.absolute(s.Module, s.Level)
		for _, a := range s.Names {
			if a.Name == "*" {
				continue
			}
			full := a.Name
			if mod != "" {
				full = mod + "." + a.Name
			}
			as := a.AsName
			if as == "" {
				as = a.Name
			}
			l.bind(as, &ir.Instr{Op: ir.Import, Pos: at(s.Pos), Name: full}, s.Pos)
		}
	case *Match:
		l.match(s)
	}
}

// absolute resolves a relative import against the module's name.
func (l *lowerer) absolute(mod string, level int) string {
	if level == 0 {
		return mod
	}
	parts := strings.Split(l.mod.Name, ".")
	if l.mod.Name == "" {
		parts = nil
	}
	if !l.pkg && len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	for i := 1; i < level && len(parts) > 0; i++ {
		parts = parts[:len(parts)-1]
	}
	base := strings.Join(parts, ".")
	switch {
	case base == "":
		return mod
	case mod == "":
		return base
	}
	return base + "." + mod
}

// bind sets a variable of the current scope to the result of in.
func (l *lowerer) bind(name string, in *ir.Instr, pos Pos) {
	in.Dst = l.varName(name)
	l.emit(in)
}

func (l *lowerer) varName(name string) string {
	for i := len(l.renames) - 1; i >= 0; i-- {
		if r, ok := l.renames[i][name]; ok {
			return r
		}
	}
	return name
}

func (l *lowerer) try(s *Try) {
	after := l.newBlock()
	var hs []*ir.Block
	for range s.Handlers {
		hs = append(hs, l.newBlock())
	}
	if len(hs) > 0 {
		// The body's blocks may raise into any handler.
		body := l.newBlockWith(hs)
		l.jump(body)
		l.handlers = append(l.handlers, hs)
		l.cur = body
		l.stmts(s.Body)
		l.handlers = l.handlers[:len(l.handlers)-1]
	} else {
		l.stmts(s.Body)
	}
	if l.cur != nil && len(hs) > 0 {
		// Leave the protected region before the else clause.
		next := l.newBlock()
		l.jump(next)
		l.cur = next
	}
	l.stmts(s.Else)
	l.jump(after)
	for i, h := range s.Handlers {
		l.cur = hs[i]
		if h.Type != nil {
			l.expr(h.Type)
		}
		if h.Name != "" {
			l.bind(h.Name, &ir.Instr{Op: ir.Copy, Pos: at(h.Pos), A: ir.C(ir.Other, "exception")}, h.Pos)
		}
		l.stmts(h.Body)
		l.jump(after)
	}
	l.cur = after
	l.stmts(s.Finally)
}

func (l *lowerer) newBlockWith(hs []*ir.Block) *ir.Block {
	b := l.fn.NewBlock()
	b.Handlers = hs
	return b
}

// ---- match ----

func (l *lowerer) match(s *Match) {
	subj := l.expr(s.Subject)
	if subj.Const == nil && ir.IsTemp(subj.Var) {
		// Keep the subject in a variable the guards can name.
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(s.Pos), Dst: t, A: subj})
		subj = ir.V(t)
	}
	after := l.newBlock()
	for _, c := range s.Cases {
		body, next := l.newBlock(), l.newBlock()
		matched := l.newBlock()
		l.pattern(subj, c.Pattern, matched, next)
		l.cur = matched
		if c.Guard != nil {
			l.cond(c.Guard, body, next)
		} else {
			l.jump(body)
		}
		l.cur = body
		l.stmts(c.Body)
		l.jump(after)
		l.cur = next
	}
	l.jump(after)
	l.cur = after
}

// pattern tests subj against a case pattern, binding its captures on the
// way to ok.
func (l *lowerer) pattern(subj ir.Operand, p Expr, ok, fail *ir.Block) {
	switch p := p.(type) {
	case *Name:
		if p.Id != "_" {
			l.bind(p.Id, &ir.Instr{Op: ir.Copy, Pos: at(p.Pos), A: subj}, p.Pos)
		}
		l.jump(ok)
	case *MatchAs:
		if p.Pattern == nil {
			if p.Name != "_" {
				l.bind(p.Name, &ir.Instr{Op: ir.Copy, Pos: at(p.Pos), A: subj}, p.Pos)
			}
			l.jump(ok)
			return
		}
		mid := l.newBlock()
		l.pattern(subj, p.Pattern, mid, fail)
		l.cur = mid
		l.bind(p.Name, &ir.Instr{Op: ir.Copy, Pos: at(p.Pos), A: subj}, p.Pos)
		l.jump(ok)
	case *BinOp:
		if p.Op == "|" {
			next := l.newBlock()
			l.pattern(subj, p.L, ok, next)
			l.cur = next
			l.pattern(subj, p.R, ok, fail)
			return
		}
		l.unknownPattern(subj, p, ok, fail)
	case *Const, *Attribute, *UnaryOp:
		v := l.expr(p)
		c := l.value(ir.Bin, p.At(), "==", subj, v)
		l.branch(c, p.At(), ok, fail)
	default:
		l.unknownPattern(subj, p, ok, fail)
	}
}

// unknownPattern binds every capture of a structural pattern to the
// subject, which over-approximates what reaches it, and may or may not
// match.
func (l *lowerer) unknownPattern(subj ir.Operand, p Expr, ok, fail *ir.Block) {
	names := map[string]bool{}
	collectLocals([]Stmt{&Match{Cases: []*Case{{Pattern: p}}}}, names, map[string]bool{})
	for n := range names {
		l.bind(n, &ir.Instr{Op: ir.Copy, Pos: at(p.At()), A: subj}, p.At())
	}
	l.branch(ir.Operand{}, p.At(), ok, fail)
}

// ---- conditions ----

// cond lowers a condition into branches to t and f, so that and, or and
// not become control flow and each test is a branch of its own.
func (l *lowerer) cond(e Expr, t, f *ir.Block) {
	switch e := e.(type) {
	case *BoolOp:
		for i, v := range e.Values {
			if i == len(e.Values)-1 {
				l.cond(v, t, f)
				return
			}
			next := l.newBlock()
			if e.Op == "and" {
				l.cond(v, next, f)
			} else {
				l.cond(v, t, next)
			}
			l.cur = next
		}
	case *UnaryOp:
		if e.Op == "not" {
			l.cond(e.X, f, t)
			return
		}
		l.branch(l.expr(e), e.Pos, t, f)
	default:
		l.branch(l.expr(e), e.At(), t, f)
	}
}

// ---- assignment ----

func (l *lowerer) assign(target Expr, v ir.Operand, pos Pos) {
	switch t := target.(type) {
	case *Name:
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(t.Pos), Dst: l.varName(t.Id), A: v})
	case *Attribute:
		l.emit(&ir.Instr{Op: ir.Store, Pos: at(t.Pos), A: l.expr(t.Obj), Name: t.Name, B: v})
	case *Subscript:
		obj := l.expr(t.Obj)
		if s, ok := t.Index.(*Slice); ok {
			l.slice(s)
			l.emit(&ir.Instr{Op: ir.SetIndex, Pos: at(t.Pos), A: obj, C: v})
			return
		}
		l.emit(&ir.Instr{Op: ir.SetIndex, Pos: at(t.Pos), A: obj, B: l.expr(t.Index), C: v})
	case *Tuple:
		l.unpack(t.Elts, v, pos)
	case *List:
		l.unpack(t.Elts, v, pos)
	case *Starred:
		l.assign(t.X, v, pos)
	}
}

func (l *lowerer) unpack(elts []Expr, v ir.Operand, pos Pos) {
	star := false
	for i, e := range elts {
		if s, ok := e.(*Starred); ok {
			star = true
			l.assign(s.X, v, pos)
			continue
		}
		idx := ir.C(ir.Int, strconv.Itoa(i))
		if star {
			idx = ir.C(ir.Int, strconv.Itoa(i-len(elts)))
		}
		l.assign(e, l.value(ir.Index, e.At(), "", v, idx), pos)
	}
}

// ---- expressions ----

func (l *lowerer) exprs(es []Expr) []ir.Operand {
	out := make([]ir.Operand, 0, len(es))
	for _, e := range es {
		out = append(out, l.expr(e))
	}
	return out
}

func (l *lowerer) name(n *Name) ir.Operand {
	id := l.varName(n.Id)
	if id != n.Id || l.module || l.locals[n.Id] {
		return ir.V(id)
	}
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Free, Pos: at(n.Pos), Dst: t, Name: n.Id})
	return ir.V(t)
}

func constOf(c *Const) ir.Operand {
	switch c.Kind {
	case ConstStr:
		return ir.C(ir.Str, c.Val)
	case ConstBytes:
		return ir.C(ir.Bytes, c.Val)
	case ConstNum:
		v := strings.ReplaceAll(c.Val, "_", "")
		if n, err := strconv.ParseInt(v, 0, 64); err == nil {
			return ir.C(ir.Int, strconv.FormatInt(n, 10))
		}
		if _, err := strconv.ParseFloat(v, 64); err == nil {
			return ir.C(ir.Float, v)
		}
		return ir.C(ir.Other, v)
	case ConstTrue:
		return ir.C(ir.Bool, "true")
	case ConstFalse:
		return ir.C(ir.Bool, "false")
	case ConstNone:
		return ir.C(ir.None, "")
	}
	return ir.C(ir.Other, "...")
}

func (l *lowerer) expr(e Expr) ir.Operand {
	switch e := e.(type) {
	case *Name:
		return l.name(e)
	case *Const:
		return constOf(e)
	case *FString:
		var parts []ir.Operand
		for _, p := range e.Parts {
			if fv, ok := p.(*FormattedValue); ok {
				v := l.expr(fv.Value)
				if fv.Spec != nil {
					l.expr(fv.Spec)
				}
				parts = append(parts, v)
				continue
			}
			parts = append(parts, l.expr(p))
		}
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Pos), Dst: t, Name: "str", Args: parts})
		return ir.V(t)
	case *FormattedValue:
		return l.expr(e.Value)
	case *Attribute:
		return l.value(ir.Load, e.Pos, e.Name, l.expr(e.Obj), ir.Operand{})
	case *Subscript:
		obj := l.expr(e.Obj)
		if s, ok := e.Index.(*Slice); ok {
			lo, hi := l.slice(s)
			t := l.temp()
			l.emit(&ir.Instr{Op: ir.Index, Pos: at(e.Pos), Dst: t, Name: "slice", A: obj, B: lo, C: hi})
			return ir.V(t)
		}
		return l.value(ir.Index, e.Pos, "", obj, l.expr(e.Index))
	case *Slice:
		l.slice(e)
		return ir.C(ir.Other, "slice")
	case *Call:
		return l.call(e)
	case *BinOp:
		return l.value(ir.Bin, e.Pos, e.Op, l.expr(e.L), l.expr(e.R))
	case *BoolOp:
		// The value of a or b is one of them: a temporary set on each path.
		t := l.temp()
		after := l.newBlock()
		for i, v := range e.Values {
			x := l.expr(v)
			l.emit(&ir.Instr{Op: ir.Copy, Pos: at(v.At()), Dst: t, A: x})
			if i == len(e.Values)-1 {
				break
			}
			next := l.newBlock()
			if e.Op == "and" {
				l.branch(ir.V(t), v.At(), next, after)
			} else {
				l.branch(ir.V(t), v.At(), after, next)
			}
			l.cur = next
		}
		l.jump(after)
		l.cur = after
		return ir.V(t)
	case *UnaryOp:
		return l.value(ir.Unary, e.Pos, e.Op, l.expr(e.X), ir.Operand{})
	case *Compare:
		left := l.expr(e.L)
		var res ir.Operand
		for i, op := range e.Ops {
			right := l.expr(e.Rights[i])
			c := l.value(ir.Bin, e.Pos, op, left, right)
			if res.IsZero() {
				res = c
			} else {
				res = l.value(ir.Bin, e.Pos, "and", res, c)
			}
			left = right
		}
		return res
	case *IfExp:
		t := l.temp()
		then, els, after := l.newBlock(), l.newBlock(), l.newBlock()
		l.cond(e.Test, then, els)
		l.cur = then
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Body.At()), Dst: t, A: l.expr(e.Body)})
		l.jump(after)
		l.cur = els
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Else.At()), Dst: t, A: l.expr(e.Else)})
		l.jump(after)
		l.cur = after
		return ir.V(t)
	case *Lambda:
		fn := l.function("<lambda>", e.Pos, e.Params, nil, []Stmt{&Return{Pos: e.Body.At(), X: e.Body}}, l.fn, "", false)
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Func, Pos: at(e.Pos), Dst: t, Fn: fn})
		return ir.V(t)
	case *Tuple:
		return l.build("tuple", e.Pos, e.Elts)
	case *List:
		return l.build("list", e.Pos, e.Elts)
	case *Set:
		return l.build("set", e.Pos, e.Elts)
	case *Dict:
		var vals, keys []ir.Operand
		for i, v := range e.Values {
			var k ir.Operand
			if e.Keys[i] != nil {
				k = l.expr(e.Keys[i])
			}
			keys = append(keys, k)
			vals = append(vals, l.expr(v))
		}
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Pos), Dst: t, Name: "dict", Args: vals, Keys2: keys})
		return ir.V(t)
	case *Comp:
		return l.comp(e)
	case *Starred:
		return l.expr(e.X)
	case *NamedExpr:
		v := l.expr(e.Value)
		name := l.varName(e.Target.Id)
		l.emit(&ir.Instr{Op: ir.Copy, Pos: at(e.Pos), Dst: name, A: v})
		return ir.V(name)
	case *Await:
		return l.expr(e.X)
	case *Yield:
		if e.X != nil {
			l.expr(e.X)
		}
		return ir.C(ir.Other, "yield")
	}
	return ir.C(ir.Other, "?")
}

func (l *lowerer) slice(s *Slice) (lo, hi ir.Operand) {
	if s.Lo != nil {
		lo = l.expr(s.Lo)
	}
	if s.Hi != nil {
		hi = l.expr(s.Hi)
	}
	if s.Step != nil {
		l.expr(s.Step)
	}
	return lo, hi
}

func (l *lowerer) build(kind string, pos Pos, elts []Expr) ir.Operand {
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Build, Pos: at(pos), Dst: t, Name: kind, Args: l.exprs(elts)})
	return ir.V(t)
}

func (l *lowerer) call(e *Call) ir.Operand {
	in := &ir.Instr{Op: ir.Call, Pos: at(e.Pos)}
	if a, ok := e.Func.(*Attribute); ok {
		in.A = l.expr(a.Obj)
		in.Name = a.Name
	} else {
		in.A = l.expr(e.Func)
	}
	for _, a := range e.Args {
		in.Args = append(in.Args, l.expr(a.Value))
		key := a.Name
		if a.Star != "" {
			key = a.Star
		}
		in.Keys = append(in.Keys, key)
	}
	in.Dst = l.temp()
	l.emit(in)
	return ir.V(in.Dst)
}

// comp lowers a comprehension as one pass over its generators: each
// element of each iterable is bound to the clause's variables, renamed so
// they do not clobber the function's own, and the result holds the
// element expression.
func (l *lowerer) comp(e *Comp) ir.Operand {
	l.ncomp++
	ren := map[string]string{}
	for _, g := range e.Gens {
		names := map[string]bool{}
		collectLocals([]Stmt{&Assign{Targets: []Expr{g.Target}}}, names, map[string]bool{})
		for n := range names {
			ren[n] = "$c" + strconv.Itoa(l.ncomp) + "." + n
		}
	}
	for i, g := range e.Gens {
		// The first iterable is evaluated in the enclosing scope.
		if i > 0 {
			l.renames = append(l.renames, ren)
		}
		it := l.expr(g.Iter)
		if i > 0 {
			l.renames = l.renames[:len(l.renames)-1]
		}
		l.renames = append(l.renames, ren)
		x := l.value(ir.Iter, e.Pos, "", it, ir.Operand{})
		l.assign(g.Target, x, e.Pos)
		for _, c := range g.Ifs {
			l.expr(c)
		}
		l.renames = l.renames[:len(l.renames)-1]
	}
	l.renames = append(l.renames, ren)
	defer func() { l.renames = l.renames[:len(l.renames)-1] }()
	t := l.temp()
	if e.Kind == "dict" {
		k := l.expr(e.Key)
		v := l.expr(e.Elt)
		l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Pos), Dst: t, Name: "dictcomp", Args: []ir.Operand{v}, Keys2: []ir.Operand{k}})
		return ir.V(t)
	}
	v := l.expr(e.Elt)
	kind := e.Kind + "comp"
	l.emit(&ir.Instr{Op: ir.Build, Pos: at(e.Pos), Dst: t, Name: kind, Args: []ir.Operand{v}})
	return ir.V(t)
}
