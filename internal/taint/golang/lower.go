// Package golang lowers Go source to the IR of the taint engine (#534).
// It uses the standard library parser. Each file is a module; the
// package-level names of the other files of its package, and of the
// packages of the project it imports, are imported by name, so calls
// across files resolve. A local variable is named $name, which keeps it
// apart from a function of the same name.
package golang

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// Env describes where a file lives.
type Env struct {
	// Module is the name of the file's module.
	Module string
	// Siblings maps each package-level name of the file's package to the
	// module that declares it.
	Siblings map[string]string
	// Package returns the package-level names of a package of the project
	// by import path, with the module of each, or false. It may be nil.
	Package func(importPath string) (map[string]string, bool)
}

// Decls returns the package-level names a file declares and its package
// name; ok is false when the file does not parse at all.
func Decls(path, src string) (names []string, pkg string, ok bool) {
	f, _ := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
	if f == nil || f.Name == nil {
		return nil, "", false
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				names = append(names, d.Name.Name)
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.ValueSpec:
					for _, n := range s.Names {
						names = append(names, n.Name)
					}
				case *ast.TypeSpec:
					names = append(names, s.Name.Name)
				}
			}
		}
	}
	return names, f.Name.Name, true
}

// ImportName is the dotted name the engine and the specification use for
// an import path: slashes become dots and dots inside a segment become
// underscores (github.com/gin-gonic/gin is github_com.gin-gonic.gin).
func ImportName(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = strings.ReplaceAll(s, ".", "_")
	}
	return strings.Join(segs, ".")
}

// Parse lowers a file. errs is 1 when the file has a syntax error; the part
// that parsed is still lowered.
func Parse(path, src string, env Env) (*ir.Module, int) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	m := &ir.Module{Path: path, Name: env.Module}
	errs := 0
	if err != nil {
		errs = 1
	}
	if f == nil {
		m.Init = &ir.Function{Name: "<module>"}
		m.Init.NewBlock().Term = ir.Term{Kind: ir.Return}
		m.Init.Link()
		m.Funcs = []*ir.Function{m.Init}
		return m, errs
	}
	l := &lowerer{fset: fset, mod: m, env: env, imports: map[string]string{}, own: map[string]bool{}}
	l.run(f)
	return m, errs
}

type scope struct {
	locals map[string]bool
	types  map[string]string
	parent *scope
}

type loopT struct{ cont, exit *ir.Block }

type lowerer struct {
	fset    *token.FileSet
	mod     *ir.Module
	env     Env
	imports map[string]string // file alias -> dotted import name
	project map[string]string // alias -> import path of a package of the project
	own     map[string]bool   // package-level names of this file

	fn    *ir.Function
	cur   *ir.Block
	ntemp int
	sc    *scope
	loops []loopT
	// classes of this file, by type name
	classes map[string]*ir.Function
	// static types of temporaries
	types map[string]string
}

func (l *lowerer) pos(n ast.Node) ir.Pos {
	p := l.fset.Position(n.Pos())
	return ir.Pos{Line: p.Line, Col: p.Column}
}

func (l *lowerer) temp() string {
	l.ntemp++
	return "$" + strconv.Itoa(l.ntemp)
}

func (l *lowerer) emit(in *ir.Instr) {
	if l.cur == nil {
		l.cur = l.fn.NewBlock()
	}
	l.cur.Instrs = append(l.cur.Instrs, in)
}

func (l *lowerer) newBlock() *ir.Block { return l.fn.NewBlock() }

func (l *lowerer) jump(b *ir.Block) {
	if l.cur != nil {
		l.cur.Term = ir.Term{Kind: ir.Jump, Succs: []*ir.Block{b}}
	}
	l.cur = nil
}

func (l *lowerer) branch(cond ir.Operand, pos ir.Pos, t, f *ir.Block) {
	if l.cur == nil {
		l.cur = l.fn.NewBlock()
	}
	l.cur.Term = ir.Term{Kind: ir.Branch, Pos: pos, Cond: cond, Succs: []*ir.Block{t, f}}
	l.cur = nil
}

func (l *lowerer) val(op ir.Op, pos ir.Pos, name string, a, b ir.Operand) ir.Operand {
	t := l.temp()
	l.emit(&ir.Instr{Op: op, Pos: pos, Dst: t, Name: name, A: a, B: b})
	return ir.V(t)
}

// cast gives a value the class typ.
func (l *lowerer) cast(pos ir.Pos, a ir.Operand, typ string) ir.Operand {
	if typ == "" || a.Var == "" {
		return a
	}
	t := l.val(ir.Cast, pos, typ, a, ir.Operand{})
	l.types[t.Var] = typ
	return t
}

// function lowers a body into a new Function.
func (l *lowerer) function(name string, pos ir.Pos, params []ir.Param, class string, parent *scope, body func()) *ir.Function {
	fn := &ir.Function{Name: name, Pos: pos, Params: params, Parent: l.fn, Class: class}
	l.mod.Funcs = append(l.mod.Funcs, fn)
	sFn, sCur, sTemp, sLoops, sSc := l.fn, l.cur, l.ntemp, l.loops, l.sc
	l.fn, l.ntemp, l.loops = fn, 0, nil
	l.sc = &scope{locals: map[string]bool{}, types: map[string]string{}, parent: parent}
	for _, p := range params {
		n := strings.TrimPrefix(p.Name, "$")
		l.sc.locals[n] = true
		if p.Ann != "" {
			l.sc.types[n] = p.Ann
		}
	}
	l.cur = fn.NewBlock()
	body()
	if l.cur != nil {
		l.cur.Term = ir.Term{Kind: ir.Return}
	}
	fn.Link()
	l.fn, l.cur, l.ntemp, l.loops, l.sc = sFn, sCur, sTemp, sLoops, sSc
	return fn
}

func (l *lowerer) run(f *ast.File) {
	l.classes = map[string]*ir.Function{}
	l.types = map[string]string{}
	l.project = map[string]string{}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		alias := path.Base(p)
		if len(alias) >= 2 && alias[0] == 'v' && alias[1] >= '0' && alias[1] <= '9' {
			alias = path.Base(path.Dir(p))
		}
		if im.Name != nil {
			alias = im.Name.Name
		}
		if alias == "_" || alias == "." {
			continue
		}
		alias = strings.ReplaceAll(alias, "-", "_")
		l.imports[alias] = ImportName(p)
		if l.env.Package != nil {
			if _, ok := l.env.Package(p); ok {
				l.project[alias] = p
			}
		}
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				l.own[d.Name.Name] = true
			}
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.ValueSpec:
					for _, n := range s.Names {
						l.own[n.Name] = true
					}
				case *ast.TypeSpec:
					l.own[s.Name.Name] = true
				}
			}
		}
	}
	l.mod.Init = l.function("<module>", ir.Pos{Line: 1, Col: 1}, nil, "", nil, func() {
		// the names of the other files of the package
		for n, mod := range l.env.Siblings {
			if l.own[n] || mod == l.env.Module {
				continue
			}
			l.emit(&ir.Instr{Op: ir.Import, Dst: n, Name: mod + "." + n})
		}
		// functions first, so a variable initializer can call them
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				l.funcDecl(fd)
			}
		}
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok {
				l.genDecl(gd, true)
			}
		}
	})
}

func (l *lowerer) typeName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		switch e.Name {
		case "string", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64",
			"float32", "float64", "bool", "byte", "rune", "error", "any":
			return e.Name
		}
		if l.own[e.Name] {
			return l.env.Module + "." + e.Name
		}
		if mod, ok := l.env.Siblings[e.Name]; ok {
			return mod + "." + e.Name
		}
	case *ast.StarExpr:
		return l.typeName(e.X)
	case *ast.ParenExpr:
		return l.typeName(e.X)
	case *ast.SelectorExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			if p, ok := l.project[id.Name]; ok {
				if names, ok := l.env.Package(p); ok {
					if mod, ok := names[e.Sel.Name]; ok {
						return mod + "." + e.Sel.Name
					}
				}
			}
			if n, ok := l.imports[id.Name]; ok {
				return n + "." + e.Sel.Name
			}
		}
	}
	return ""
}

func (l *lowerer) params(ft *ast.FuncType, recv *ast.FieldList) []ir.Param {
	var out []ir.Param
	add := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			ann := l.typeName(f.Type)
			kind := ""
			if _, ok := f.Type.(*ast.Ellipsis); ok {
				kind = "*"
			}
			if len(f.Names) == 0 {
				out = append(out, ir.Param{Name: "$_", Pos: l.pos(f), Ann: ann, Kind: kind})
				continue
			}
			for _, n := range f.Names {
				out = append(out, ir.Param{Name: "$" + n.Name, Pos: l.pos(n), Ann: ann, Kind: kind})
			}
		}
	}
	add(recv)
	add(ft.Params)
	return out
}

func (l *lowerer) funcDecl(fd *ast.FuncDecl) {
	pos := l.pos(fd)
	if fd.Body == nil {
		return
	}
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		tn := ""
		switch t := fd.Recv.List[0].Type.(type) {
		case *ast.StarExpr:
			if id, ok := t.X.(*ast.Ident); ok {
				tn = id.Name
			}
		case *ast.Ident:
			tn = t.Name
		case *ast.IndexExpr:
			if id, ok := t.X.(*ast.Ident); ok {
				tn = id.Name
			}
		}
		if tn == "" {
			return
		}
		class := l.classes[tn]
		if class == nil {
			class = &ir.Function{Name: "<class " + tn + ">", Pos: pos, Class: tn, Parent: l.fn}
			class.NewBlock().Term = ir.Term{Kind: ir.Return}
			class.Link()
			l.mod.Funcs = append(l.mod.Funcs, class)
			l.classes[tn] = class
			l.emit(&ir.Instr{Op: ir.Func, Pos: pos, Dst: tn, Fn: class})
		}
		params := l.params(fd.Type, fd.Recv)
		// the receiver is an instance of the class
		if len(params) > 0 {
			params[0].Ann = l.env.Module + "." + tn
		}
		sFn := l.fn
		l.fn = class
		fn := l.function(tn+"."+fd.Name.Name, pos, params, tn, nil, func() { l.block(fd.Body) })
		l.fn = sFn
		fn.Parent = class
		return
	}
	fn := l.function(fd.Name.Name, pos, l.params(fd.Type, nil), "", nil, func() { l.block(fd.Body) })
	l.emit(&ir.Instr{Op: ir.Func, Pos: pos, Dst: fd.Name.Name, Fn: fn})
}

func (l *lowerer) genDecl(gd *ast.GenDecl, pkgLevel bool) {
	for _, s := range gd.Specs {
		vs, ok := s.(*ast.ValueSpec)
		if !ok {
			continue
		}
		var vals []ir.Operand
		for _, v := range vs.Values {
			vals = append(vals, l.expr(v))
		}
		typ := ""
		if vs.Type != nil {
			typ = l.typeName(vs.Type)
		}
		for i, n := range vs.Names {
			if n.Name == "_" {
				continue
			}
			var v ir.Operand
			switch {
			case len(vals) == len(vs.Names):
				v = vals[i]
			case len(vals) == 1:
				v = l.val(ir.Index, l.pos(n), "", vals[0], ir.C(ir.Int, strconv.Itoa(i)))
			default:
				v = ir.C(ir.None, "None")
			}
			if typ != "" {
				v = l.cast(l.pos(n), v, typ)
			}
			l.assignName(n.Name, v, l.pos(n), pkgLevel)
		}
	}
}

// assignName sets a local, or at package level a name of the module.
func (l *lowerer) assignName(name string, v ir.Operand, pos ir.Pos, pkgLevel bool) {
	if name == "_" {
		return
	}
	dst := "$" + name
	if pkgLevel && l.fn == l.mod.Init {
		dst = name
	} else {
		l.sc.locals[name] = true
		if t := l.types[v.Var]; t != "" && v.Var != "" {
			l.sc.types[name] = t
		} else {
			delete(l.sc.types, name)
		}
	}
	l.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: dst, A: v})
}

// ---- statements ----

func (l *lowerer) block(b *ast.BlockStmt) {
	if b == nil {
		return
	}
	for _, s := range b.List {
		l.stmt(s)
	}
}

func (l *lowerer) stmt(s ast.Stmt) {
	switch s := s.(type) {
	case *ast.ExprStmt:
		l.expr(s.X)
	case *ast.AssignStmt:
		l.assign(s)
	case *ast.DeclStmt:
		if gd, ok := s.Decl.(*ast.GenDecl); ok {
			l.genDecl(gd, false)
		}
	case *ast.IncDecStmt:
		cur := l.expr(s.X)
		n := l.val(ir.Bin, l.pos(s), "+", cur, ir.C(ir.Int, "1"))
		l.store(s.X, n, l.pos(s))
	case *ast.BlockStmt:
		l.block(s)
	case *ast.IfStmt:
		l.ifStmt(s)
	case *ast.ForStmt:
		l.forStmt(s)
	case *ast.RangeStmt:
		l.rangeStmt(s)
	case *ast.SwitchStmt:
		l.switchStmt(s.Init, s.Tag, s.Body, "")
	case *ast.TypeSwitchStmt:
		var x ast.Expr
		bind := ""
		switch a := s.Assign.(type) {
		case *ast.AssignStmt:
			if ta, ok := a.Rhs[0].(*ast.TypeAssertExpr); ok {
				x = ta.X
			}
			if id, ok := a.Lhs[0].(*ast.Ident); ok {
				bind = id.Name
			}
		case *ast.ExprStmt:
			if ta, ok := a.X.(*ast.TypeAssertExpr); ok {
				x = ta.X
			}
		}
		l.switchStmt(s.Init, x, s.Body, bind)
	case *ast.SelectStmt:
		l.switchStmt(nil, nil, s.Body, "")
	case *ast.ReturnStmt:
		var ops []ir.Operand
		for _, r := range s.Results {
			ops = append(ops, l.expr(r))
		}
		var v ir.Operand
		switch len(ops) {
		case 0:
		case 1:
			v = ops[0]
		default:
			t := l.temp()
			l.emit(&ir.Instr{Op: ir.Build, Pos: l.pos(s), Dst: t, Name: "tuple", Args: ops})
			v = ir.V(t)
		}
		if l.cur == nil {
			l.cur = l.fn.NewBlock()
		}
		l.cur.Term = ir.Term{Kind: ir.Return, Pos: l.pos(s), Value: v}
		l.cur = nil
	case *ast.GoStmt:
		l.expr(s.Call)
	case *ast.DeferStmt:
		l.expr(s.Call)
	case *ast.SendStmt:
		l.expr(s.Chan)
		l.expr(s.Value)
	case *ast.LabeledStmt:
		l.stmt(s.Stmt)
	case *ast.BranchStmt:
		if len(l.loops) > 0 {
			t := l.loops[len(l.loops)-1]
			switch s.Tok {
			case token.BREAK:
				l.jump(t.exit)
			case token.CONTINUE:
				l.jump(t.cont)
			}
		}
	}
}

func (l *lowerer) assign(s *ast.AssignStmt) {
	pos := l.pos(s)
	define := s.Tok == token.DEFINE
	if s.Tok != token.ASSIGN && !define {
		// x op= y
		op := strings.TrimSuffix(s.Tok.String(), "=")
		cur := l.expr(s.Lhs[0])
		r := l.expr(s.Rhs[0])
		l.store(s.Lhs[0], l.val(ir.Bin, pos, op, cur, r), pos)
		return
	}
	if len(s.Rhs) == 1 && len(s.Lhs) > 1 {
		t := l.expr(s.Rhs[0])
		for i, lhs := range s.Lhs {
			el := l.val(ir.Index, pos, "", t, ir.C(ir.Int, strconv.Itoa(i)))
			if i == 0 {
				if ty := l.types[t.Var]; ty != "" {
					l.types[el.Var] = ty
				}
			}
			l.storeDef(lhs, el, pos, define)
		}
		return
	}
	vals := make([]ir.Operand, len(s.Rhs))
	for i, r := range s.Rhs {
		vals[i] = l.expr(r)
	}
	for i, lhs := range s.Lhs {
		if i < len(vals) {
			l.storeDef(lhs, vals[i], pos, define)
		}
	}
}

func (l *lowerer) storeDef(lhs ast.Expr, v ir.Operand, pos ir.Pos, define bool) {
	if id, ok := lhs.(*ast.Ident); ok && define {
		l.assignName(id.Name, v, pos, false)
		return
	}
	l.store(lhs, v, pos)
}

func (l *lowerer) store(lhs ast.Expr, v ir.Operand, pos ir.Pos) {
	switch e := lhs.(type) {
	case *ast.Ident:
		if e.Name == "_" {
			return
		}
		if l.isLocal(e.Name) {
			l.assignName(e.Name, v, pos, false)
			return
		}
		// a package-level variable
		l.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: e.Name, A: v})
	case *ast.SelectorExpr:
		l.emit(&ir.Instr{Op: ir.Store, Pos: pos, A: l.expr(e.X), Name: e.Sel.Name, B: v})
	case *ast.IndexExpr:
		l.emit(&ir.Instr{Op: ir.SetIndex, Pos: pos, A: l.expr(e.X), B: l.expr(e.Index), C: v})
	case *ast.StarExpr:
		l.store(e.X, v, pos)
	case *ast.ParenExpr:
		l.store(e.X, v, pos)
	}
}

func (l *lowerer) isLocal(name string) bool {
	for s := l.sc; s != nil; s = s.parent {
		if s.locals[name] {
			return true
		}
	}
	return false
}

func (l *lowerer) ifStmt(s *ast.IfStmt) {
	if s.Init != nil {
		l.stmt(s.Init)
	}
	then, els, join := l.newBlock(), l.newBlock(), l.newBlock()
	l.condTo(s.Cond, then, els)
	l.cur = then
	l.block(s.Body)
	l.jump(join)
	l.cur = els
	if s.Else != nil {
		l.stmt(s.Else)
	}
	l.jump(join)
	l.cur = join
}

// condTo branches to t when e is true and to f otherwise; && || and !
// become branches so a check guards the code it leads to.
func (l *lowerer) condTo(e ast.Expr, t, f *ir.Block) {
	switch e := e.(type) {
	case *ast.ParenExpr:
		l.condTo(e.X, t, f)
		return
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			l.condTo(e.X, f, t)
			return
		}
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			mid := l.newBlock()
			l.condTo(e.X, mid, f)
			l.cur = mid
			l.condTo(e.Y, t, f)
			return
		case token.LOR:
			mid := l.newBlock()
			l.condTo(e.X, t, mid)
			l.cur = mid
			l.condTo(e.Y, t, f)
			return
		}
	}
	c := l.expr(e)
	l.branch(c, l.pos(e), t, f)
}

func (l *lowerer) forStmt(s *ast.ForStmt) {
	if s.Init != nil {
		l.stmt(s.Init)
	}
	head, body, post, exit := l.newBlock(), l.newBlock(), l.newBlock(), l.newBlock()
	l.jump(head)
	l.cur = head
	if s.Cond != nil {
		l.condTo(s.Cond, body, exit)
	} else {
		l.jump(body)
	}
	l.loops = append(l.loops, loopT{post, exit})
	l.cur = body
	l.block(s.Body)
	l.jump(post)
	l.loops = l.loops[:len(l.loops)-1]
	l.cur = post
	if s.Post != nil {
		l.stmt(s.Post)
	}
	l.jump(head)
	l.cur = exit
}

func (l *lowerer) rangeStmt(s *ast.RangeStmt) {
	x := l.expr(s.X)
	head, body, exit := l.newBlock(), l.newBlock(), l.newBlock()
	l.jump(head)
	l.cur = head
	l.branch(ir.C(ir.Other, "range"), l.pos(s), body, exit)
	l.loops = append(l.loops, loopT{head, exit})
	l.cur = body
	pos := l.pos(s)
	define := s.Tok == token.DEFINE
	if s.Key != nil {
		l.storeDef(s.Key, l.val(ir.Iter, pos, "", x, ir.Operand{}), pos, define)
	}
	if s.Value != nil {
		l.storeDef(s.Value, l.val(ir.Iter, pos, "", x, ir.Operand{}), pos, define)
	}
	l.block(s.Body)
	l.jump(head)
	l.loops = l.loops[:len(l.loops)-1]
	l.cur = exit
}

func (l *lowerer) switchStmt(init ast.Stmt, tag ast.Expr, body *ast.BlockStmt, bind string) {
	if init != nil {
		l.stmt(init)
	}
	var tv ir.Operand
	if tag != nil {
		tv = l.expr(tag)
	}
	exit := l.newBlock()
	l.loops = append(l.loops, loopT{exit, exit})
	for _, c := range body.List {
		var list []ast.Expr
		var stmts []ast.Stmt
		var comm ast.Stmt
		switch c := c.(type) {
		case *ast.CaseClause:
			list, stmts = c.List, c.Body
		case *ast.CommClause:
			stmts, comm = c.Body, c.Comm
		}
		then, next := l.newBlock(), l.newBlock()
		cond := ir.C(ir.Other, "case")
		if tag != nil && len(list) == 1 && bind == "" {
			cond = l.val(ir.Bin, l.pos(c), "==", tv, l.expr(list[0]))
		}
		l.branch(cond, l.pos(c), then, next)
		l.cur = then
		if bind != "" {
			l.assignName(bind, tv, l.pos(c), false)
		}
		if comm != nil {
			l.stmt(comm)
		}
		for _, st := range stmts {
			l.stmt(st)
		}
		l.jump(exit)
		l.cur = next
	}
	l.jump(exit)
	l.loops = l.loops[:len(l.loops)-1]
	l.cur = exit
}
