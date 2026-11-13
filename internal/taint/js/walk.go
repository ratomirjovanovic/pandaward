package js

// Inspect calls fn for n and every node below it in source order. When fn
// returns false the children of that node are skipped.
func Inspect(n Node, fn func(Node) bool) {
	if n == nil || !fn(n) {
		return
	}
	ex := func(x Expr) {
		if x != nil {
			Inspect(x, fn)
		}
	}
	st := func(s Stmt) {
		if s != nil {
			Inspect(s, fn)
		}
	}
	list := func(ss []Stmt) {
		for _, s := range ss {
			st(s)
		}
	}
	exprs := func(xs []Expr) {
		for _, x := range xs {
			ex(x)
		}
	}
	switch n := n.(type) {
	case *TemplateLit:
		ex(n.Tag)
		exprs(n.Exprs)
	case *Member:
		ex(n.Obj)
		ex(n.Computed)
	case *Call:
		ex(n.Callee)
		exprs(n.Args)
	case *Binary:
		ex(n.L)
		ex(n.R)
	case *Unary:
		ex(n.X)
	case *Assign:
		ex(n.Target)
		ex(n.Value)
	case *Cond:
		ex(n.Test)
		ex(n.Then)
		ex(n.Else)
	case *Seq:
		exprs(n.List)
	case *ArrayLit:
		exprs(n.Elems)
	case *ObjectLit:
		for _, p := range n.Props {
			ex(p.Computed)
			ex(p.Value)
		}
	case *Spread:
		ex(n.X)
	case *Yield:
		ex(n.X)
	case *Func:
		exprs(n.Params)
		list(n.Body)
		ex(n.ExprBody)
	case *Class:
		ex(n.Super)
		for _, m := range n.Members {
			ex(m.Computed)
			ex(m.Value)
			list(m.Block)
		}
	case *JSXElement:
		for _, a := range n.Attrs {
			ex(a.Value)
		}
		exprs(n.Children)
	case *ExprStmt:
		ex(n.X)
	case *VarDecl:
		for _, d := range n.Decls {
			ex(d.Target)
			ex(d.Init)
		}
	case *Return:
		ex(n.X)
	case *If:
		ex(n.Test)
		st(n.Then)
		st(n.Else)
	case *For:
		st(n.Init)
		ex(n.Test)
		ex(n.Update)
		st(n.Body)
	case *ForIn:
		st(n.Left)
		ex(n.Right)
		st(n.Body)
	case *While:
		ex(n.Test)
		st(n.Body)
	case *Block:
		list(n.List)
	case *Try:
		if n.Block != nil {
			st(n.Block)
		}
		ex(n.Param)
		if n.Handler != nil {
			st(n.Handler)
		}
		if n.Finally != nil {
			st(n.Finally)
		}
	case *Switch:
		ex(n.Disc)
		for _, c := range n.Cases {
			ex(c.Test)
			list(c.Body)
		}
	case *Throw:
		ex(n.X)
	case *Labeled:
		st(n.Body)
	case *FuncDecl:
		ex(n.Func)
	case *ClassDecl:
		ex(n.Class)
	case *Export:
		st(n.Decl)
		ex(n.Default)
	}
}
