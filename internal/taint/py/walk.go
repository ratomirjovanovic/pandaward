package py

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
	exprs := func(xs []Expr) {
		for _, x := range xs {
			ex(x)
		}
	}
	body := func(ss []Stmt) {
		for _, s := range ss {
			if s != nil {
				Inspect(s, fn)
			}
		}
	}
	params := func(ps []*Param) {
		for _, p := range ps {
			ex(p.Ann)
			ex(p.Default)
		}
	}
	gens := func(gs []*Comprehension) {
		for _, g := range gs {
			ex(g.Iter)
			ex(g.Target)
			exprs(g.Ifs)
		}
	}
	switch n := n.(type) {
	case *FString:
		exprs(n.Parts)
	case *FormattedValue:
		ex(n.Value)
		ex(n.Spec)
	case *Attribute:
		ex(n.Obj)
	case *Subscript:
		ex(n.Obj)
		ex(n.Index)
	case *Slice:
		ex(n.Lo)
		ex(n.Hi)
		ex(n.Step)
	case *Call:
		ex(n.Func)
		for _, a := range n.Args {
			ex(a.Value)
		}
	case *BinOp:
		ex(n.L)
		ex(n.R)
	case *BoolOp:
		exprs(n.Values)
	case *UnaryOp:
		ex(n.X)
	case *Compare:
		ex(n.L)
		exprs(n.Rights)
	case *IfExp:
		ex(n.Test)
		ex(n.Body)
		ex(n.Else)
	case *Lambda:
		params(n.Params)
		ex(n.Body)
	case *Tuple:
		exprs(n.Elts)
	case *List:
		exprs(n.Elts)
	case *Set:
		exprs(n.Elts)
	case *Dict:
		for i := range n.Values {
			ex(n.Keys[i])
			ex(n.Values[i])
		}
	case *Comp:
		gens(n.Gens)
		ex(n.Key)
		ex(n.Elt)
	case *Starred:
		ex(n.X)
	case *NamedExpr:
		ex(n.Target)
		ex(n.Value)
	case *Await:
		ex(n.X)
	case *Yield:
		ex(n.X)
	case *MatchAs:
		ex(n.Pattern)

	case *ExprStmt:
		ex(n.X)
	case *Assign:
		ex(n.Value)
		exprs(n.Targets)
	case *AugAssign:
		ex(n.Target)
		ex(n.Value)
	case *AnnAssign:
		ex(n.Target)
		ex(n.Ann)
		ex(n.Value)
	case *FuncDef:
		exprs(n.Decorators)
		params(n.TypeParams)
		params(n.Params)
		ex(n.Returns)
		body(n.Body)
	case *ClassDef:
		exprs(n.Decorators)
		params(n.TypeParams)
		for _, a := range n.Bases {
			ex(a.Value)
		}
		body(n.Body)
	case *Return:
		ex(n.X)
	case *Delete:
		exprs(n.Targets)
	case *If:
		ex(n.Test)
		body(n.Body)
		body(n.Else)
	case *For:
		ex(n.Iter)
		ex(n.Target)
		body(n.Body)
		body(n.Else)
	case *While:
		ex(n.Test)
		body(n.Body)
		body(n.Else)
	case *With:
		for _, it := range n.Items {
			ex(it.Ctx)
			ex(it.Target)
		}
		body(n.Body)
	case *Raise:
		ex(n.Exc)
		ex(n.Cause)
	case *Try:
		body(n.Body)
		for _, h := range n.Handlers {
			ex(h.Type)
			body(h.Body)
		}
		body(n.Else)
		body(n.Finally)
	case *Assert:
		ex(n.Test)
		ex(n.Msg)
	case *Match:
		ex(n.Subject)
		for _, c := range n.Cases {
			ex(c.Pattern)
			ex(c.Guard)
			body(c.Body)
		}
	case *TypeAlias:
		ex(n.Name)
		params(n.TypeParams)
		ex(n.Value)
	}
}
