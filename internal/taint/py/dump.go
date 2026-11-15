package py

import (
	"strconv"
	"strings"
)

// Dump renders an expression or statement as compact text for tests and
// tools: names as is, strings quoted, operators as (op a b).
func Dump(n Node) string {
	var b strings.Builder
	dump(&b, n)
	return b.String()
}

// DumpBody renders statements one per line.
func DumpBody(ss []Stmt) string {
	var lines []string
	for _, s := range ss {
		lines = append(lines, Dump(s))
	}
	return strings.Join(lines, "\n")
}

func dump(b *strings.Builder, n Node) {
	w := b.WriteString
	list := func(open, close string, xs []Expr) {
		w(open)
		for i, x := range xs {
			if i > 0 {
				w(" ")
			}
			dump(b, x)
		}
		w(close)
	}
	opt := func(x Expr) {
		if x == nil {
			w("_")
		} else {
			dump(b, x)
		}
	}
	stmts := func(ss []Stmt) {
		w("{")
		for i, s := range ss {
			if i > 0 {
				w("; ")
			}
			dump(b, s)
		}
		w("}")
	}
	params := func(ps []*Param) {
		w("(")
		for i, p := range ps {
			if i > 0 {
				w(" ")
			}
			w(p.Kind)
			w(p.Name)
			if p.Ann != nil {
				w(":")
				dump(b, p.Ann)
			}
			if p.Default != nil {
				w("=")
				dump(b, p.Default)
			}
		}
		w(")")
	}
	gens := func(gs []*Comprehension) {
		for _, g := range gs {
			w(" for ")
			dump(b, g.Target)
			w(" in ")
			dump(b, g.Iter)
			for _, c := range g.Ifs {
				w(" if ")
				dump(b, c)
			}
		}
	}
	switch n := n.(type) {
	case nil:
		w("_")
	case *Name:
		w(n.Id)
	case *Const:
		switch n.Kind {
		case ConstStr:
			w(strconv.Quote(n.Val))
		case ConstBytes:
			w("b" + strconv.Quote(n.Val))
		default:
			w(n.Val)
		}
	case *FString:
		list("(f ", ")", n.Parts)
	case *FormattedValue:
		w("{")
		dump(b, n.Value)
		if n.Conv != 0 {
			w("!" + string(n.Conv))
		}
		if n.Spec != nil {
			w(":")
			dump(b, n.Spec)
		}
		w("}")
	case *Attribute:
		dump(b, n.Obj)
		w("." + n.Name)
	case *Subscript:
		dump(b, n.Obj)
		w("[")
		dump(b, n.Index)
		w("]")
	case *Slice:
		opt(n.Lo)
		w(":")
		opt(n.Hi)
		if n.Step != nil {
			w(":")
			dump(b, n.Step)
		}
	case *Call:
		dump(b, n.Func)
		w("(")
		for i, a := range n.Args {
			if i > 0 {
				w(" ")
			}
			w(a.Star)
			if a.Name != "" {
				w(a.Name + "=")
			}
			dump(b, a.Value)
		}
		w(")")
	case *BinOp:
		w("(" + n.Op + " ")
		dump(b, n.L)
		w(" ")
		dump(b, n.R)
		w(")")
	case *BoolOp:
		list("("+n.Op+" ", ")", n.Values)
	case *UnaryOp:
		w("(" + n.Op + " ")
		dump(b, n.X)
		w(")")
	case *Compare:
		w("(cmp ")
		dump(b, n.L)
		for i, op := range n.Ops {
			w(" " + op + " ")
			dump(b, n.Rights[i])
		}
		w(")")
	case *IfExp:
		w("(if ")
		dump(b, n.Test)
		w(" ")
		dump(b, n.Body)
		w(" ")
		dump(b, n.Else)
		w(")")
	case *Lambda:
		w("(lambda ")
		params(n.Params)
		w(" ")
		dump(b, n.Body)
		w(")")
	case *Tuple:
		list("(tuple ", ")", n.Elts)
	case *List:
		list("[", "]", n.Elts)
	case *Set:
		list("(set ", ")", n.Elts)
	case *Dict:
		w("{")
		for i := range n.Values {
			if i > 0 {
				w(" ")
			}
			if n.Keys[i] == nil {
				w("**")
			} else {
				dump(b, n.Keys[i])
				w(":")
			}
			dump(b, n.Values[i])
		}
		w("}")
	case *Comp:
		w("(" + n.Kind + "comp ")
		if n.Key != nil {
			dump(b, n.Key)
			w(":")
		}
		dump(b, n.Elt)
		gens(n.Gens)
		w(")")
	case *Starred:
		w("*")
		dump(b, n.X)
	case *NamedExpr:
		w("(:= ")
		dump(b, n.Target)
		w(" ")
		dump(b, n.Value)
		w(")")
	case *Await:
		w("(await ")
		dump(b, n.X)
		w(")")
	case *Yield:
		if n.From {
			w("(yield-from ")
		} else {
			w("(yield ")
		}
		opt(n.X)
		w(")")
	case *MatchAs:
		w("(as ")
		opt(n.Pattern)
		w(" " + n.Name + ")")
	case *Bad:
		w("BAD")

	case *ExprStmt:
		dump(b, n.X)
	case *Assign:
		for _, t := range n.Targets {
			dump(b, t)
			w(" = ")
		}
		dump(b, n.Value)
	case *AugAssign:
		dump(b, n.Target)
		w(" " + n.Op + "= ")
		dump(b, n.Value)
	case *AnnAssign:
		dump(b, n.Target)
		w(": ")
		dump(b, n.Ann)
		if n.Value != nil {
			w(" = ")
			dump(b, n.Value)
		}
	case *FuncDef:
		for _, d := range n.Decorators {
			w("@")
			dump(b, d)
			w(" ")
		}
		if n.Async {
			w("async ")
		}
		w("def " + n.Name)
		params(n.Params)
		if n.Returns != nil {
			w(" -> ")
			dump(b, n.Returns)
		}
		w(" ")
		stmts(n.Body)
	case *ClassDef:
		for _, d := range n.Decorators {
			w("@")
			dump(b, d)
			w(" ")
		}
		w("class " + n.Name + "(")
		for i, a := range n.Bases {
			if i > 0 {
				w(" ")
			}
			if a.Name != "" {
				w(a.Name + "=")
			}
			dump(b, a.Value)
		}
		w(") ")
		stmts(n.Body)
	case *Return:
		w("return ")
		opt(n.X)
	case *Delete:
		list("del ", "", n.Targets)
	case *Pass:
		w("pass")
	case *Break:
		w("break")
	case *Continue:
		w("continue")
	case *If:
		w("if ")
		dump(b, n.Test)
		w(" ")
		stmts(n.Body)
		if n.Else != nil {
			w(" else ")
			stmts(n.Else)
		}
	case *For:
		if n.Async {
			w("async ")
		}
		w("for ")
		dump(b, n.Target)
		w(" in ")
		dump(b, n.Iter)
		w(" ")
		stmts(n.Body)
		if n.Else != nil {
			w(" else ")
			stmts(n.Else)
		}
	case *While:
		w("while ")
		dump(b, n.Test)
		w(" ")
		stmts(n.Body)
		if n.Else != nil {
			w(" else ")
			stmts(n.Else)
		}
	case *With:
		if n.Async {
			w("async ")
		}
		w("with ")
		for i, it := range n.Items {
			if i > 0 {
				w(", ")
			}
			dump(b, it.Ctx)
			if it.Target != nil {
				w(" as ")
				dump(b, it.Target)
			}
		}
		w(" ")
		stmts(n.Body)
	case *Raise:
		w("raise ")
		opt(n.Exc)
		if n.Cause != nil {
			w(" from ")
			dump(b, n.Cause)
		}
	case *Try:
		w("try ")
		stmts(n.Body)
		for _, h := range n.Handlers {
			w(" except")
			if h.Star {
				w("*")
			}
			w(" ")
			opt(h.Type)
			if h.Name != "" {
				w(" as " + h.Name)
			}
			w(" ")
			stmts(h.Body)
		}
		if n.Else != nil {
			w(" else ")
			stmts(n.Else)
		}
		if n.Finally != nil {
			w(" finally ")
			stmts(n.Finally)
		}
	case *Assert:
		w("assert ")
		dump(b, n.Test)
		if n.Msg != nil {
			w(", ")
			dump(b, n.Msg)
		}
	case *Import:
		w("import")
		for _, a := range n.Names {
			w(" " + a.Name)
			if a.AsName != "" {
				w(" as " + a.AsName)
			}
		}
	case *ImportFrom:
		w("from " + strings.Repeat(".", n.Level) + n.Module + " import")
		for _, a := range n.Names {
			w(" " + a.Name)
			if a.AsName != "" {
				w(" as " + a.AsName)
			}
		}
	case *Global:
		w("global " + strings.Join(n.Names, " "))
	case *Nonlocal:
		w("nonlocal " + strings.Join(n.Names, " "))
	case *Match:
		w("match ")
		dump(b, n.Subject)
		for _, c := range n.Cases {
			w(" case ")
			dump(b, c.Pattern)
			if c.Guard != nil {
				w(" if ")
				dump(b, c.Guard)
			}
			w(" ")
			stmts(c.Body)
		}
	case *TypeAlias:
		w("type " + n.Name.Id + " = ")
		dump(b, n.Value)
	case *BadStmt:
		w("BAD")
	}
}
