package js

import (
	"fmt"
	"strconv"
	"strings"
)

// Dump renders statements as compact S-expressions, for tests and
// debugging.
func Dump(stmts []Stmt) string {
	var parts []string
	for _, s := range stmts {
		parts = append(parts, dumpStmt(s))
	}
	return strings.Join(parts, " ")
}

// DumpExpr renders one expression.
func DumpExpr(x Expr) string { return dumpExpr(x) }

func dumpList(xs []Expr) string {
	var parts []string
	for _, x := range xs {
		parts = append(parts, dumpExpr(x))
	}
	return strings.Join(parts, " ")
}

func dumpStmts(ss []Stmt) string {
	return "{" + Dump(ss) + "}"
}

func dumpExpr(x Expr) string {
	switch x := x.(type) {
	case nil:
		return "_"
	case *Ident:
		return x.Name
	case *Lit:
		if x.Kind == TString {
			return strconv.Quote(x.Val)
		}
		return x.Val
	case *TemplateLit:
		var b strings.Builder
		b.WriteString("(tpl")
		if x.Tag != nil {
			b.WriteString(" tag=" + dumpExpr(x.Tag))
		}
		for i, q := range x.Quasis {
			b.WriteString(" " + strconv.Quote(q))
			if i < len(x.Exprs) {
				b.WriteString(" " + dumpExpr(x.Exprs[i]))
			}
		}
		return b.String() + ")"
	case *Member:
		op := "."
		if x.Optional {
			op = "?."
		}
		if x.Computed != nil {
			return "(" + op + "[] " + dumpExpr(x.Obj) + " " + dumpExpr(x.Computed) + ")"
		}
		return "(" + op + " " + dumpExpr(x.Obj) + " " + x.Prop + ")"
	case *Call:
		head := "call"
		switch {
		case x.New:
			head = "new"
		case x.Optional:
			head = "call?"
		}
		s := "(" + head + " " + dumpExpr(x.Callee)
		if len(x.Args) > 0 {
			s += " " + dumpList(x.Args)
		}
		return s + ")"
	case *Binary:
		return "(" + x.Op + " " + dumpExpr(x.L) + " " + dumpExpr(x.R) + ")"
	case *Unary:
		if x.Postfix {
			return "(post" + x.Op + " " + dumpExpr(x.X) + ")"
		}
		return "(" + x.Op + " " + dumpExpr(x.X) + ")"
	case *Assign:
		return "(" + x.Op + " " + dumpExpr(x.Target) + " " + dumpExpr(x.Value) + ")"
	case *Cond:
		return "(? " + dumpExpr(x.Test) + " " + dumpExpr(x.Then) + " " + dumpExpr(x.Else) + ")"
	case *Seq:
		return "(, " + dumpList(x.List) + ")"
	case *ArrayLit:
		return "[" + dumpList(x.Elems) + "]"
	case *ObjectLit:
		var parts []string
		for _, p := range x.Props {
			key := p.Key
			if p.Computed != nil {
				key = "[" + dumpExpr(p.Computed) + "]"
			}
			switch p.Kind {
			case "spread":
				parts = append(parts, "..."+dumpExpr(p.Value))
			case "shorthand":
				parts = append(parts, dumpExpr(p.Value))
			case "init":
				parts = append(parts, key+":"+dumpExpr(p.Value))
			default:
				parts = append(parts, p.Kind+" "+key+":"+dumpExpr(p.Value))
			}
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case *Spread:
		return "..." + dumpExpr(x.X)
	case *Yield:
		if x.Delegate {
			return "(yield* " + dumpExpr(x.X) + ")"
		}
		return "(yield " + dumpExpr(x.X) + ")"
	case *Func:
		var b strings.Builder
		switch {
		case x.Arrow:
			b.WriteString("(=>")
		default:
			b.WriteString("(fn")
		}
		if x.Async {
			b.WriteString(" async")
		}
		if x.Generator {
			b.WriteString(" *")
		}
		if x.Name != "" {
			b.WriteString(" " + x.Name)
		}
		b.WriteString(" (" + dumpList(x.Params) + ")")
		switch {
		case x.ExprBody != nil:
			b.WriteString(" " + dumpExpr(x.ExprBody))
		case x.Body == nil:
			b.WriteString(" nobody")
		default:
			b.WriteString(" " + dumpStmts(x.Body))
		}
		return b.String() + ")"
	case *Class:
		var b strings.Builder
		b.WriteString("(class")
		if x.Name != "" {
			b.WriteString(" " + x.Name)
		}
		if x.Super != nil {
			b.WriteString(" extends " + dumpExpr(x.Super))
		}
		for _, m := range x.Members {
			b.WriteString(" " + dumpMember(m))
		}
		return b.String() + ")"
	case *JSXElement:
		var b strings.Builder
		b.WriteString("<" + x.Tag)
		for _, a := range x.Attrs {
			switch {
			case a.Spread:
				b.WriteString(" {..." + dumpExpr(a.Value) + "}")
			case a.Value == nil:
				b.WriteString(" " + a.Name)
			default:
				b.WriteString(" " + a.Name + "=" + dumpExpr(a.Value))
			}
		}
		b.WriteString(">")
		for _, c := range x.Children {
			b.WriteString(dumpExpr(c))
		}
		return b.String() + "</>"
	case *JSXText:
		return strings.TrimSpace(x.Text)
	case *Bad:
		return "BAD"
	}
	return fmt.Sprintf("?%T", x)
}

func dumpMember(m *ClassMember) string {
	s := m.Kind
	if m.Static {
		s = "static " + s
	}
	key := m.Key
	if m.Computed != nil {
		key = "[" + dumpExpr(m.Computed) + "]"
	}
	switch m.Kind {
	case "block":
		return "(" + s + " " + dumpStmts(m.Block) + ")"
	case "field":
		return "(" + s + " " + key + " " + dumpExpr(m.Value) + ")"
	}
	out := "(" + s + " " + key + " " + dumpExpr(m.Value)
	if len(m.ParamProps) > 0 {
		out += " props=" + strings.Join(m.ParamProps, ",")
	}
	return out + ")"
}

func dumpStmt(s Stmt) string {
	switch s := s.(type) {
	case nil:
		return "_"
	case *ExprStmt:
		return dumpExpr(s.X) + ";"
	case *VarDecl:
		var parts []string
		for _, d := range s.Decls {
			if d.Init != nil {
				parts = append(parts, dumpExpr(d.Target)+"="+dumpExpr(d.Init))
			} else {
				parts = append(parts, dumpExpr(d.Target))
			}
		}
		return "(" + s.Kind + " " + strings.Join(parts, " ") + ")"
	case *Return:
		if s.X == nil {
			return "(return)"
		}
		return "(return " + dumpExpr(s.X) + ")"
	case *If:
		out := "(if " + dumpExpr(s.Test) + " " + dumpStmt(s.Then)
		if s.Else != nil {
			out += " else " + dumpStmt(s.Else)
		}
		return out + ")"
	case *For:
		return "(for " + dumpStmt(s.Init) + " " + dumpExpr(s.Test) + " " + dumpExpr(s.Update) + " " + dumpStmt(s.Body) + ")"
	case *ForIn:
		kw := "in"
		if s.Of {
			kw = "of"
		}
		return "(for " + dumpStmt(s.Left) + " " + kw + " " + dumpExpr(s.Right) + " " + dumpStmt(s.Body) + ")"
	case *While:
		if s.Do {
			return "(do " + dumpStmt(s.Body) + " " + dumpExpr(s.Test) + ")"
		}
		return "(while " + dumpExpr(s.Test) + " " + dumpStmt(s.Body) + ")"
	case *Block:
		return dumpStmts(s.List)
	case *Try:
		out := "(try " + dumpStmt(s.Block)
		if s.Handler != nil {
			out += " catch " + dumpExpr(s.Param) + " " + dumpStmt(s.Handler)
		}
		if s.Finally != nil {
			out += " finally " + dumpStmt(s.Finally)
		}
		return out + ")"
	case *Switch:
		out := "(switch " + dumpExpr(s.Disc)
		for _, c := range s.Cases {
			out += " (case " + dumpExpr(c.Test) + " " + Dump(c.Body) + ")"
		}
		return out + ")"
	case *Throw:
		return "(throw " + dumpExpr(s.X) + ")"
	case *Branch:
		if s.Label != "" {
			return "(" + s.Tok + " " + s.Label + ")"
		}
		return "(" + s.Tok + ")"
	case *Labeled:
		return "(label " + s.Label + " " + dumpStmt(s.Body) + ")"
	case *FuncDecl:
		return dumpExpr(s.Func)
	case *ClassDecl:
		return dumpExpr(s.Class)
	case *Import:
		var parts []string
		for _, sp := range s.Specs {
			parts = append(parts, sp.Imported+":"+sp.Local)
		}
		return "(import " + strconv.Quote(s.Source) + " " + strings.Join(parts, " ") + ")"
	case *Export:
		switch {
		case s.Decl != nil:
			return "(export " + dumpStmt(s.Decl) + ")"
		case s.Default != nil:
			return "(export default " + dumpExpr(s.Default) + ")"
		}
		var parts []string
		for _, sp := range s.Specs {
			parts = append(parts, sp.Local+":"+sp.Exported)
		}
		out := "(export"
		if s.All {
			out += " *"
		}
		if len(parts) > 0 {
			out += " " + strings.Join(parts, " ")
		}
		if s.From != "" {
			out += " from " + strconv.Quote(s.From)
		}
		return out + ")"
	case *Empty:
		return ";"
	case *BadStmt:
		return "BAD;"
	}
	return fmt.Sprintf("?%T", s)
}
