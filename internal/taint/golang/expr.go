package golang

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// fieldTypes give the class of a field of a library type read in a chain
// such as r.URL.Query().Get("x"); the specification then names the method.
var fieldTypes = map[string]string{
	"net.http.Request.URL":      "net.url.URL",
	"net.http.Request.Header":   "net.http.Header",
	"net.http.Request.Form":     "net.url.Values",
	"net.http.Request.PostForm": "net.url.Values",
	"net.http.Request.Body":     "net.http.RequestBody",
}

// sourceFields are fields of library types that hold client input. They
// are lowered as a call named field_<Name> on the value, which the
// specification lists as a source.
var sourceFields = map[string]bool{
	"net.url.URL.Path":               true,
	"net.url.URL.RawPath":            true,
	"net.url.URL.RawQuery":           true,
	"net.url.URL.Fragment":           true,
	"net.http.Request.RequestURI":    true,
	"net.http.Request.Host":          true,
	"net.http.Request.Form":          true,
	"net.http.Request.PostForm":      true,
	"net.http.Request.Body":          true,
	"net.http.Request.Referer":       true,
	"net.http.Request.UserAgent":     true,
	"net.http.Request.MultipartForm": true,
}

var builtinTypes = map[string]bool{
	"string": true, "int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"float32": true, "float64": true, "bool": true, "byte": true, "rune": true, "any": true,
}

func (l *lowerer) callPos(e *ast.CallExpr) ir.Pos {
	p := l.pos(e)
	if end := l.fset.Position(e.End()).Line; end > p.Line {
		p.End = end
	}
	return p
}

// typeOf is the static class of a value, when the lowering knows it.
func (l *lowerer) typeOf(e ast.Expr, op ir.Operand) string {
	if id, ok := e.(*ast.Ident); ok {
		for s := l.sc; s != nil; s = s.parent {
			if s.locals[id.Name] {
				return s.types[id.Name]
			}
		}
	}
	if op.Var != "" {
		return l.types[op.Var]
	}
	return ""
}

func (l *lowerer) importAlias(e ast.Expr) (string, bool) {
	id, ok := e.(*ast.Ident)
	if !ok || l.isLocal(id.Name) || l.own[id.Name] {
		return "", false
	}
	n, ok := l.imports[id.Name]
	return n, ok
}

// pkgMember lowers pkg.Name: a name of a package of the project, or of a
// library.
func (l *lowerer) pkgMember(alias *ast.Ident, sel string, pos ir.Pos) ir.Operand {
	if p, ok := l.project[alias.Name]; ok {
		if names, ok := l.env.Package(p); ok {
			if mod, ok := names[sel]; ok {
				return l.val(ir.Import, pos, mod+"."+sel, ir.Operand{}, ir.Operand{})
			}
		}
	}
	return l.val(ir.Load, pos, sel, l.val(ir.Import, pos, l.imports[alias.Name], ir.Operand{}, ir.Operand{}), ir.Operand{})
}

func (l *lowerer) ident(e *ast.Ident) ir.Operand {
	pos := l.pos(e)
	switch e.Name {
	case "nil":
		return ir.C(ir.None, "None")
	case "true":
		return ir.C(ir.Bool, "true")
	case "false":
		return ir.C(ir.Bool, "false")
	case "_":
		return ir.Operand{}
	}
	if l.sc != nil {
		if l.sc.locals[e.Name] {
			return ir.V("$" + e.Name)
		}
		for s := l.sc.parent; s != nil; s = s.parent {
			if s.locals[e.Name] {
				t := l.val(ir.Free, pos, "$"+e.Name, ir.Operand{}, ir.Operand{})
				if ty := s.types[e.Name]; ty != "" {
					l.types[t.Var] = ty
				}
				return t
			}
		}
	}
	if n, ok := l.imports[e.Name]; ok && !l.own[e.Name] {
		return l.val(ir.Import, pos, n, ir.Operand{}, ir.Operand{})
	}
	return l.val(ir.Free, pos, e.Name, ir.Operand{}, ir.Operand{})
}

func (l *lowerer) expr(e ast.Expr) ir.Operand {
	if e == nil {
		return ir.Operand{}
	}
	pos := l.pos(e)
	switch e := e.(type) {
	case *ast.Ident:
		return l.ident(e)
	case *ast.BasicLit:
		switch e.Kind {
		case token.STRING:
			s, err := strconv.Unquote(e.Value)
			if err != nil {
				s = strings.Trim(e.Value, "`\"")
			}
			return ir.C(ir.Str, s)
		case token.INT:
			return ir.C(ir.Int, e.Value)
		case token.FLOAT:
			return ir.C(ir.Float, e.Value)
		case token.CHAR:
			if s, err := strconv.Unquote(e.Value); err == nil {
				return ir.C(ir.Str, s)
			}
		}
		return ir.C(ir.Other, e.Value)
	case *ast.ParenExpr:
		return l.expr(e.X)
	case *ast.StarExpr:
		return l.expr(e.X)
	case *ast.UnaryExpr:
		x := l.expr(e.X)
		switch e.Op {
		case token.AND, token.ARROW:
			return x
		case token.NOT:
			return l.val(ir.Unary, pos, "not", x, ir.Operand{})
		}
		return l.val(ir.Unary, pos, e.Op.String(), x, ir.Operand{})
	case *ast.BinaryExpr:
		a, b := l.expr(e.X), l.expr(e.Y)
		op := e.Op.String()
		switch e.Op {
		case token.LAND:
			op = "and"
		case token.LOR:
			op = "or"
		}
		return l.val(ir.Bin, pos, op, a, b)
	case *ast.SelectorExpr:
		return l.selector(e)
	case *ast.IndexExpr:
		return l.val(ir.Index, pos, "", l.expr(e.X), l.expr(e.Index))
	case *ast.IndexListExpr:
		return l.expr(e.X)
	case *ast.SliceExpr:
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Index, Pos: pos, Dst: t, Name: "slice", A: l.expr(e.X), B: l.expr(e.Low), C: l.expr(e.High)})
		return ir.V(t)
	case *ast.TypeAssertExpr:
		x := l.expr(e.X)
		if e.Type == nil {
			return x
		}
		return l.cast(pos, x, l.typeName(e.Type))
	case *ast.CompositeLit:
		return l.composite(e)
	case *ast.FuncLit:
		params := l.params(e.Type, nil)
		fn := l.function("<lambda>", pos, params, "", l.sc, func() { l.block(e.Body) })
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Func, Pos: pos, Dst: t, Fn: fn})
		return ir.V(t)
	case *ast.CallExpr:
		return l.callExpr(e)
	case *ast.KeyValueExpr:
		return l.expr(e.Value)
	}
	return ir.Operand{}
}

func (l *lowerer) selector(e *ast.SelectorExpr) ir.Operand {
	pos := l.pos(e)
	if id, ok := e.X.(*ast.Ident); ok {
		if _, isPkg := l.importAlias(id); isPkg {
			return l.pkgMember(id, e.Sel.Name, pos)
		}
	}
	x := l.expr(e.X)
	typ := l.typeOf(e.X, x)
	key := typ + "." + e.Sel.Name
	if typ != "" && sourceFields[key] {
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Call, Pos: pos, Dst: t, A: x, Name: "field_" + e.Sel.Name})
		r := ir.V(t)
		return l.cast(pos, r, fieldTypes[key])
	}
	r := l.val(ir.Load, pos, e.Sel.Name, x, ir.Operand{})
	return l.cast(pos, r, fieldTypes[key])
}

func (l *lowerer) composite(e *ast.CompositeLit) ir.Operand {
	pos := l.pos(e)
	t := l.temp()
	in := &ir.Instr{Op: ir.Build, Pos: pos, Dst: t, Name: "list"}
	keyed := false
	for _, el := range e.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			keyed = true
			var k ir.Operand
			if id, ok := kv.Key.(*ast.Ident); ok && !l.isLocal(id.Name) && !l.own[id.Name] {
				k = ir.C(ir.Str, id.Name) // a struct field
			} else {
				k = l.expr(kv.Key)
			}
			in.Args = append(in.Args, l.expr(kv.Value))
			in.Keys2 = append(in.Keys2, k)
			continue
		}
		in.Args = append(in.Args, l.expr(el))
		in.Keys2 = append(in.Keys2, ir.C(ir.Int, strconv.Itoa(len(in.Args)-1)))
	}
	if keyed {
		in.Name = "dict"
	} else {
		in.Keys2 = nil
	}
	l.emit(in)
	r := ir.V(t)
	if e.Type != nil {
		if tn := l.typeName(e.Type); tn != "" && !builtinTypes[tn] {
			r = l.cast(pos, r, tn)
		}
	}
	return r
}

func (l *lowerer) args(e *ast.CallExpr) ([]ir.Operand, []string) {
	var args []ir.Operand
	var keys []string
	for _, a := range e.Args {
		args = append(args, l.expr(a))
		keys = append(keys, "")
	}
	if e.Ellipsis != token.NoPos && len(keys) > 0 {
		keys[len(keys)-1] = "*"
	}
	return args, keys
}

func (l *lowerer) callExpr(e *ast.CallExpr) ir.Operand {
	pos := l.callPos(e)
	fun := e.Fun
	for {
		p, ok := fun.(*ast.ParenExpr)
		if !ok {
			break
		}
		fun = p.X
	}
	switch f := fun.(type) {
	case *ast.ArrayType, *ast.MapType, *ast.InterfaceType, *ast.ChanType:
		// []byte(x) and the like: a conversion keeps the value
		args, _ := l.args(e)
		if len(args) == 1 {
			return args[0]
		}
		return ir.Operand{}
	case *ast.Ident:
		if !l.isLocal(f.Name) && !l.own[f.Name] {
			if builtinTypes[f.Name] {
				args, _ := l.args(e)
				if len(args) == 1 {
					return args[0]
				}
				return ir.Operand{}
			}
			switch f.Name {
			case "append":
				args, _ := l.args(e)
				t := l.temp()
				l.emit(&ir.Instr{Op: ir.Build, Pos: pos, Dst: t, Name: "list", Args: args})
				return ir.V(t)
			case "make", "new":
				return l.val(ir.Build, pos, "list", ir.Operand{}, ir.Operand{})
			}
		}
		callee := l.ident(f)
		args, keys := l.args(e)
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Call, Pos: pos, Dst: t, A: callee, Args: args, Keys: keys})
		return ir.V(t)
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			if _, isPkg := l.importAlias(id); isPkg {
				recv := l.val(ir.Import, pos, l.imports[id.Name], ir.Operand{}, ir.Operand{})
				if p, ok := l.project[id.Name]; ok {
					if names, ok := l.env.Package(p); ok {
						if mod, ok := names[f.Sel.Name]; ok {
							callee := l.val(ir.Import, pos, mod+"."+f.Sel.Name, ir.Operand{}, ir.Operand{})
							args, keys := l.args(e)
							t := l.temp()
							l.emit(&ir.Instr{Op: ir.Call, Pos: pos, Dst: t, A: callee, Args: args, Keys: keys})
							return ir.V(t)
						}
					}
				}
				args, keys := l.args(e)
				// fmt.Fprintf(w, ...) writes to w: it is a call on w, so the
				// specification can tell the response (net.http.ResponseWriter)
				// from a log file.
				if wr := l.writerCall(id.Name, f.Sel.Name); wr != "" && len(args) > 0 {
					t := l.temp()
					l.emit(&ir.Instr{Op: ir.Call, Pos: pos, Dst: t, A: args[0], Name: wr, Args: args[1:], Keys: keys[1:]})
					return ir.V(t)
				}
				t := l.temp()
				l.emit(&ir.Instr{Op: ir.Call, Pos: pos, Dst: t, A: recv, Name: f.Sel.Name, Args: args, Keys: keys})
				return ir.V(t)
			}
		}
		recv := l.expr(f.X)
		args, keys := l.args(e)
		t := l.temp()
		l.emit(&ir.Instr{Op: ir.Call, Pos: pos, Dst: t, A: recv, Name: f.Sel.Name, Args: args, Keys: keys})
		return ir.V(t)
	}
	callee := l.expr(fun)
	args, keys := l.args(e)
	t := l.temp()
	l.emit(&ir.Instr{Op: ir.Call, Pos: pos, Dst: t, A: callee, Args: args, Keys: keys})
	return ir.V(t)
}

// writerCall names a function of fmt or io that writes to its first
// argument.
func (l *lowerer) writerCall(alias, name string) string {
	switch l.imports[alias] + "." + name {
	case "fmt.Fprintf", "fmt.Fprint", "fmt.Fprintln", "io.WriteString":
		return l.imports[alias] + "." + name
	}
	return ""
}
