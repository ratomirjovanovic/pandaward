package jsflow

import (
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

// Prototype pollution is found by shape rather than by a flow from a
// source: the keys come from whatever object a caller passes.
//
//   - A recursive merge: a function that calls itself, loops over the keys
//     of its input and writes target[key], also reading target[key] (so a
//     key __proto__ leads the merge into Object.prototype).
//   - A path walk: a loop that descends with o = o[k] and writes o[key].
//
// Either is safe when it checks the key against __proto__ or constructor,
// or checks that the target owns the key.

func (a *analyzer) protoPollution(f *js.File) {
	var sink *taint.Sink
	for _, k := range a.spec.Sinks {
		if k.Kind == taint.Proto {
			sink = k
		}
	}
	if sink == nil {
		return
	}
	report := func(line int, what string) {
		key := sink.ID + "|" + itoa(line)
		if a.seen[key] {
			return
		}
		a.seen[key] = true
		a.out = append(a.out, taint.Finding{Sink: sink, File: a.file, Line: line, EndLine: line, Library: true,
			Steps: []taint.Step{{Line: line, What: what}, {Line: line, What: sink.Title}}})
	}
	for _, st := range f.Stmts {
		js.Inspect(st, func(n js.Node) bool {
			switch n := n.(type) {
			case *js.FuncDecl:
				a.recursiveMerge(n.Func, n.Func.Name, report)
			case *js.VarDecl:
				for _, d := range n.Decls {
					if fn, ok := d.Init.(*js.Func); ok {
						a.recursiveMerge(fn, patternName(d.Target), report)
					}
				}
			case *js.Assign:
				if fn, ok := innerFunc(n.Value); ok {
					name := exprText(n.Target)
					a.recursiveMerge(fn, shortName(name), report)
				}
			case *js.For, *js.While, *js.ForIn:
				a.pathWalk(n, report)
			}
			return true
		})
		// Object literal methods and class members are not statements;
		// reach them through their containers.
		js.Inspect(st, func(n js.Node) bool {
			switch n := n.(type) {
			case *js.ObjectLit:
				for _, p := range n.Props {
					if fn, ok := p.Value.(*js.Func); ok {
						a.recursiveMerge(fn, p.Key, report)
					}
				}
			case *js.Class:
				for _, m := range n.Members {
					if fn, ok := m.Value.(*js.Func); ok {
						a.recursiveMerge(fn, m.Key, report)
					}
				}
			}
			return true
		})
	}
}

// innerFunc unwraps a = b = function () {}.
func innerFunc(x js.Expr) (*js.Func, bool) {
	for {
		switch v := x.(type) {
		case *js.Func:
			return v, true
		case *js.Assign:
			x = v.Value
		default:
			return nil, false
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// calls reports whether body calls a function named name (f(), this.f(),
// exports.f(), obj.f()).
func calls(fn *js.Func, name string) bool {
	if name == "" {
		return false
	}
	found := false
	inspectBody(fn, func(n js.Node) bool {
		if c, ok := n.(*js.Call); ok {
			switch cal := c.Callee.(type) {
			case *js.Ident:
				found = found || cal.Name == name
			case *js.Member:
				found = found || cal.Computed == nil && cal.Prop == name
			}
		}
		return !found
	})
	return found
}

func inspectBody(fn *js.Func, f func(js.Node) bool) {
	for _, s := range fn.Body {
		js.Inspect(s, f)
	}
	if fn.ExprBody != nil {
		js.Inspect(fn.ExprBody, f)
	}
}

// keyLoops returns the loops over keys or entries in fn with their key
// variable: for (k in src), for (k of keys), keys.forEach(k => ...).
type keyLoop struct {
	key  string
	body js.Node
}

func keyLoops(fn *js.Func) []keyLoop {
	var out []keyLoop
	inspectBody(fn, func(n js.Node) bool {
		switch n := n.(type) {
		case *js.ForIn:
			var k string
			switch l := n.Left.(type) {
			case *js.VarDecl:
				if len(l.Decls) > 0 {
					k = patternName(l.Decls[0].Target)
				}
			case *js.ExprStmt:
				k = exprText(l.X)
			}
			if k != "" {
				out = append(out, keyLoop{k, n.Body})
			}
		case *js.Call:
			if m, ok := n.Callee.(*js.Member); ok && m.Prop == "forEach" && len(n.Args) > 0 {
				if cb, ok := n.Args[0].(*js.Func); ok && len(cb.Params) > 0 {
					out = append(out, keyLoop{patternName(cb.Params[0]), cb})
				}
			}
		}
		return true
	})
	return out
}

func (a *analyzer) recursiveMerge(fn *js.Func, name string, report func(int, string)) {
	if fn == nil || !calls(fn, name) {
		return
	}
	for _, l := range keyLoops(fn) {
		js.Inspect(l.body, func(n js.Node) bool {
			as, ok := n.(*js.Assign)
			if !ok || as.Op != "=" {
				return true
			}
			m, ok := as.Target.(*js.Member)
			if !ok || m.Computed == nil || exprText(m.Computed) != l.key {
				return true
			}
			target := exprText(m.Obj)
			if target == "" || freshObject(fn, target) || !readsKey(fn, target, l.key, as) || keyChecked(fn, target, l.key) {
				return true
			}
			report(as.Line, "recursive merge writes "+target+"["+l.key+"]")
			return true
		})
	}
}

// freshObject reports a target the function creates itself (const out =
// {...base}, Object.assign({}, x)): a key __proto__ then only changes the
// prototype of that new object, not Object.prototype.
func freshObject(fn *js.Func, target string) bool {
	for _, p := range fn.Params {
		if patternName(p) == target {
			return false
		}
	}
	isNew := func(x js.Expr) bool {
		switch v := x.(type) {
		case *js.ObjectLit:
			return true
		case *js.Call:
			n := exprText(v.Callee)
			return n == "Object.assign" && len(v.Args) > 0 && isEmptyObject(v.Args[0]) || n == "structuredClone" || n == "Object.create"
		}
		return false
	}
	created, other := false, false
	inspectBody(fn, func(n js.Node) bool {
		switch n := n.(type) {
		case *js.VarDecl:
			for _, d := range n.Decls {
				if patternName(d.Target) == target && d.Init != nil {
					if isNew(d.Init) {
						created = true
					} else {
						other = true
					}
				}
			}
		case *js.Assign:
			if exprText(n.Target) == target {
				if n.Op == "=" && isNew(n.Value) {
					created = true
				} else {
					other = true
				}
			}
		}
		return true
	})
	return created && !other
}

func isEmptyObject(x js.Expr) bool {
	o, ok := x.(*js.ObjectLit)
	return ok && len(o.Props) == 0
}

// readsKey reports a read of target[key] other than the write itself: the
// merge descends into the existing value.
func readsKey(fn *js.Func, target, key string, write *js.Assign) bool {
	found := false
	inspectBody(fn, func(n js.Node) bool {
		if found {
			return false
		}
		if as, ok := n.(*js.Assign); ok && as == write {
			// The written member itself is not a read; its value may be.
			js.Inspect(as.Value, func(m js.Node) bool {
				found = found || isKeyRead(m, target, key)
				return !found
			})
			return false
		}
		found = isKeyRead(n, target, key)
		return !found
	})
	return found
}

func isKeyRead(n js.Node, target, key string) bool {
	m, ok := n.(*js.Member)
	return ok && m.Computed != nil && exprText(m.Computed) == key && exprText(m.Obj) == target
}

// keyChecked reports a check of the key against the dangerous names or of
// the target owning it.
func keyChecked(fn *js.Func, target, key string) bool {
	found := false
	inspectBody(fn, func(n js.Node) bool {
		switch n := n.(type) {
		case *js.Lit:
			if n.Kind == js.TString && (n.Val == "__proto__" || n.Val == "constructor" || n.Val == "prototype") {
				found = true
			}
		case *js.Call:
			callee := exprText(n.Callee)
			own := strings.HasSuffix(callee, "hasOwnProperty") || callee == "Object.hasOwn" || strings.HasSuffix(callee, "hasOwnProperty.call")
			if own {
				args := ""
				for _, x := range n.Args {
					args += " " + exprText(x)
				}
				recv := ""
				if m, ok := n.Callee.(*js.Member); ok {
					recv = exprText(m.Obj)
				}
				if strings.Contains(args, " "+target) || recv == target {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// pathWalk finds o = o[k] in a loop with a write o[key] = v and no key check.
func (a *analyzer) pathWalk(loop js.Node, report func(int, string)) {
	var body js.Node
	switch l := loop.(type) {
	case *js.For:
		body = l.Body
	case *js.While:
		body = l.Body
	case *js.ForIn:
		body = l.Body
	}
	if body == nil {
		return
	}
	descends := map[string]bool{}
	js.Inspect(body, func(n js.Node) bool {
		if _, isFn := n.(*js.Func); isFn {
			return false
		}
		if as, ok := n.(*js.Assign); ok && as.Op == "=" {
			o := exprText(as.Target)
			if o != "" && !strings.Contains(o, ".") && descendsInto(as.Value, o) {
				descends[o] = true
			}
		}
		return true
	})
	if len(descends) == 0 || loopChecksKey(body) {
		return
	}
	js.Inspect(body, func(n js.Node) bool {
		if _, isFn := n.(*js.Func); isFn {
			return false
		}
		as, ok := n.(*js.Assign)
		if !ok {
			return true
		}
		m, ok := as.Target.(*js.Member)
		if !ok || m.Computed == nil || !descends[exprText(m.Obj)] {
			return true
		}
		if _, isIdent := m.Computed.(*js.Ident); !isIdent {
			return true
		}
		if o, isObj := as.Value.(*js.ObjectLit); isObj && len(o.Props) > 0 {
			// o[k] = { ...o[k] } copies on write: the walk continues into
			// the copy, never into Object.prototype.
			return true
		}
		report(as.Line, "walk along a key path writes "+exprText(m.Obj)+"["+exprText(m.Computed)+"]")
		return true
	})
}

// descendsInto reports o[k] or o[k] || d.
func descendsInto(x js.Expr, o string) bool {
	switch v := x.(type) {
	case *js.Member:
		return v.Computed != nil && exprText(v.Obj) == o
	case *js.Binary:
		return (v.Op == "||" || v.Op == "??") && descendsInto(v.L, o)
	}
	return false
}

// loopChecksKey reports a key check in an if of the loop body.
func loopChecksKey(body js.Node) bool {
	found := false
	js.Inspect(body, func(n js.Node) bool {
		if found {
			return false
		}
		iff, ok := n.(*js.If)
		if !ok {
			return true
		}
		js.Inspect(iff.Test, func(t js.Node) bool {
			switch t := t.(type) {
			case *js.Lit:
				found = found || t.Kind == js.TString && (t.Val == "__proto__" || t.Val == "constructor" || t.Val == "prototype")
			case *js.Call:
				callee := exprText(t.Callee)
				if m, ok := t.Callee.(*js.Member); ok {
					callee = m.Prop
				}
				switch callee {
				case "test", "includes", "indexOf", "hasOwnProperty", "hasOwn", "has":
					found = true
				default:
					// isSafeKey(k), isPrototypePolluted(k), ...
					found = found || isValidatorName(callee) || isSanitizerName(callee)
				}
			}
			return !found
		})
		return true
	})
	return found
}
