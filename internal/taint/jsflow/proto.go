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
	// span reports a finding from line from to line to, keyed by the
	// write at to.
	span := func(from, to int, what string) {
		key := sink.ID + "|" + itoa(to)
		if a.seen[key] {
			return
		}
		a.seen[key] = true
		if from > to {
			from, to = to, from
		}
		a.out = append(a.out, taint.Finding{Sink: sink, File: a.file, Line: from, EndLine: to, Library: true,
			Steps: []taint.Step{{Line: from, What: what}, {Line: to, What: sink.Title}}})
	}
	report := func(line int, what string) { span(line, line, what) }
	fixed := constStrings(f)
	a.mergeHelpers(f, report)
	a.writesAfterWalk(f, span)
	for _, st := range f.Stmts {
		js.Inspect(st, func(n js.Node) bool {
			switch n := n.(type) {
			case *js.ForIn:
				if fixed[exprText(n.Right)] {
					return false // for (p of ['a', 'b.c']): the keys are the code's own
				}
				a.pathWalk(n, span)
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
			case *js.For, *js.While:
				a.pathWalk(n, span)
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

// constStrings names the top-level constants that are arrays of string
// literals.
func constStrings(f *js.File) map[string]bool {
	out := map[string]bool{}
	for _, st := range f.Stmts {
		if ex, ok := st.(*js.Export); ok && ex.Decl != nil {
			st = ex.Decl
		}
		d, ok := st.(*js.VarDecl)
		if !ok || d.Kind != "const" {
			continue
		}
		for _, dc := range d.Decls {
			arr, ok := dc.Init.(*js.ArrayLit)
			if !ok || len(arr.Elems) == 0 {
				continue
			}
			all := true
			for _, e := range arr.Elems {
				l, isLit := e.(*js.Lit)
				all = all && isLit && l.Kind == js.TString
			}
			if all {
				out[patternName(dc.Target)] = true
			}
		}
	}
	return out
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
	of   string // the object whose keys are walked, when known
	body js.Node
}

// keysOf names the object of Object.keys(x), Object.entries(x) or x.
func keysOf(x js.Expr) string {
	if c, ok := x.(*js.Call); ok && len(c.Args) == 1 {
		switch exprText(c.Callee) {
		case "Object.keys", "Object.entries", "Object.getOwnPropertyNames", "Reflect.ownKeys":
			return exprText(c.Args[0])
		}
		return ""
	}
	return exprText(x)
}

func keyLoops(fn *js.Func) []keyLoop {
	var out []keyLoop
	arrays := keyArrays(fn)
	inspectBody(fn, func(n js.Node) bool {
		switch n := n.(type) {
		case *js.For:
			// const keys = Object.keys(src); for (i...) { const k = keys[i]; ... }
			if k, of := indexedKey(n.Body, arrays); k != "" {
				out = append(out, keyLoop{k, of, n.Body})
			}
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
				out = append(out, keyLoop{k, keysOf(n.Right), n.Body})
			}
		case *js.Call:
			if m, ok := n.Callee.(*js.Member); ok && m.Prop == "forEach" && len(n.Args) > 0 {
				if cb, ok := n.Args[0].(*js.Func); ok && len(cb.Params) > 0 {
					out = append(out, keyLoop{patternName(cb.Params[0]), keysOf(m.Obj), cb})
				}
			}
		}
		return true
	})
	return out
}

// keyArrays maps the variables of fn that hold the keys of an object
// (const keys = Object.keys(src)) to that object.
func keyArrays(fn *js.Func) map[string]string {
	out := map[string]string{}
	inspectBody(fn, func(n js.Node) bool {
		if d, ok := n.(*js.VarDecl); ok {
			for _, dc := range d.Decls {
				if c, ok := dc.Init.(*js.Call); ok {
					if of := keysOf(c); of != "" && of != exprText(c) {
						out[patternName(dc.Target)] = of
					}
				}
			}
		}
		return true
	})
	return out
}

// indexedKey finds const k = keys[i] at the top of a loop body, where keys
// holds the keys of an object.
func indexedKey(body js.Stmt, arrays map[string]string) (key, of string) {
	b, ok := body.(*js.Block)
	if !ok {
		return "", ""
	}
	for _, st := range b.List {
		d, ok := st.(*js.VarDecl)
		if !ok {
			continue
		}
		for _, dc := range d.Decls {
			m, ok := dc.Init.(*js.Member)
			if !ok || m.Computed == nil {
				continue
			}
			if _, isIdx := m.Computed.(*js.Ident); !isIdx {
				continue
			}
			if obj, ok := arrays[exprText(m.Obj)]; ok {
				return patternName(dc.Target), obj
			}
		}
	}
	return "", ""
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
			// for (k of Object.keys(a)) a[k] = f(a[k]) rewrites keys a
			// already owns: a key __proto__ there only reaches a's own
			// prototype slot.
			if target == "" || target == l.of || freshObject(fn, target) || !readsKey(fn, target, l.key, as) || keyChecked(fn, target, l.key) {
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

// givenKey reports a call given a plain name or string, such as a key,
// rather than only members or other values.
func givenKey(c *js.Call) bool {
	for _, x := range c.Args {
		switch x.(type) {
		case *js.Ident, *js.Lit, *js.TemplateLit:
			return true
		}
	}
	return len(c.Args) == 0
}

// pathWalk finds o = o[k] in a loop with a write o[key] = v and no key check.
func (a *analyzer) pathWalk(loop js.Node, report func(from, to int, what string)) {
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
	descends := map[string]int{} // variable -> line of o = o[k]
	js.Inspect(body, func(n js.Node) bool {
		if _, isFn := n.(*js.Func); isFn {
			return false
		}
		if as, ok := n.(*js.Assign); ok && as.Op == "=" {
			o := exprText(as.Target)
			if o != "" && !strings.Contains(o, ".") && descendsInto(as.Value, o) {
				descends[o] = as.Line
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
		if !ok || m.Computed == nil {
			return true
		}
		from, walks := descends[exprText(m.Obj)]
		if !walks {
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
		report(from, as.Line, "walk along a key path writes "+exprText(m.Obj)+"["+exprText(m.Computed)+"]")
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
					// isSafeKey(k), isPrototypePolluted(k), ...; not
					// isObject(o[k]), which checks the value.
					found = found || (isValidatorName(callee) || isSanitizerName(callee)) && givenKey(t)
				}
			}
			return !found
		})
		return true
	})
	return found
}

// mergeHelpers finds a merge split over two functions of the file: one
// walks the keys of its input and hands each to a helper (mixin(target,
// val, key), or forIn(obj, copy, target)); the helper reads target[key],
// descends by calling the first function again and otherwise writes
// target[key] = val. Either function may check the key; checking only
// __proto__ still lets constructor.prototype through.
func (a *analyzer) mergeHelpers(f *js.File, report func(int, string)) {
	fns := map[string]*js.Func{}
	var order []string // file order, so findings come out the same each run
	add := func(name string, fn *js.Func) {
		if name != "" && fns[name] == nil {
			fns[name] = fn
			order = append(order, name)
		}
	}
	for _, st := range f.Stmts {
		if ex, ok := st.(*js.Export); ok && ex.Decl != nil {
			st = ex.Decl
		}
		switch st := st.(type) {
		case *js.FuncDecl:
			add(st.Func.Name, st.Func)
		case *js.VarDecl:
			for _, d := range st.Decls {
				if fn, ok := d.Init.(*js.Func); ok {
					add(patternName(d.Target), fn)
				}
			}
		case *js.ExprStmt:
			if as, ok := st.X.(*js.Assign); ok {
				if fn, ok := innerFunc(as.Value); ok {
					add(shortName(exprText(as.Target)), fn)
				}
			}
		}
	}
	for _, hName := range order {
		h := fns[hName]
		params := map[string]bool{"this": true}
		for _, p := range h.Params {
			params[patternName(p)] = true
		}
		for _, mName := range order {
			m := fns[mName]
			if mName == hName || !calls(h, mName) || !handsOver(m, hName) {
				continue
			}
			inspectBody(h, func(n js.Node) bool {
				as, ok := n.(*js.Assign)
				if !ok || as.Op != "=" {
					return true
				}
				t, ok := as.Target.(*js.Member)
				if !ok || t.Computed == nil {
					return true
				}
				key, target := exprText(t.Computed), exprText(t.Obj)
				if _, isIdent := t.Computed.(*js.Ident); !isIdent || !params[key] || key == "this" || !params[target] {
					return true
				}
				if !readsKey(h, target, key, as) || fullyChecked(h, m) {
					return true
				}
				report(as.Line, "merge through "+hName+"() writes "+target+"["+key+"]")
				return true
			})
		}
	}
}

// handsOver reports a function that walks keys and calls name, or passes
// name to an iterator such as forIn(obj, name, target).
func handsOver(m *js.Func, name string) bool {
	passed := false
	inspectBody(m, func(n js.Node) bool {
		if c, ok := n.(*js.Call); ok {
			for _, x := range c.Args {
				if id, ok := x.(*js.Ident); ok && id.Name == name {
					passed = true
				}
			}
		}
		return !passed
	})
	return passed || calls(m, name) && len(keyLoops(m)) > 0
}

// fullyChecked reports key checks in fns that cover both ways into
// Object.prototype (__proto__, and constructor or prototype), an own
// property check, or a key validator.
func fullyChecked(fns ...*js.Func) bool {
	names := map[string]bool{}
	own := false
	for _, fn := range fns {
		inspectBody(fn, func(n js.Node) bool {
			switch n := n.(type) {
			case *js.Lit:
				if n.Kind == js.TString && (n.Val == "__proto__" || n.Val == "constructor" || n.Val == "prototype") {
					names[n.Val] = true
				}
				if n.Kind == js.TRegex && strings.Contains(n.Val, "__proto__") && (strings.Contains(n.Val, "constructor") || strings.Contains(n.Val, "prototype")) {
					own = true
				}
			case *js.Call:
				callee := exprText(n.Callee)
				if strings.HasSuffix(callee, "hasOwnProperty") || strings.HasSuffix(callee, "hasOwnProperty.call") || callee == "Object.hasOwn" {
					own = true
				}
				if (isValidatorName(shortName(callee)) || isSanitizerName(shortName(callee))) && givenKey(n) && strings.Contains(strings.ToLower(callee), "key") {
					own = true
				}
			}
			return true
		})
	}
	return own || names["__proto__"] && (names["constructor"] || names["prototype"])
}

// writesAfterWalk finds a loop that only descends (o = o[k]) followed in
// the same block by a write o[key] = v: the walk ends wherever the path
// led, Object.prototype for a path through __proto__. The finding spans
// the descent and the write.
func (a *analyzer) writesAfterWalk(f *js.File, report func(from, to int, what string)) {
	check := func(list []js.Stmt) {
		for i, st := range list {
			var body js.Node
			switch l := st.(type) {
			case *js.For:
				body = l.Body
			case *js.While:
				body = l.Body
			case *js.ForIn:
				body = l.Body
			}
			if body == nil {
				continue
			}
			descends := map[string]int{}
			js.Inspect(body, func(n js.Node) bool {
				if _, isFn := n.(*js.Func); isFn {
					return false
				}
				if as, ok := n.(*js.Assign); ok && as.Op == "=" {
					o := exprText(as.Target)
					if o != "" && !strings.Contains(o, ".") && descendsInto(as.Value, o) {
						descends[o] = as.Line
					}
				}
				return true
			})
			if len(descends) == 0 || loopChecksKey(body) || writesInto(body, descends) {
				continue // pathWalk reports a loop that writes as it walks
			}
			for _, next := range list[i+1:] {
				es, ok := next.(*js.ExprStmt)
				if !ok {
					continue
				}
				as, ok := es.X.(*js.Assign)
				if !ok || as.Op != "=" {
					continue
				}
				m, ok := as.Target.(*js.Member)
				if !ok || m.Computed == nil {
					continue
				}
				o := exprText(m.Obj)
				from, ok := descends[o]
				if !ok {
					continue
				}
				if lit, isLit := m.Computed.(*js.Lit); isLit && lit.Kind == js.TString {
					continue // o['fixed'] = v
				}
				report(from, as.Line, "walk along a key path descends into "+o+", then writes "+exprText(m))
			}
		}
	}
	check(f.Stmts)
	for _, st := range f.Stmts {
		js.Inspect(st, func(n js.Node) bool {
			switch n := n.(type) {
			case *js.Func:
				check(n.Body)
			case *js.Block:
				check(n.List)
			}
			return true
		})
	}
}

// writesInto reports a write o[k] = v in body to a variable of descends.
func writesInto(body js.Node, descends map[string]int) bool {
	found := false
	js.Inspect(body, func(n js.Node) bool {
		if as, ok := n.(*js.Assign); ok {
			if m, ok := as.Target.(*js.Member); ok && m.Computed != nil {
				_, found = descends[exprText(m.Obj)]
			}
		}
		return !found
	})
	return found
}
