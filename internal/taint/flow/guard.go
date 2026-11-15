package flow

import (
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// Flags that a check left on a value, kept as fields so that joins keep
// them only where every path checked.
const (
	flagStarts = "?starts:"
	flagEnds   = "?ends:"
	flagInner  = "?inner:"
)

// refine returns the state on one edge of a branch: a guard that holds on
// that edge marks the checked variable safe for the guard's kinds.
func (f *fnRun) refine(st State, cond ir.Operand, edge bool) State {
	d := f.fn.Defs[cond.Var]
	if d == nil {
		return st
	}
	var out State
	update := func(name string, change func(*Value)) {
		if name == "" {
			return
		}
		v, ok := st[name]
		if out != nil {
			v, ok = out[name]
		}
		if !ok || v.T == nil {
			return
		}
		if out == nil {
			out = st.copy()
		}
		n := v.copy()
		change(n)
		out[name] = n
	}
	mark := func(name string, kinds taint.Kind) {
		update(name, func(v *Value) { v.Safe |= kinds })
	}
	flag := func(name, fl string) {
		update(name, func(v *Value) {
			if v.Fields == nil {
				v.Fields = map[string]*Value{}
			}
			v.Fields[fl] = boolVal(true)
		})
	}
	quote := func(o ir.Operand) string {
		v := f.val(st, o)
		if v.C != nil && v.C.Kind == ir.Str && (v.C.Val == "'" || v.C.Val == `"`) {
			return v.C.Val
		}
		return ""
	}
	isIn := d.Op == ir.Bin && (d.Name == "in" || d.Name == "not in")
	// `c in x` is false on this edge: x does not contain c.
	absent := isIn && (d.Name == "in") != edge
	for _, g := range f.e.spec.Guards {
		switch {
		case len(g.Contains) > 0:
			needle, hay, ok := f.lacks(st, d, edge)
			if !ok {
				continue
			}
			for _, c := range g.Contains {
				if strings.Contains(needle, c) {
					mark(f.root(hay), g.Kinds)
					break
				}
			}
		case g.Method != "" && d.Op == ir.Call && d.Name == g.Method && edge:
			name := f.root(d.A)
			if g.Normalized {
				if v, ok := st[name]; !ok || !v.Norm {
					continue
				}
			}
			mark(name, g.Kinds)
		case g.QuotedLiteral:
			var name string
			switch {
			case d.Op == ir.Call && (d.Name == "startswith" || d.Name == "endswith") && edge && len(d.Args) == 1 && quote(d.Args[0]) != "":
				name = f.root(d.A)
				fl := flagStarts
				if d.Name == "endswith" {
					fl = flagEnds
				}
				flag(name, fl+quote(d.Args[0]))
			case absent && quote(d.A) != "":
				// c in x[1:-1]
				s := f.fn.Defs[d.B.Var]
				if s == nil || s.Op != ir.Index || s.Name != "slice" || !isInt(f.val(st, s.B), 1) || !isInt(f.val(st, s.C), -1) {
					continue
				}
				name = f.root(s.A)
				flag(name, flagInner+quote(d.A))
			default:
				continue
			}
			src := st
			if out != nil {
				src = out
			}
			if v, ok := src[name]; ok {
				for _, q := range []string{"'", `"`} {
					if v.Fields[flagStarts+q] != nil && v.Fields[flagEnds+q] != nil && v.Fields[flagInner+q] != nil {
						mark(name, g.Kinds)
					}
				}
			}
		case len(g.Methods) > 0 && d.Op == ir.Call && edge && contains(g.Methods, d.Name):
			// letters and digits are harmless, but still the client's data
			mark(f.root(d.A), g.Kinds&^taint.Trust)
		case len(g.Calls) > 0 && d.Op == ir.Call && edge && len(d.Args) > 0 && f.calls(d, st, g.Calls):
			mark(f.root(d.Args[0]), g.Kinds)
		case g.Allowlist && isIn && !absent && constant(f.val(st, d.B)) && f.val(st, d.B).C == nil:
			mark(f.root(d.A), g.Kinds)
		case g.Netloc:
			// url.netloc in [...] on this edge, url = urlparse(x)
			var host ir.Operand
			switch {
			case isIn && !absent:
				host = d.A
			case d.Op == ir.Bin && (d.Name == "==" && edge || d.Name == "!=" && !edge):
				host = d.A
			default:
				continue
			}
			allow := d.B
			if d.Op == ir.Bin && (d.Name == "==" || d.Name == "!=") && f.val(st, host).C != nil {
				host, allow = d.B, d.A
			}
			if !constant(f.val(st, allow)) {
				continue
			}
			ld := f.fn.Defs[host.Var]
			if ld == nil || ld.Op != ir.Load || ld.Name != "netloc" && ld.Name != "hostname" {
				continue
			}
			url := f.root(ld.A)
			v, ok := st[url]
			if !ok {
				continue
			}
			mark(url, g.Kinds)
			if v.From != "" {
				mark(v.From, g.Kinds)
			}
		}
	}
	val := func(o ir.Operand) *Value { return f.val(st, o) }
	if o, kinds, ok := f.valueCheck(f.fn, val, d, edge, 0); ok {
		mark(f.root(o), kinds)
	}
	if out == nil {
		return st
	}
	return out
}

// lacks reports a check that holds on this edge when hay does not contain
// the constant needle: needle not in hay, and in JavaScript
// !hay.includes(needle), hay.indexOf(needle) === -1 (or < 0) and
// !/needle/.test(hay).
func (f *fnRun) lacks(st State, d *ir.Instr, edge bool) (string, ir.Operand, bool) {
	str := func(o ir.Operand) (string, bool) {
		v := f.val(st, o)
		if v.C == nil || v.C.Kind != ir.Str {
			return "", false
		}
		return v.C.Val, true
	}
	switch {
	case d.Op == ir.Bin && (d.Name == "in" || d.Name == "not in") && (d.Name == "in") != edge:
		if s, ok := str(d.A); ok {
			return s, d.B, true
		}
	case d.Op == ir.Call && d.Name == "includes" && len(d.Args) == 1 && !edge:
		if s, ok := str(d.Args[0]); ok {
			return s, d.A, true
		}
	case d.Op == ir.Call && d.Name == "test" && len(d.Args) == 1 && !edge:
		// /\.\./.test(p): the pattern's literal text, unescaped
		re := f.val(st, d.A)
		if re.C != nil && re.C.Kind == ir.Other && strings.HasPrefix(re.C.Val, "/") {
			return strings.ReplaceAll(re.C.Val, `\`, ""), d.Args[0], true
		}
	case d.Op == ir.Bin:
		call, other, op := f.fn.Defs[d.A.Var], d.B, d.Name
		if call == nil || call.Op != ir.Call {
			call, other, op = f.fn.Defs[d.B.Var], d.A, flipCompare[d.Name]
		}
		if call == nil || call.Op != ir.Call || call.Name != "indexOf" || len(call.Args) != 1 {
			break
		}
		n, isNum := intConst(f.val(st, other))
		if !isNum {
			break
		}
		// indexOf(...) is -1 on this edge
		minus := op == "==" && n == -1 || op == "<" && n == 0 || op == "<=" && n == -1
		found := op == "!=" && n == -1 || op == ">=" && n == 0 || op == ">" && n == -1
		if !(minus && edge || found && !edge) {
			break
		}
		if s, ok := str(call.Args[0]); ok {
			return s, call.A, true
		}
	}
	return "", ir.Operand{}, false
}

// flipCompare is the comparison with its operands swapped.
var flipCompare = map[string]string{"==": "==", "!=": "!=", "<": ">", ">": "<", "<=": ">=", ">=": "<="}

// calls reports a call instruction whose qualified callee is in list.
func (f *fnRun) calls(d *ir.Instr, st State, list []string) bool {
	q := f.val(st, d.A).Q
	if d.Name != "" && q != "" {
		q += "." + d.Name
	} else if d.Name != "" {
		return false
	}
	return contains(list, q)
}

func isInt(v *Value, n int) bool {
	i, ok := intConst(v)
	return ok && i == n
}

// constant reports a constant or a list, tuple or set of constants.
func constant(v *Value) bool {
	if v.C != nil {
		return true
	}
	if !v.Known || v.T != nil {
		return false
	}
	for _, e := range v.Elems {
		if e.C == nil {
			return false
		}
	}
	return true
}

// root follows a temporary back to the source variable it stands for,
// through copies and str() or os.fspath() conversions.
func (f *fnRun) root(o ir.Operand) string {
	for i := 0; i < 8; i++ {
		if o.Var == "" {
			return ""
		}
		if !ir.IsTemp(o.Var) {
			return o.Var
		}
		d := f.fn.Defs[o.Var]
		if d == nil {
			return ""
		}
		switch {
		case d.Op == ir.Copy:
			o = d.A
		case d.Op == ir.Call && d.Name == "" && len(d.Args) == 1:
			callee := d.A
			if cd := f.fn.Defs[callee.Var]; cd != nil && cd.Op == ir.Free && (cd.Name == "str" || cd.Name == "os.fspath") {
				o = d.Args[0]
				continue
			}
			return ""
		default:
			return ""
		}
	}
	return ""
}
