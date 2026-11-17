package flow

import (
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// Checks of JavaScript that prove a value safe on one edge of a branch:
// a match of a regular expression anchored at both ends that admits no
// arbitrary character, membership in a list of constants, and a call of a
// function of the project that only returns such a check of a parameter
// (isValidHostName(h)).

// valueCheck returns the operand a condition (the instruction d) proves
// safe on this edge, and the kinds it is safe for. val evaluates the
// operands of fn, the function d belongs to.
func (f *fnRun) valueCheck(fn *ir.Function, val func(ir.Operand) *Value, d *ir.Instr, edge bool, depth int) (ir.Operand, taint.Kind, bool) {
	var kinds taint.Kind
	for _, g := range f.e.spec.Guards {
		switch {
		case g.AnchoredRegex && edge && d.Op == ir.Call && (d.Name == "test" && len(d.Args) == 1 || d.Name == "match" && len(d.Args) == 1):
			re, subject := d.A, d.Args[0]
			if d.Name == "match" {
				re, subject = d.Args[0], d.A
			}
			if strictRegex(val(re)) {
				return subject, g.Kinds, true
			}
		case g.Allowlist && d.Op == ir.Call && d.Name == "includes" && len(d.Args) == 1 && edge:
			if constant(val(d.A)) && val(d.A).C == nil {
				return d.Args[0], g.Kinds, true
			}
		case g.Allowlist && d.Op == ir.Bin:
			call, other, op := fn.Defs[d.A.Var], d.B, d.Name
			if call == nil || call.Op != ir.Call {
				call, other, op = fn.Defs[d.B.Var], d.A, flipCompare[d.Name]
			}
			if call == nil || call.Op != ir.Call || call.Name != "indexOf" || len(call.Args) != 1 {
				continue
			}
			n, isNum := intConst(val(other))
			if !isNum || !constant(val(call.A)) || val(call.A).C != nil {
				continue
			}
			minus := op == "==" && n == -1 || op == "<" && n == 0 || op == "<=" && n == -1
			found := op == "!=" && n == -1 || op == ">=" && n == 0 || op == ">" && n == -1
			if found && edge || minus && !edge {
				return call.Args[0], g.Kinds, true
			}
		}
	}
	// A call of a validator of the project: map its parameter to the
	// argument.
	if depth > 0 || d.Op != ir.Call || d.Name != "" {
		return ir.Operand{}, kinds, false
	}
	callee := val(d.A).Fn
	if callee == nil || f.p.owner[callee] == nil {
		return ir.Operand{}, kinds, false
	}
	ret, ok := singleReturn(callee)
	if !ok {
		return ir.Operand{}, kinds, false
	}
	rd := callee.Defs[ret.Var]
	if rd == nil {
		return ir.Operand{}, kinds, false
	}
	owner := f.p.owner[callee]
	cval := func(o ir.Operand) *Value {
		if o.Const != nil {
			return constVal(o.Const)
		}
		if def := callee.Defs[o.Var]; def != nil && def.Op == ir.Free {
			if v, ok := owner.exit[def.Name]; ok {
				return v
			}
		}
		return empty
	}
	checked, k, ok := f.valueCheck(callee, cval, rd, edge, depth+1)
	if !ok || checked.Var == "" {
		return ir.Operand{}, kinds, false
	}
	for i, prm := range callee.Params {
		if prm.Name == checked.Var && i < len(d.Args) {
			return d.Args[i], k, true
		}
	}
	return ir.Operand{}, kinds, false
}

// singleReturn returns the value of a function with one return of a
// value.
func singleReturn(fn *ir.Function) (ir.Operand, bool) {
	var out ir.Operand
	n := 0
	for _, b := range fn.Blocks {
		if b.Term.Kind == ir.Return && !b.Term.Value.IsZero() {
			out = b.Term.Value
			n++
		}
	}
	return out, n == 1 && out.Var != ""
}

// strictRegex reports a JavaScript regular expression anchored at both
// ends whose pattern admits no arbitrary character (no . and no negated
// class), so a value it matches holds only the characters it lists.
func strictRegex(v *Value) bool {
	if v.C == nil || v.C.Kind != ir.Other || !strings.HasPrefix(v.C.Val, "/") {
		return false
	}
	end := strings.LastIndexByte(v.C.Val, '/')
	if end <= 1 || strings.Contains(v.C.Val[end:], "m") {
		return false // with m, ^ and $ match at each line
	}
	p := v.C.Val[1:end]
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") || strings.HasSuffix(p, `\$`) {
		return false
	}
	inClass := false
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '\\':
			if i+1 < len(p) && strings.IndexByte("SWDs", p[i+1]) >= 0 {
				return false // \S, \W, \D and \s admit what matters
			}
			i++
		case c == '[' && !inClass:
			inClass = true
			if i+1 < len(p) && p[i+1] == '^' {
				return false
			}
		case c == ']' && inClass:
			inClass = false
		case c == '.' && !inClass:
			return false
		case c == '|' && !inClass:
			// ^a|b$ anchors only one side of each alternative
			if !alternativesGrouped(p) {
				return false
			}
		}
	}
	return true
}

// alternativesGrouped reports a pattern whose alternatives are inside a
// group, ^(a|b)$, rather than at the top level.
func alternativesGrouped(p string) bool {
	depth, inClass := 0, false
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '\\':
			i++
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '(' && !inClass:
			depth++
		case c == ')' && !inClass:
			depth--
		case c == '|' && !inClass && depth == 0:
			return false
		}
	}
	return true
}
