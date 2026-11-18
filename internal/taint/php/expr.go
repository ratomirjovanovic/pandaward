package php

import (
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// binding powers, low to high
const (
	bpAssign   = 4
	bpTernary  = 5
	bpCoalesce = 6
)

var binBP = map[string]int{
	"or": 1, "xor": 2, "and": 3,
	"??": bpCoalesce, "||": 7, "&&": 8, "|": 9, "^": 10, "&": 11,
	"==": 12, "!=": 12, "===": 12, "!==": 12, "<>": 12, "<=>": 12,
	"<": 13, "<=": 13, ">": 13, ">=": 13,
	".": 14, "<<": 15, ">>": 15, "+": 16, "-": 16, "*": 17, "/": 17, "%": 17,
	"instanceof": 19, "**": 20,
}

var assignOps = map[string]string{"=": "", "+=": "+", "-=": "-", "*=": "*", "/=": "/", ".=": "+", "%=": "%", "**=": "**", "??=": "??", "&=": "&", "|=": "|", "^=": "^", "<<=": "<<", ">>=": ">>"}

// expr parses and lowers an expression and returns its value.
func (p *parser) expr() ir.Operand { return p.exprBP(0) }

func (p *parser) exprBP(minBP int) ir.Operand {
	r := p.unary()
	var left ir.Operand
	assigned := false
	if t := p.peek(); t.k == tOp {
		if op, ok := assignOps[t.s]; ok && assignable(r) {
			pos := p.pos()
			p.next()
			p.acceptOp("&") // =& reference
			rhs := p.exprBP(bpAssign)
			left = p.assignOp(r, op, rhs, pos)
			assigned = true
		}
	}
	if !assigned {
		left = p.read(r)
	}
	for {
		t := p.peek()
		var op string
		switch {
		case t.k == tOp && (binBP[t.s] > 0 || t.s == "?"):
			op = t.s
		case t.k == tIdent && (strings.EqualFold(t.s, "and") || strings.EqualFold(t.s, "or") || strings.EqualFold(t.s, "xor") || strings.EqualFold(t.s, "instanceof")):
			op = strings.ToLower(t.s)
		default:
			return left
		}
		if op == "?" {
			if bpTernary < minBP {
				return left
			}
			p.next()
			left = p.ternary(left)
			continue
		}
		bp := binBP[op]
		if bp < minBP {
			return left
		}
		pos := p.pos()
		p.next()
		switch op {
		case "&&", "and", "||", "or", "??":
			left = p.shortCircuit(op, left, bp, pos)
		case "instanceof":
			p.unary()
			left = p.value(ir.Bin, pos, "is", left, ir.Operand{})
		default:
			next := bp + 1
			if op == "**" {
				next = bp
			}
			right := p.exprBP(next)
			name := op
			if op == "." {
				name = "+"
			}
			left = p.value(ir.Bin, pos, name, left, right)
		}
	}
}

func (p *parser) shortCircuit(op string, left ir.Operand, bp int, pos ir.Pos) ir.Operand {
	t := p.temp()
	p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: t, A: left})
	after, next := p.newBlock(), p.newBlock()
	if op == "&&" || op == "and" {
		p.branch(ir.V(t), pos, next, after)
	} else {
		p.branch(ir.V(t), pos, after, next)
	}
	p.cur = next
	right := p.exprBP(bp + 1)
	p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: t, A: right})
	p.jump(after)
	p.cur = after
	return ir.V(t)
}

func (p *parser) ternary(cond ir.Operand) ir.Operand {
	pos := p.pos()
	t := p.temp()
	then, els, after := p.newBlock(), p.newBlock(), p.newBlock()
	p.branch(cond, pos, then, els)
	p.cur = then
	if p.acceptOp(":") { // a ?: b
		p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: t, A: cond})
	} else {
		v := p.exprBP(bpAssign)
		p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: t, A: v})
		p.expectOp(":")
	}
	p.jump(after)
	p.cur = els
	v := p.exprBP(bpTernary + 1)
	p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: t, A: v})
	p.jump(after)
	p.cur = after
	return ir.V(t)
}

func assignable(r ref) bool {
	switch r.kind {
	case "var", "index", "prop", "list":
		return true
	}
	return false
}

// ---- reading and writing a ref ----

func (p *parser) read(r ref) ir.Operand {
	switch r.kind {
	case "var":
		return p.varOp(r.name, r.pos)
	case "index":
		return p.value(ir.Index, r.pos, "", r.base, r.key)
	case "prop":
		return p.value(ir.Load, r.pos, r.name, r.base, ir.Operand{})
	case "list":
		return ir.C(ir.Other, "list")
	}
	return r.op
}

func (p *parser) varOp(name string, pos ir.Pos) ir.Operand {
	if p.arrow && !p.locals[name] {
		return p.free("$"+name, pos)
	}
	return ir.V("$" + name)
}

func (p *parser) assignOp(r ref, op string, rhs ir.Operand, pos ir.Pos) ir.Operand {
	if op != "" {
		cur := p.read(r)
		bin := op
		if op == "??" {
			t := p.temp()
			p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: t, A: cur})
			p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: t, A: rhs})
			rhs = ir.V(t)
		} else {
			rhs = p.value(ir.Bin, pos, bin, cur, rhs)
		}
	}
	p.assignRef(r, rhs, pos)
	return rhs
}

// assignRef stores v into the target.
func (p *parser) assignRef(r ref, v ir.Operand, pos ir.Pos) {
	switch r.kind {
	case "var":
		p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: "$" + r.name, A: v})
		p.locals[r.name] = true
	case "index":
		p.emit(&ir.Instr{Op: ir.SetIndex, Pos: pos, A: r.base, B: r.key, C: v})
	case "prop":
		p.emit(&ir.Instr{Op: ir.Store, Pos: pos, A: r.base, Name: r.name, B: v})
	case "list":
		for i, e := range r.elts {
			if e.kind == "" {
				continue
			}
			el := p.value(ir.Index, pos, "", v, ir.C(ir.Int, strconv.Itoa(i)))
			p.assignRef(e, el, pos)
		}
	}
}

// ---- unary and postfix ----

func (p *parser) unary() ref {
	t := p.peek()
	pos := p.pos()
	switch t.k {
	case tCast:
		p.next()
		v := p.exprBP(18)
		switch t.s {
		case "int":
			return val(p.callFree(pos, "intval", v))
		case "float":
			return val(p.callFree(pos, "floatval", v))
		case "bool":
			return val(p.value(ir.Unary, pos, "not", v, ir.Operand{}))
		}
		return val(v)
	case tOp:
		switch t.s {
		case "!":
			p.next()
			return val(p.value(ir.Unary, pos, "not", p.exprBP(18), ir.Operand{}))
		case "-", "+", "~":
			p.next()
			return val(p.value(ir.Unary, pos, t.s, p.exprBP(18), ir.Operand{}))
		case "@", "&":
			p.next()
			return p.unary()
		case "++", "--":
			p.next()
			r := p.unary()
			if assignable(r) {
				cur := p.read(r)
				nv := p.value(ir.Bin, pos, t.s[:1], cur, ir.C(ir.Int, "1"))
				p.assignRef(r, nv, pos)
				return val(nv)
			}
			return r
		}
	case tIdent:
		switch strings.ToLower(t.s) {
		case "new":
			p.next()
			return p.postfix(p.newExpr(pos))
		case "clone":
			p.next()
			return val(p.exprBP(18))
		case "print":
			p.next()
			return val(p.callFree(pos, "print", p.exprBP(bpAssign)))
		case "include", "include_once", "require", "require_once":
			p.next()
			return val(p.callFree(pos, strings.ToLower(t.s), p.exprBP(bpAssign)))
		case "yield":
			p.next()
			if p.isOp(";") || p.isOp(")") || p.isOp(",") {
				return val(ir.C(ir.Other, "yield"))
			}
			p.acceptKw("from")
			return val(p.exprBP(bpAssign))
		case "throw":
			p.next()
			p.exprBP(bpAssign)
			return val(ir.C(ir.Other, "throw"))
		}
	}
	return p.postfix(p.primary())
}

func val(o ir.Operand) ref { return ref{kind: "val", op: o} }

func (p *parser) postfix(r ref) ref {
	for {
		t := p.peek()
		if t.k != tOp {
			return r
		}
		pos := ir.Pos{Line: t.line, Col: t.col}
		switch t.s {
		case "[":
			p.next()
			base := p.read(r)
			if p.acceptOp("]") {
				r = ref{kind: "index", base: base, pos: pos}
				continue
			}
			k := p.expr()
			p.expectOp("]")
			r = ref{kind: "index", base: base, key: k, pos: pos}
		case "{":
			return r
		case "->", "?->":
			p.next()
			base := p.read(r)
			name := ""
			switch n := p.peek(); {
			case n.k == tIdent:
				p.next()
				name = strings.ToLower(n.s)
			case n.k == tVar:
				p.next()
				p.varOp(n.s, pos)
			case p.isOp("{"):
				p.next()
				p.expr()
				p.expectOp("}")
			}
			if p.isOp("(") {
				args, keys := p.args()
				if name == "" {
					r = val(p.call(pos, base, "", args, keys))
				} else {
					r = val(p.call(pos, base, name, args, keys))
				}
				continue
			}
			r = ref{kind: "prop", base: base, name: name, pos: pos}
		case "::":
			p.next()
			base := p.read(r)
			n := p.peek()
			switch {
			case n.k == tVar:
				p.next()
				r = ref{kind: "prop", base: base, name: n.s, pos: pos}
			case n.k == tIdent:
				p.next()
				name := strings.ToLower(n.s)
				if p.isOp("(") {
					args, keys := p.args()
					r = val(p.call(pos, base, name, args, keys))
				} else {
					r = ref{kind: "prop", base: base, name: n.s, pos: pos}
				}
			default:
				r = val(ir.C(ir.Other, "?"))
			}
		case "(":
			args, keys := p.args()
			r = val(p.call(pos, p.read(r), "", args, keys))
		case "++", "--":
			if !assignable(r) {
				return r
			}
			p.next()
			cur := p.read(r)
			nv := p.value(ir.Bin, pos, t.s[:1], cur, ir.C(ir.Int, "1"))
			p.assignRef(r, nv, pos)
			r = val(cur)
		default:
			return r
		}
	}
}

// args parses (a, name: b, ...c).
func (p *parser) args() ([]ir.Operand, []string) {
	var out []ir.Operand
	var keys []string
	p.expectOp("(")
	for !p.isOp(")") && p.peek().k != tEOF {
		key := ""
		switch {
		case p.acceptOp("..."):
			key = "*"
			if p.isOp(")") { // first-class callable f(...)
				keys = append(keys, "")
				out = append(out, ir.C(ir.Other, "callable"))
				continue
			}
		case p.peek().k == tIdent && p.peekAt(1).k == tOp && p.peekAt(1).s == ":" && !(p.peekAt(2).k == tOp && p.peekAt(2).s == ":"):
			key = p.next().s
			p.next()
		}
		out = append(out, p.expr())
		keys = append(keys, key)
		if !p.acceptOp(",") {
			break
		}
	}
	p.expectOp(")")
	return out, keys
}

func (p *parser) newExpr(pos ir.Pos) ref {
	var class ir.Operand
	switch t := p.peek(); {
	case t.k == tIdent && strings.EqualFold(t.s, "class"):
		// an anonymous class: its body is skipped
		p.next()
		if p.isOp("(") {
			p.args()
		}
		for p.peek().k != tEOF && !p.isOp("{") {
			p.next()
		}
		depth := 0
		for p.peek().k != tEOF {
			t := p.next()
			if t.k == tOp && t.s == "{" {
				depth++
			} else if t.k == tOp && t.s == "}" {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		return val(ir.C(ir.Other, "object"))
	case t.k == tIdent:
		p.next()
		class = p.fnRef(strings.ToLower(strings.TrimPrefix(t.s, "\\")), pos)
	case t.k == tVar:
		p.next()
		class = p.varOp(t.s, pos)
	default:
		return val(ir.C(ir.Other, "?"))
	}
	var args []ir.Operand
	var keys []string
	if p.isOp("(") {
		args, keys = p.args()
	}
	return val(p.call(pos, class, "", args, keys))
}

// ---- primary expressions ----

func (p *parser) primary() ref {
	t := p.next()
	pos := ir.Pos{Line: t.line, Col: t.col}
	switch t.k {
	case tVar:
		if t.s == "this" {
			return ref{kind: "var", name: "this", pos: pos}
		}
		if superglobals[t.s] {
			return val(p.value(ir.Load, pos, t.s, p.value(ir.Import, pos, "php", ir.Operand{}, ir.Operand{}), ir.Operand{}))
		}
		return ref{kind: "var", name: t.s, pos: pos}
	case tNum:
		if strings.ContainsAny(t.s, ".eE") && !strings.HasPrefix(t.s, "0x") {
			return val(ir.C(ir.Float, t.s))
		}
		return val(ir.C(ir.Int, strings.ReplaceAll(t.s, "_", "")))
	case tStr:
		return val(ir.C(ir.Str, t.s))
	case tTpl:
		o := p.template(t)
		if t.shell {
			return val(p.callFree(pos, "shell_exec", o))
		}
		return val(o)
	case tOp:
		switch t.s {
		case "(":
			v := p.expr()
			p.expectOp(")")
			return val(v)
		case "[":
			return p.arrayLit(pos, "]")
		case "&":
			return p.unary()
		}
	case tIdent:
		return p.identExpr(t, pos)
	}
	p.fail()
	return val(ir.C(ir.Other, "?"))
}

var superglobals = map[string]bool{"_GET": true, "_POST": true, "_REQUEST": true, "_COOKIE": true, "_FILES": true, "_SERVER": true, "_SESSION": true, "_ENV": true, "GLOBALS": true}

func (p *parser) template(t token) ir.Operand {
	pos := ir.Pos{Line: t.line, Col: t.col}
	var parts []ir.Operand
	for _, part := range t.parts {
		if part.code == "" {
			parts = append(parts, ir.C(ir.Str, part.lit))
			continue
		}
		parts = append(parts, p.subExpr(part, pos))
	}
	tmp := p.temp()
	p.emit(&ir.Instr{Op: ir.Build, Pos: pos, Dst: tmp, Name: "str", Args: parts})
	return ir.V(tmp)
}

// subExpr parses the code of an interpolated part with a parser of its own
// that shares the lowering state.
func (p *parser) subExpr(pt part, pos ir.Pos) ir.Operand {
	saved, savedP := p.toks, p.p
	p.toks, p.p = lex(pt.code, pt.line, true), 0
	v := p.expr()
	p.toks, p.p = saved, savedP
	return v
}

func (p *parser) arrayLit(pos ir.Pos, end string) ref {
	// [$a, $b] = ... and list($a, $b) = ... assign to their elements.
	if p.inTarget || p.closesWithAssign(end) {
		saved := p.inTarget
		p.inTarget = true
		r := ref{kind: "list", pos: pos}
		for !p.isOp(end) && p.peek().k != tEOF {
			if p.isOp(",") {
				p.next()
				r.elts = append(r.elts, ref{})
				continue
			}
			p.acceptOp("&")
			t := p.unary()
			if p.acceptOp("=>") { // ['k' => $v]: the key is not a target
				p.acceptOp("&")
				t = p.unary()
			}
			if assignable(t) {
				r.elts = append(r.elts, t)
			} else {
				r.elts = append(r.elts, ref{})
			}
			if !p.acceptOp(",") {
				break
			}
		}
		p.inTarget = saved
		p.expectOp(end)
		return r
	}
	var vals, keys []ir.Operand
	var hasKey []bool
	keyed := false
	for !p.isOp(end) && p.peek().k != tEOF {
		if p.acceptOp("...") {
			vals, keys, hasKey = append(vals, p.expr()), append(keys, ir.Operand{}), append(hasKey, false)
		} else {
			p.acceptOp("&")
			v := p.exprBP(bpAssign)
			k, has := ir.Operand{}, false
			if p.acceptOp("=>") {
				p.acceptOp("&")
				k, has, keyed = v, true, true
				v = p.exprBP(bpAssign)
			}
			vals, keys, hasKey = append(vals, v), append(keys, k), append(hasKey, has)
		}
		if !p.acceptOp(",") {
			break
		}
	}
	p.expectOp(end)
	tmp := p.temp()
	in := &ir.Instr{Op: ir.Build, Pos: pos, Dst: tmp, Name: "list", Args: vals}
	if keyed {
		in.Name = "dict"
		for i := range vals {
			if hasKey[i] {
				in.Keys2 = append(in.Keys2, keys[i])
			} else {
				in.Keys2 = append(in.Keys2, ir.C(ir.Int, strconv.Itoa(i)))
			}
		}
	}
	p.emit(in)
	return val(ir.V(tmp))
}

// closesWithAssign reports whether the bracket group that starts at the
// current token ends with the closing token end and is followed by =.
func (p *parser) closesWithAssign(end string) bool {
	depth := 0
	for i := p.p; i < len(p.toks); i++ {
		t := p.toks[i]
		if t.k == tEOF {
			return false
		}
		if t.k != tOp {
			continue
		}
		switch t.s {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			if depth == 0 {
				n := p.toks[min(i+1, len(p.toks)-1)]
				return t.s == end && n.k == tOp && n.s == "="
			}
			depth--
		}
	}
	return false
}

func (p *parser) identExpr(t token, pos ir.Pos) ref {
	name := strings.TrimPrefix(t.s, "\\")
	low := strings.ToLower(name)
	switch low {
	case "true":
		return val(ir.C(ir.Bool, "true"))
	case "false":
		return val(ir.C(ir.Bool, "false"))
	case "null":
		return val(ir.C(ir.None, "None"))
	case "array":
		if p.isOp("(") {
			p.next()
			return p.arrayLit(pos, ")")
		}
	case "list":
		if p.isOp("(") {
			p.next()
			return p.arrayLit(pos, ")")
		}
	case "isset", "empty":
		if p.isOp("(") {
			p.next()
			var last ir.Operand
			for !p.isOp(")") && p.peek().k != tEOF {
				last = p.expr()
				if !p.acceptOp(",") {
					break
				}
			}
			p.expectOp(")")
			return val(p.value(ir.Unary, pos, "not", last, ir.Operand{}))
		}
	case "exit", "die":
		var args []ir.Operand
		if p.isOp("(") {
			args, _ = p.args()
		}
		p.callFree(pos, "exit", args...)
		// Nothing runs after exit: a check that ends in it guards what follows.
		p.cur.Term = ir.Term{Kind: ir.Raise, Pos: pos}
		p.cur = nil
		return val(ir.C(ir.Other, "exit"))
	case "function", "fn":
		return p.closure(low, pos)
	case "static":
		if p.isKw("function") || p.isKw("fn") {
			n := strings.ToLower(p.next().s)
			return p.closure(n, pos)
		}
	case "match":
		if p.isOp("(") {
			return p.matchExpr(pos)
		}
	}
	if p.isOp("(") {
		args, keys := p.args()
		return val(p.call(pos, p.fnRef(low, pos), "", args, keys))
	}
	if p.isOp("::") {
		return val(p.fnRef(low, pos))
	}
	// a constant
	return val(ir.C(ir.Other, name))
}

// closure parses function (...) use (...) {...} and fn(...) => expr.
func (p *parser) closure(kw string, pos ir.Pos) ref {
	p.acceptOp("&")
	params := p.params()
	var imports []string
	if kw == "function" && p.acceptKw("use") {
		p.expectOp("(")
		for !p.isOp(")") && p.peek().k != tEOF {
			p.acceptOp("&")
			if p.peek().k == tVar {
				imports = append(imports, p.next().s)
			}
			if !p.acceptOp(",") {
				break
			}
		}
		p.expectOp(")")
	}
	if p.acceptOp(":") {
		p.skipType()
	}
	var fn *ir.Function
	if kw == "fn" {
		p.expectOp("=>")
		fn = p.function("<lambda>", pos, params, "", nil, true, func() {
			v := p.exprBP(bpAssign)
			p.cur.Term = ir.Term{Kind: ir.Return, Pos: pos, Value: v}
			p.cur = nil
		})
	} else {
		fn = p.function("<lambda>", pos, params, "", imports, false, func() { p.body() })
	}
	t := p.temp()
	p.emit(&ir.Instr{Op: ir.Func, Pos: pos, Dst: t, Fn: fn})
	return val(ir.V(t))
}

// matchExpr lowers match (x) { a, b => r, default => d }: its value is one
// of the results.
func (p *parser) matchExpr(pos ir.Pos) ref {
	p.expectOp("(")
	p.expr()
	p.expectOp(")")
	p.expectOp("{")
	t := p.temp()
	after := p.newBlock()
	for !p.isOp("}") && p.peek().k != tEOF {
		for !p.isOp("=>") && p.peek().k != tEOF && !p.isOp("}") {
			if p.isKw("default") {
				p.next()
			} else {
				p.expr()
			}
			if !p.acceptOp(",") {
				break
			}
		}
		p.expectOp("=>")
		arm, next := p.newBlock(), p.newBlock()
		p.branch(ir.C(ir.Other, "match"), pos, arm, next)
		p.cur = arm
		v := p.exprBP(bpAssign)
		p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: t, A: v})
		p.jump(after)
		p.cur = next
		if !p.acceptOp(",") {
			break
		}
	}
	p.expectOp("}")
	p.jump(after)
	p.cur = after
	return val(ir.V(t))
}

// fnRef is the value of a global function or class name: a plain name in
// the module body (a function declared above is bound there), a free name
// inside a function.
func (p *parser) fnRef(name string, pos ir.Pos) ir.Operand {
	if p.fn.Parent == nil {
		return ir.V(name)
	}
	return p.free(name, pos)
}
