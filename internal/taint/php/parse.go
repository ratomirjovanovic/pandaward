package php

import (
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// Parse lowers a PHP file to the IR and counts the statements it could not
// understand (each skipped up to its end).
func Parse(path, src string) (*ir.Module, int) {
	m, errs := parse(path, src)
	return m, len(errs)
}

// parse is Parse with the line of each statement it could not understand.
func parse(path, src string) (*ir.Module, []int) {
	p := &parser{toks: lex(src, 1, false), mod: &ir.Module{Path: path}}
	p.mod.Init = p.function("<module>", ir.Pos{Line: 1, Col: 1}, nil, "", nil, false, func() {
		for p.peek().k != tEOF {
			p.stmt()
		}
	})
	return p.mod, p.errlines
}

type loopT struct{ cont, exit *ir.Block }

type parser struct {
	toks     []token
	p        int
	mod      *ir.Module
	errlines []int

	fn    *ir.Function
	cur   *ir.Block
	ntemp int
	loops []loopT
	arrow bool
	// inTarget is set while the elements of a destructuring target are read.
	inTarget bool
	locals   map[string]bool
}

// ref is an expression whose last step is not read yet, so an assignment
// can still write to it.
type ref struct {
	kind string // "val", "var", "index", "prop", "list"
	op   ir.Operand
	name string
	base ir.Operand
	key  ir.Operand
	pos  ir.Pos
	elts []ref
}

// fail records a construct the parser could not understand.
func (p *parser) fail() { p.errlines = append(p.errlines, p.peek().line) }

func (p *parser) peek() token { return p.toks[p.p] }
func (p *parser) peekAt(n int) token {
	if p.p+n < len(p.toks) {
		return p.toks[p.p+n]
	}
	return p.toks[len(p.toks)-1]
}
func (p *parser) next() token {
	t := p.toks[p.p]
	if t.k != tEOF {
		p.p++
	}
	return t
}
func (p *parser) isOp(s string) bool { t := p.peek(); return t.k == tOp && t.s == s }
func (p *parser) isKw(s string) bool {
	t := p.peek()
	return t.k == tIdent && strings.EqualFold(t.s, s)
}
func (p *parser) acceptOp(s string) bool {
	if p.isOp(s) {
		p.p++
		return true
	}
	return false
}
func (p *parser) acceptKw(s string) bool {
	if p.isKw(s) {
		p.p++
		return true
	}
	return false
}
func (p *parser) pos() ir.Pos { t := p.peek(); return ir.Pos{Line: t.line, Col: t.col} }

// expectOp consumes s, or counts an error and leaves the token.
func (p *parser) expectOp(s string) bool {
	if p.acceptOp(s) {
		return true
	}
	p.fail()
	return false
}

// ---- IR building ----

func (p *parser) temp() string {
	p.ntemp++
	return "$" + strconv.Itoa(p.ntemp)
}

func (p *parser) emit(in *ir.Instr) {
	if p.cur == nil {
		p.cur = p.fn.NewBlock()
	}
	p.cur.Instrs = append(p.cur.Instrs, in)
}

func (p *parser) newBlock() *ir.Block { return p.fn.NewBlock() }

func (p *parser) jump(b *ir.Block) {
	if p.cur != nil {
		p.cur.Term = ir.Term{Kind: ir.Jump, Succs: []*ir.Block{b}}
	}
	p.cur = nil
}

func (p *parser) branch(cond ir.Operand, pos ir.Pos, t, f *ir.Block) {
	if p.cur == nil {
		p.cur = p.fn.NewBlock()
	}
	p.cur.Term = ir.Term{Kind: ir.Branch, Pos: pos, Cond: cond, Succs: []*ir.Block{t, f}}
	p.cur = nil
}

func (p *parser) value(op ir.Op, pos ir.Pos, name string, a, b ir.Operand) ir.Operand {
	t := p.temp()
	p.emit(&ir.Instr{Op: op, Pos: pos, Dst: t, Name: name, A: a, B: b})
	return ir.V(t)
}

func (p *parser) free(name string, pos ir.Pos) ir.Operand {
	return p.value(ir.Free, pos, name, ir.Operand{}, ir.Operand{})
}

func (p *parser) call(pos ir.Pos, callee ir.Operand, method string, args []ir.Operand, keys []string) ir.Operand {
	in := &ir.Instr{Op: ir.Call, Pos: pos, A: callee, Name: method, Args: args, Keys: keys, Dst: p.temp()}
	p.emit(in)
	return ir.V(in.Dst)
}

// callFree calls a global function by name.
func (p *parser) callFree(pos ir.Pos, name string, args ...ir.Operand) ir.Operand {
	return p.call(pos, p.free(name, pos), "", args, make([]string, len(args)))
}

// function lowers a body into a new Function. The body callback parses and
// lowers the statements inside the new context.
func (p *parser) function(name string, pos ir.Pos, params []ir.Param, class string, imports []string, arrow bool, body func()) *ir.Function {
	fn := &ir.Function{Name: name, Pos: pos, Params: params, Parent: p.fn, Class: class}
	p.mod.Funcs = append(p.mod.Funcs, fn)
	sFn, sCur, sTemp, sLoops, sArrow, sLocals := p.fn, p.cur, p.ntemp, p.loops, p.arrow, p.locals
	p.fn, p.ntemp, p.loops, p.arrow = fn, 0, nil, arrow
	p.locals = map[string]bool{}
	for _, prm := range params {
		p.locals[strings.TrimPrefix(prm.Name, "$")] = true
	}
	p.cur = fn.NewBlock()
	for _, n := range imports {
		t := p.free("$"+n, pos)
		p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: "$" + n, A: t})
		p.locals[n] = true
	}
	body()
	if p.cur != nil {
		p.cur.Term = ir.Term{Kind: ir.Return}
	}
	fn.Link()
	p.fn, p.cur, p.ntemp, p.loops, p.arrow, p.locals = sFn, sCur, sTemp, sLoops, sArrow, sLocals
	return fn
}

// ---- statements ----

// endStmt consumes the end of a statement.
func (p *parser) endStmt() {
	if p.acceptOp(";") || p.peek().k == tEOF || p.peek().k == tInline || p.peek().k == tOpenEc || p.isOp("}") {
		return
	}
	p.skipStmt()
}

// skipStmt counts an error and skips to the end of the statement.
func (p *parser) skipStmt() {
	p.fail()
	depth := 0
	for p.peek().k != tEOF {
		t := p.next()
		if t.k != tOp {
			continue
		}
		switch t.s {
		case "(", "[", "{":
			depth++
		case ")", "]":
			depth--
		case "}":
			depth--
			if depth <= 0 {
				return
			}
		case ";":
			if depth <= 0 {
				return
			}
		}
	}
}

func (p *parser) stmts(stop func() bool) {
	for p.peek().k != tEOF && !stop() {
		before := p.p
		p.stmt()
		if p.p == before {
			p.next() // always make progress
			p.fail()
		}
	}
}

// body parses one statement or a braced block.
func (p *parser) body() {
	if p.acceptOp("{") {
		p.stmts(func() bool { return p.isOp("}") })
		p.expectOp("}")
		return
	}
	p.stmt()
}

func (p *parser) altEnd(kws ...string) func() bool {
	return func() bool {
		for _, k := range kws {
			if p.isKw(k) {
				return true
			}
		}
		return false
	}
}

func (p *parser) stmt() {
	t := p.peek()
	switch t.k {
	case tInline:
		p.next()
		return
	case tOpenEc:
		p.next()
		pos := p.pos()
		var args []ir.Operand
		for {
			args = append(args, p.expr())
			if !p.acceptOp(",") {
				break
			}
		}
		p.callFree(pos, "echo", args...)
		p.endStmt()
		return
	case tOp:
		switch t.s {
		case "{":
			p.body()
			return
		case ";":
			p.next()
			return
		}
	case tIdent:
		if p.keywordStmt(strings.ToLower(t.s)) {
			return
		}
	}
	p.expr()
	p.endStmt()
}

// keywordStmt handles statements that start with a keyword; it reports
// whether it consumed one.
func (p *parser) keywordStmt(kw string) bool {
	pos := p.pos()
	switch kw {
	case "echo":
		p.next()
		var args []ir.Operand
		for {
			args = append(args, p.expr())
			if !p.acceptOp(",") {
				break
			}
		}
		p.callFree(pos, "echo", args...)
		p.endStmt()
	case "if":
		p.next()
		p.ifStmt()
	case "while":
		p.next()
		p.whileStmt()
	case "do":
		p.next()
		p.doStmt()
	case "for":
		p.next()
		p.forStmt()
	case "foreach":
		p.next()
		p.foreachStmt()
	case "switch":
		p.next()
		p.switchStmt()
	case "break", "continue":
		p.next()
		n := 1
		if p.peek().k == tNum {
			n, _ = strconv.Atoi(p.next().s)
		}
		p.endStmt()
		if len(p.loops) > 0 {
			l := p.loops[max(len(p.loops)-n, 0)]
			if kw == "break" {
				p.jump(l.exit)
			} else {
				p.jump(l.cont)
			}
		}
	case "return":
		p.next()
		var v ir.Operand
		if !p.isOp(";") && p.peek().k != tEOF && p.peek().k != tInline {
			v = p.expr()
		}
		p.endStmt()
		if p.cur == nil {
			p.cur = p.fn.NewBlock()
		}
		p.cur.Term = ir.Term{Kind: ir.Return, Pos: pos, Value: v}
		p.cur = nil
	case "throw":
		p.next()
		p.expr()
		p.endStmt()
		if p.cur == nil {
			p.cur = p.fn.NewBlock()
		}
		p.cur.Term = ir.Term{Kind: ir.Raise, Pos: pos}
		p.cur = nil
	case "function":
		// A declaration has a name (maybe after &); a closure does not.
		n := p.peekAt(1)
		if n.k == tOp && n.s == "&" {
			n = p.peekAt(2)
		}
		if n.k != tIdent {
			return false
		}
		p.next()
		p.acceptOp("&")
		name := strings.ToLower(p.next().s)
		fn := p.funcRest(name, pos, "", false)
		p.emit(&ir.Instr{Op: ir.Func, Pos: pos, Dst: name, Fn: fn})
	case "abstract", "final", "readonly":
		n := p.peekAt(1)
		if n.k == tIdent {
			p.next()
			return p.keywordStmt(strings.ToLower(n.s))
		}
		return false
	case "class", "interface", "trait", "enum":
		if p.peekAt(1).k != tIdent {
			return false
		}
		p.next()
		p.classDecl(pos)
	case "namespace":
		p.next()
		for p.peek().k == tIdent {
			p.next()
		}
		if p.isOp("{") {
			p.body()
		} else {
			p.endStmt()
		}
	case "use", "declare", "goto":
		p.next()
		p.skipTo(";")
	case "const":
		p.next()
		for {
			if p.peek().k == tIdent {
				p.next()
			}
			if p.acceptOp("=") {
				p.expr()
			}
			if !p.acceptOp(",") {
				break
			}
		}
		p.endStmt()
	case "global":
		p.next()
		for p.peek().k == tVar {
			n := p.next().s
			t := p.free("$"+n, pos)
			p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: "$" + n, A: t})
			p.locals[n] = true
			if !p.acceptOp(",") {
				break
			}
		}
		p.endStmt()
	case "static":
		if p.peekAt(1).k != tVar {
			return false
		}
		p.next()
		for p.peek().k == tVar {
			n := p.next().s
			if p.acceptOp("=") {
				v := p.expr()
				p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: "$" + n, A: v})
			}
			if !p.acceptOp(",") {
				break
			}
		}
		p.endStmt()
	case "try":
		p.next()
		p.tryStmt()
	default:
		return false
	}
	return true
}

func (p *parser) skipTo(op string) {
	for p.peek().k != tEOF {
		if p.acceptOp(op) {
			return
		}
		p.next()
	}
}

func (p *parser) ifStmt() {
	after := p.newBlock()
	alt := false
	for first := true; ; first = false {
		then, els := p.newBlock(), p.newBlock()
		p.condTo(then, els)
		if first {
			alt = p.isOp(":")
		}
		p.cur = then
		if alt {
			p.expectOp(":")
			p.stmts(p.altEnd("elseif", "else", "endif"))
		} else {
			p.body()
		}
		p.jump(after)
		p.cur = els
		if p.isKw("elseif") || !alt && p.isKw("else") && p.peekAt(1).k == tIdent && strings.EqualFold(p.peekAt(1).s, "if") {
			if p.isKw("else") {
				p.next()
			}
			p.next()
			continue
		}
		if p.acceptKw("else") {
			if alt {
				p.expectOp(":")
				p.stmts(p.altEnd("endif"))
			} else {
				p.body()
			}
		}
		p.jump(after)
		break
	}
	if alt {
		p.acceptKw("endif")
		p.endStmt()
	}
	p.cur = after
}

func (p *parser) loopBody(alt string, cont, exit *ir.Block) {
	p.loops = append(p.loops, loopT{cont, exit})
	if p.isOp(":") && alt != "" {
		p.next()
		p.stmts(p.altEnd(alt))
		p.acceptKw(alt)
		p.endStmt()
	} else {
		p.body()
	}
	p.loops = p.loops[:len(p.loops)-1]
}

func (p *parser) whileStmt() {
	head, body, exit := p.newBlock(), p.newBlock(), p.newBlock()
	p.jump(head)
	p.cur = head
	p.condTo(body, exit)
	p.cur = body
	p.loopBody("endwhile", head, exit)
	p.jump(head)
	p.cur = exit
}

func (p *parser) doStmt() {
	body, test, exit := p.newBlock(), p.newBlock(), p.newBlock()
	p.jump(body)
	p.cur = body
	p.loopBody("", test, exit)
	p.jump(test)
	p.cur = test
	p.acceptKw("while")
	p.condTo(body, exit)
	p.endStmt()
	p.cur = exit
}

func (p *parser) exprList(end string) ir.Operand {
	var last ir.Operand
	for !p.isOp(end) && p.peek().k != tEOF {
		last = p.expr()
		if !p.acceptOp(",") {
			break
		}
	}
	return last
}

func (p *parser) forStmt() {
	p.expectOp("(")
	p.exprList(";")
	p.expectOp(";")
	head, body, step, exit := p.newBlock(), p.newBlock(), p.newBlock(), p.newBlock()
	p.jump(head)
	p.cur = head
	pos := p.pos()
	c := p.exprList(";")
	p.expectOp(";")
	if c.IsZero() {
		c = ir.C(ir.Bool, "true")
	}
	p.branch(c, pos, body, exit)
	// The step is lowered in its own block, after the condition.
	p.cur = step
	p.exprList(")")
	p.expectOp(")")
	p.jump(head)
	p.cur = body
	p.loopBody("endfor", step, exit)
	p.jump(step)
	p.cur = exit
}

func (p *parser) foreachStmt() {
	p.expectOp("(")
	pos := p.pos()
	subject := p.expr()
	p.acceptKw("as")
	head, body, exit := p.newBlock(), p.newBlock(), p.newBlock()
	p.jump(head)
	p.cur = head
	var targets []ref
	for {
		p.acceptOp("&")
		targets = append(targets, p.unary())
		if !p.acceptOp("=>") {
			break
		}
	}
	p.expectOp(")")
	it := p.value(ir.Iter, pos, "", subject, ir.Operand{})
	for i, t := range targets {
		if i == len(targets)-1 {
			p.assignRef(t, it, pos)
		} else {
			p.assignRef(t, it, pos)
		}
	}
	p.branch(ir.C(ir.Other, "foreach"), pos, body, exit)
	p.cur = body
	p.loopBody("endforeach", head, exit)
	p.jump(head)
	p.cur = exit
}

func (p *parser) switchStmt() {
	pos := p.pos()
	p.expectOp("(")
	c := p.expr()
	p.expectOp(")")
	alt := p.isOp(":")
	if alt {
		p.next()
	} else {
		p.expectOp("{")
	}
	exit := p.newBlock()
	p.loops = append(p.loops, loopT{exit, exit})
	end := func() bool {
		if alt {
			return p.isKw("endswitch")
		}
		return p.isOp("}")
	}
	var fall *ir.Block
	var dflt *ir.Block
	for !end() && p.peek().k != tEOF {
		switch {
		case p.acceptKw("case"):
			v := p.expr()
			p.acceptOp(":")
			p.acceptOp(";")
			match := p.value(ir.Bin, pos, "==", c, v)
			body, next := fall, p.newBlock()
			if body == nil {
				body = p.newBlock()
			}
			p.branch(match, pos, body, next)
			p.cur = body
			p.caseBody(end)
			fall = p.newBlock()
			p.jump(fall)
			p.cur = next
		case p.acceptKw("default"):
			p.acceptOp(":")
			p.acceptOp(";")
			dflt = p.newBlock()
			if fall != nil {
				// the previous case falls into default
				fb := fall
				saved := p.cur
				p.cur = fb
				p.jump(dflt)
				p.cur = saved
			}
			// default runs when no case matched: reached from the last test
			rest := p.cur
			p.cur = dflt
			p.caseBody(end)
			fall = p.newBlock()
			p.jump(fall)
			p.cur = rest
		default:
			p.next()
			p.fail()
		}
	}
	// No case matched: default, or nothing.
	if dflt != nil {
		p.jump(dflt)
	} else {
		p.jump(exit)
	}
	if fall != nil {
		p.cur = fall
		p.jump(exit)
	}
	p.loops = p.loops[:len(p.loops)-1]
	if alt {
		p.acceptKw("endswitch")
		p.endStmt()
	} else {
		p.expectOp("}")
	}
	p.cur = exit
}

func (p *parser) caseBody(end func() bool) {
	p.stmts(func() bool { return end() || p.isKw("case") || p.isKw("default") })
}

func (p *parser) tryStmt() {
	pos := p.pos()
	tryBlk, catch, after := p.newBlock(), p.newBlock(), p.newBlock()
	// A catch block is reached from before the try body.
	p.branch(ir.C(ir.Other, "try"), pos, tryBlk, catch)
	p.cur = tryBlk
	p.body()
	p.jump(after)
	p.cur = catch
	for p.isKw("catch") {
		p.next()
		p.expectOp("(")
		for p.peek().k == tIdent || p.isOp("|") {
			p.next()
		}
		name := ""
		if p.peek().k == tVar {
			name = p.next().s
		}
		p.expectOp(")")
		body, next := p.newBlock(), p.newBlock()
		p.branch(ir.C(ir.Other, "catch"), pos, body, next)
		p.cur = body
		if name != "" {
			p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: "$" + name, A: ir.C(ir.Other, "exception")})
		}
		p.body()
		p.jump(after)
		p.cur = next
	}
	p.jump(after)
	p.cur = after
	if p.acceptKw("finally") {
		p.body()
	}
}

// ---- functions and classes ----

// params parses (type $a = default, &$b, ...$c).
func (p *parser) params() []ir.Param {
	var out []ir.Param
	p.expectOp("(")
	for !p.isOp(")") && p.peek().k != tEOF {
		for p.peek().k != tVar && !p.isOp(",") && !p.isOp(")") && p.peek().k != tEOF {
			p.next() // modifiers, types, &, ...
		}
		if p.peek().k == tVar {
			t := p.next()
			prm := ir.Param{Name: "$" + t.s, Pos: ir.Pos{Line: t.line, Col: t.col}}
			if p.acceptOp("=") {
				if c := p.constantOnly(); c != nil {
					prm.Default = c
				}
			}
			out = append(out, prm)
		}
		if !p.acceptOp(",") {
			break
		}
	}
	p.expectOp(")")
	return out
}

// constantOnly parses a default value, returning it when it is a literal.
func (p *parser) constantOnly() *ir.Const {
	t := p.peek()
	switch {
	case t.k == tStr && !p.nextIsOpAfter(1, "."):
		p.next()
		return &ir.Const{Kind: ir.Str, Val: t.s}
	case t.k == tNum && !p.nextIsOpAfter(1, "."):
		p.next()
		return &ir.Const{Kind: ir.Int, Val: t.s}
	}
	p.expr()
	return nil
}

func (p *parser) nextIsOpAfter(n int, op string) bool {
	t := p.peekAt(n)
	return t.k == tOp && (t.s == op || t.s == "+" || t.s == "-" || t.s == "*" || t.s == "?")
}

// funcRest parses the parameters, an optional return type and the body of
// a named function or method.
func (p *parser) funcRest(name string, pos ir.Pos, class string, static bool) *ir.Function {
	params := p.params()
	if class != "" {
		name = class + "." + name // the engine finds a method by this name
	}
	if class != "" && !static {
		params = append([]ir.Param{{Name: "$this", Pos: pos}}, params...)
	}
	if p.acceptOp(":") {
		p.skipType()
	}
	if !p.isOp("{") {
		// abstract or interface method
		p.endStmt()
		fn := p.function(name, pos, params, class, nil, false, func() {})
		markStatic(fn, static)
		return fn
	}
	fn := p.function(name, pos, params, class, nil, false, func() { p.body() })
	markStatic(fn, static)
	return fn
}

func markStatic(fn *ir.Function, static bool) {
	if static {
		fn.Decorators = append(fn.Decorators, ir.Decorator{Name: "staticmethod"})
	}
}

func (p *parser) skipType() {
	for p.peek().k == tIdent || p.isOp("?") || p.isOp("|") || p.isOp("&") {
		p.next()
	}
}

func (p *parser) classDecl(pos ir.Pos) {
	name := strings.ToLower(p.next().s)
	var bases []string
	for p.peek().k != tEOF && !p.isOp("{") {
		t := p.next()
		if t.k == tIdent && !strings.EqualFold(t.s, "extends") && !strings.EqualFold(t.s, "implements") {
			bases = append(bases, strings.ToLower(strings.TrimPrefix(t.s, "\\")))
		}
	}
	p.expectOp("{")
	fn := p.function("<class "+name+">", pos, nil, name, nil, false, func() {
		for !p.isOp("}") && p.peek().k != tEOF {
			p.member(name)
		}
	})
	p.expectOp("}")
	fn.Bases = bases
	p.emit(&ir.Instr{Op: ir.Func, Pos: pos, Dst: name, Fn: fn})
}

func (p *parser) member(class string) {
	pos := p.pos()
	static := false
	for p.peek().k == tIdent {
		switch strings.ToLower(p.peek().s) {
		case "static":
			static = true
			p.next()
			continue
		case "public", "private", "protected", "abstract", "final", "readonly", "var":
			p.next()
			continue
		}
		break
	}
	switch {
	case p.isKw("function"):
		p.next()
		p.acceptOp("&")
		name := strings.ToLower(p.next().s)
		if name == "__construct" {
			name = "__init__"
		}
		fn := p.funcRest(name, pos, class, static)
		p.emit(&ir.Instr{Op: ir.Func, Pos: pos, Dst: name, Fn: fn})
	case p.isKw("const"):
		p.next()
		p.skipTo(";")
	case p.isKw("use") || p.isKw("case"):
		p.next()
		p.skipTo(";")
	case p.peek().k == tVar || p.peek().k == tIdent || p.isOp("?"):
		// a typed property: skip the type, then the name and default
		for p.peek().k != tVar && p.peek().k != tEOF && !p.isOp(";") {
			p.next()
		}
		for p.peek().k == tVar {
			n := p.next().s
			if p.acceptOp("=") {
				v := p.expr()
				p.emit(&ir.Instr{Op: ir.Copy, Pos: pos, Dst: "$" + n, A: v})
			}
			if !p.acceptOp(",") {
				break
			}
		}
		p.endStmt()
	default:
		p.skipStmt()
	}
}

// ---- conditions ----

// logicalIn reports whether the tokens from the current one up to the
// closing parenthesis of the condition hold && || and or at the top level
// and no ternary: only then is the condition split into branches, so a
// check in one operand guards the code it leads to.
func (p *parser) logicalIn() bool {
	depth, logical := 0, false
	for i := p.p; i < len(p.toks); i++ {
		t := p.toks[i]
		if t.k == tEOF {
			break
		}
		if t.k == tIdent && depth == 0 {
			switch strings.ToLower(t.s) {
			case "and", "or", "xor":
				logical = true
			}
			continue
		}
		if t.k != tOp {
			continue
		}
		switch t.s {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			if depth == 0 {
				return logical
			}
			depth--
		case "&&", "||":
			if depth == 0 {
				logical = true
			}
		case "?", "??", "?:":
			if depth == 0 {
				return false
			}
		}
	}
	return logical
}

// condTo parses "(" condition ")" and branches to t when it is true and to
// f otherwise.
func (p *parser) condTo(t, f *ir.Block) {
	pos := p.pos()
	p.expectOp("(")
	if p.isOp("!") || p.logicalIn() {
		p.condOr(t, f)
	} else {
		c := p.expr()
		p.branch(c, pos, t, f)
	}
	p.expectOp(")")
}

func (p *parser) isOrOp() bool  { return p.isOp("||") || p.isKw("or") }
func (p *parser) isAndOp() bool { return p.isOp("&&") || p.isKw("and") }

func (p *parser) condOr(t, f *ir.Block) {
	next := p.newBlock()
	p.condAnd(t, next)
	if p.isOrOp() {
		p.next()
		p.cur = next
		p.condOr(t, f)
		return
	}
	p.cur = next
	p.jump(f)
}

func (p *parser) condAnd(t, f *ir.Block) {
	next := p.newBlock()
	p.condNot(next, f)
	if p.isAndOp() {
		p.next()
		p.cur = next
		p.condAnd(t, f)
		return
	}
	p.cur = next
	p.jump(t)
}

func (p *parser) condNot(t, f *ir.Block) {
	if p.isOp("!") {
		p.next()
		p.condNot(f, t)
		return
	}
	pos := p.pos()
	if p.isOp("(") {
		// a group of conditions, or a value in parentheses
		save := p.p
		p.next()
		if p.logicalIn() {
			p.condOr(t, f)
			if p.acceptOp(")") && (p.isOp(")") || p.isOrOp() || p.isAndOp()) {
				return
			}
		}
		p.p = save
	}
	c := p.exprBP(9)
	p.branch(c, pos, t, f)
}
