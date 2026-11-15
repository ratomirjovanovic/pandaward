package py

import (
	"strings"
)

// maxErrors stops recording errors after this many; parsing goes on.
const maxErrors = 200

// Parse parses a Python module. It always returns a File: statements that
// do not parse become *BadStmt and their errors are listed in File.Errors.
func Parse(path, src string) *File {
	lx := newLexer(src)
	var toks []token
	for {
		t := lx.next()
		toks = append(toks, t)
		if t.kind == tEOF {
			break
		}
	}
	p := &parser{toks: toks}
	f := &File{Path: path}
	f.Body = p.statements(func() bool { return p.tok().kind == tEOF })
	f.Errors = append(lx.errs, p.errs...)
	if len(f.Errors) > maxErrors {
		f.Errors = f.Errors[:maxErrors]
	}
	return f
}

// ParseExpr parses one expression, as the value of an f-string field.
func parseExprAt(src string, line, col int) (Expr, []Error) {
	lx := newLexer(src)
	lx.line = line
	var toks []token
	for {
		t := lx.next()
		if t.line == line {
			t.col += col - 1
		}
		toks = append(toks, t)
		if t.kind == tEOF {
			break
		}
	}
	p := &parser{toks: toks}
	var x Expr
	func() {
		defer p.recoverTo(nil)
		x = p.starExprs()
		p.skipNewlines()
		if p.tok().kind != tEOF {
			p.fail("unexpected " + p.tok().describe())
		}
	}()
	if x == nil {
		x = &Bad{Pos{line, col}}
	}
	return x, append(lx.errs, p.errs...)
}

type parser struct {
	toks      []token
	i         int
	errs      []Error
	inPattern bool
}

type bailout struct{}

func (p *parser) tok() token { return p.toks[p.i] }

func (p *parser) peekAt(n int) token {
	if p.i+n < len(p.toks) {
		return p.toks[p.i+n]
	}
	return p.toks[len(p.toks)-1]
}

func (p *parser) advance() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (t token) is(op string) bool { return t.kind == tOp && t.val == op }

func (t token) kw(w string) bool { return t.kind == tName && t.val == w }

func (t token) describe() string {
	switch t.kind {
	case tEOF:
		return "end of file"
	case tNewline:
		return "end of line"
	case tIndent:
		return "indent"
	case tDedent:
		return "dedent"
	case tString:
		return "string"
	case tNumber:
		return "number " + t.val
	}
	return "'" + t.val + "'"
}

func (p *parser) at(op string) bool  { return p.tok().is(op) }
func (p *parser) atKw(w string) bool { return p.tok().kw(w) }

func (p *parser) accept(op string) bool {
	if p.at(op) {
		p.advance()
		return true
	}
	return false
}

func (p *parser) acceptKw(w string) bool {
	if p.atKw(w) {
		p.advance()
		return true
	}
	return false
}

func (p *parser) pos() Pos {
	t := p.tok()
	return Pos{t.line, t.col}
}

func (p *parser) fail(msg string) {
	t := p.tok()
	if len(p.errs) < maxErrors {
		p.errs = append(p.errs, Error{t.line, t.col, msg})
	}
	panic(bailout{})
}

func (p *parser) expect(op string) {
	if !p.accept(op) {
		p.fail("expected '" + op + "', found " + p.tok().describe())
	}
}

func (p *parser) expectKw(w string) {
	if !p.acceptKw(w) {
		p.fail("expected '" + w + "', found " + p.tok().describe())
	}
}

func (p *parser) name() string {
	t := p.tok()
	if t.kind != tName || keywords[t.val] {
		p.fail("expected a name, found " + t.describe())
	}
	p.advance()
	return t.val
}

func (p *parser) skipNewlines() {
	for p.tok().kind == tNewline {
		p.advance()
	}
}

// recoverTo turns a bailout into a recovered error; with sync it skips to
// the end of the broken statement first.
func (p *parser) recoverTo(sync func()) {
	if r := recover(); r != nil {
		if _, ok := r.(bailout); !ok {
			panic(r)
		}
		if sync != nil {
			sync()
		}
	}
}

// syncStatement skips the rest of a broken logical line and, if a block
// follows it, the whole block.
func (p *parser) syncStatement() {
	for {
		k := p.tok().kind
		if k == tEOF || k == tDedent {
			return
		}
		if k == tIndent {
			p.skipBlock()
			continue
		}
		p.advance()
		if k == tNewline {
			if p.tok().kind == tIndent {
				p.skipBlock()
			}
			return
		}
	}
}

func (p *parser) skipBlock() {
	depth := 0
	for {
		switch p.tok().kind {
		case tEOF:
			return
		case tIndent:
			depth++
		case tDedent:
			depth--
			if depth == 0 {
				p.advance()
				return
			}
		}
		p.advance()
	}
}

var keywords = map[string]bool{
	"False": true, "None": true, "True": true, "and": true, "as": true, "assert": true, "async": true, "await": true,
	"break": true, "class": true, "continue": true, "def": true, "del": true, "elif": true, "else": true, "except": true,
	"finally": true, "for": true, "from": true, "global": true, "if": true, "import": true, "in": true, "is": true,
	"lambda": true, "nonlocal": true, "not": true, "or": true, "pass": true, "raise": true, "return": true, "try": true,
	"while": true, "with": true, "yield": true,
}

// ---- statements ----

func (p *parser) statements(done func() bool) []Stmt {
	var out []Stmt
	for !done() {
		switch p.tok().kind {
		case tNewline:
			p.advance()
			continue
		case tIndent:
			if len(p.errs) < maxErrors {
				t := p.tok()
				p.errs = append(p.errs, Error{t.line, t.col, "unexpected indent"})
			}
			p.advance()
			out = append(out, p.statements(func() bool { k := p.tok().kind; return k == tDedent || k == tEOF })...)
			if p.tok().kind == tDedent {
				p.advance()
			}
			continue
		case tDedent:
			// A dedent the caller does not expect: skip it.
			p.advance()
			continue
		}
		start := p.i
		out = append(out, p.statement()...)
		if p.i == start {
			p.advance() // guarantee progress
		}
	}
	return out
}

// statement parses one statement; a line of simple statements separated
// by semicolons gives several.
func (p *parser) statement() (out []Stmt) {
	pos := p.pos()
	defer p.recoverTo(func() {
		p.syncStatement()
		out = append(out, &BadStmt{pos})
	})
	t := p.tok()
	if t.kind == tName {
		switch t.val {
		case "if":
			return []Stmt{p.ifStmt()}
		case "while":
			return []Stmt{p.whileStmt()}
		case "for":
			return []Stmt{p.forStmt(false)}
		case "try":
			return []Stmt{p.tryStmt()}
		case "with":
			return []Stmt{p.withStmt(false)}
		case "def":
			return []Stmt{p.funcDef(nil, false)}
		case "class":
			return []Stmt{p.classDef(nil)}
		case "async":
			return []Stmt{p.asyncStmt(nil)}
		case "match":
			if p.isMatchStmt() {
				return []Stmt{p.matchStmt()}
			}
		}
	}
	if t.is("@") {
		return []Stmt{p.decorated()}
	}
	return p.simpleStmts()
}

func (p *parser) simpleStmts() []Stmt {
	var out []Stmt
	for {
		out = append(out, p.smallStmt())
		if !p.accept(";") {
			break
		}
		if k := p.tok().kind; k == tNewline || k == tEOF {
			break
		}
	}
	switch p.tok().kind {
	case tNewline:
		p.advance()
	case tEOF, tDedent:
	default:
		p.fail("expected end of statement, found " + p.tok().describe())
	}
	return out
}

func (p *parser) smallStmt() Stmt {
	pos := p.pos()
	t := p.tok()
	if t.kind == tName {
		switch t.val {
		case "pass":
			p.advance()
			return &Pass{pos}
		case "break":
			p.advance()
			return &Break{pos}
		case "continue":
			p.advance()
			return &Continue{pos}
		case "return":
			p.advance()
			var x Expr
			if !p.atStmtEnd() {
				x = p.starExprs()
			}
			return &Return{pos, x}
		case "raise":
			p.advance()
			r := &Raise{Pos: pos}
			if !p.atStmtEnd() {
				r.Exc = p.expr()
				if p.acceptKw("from") {
					r.Cause = p.expr()
				}
			}
			return r
		case "global", "nonlocal":
			p.advance()
			names := []string{p.name()}
			for p.accept(",") {
				names = append(names, p.name())
			}
			if t.val == "global" {
				return &Global{pos, names}
			}
			return &Nonlocal{pos, names}
		case "del":
			p.advance()
			var ts []Expr
			for {
				ts = append(ts, p.bitor())
				if !p.accept(",") || p.atStmtEnd() {
					break
				}
			}
			return &Delete{pos, ts}
		case "assert":
			p.advance()
			a := &Assert{Pos: pos, Test: p.expr()}
			if p.accept(",") {
				a.Msg = p.expr()
			}
			return a
		case "import":
			p.advance()
			return p.importStmt(pos)
		case "from":
			p.advance()
			return p.fromImport(pos)
		case "type":
			if n := p.peekAt(1); n.kind == tName && !keywords[n.val] {
				if a := p.peekAt(2); a.is("=") || a.is("[") {
					p.advance()
					name := &Name{p.pos(), p.name()}
					tps := p.typeParams()
					p.expect("=")
					return &TypeAlias{pos, name, tps, p.expr()}
				}
			}
		}
	}
	return p.exprStmt(pos)
}

func (p *parser) atStmtEnd() bool {
	k := p.tok().kind
	return k == tNewline || k == tEOF || k == tDedent || p.at(";")
}

var augOps = map[string]bool{"+=": true, "-=": true, "*=": true, "/=": true, "//=": true, "%=": true, "**=": true, "@=": true, "&=": true, "|=": true, "^=": true, ">>=": true, "<<=": true}

func (p *parser) exprStmt(pos Pos) Stmt {
	if p.atKw("yield") {
		return &ExprStmt{pos, p.yieldExpr()}
	}
	x := p.starExprs()
	if p.at(":") {
		p.advance()
		a := &AnnAssign{Pos: pos, Target: x, Ann: p.expr()}
		if p.accept("=") {
			a.Value = p.rhs()
		}
		return a
	}
	if t := p.tok(); t.kind == tOp && augOps[t.val] {
		p.advance()
		return &AugAssign{pos, x, strings.TrimSuffix(t.val, "="), p.rhs()}
	}
	if p.at("=") {
		targets := []Expr{x}
		var value Expr
		for p.accept("=") {
			value = p.rhs()
			if p.at("=") {
				targets = append(targets, value)
			}
		}
		return &Assign{pos, targets, value}
	}
	return &ExprStmt{pos, x}
}

func (p *parser) rhs() Expr {
	if p.atKw("yield") {
		return p.yieldExpr()
	}
	return p.starExprs()
}

func (p *parser) yieldExpr() Expr {
	pos := p.pos()
	p.expectKw("yield")
	if p.acceptKw("from") {
		return &Yield{pos, p.expr(), true}
	}
	y := &Yield{Pos: pos}
	if !p.atStmtEnd() && !p.at(")") && !p.at("]") && !p.at("}") && !p.at("=") {
		y.X = p.starExprs()
	}
	return y
}

func (p *parser) dottedName() string {
	s := p.name()
	for p.at(".") {
		p.advance()
		s += "." + p.name()
	}
	return s
}

func (p *parser) importStmt(pos Pos) Stmt {
	var names []*Alias
	for {
		a := &Alias{Name: p.dottedName()}
		if p.acceptKw("as") {
			a.AsName = p.name()
		}
		names = append(names, a)
		if !p.accept(",") {
			break
		}
	}
	return &Import{pos, names}
}

func (p *parser) fromImport(pos Pos) Stmt {
	im := &ImportFrom{Pos: pos}
	for p.at(".") || p.at("...") {
		if p.advance().val == "..." {
			im.Level += 3
		} else {
			im.Level++
		}
	}
	if !p.atKw("import") {
		im.Module = p.dottedName()
	}
	p.expectKw("import")
	if p.accept("*") {
		im.Names = []*Alias{{Name: "*"}}
		return im
	}
	paren := p.accept("(")
	for {
		if paren && p.at(")") {
			break
		}
		a := &Alias{Name: p.name()}
		if p.acceptKw("as") {
			a.AsName = p.name()
		}
		im.Names = append(im.Names, a)
		if !p.accept(",") {
			break
		}
	}
	if paren {
		p.skipNewlines()
		p.expect(")")
	}
	return im
}

// block parses ':' and an indented block or simple statements on the same
// line.
func (p *parser) block() []Stmt {
	p.expect(":")
	if p.tok().kind != tNewline {
		return p.simpleStmts()
	}
	p.advance()
	if p.tok().kind != tIndent {
		p.fail("expected an indented block, found " + p.tok().describe())
	}
	p.advance()
	body := p.statements(func() bool { k := p.tok().kind; return k == tDedent || k == tEOF })
	if p.tok().kind == tDedent {
		p.advance()
	}
	return body
}

func (p *parser) ifStmt() Stmt {
	pos := p.pos()
	p.advance() // if or elif
	s := &If{Pos: pos, Test: p.namedExpr()}
	s.Body = p.block()
	switch {
	case p.atKw("elif"):
		s.Else = []Stmt{p.ifStmt()}
	case p.atKw("else"):
		p.advance()
		s.Else = p.block()
	}
	return s
}

func (p *parser) whileStmt() Stmt {
	pos := p.pos()
	p.advance()
	s := &While{Pos: pos, Test: p.namedExpr()}
	s.Body = p.block()
	if p.acceptKw("else") {
		s.Else = p.block()
	}
	return s
}

func (p *parser) forStmt(async bool) Stmt {
	pos := p.pos()
	p.expectKw("for")
	s := &For{Pos: pos, Async: async, Target: p.targetList()}
	p.expectKw("in")
	s.Iter = p.starExprs()
	s.Body = p.block()
	if p.acceptKw("else") {
		s.Else = p.block()
	}
	return s
}

// targetList parses for-loop and comprehension targets, which stop before
// "in".
func (p *parser) targetList() Expr {
	pos := p.pos()
	var elts []Expr
	comma := false
	for {
		if p.at("*") {
			sp := p.pos()
			p.advance()
			elts = append(elts, &Starred{sp, p.bitor()})
		} else {
			elts = append(elts, p.bitor())
		}
		if !p.at(",") {
			break
		}
		p.advance()
		comma = true
		if p.atKw("in") || p.at("=") {
			break
		}
	}
	if len(elts) == 1 && !comma {
		return elts[0]
	}
	return &Tuple{pos, elts}
}

func (p *parser) tryStmt() Stmt {
	pos := p.pos()
	p.advance()
	s := &Try{Pos: pos, Body: p.block()}
	for p.atKw("except") {
		h := &Handler{Pos: p.pos()}
		p.advance()
		if p.accept("*") {
			h.Star = true
		}
		if !p.at(":") {
			h.Type = p.expr()
			if p.at(",") {
				// except A, B: (3.14) means a tuple.
				elts := []Expr{h.Type}
				for p.accept(",") {
					elts = append(elts, p.expr())
				}
				h.Type = &Tuple{h.Type.At(), elts}
			}
			if p.acceptKw("as") {
				h.Name = p.name()
			}
		}
		h.Body = p.block()
		s.Handlers = append(s.Handlers, h)
	}
	if p.acceptKw("else") {
		s.Else = p.block()
	}
	if p.acceptKw("finally") {
		s.Finally = p.block()
	}
	if len(s.Handlers) == 0 && s.Finally == nil {
		p.fail("try without except or finally")
	}
	return s
}

func (p *parser) withStmt(async bool) Stmt {
	pos := p.pos()
	p.expectKw("with")
	s := &With{Pos: pos, Async: async}
	if p.at("(") {
		// with (a as b, c as d): parenthesized items, or an expression
		// that starts with a parenthesis.
		save, nerr := p.i, len(p.errs)
		ok := func() (ok bool) {
			defer func() {
				if r := recover(); r != nil {
					if _, b := r.(bailout); !b {
						panic(r)
					}
					ok = false
				}
			}()
			p.advance()
			var items []*WithItem
			for !p.at(")") {
				items = append(items, p.withItem())
				if !p.accept(",") {
					break
				}
			}
			p.expect(")")
			if !p.at(":") {
				return false
			}
			s.Items = items
			return true
		}()
		if !ok {
			p.i, p.errs = save, p.errs[:nerr]
			s.Items = nil
		}
	}
	if s.Items == nil {
		for {
			s.Items = append(s.Items, p.withItem())
			if !p.accept(",") {
				break
			}
		}
	}
	s.Body = p.block()
	return s
}

func (p *parser) withItem() *WithItem {
	w := &WithItem{Ctx: p.expr()}
	if p.acceptKw("as") {
		w.Target = p.bitor()
	}
	return w
}

func (p *parser) asyncStmt(decos []Expr) Stmt {
	pos := p.pos()
	p.advance()
	switch {
	case p.atKw("def"):
		f := p.funcDef(decos, true).(*FuncDef)
		f.Pos = pos
		return f
	case p.atKw("for"):
		f := p.forStmt(true).(*For)
		f.Pos = pos
		return f
	case p.atKw("with"):
		w := p.withStmt(true).(*With)
		w.Pos = pos
		return w
	}
	p.fail("expected def, for or with after async")
	return nil
}

func (p *parser) decorated() Stmt {
	var decos []Expr
	for p.at("@") {
		p.advance()
		decos = append(decos, p.namedExpr())
		if p.tok().kind != tNewline {
			p.fail("expected end of line after decorator")
		}
		p.advance()
	}
	switch {
	case p.atKw("def"):
		return p.funcDef(decos, false)
	case p.atKw("class"):
		return p.classDef(decos)
	case p.atKw("async"):
		return p.asyncStmt(decos)
	}
	p.fail("expected def or class after decorator")
	return nil
}

// typeParams parses an optional [T, *Ts, **P, U: bound = default] list.
func (p *parser) typeParams() []*Param {
	if !p.accept("[") {
		return nil
	}
	var out []*Param
	for !p.at("]") {
		tp := &Param{Pos: p.pos()}
		switch {
		case p.accept("**"):
			tp.Kind = "**"
		case p.accept("*"):
			tp.Kind = "*"
		}
		tp.Name = p.name()
		if p.accept(":") {
			tp.Ann = p.expr()
		}
		if p.accept("=") {
			if p.at("*") {
				sp := p.pos()
				p.advance()
				tp.Default = &Starred{sp, p.expr()}
			} else {
				tp.Default = p.expr()
			}
		}
		out = append(out, tp)
		if !p.accept(",") {
			break
		}
	}
	p.expect("]")
	return out
}

func (p *parser) funcDef(decos []Expr, async bool) Stmt {
	pos := p.pos()
	p.expectKw("def")
	f := &FuncDef{Pos: pos, Name: p.name(), Decorators: decos, Async: async}
	f.TypeParams = p.typeParams()
	p.expect("(")
	f.Params = p.params(")", true)
	p.expect(")")
	if p.accept("->") {
		f.Returns = p.expr()
	}
	f.Body = p.block()
	return f
}

// params parses a parameter list up to end; annotations only for def.
func (p *parser) params(end string, ann bool) []*Param {
	var out []*Param
	for !p.at(end) {
		pr := &Param{Pos: p.pos()}
		switch {
		case p.accept("/"):
			pr.Kind = "/"
		case p.accept("**"):
			pr.Kind = "**"
			pr.Name = p.name()
		case p.accept("*"):
			if p.at(",") || p.at(end) {
				pr.Kind = "*marker"
			} else {
				pr.Kind = "*"
				pr.Name = p.name()
			}
		default:
			pr.Name = p.name()
		}
		if ann && pr.Name != "" && p.accept(":") {
			if pr.Kind == "*" && p.at("*") {
				sp := p.pos()
				p.advance()
				pr.Ann = &Starred{sp, p.expr()}
			} else {
				pr.Ann = p.expr()
			}
		}
		if pr.Kind == "" && p.accept("=") {
			pr.Default = p.expr()
		}
		out = append(out, pr)
		if !p.accept(",") {
			break
		}
	}
	return out
}

func (p *parser) classDef(decos []Expr) Stmt {
	pos := p.pos()
	p.expectKw("class")
	c := &ClassDef{Pos: pos, Name: p.name(), Decorators: decos}
	c.TypeParams = p.typeParams()
	if p.accept("(") {
		c.Bases = p.args()
		p.expect(")")
	}
	c.Body = p.block()
	return c
}

// isMatchStmt tells the soft keyword match from a name: the logical line
// must end with ':' and the next token must start an expression.
func (p *parser) isMatchStmt() bool {
	n := p.peekAt(1)
	switch n.kind {
	case tNewline, tEOF, tIndent, tDedent:
		return false
	case tOp:
		switch n.val {
		case "(", "[", "{", "-", "*", "~", "...":
		default:
			return false
		}
	case tName:
		if keywords[n.val] && n.val != "not" && n.val != "lambda" && n.val != "None" && n.val != "True" && n.val != "False" && n.val != "await" {
			return false
		}
	}
	depth := 0
	last := token{}
	for j := p.i + 1; j < len(p.toks); j++ {
		t := p.toks[j]
		if t.kind == tNewline || t.kind == tEOF {
			return last.is(":") && depth == 0
		}
		if t.kind == tOp {
			switch t.val {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			}
		}
		last = t
	}
	return false
}

func (p *parser) matchStmt() Stmt {
	pos := p.pos()
	p.advance()
	m := &Match{Pos: pos, Subject: p.starExprs()}
	p.expect(":")
	if p.tok().kind != tNewline {
		p.fail("expected a block of case clauses")
	}
	p.advance()
	if p.tok().kind != tIndent {
		p.fail("expected an indented block of case clauses")
	}
	p.advance()
	for p.tok().kind != tDedent && p.tok().kind != tEOF {
		if p.tok().kind == tNewline {
			p.advance()
			continue
		}
		if !p.atKw("case") {
			p.fail("expected 'case', found " + p.tok().describe())
		}
		c := &Case{Pos: p.pos()}
		p.advance()
		c.Pattern = p.patterns()
		if p.acceptKw("if") {
			c.Guard = p.namedExpr()
		}
		c.Body = p.block()
		m.Cases = append(m.Cases, c)
	}
	if p.tok().kind == tDedent {
		p.advance()
	}
	return m
}

// patterns parses an open sequence of case patterns.
func (p *parser) patterns() Expr {
	old := p.inPattern
	p.inPattern = true
	defer func() { p.inPattern = old }()
	pos := p.pos()
	first := p.pattern()
	if !p.at(",") {
		return first
	}
	elts := []Expr{first}
	for p.accept(",") {
		if p.at(":") || p.atKw("if") {
			break
		}
		elts = append(elts, p.pattern())
	}
	return &Tuple{pos, elts}
}

// pattern parses one pattern: alternatives joined by |, then as name.
func (p *parser) pattern() Expr {
	pos := p.pos()
	if p.at("*") {
		p.advance()
		return &Starred{pos, &Name{p.pos(), p.name()}}
	}
	if p.at("**") {
		p.advance()
		return &Starred{pos, &Name{p.pos(), p.name()}}
	}
	x := p.closedPattern()
	for p.at("|") {
		p.advance()
		x = &BinOp{pos, "|", x, p.closedPattern()}
	}
	if p.acceptKw("as") {
		return &MatchAs{pos, x, p.name()}
	}
	return x
}

func (p *parser) closedPattern() Expr { return p.sum() }

// ---- expressions ----

// starExprs parses a comma list of expressions and *x, giving a Tuple when
// there is a comma.
func (p *parser) starExprs() Expr {
	pos := p.pos()
	first := p.starOrNamed()
	if !p.at(",") {
		return first
	}
	elts := []Expr{first}
	for p.accept(",") {
		if p.atExprEnd() {
			break
		}
		elts = append(elts, p.starOrNamed())
	}
	return &Tuple{pos, elts}
}

// atExprEnd reports a token that cannot start an expression after a
// trailing comma.
func (p *parser) atExprEnd() bool {
	t := p.tok()
	switch t.kind {
	case tNewline, tEOF, tDedent, tIndent:
		return true
	case tOp:
		switch t.val {
		case ")", "]", "}", "=", ":", ";":
			return true
		}
		return augOps[t.val]
	case tName:
		return false
	}
	return false
}

func (p *parser) starOrNamed() Expr {
	if p.at("*") {
		pos := p.pos()
		p.advance()
		return &Starred{pos, p.bitor()}
	}
	if p.inPattern {
		return p.pattern()
	}
	return p.namedExpr()
}

func (p *parser) namedExpr() Expr {
	if t := p.tok(); t.kind == tName && !keywords[t.val] && p.peekAt(1).is(":=") {
		pos := p.pos()
		p.advance()
		p.advance()
		return &NamedExpr{pos, &Name{pos, t.val}, p.expr()}
	}
	return p.expr()
}

func (p *parser) expr() Expr {
	if p.atKw("lambda") {
		return p.lambda()
	}
	pos := p.pos()
	x := p.disjunction()
	if p.atKw("if") && !p.inPattern {
		// x if test else y; an if without else belongs to a comprehension.
		save := p.i
		p.advance()
		test := p.disjunction()
		if !p.acceptKw("else") {
			p.i = save
			return x
		}
		return &IfExp{pos, test, x, p.expr()}
	}
	return x
}

func (p *parser) lambda() Expr {
	pos := p.pos()
	p.advance()
	l := &Lambda{Pos: pos, Params: p.params(":", false)}
	p.expect(":")
	l.Body = p.expr()
	return l
}

func (p *parser) disjunction() Expr {
	pos := p.pos()
	x := p.conjunction()
	if !p.atKw("or") {
		return x
	}
	vals := []Expr{x}
	for p.acceptKw("or") {
		vals = append(vals, p.conjunction())
	}
	return &BoolOp{pos, "or", vals}
}

func (p *parser) conjunction() Expr {
	pos := p.pos()
	x := p.inversion()
	if !p.atKw("and") {
		return x
	}
	vals := []Expr{x}
	for p.acceptKw("and") {
		vals = append(vals, p.inversion())
	}
	return &BoolOp{pos, "and", vals}
}

func (p *parser) inversion() Expr {
	if p.atKw("not") {
		pos := p.pos()
		p.advance()
		return &UnaryOp{pos, "not", p.inversion()}
	}
	return p.comparison()
}

func (p *parser) compOp() string {
	t := p.tok()
	switch {
	case t.kind == tOp:
		switch t.val {
		case "<", ">", "==", ">=", "<=", "!=", "<>":
			p.advance()
			return t.val
		}
	case t.kw("in"):
		p.advance()
		return "in"
	case t.kw("not") && p.peekAt(1).kw("in"):
		p.advance()
		p.advance()
		return "not in"
	case t.kw("is"):
		p.advance()
		if p.acceptKw("not") {
			return "is not"
		}
		return "is"
	}
	return ""
}

func (p *parser) comparison() Expr {
	pos := p.pos()
	x := p.bitor()
	var ops []string
	var rights []Expr
	for {
		op := p.compOp()
		if op == "" {
			break
		}
		ops = append(ops, op)
		rights = append(rights, p.bitor())
	}
	if ops == nil {
		return x
	}
	return &Compare{pos, x, ops, rights}
}

// binary parses a left-associative level of binary operators.
func (p *parser) binary(next func() Expr, ops ...string) Expr {
	pos := p.pos()
	x := next()
	for {
		t := p.tok()
		matched := false
		if t.kind == tOp {
			for _, o := range ops {
				if t.val == o {
					matched = true
					break
				}
			}
		}
		if !matched {
			return x
		}
		p.advance()
		x = &BinOp{pos, t.val, x, next()}
	}
}

func (p *parser) bitor() Expr {
	if p.inPattern {
		return p.bitxor()
	}
	return p.binary(p.bitxor, "|")
}
func (p *parser) bitxor() Expr { return p.binary(p.bitand, "^") }
func (p *parser) bitand() Expr { return p.binary(p.shift, "&") }
func (p *parser) shift() Expr  { return p.binary(p.sum, "<<", ">>") }
func (p *parser) sum() Expr    { return p.binary(p.term, "+", "-") }
func (p *parser) term() Expr   { return p.binary(p.factor, "*", "/", "//", "%", "@") }

func (p *parser) factor() Expr {
	t := p.tok()
	if t.is("+") || t.is("-") || t.is("~") {
		pos := p.pos()
		p.advance()
		return &UnaryOp{pos, t.val, p.factor()}
	}
	return p.power()
}

func (p *parser) power() Expr {
	pos := p.pos()
	x := p.awaitPrimary()
	if p.accept("**") {
		return &BinOp{pos, "**", x, p.factor()}
	}
	return x
}

func (p *parser) awaitPrimary() Expr {
	if p.atKw("await") {
		pos := p.pos()
		p.advance()
		return &Await{pos, p.primary()}
	}
	return p.primary()
}

func (p *parser) primary() Expr {
	// A trailer starts where its primary starts, including the opening
	// parenthesis of a parenthesized expression, as in CPython.
	start := p.pos()
	x := p.atom()
	for {
		switch {
		case p.at("."):
			p.advance()
			t := p.tok()
			if t.kind != tName {
				p.fail("expected an attribute name, found " + t.describe())
			}
			p.advance()
			x = &Attribute{start, x, t.val}
		case p.at("("):
			lparen := p.pos()
			p.advance()
			args := p.argsAt(lparen)
			p.expect(")")
			x = &Call{start, x, args}
		case p.at("["):
			p.advance()
			idx := p.subscript()
			p.expect("]")
			x = &Subscript{start, x, idx}
		default:
			return x
		}
	}
}

// args parses call arguments up to ")".
func (p *parser) args() []*Arg { return p.argsAt(p.pos()) }

// argsAt parses call arguments; lparen is where a generator expression
// that is the only argument starts.
func (p *parser) argsAt(lparen Pos) []*Arg {
	var out []*Arg
	for !p.at(")") {
		a := &Arg{Pos: p.pos()}
		switch {
		case p.accept("**"):
			a.Star = "**"
			a.Value = p.expr()
		case p.accept("*"):
			a.Star = "*"
			a.Value = p.expr()
		case p.tok().kind == tName && !keywords[p.tok().val] && p.peekAt(1).is("="):
			a.Name = p.advance().val
			p.advance()
			a.Value = p.expr()
		default:
			v := p.starOrNamedArg()
			if p.atKw("for") || p.atKw("async") && p.peekAt(1).kw("for") {
				v = &Comp{Pos: lparen, Kind: "gen", Elt: v, Gens: p.comprehensions()}
			}
			a.Value = v
		}
		out = append(out, a)
		if !p.accept(",") {
			break
		}
	}
	return out
}

func (p *parser) starOrNamedArg() Expr {
	if p.inPattern {
		return p.pattern()
	}
	return p.namedExpr()
}

// subscript parses the inside of [...]: one index, a slice, or several.
func (p *parser) subscript() Expr {
	pos := p.pos()
	first := p.sliceItem()
	if !p.at(",") {
		return first
	}
	elts := []Expr{first}
	for p.accept(",") {
		if p.at("]") {
			break
		}
		elts = append(elts, p.sliceItem())
	}
	return &Tuple{pos, elts}
}

func (p *parser) sliceItem() Expr {
	pos := p.pos()
	var lo Expr
	if !p.at(":") {
		if p.at("*") {
			p.advance()
			return &Starred{pos, p.bitor()}
		}
		lo = p.namedExpr()
		if !p.at(":") {
			return lo
		}
	}
	p.expect(":")
	s := &Slice{Pos: pos, Lo: lo}
	if !p.at(":") && !p.at(",") && !p.at("]") {
		s.Hi = p.expr()
	}
	if p.accept(":") && !p.at(",") && !p.at("]") {
		s.Step = p.expr()
	}
	return s
}

func (p *parser) comprehensions() []*Comprehension {
	var out []*Comprehension
	for p.atKw("for") || p.atKw("async") && p.peekAt(1).kw("for") {
		c := &Comprehension{}
		if p.acceptKw("async") {
			c.Async = true
		}
		p.expectKw("for")
		c.Target = p.targetList()
		p.expectKw("in")
		c.Iter = p.disjunction()
		for p.atKw("if") {
			p.advance()
			c.Ifs = append(c.Ifs, p.disjunction())
		}
		out = append(out, c)
	}
	return out
}

func (p *parser) atom() Expr {
	pos := p.pos()
	t := p.tok()
	switch t.kind {
	case tName:
		switch t.val {
		case "True":
			p.advance()
			return &Const{pos, ConstTrue, "True"}
		case "False":
			p.advance()
			return &Const{pos, ConstFalse, "False"}
		case "None":
			p.advance()
			return &Const{pos, ConstNone, "None"}
		case "yield":
			return p.yieldExpr()
		case "lambda":
			return p.lambda()
		}
		if keywords[t.val] {
			p.fail("unexpected keyword '" + t.val + "'")
		}
		p.advance()
		return &Name{pos, t.val}
	case tNumber:
		p.advance()
		return &Const{pos, ConstNum, t.val}
	case tString:
		return p.strings()
	case tOp:
		switch t.val {
		case "...":
			p.advance()
			return &Const{pos, ConstEllipsis, "..."}
		case "(":
			return p.parenAtom()
		case "[":
			return p.listAtom()
		case "{":
			return p.braceAtom()
		}
	}
	p.fail("unexpected " + t.describe())
	return nil
}

func (p *parser) parenAtom() Expr {
	pos := p.pos()
	p.advance()
	if p.accept(")") {
		return &Tuple{pos, nil}
	}
	if p.atKw("yield") {
		y := p.yieldExpr()
		p.expect(")")
		return y
	}
	first := p.starOrNamed()
	if p.atKw("for") || p.atKw("async") && p.peekAt(1).kw("for") {
		c := &Comp{Pos: pos, Kind: "gen", Elt: first, Gens: p.comprehensions()}
		p.expect(")")
		return c
	}
	if !p.at(",") {
		p.expect(")")
		return first
	}
	elts := []Expr{first}
	for p.accept(",") {
		if p.at(")") {
			break
		}
		elts = append(elts, p.starOrNamed())
	}
	p.expect(")")
	return &Tuple{pos, elts}
}

func (p *parser) listAtom() Expr {
	pos := p.pos()
	p.advance()
	if p.accept("]") {
		return &List{pos, nil}
	}
	first := p.starOrNamed()
	if p.atKw("for") || p.atKw("async") && p.peekAt(1).kw("for") {
		c := &Comp{Pos: pos, Kind: "list", Elt: first, Gens: p.comprehensions()}
		p.expect("]")
		return c
	}
	elts := []Expr{first}
	for p.accept(",") {
		if p.at("]") {
			break
		}
		elts = append(elts, p.starOrNamed())
	}
	p.expect("]")
	return &List{pos, elts}
}

func (p *parser) braceAtom() Expr {
	pos := p.pos()
	p.advance()
	if p.accept("}") {
		return &Dict{Pos: pos}
	}
	// Dict: key: value or **mapping; set: values.
	if p.at("**") {
		return p.dictRest(pos, nil, nil)
	}
	first := p.starOrNamed()
	if p.accept(":") {
		var v Expr
		if p.inPattern {
			v = p.pattern()
		} else {
			v = p.expr()
		}
		if p.atKw("for") || p.atKw("async") && p.peekAt(1).kw("for") {
			c := &Comp{Pos: pos, Kind: "dict", Key: first, Elt: v, Gens: p.comprehensions()}
			p.expect("}")
			return c
		}
		return p.dictRest(pos, []Expr{first}, []Expr{v})
	}
	if p.atKw("for") || p.atKw("async") && p.peekAt(1).kw("for") {
		c := &Comp{Pos: pos, Kind: "set", Elt: first, Gens: p.comprehensions()}
		p.expect("}")
		return c
	}
	elts := []Expr{first}
	for p.accept(",") {
		if p.at("}") {
			break
		}
		elts = append(elts, p.starOrNamed())
	}
	p.expect("}")
	return &Set{pos, elts}
}

func (p *parser) dictRest(pos Pos, keys, vals []Expr) Expr {
	d := &Dict{Pos: pos, Keys: keys, Values: vals}
	if keys != nil && !p.accept(",") {
		p.expect("}")
		return d
	}
	for !p.at("}") {
		if p.accept("**") {
			d.Keys = append(d.Keys, nil)
			if p.inPattern {
				d.Values = append(d.Values, &Name{p.pos(), p.name()})
			} else {
				d.Values = append(d.Values, p.bitor())
			}
		} else {
			var k Expr
			if p.inPattern {
				k = p.pattern()
			} else {
				k = p.expr()
			}
			p.expect(":")
			var v Expr
			if p.inPattern {
				v = p.pattern()
			} else {
				v = p.expr()
			}
			d.Keys = append(d.Keys, k)
			d.Values = append(d.Values, v)
		}
		if !p.accept(",") {
			break
		}
	}
	p.expect("}")
	return d
}

// strings parses adjacent string literals into one Const or FString.
func (p *parser) strings() Expr {
	pos := p.pos()
	var parts []Expr
	var text strings.Builder
	isF, isBytes := false, false
	for p.tok().kind == tString {
		t := p.advance()
		lit := decodeLiteral(t.val)
		if lit.bytes {
			isBytes = true
		}
		if !lit.fmt {
			text.WriteString(lit.value)
			continue
		}
		isF = true
		fparts, errs := parseFString(lit.body, lit.raw, t.line, t.col+lit.offset)
		for _, e := range errs {
			if len(p.errs) < maxErrors {
				p.errs = append(p.errs, e)
			}
		}
		for _, fp := range fparts {
			if c, ok := fp.(*Const); ok {
				text.WriteString(c.Val)
				continue
			}
			if text.Len() > 0 {
				parts = append(parts, &Const{pos, ConstStr, text.String()})
				text.Reset()
			}
			parts = append(parts, fp)
		}
	}
	if !isF {
		k := ConstStr
		if isBytes {
			k = ConstBytes
		}
		return &Const{pos, k, text.String()}
	}
	if text.Len() > 0 {
		parts = append(parts, &Const{pos, ConstStr, text.String()})
	}
	return &FString{pos, parts}
}
