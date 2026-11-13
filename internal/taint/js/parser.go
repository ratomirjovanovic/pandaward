package js

import (
	"fmt"
	"strings"
)

// Options selects the dialect. TS enables TypeScript syntax; JSX enables
// JSX elements. A .tsx file has both, a .ts file only TS (where <T>x is a
// type assertion), a .js file JSX (a < at the start of an expression can
// only be JSX in plain JavaScript).
type Options struct {
	TS  bool
	JSX bool
}

// OptionsFor picks the dialect from a file name.
func OptionsFor(path string) Options {
	p := strings.ToLower(path)
	switch {
	case strings.HasSuffix(p, ".tsx"):
		return Options{TS: true, JSX: true}
	case strings.HasSuffix(p, ".ts"), strings.HasSuffix(p, ".mts"), strings.HasSuffix(p, ".cts"):
		return Options{TS: true}
	default:
		return Options{JSX: true}
	}
}

// maxDepth bounds recursion; deeper nesting is reported and skipped.
const maxDepth = 400

// maxErrors stops recording errors after this many; parsing goes on.
const maxErrors = 200

// Parse parses src. It never fails: syntax errors are recorded in
// File.Errors and the statements around them are kept.
func Parse(path, src string, opt Options) *File {
	p := &parser{lx: newLexer(src), src: src, ts: opt.TS || flowPragma(src), jsx: opt.JSX}
	p.next()
	f := &File{Path: path}
	for p.tok.Kind != TEOF {
		if p.is("}") {
			p.errorf("unexpected }")
			p.next()
			continue
		}
		f.Stmts = append(f.Stmts, p.safeStmt())
	}
	f.Errors = p.errs
	return f
}

// flowPragma reports a Flow-annotated file: its type annotations are close
// enough to TypeScript's for the type skipper.
func flowPragma(src string) bool {
	head := src
	if len(head) > 2048 {
		head = head[:2048]
	}
	return strings.Contains(head, "@flow")
}

type parser struct {
	lx    *lexer
	src   string
	tok   Token
	ts    bool
	jsx   bool
	errs  []Error
	depth int
	// noIn forbids the in operator (the init clause of a for loop).
	noIn bool
	// inGen and inAsync are set inside generator and async functions;
	// fnDepth counts enclosing functions.
	inGen, inAsync bool
	fnDepth        int
	// bailPos is the token position where the last bailout happened.
	bailPos int
}

// bailout unwinds to the nearest statement list or speculative parse.
type bailout struct{}

type state struct {
	pos, line int
	tok       Token
	nerr      int
}

func (p *parser) save() state { return state{p.lx.pos, p.lx.line, p.tok, len(p.errs)} }

func (p *parser) restore(s state) {
	p.lx.seek(s.pos, s.line)
	p.tok = s.tok
	p.errs = p.errs[:s.nerr]
}

func (p *parser) next() { p.tok = p.lx.next() }

// peek returns the token after the current one.
func (p *parser) peek() Token { return p.lx.peekNext() }

func (p *parser) is(v string) bool { return p.tok.Kind == TPunct && p.tok.Val == v }

func (p *parser) isWord(v string) bool { return p.tok.Kind == TIdent && p.tok.Val == v }

func isPunct(t Token, v string) bool { return t.Kind == TPunct && t.Val == v }

func (p *parser) eat(v string) bool {
	if p.is(v) {
		p.next()
		return true
	}
	return false
}

func (p *parser) errorf(format string, args ...any) {
	if len(p.errs) < maxErrors {
		p.errs = append(p.errs, Error{Line: p.tok.Line, Msg: fmt.Sprintf(format, args...)})
	}
}

// fail records an error and unwinds.
func (p *parser) fail(format string, args ...any) {
	p.errorf(format, args...)
	p.bailPos = p.tok.Pos
	panic(bailout{})
}

func (p *parser) expect(v string) {
	if !p.eat(v) {
		p.fail("expected %s, found %q", v, p.tok.Val)
	}
}

func (p *parser) enter() {
	p.depth++
	if p.depth > maxDepth {
		p.depth = 0
		p.fail("nesting too deep")
	}
}

func (p *parser) leave() { p.depth-- }

// semi ends a statement: a semicolon, or automatic insertion before }, at
// the end of input or after a line break.
func (p *parser) semi() {
	if p.eat(";") {
		return
	}
	if p.is("}") || p.tok.Kind == TEOF || p.tok.NL {
		return
	}
	p.fail("expected ;, found %q", p.tok.Val)
}

// safeStmt parses one statement; on a syntax error it skips to the end of
// the statement and returns a BadStmt.
func (p *parser) safeStmt() (st Stmt) {
	start := p.save()
	depth := p.depth
	noIn, inGen, inAsync, fnDepth := p.noIn, p.inGen, p.inAsync, p.fnDepth
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if _, ok := r.(bailout); !ok {
			panic(r)
		}
		p.depth, p.noIn, p.inGen, p.inAsync, p.fnDepth = depth, noIn, inGen, inAsync, fnDepth
		p.syncFrom(start)
		st = &BadStmt{Pos{start.tok.Line}}
	}()
	return p.stmt()
}

// syncFrom rescans from the start of a failed statement, keeping brackets
// balanced, and stops after the semicolon that ends it, before a closing
// brace of the enclosing block, or at a line break past the error.
func (p *parser) syncFrom(start state) {
	// Keep the error that caused the bailout: restore would drop it.
	errs := append([]Error(nil), p.errs...)
	p.restore(start)
	p.errs = errs
	bail := p.bailPos
	depth := 0
	var templates []int // depths at which a template substitution opened
	first := true
	for p.tok.Kind != TEOF {
		if !first && depth == 0 && p.tok.NL && p.tok.Pos > bail {
			return
		}
		first = false
		t := p.tok
		switch {
		case t.Kind == TTemplate && !t.TailTemplate:
			templates = append(templates, depth)
			depth++
		case isPunct(t, "(") || isPunct(t, "[") || isPunct(t, "{"):
			depth++
		case isPunct(t, ")") || isPunct(t, "]"):
			// A stray closer directly inside a template substitution does
			// not close the substitution.
			if n := len(templates); depth > 0 && (n == 0 || templates[n-1] != depth-1) {
				depth--
			}
		case isPunct(t, "}"):
			if depth == 0 {
				return
			}
			depth--
			if n := len(templates); n > 0 && templates[n-1] == depth {
				templates = templates[:n-1]
				p.tok = p.lx.rescanTemplate(t)
				if !p.tok.TailTemplate {
					templates = append(templates, depth)
					depth++
				}
			}
		case isPunct(t, ";") && depth == 0:
			p.next()
			return
		case isPunct(t, "/") || isPunct(t, "/="):
			if regexContext(p.src, t.Pos) {
				if r, ok := p.lx.rescanRegex(t); ok {
					p.tok = r
				}
			}
		}
		p.next()
	}
	// The brackets never balanced: the statement is missing a closer. Skip
	// only to the first line break past the error instead of the rest of
	// the file.
	if depth > 0 {
		p.restore(start)
		p.errs = errs
		for p.tok.Kind != TEOF && !(p.tok.NL && p.tok.Pos > bail) {
			p.next()
		}
		if p.tok.Pos == start.tok.Pos {
			p.next()
		}
	}
}

// regexContext reports whether a slash at i, judged by the preceding
// significant character, starts a regular expression. Used only while
// skipping a broken statement.
func regexContext(src string, i int) bool {
	j := i - 1
	for j >= 0 && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n' || src[j] == '\r') {
		j--
	}
	if j < 0 {
		return true
	}
	c := src[j]
	if strings.IndexByte("(,=:[!&|?{};+-*%~^<>", c) >= 0 {
		return true
	}
	k := j
	for k >= 0 && isIdentByte(src[k]) {
		k--
	}
	switch src[k+1 : j+1] {
	case "return", "typeof", "case", "do", "else", "in", "of", "void", "yield", "await", "delete", "throw", "new", "instanceof":
		return true
	}
	return false
}

// stmtList parses statements up to the closing brace, which it consumes.
func (p *parser) stmtList() []Stmt {
	var list []Stmt
	for !p.is("}") {
		if p.tok.Kind == TEOF {
			p.errorf("unexpected end of input, expected }")
			return list
		}
		list = append(list, p.safeStmt())
	}
	p.next()
	return list
}

func (p *parser) block() *Block {
	b := &Block{Pos: Pos{p.tok.Line}}
	p.expect("{")
	b.List = p.stmtList()
	return b
}

// keywords that cannot be identifiers in expressions.
var reserved = map[string]bool{
	"break": true, "case": true, "catch": true, "class": true, "const": true, "continue": true, "debugger": true, "default": true,
	"delete": true, "do": true, "else": true, "export": true, "extends": true, "finally": true, "for": true, "function": true,
	"if": true, "import": true, "in": true, "instanceof": true, "new": true, "return": true, "switch": true, "throw": true,
	"try": true, "typeof": true, "var": true, "void": true, "while": true, "with": true,
}

func (p *parser) stmt() Stmt {
	p.enter()
	defer p.leave()
	t := p.tok
	ln := Pos{t.Line}
	if t.Kind == TPunct {
		switch t.Val {
		case "{":
			return p.block()
		case ";":
			p.next()
			return &Empty{ln}
		case "@":
			p.decorators()
			return p.stmt()
		}
	}
	if t.Kind != TIdent {
		return p.exprStmt()
	}
	switch t.Val {
	case "var", "const":
		if t.Val == "const" && p.ts && p.peek().Val == "enum" {
			p.next()
			return p.tsEnum()
		}
		p.next()
		d := p.varDecl(t.Val, ln)
		p.semi()
		return d
	case "let":
		if nt := p.peek(); nt.Kind == TIdent && !reserved[nt.Val] || isPunct(nt, "[") || isPunct(nt, "{") {
			p.next()
			d := p.varDecl("let", ln)
			p.semi()
			return d
		}
	case "using":
		if nt := p.peek(); nt.Kind == TIdent && !nt.NL && nt.Val != "in" && nt.Val != "of" {
			p.next()
			d := p.varDecl("using", ln)
			p.semi()
			return d
		}
	case "if":
		p.next()
		s := &If{Pos: ln}
		p.expect("(")
		s.Test = p.expr()
		p.expect(")")
		s.Then = p.stmt()
		if p.isWord("else") {
			p.next()
			s.Else = p.stmt()
		}
		return s
	case "for":
		return p.forStmt()
	case "while":
		p.next()
		s := &While{Pos: ln}
		p.expect("(")
		s.Test = p.expr()
		p.expect(")")
		s.Body = p.stmt()
		return s
	case "do":
		p.next()
		s := &While{Pos: ln, Do: true}
		s.Body = p.stmt()
		if !p.isWord("while") {
			p.fail("expected while")
		}
		p.next()
		p.expect("(")
		s.Test = p.expr()
		p.expect(")")
		p.eat(";")
		return s
	case "return":
		p.next()
		s := &Return{Pos: ln}
		if !p.is(";") && !p.is("}") && p.tok.Kind != TEOF && !p.tok.NL {
			s.X = p.expr()
		}
		p.semi()
		return s
	case "throw":
		p.next()
		s := &Throw{Pos: ln, X: p.expr()}
		p.semi()
		return s
	case "break", "continue":
		p.next()
		s := &Branch{Pos: ln, Tok: t.Val}
		if p.tok.Kind == TIdent && !p.tok.NL && !reserved[p.tok.Val] {
			s.Label = p.tok.Val
			p.next()
		}
		p.semi()
		return s
	case "try":
		return p.tryStmt()
	case "switch":
		return p.switchStmt()
	case "function":
		return &FuncDecl{Pos: ln, Func: p.function(false)}
	case "async":
		if nt := p.peek(); nt.Val == "function" && !nt.NL {
			p.next()
			return &FuncDecl{Pos: ln, Func: p.function(true)}
		}
	case "class":
		return &ClassDecl{Pos: ln, Class: p.class()}
	case "import":
		if nt := p.peek(); !isPunct(nt, "(") && !isPunct(nt, ".") {
			return p.importDecl()
		}
	case "export":
		return p.exportDecl()
	case "debugger":
		p.next()
		p.semi()
		return &Empty{ln}
	case "with":
		p.next()
		p.expect("(")
		x := p.expr()
		p.expect(")")
		return &Block{Pos: ln, List: []Stmt{&ExprStmt{Pos: ln, X: x}, p.stmt()}}
	}
	if p.ts {
		if s := p.tsDecl(); s != nil {
			return s
		}
	}
	// A label.
	if !reserved[t.Val] {
		if nt := p.peek(); isPunct(nt, ":") {
			p.next()
			p.next()
			return &Labeled{Pos: ln, Label: t.Val, Body: p.stmt()}
		}
	}
	return p.exprStmt()
}

func (p *parser) exprStmt() Stmt {
	ln := Pos{p.tok.Line}
	s := &ExprStmt{Pos: ln, X: p.expr()}
	p.semi()
	return s
}

// varDecl parses the declarators after var, let, const or using.
func (p *parser) varDecl(kind string, ln Pos) *VarDecl {
	d := &VarDecl{Pos: ln, Kind: kind}
	for {
		dc := &Declarator{Pos: Pos{p.tok.Line}}
		dc.Target = p.bindingTarget()
		if p.ts {
			p.eat("!")
			if p.eat(":") {
				p.skipType()
			}
		}
		if p.eat("=") {
			dc.Init = p.assign()
		}
		d.Decls = append(d.Decls, dc)
		if !p.eat(",") {
			return d
		}
	}
}

// bindingTarget parses an identifier, object pattern or array pattern.
func (p *parser) bindingTarget() Expr {
	switch {
	case p.is("{"):
		return p.objectLit()
	case p.is("["):
		return p.arrayLit()
	case p.tok.Kind == TIdent:
		id := &Ident{Pos: Pos{p.tok.Line}, Name: p.tok.Val}
		p.next()
		return id
	}
	p.fail("expected a binding name, found %q", p.tok.Val)
	return nil
}

func (p *parser) forStmt() Stmt {
	ln := Pos{p.tok.Line}
	p.next()
	await := false
	if p.isWord("await") {
		await = true
		p.next()
	}
	p.expect("(")
	var init Stmt
	if !p.is(";") {
		outer := p.noIn
		p.noIn = true
		t := p.tok
		switch {
		case t.Kind == TIdent && (t.Val == "var" || t.Val == "const") ||
			t.Kind == TIdent && t.Val == "let" && func() bool {
				nt := p.peek()
				return nt.Kind == TIdent && nt.Val != "in" && nt.Val != "of" || isPunct(nt, "[") || isPunct(nt, "{")
			}() ||
			t.Kind == TIdent && t.Val == "using" && func() bool { nt := p.peek(); return nt.Kind == TIdent && nt.Val != "in" && nt.Val != "of" }():
			p.next()
			init = p.varDecl(t.Val, Pos{t.Line})
		default:
			init = &ExprStmt{Pos: Pos{t.Line}, X: p.expr()}
		}
		p.noIn = outer
	}
	if p.isWord("of") || p.isWord("in") {
		of := p.isWord("of")
		p.next()
		s := &ForIn{Pos: ln, Left: init, Of: of, Await: await}
		if of {
			s.Right = p.assign()
		} else {
			s.Right = p.expr()
		}
		p.expect(")")
		s.Body = p.stmt()
		return s
	}
	s := &For{Pos: ln, Init: init}
	p.expect(";")
	if !p.is(";") {
		s.Test = p.expr()
	}
	p.expect(";")
	if !p.is(")") {
		s.Update = p.expr()
	}
	p.expect(")")
	s.Body = p.stmt()
	return s
}

func (p *parser) tryStmt() Stmt {
	s := &Try{Pos: Pos{p.tok.Line}}
	p.next()
	s.Block = p.block()
	if p.isWord("catch") {
		p.next()
		if p.eat("(") {
			s.Param = p.bindingTarget()
			if p.ts && p.eat(":") {
				p.skipType()
			}
			p.expect(")")
		}
		s.Handler = p.block()
	}
	if p.isWord("finally") {
		p.next()
		s.Finally = p.block()
	}
	return s
}

func (p *parser) switchStmt() Stmt {
	s := &Switch{Pos: Pos{p.tok.Line}}
	p.next()
	p.expect("(")
	s.Disc = p.expr()
	p.expect(")")
	p.expect("{")
	for !p.eat("}") {
		if p.tok.Kind == TEOF {
			p.errorf("unexpected end of input in switch")
			return s
		}
		c := &Case{Pos: Pos{p.tok.Line}}
		switch {
		case p.isWord("case"):
			p.next()
			c.Test = p.expr()
		case p.isWord("default"):
			p.next()
		default:
			p.fail("expected case or default, found %q", p.tok.Val)
		}
		p.expect(":")
		for !p.is("}") && !p.isWord("case") && !p.isWord("default") && p.tok.Kind != TEOF {
			c.Body = append(c.Body, p.safeStmt())
		}
		s.Cases = append(s.Cases, c)
	}
	return s
}

// decorators skips @expr decorators.
func (p *parser) decorators() {
	for p.eat("@") {
		p.lhs(true)
	}
}

func (p *parser) importDecl() Stmt {
	s := &Import{Pos: Pos{p.tok.Line}}
	p.next() // import
	if p.ts && p.isWord("type") {
		if nt := p.peek(); nt.Kind == TIdent && nt.Val != "from" || isPunct(nt, "{") || isPunct(nt, "*") {
			p.next()
		}
	}
	if p.tok.Kind == TString {
		s.Source = p.tok.Val
		p.next()
		p.importAttributes()
		p.semi()
		return s
	}
	// A default import; `import from from 'x'` imports a binding named from.
	if p.tok.Kind == TIdent && (p.tok.Val != "from" || p.peek().Kind == TIdent) {
		local := p.tok.Val
		p.next()
		if p.ts && p.is("=") {
			// import x = require('y') or import x = A.B
			p.next()
			ln := s.Pos
			init := p.assign()
			p.semi()
			return &VarDecl{Pos: ln, Kind: "const", Decls: []*Declarator{{Pos: ln, Target: &Ident{Pos: ln, Name: local}, Init: init}}}
		}
		s.Specs = append(s.Specs, ImportSpec{Imported: "default", Local: local})
		p.eat(",")
	}
	if p.eat("*") {
		if !p.isWord("as") {
			p.fail("expected as")
		}
		p.next()
		s.Specs = append(s.Specs, ImportSpec{Imported: "*", Local: p.tok.Val})
		p.next()
	} else if p.eat("{") {
		for !p.eat("}") {
			if p.ts && p.isWord("type") {
				if nt := p.peek(); nt.Kind == TIdent || nt.Kind == TString {
					p.next()
				}
			}
			if p.tok.Kind != TIdent && p.tok.Kind != TString {
				p.fail("expected an import name, found %q", p.tok.Val)
			}
			imported := p.tok.Val
			local := imported
			p.next()
			if p.isWord("as") {
				p.next()
				local = p.tok.Val
				p.next()
			}
			s.Specs = append(s.Specs, ImportSpec{Imported: imported, Local: local})
			if !p.eat(",") && !p.is("}") {
				p.fail("expected , or }")
			}
		}
	}
	if !p.isWord("from") {
		p.fail("expected from")
	}
	p.next()
	if p.tok.Kind != TString {
		p.fail("expected a module name")
	}
	s.Source = p.tok.Val
	p.next()
	p.importAttributes()
	p.semi()
	return s
}

// importAttributes skips `with { type: 'json' }` and the older `assert`.
func (p *parser) importAttributes() {
	if (p.isWord("with") || p.isWord("assert")) && !p.tok.NL {
		p.next()
		p.skipBalanced("{", "}")
	}
}

func (p *parser) exportDecl() Stmt {
	ln := Pos{p.tok.Line}
	p.next() // export
	s := &Export{Pos: ln}
	switch {
	case p.isWord("default"):
		p.next()
		switch {
		case p.isWord("function"):
			s.Default = p.function(false)
		case p.isWord("async") && p.peek().Val == "function":
			p.next()
			s.Default = p.function(true)
		case p.isWord("class"):
			s.Default = p.class()
		case p.is("@"):
			p.decorators()
			s.Default = p.class()
		case p.ts && p.isWord("interface"):
			p.tsDecl()
			return &Empty{ln}
		case p.ts && p.isWord("abstract") && p.peek().Val == "class":
			p.next()
			s.Default = p.class()
		default:
			s.Default = p.assign()
			p.semi()
		}
		return s
	case p.is("="):
		// TypeScript export = x
		p.next()
		s.Default = p.assign()
		p.semi()
		return s
	case p.is("*") || p.ts && p.isWord("type") && isPunct(p.peek(), "*"):
		if !p.is("*") {
			p.next() // export type * from
		}
		p.next()
		s.All = true
		if p.isWord("as") {
			p.next()
			s.Specs = append(s.Specs, ExportSpec{Local: "*", Exported: p.tok.Val})
			p.next()
		}
		if !p.isWord("from") {
			p.fail("expected from")
		}
		p.next()
		s.From = p.tok.Val
		p.next()
		p.importAttributes()
		p.semi()
		return s
	case p.is("{") || p.ts && p.isWord("type") && isPunct(p.peek(), "{"):
		if !p.is("{") {
			p.next()
		}
		p.next()
		for !p.eat("}") {
			if p.ts && p.isWord("type") {
				if nt := p.peek(); nt.Kind == TIdent || nt.Kind == TString {
					p.next()
				}
			}
			if p.tok.Kind != TIdent && p.tok.Kind != TString {
				p.fail("expected an export name, found %q", p.tok.Val)
			}
			sp := ExportSpec{Local: p.tok.Val, Exported: p.tok.Val}
			p.next()
			if p.isWord("as") {
				p.next()
				sp.Exported = p.tok.Val
				p.next()
			}
			s.Specs = append(s.Specs, sp)
			if !p.eat(",") && !p.is("}") {
				p.fail("expected , or }")
			}
		}
		if p.isWord("from") {
			p.next()
			s.From = p.tok.Val
			p.next()
			p.importAttributes()
		}
		p.semi()
		return s
	case p.ts && p.isWord("as"):
		// export as namespace X;
		p.next()
		p.next()
		p.next()
		p.semi()
		return &Empty{ln}
	case p.ts && p.isWord("import"):
		s.Decl = p.importDecl()
		return s
	}
	s.Decl = p.stmt()
	return s
}

// expr parses a comma expression.
func (p *parser) expr() Expr {
	x := p.assign()
	if !p.is(",") {
		return x
	}
	s := &Seq{Pos: Pos{x.Ln()}, List: []Expr{x}}
	for p.eat(",") {
		s.List = append(s.List, p.assign())
	}
	return s
}

var assignOps = map[string]bool{"=": true, "+=": true, "-=": true, "*=": true, "/=": true, "%=": true, "**=": true, "<<=": true, ">>=": true, ">>>=": true,
	"&=": true, "|=": true, "^=": true, "&&=": true, "||=": true, "??=": true}

func (p *parser) assign() Expr {
	p.enter()
	defer p.leave()
	t := p.tok
	ln := Pos{t.Line}
	if t.Kind == TIdent {
		switch {
		case t.Val == "yield" && p.inGen:
			return p.yield()
		case t.Val == "async":
			nt := p.peek()
			if !nt.NL && (nt.Kind == TIdent && !reserved[nt.Val] || isPunct(nt, "(") || p.ts && isPunct(nt, "<")) {
				s := p.save()
				p.next()
				if f := p.tryArrow(true); f != nil {
					return f
				}
				p.restore(s)
			}
		case !reserved[t.Val]:
			if nt := p.peek(); isPunct(nt, "=>") && !nt.NL {
				return p.tryArrow(false)
			}
		}
	}
	if p.is("(") || p.ts && p.is("<") {
		if f := p.tryArrowAt(); f != nil {
			return f
		}
	}
	left := p.cond()
	if p.tok.Kind == TPunct && assignOps[p.tok.Val] {
		op := p.tok.Val
		p.next()
		return &Assign{Pos: ln, Op: op, Target: left, Value: p.assign()}
	}
	return left
}

func (p *parser) yield() Expr {
	y := &Yield{Pos: Pos{p.tok.Line}}
	p.next()
	if p.eat("*") {
		y.Delegate = true
		y.X = p.assign()
		return y
	}
	if !p.tok.NL && canStartExpr(p.tok) {
		y.X = p.assign()
	}
	return y
}

// tryArrowAt tries an arrow function at ( or <, restoring on failure.
func (p *parser) tryArrowAt() Expr {
	s := p.save()
	if f := p.tryArrow(false); f != nil {
		return f
	}
	p.restore(s)
	return nil
}

// tryArrow parses an arrow function whose parameters start at the current
// token (after async when async is set). It returns nil without restoring
// when the input is not an arrow function; callers restore.
func (p *parser) tryArrow(async bool) (f Expr) {
	ln := Pos{p.tok.Line}
	fn := &Func{Pos: ln, Arrow: true, Async: async}
	ok := func() (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				if _, isBail := r.(bailout); !isBail {
					panic(r)
				}
				ok = false
			}
		}()
		if p.tok.Kind == TIdent {
			fn.Params = []Expr{&Ident{Pos: ln, Name: p.tok.Val}}
			p.next()
		} else {
			if p.ts && p.is("<") {
				p.skipTypeParams()
			}
			if !p.is("(") {
				return false
			}
			fn.Params, _ = p.params()
			if p.ts && p.is(":") {
				p.next()
				p.skipReturnType()
			}
		}
		return p.is("=>") && !p.tok.NL
	}()
	if !ok {
		return nil
	}
	p.next() // =>
	inGen, inAsync := p.inGen, p.inAsync
	p.inGen, p.inAsync = false, async
	p.fnDepth++
	defer func() { p.inGen, p.inAsync = inGen, inAsync; p.fnDepth-- }()
	if p.is("{") {
		noIn := p.noIn
		p.noIn = false
		p.next()
		fn.Body = p.stmtList()
		if fn.Body == nil {
			fn.Body = []Stmt{}
		}
		p.noIn = noIn
	} else {
		fn.ExprBody = p.assign()
	}
	return fn
}

// params parses a parenthesized parameter list and returns the patterns and
// the names declared as properties (TypeScript constructor shorthand).
func (p *parser) params() ([]Expr, []string) {
	p.expect("(")
	noIn := p.noIn
	p.noIn = false
	defer func() { p.noIn = noIn }()
	var list []Expr
	var props []string
	for !p.eat(")") {
		p.decorators()
		isProp := false
		if p.ts {
			for p.tok.Kind == TIdent && tsParamModifiers[p.tok.Val] {
				nt := p.peek()
				if nt.Kind != TIdent && !isPunct(nt, "{") && !isPunct(nt, "[") {
					break
				}
				isProp = true
				p.next()
			}
			if p.isWord("this") {
				if nt := p.peek(); isPunct(nt, ":") {
					p.next()
					p.next()
					p.skipType()
					if !p.eat(",") && !p.is(")") {
						p.fail("expected , or )")
					}
					continue
				}
			}
		}
		var param Expr
		if p.is("...") {
			ln := Pos{p.tok.Line}
			p.next()
			param = &Spread{Pos: ln, X: p.bindingTarget()}
		} else {
			param = p.bindingTarget()
		}
		if id, ok := param.(*Ident); ok && isProp {
			props = append(props, id.Name)
		}
		if p.ts {
			p.eat("?")
			if p.eat(":") {
				p.skipType()
			}
		}
		if p.is("=") {
			ln := Pos{p.tok.Line}
			p.next()
			param = &Assign{Pos: ln, Op: "=", Target: param, Value: p.assign()}
		}
		list = append(list, param)
		if !p.eat(",") && !p.is(")") {
			p.fail("expected , or ) in parameters, found %q", p.tok.Val)
		}
	}
	return list, props
}

var tsParamModifiers = map[string]bool{"public": true, "private": true, "protected": true, "readonly": true, "override": true}

// function parses `function [*] [name] (params) body` at the function
// keyword.
func (p *parser) function(async bool) *Func {
	f := &Func{Pos: Pos{p.tok.Line}, Async: async}
	p.next() // function
	if p.eat("*") {
		f.Generator = true
	}
	if p.tok.Kind == TIdent && !p.is("(") {
		f.Name = p.tok.Val
		p.next()
	}
	p.funcRest(f)
	return f
}

// funcRest parses type parameters, parameters, return type and body.
func (p *parser) funcRest(f *Func) []string {
	inGen, inAsync := p.inGen, p.inAsync
	p.inGen, p.inAsync = f.Generator, f.Async
	p.fnDepth++
	defer func() { p.inGen, p.inAsync = inGen, inAsync; p.fnDepth-- }()
	if p.ts && p.is("<") {
		p.skipTypeParams()
	}
	var props []string
	f.Params, props = p.params()
	if p.ts && p.eat(":") {
		p.skipReturnType()
	}
	if p.is("{") {
		noIn := p.noIn
		p.noIn = false
		p.next()
		f.Body = p.stmtList()
		if f.Body == nil {
			f.Body = []Stmt{}
		}
		p.noIn = noIn
		return props
	}
	// A declaration without body: TypeScript overloads and abstract methods.
	if !p.ts {
		p.fail("expected function body, found %q", p.tok.Val)
	}
	p.semi()
	return props
}

func (p *parser) class() *Class {
	c := &Class{Pos: Pos{p.tok.Line}}
	p.next() // class
	if p.tok.Kind == TIdent && p.tok.Val != "extends" && p.tok.Val != "implements" {
		c.Name = p.tok.Val
		p.next()
	}
	if p.ts && p.is("<") {
		p.skipTypeParams()
	}
	if p.isWord("extends") {
		p.next()
		c.Super = p.lhs(true)
		if p.ts && p.is("<") {
			p.skipTypeArgs()
		}
	}
	if p.ts && p.isWord("implements") {
		p.next()
		for {
			p.skipType()
			if !p.eat(",") {
				break
			}
		}
	}
	p.expect("{")
	for !p.eat("}") {
		if p.tok.Kind == TEOF {
			p.errorf("unexpected end of input in class body")
			return c
		}
		if p.eat(";") {
			continue
		}
		if m := p.safeMember(); m != nil {
			c.Members = append(c.Members, m)
		}
	}
	return c
}

// safeMember parses one class member, skipping it on a syntax error.
func (p *parser) safeMember() (m *ClassMember) {
	start := p.save()
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if _, ok := r.(bailout); !ok {
			panic(r)
		}
		p.syncFrom(start)
		m = nil
	}()
	return p.member()
}

var classModifiers = map[string]bool{"static": true, "public": true, "private": true, "protected": true, "readonly": true,
	"abstract": true, "override": true, "declare": true, "accessor": true, "async": true, "get": true, "set": true}

// isKeyStart reports whether t can start a property key.
func isKeyStart(t Token) bool {
	return t.Kind == TIdent || t.Kind == TString || t.Kind == TNumber || t.Kind == TPrivateName || isPunct(t, "[") || isPunct(t, "*") || isPunct(t, "#")
}

func (p *parser) member() *ClassMember {
	p.decorators()
	m := &ClassMember{Pos: Pos{p.tok.Line}, Kind: "method"}
	async, gen := false, false
	kind := ""
	for p.tok.Kind == TIdent && classModifiers[p.tok.Val] {
		nt := p.peek()
		if p.tok.Val == "static" && isPunct(nt, "{") {
			p.next()
			p.next()
			m.Kind, m.Static = "block", true
			m.Block = p.stmtList()
			return m
		}
		if !isKeyStart(nt) || nt.NL && p.tok.Val != "static" {
			break
		}
		switch p.tok.Val {
		case "static":
			m.Static = true
		case "async":
			async = true
		case "get", "set":
			kind = p.tok.Val
		}
		p.next()
	}
	if p.eat("*") {
		gen = true
	}
	if p.ts && p.is("[") {
		// An index signature: [key: string]: T;
		s := p.save()
		p.next()
		if p.tok.Kind == TIdent {
			p.next()
			if p.is(":") {
				p.restore(s)
				p.skipBalanced("[", "]")
				if p.eat(":") {
					p.skipType()
				}
				p.semi()
				return nil
			}
		}
		p.restore(s)
	}
	m.Key, m.Computed = p.propKey()
	if p.ts {
		if !p.eat("?") {
			p.eat("!")
		}
	}
	if p.is("(") || p.is("<") {
		f := &Func{Pos: m.Pos, Name: m.Key, Async: async, Generator: gen}
		m.ParamProps = p.funcRest(f)
		m.Value = f
		switch {
		case kind != "":
			m.Kind = kind
		case m.Key == "constructor" && m.Computed == nil && !m.Static:
			m.Kind = "constructor"
		}
		return m
	}
	m.Kind = "field"
	if p.ts && p.eat(":") {
		p.skipType()
	}
	if p.eat("=") {
		inGen, inAsync := p.inGen, p.inAsync
		p.inGen, p.inAsync = false, false
		m.Value = p.assign()
		p.inGen, p.inAsync = inGen, inAsync
	}
	p.semi()
	return m
}

// propKey parses a property key: a name, string, number, private name or
// computed [expr].
func (p *parser) propKey() (string, Expr) {
	t := p.tok
	switch t.Kind {
	case TIdent, TString, TNumber, TPrivateName:
		p.next()
		return t.Val, nil
	}
	if p.eat("[") {
		x := p.assign()
		p.expect("]")
		return "", x
	}
	p.fail("expected a property name, found %q", t.Val)
	return "", nil
}

// cond parses a conditional expression.
func (p *parser) cond() Expr {
	test := p.binary(0)
	if !p.is("?") {
		return test
	}
	ln := Pos{test.Ln()}
	p.next()
	noIn := p.noIn
	p.noIn = false
	then := p.assign()
	p.noIn = noIn
	p.expect(":")
	return &Cond{Pos: ln, Test: test, Then: then, Else: p.assign()}
}

var binPrec = map[string]int{
	"??": 1, "||": 2, "&&": 3, "|": 4, "^": 5, "&": 6,
	"==": 7, "!=": 7, "===": 7, "!==": 7,
	"<": 8, ">": 8, "<=": 8, ">=": 8, "instanceof": 8, "in": 8,
	"<<": 9, ">>": 9, ">>>": 9,
	"+": 10, "-": 10, "*": 11, "/": 11, "%": 11, "**": 12,
}

func (p *parser) binOp() (string, int) {
	t := p.tok
	switch t.Kind {
	case TPunct:
		if pr, ok := binPrec[t.Val]; ok {
			return t.Val, pr
		}
	case TIdent:
		switch t.Val {
		case "instanceof":
			return t.Val, 8
		case "in":
			if !p.noIn {
				return t.Val, 8
			}
		case "as", "satisfies":
			if p.ts && !t.NL {
				return t.Val, 8
			}
		}
	}
	return "", 0
}

func (p *parser) binary(min int) Expr {
	left := p.unary()
	for {
		op, prec := p.binOp()
		if prec == 0 || prec <= min && !(op == "**" && prec == min) {
			return left
		}
		if op == "as" || op == "satisfies" {
			p.next()
			if p.isWord("const") {
				p.next()
			} else {
				p.skipType()
			}
			continue
		}
		p.next()
		next := prec
		if op == "**" {
			next = prec - 1 // right associative
		}
		right := p.binary(next)
		left = &Binary{Pos: Pos{left.Ln()}, Op: op, L: left, R: right}
	}
}

func canStartExpr(t Token) bool {
	switch t.Kind {
	case TEOF:
		return false
	case TPunct:
		switch t.Val {
		case "(", "[", "{", "+", "-", "!", "~", "++", "--", "/", "/=", "<", "@", "...", "#":
			return true
		}
		return false
	case TIdent:
		switch t.Val {
		case "in", "of", "instanceof", "as", "satisfies":
			return false
		}
	}
	return true
}

func (p *parser) unary() Expr {
	p.enter()
	defer p.leave()
	t := p.tok
	ln := Pos{t.Line}
	switch t.Kind {
	case TPunct:
		switch t.Val {
		case "!", "~", "+", "-", "++", "--":
			p.next()
			return &Unary{Pos: ln, Op: t.Val, X: p.unary()}
		case "<":
			if p.ts && !p.jsx {
				// A type assertion <T>x.
				p.skipTypeArgs()
				return p.unary()
			}
		}
	case TIdent:
		switch t.Val {
		case "typeof", "void", "delete":
			p.next()
			return &Unary{Pos: ln, Op: t.Val, X: p.unary()}
		case "await":
			// await is the operator in async functions and at module top
			// level; elsewhere only when an operand clearly follows (a
			// function named await can still be called).
			nt := p.peek()
			operand := canStartExpr(nt) && !nt.NL
			if p.inAsync || p.fnDepth == 0 && operand || operand && nt.Kind != TPunct {
				p.next()
				return &Unary{Pos: ln, Op: "await", X: p.unary()}
			}
		}
	}
	x := p.lhs(true)
	if (p.is("++") || p.is("--")) && !p.tok.NL {
		op := p.tok.Val
		p.next()
		return &Unary{Pos: ln, Op: op, X: x, Postfix: true}
	}
	return x
}

// lhs parses a member, call or new expression. With calls false it stops
// before call arguments (the callee of new, decorators).
func (p *parser) lhs(calls bool) Expr {
	var x Expr
	if p.isWord("new") {
		x = p.newExpr()
	} else {
		x = p.primary()
	}
	for {
		t := p.tok
		ln := Pos{x.Ln()}
		switch {
		case isPunct(t, "."):
			p.next()
			x = &Member{Pos: ln, Obj: x, Prop: p.memberName()}
		case isPunct(t, "?."):
			p.next()
			if p.ts && p.is("<") {
				p.tryTypeArgsBeforeCall() // a?.<T>(x)
			}
			switch {
			case p.is("("):
				if !calls {
					return x
				}
				x = &Call{Pos: ln, Callee: x, Args: p.args(), Optional: true}
			case p.is("["):
				p.next()
				k := p.expr()
				p.expect("]")
				x = &Member{Pos: ln, Obj: x, Computed: k, Optional: true}
			default:
				x = &Member{Pos: ln, Obj: x, Prop: p.memberName(), Optional: true}
			}
		case isPunct(t, "["):
			p.next()
			noIn := p.noIn
			p.noIn = false
			k := p.expr()
			p.noIn = noIn
			p.expect("]")
			x = &Member{Pos: ln, Obj: x, Computed: k}
		case isPunct(t, "("):
			if !calls {
				return x
			}
			x = &Call{Pos: ln, Callee: x, Args: p.args()}
		case t.Kind == TTemplate:
			x = p.template(x)
		case p.ts && isPunct(t, "!") && !t.NL:
			p.next() // non-null assertion
		case p.ts && isPunct(t, "<"):
			if !p.tryTypeArgsBeforeCall() {
				return x
			}
		default:
			return x
		}
	}
}

// tryTypeArgsBeforeCall skips f<T>(...) type arguments when they are
// followed by a call or template; otherwise it leaves the < alone.
func (p *parser) tryTypeArgsBeforeCall() bool {
	s := p.save()
	ok := func() (ok bool) {
		defer func() {
			if r := recover(); r != nil {
				if _, isBail := r.(bailout); !isBail {
					panic(r)
				}
				ok = false
			}
		}()
		p.skipTypeArgs()
		return p.is("(") || p.tok.Kind == TTemplate || p.is(".") || p.is("?.") ||
			// f<T> as a value (instantiation expression) before a terminator
			p.is(")") || p.is(";") || p.is(",")
	}()
	if !ok {
		p.restore(s)
	}
	return ok
}

// memberName parses the name after a dot: any identifier including
// keywords, or a private name.
func (p *parser) memberName() string {
	if p.tok.Kind == TIdent || p.tok.Kind == TPrivateName {
		n := p.tok.Val
		p.next()
		return n
	}
	p.fail("expected a property name after ., found %q", p.tok.Val)
	return ""
}

func (p *parser) newExpr() Expr {
	ln := Pos{p.tok.Line}
	p.next() // new
	if p.is(".") {
		p.next()
		name := p.memberName()
		return &Ident{Pos: ln, Name: "new." + name}
	}
	var callee Expr
	if p.isWord("new") {
		callee = p.newExpr()
	} else {
		callee = p.lhs(false)
	}
	if p.ts && p.is("<") {
		p.tryTypeArgsBeforeCall()
	}
	c := &Call{Pos: ln, Callee: callee, New: true}
	if p.is("(") {
		c.Args = p.args()
	}
	return c
}

func (p *parser) args() []Expr {
	p.expect("(")
	noIn := p.noIn
	p.noIn = false
	defer func() { p.noIn = noIn }()
	var list []Expr
	for !p.eat(")") {
		if p.is("...") {
			ln := Pos{p.tok.Line}
			p.next()
			list = append(list, &Spread{Pos: ln, X: p.assign()})
		} else {
			list = append(list, p.assign())
		}
		if !p.eat(",") && !p.is(")") {
			p.fail("expected , or ) in arguments, found %q", p.tok.Val)
		}
	}
	return list
}

// template parses a template literal at the current Template token.
func (p *parser) template(tag Expr) Expr {
	t := &TemplateLit{Pos: Pos{p.tok.Line}, Tag: tag}
	if tag != nil {
		t.Pos = Pos{tag.Ln()}
	}
	t.Quasis = append(t.Quasis, p.tok.Val)
	if p.tok.TailTemplate {
		p.next()
		return t
	}
	noIn := p.noIn
	p.noIn = false
	defer func() { p.noIn = noIn }()
	for {
		p.next()
		t.Exprs = append(t.Exprs, p.expr())
		if !p.is("}") {
			p.fail("expected } in template, found %q", p.tok.Val)
		}
		p.tok = p.lx.rescanTemplate(p.tok)
		t.Quasis = append(t.Quasis, p.tok.Val)
		if p.tok.TailTemplate {
			p.next()
			return t
		}
	}
}

func (p *parser) primary() Expr {
	t := p.tok
	ln := Pos{t.Line}
	switch t.Kind {
	case TNumber, TString:
		p.next()
		return &Lit{Pos: ln, Kind: t.Kind, Val: t.Val}
	case TTemplate:
		return p.template(nil)
	case TPrivateName:
		p.next()
		return &Ident{Pos: ln, Name: t.Val}
	case TIdent:
		switch t.Val {
		case "function":
			return p.function(false)
		case "async":
			if nt := p.peek(); nt.Val == "function" && !nt.NL {
				p.next()
				return p.function(true)
			}
		case "class":
			return p.class()
		case "true", "false", "null":
			p.next()
			return &Lit{Pos: ln, Kind: TIdent, Val: t.Val}
		case "import":
			p.next()
			if p.is(".") {
				p.next()
				return &Member{Pos: ln, Obj: &Ident{Pos: ln, Name: "import"}, Prop: p.memberName()}
			}
			return &Ident{Pos: ln, Name: "import"}
		}
		if reserved[t.Val] && t.Val != "import" {
			p.fail("unexpected keyword %s", t.Val)
		}
		p.next()
		return &Ident{Pos: ln, Name: t.Val}
	case TPunct:
		switch t.Val {
		case "(":
			p.next()
			noIn := p.noIn
			p.noIn = false
			x := p.expr()
			p.noIn = noIn
			p.expect(")")
			return x
		case "[":
			return p.arrayLit()
		case "{":
			return p.objectLit()
		case "/", "/=":
			if r, ok := p.lx.rescanRegex(t); ok {
				p.tok = r
				p.next()
				return &Lit{Pos: ln, Kind: TRegex, Val: r.Val}
			}
		case "<":
			if p.jsx {
				el := p.jsxElement()
				p.next()
				return el
			}
		case "@":
			p.decorators()
			if p.isWord("class") {
				return p.class()
			}
		}
	}
	p.fail("unexpected %q", t.Val)
	return nil
}

func (p *parser) arrayLit() Expr {
	a := &ArrayLit{Pos: Pos{p.tok.Line}}
	p.next() // [
	noIn := p.noIn
	p.noIn = false
	defer func() { p.noIn = noIn }()
	for !p.eat("]") {
		if p.is(",") {
			p.next()
			a.Elems = append(a.Elems, nil)
			continue
		}
		if p.is("...") {
			ln := Pos{p.tok.Line}
			p.next()
			a.Elems = append(a.Elems, &Spread{Pos: ln, X: p.assign()})
		} else {
			a.Elems = append(a.Elems, p.assign())
		}
		if !p.eat(",") && !p.is("]") {
			p.fail("expected , or ] in array, found %q", p.tok.Val)
		}
	}
	return a
}

func (p *parser) objectLit() Expr {
	o := &ObjectLit{Pos: Pos{p.tok.Line}}
	p.next() // {
	noIn := p.noIn
	p.noIn = false
	defer func() { p.noIn = noIn }()
	for !p.eat("}") {
		o.Props = append(o.Props, p.prop())
		if !p.eat(",") && !p.is("}") {
			p.fail("expected , or } in object, found %q", p.tok.Val)
		}
	}
	return o
}

func (p *parser) prop() *Prop {
	pr := &Prop{Pos: Pos{p.tok.Line}, Kind: "init"}
	if p.eat("...") {
		pr.Kind, pr.Value = "spread", p.assign()
		return pr
	}
	async, gen := false, false
	for p.tok.Kind == TIdent && (p.tok.Val == "async" || p.tok.Val == "get" || p.tok.Val == "set") {
		nt := p.peek()
		if !isKeyStart(nt) || p.tok.Val == "async" && nt.NL {
			break
		}
		switch p.tok.Val {
		case "async":
			async = true
		default:
			pr.Kind = p.tok.Val
		}
		p.next()
	}
	if p.eat("*") {
		gen = true
	}
	keyTok := p.tok
	pr.Key, pr.Computed = p.propKey()
	switch {
	case p.is("(") || p.is("<"):
		f := &Func{Pos: pr.Pos, Name: pr.Key, Async: async, Generator: gen}
		p.funcRest(f)
		if pr.Kind == "init" {
			pr.Kind = "method"
		}
		pr.Value = f
	case p.eat(":"):
		pr.Value = p.assign()
	case keyTok.Kind == TIdent && pr.Computed == nil:
		pr.Kind = "shorthand"
		id := &Ident{Pos: pr.Pos, Name: pr.Key}
		pr.Value = id
		if p.is("=") {
			// A default in a destructuring pattern: { a = 1 }.
			ln := Pos{p.tok.Line}
			p.next()
			pr.Value = &Assign{Pos: ln, Op: "=", Target: id, Value: p.assign()}
		}
	default:
		p.fail("expected : after property name, found %q", p.tok.Val)
	}
	return pr
}
