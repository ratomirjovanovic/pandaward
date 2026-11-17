package java

import "strings"

// Parse parses a Java compilation unit. It never fails: syntax errors are
// recorded in File.Errors and the broken statement or member is dropped.
func Parse(path, src string) *File {
	toks, errs := lex(src)
	p := &parser{toks: toks}
	f := &File{Path: path}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(syntaxError); !ok {
					panic(r)
				}
			}
		}()
		p.compilationUnit(f)
	}()
	f.Errors = append(errs, p.errs...)
	return f
}

type syntaxError struct{}
type bailout struct{}

type parser struct {
	toks []token
	i    int
	errs []Error
	// spec counts nested speculative parses, in which an error abandons
	// the attempt instead of being recorded.
	spec int
	// depth guards against stack exhaustion on pathological input.
	depth int
	// split logs the tokens expectGT changed, so that a failed
	// speculation can restore them.
	split []splitTok
}

type splitTok struct {
	i   int
	old token
}

func (p *parser) tok() token { return p.toks[p.i] }

func (p *parser) peek(n int) token {
	if p.i+n < len(p.toks) {
		return p.toks[p.i+n]
	}
	return p.toks[len(p.toks)-1]
}

func (p *parser) advance() token {
	t := p.toks[p.i]
	if p.i < len(p.toks)-1 {
		p.i++
	}
	return t
}

func (p *parser) pos() Pos { t := p.tok(); return Pos{t.line, t.col} }

func (p *parser) at(op string) bool    { t := p.tok(); return t.kind == tOp && t.val == op }
func (p *parser) atKw(w string) bool   { t := p.tok(); return t.kind == tKeyword && t.val == w }
func (p *parser) atIdent() bool        { return p.tok().kind == tIdent }
func (p *parser) atWord(w string) bool { t := p.tok(); return t.kind == tIdent && t.val == w }

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

func (p *parser) fail(msg string) {
	if p.spec > 0 {
		panic(bailout{})
	}
	t := p.tok()
	p.errs = append(p.errs, Error{Line: t.line, Col: t.col, Msg: msg})
	panic(syntaxError{})
}

func (p *parser) describe() string {
	t := p.tok()
	switch t.kind {
	case tEOF:
		return "end of file"
	case tString:
		return "string"
	case tIdent:
		return "identifier '" + t.val + "'"
	}
	return "'" + t.val + "'"
}

func (p *parser) expect(op string) {
	if !p.accept(op) {
		p.fail("expected '" + op + "', found " + p.describe())
	}
}

func (p *parser) ident() string {
	t := p.tok()
	if t.kind != tIdent {
		p.fail("expected an identifier, found " + p.describe())
	}
	p.advance()
	return t.val
}

// expectGT consumes one '>' closing type arguments, splitting >> and >>>.
func (p *parser) expectGT() {
	t := p.tok()
	if t.kind == tOp && strings.HasPrefix(t.val, ">") {
		if t.val == ">" {
			p.advance()
			return
		}
		if p.spec > 0 {
			p.split = append(p.split, splitTok{p.i, t})
		}
		p.toks[p.i].val = t.val[1:]
		p.toks[p.i].col++
		return
	}
	p.fail("expected '>', found " + p.describe())
}

// try runs f speculatively and reports whether it parsed; on failure the
// position is restored.
func (p *parser) try(f func()) (ok bool) {
	save, splits := p.i, len(p.split)
	p.spec++
	defer func() {
		p.spec--
		if r := recover(); r != nil {
			if _, isBail := r.(bailout); !isBail {
				panic(r)
			}
			for k := len(p.split) - 1; k >= splits; k-- {
				p.toks[p.split[k].i] = p.split[k].old
			}
			p.split = p.split[:splits]
			p.i = save
			ok = false
		}
	}()
	f()
	if p.spec == 0 {
		p.split = p.split[:0]
	}
	return true
}

func (p *parser) enter() {
	p.depth++
	if p.depth > 400 {
		p.fail("nesting too deep")
	}
}

func (p *parser) leave() { p.depth-- }

// ---- compilation unit ----

func (p *parser) compilationUnit(f *File) {
	// package annotations
	for p.at("@") && !(p.peek(1).kind == tKeyword && p.peek(1).val == "interface") {
		save := p.i
		p.annotation()
		if !p.atKw("package") {
			p.i = save
			break
		}
	}
	if p.acceptKw("package") {
		f.Package = p.qualified()
		p.expect(";")
	}
	for p.atKw("import") {
		p.recoverMember(func() {
			p.advance()
			imp := Import{Static: p.acceptKw("static")}
			parts := []string{p.ident()}
			for p.accept(".") {
				if p.accept("*") {
					imp.Star = true
					break
				}
				parts = append(parts, p.ident())
			}
			imp.Path = strings.Join(parts, ".")
			p.expect(";")
			f.Imports = append(f.Imports, imp)
		})
	}
	for p.tok().kind != tEOF {
		if p.accept(";") {
			continue
		}
		start := p.i
		p.recoverMember(func() {
			mods, anns := p.modifiers()
			if p.atWord("module") || p.atWord("open") {
				p.skipModule()
				return
			}
			f.Types = append(f.Types, p.classDecl(mods, anns))
		})
		if p.i == start {
			p.advance()
		}
	}
}

func (p *parser) skipModule() {
	for p.tok().kind != tEOF && !p.at("{") {
		p.advance()
	}
	p.skipBalanced()
}

// recoverMember runs f; after a syntax error it skips to the end of the
// broken member or declaration.
func (p *parser) recoverMember(f func()) {
	start := p.i
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(syntaxError); !ok {
				panic(r)
			}
			p.depth = 0
			p.syncMember(start)
		}
	}()
	f()
}

// syncMember skips to after a ';' or a balanced {...} at the member's
// level, or to a '}' that closes the enclosing body.
func (p *parser) syncMember(start int) {
	if p.i == start {
		p.advance()
	}
	depth := 0
	for p.tok().kind != tEOF {
		switch {
		case p.at("{"):
			depth++
		case p.at("}"):
			if depth == 0 {
				return
			}
			depth--
			if depth == 0 {
				p.advance()
				return
			}
		case p.at(";") && depth == 0:
			p.advance()
			return
		}
		p.advance()
	}
}

func (p *parser) skipBalanced() {
	if !p.at("{") {
		return
	}
	depth := 0
	for p.tok().kind != tEOF {
		if p.at("{") {
			depth++
		} else if p.at("}") {
			depth--
			if depth == 0 {
				p.advance()
				return
			}
		}
		p.advance()
	}
}

func (p *parser) qualified() string {
	parts := []string{p.ident()}
	for p.at(".") && p.peek(1).kind == tIdent {
		p.advance()
		parts = append(parts, p.ident())
	}
	return strings.Join(parts, ".")
}

var modifierWords = map[string]bool{"public": true, "private": true, "protected": true, "static": true, "final": true,
	"abstract": true, "native": true, "synchronized": true, "transient": true, "volatile": true, "strictfp": true, "default": true}

// modifiers reads modifiers and annotations in any order.
func (p *parser) modifiers() (mods []string, anns []*Annotation) {
	for {
		t := p.tok()
		switch {
		case t.kind == tOp && t.val == "@" && !(p.peek(1).kind == tKeyword && p.peek(1).val == "interface"):
			anns = append(anns, p.annotation())
		case t.kind == tKeyword && modifierWords[t.val] && !(t.val == "default" && (p.peek(1).kind == tOp && (p.peek(1).val == ":" || p.peek(1).val == "->"))):
			mods = append(mods, t.val)
			p.advance()
		case t.kind == tIdent && t.val == "sealed" && p.peek(1).kind != tOp:
			mods = append(mods, "sealed")
			p.advance()
		case t.kind == tIdent && t.val == "non" && p.peek(1).val == "-" && p.peek(2).val == "sealed":
			p.advance()
			p.advance()
			p.advance()
			mods = append(mods, "non-sealed")
		default:
			return
		}
	}
}

func (p *parser) annotation() *Annotation {
	a := &Annotation{Pos: p.pos()}
	p.expect("@")
	a.Name = p.qualified()
	if p.accept("(") {
		if !p.at(")") {
			if p.atIdent() && p.peek(1).kind == tOp && p.peek(1).val == "=" {
				for {
					name := p.ident()
					p.expect("=")
					a.Args = append(a.Args, &AnnArg{Name: name, Value: p.elementValue()})
					if !p.accept(",") {
						break
					}
				}
			} else {
				a.Args = append(a.Args, &AnnArg{Name: "value", Value: p.elementValue()})
			}
		}
		p.expect(")")
	}
	return a
}

func (p *parser) elementValue() Expr {
	switch {
	case p.at("@"):
		pos := p.pos()
		p.annotation()
		return &Bad{pos}
	case p.at("{"):
		init := &ArrayInit{Pos: p.pos()}
		p.advance()
		for !p.at("}") && p.tok().kind != tEOF {
			init.Elts = append(init.Elts, p.elementValue())
			if !p.accept(",") {
				break
			}
		}
		p.expect("}")
		return init
	}
	return p.conditional()
}

// typeParams skips <T extends A & B, U>.
func (p *parser) typeParams() {
	if !p.at("<") {
		return
	}
	p.advance()
	for {
		p.modifiers()
		p.ident()
		if p.acceptKw("extends") {
			p.typ()
			for p.accept("&") {
				p.typ()
			}
		}
		if !p.accept(",") {
			break
		}
	}
	p.expectGT()
}

// ---- types ----

var primitives = map[string]bool{"boolean": true, "byte": true, "char": true, "short": true, "int": true, "long": true, "float": true, "double": true, "void": true}

// typ parses a type and returns its dotted name with [] per dimension.
func (p *parser) typ() string {
	for p.at("@") {
		p.annotation()
	}
	var name string
	t := p.tok()
	switch {
	case t.kind == tKeyword && primitives[t.val]:
		p.advance()
		name = t.val
	case t.kind == tIdent:
		parts := []string{p.ident()}
		p.typeArgs()
		for p.at(".") && (p.peek(1).kind == tIdent || p.peek(1).val == "@") {
			p.advance()
			for p.at("@") {
				p.annotation()
			}
			parts = append(parts, p.ident())
			p.typeArgs()
		}
		name = strings.Join(parts, ".")
	case t.kind == tOp && t.val == "?":
		p.advance()
		name = "Object"
		if p.acceptKw("extends") || p.acceptKw("super") {
			name = p.typ()
		}
		return name
	default:
		p.fail("expected a type, found " + p.describe())
	}
	for p.at("@") {
		p.annotation()
	}
	for p.at("[") && p.peek(1).val == "]" {
		p.advance()
		p.advance()
		name += "[]"
	}
	return name
}

// typeArgs skips <...> after a type name.
func (p *parser) typeArgs() {
	if !p.at("<") {
		return
	}
	p.advance()
	if p.at(">") { // diamond
		p.advance()
		return
	}
	for {
		p.typ()
		for p.accept("&") {
			p.typ()
		}
		if !p.accept(",") {
			break
		}
	}
	p.expectGT()
}

// ---- declarations ----

func (p *parser) classDecl(mods []string, anns []*Annotation) *ClassDecl {
	p.enter()
	defer p.leave()
	c := &ClassDecl{Pos: p.pos(), Mods: mods, Annotations: anns}
	switch {
	case p.acceptKw("class"):
		c.Kind = "class"
	case p.acceptKw("interface"):
		c.Kind = "interface"
	case p.acceptKw("enum"):
		c.Kind = "enum"
	case p.atWord("record") && p.peek(1).kind == tIdent:
		p.advance()
		c.Kind = "record"
	case p.at("@") && p.peek(1).val == "interface":
		p.advance()
		p.advance()
		c.Kind = "@interface"
	default:
		p.fail("expected a class, interface, enum or record, found " + p.describe())
	}
	c.Name = p.ident()
	p.typeParams()
	if c.Kind == "record" {
		p.expect("(")
		for !p.at(")") {
			c.Components = append(c.Components, p.param())
			if !p.accept(",") {
				break
			}
		}
		p.expect(")")
	}
	if p.acceptKw("extends") {
		c.Extends = append(c.Extends, p.typ())
		for p.accept(",") {
			c.Extends = append(c.Extends, p.typ())
		}
	}
	if p.acceptKw("implements") {
		c.Implements = append(c.Implements, p.typ())
		for p.accept(",") {
			c.Implements = append(c.Implements, p.typ())
		}
	}
	if p.atWord("permits") {
		p.advance()
		p.typ()
		for p.accept(",") {
			p.typ()
		}
	}
	p.classBody(c)
	return c
}

func (p *parser) classBody(c *ClassDecl) {
	p.expect("{")
	if c.Kind == "enum" {
		p.enumConstants(c)
	}
	for !p.at("}") && p.tok().kind != tEOF {
		start := p.i
		p.recoverMember(func() { p.member(c) })
		if p.i == start {
			p.advance()
		}
	}
	p.expect("}")
}

func (p *parser) enumConstants(c *ClassDecl) {
	for p.atIdent() || p.at("@") {
		p.recoverMember(func() {
			for p.at("@") {
				p.annotation()
			}
			ec := &EnumConst{Pos: p.pos(), Name: p.ident()}
			if p.at("(") {
				ec.Args = p.args()
			}
			if p.at("{") {
				ec.Body = &ClassDecl{Pos: p.pos(), Kind: "class", Name: ec.Name}
				p.classBody(ec.Body)
			}
			c.Consts = append(c.Consts, ec)
		})
		if !p.accept(",") {
			break
		}
	}
	p.accept(";")
}

func (p *parser) member(c *ClassDecl) {
	if p.accept(";") {
		return
	}
	pos := p.pos()
	if p.at("{") {
		c.Members = append(c.Members, &Initializer{Pos: pos, Body: p.block()})
		return
	}
	if p.atKw("static") && p.peek(1).val == "{" {
		p.advance()
		c.Members = append(c.Members, &Initializer{Pos: pos, Static: true, Body: p.block()})
		return
	}
	mods, anns := p.modifiers()
	pos = p.pos()
	if p.atKw("class") || p.atKw("interface") || p.atKw("enum") || p.at("@") && p.peek(1).val == "interface" ||
		p.atWord("record") && p.peek(1).kind == tIdent && p.peek(2).val != "=" && p.peek(2).val != ";" {
		c.Members = append(c.Members, p.classDecl(mods, anns))
		return
	}
	p.typeParams()
	// constructor, or a record's compact constructor
	if p.atIdent() && p.tok().val == c.Name && (p.peek(1).val == "(" || p.peek(1).val == "{" && c.Kind == "record") {
		m := &Method{Pos: pos, Name: "<init>", Ctor: true, Mods: mods, Annotations: anns}
		p.advance()
		if p.at("(") {
			m.Params = p.params()
		} else {
			m.Params = c.Components
		}
		m.Throws = p.throws()
		m.Body = p.block()
		c.Members = append(c.Members, m)
		return
	}
	typ := p.typ()
	namePos := p.pos()
	name := p.ident()
	if p.at("(") {
		m := &Method{Pos: namePos, Name: name, Ret: typ, Mods: mods, Annotations: anns}
		m.Params = p.params()
		for p.at("[") {
			p.advance()
			p.expect("]")
		}
		m.Throws = p.throws()
		if p.acceptKw("default") {
			p.elementValue()
		}
		if p.at("{") {
			m.Body = p.block()
		} else {
			p.expect(";")
		}
		c.Members = append(c.Members, m)
		return
	}
	fd := &FieldDecl{Pos: pos, Type: typ, Mods: mods, Annotations: anns}
	fd.Vars = p.varDeclRest(namePos, name)
	p.expect(";")
	c.Members = append(c.Members, fd)
}

func (p *parser) throws() []string {
	var out []string
	if p.acceptKw("throws") {
		out = append(out, p.typ())
		for p.accept(",") {
			out = append(out, p.typ())
		}
	}
	return out
}

func (p *parser) params() []*Param {
	p.expect("(")
	var out []*Param
	for !p.at(")") && p.tok().kind != tEOF {
		prm := p.param()
		if prm.Name != "this" {
			out = append(out, prm)
		}
		if !p.accept(",") {
			break
		}
	}
	p.expect(")")
	return out
}

func (p *parser) param() *Param {
	_, anns := p.modifiers()
	prm := &Param{Pos: p.pos(), Annotations: anns}
	prm.Type = p.typ()
	if p.accept("...") {
		prm.Varargs = true
		prm.Type += "[]"
	}
	if p.atKw("this") { // receiver parameter
		p.advance()
		prm.Name = "this"
		return prm
	}
	prm.Pos = p.pos()
	prm.Name = p.ident()
	for p.at("[") {
		p.advance()
		p.expect("]")
		prm.Type += "[]"
	}
	return prm
}

// varDeclRest reads declarators after the first name: [dims] [= init] {, name ...}.
func (p *parser) varDeclRest(pos Pos, name string) []*Var {
	var vars []*Var
	for {
		v := &Var{Pos: pos, Name: name}
		for p.at("[") {
			p.advance()
			p.expect("]")
			v.Dims++
		}
		if p.accept("=") {
			v.Init = p.varInit()
		}
		vars = append(vars, v)
		if !p.accept(",") {
			return vars
		}
		pos = p.pos()
		name = p.ident()
	}
}

func (p *parser) varInit() Expr {
	if p.at("{") {
		return p.arrayInit()
	}
	return p.expr()
}

func (p *parser) arrayInit() *ArrayInit {
	init := &ArrayInit{Pos: p.pos()}
	p.expect("{")
	for !p.at("}") && p.tok().kind != tEOF {
		init.Elts = append(init.Elts, p.varInit())
		if !p.accept(",") {
			break
		}
	}
	p.expect("}")
	return init
}

// ---- statements ----

func (p *parser) block() *Block {
	b := &Block{Pos: p.pos()}
	p.expect("{")
	for !p.at("}") && p.tok().kind != tEOF {
		b.Stmts = append(b.Stmts, p.blockStmtRecover()...)
	}
	p.expect("}")
	return b
}

// blockStmtRecover parses one statement; after a syntax error it skips to
// the end of the broken statement and returns a BadStmt.
func (p *parser) blockStmtRecover() (out []Stmt) {
	start := p.i
	pos := p.pos()
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(syntaxError); !ok {
				panic(r)
			}
			p.depth = 0
			p.syncStmt(start)
			out = []Stmt{&BadStmt{pos}}
		}
	}()
	return []Stmt{p.blockStmt()}
}

// syncStmt skips to after the next ';' or balanced block at the
// statement's level, stopping before a '}' that closes the enclosing block.
func (p *parser) syncStmt(start int) {
	if p.i == start {
		if p.at("}") {
			return
		}
		p.advance()
	}
	depth := 0
	for p.tok().kind != tEOF {
		switch {
		case p.at("{") || p.at("("):
			depth++
		case p.at("}") || p.at(")"):
			if depth == 0 {
				return
			}
			depth--
			if depth == 0 && p.at("}") {
				p.advance()
				return
			}
		case p.at(";") && depth == 0:
			p.advance()
			return
		}
		p.advance()
	}
}

func (p *parser) blockStmt() Stmt {
	p.enter()
	defer p.leave()
	pos := p.pos()
	// local class, record, enum or interface
	if p.atKw("class") || p.atKw("interface") || p.atKw("enum") ||
		(p.atKw("final") || p.atKw("abstract") || p.atKw("static")) && (p.peek(1).val == "class" || p.peek(1).val == "interface") ||
		p.atWord("record") && p.peek(1).kind == tIdent && p.peek(2).val == "(" {
		mods, anns := p.modifiers()
		return &LocalClass{Pos: pos, Decl: p.classDecl(mods, anns)}
	}
	if lv := p.tryLocalVar(); lv != nil {
		p.expect(";")
		return lv
	}
	return p.statement()
}

// tryLocalVar parses `[final] Type name ...` when that is what follows.
func (p *parser) tryLocalVar() *LocalVar {
	t := p.tok()
	if !(t.kind == tIdent || t.kind == tKeyword && (primitives[t.val] || t.val == "final") || t.kind == tOp && t.val == "@") {
		return nil
	}
	if t.kind == tIdent {
		// fast rejects: a call, assignment or label
		n := p.peek(1)
		if n.kind == tOp && (n.val == "(" || n.val == "=" || n.val == ":" || n.val == "++" || n.val == "--" || n.val == "->" ||
			strings.HasSuffix(n.val, "=") && n.val != "==" && n.val != "<=" && n.val != ">=" && n.val != "!=" || n.val == ";") {
			return nil
		}
	}
	pos := p.pos()
	var lv *LocalVar
	var name string
	var namePos Pos
	ok := p.try(func() {
		mods, _ := p.modifiers()
		typ := p.typ()
		namePos = p.pos()
		name = p.ident()
		if !(p.at("=") || p.at(";") || p.at(",") || p.at("[") || p.at(":")) {
			p.fail("not a declaration")
		}
		lv = &LocalVar{Pos: pos, Type: typ, Mods: mods}
	})
	if !ok {
		return nil
	}
	if p.at(":") { // the for-each form, handled by the caller
		lv.Vars = []*Var{{Pos: namePos, Name: name}}
		return lv
	}
	lv.Vars = p.varDeclRest(namePos, name)
	return lv
}

func (p *parser) statement() Stmt {
	pos := p.pos()
	t := p.tok()
	switch {
	case t.kind == tOp && t.val == "{":
		return p.block()
	case t.kind == tOp && t.val == ";":
		p.advance()
		return &Empty{pos}
	case t.kind == tKeyword:
		switch t.val {
		case "if":
			p.advance()
			s := &If{Pos: pos, C: p.parenExpr()}
			s.Then = p.statementRecover()
			if p.acceptKw("else") {
				s.Else = p.statementRecover()
			}
			return s
		case "while":
			p.advance()
			return &While{Pos: pos, C: p.parenExpr(), Body: p.statementRecover()}
		case "do":
			p.advance()
			s := &DoWhile{Pos: pos, Body: p.statementRecover()}
			if !p.acceptKw("while") {
				p.fail("expected 'while', found " + p.describe())
			}
			s.C = p.parenExpr()
			p.expect(";")
			return s
		case "for":
			return p.forStmt()
		case "try":
			return p.tryStmt()
		case "switch":
			p.advance()
			s := &Switch{Pos: pos, X: p.parenExpr()}
			s.Cases = p.switchBody()
			return s
		case "return":
			p.advance()
			s := &Return{Pos: pos}
			if !p.at(";") {
				s.X = p.expr()
			}
			p.expect(";")
			return s
		case "throw":
			p.advance()
			s := &Throw{Pos: pos, X: p.expr()}
			p.expect(";")
			return s
		case "break", "continue":
			p.advance()
			label := ""
			if p.atIdent() {
				label = p.ident()
			}
			p.expect(";")
			if t.val == "break" {
				return &Break{pos, label}
			}
			return &Continue{pos, label}
		case "synchronized":
			p.advance()
			return &Sync{Pos: pos, X: p.parenExpr(), Body: p.block()}
		case "assert":
			p.advance()
			s := &Assert{Pos: pos, C: p.expr()}
			if p.accept(":") {
				s.Msg = p.expr()
			}
			p.expect(";")
			return s
		}
	case t.kind == tIdent && t.val == "yield" && !(p.peek(1).kind == tOp && (p.peek(1).val == "=" || p.peek(1).val == "." || p.peek(1).val == "(" || p.peek(1).val == "[")):
		p.advance()
		s := &Yield{Pos: pos, X: p.expr()}
		p.expect(";")
		return s
	case t.kind == tIdent && p.peek(1).kind == tOp && p.peek(1).val == ":":
		label := p.ident()
		p.advance()
		return &Labeled{Pos: pos, Label: label, Body: p.statementRecover()}
	}
	x := p.expr()
	p.expect(";")
	return &ExprStmt{pos, x}
}

// statementRecover parses the body of an if, loop or label, keeping the
// enclosing statement when only its body is broken.
func (p *parser) statementRecover() Stmt {
	if p.at("{") {
		return p.block()
	}
	stmts := p.blockStmtRecover()
	return stmts[0]
}

func (p *parser) parenExpr() Expr {
	p.expect("(")
	x := p.expr()
	p.expect(")")
	return x
}

func (p *parser) forStmt() Stmt {
	pos := p.pos()
	p.advance()
	p.expect("(")
	if lv := p.tryLocalVar(); lv != nil && p.at(":") {
		p.advance()
		fe := &ForEach{Pos: pos, Type: lv.Type, Name: lv.Vars[0].Name, Iter: p.expr()}
		p.expect(")")
		fe.Body = p.statementRecover()
		return fe
	} else if lv != nil {
		f := &For{Pos: pos, Init: []Stmt{lv}}
		return p.forRest(f)
	}
	f := &For{Pos: pos}
	for !p.at(";") {
		f.Init = append(f.Init, &ExprStmt{p.pos(), p.expr()})
		if !p.accept(",") {
			break
		}
	}
	return p.forRest(f)
}

func (p *parser) forRest(f *For) Stmt {
	p.expect(";")
	if !p.at(";") {
		f.C = p.expr()
	}
	p.expect(";")
	for !p.at(")") {
		f.Update = append(f.Update, p.expr())
		if !p.accept(",") {
			break
		}
	}
	p.expect(")")
	f.Body = p.statementRecover()
	return f
}

func (p *parser) tryStmt() Stmt {
	s := &Try{Pos: p.pos()}
	p.advance()
	if p.accept("(") {
		for !p.at(")") && p.tok().kind != tEOF {
			if lv := p.tryLocalVar(); lv != nil {
				s.Resources = append(s.Resources, lv)
			} else {
				s.Resources = append(s.Resources, &ExprStmt{p.pos(), p.expr()})
			}
			if !p.accept(";") {
				break
			}
		}
		p.expect(")")
	}
	s.Body = p.block()
	for p.atKw("catch") {
		c := &Catch{Pos: p.pos()}
		p.advance()
		p.expect("(")
		p.modifiers()
		c.Types = append(c.Types, p.typ())
		for p.accept("|") {
			c.Types = append(c.Types, p.typ())
		}
		c.Name = p.ident()
		p.expect(")")
		c.Body = p.block()
		s.Catches = append(s.Catches, c)
	}
	if p.acceptKw("finally") {
		s.Finally = p.block()
	}
	return s
}

// switchBody parses { case ...: stmts | case ... -> body }.
func (p *parser) switchBody() []*Case {
	p.expect("{")
	var cases []*Case
	for !p.at("}") && p.tok().kind != tEOF {
		c := &Case{Pos: p.pos()}
		switch {
		case p.acceptKw("default"):
			c.Default = true
		case p.acceptKw("case"):
			for {
				if p.acceptKw("default") {
					c.Default = true
				} else {
					c.Labels = append(c.Labels, p.caseLabel())
				}
				if !p.accept(",") {
					break
				}
			}
			if p.atWord("when") {
				p.advance()
				c.Guard = p.expr()
			}
		default:
			p.fail("expected 'case' or 'default', found " + p.describe())
		}
		if p.accept("->") {
			c.Arrow = true
			switch {
			case p.at("{"):
				c.Body = []Stmt{p.block()}
			case p.atKw("throw"):
				c.Body = []Stmt{p.statement()}
			default:
				pos := p.pos()
				x := p.expr()
				p.expect(";")
				c.Body = []Stmt{&Yield{pos, x}}
			}
		} else {
			if !p.accept(":") {
				p.fail("expected ':' or '->', found " + p.describe())
			}
			for !p.atKw("case") && !p.atKw("default") && !p.at("}") && p.tok().kind != tEOF {
				c.Body = append(c.Body, p.blockStmtRecover()...)
			}
			// default: followed by a statement that starts with default is
			// not possible; a 'default ->' inside is a new case.
		}
		cases = append(cases, c)
	}
	p.expect("}")
	return cases
}

// caseLabel parses a constant, an enum name, a type pattern (Type name) or
// a record pattern (Type(...) name?).
func (p *parser) caseLabel() Expr {
	pos := p.pos()
	var x Expr
	if p.try(func() {
		typ := p.typ()
		if p.at("(") {
			p.skipParens()
			bind := ""
			if p.atIdent() && !p.atWord("when") {
				bind = p.ident()
			}
			x = &InstanceOf{Pos: pos, Type: typ, Bind: bind}
			return
		}
		bind := p.ident()
		if p.atWord("when") && bind == "when" {
			p.fail("not a pattern")
		}
		x = &InstanceOf{Pos: pos, Type: typ, Bind: bind}
	}) {
		return x
	}
	return p.conditional()
}

func (p *parser) skipParens() {
	depth := 0
	for p.tok().kind != tEOF {
		if p.at("(") {
			depth++
		} else if p.at(")") {
			depth--
			if depth == 0 {
				p.advance()
				return
			}
		}
		p.advance()
	}
}

// ---- expressions ----

func (p *parser) expr() Expr {
	p.enter()
	defer p.leave()
	if l := p.tryLambda(); l != nil {
		return l
	}
	pos := p.pos()
	x := p.conditional()
	if t := p.tok(); t.kind == tOp && isAssignOp(t.val) {
		p.advance()
		return &Assign{Pos: pos, Op: t.val, L: x, R: p.expr()}
	}
	return x
}

func isAssignOp(s string) bool {
	switch s {
	case "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>=":
		return true
	}
	return false
}

// tryLambda parses x -> ..., (a, b) -> ... or (T a, T b) -> ....
func (p *parser) tryLambda() Expr {
	pos := p.pos()
	if p.atIdent() && p.peek(1).val == "->" {
		name := p.ident()
		p.advance()
		return &Lambda{Pos: pos, Params: []*Param{{Pos: pos, Name: name}}, Body: p.lambdaBody()}
	}
	if !p.at("(") {
		return nil
	}
	// find the matching ')' and check for '->'
	depth, k := 0, p.i
	for ; k < len(p.toks); k++ {
		v := p.toks[k]
		if v.kind == tEOF {
			return nil
		}
		if v.kind == tOp && v.val == "(" {
			depth++
		} else if v.kind == tOp && v.val == ")" {
			depth--
			if depth == 0 {
				break
			}
		}
	}
	if k+1 >= len(p.toks) || p.toks[k+1].val != "->" {
		return nil
	}
	p.advance()
	var params []*Param
	for !p.at(")") && p.tok().kind != tEOF {
		if p.atIdent() && (p.peek(1).val == "," || p.peek(1).val == ")") {
			params = append(params, &Param{Pos: p.pos(), Name: p.ident()})
		} else {
			params = append(params, p.param())
		}
		if !p.accept(",") {
			break
		}
	}
	p.expect(")")
	p.expect("->")
	return &Lambda{Pos: pos, Params: params, Body: p.lambdaBody()}
}

func (p *parser) lambdaBody() Node {
	if p.at("{") {
		return p.block()
	}
	return p.expr()
}

func (p *parser) conditional() Expr {
	pos := p.pos()
	c := p.binary(1)
	if !p.accept("?") {
		return c
	}
	t := p.lambdaOr(p.conditional)
	p.expect(":")
	f := p.lambdaOr(p.conditional)
	return &Cond{Pos: pos, C: c, T: t, F: f}
}

func (p *parser) lambdaOr(f func() Expr) Expr {
	if l := p.tryLambda(); l != nil {
		return l
	}
	return f()
}

var binPrec = map[string]int{
	"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6,
	"<": 7, ">": 7, "<=": 7, ">=": 7, "<<": 8, ">>": 8, ">>>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10,
}

func (p *parser) binary(min int) Expr {
	pos := p.pos()
	x := p.unary()
	for {
		t := p.tok()
		if t.kind == tKeyword && t.val == "instanceof" && min <= 7 {
			p.advance()
			io := &InstanceOf{Pos: pos, X: x}
			p.acceptKw("final")
			io.Type = p.typ()
			if p.at("(") {
				p.skipParens()
			}
			if p.atIdent() {
				io.Bind = p.ident()
			}
			x = io
			continue
		}
		prec, ok := binPrec[t.val]
		if t.kind != tOp || !ok || prec < min {
			return x
		}
		p.advance()
		y := p.binary(prec + 1)
		x = &Binary{Pos: pos, Op: t.val, L: x, R: y}
	}
}

func (p *parser) unary() Expr {
	p.enter()
	defer p.leave()
	pos := p.pos()
	t := p.tok()
	if t.kind == tOp {
		switch t.val {
		case "+", "-", "!", "~", "++", "--":
			p.advance()
			return &Unary{Pos: pos, Op: t.val, X: p.unary()}
		case "(":
			if c := p.tryCast(); c != nil {
				return c
			}
		}
	}
	return p.postfix(p.primary())
}

// tryCast parses (Type) x when the parenthesized part is a type and what
// follows can start an operand.
func (p *parser) tryCast() Expr {
	pos := p.pos()
	var c *Cast
	p.try(func() {
		p.advance()
		typ := p.typ()
		for p.accept("&") {
			p.typ()
		}
		p.expect(")")
		n := p.tok()
		prim := primitives[strings.TrimSuffix(typ, "[]")]
		switch {
		case n.kind == tIdent || n.kind == tString || n.kind == tChar || n.kind == tInt || n.kind == tFloat:
		case n.kind == tKeyword && (n.val == "this" || n.val == "super" || n.val == "new" || n.val == "true" || n.val == "false" || n.val == "null" || n.val == "switch" || primitives[n.val]):
		case n.kind == tOp && (n.val == "(" || n.val == "!" || n.val == "~"):
		case prim && n.kind == tOp && (n.val == "+" || n.val == "-" || n.val == "++" || n.val == "--"):
		default:
			p.fail("not a cast")
		}
		c = &Cast{Pos: pos, Type: typ}
	})
	if c == nil {
		return nil
	}
	if l := p.tryLambda(); l != nil {
		c.X = l
	} else {
		c.X = p.unary()
	}
	return c
}

func (p *parser) args() []Expr {
	p.expect("(")
	var out []Expr
	for !p.at(")") && p.tok().kind != tEOF {
		out = append(out, p.expr())
		if !p.accept(",") {
			break
		}
	}
	p.expect(")")
	return out
}

func (p *parser) primary() Expr {
	pos := p.pos()
	t := p.tok()
	switch t.kind {
	case tString:
		p.advance()
		return &Literal{pos, LitString, t.val}
	case tChar:
		p.advance()
		return &Literal{pos, LitChar, t.val}
	case tInt:
		p.advance()
		return &Literal{pos, LitInt, t.val}
	case tFloat:
		p.advance()
		return &Literal{pos, LitFloat, t.val}
	case tIdent:
		// a generic type used as a method reference qualifier: List<T>::m
		if p.peek(1).val == "<" {
			var x Expr
			if p.try(func() {
				typ := p.typ()
				if !p.at("::") {
					p.fail("not a type")
				}
				x = &TypeExpr{pos, typ}
			}) {
				return x
			}
		}
		name := p.ident()
		if p.at("(") {
			return &Call{Pos: pos, Name: name, Args: p.args()}
		}
		if p.at("[") && p.peek(1).val == "]" {
			typ := name
			for p.at("[") && p.peek(1).val == "]" {
				p.advance()
				p.advance()
				typ += "[]"
			}
			if p.at(".") && p.peek(1).val == "class" {
				p.advance()
				p.advance()
				return &ClassLit{pos, typ}
			}
			return &TypeExpr{pos, typ}
		}
		return &Name{pos, name}
	case tKeyword:
		switch t.val {
		case "true":
			p.advance()
			return &Literal{pos, LitTrue, "true"}
		case "false":
			p.advance()
			return &Literal{pos, LitFalse, "false"}
		case "null":
			p.advance()
			return &Literal{pos, LitNull, "null"}
		case "this", "super":
			p.advance()
			if p.at("(") {
				return &Call{Pos: pos, Name: t.val, Args: p.args()}
			}
			return &Name{pos, t.val}
		case "new":
			return p.creator(nil)
		case "switch":
			p.advance()
			s := &SwitchExpr{Pos: pos, X: p.parenExpr()}
			s.Cases = p.switchBody()
			return s
		}
		if primitives[t.val] {
			typ := p.typ()
			if p.at(".") && p.peek(1).val == "class" {
				p.advance()
				p.advance()
				return &ClassLit{pos, typ}
			}
			return &TypeExpr{pos, typ}
		}
	case tOp:
		switch t.val {
		case "(":
			p.advance()
			x := p.expr()
			p.expect(")")
			return x
		case "@":
			p.annotation()
			return p.primary()
		}
	}
	p.fail("expected an expression, found " + p.describe())
	return nil
}

// creator parses new Type(args) [body] or new Type[dims][] [init].
func (p *parser) creator(outer Expr) Expr {
	pos := p.pos()
	p.advance() // new
	p.typeArgs()
	for p.at("@") {
		p.annotation()
	}
	n := &New{Pos: pos, Outer: outer}
	// the element type without dimensions
	t := p.tok()
	if t.kind == tKeyword && primitives[t.val] {
		p.advance()
		n.Type = t.val
	} else {
		parts := []string{p.ident()}
		p.typeArgs()
		for p.at(".") {
			p.advance()
			for p.at("@") {
				p.annotation()
			}
			parts = append(parts, p.ident())
			p.typeArgs()
		}
		n.Type = strings.Join(parts, ".")
	}
	if p.at("[") {
		for p.at("[") {
			p.advance()
			if p.at("]") {
				p.advance()
				n.Type += "[]"
				continue
			}
			n.Dims = append(n.Dims, p.expr())
			p.expect("]")
			n.Type += "[]"
		}
		if p.at("{") {
			n.Init = p.arrayInit()
		}
		return n
	}
	n.Args = p.args()
	if p.at("{") {
		n.Body = &ClassDecl{Pos: p.pos(), Kind: "class", Name: "", Extends: []string{n.Type}}
		p.classBody(n.Body)
	}
	return n
}

func (p *parser) postfix(x Expr) Expr {
	for {
		pos := x.At()
		t := p.tok()
		if t.kind != tOp {
			return x
		}
		switch t.val {
		case ".":
			p.advance()
			n := p.tok()
			switch {
			case n.kind == tKeyword && n.val == "new":
				x = p.creator(x)
			case n.kind == tKeyword && n.val == "class":
				p.advance()
				x = &ClassLit{pos, exprName(x)}
			case n.kind == tKeyword && (n.val == "this" || n.val == "super"):
				p.advance()
				if p.at("(") {
					x = &Call{Pos: pos, X: x, Name: n.val, Args: p.args()}
				} else {
					x = &Field{pos, x, n.val}
				}
			case n.kind == tOp && n.val == "<":
				p.typeArgs()
				name := p.ident()
				x = &Call{Pos: pos, X: x, Name: name, Args: p.args()}
			default:
				name := p.ident()
				if p.at("(") {
					x = &Call{Pos: pos, X: x, Name: name, Args: p.args()}
				} else {
					x = &Field{pos, x, name}
				}
			}
		case "[":
			if p.peek(1).val == "]" {
				// Type[]::new or Type[].class after a qualified name
				typ := exprName(x)
				for p.at("[") && p.peek(1).val == "]" {
					p.advance()
					p.advance()
					typ += "[]"
				}
				if p.at(".") && p.peek(1).val == "class" {
					p.advance()
					p.advance()
					x = &ClassLit{pos, typ}
				} else {
					x = &TypeExpr{pos, typ}
				}
				continue
			}
			p.advance()
			idx := p.expr()
			p.expect("]")
			x = &Index{pos, x, idx}
		case "::":
			p.advance()
			if p.acceptKw("new") {
				x = &MethodRef{pos, x, "new"}
			} else {
				p.typeArgs()
				x = &MethodRef{pos, x, p.ident()}
			}
		case "++", "--":
			p.advance()
			x = &Unary{Pos: pos, Op: t.val, X: x, Postfix: true}
		default:
			return x
		}
	}
}

// exprName returns the dotted name of a name or field chain.
func exprName(x Expr) string {
	switch x := x.(type) {
	case *Name:
		return x.Id
	case *Field:
		return exprName(x.X) + "." + x.Name
	case *TypeExpr:
		return x.Type
	}
	return ""
}
