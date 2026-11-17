package js

// TypeScript: types are parsed only to be skipped. The skipper follows the
// type grammar closely enough to know where a type ends, which is all the
// expression parser needs.

// eatGT consumes a > that closes type arguments, splitting >> and >= tokens.
func (p *parser) eatGT() bool {
	if p.tok.Kind != TPunct || p.tok.Val == "" || p.tok.Val[0] != '>' {
		return false
	}
	if p.tok.Val == ">" {
		p.next()
		return true
	}
	p.tok.Val = p.tok.Val[1:]
	p.tok.Pos++
	p.tok.NL = false
	return true
}

// skipTypeArgs skips <T, U>.
func (p *parser) skipTypeArgs() {
	p.expect("<")
	for !p.eatGT() {
		p.skipType()
		if !p.eat(",") && !(p.tok.Kind == TPunct && len(p.tok.Val) > 0 && p.tok.Val[0] == '>') {
			p.fail("expected , or > in type arguments, found %q", p.tok.Val)
		}
	}
}

// skipTypeParams skips <T extends U = V, const W>.
func (p *parser) skipTypeParams() {
	p.expect("<")
	for !p.eatGT() {
		for p.isWord("in") || p.isWord("out") || p.isWord("const") {
			if nt := p.peek(); nt.Kind != TIdent {
				break
			}
			p.next()
		}
		if p.tok.Kind != TIdent {
			p.fail("expected a type parameter, found %q", p.tok.Val)
		}
		p.next()
		if p.isWord("extends") {
			p.next()
			p.skipType()
		}
		if p.eat("=") {
			p.skipType()
		}
		if !p.eat(",") && !(p.tok.Kind == TPunct && len(p.tok.Val) > 0 && p.tok.Val[0] == '>') {
			p.fail("expected , or > in type parameters, found %q", p.tok.Val)
		}
	}
}

// skipReturnType skips a return type, including type predicates.
func (p *parser) skipReturnType() {
	if p.isWord("asserts") {
		if nt := p.peek(); nt.Kind == TIdent && !nt.NL {
			p.next()
			p.next()
			if p.isWord("is") {
				p.next()
				p.skipType()
			}
			return
		}
	}
	if p.tok.Kind == TIdent {
		if nt := p.peek(); nt.Kind == TIdent && nt.Val == "is" && !nt.NL {
			p.next()
			p.next()
			p.skipType()
			return
		}
	}
	p.skipType()
}

// skipType skips one type, including unions and conditional types.
func (p *parser) skipType() {
	p.enter()
	defer p.leave()
	p.skipUnionType()
	if p.isWord("extends") && !p.tok.NL {
		p.next()
		p.skipUnionType()
		p.expect("?")
		p.skipType()
		p.expect(":")
		p.skipType()
	}
}

func (p *parser) skipUnionType() {
	if !p.eat("|") {
		p.eat("&")
	}
	p.skipPostfixType()
	for p.is("|") || p.is("&") {
		p.next()
		p.skipPostfixType()
	}
}

func (p *parser) skipPostfixType() {
	p.skipPrimaryType()
	for p.is("[") && !p.tok.NL {
		p.skipBalanced("[", "]")
	}
}

func (p *parser) skipPrimaryType() {
	p.enter()
	defer p.leave()
	t := p.tok
	switch t.Kind {
	case TString, TNumber:
		p.next()
		return
	case TTemplate:
		p.skipTemplateType()
		return
	case TPunct:
		switch t.Val {
		case "(":
			p.skipBalanced("(", ")")
			if p.eat("=>") {
				p.skipReturnType()
			}
			return
		case "<":
			p.skipTypeParams()
			p.skipBalanced("(", ")")
			p.expect("=>")
			p.skipReturnType()
			return
		case "{":
			p.skipBalanced("{", "}")
			return
		case "[":
			p.skipBalanced("[", "]")
			return
		case "-":
			p.next()
			if p.tok.Kind != TNumber {
				p.fail("expected a number in type, found %q", p.tok.Val)
			}
			p.next()
			return
		}
		p.fail("expected a type, found %q", t.Val)
	case TIdent:
		switch t.Val {
		case "keyof", "unique", "readonly":
			p.next()
			p.skipPostfixType()
			return
		case "infer":
			// infer X extends C: inside the extends clause of a conditional
			// type a nested conditional needs parentheses, so the
			// constraint always belongs to infer.
			p.next()
			p.next()
			if p.isWord("extends") {
				p.next()
				p.skipUnionType()
			}
			return
		case "typeof":
			p.next()
			if p.isWord("import") {
				p.next()
				p.skipBalanced("(", ")")
			} else {
				p.next()
			}
			for p.eat(".") {
				p.memberName()
			}
			if p.is("<") && !p.tok.NL {
				p.skipTypeArgs()
			}
			return
		case "new":
			p.next()
			if p.is("<") {
				p.skipTypeParams()
			}
			p.skipBalanced("(", ")")
			p.expect("=>")
			p.skipType()
			return
		case "abstract":
			if nt := p.peek(); nt.Val == "new" {
				p.next()
				p.skipPrimaryType()
				return
			}
		case "import":
			p.next()
			p.skipBalanced("(", ")")
			for p.eat(".") {
				p.memberName()
			}
			if p.is("<") && !p.tok.NL {
				p.skipTypeArgs()
			}
			return
		case "asserts":
			if nt := p.peek(); nt.Kind == TIdent && !nt.NL {
				p.next()
			}
		}
		p.next()
		for p.eat(".") {
			p.memberName()
		}
		if p.is("<") && !p.tok.NL {
			p.skipTypeArgs()
		}
		if p.isWord("is") && !p.tok.NL {
			p.next()
			p.skipType()
		}
		return
	}
	p.fail("expected a type, found %q", t.Val)
}

// skipTemplateType skips a template literal type `a${T}b`.
func (p *parser) skipTemplateType() {
	if p.tok.TailTemplate {
		p.next()
		return
	}
	for {
		p.next()
		p.skipType()
		if !p.is("}") {
			p.fail("expected } in template type, found %q", p.tok.Val)
		}
		p.tok = p.lx.rescanTemplate(p.tok)
		if p.tok.TailTemplate {
			p.next()
			return
		}
	}
}

// skipBalanced skips from the opening token to its matching close,
// counting every kind of bracket.
func (p *parser) skipBalanced(open, close string) {
	if !p.is(open) {
		p.fail("expected %s, found %q", open, p.tok.Val)
	}
	depth := 0
	var templates []int
	for {
		t := p.tok
		switch {
		case t.Kind == TEOF:
			p.fail("unexpected end of input, expected %s", close)
		case t.Kind == TTemplate && !t.TailTemplate:
			templates = append(templates, depth)
			depth++
		case isPunct(t, "(") || isPunct(t, "[") || isPunct(t, "{"):
			depth++
		case isPunct(t, ")") || isPunct(t, "]") || isPunct(t, "}"):
			depth--
			if n := len(templates); n > 0 && templates[n-1] == depth && t.Val == "}" {
				templates = templates[:n-1]
				p.tok = p.lx.rescanTemplate(t)
				if !p.tok.TailTemplate {
					templates = append(templates, depth)
					depth++
				}
				break
			}
			if depth <= 0 {
				p.next()
				return
			}
		}
		p.next()
	}
}

// tsDecl parses a TypeScript-only declaration at the current word, or
// returns nil when the word starts something else.
func (p *parser) tsDecl() Stmt {
	t := p.tok
	ln := Pos{t.Line}
	nt := p.peek()
	switch t.Val {
	case "interface":
		if nt.Kind != TIdent || nt.NL {
			return nil
		}
		p.next()
		p.next()
		if p.is("<") {
			p.skipTypeParams()
		}
		if p.isWord("extends") {
			p.next()
			for {
				p.skipType()
				if !p.eat(",") {
					break
				}
			}
		}
		p.skipBalanced("{", "}")
		return &Empty{ln}
	case "type":
		if nt.Kind != TIdent || nt.NL {
			return nil
		}
		p.next()
		p.next()
		if p.is("<") {
			p.skipTypeParams()
		}
		p.expect("=")
		p.skipType()
		p.semi()
		return &Empty{ln}
	case "enum":
		if nt.Kind != TIdent || nt.NL {
			return nil
		}
		return p.tsEnum()
	case "declare":
		if nt.Kind != TIdent || nt.NL {
			return nil
		}
		p.next()
		if p.isWord("global") {
			p.next()
			p.skipBalanced("{", "}")
			return &Empty{ln}
		}
		p.stmt()
		return &Empty{ln}
	case "namespace", "module":
		if nt.Kind != TIdent && nt.Kind != TString || nt.NL {
			return nil
		}
		p.next()
		p.next()
		for p.eat(".") {
			p.memberName()
		}
		if p.is("{") {
			return p.block()
		}
		p.semi()
		return &Empty{ln}
	case "abstract":
		if nt.Val != "class" || nt.NL {
			return nil
		}
		p.next()
		return &ClassDecl{Pos: ln, Class: p.class()}
	case "global":
		if !isPunct(nt, "{") {
			return nil
		}
		p.next()
		p.skipBalanced("{", "}")
		return &Empty{ln}
	}
	return nil
}

// tsEnum skips enum Name { ... } at the enum keyword.
func (p *parser) tsEnum() Stmt {
	ln := Pos{p.tok.Line}
	p.next() // enum
	p.next() // name
	p.skipBalanced("{", "}")
	return &Empty{ln}
}
