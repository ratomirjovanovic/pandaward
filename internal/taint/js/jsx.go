package js

import "strings"

// jsxElement parses a JSX element or fragment at <. It returns with the
// final > as the current token, unconsumed: the caller decides whether JSX
// text or ordinary tokens follow.
func (p *parser) jsxElement() *JSXElement {
	p.enter()
	defer p.leave()
	el := &JSXElement{Pos: Pos{p.tok.Line}}
	p.next() // <
	if p.jsxGT() {
		p.jsxChildren(el)
		return el
	}
	el.Tag = p.jsxTagName()
	if p.ts && p.is("<") {
		p.skipTypeArgs()
	}
	for {
		switch {
		case p.is("/"):
			p.next()
			if !p.jsxGT() {
				p.fail("expected > after / in JSX, found %q", p.tok.Val)
			}
			return el
		case p.jsxGT():
			p.jsxChildren(el)
			return el
		case p.is("{"):
			ln := Pos{p.tok.Line}
			p.next()
			p.expect("...")
			x := p.assign()
			p.expect("}")
			el.Attrs = append(el.Attrs, &JSXAttr{Pos: ln, Value: x, Spread: true})
		case p.tok.Kind == TIdent:
			name := p.lx.jsxName(p.tok)
			a := &JSXAttr{Pos: Pos{name.Line}, Name: name.Val}
			p.next()
			if p.is("=") {
				p.next()
				switch {
				case p.tok.Kind == TString:
					s := p.lx.jsxString(p.tok)
					a.Value = &Lit{Pos: Pos{s.Line}, Kind: TString, Val: s.Val}
					p.next()
				case p.is("{"):
					p.next()
					a.Value = p.assign()
					p.expect("}")
				case p.is("<"):
					a.Value = p.jsxElement()
					p.next()
				default:
					p.fail("expected a JSX attribute value, found %q", p.tok.Val)
				}
			}
			el.Attrs = append(el.Attrs, a)
		default:
			p.fail("unexpected %q in JSX tag", p.tok.Val)
		}
	}
}

// jsxGT reports whether the current token starts with >, and if so makes
// it a lone >: in a JSX tag `>=` or `>>` is the end of the tag followed by
// text.
func (p *parser) jsxGT() bool {
	t := p.tok
	if t.Kind != TPunct || t.Val == "" || t.Val[0] != '>' {
		return false
	}
	if t.Val != ">" {
		p.lx.seek(t.Pos+1, t.Line)
		p.tok.Val, p.tok.End = ">", t.Pos+1
	}
	return true
}

// jsxTagName parses div, my-element, ns:tag or Foo.Bar.
func (p *parser) jsxTagName() string {
	if p.tok.Kind != TIdent {
		p.fail("expected a JSX tag name, found %q", p.tok.Val)
	}
	name := p.lx.jsxName(p.tok).Val
	p.next()
	for p.is(".") {
		p.next()
		name += "." + p.memberName()
	}
	return name
}

// jsxChildren parses children after the > of an opening tag up to and
// including the closing tag, leaving its > as the current token.
func (p *parser) jsxChildren(el *JSXElement) {
	pos, line := p.tok.End, p.tok.Line
	for {
		t := p.lx.jsxText(pos, line)
		if strings.TrimSpace(t.Val) != "" {
			el.Children = append(el.Children, &JSXText{Pos: Pos{t.Line}, Text: t.Val})
		}
		p.next()
		switch {
		case p.tok.Kind == TEOF:
			p.fail("unterminated JSX element <%s>", el.Tag)
		case p.is("{"):
			p.next()
			if !p.is("}") {
				if p.is("...") {
					p.next()
				}
				el.Children = append(el.Children, p.expr())
				if !p.is("}") {
					p.fail("expected } in JSX, found %q", p.tok.Val)
				}
			}
		case p.is("<"):
			if isPunct(p.peek(), "/") {
				p.next()
				p.next()
				for !p.jsxGT() {
					if p.tok.Kind == TEOF {
						p.fail("unterminated JSX closing tag")
					}
					p.next()
				}
				return
			}
			el.Children = append(el.Children, p.jsxElement())
		default:
			p.fail("unexpected %q in JSX", p.tok.Val)
		}
		pos, line = p.tok.End, p.lx.line
	}
}
