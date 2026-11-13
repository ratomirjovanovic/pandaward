// Package js parses JavaScript, TypeScript and JSX into a small AST for the
// taint engine. It is written for analysis, not for execution: it accepts
// any source, records syntax errors and keeps going, so one construct it does
// not understand costs a statement, not the file. Type annotations are
// parsed and dropped.
package js

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kind is a token kind.
type Kind uint8

const (
	TEOF Kind = iota
	TIdent
	TPrivateName // #name
	TNumber
	TString
	TTemplate // a whole template without substitutions, or one part of one
	TRegex
	TPunct
	TJSXText
)

var kindNames = [...]string{"EOF", "Ident", "PrivateName", "Number", "String", "Template", "Regex", "Punct", "JSXText"}

func (k Kind) String() string { return kindNames[k] }

// Token is one lexical token. Val is the source text, except for strings and
// template parts, where it is the cooked value.
type Token struct {
	Kind Kind
	Val  string
	Pos  int  // byte offset of the first byte
	End  int  // byte offset after the last byte
	Line int  // 1-based line of Pos
	NL   bool // a line break precedes the token
	// TailTemplate is set on a Template token that ends the template (it
	// closes with a backquote rather than opening a substitution).
	TailTemplate bool
}

// lexer scans tokens on demand. The parser decides the context: a slash is
// always lexed as an operator, and the parser rescans it as a regular
// expression where an expression starts; a closing brace is rescanned as the
// continuation of a template when it ends a substitution.
type lexer struct {
	src  string
	pos  int
	line int
	// la caches the token after the current one for peek, with the lexer
	// state after it. Any method that moves pos drops it.
	la            Token
	laPos, laLine int
	hasLA         bool
}

// peekNext returns the next token without consuming it.
func (l *lexer) peekNext() Token {
	if !l.hasLA {
		pos, line := l.pos, l.line
		l.la = l.scan()
		l.laPos, l.laLine = l.pos, l.line
		l.pos, l.line = pos, line
		l.hasLA = true
	}
	return l.la
}

// next scans the next token in the default context.
func (l *lexer) next() Token {
	if l.hasLA {
		l.hasLA = false
		l.pos, l.line = l.laPos, l.laLine
		return l.la
	}
	return l.scan()
}

// seek moves the lexer, dropping the lookahead.
func (l *lexer) seek(pos, line int) {
	l.pos, l.line, l.hasLA = pos, line, false
}

func newLexer(src string) *lexer {
	l := &lexer{src: src, line: 1}
	// A hashbang line is a comment.
	if strings.HasPrefix(src, "#!") {
		for l.pos < len(src) && src[l.pos] != '\n' {
			l.pos++
		}
	}
	return l
}

// skipSpace skips white space and comments and reports whether a line
// break was among them.
func (l *lexer) skipSpace() bool {
	nl := false
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			nl = true
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f':
			l.pos++
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			end := strings.Index(l.src[l.pos+2:], "*/")
			stop := len(l.src)
			if end >= 0 {
				stop = l.pos + 2 + end + 2
			}
			if n := strings.Count(l.src[l.pos:stop], "\n"); n > 0 {
				nl = true
				l.line += n
			}
			l.pos = stop
		case c >= utf8.RuneSelf:
			r, size := utf8.DecodeRuneInString(l.src[l.pos:])
			if r == '\u2028' || r == '\u2029' {
				nl = true
				l.pos += size
				continue
			}
			if r == '\ufeff' || r == '\u00a0' || unicode.Is(unicode.Zs, r) {
				l.pos += size
				continue
			}
			return nl
		default:
			return nl
		}
	}
	return nl
}

func isIDStart(r rune) bool {
	return r == '$' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= utf8.RuneSelf && unicode.IsLetter(r)
}

func isIDPart(r rune) bool {
	return isIDStart(r) || r >= '0' && r <= '9' || r == '\u200c' || r == '\u200d' ||
		r >= utf8.RuneSelf && (unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Pc, r))
}

// punctsByByte lists the operators starting with each byte, longest first.
var punctsByByte = func() [256][]string {
	var t [256][]string
	for _, p := range []string{
		">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
		"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
		"{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/", "%", "&", "|", "^", "!", "~", "?", ":", "=", ".", "@", "#",
	} {
		t[p[0]] = append(t[p[0]], p)
	}
	return t
}()

// scanPunct returns the longest operator at the start of rest, or "".
func scanPunct(rest string) string {
	for _, p := range punctsByByte[rest[0]] {
		if len(rest) >= len(p) && rest[:len(p)] == p {
			// a?.5 is a conditional with .5, not optional chaining.
			if p == "?." && len(rest) > 2 && rest[2] >= '0' && rest[2] <= '9' {
				continue
			}
			return p
		}
	}
	return ""
}

// scan lexes one token at pos.
func (l *lexer) scan() Token {
	nl := l.skipSpace()
	t := Token{Pos: l.pos, Line: l.line, NL: nl}
	if l.pos >= len(l.src) {
		t.Kind, t.End = TEOF, l.pos
		return t
	}
	c := l.src[l.pos]
	switch {
	case c == '\'' || c == '"':
		t.Kind, t.Val = TString, l.scanString(c)
	case c == '`':
		l.pos++
		t.Kind = TTemplate
		t.Val, t.TailTemplate = l.scanTemplatePart()
	case c >= '0' && c <= '9' || c == '.' && l.pos+1 < len(l.src) && l.src[l.pos+1] >= '0' && l.src[l.pos+1] <= '9':
		t.Kind, t.Val = TNumber, l.scanNumber()
	case c == '#' && l.pos+1 < len(l.src) && l.identStartAt(l.pos+1):
		l.pos++
		t.Kind, t.Val = TPrivateName, "#"+l.scanIdent()
	case l.identStartAt(l.pos):
		t.Kind, t.Val = TIdent, l.scanIdent()
	default:
		t.Kind = TPunct
		rest := l.src[l.pos:]
		t.Val = scanPunct(rest)
		if t.Val == "" {
			// An unknown character becomes its own token so the parser can
			// report it and move on.
			_, size := utf8.DecodeRuneInString(rest)
			t.Val = rest[:size]
		}
		l.pos += len(t.Val)
	}
	t.End = l.pos
	return t
}

func (l *lexer) identStartAt(i int) bool {
	if i >= len(l.src) {
		return false
	}
	if l.src[i] == '\\' {
		return i+1 < len(l.src) && l.src[i+1] == 'u'
	}
	r, _ := utf8.DecodeRuneInString(l.src[i:])
	return isIDStart(r)
}

func (l *lexer) scanIdent() string {
	start := l.pos
	escaped := false
	for l.pos < len(l.src) {
		if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) && l.src[l.pos+1] == 'u' {
			escaped = true
			l.pos += 2
			if l.pos < len(l.src) && l.src[l.pos] == '{' {
				for l.pos < len(l.src) && l.src[l.pos] != '}' {
					l.pos++
				}
				l.pos++
			} else {
				l.pos += 4
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(l.src[l.pos:])
		if !isIDPart(r) {
			break
		}
		l.pos += size
	}
	if l.pos > len(l.src) {
		l.pos = len(l.src)
	}
	if !escaped {
		return l.src[start:l.pos]
	}
	return unescapeIdent(l.src[start:l.pos])
}

func unescapeIdent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == 'u' {
			r, n := readUnicodeEscape(s[i+2:])
			if n > 0 {
				b.WriteRune(r)
				i += 1 + n
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// readUnicodeEscape reads XXXX or {X...} and returns the rune and the bytes
// consumed, or 0 bytes when the escape is malformed.
func readUnicodeEscape(s string) (rune, int) {
	if strings.HasPrefix(s, "{") {
		end := strings.IndexByte(s, '}')
		if end < 2 {
			return 0, 0
		}
		v, ok := hexVal(s[1:end])
		if !ok {
			return 0, 0
		}
		return rune(v), end + 1
	}
	if len(s) < 4 {
		return 0, 0
	}
	v, ok := hexVal(s[:4])
	if !ok {
		return 0, 0
	}
	return rune(v), 4
}

func hexVal(s string) (int, bool) {
	if s == "" || len(s) > 6 {
		return 0, false
	}
	v := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + int(c-'0')
		case c >= 'a' && c <= 'f':
			v = v*16 + int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v = v*16 + int(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

func (l *lexer) scanNumber() string {
	start := l.pos
	s := l.src
	if s[l.pos] == '0' && l.pos+1 < len(s) && strings.IndexByte("xXoObB", s[l.pos+1]) >= 0 {
		l.pos += 2
		for l.pos < len(s) && (isHex(s[l.pos]) || s[l.pos] == '_') {
			l.pos++
		}
	} else {
		for l.pos < len(s) && (s[l.pos] >= '0' && s[l.pos] <= '9' || s[l.pos] == '_') {
			l.pos++
		}
		if l.pos < len(s) && s[l.pos] == '.' {
			l.pos++
			for l.pos < len(s) && (s[l.pos] >= '0' && s[l.pos] <= '9' || s[l.pos] == '_') {
				l.pos++
			}
		}
		if l.pos < len(s) && (s[l.pos] == 'e' || s[l.pos] == 'E') {
			j := l.pos + 1
			if j < len(s) && (s[j] == '+' || s[j] == '-') {
				j++
			}
			if j < len(s) && s[j] >= '0' && s[j] <= '9' {
				l.pos = j
				for l.pos < len(s) && (s[l.pos] >= '0' && s[l.pos] <= '9' || s[l.pos] == '_') {
					l.pos++
				}
			}
		}
	}
	if l.pos < len(s) && s[l.pos] == 'n' {
		l.pos++
	}
	return s[start:l.pos]
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// scanString scans a quoted string at l.pos and returns its cooked value. An
// unterminated string ends at the line break.
func (l *lexer) scanString(q byte) string {
	l.pos++
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch c {
		case q:
			l.pos++
			return b.String()
		case '\n':
			return b.String()
		case '\\':
			l.pos++
			l.escape(&b)
			continue
		}
		b.WriteByte(c)
		l.pos++
	}
	return b.String()
}

// escape reads the escape sequence after a backslash into b.
func (l *lexer) escape(b *strings.Builder) {
	if l.pos >= len(l.src) {
		return
	}
	c := l.src[l.pos]
	l.pos++
	switch c {
	case 'n':
		b.WriteByte('\n')
	case 't':
		b.WriteByte('\t')
	case 'r':
		b.WriteByte('\r')
	case 'b':
		b.WriteByte('\b')
	case 'f':
		b.WriteByte('\f')
	case 'v':
		b.WriteByte('\v')
	case '0':
		b.WriteByte(0)
	case '\r':
		if l.pos < len(l.src) && l.src[l.pos] == '\n' {
			l.pos++
		}
		l.line++
	case '\n':
		l.line++
	case 'x':
		if l.pos+2 <= len(l.src) {
			if v, ok := hexVal(l.src[l.pos : l.pos+2]); ok {
				b.WriteRune(rune(v))
				l.pos += 2
				return
			}
		}
		b.WriteByte('x')
	case 'u':
		r, n := readUnicodeEscape(l.src[l.pos:])
		if n == 0 {
			b.WriteByte('u')
			return
		}
		b.WriteRune(r)
		l.pos += n
	default:
		// Any other escaped character, including a multi-byte one, stands
		// for itself.
		l.pos--
		_, size := utf8.DecodeRuneInString(l.src[l.pos:])
		b.WriteString(l.src[l.pos : l.pos+size])
		l.pos += size
	}
}

// scanTemplatePart scans template text from l.pos (just after ` or }) up to
// and including the closing ` or the ${ of a substitution. It reports the
// cooked text and whether the template ends here.
func (l *lexer) scanTemplatePart() (string, bool) {
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '`':
			l.pos++
			return b.String(), true
		case c == '$' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '{':
			l.pos += 2
			return b.String(), false
		case c == '\\':
			l.pos++
			l.escape(&b)
			continue
		case c == '\n':
			l.line++
		}
		b.WriteByte(c)
		l.pos++
	}
	return b.String(), true
}

// rescanTemplate turns the closing brace token t of a substitution into the
// next template part.
func (l *lexer) rescanTemplate(t Token) Token {
	l.seek(t.Pos+1, t.Line)
	nt := Token{Kind: TTemplate, Pos: t.Pos, Line: t.Line, NL: t.NL}
	nt.Val, nt.TailTemplate = l.scanTemplatePart()
	nt.End = l.pos
	return nt
}

// rescanRegex turns the slash token t into a regular expression literal.
// It reports false, leaving the lexer unchanged, when no regex closes on the
// line.
func (l *lexer) rescanRegex(t Token) (Token, bool) {
	inClass := false
	for j := t.Pos + 1; j < len(l.src); j++ {
		switch l.src[j] {
		case '\\':
			j++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '\n':
			return t, false
		case '/':
			if inClass {
				continue
			}
			j++
			for j < len(l.src) && (isIdentByte(l.src[j])) {
				j++
			}
			l.seek(j, l.line)
			return Token{Kind: TRegex, Val: l.src[t.Pos:j], Pos: t.Pos, End: j, Line: t.Line, NL: t.NL}, true
		}
	}
	return t, false
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// jsxText scans JSX child text from pos up to the next < or {.
func (l *lexer) jsxText(pos, line int) Token {
	l.seek(pos, line)
	start := pos
	for l.pos < len(l.src) && l.src[l.pos] != '<' && l.src[l.pos] != '{' {
		if l.src[l.pos] == '\n' {
			l.line++
		}
		l.pos++
	}
	return Token{Kind: TJSXText, Val: l.src[start:l.pos], Pos: start, End: l.pos, Line: line}
}

// jsxName extends the identifier token t over JSX name characters (- and
// :), as in data-id or xlink:href.
func (l *lexer) jsxName(t Token) Token {
	if t.Kind != TIdent {
		return t
	}
	l.seek(t.End, l.line)
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '-' || c == ':' || isIdentByte(c) {
			l.pos++
			continue
		}
		break
	}
	t.Val, t.End = l.src[t.Pos:l.pos], l.pos
	return t
}

// jsxString scans a JSX attribute string, where backslashes are plain text.
func (l *lexer) jsxString(t Token) Token {
	q := l.src[t.Pos]
	end := strings.IndexByte(l.src[t.Pos+1:], q)
	if end < 0 {
		return t
	}
	l.seek(t.Pos+1+end+1, l.line)
	val := l.src[t.Pos+1 : t.Pos+1+end]
	l.line = t.Line + strings.Count(val, "\n")
	return Token{Kind: TString, Val: val, Pos: t.Pos, End: l.pos, Line: t.Line, NL: t.NL}
}
