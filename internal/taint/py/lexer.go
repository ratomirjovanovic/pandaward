package py

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type tokKind uint8

const (
	tEOF tokKind = iota
	tName
	tNumber
	tString
	tOp
	tNewline
	tIndent
	tDedent
)

// token is one lexical token. A string token keeps its source text with
// prefix and quotes in Val; the parser decodes it.
type token struct {
	kind      tokKind
	val       string
	line, col int
	// space reports whitespace (or a line break) before the token, which
	// tells a soft keyword (match, case, type) from a call or subscript.
	space bool
}

// lexer turns source into tokens, with INDENT and DEDENT for blocks and
// NEWLINE at the end of each logical line. It never fails: an unknown
// character becomes an operator token the parser rejects, and an
// unterminated string ends at the end of its line (or of the file).
type lexer struct {
	src     string
	pos     int
	line    int
	lineAt  int // offset where the current line starts
	indents []int
	depth   int // open brackets
	atBOL   bool
	last    tokKind
	pending []token
	errs    []Error
}

// bom is the UTF-8 byte order mark.
const bom = "\xef\xbb\xbf"

func newLexer(src string) *lexer {
	src = strings.TrimPrefix(src, bom)
	return &lexer{src: src, line: 1, indents: []int{0}, atBOL: true, last: tNewline}
}

func (l *lexer) col() int { return l.pos - l.lineAt + 1 }

func (l *lexer) errorf(line, col int, msg string) {
	if len(l.errs) < maxErrors {
		l.errs = append(l.errs, Error{line, col, msg})
	}
}

func (l *lexer) newline() {
	l.line++
	l.lineAt = l.pos
}

// next returns the next token.
func (l *lexer) next() token {
	if len(l.pending) > 0 {
		t := l.pending[0]
		l.pending = l.pending[1:]
		l.last = t.kind
		return t
	}
	t := l.scan()
	l.last = t.kind
	return t
}

func (l *lexer) emit(t token) token { return t }

func (l *lexer) scan() token {
	for {
		if l.atBOL && l.depth == 0 {
			if t, ok := l.indentation(); ok {
				return t
			}
			if len(l.pending) > 0 {
				t := l.pending[0]
				l.pending = l.pending[1:]
				return t
			}
		}
		space := false
		for l.pos < len(l.src) {
			c := l.src[l.pos]
			if c == ' ' || c == '\t' || c == '\f' {
				l.pos++
				space = true
				continue
			}
			if c == '\\' && l.pos+1 < len(l.src) && (l.src[l.pos+1] == '\n' || l.src[l.pos+1] == '\r') {
				l.pos++
				if l.src[l.pos] == '\r' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '\n' {
					l.pos++
				}
				l.pos++
				l.newline()
				space = true
				continue
			}
			break
		}
		if l.pos >= len(l.src) {
			return l.eof()
		}
		c := l.src[l.pos]
		line, col := l.line, l.col()
		switch {
		case c == '#':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' && l.src[l.pos] != '\r' {
				l.pos++
			}
			continue
		case c == '\n' || c == '\r':
			if c == '\r' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '\n' {
				l.pos++
			}
			l.pos++
			l.newline()
			if l.depth > 0 {
				continue
			}
			l.atBOL = true
			if l.last == tNewline || l.last == tIndent || l.last == tDedent {
				continue // blank line or comment-only line
			}
			return token{kind: tNewline, line: line, col: col}
		case isIdentStart(c, l.src[l.pos:]):
			start := l.pos
			l.ident()
			word := l.src[start:l.pos]
			if l.pos < len(l.src) && (l.src[l.pos] == '\'' || l.src[l.pos] == '"') && isStringPrefix(word) {
				l.pos = start
				return l.string(line, col, space)
			}
			return token{kind: tName, val: word, line: line, col: col, space: space}
		case c >= '0' && c <= '9' || c == '.' && l.pos+1 < len(l.src) && l.src[l.pos+1] >= '0' && l.src[l.pos+1] <= '9':
			return l.number(line, col, space)
		case c == '\'' || c == '"':
			return l.string(line, col, space)
		}
		op := l.operator()
		switch op {
		case "(", "[", "{":
			l.depth++
		case ")", "]", "}":
			if l.depth > 0 {
				l.depth--
			}
		}
		return token{kind: tOp, val: op, line: line, col: col, space: space}
	}
}

// indentation measures the indentation of a new logical line and queues
// INDENT or DEDENT tokens. Blank and comment-only lines are skipped.
func (l *lexer) indentation() (token, bool) {
	for {
		width, p := 0, l.pos
		for p < len(l.src) {
			switch l.src[p] {
			case ' ':
				width++
			case '\t':
				width = (width/8 + 1) * 8
			case '\f':
				width = 0
			default:
				goto done
			}
			p++
		}
	done:
		if p >= len(l.src) {
			l.pos = p
			l.atBOL = false
			return token{}, false
		}
		c := l.src[p]
		if c == '\n' || c == '\r' || c == '#' {
			// Blank or comment-only line: skip it whole.
			for p < len(l.src) && l.src[p] != '\n' && l.src[p] != '\r' {
				p++
			}
			if p < len(l.src) && l.src[p] == '\r' {
				p++
			}
			if p < len(l.src) && l.src[p] == '\n' {
				p++
			}
			l.pos = p
			if p >= len(l.src) {
				l.atBOL = false
				return token{}, false
			}
			l.newline()
			continue
		}
		if c == '\\' && p+1 < len(l.src) && (l.src[p+1] == '\n' || l.src[p+1] == '\r') {
			// A continuation at the start of a line joins the next one.
			l.pos = p
			l.atBOL = false
			return token{}, false
		}
		l.pos = p
		l.atBOL = false
		line, col := l.line, l.col()
		top := l.indents[len(l.indents)-1]
		switch {
		case width > top:
			l.indents = append(l.indents, width)
			return token{kind: tIndent, line: line, col: col}, true
		case width < top:
			for len(l.indents) > 1 && width < l.indents[len(l.indents)-1] {
				l.indents = l.indents[:len(l.indents)-1]
				l.pending = append(l.pending, token{kind: tDedent, line: line, col: col})
			}
			if width != l.indents[len(l.indents)-1] {
				l.errorf(line, col, "unindent does not match any outer indentation level")
				l.indents = append(l.indents, width)
			}
			t := l.pending[0]
			l.pending = l.pending[1:]
			return t, true
		}
		return token{}, false
	}
}

func (l *lexer) eof() token {
	line, col := l.line, l.col()
	if l.last != tNewline && l.last != tIndent && l.last != tDedent && l.last != tEOF {
		for len(l.indents) > 1 {
			l.indents = l.indents[:len(l.indents)-1]
			l.pending = append(l.pending, token{kind: tDedent, line: line, col: col})
		}
		l.pending = append(l.pending, token{kind: tEOF, line: line, col: col})
		return token{kind: tNewline, line: line, col: col}
	}
	if len(l.indents) > 1 {
		l.indents = l.indents[:len(l.indents)-1]
		return token{kind: tDedent, line: line, col: col}
	}
	return token{kind: tEOF, line: line, col: col}
}

func isIdentStart(c byte, rest string) bool {
	if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
		return true
	}
	if c < utf8.RuneSelf {
		return false
	}
	r, _ := utf8.DecodeRuneInString(rest)
	return unicode.IsLetter(r) || unicode.Is(unicode.Other_ID_Start, r)
}

func (l *lexer) ident() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			l.pos++
			continue
		}
		if c < utf8.RuneSelf {
			return
		}
		r, n := utf8.DecodeRuneInString(l.src[l.pos:])
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Pc, r) || unicode.Is(unicode.Other_ID_Continue, r)) {
			return
		}
		l.pos += n
	}
}

// isStringPrefix reports a valid string prefix: any order and case of r
// with one of b, f or t, or u alone.
func isStringPrefix(w string) bool {
	if len(w) > 2 {
		return false
	}
	w = strings.ToLower(w)
	switch w {
	case "r", "u", "b", "f", "t", "rb", "br", "rf", "fr", "rt", "tr":
		return true
	}
	return false
}

func (l *lexer) number(line, col int, space bool) token {
	start := l.pos
	s := l.src
	if s[l.pos] == '0' && l.pos+1 < len(s) && strings.ContainsRune("xXoObB", rune(s[l.pos+1])) {
		l.pos += 2
		for l.pos < len(s) && (isHex(s[l.pos]) || s[l.pos] == '_') {
			l.pos++
		}
	} else {
		digits := func() {
			for l.pos < len(s) && (s[l.pos] >= '0' && s[l.pos] <= '9' || s[l.pos] == '_') {
				l.pos++
			}
		}
		digits()
		if l.pos < len(s) && s[l.pos] == '.' {
			l.pos++
			digits()
		}
		if l.pos < len(s) && (s[l.pos] == 'e' || s[l.pos] == 'E') {
			p := l.pos + 1
			if p < len(s) && (s[p] == '+' || s[p] == '-') {
				p++
			}
			if p < len(s) && s[p] >= '0' && s[p] <= '9' {
				l.pos = p
				digits()
			}
		}
	}
	if l.pos < len(s) && (s[l.pos] == 'j' || s[l.pos] == 'J' || s[l.pos] == 'l' || s[l.pos] == 'L') {
		l.pos++
	}
	return token{kind: tNumber, val: s[start:l.pos], line: line, col: col, space: space}
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// string scans a string literal starting at l.pos (prefix included). In an
// f-string (or t-string) the replacement fields may hold any expression,
// including strings with the same quotes, so fields are skipped with
// skipField.
func (l *lexer) string(line, col int, space bool) token {
	start := l.pos
	for l.src[l.pos] != '\'' && l.src[l.pos] != '"' {
		l.pos++
	}
	prefix := strings.ToLower(l.src[start:l.pos])
	raw := strings.ContainsRune(prefix, 'r')
	fmtStr := strings.ContainsAny(prefix, "ft")
	if !l.scanBody(raw, fmtStr, line, col) {
		l.errorf(line, col, "unterminated string literal")
	}
	return token{kind: tString, val: l.src[start:l.pos], line: line, col: col, space: space}
}

// scanBody scans from the opening quote to past the closing one and
// reports whether the string was terminated.
func (l *lexer) scanBody(raw, fmtStr bool, line, col int) bool {
	s := l.src
	q := s[l.pos]
	triple := l.pos+2 < len(s) && s[l.pos+1] == q && s[l.pos+2] == q
	if triple {
		l.pos += 3
	} else {
		l.pos++
	}
	for l.pos < len(s) {
		c := s[l.pos]
		switch {
		case c == '\\':
			l.pos++
			if l.pos < len(s) {
				if s[l.pos] == '\n' || s[l.pos] == '\r' {
					if s[l.pos] == '\r' && l.pos+1 < len(s) && s[l.pos+1] == '\n' {
						l.pos++
					}
					l.pos++
					l.newline()
					continue
				}
				l.pos++
			}
			_ = raw // a backslash escapes the quote in raw strings too
		case c == q:
			if !triple {
				l.pos++
				return true
			}
			if l.pos+2 < len(s) && s[l.pos+1] == q && s[l.pos+2] == q {
				l.pos += 3
				return true
			}
			l.pos++
		case c == '\n' || c == '\r':
			if !triple {
				return false
			}
			if c == '\r' && l.pos+1 < len(s) && s[l.pos+1] == '\n' {
				l.pos++
			}
			l.pos++
			l.newline()
		case fmtStr && c == '{':
			if l.pos+1 < len(s) && s[l.pos+1] == '{' {
				l.pos += 2
				continue
			}
			l.pos++
			l.skipField()
		default:
			l.pos++
		}
	}
	return false
}

// skipField skips an f-string replacement field after its "{", up to and
// past the matching "}". Nested brackets and strings are skipped whole; a
// format spec may hold nested fields.
func (l *lexer) skipField() {
	s := l.src
	depth := 0
	for l.pos < len(s) {
		c := s[l.pos]
		switch {
		case c == '\'' || c == '"':
			// A string inside the expression; it may be an f-string too.
			p := l.pos - 1
			for p >= 0 && (s[p] >= 'a' && s[p] <= 'z' || s[p] >= 'A' && s[p] <= 'Z') {
				p--
			}
			prefix := strings.ToLower(s[p+1 : l.pos])
			if !isStringPrefix(prefix) {
				prefix = ""
			}
			l.scanBody(strings.ContainsRune(prefix, 'r'), strings.ContainsAny(prefix, "ft"), l.line, l.col())
		case c == '(' || c == '[' || c == '{':
			depth++
			l.pos++
		case c == ')' || c == ']':
			depth--
			l.pos++
		case c == '}':
			l.pos++
			if depth == 0 {
				return
			}
			depth--
		case c == '\n':
			l.pos++
			l.newline()
		case c == '#':
			for l.pos < len(s) && s[l.pos] != '\n' {
				l.pos++
			}
		default:
			l.pos++
		}
	}
}

var ops3 = []string{"**=", "//=", ">>=", "<<=", "...", "!=="}
var ops2 = []string{"**", "//", "<<", ">>", "<=", ">=", "==", "!=", "->", ":=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "@=", "<>"}

func (l *lexer) operator() string {
	rest := l.src[l.pos:]
	for _, o := range ops3[:5] {
		if strings.HasPrefix(rest, o) {
			l.pos += 3
			return o
		}
	}
	for _, o := range ops2 {
		if strings.HasPrefix(rest, o) {
			l.pos += 2
			return o
		}
	}
	r, n := utf8.DecodeRuneInString(rest)
	l.pos += n
	return string(r)
}
