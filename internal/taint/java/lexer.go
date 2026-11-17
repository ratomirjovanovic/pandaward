package java

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

type tokKind uint8

const (
	tEOF tokKind = iota
	tIdent
	tKeyword
	tInt
	tFloat
	tChar
	tString
	tOp
)

type token struct {
	kind      tokKind
	val       string // identifier, keyword, operator, or the decoded literal
	line, col int
}

// keywords are reserved; contextual words (var, record, yield, sealed,
// permits, non-sealed, module words) are identifiers the parser checks.
var keywords = map[string]bool{
	"abstract": true, "assert": true, "boolean": true, "break": true, "byte": true, "case": true, "catch": true,
	"char": true, "class": true, "const": true, "continue": true, "default": true, "do": true, "double": true,
	"else": true, "enum": true, "extends": true, "final": true, "finally": true, "float": true, "for": true,
	"goto": true, "if": true, "implements": true, "import": true, "instanceof": true, "int": true,
	"interface": true, "long": true, "native": true, "new": true, "package": true, "private": true,
	"protected": true, "public": true, "return": true, "short": true, "static": true, "strictfp": true,
	"super": true, "switch": true, "synchronized": true, "this": true, "throw": true, "throws": true,
	"transient": true, "try": true, "void": true, "volatile": true, "while": true,
	"true": true, "false": true, "null": true,
}

// operators, longest first within each length.
var ops4 = []string{">>>="}
var ops3 = []string{"<<=", ">>=", ">>>", "..."}
var ops2 = []string{"==", "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", "&=", "|=", "^=", "%=", "<<", ">>", "->", "::"}

type lexer struct {
	src       string
	pos       int
	line, col int
	toks      []token
	errs      []Error
}

func lex(src string) ([]token, []Error) {
	l := &lexer{src: src, line: 1, col: 1}
	for {
		t := l.next()
		l.toks = append(l.toks, t)
		if t.kind == tEOF {
			break
		}
	}
	return l.toks, l.errs
}

func (l *lexer) errorf(line, col int, msg string) {
	l.errs = append(l.errs, Error{Line: line, Col: col, Msg: msg})
}

func (l *lexer) advance(n int) {
	for i := 0; i < n && l.pos < len(l.src); i++ {
		if l.src[l.pos] == '\n' {
			l.line++
			l.col = 1
		} else {
			l.col++
		}
		l.pos++
	}
}

func (l *lexer) skipSpace() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f':
			l.advance(1)
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.advance(1)
			}
		case c == '/' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '*':
			l.advance(2)
			for l.pos < len(l.src) && !(l.src[l.pos] == '*' && l.pos+1 < len(l.src) && l.src[l.pos+1] == '/') {
				l.advance(1)
			}
			l.advance(2)
		case c >= 0x80:
			r, n := utf8.DecodeRuneInString(l.src[l.pos:])
			if !unicode.IsSpace(r) {
				return
			}
			l.pos += n
			l.col++
		default:
			return
		}
	}
}

func isIdentStart(r rune) bool { return r == '_' || r == '$' || unicode.IsLetter(r) }
func isIdentPart(r rune) bool  { return isIdentStart(r) || unicode.IsDigit(r) }

func (l *lexer) next() token {
	l.skipSpace()
	line, col := l.line, l.col
	if l.pos >= len(l.src) {
		return token{kind: tEOF, line: line, col: col}
	}
	s := l.src[l.pos:]
	r, n := utf8.DecodeRuneInString(s)
	switch {
	case isIdentStart(r):
		end := n
		for end < len(s) {
			r2, n2 := utf8.DecodeRuneInString(s[end:])
			if !isIdentPart(r2) {
				break
			}
			end += n2
		}
		word := s[:end]
		l.pos += end
		l.col += utf8.RuneCountInString(word)
		if keywords[word] {
			return token{kind: tKeyword, val: word, line: line, col: col}
		}
		return token{kind: tIdent, val: word, line: line, col: col}
	case r >= '0' && r <= '9' || r == '.' && len(s) > 1 && s[1] >= '0' && s[1] <= '9':
		return l.number(line, col)
	case r == '"':
		if strings.HasPrefix(s, `"""`) {
			return l.textBlock(line, col)
		}
		return l.quoted('"', tString, line, col)
	case r == '\'':
		return l.quoted('\'', tChar, line, col)
	}
	for _, set := range [][]string{ops4, ops3, ops2} {
		for _, op := range set {
			if strings.HasPrefix(s, op) {
				l.advance(len(op))
				return token{kind: tOp, val: op, line: line, col: col}
			}
		}
	}
	l.pos += n
	l.col++
	if strings.ContainsRune("(){}[];,.@=<>!~?:+-*/&|^%", r) {
		return token{kind: tOp, val: string(r), line: line, col: col}
	}
	l.errorf(line, col, "unexpected character "+string(r))
	return l.next()
}

func (l *lexer) number(line, col int) token {
	s := l.src[l.pos:]
	i := 0
	float := false
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") || strings.HasPrefix(s, "0b") || strings.HasPrefix(s, "0B") {
		i = 2
		for i < len(s) && (isHex(s[i]) || s[i] == '_') {
			i++
		}
		if i < len(s) && (s[i] == '.' || s[i] == 'p' || s[i] == 'P') {
			float = true
			for i < len(s) && (isHex(s[i]) || s[i] == '.' || s[i] == 'p' || s[i] == 'P' || s[i] == '_' || (s[i] == '+' || s[i] == '-') && (s[i-1] == 'p' || s[i-1] == 'P')) {
				i++
			}
		}
	} else {
		for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '_') {
			i++
		}
		if i < len(s) && s[i] == '.' && (i+1 >= len(s) || s[i+1] != '.') && !(i+1 < len(s) && isIdentStart(rune(s[i+1])) && s[i+1] != 'e' && s[i+1] != 'E' && s[i+1] != 'f' && s[i+1] != 'F' && s[i+1] != 'd' && s[i+1] != 'D') {
			float = true
			i++
			for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '_') {
				i++
			}
		}
		if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
			float = true
			i++
			if i < len(s) && (s[i] == '+' || s[i] == '-') {
				i++
			}
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
		}
	}
	kind := tInt
	if i < len(s) {
		switch s[i] {
		case 'l', 'L':
			i++
		case 'f', 'F', 'd', 'D':
			float = true
			i++
		}
	}
	if float {
		kind = tFloat
	}
	text := s[:i]
	l.advance(i)
	return token{kind: kind, val: text, line: line, col: col}
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// quoted reads a string or char literal and decodes its escapes.
func (l *lexer) quoted(q byte, kind tokKind, line, col int) token {
	l.advance(1)
	var sb strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		if c == q {
			l.advance(1)
			return token{kind: kind, val: sb.String(), line: line, col: col}
		}
		if c == '\n' {
			break
		}
		if c == '\\' && l.pos+1 < len(l.src) {
			l.escape(&sb)
			continue
		}
		r, n := utf8.DecodeRuneInString(l.src[l.pos:])
		sb.WriteRune(r)
		l.pos += n
		l.col++
	}
	l.errorf(line, col, "unterminated literal")
	return token{kind: kind, val: sb.String(), line: line, col: col}
}

func (l *lexer) escape(sb *strings.Builder) {
	e := l.src[l.pos+1]
	switch e {
	case 'n':
		sb.WriteByte('\n')
	case 't':
		sb.WriteByte('\t')
	case 'r':
		sb.WriteByte('\r')
	case 'b':
		sb.WriteByte('\b')
	case 'f':
		sb.WriteByte('\f')
	case 's':
		sb.WriteByte(' ')
	case '0', '1', '2', '3', '4', '5', '6', '7':
		v, i := 0, l.pos+1
		for j := 0; j < 3 && i < len(l.src) && l.src[i] >= '0' && l.src[i] <= '7'; j++ {
			v = v*8 + int(l.src[i]-'0')
			i++
		}
		sb.WriteRune(rune(v))
		l.advance(i - l.pos)
		return
	case 'u':
		i := l.pos + 1
		for i < len(l.src) && l.src[i] == 'u' {
			i++
		}
		if i+4 <= len(l.src) {
			v := 0
			ok := true
			for _, c := range []byte(l.src[i : i+4]) {
				switch {
				case c >= '0' && c <= '9':
					v = v*16 + int(c-'0')
				case c >= 'a' && c <= 'f':
					v = v*16 + int(c-'a'+10)
				case c >= 'A' && c <= 'F':
					v = v*16 + int(c-'A'+10)
				default:
					ok = false
				}
			}
			if ok {
				sb.WriteRune(rune(v))
				l.advance(i + 4 - l.pos)
				return
			}
		}
		sb.WriteByte('u')
	case '\n':
		// a line continuation in a text block
	default:
		sb.WriteByte(e)
	}
	l.advance(2)
}

// textBlock reads """ ... """ and strips the common indentation.
func (l *lexer) textBlock(line, col int) token {
	l.advance(3)
	for l.pos < len(l.src) && l.src[l.pos] != '\n' {
		l.advance(1)
	}
	l.advance(1)
	var sb strings.Builder
	for l.pos < len(l.src) {
		if strings.HasPrefix(l.src[l.pos:], `"""`) {
			l.advance(3)
			return token{kind: tString, val: stripIndent(sb.String()), line: line, col: col}
		}
		if l.src[l.pos] == '\\' && l.pos+1 < len(l.src) {
			l.escape(&sb)
			continue
		}
		sb.WriteByte(l.src[l.pos])
		l.advance(1)
	}
	l.errorf(line, col, "unterminated text block")
	return token{kind: tString, val: sb.String(), line: line, col: col}
}

func stripIndent(s string) string {
	lines := strings.Split(s, "\n")
	min := -1
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		n := len(ln) - len(strings.TrimLeft(ln, " \t"))
		if min < 0 || n < min {
			min = n
		}
	}
	if min <= 0 {
		return s
	}
	for i, ln := range lines {
		if len(ln) >= min {
			lines[i] = ln[min:]
		} else {
			lines[i] = strings.TrimLeft(ln, " \t")
		}
	}
	return strings.Join(lines, "\n")
}
