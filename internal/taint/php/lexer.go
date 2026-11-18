// Package php is the PHP front end of the taint engine: a lexer and a
// parser that lowers straight to the IR (internal/taint/ir), covering the
// language of web applications (superglobals, string interpolation,
// functions, classes, control flow) and not all of PHP. What it does not
// understand is skipped statement by statement, so one construct does not
// hide a whole file.
package php

import (
	"strings"
)

type kind uint8

const (
	tEOF kind = iota
	tInline
	tVar    // $name (s is the name without $)
	tIdent  // names, keywords, namespaced names
	tNum    // number
	tStr    // string without interpolation (s is the decoded text)
	tTpl    // string with interpolation (parts)
	tOp     // operator or punctuation
	tCast   // (int) and friends (s is the type)
	tOpenEc // <?=
)

// part is a piece of an interpolated string: literal text, or the source
// of an expression with the line it starts on.
type part struct {
	lit  string
	code string
	line int
}

type token struct {
	k     kind
	s     string
	line  int
	col   int
	parts []part
	// shell marks a backtick string, which runs a command.
	shell bool
}

type lexer struct {
	src  string
	pos  int
	line int
	toks []token
}

// lex splits source into tokens. Text outside <?php ... ?> becomes inline
// tokens; ?> acts as a semicolon.
func lex(src string, startLine int, code bool) []token {
	lx := &lexer{src: src, line: startLine}
	if !code {
		lx.inline()
	}
	lx.php()
	lx.toks = append(lx.toks, token{k: tEOF, line: lx.line})
	return lx.toks
}

func (lx *lexer) emit(k kind, s string, line, col int) {
	lx.toks = append(lx.toks, token{k: k, s: s, line: line, col: col})
}

// inline reads text up to the next opening tag.
func (lx *lexer) inline() {
	start := lx.pos
	for lx.pos < len(lx.src) {
		if strings.HasPrefix(lx.src[lx.pos:], "<?php") || strings.HasPrefix(lx.src[lx.pos:], "<?=") {
			break
		}
		if lx.src[lx.pos] == '\n' {
			lx.line++
		}
		lx.pos++
	}
	if lx.pos > start {
		lx.emit(tInline, lx.src[start:lx.pos], lx.line, 1)
	}
	if lx.pos < len(lx.src) {
		if strings.HasPrefix(lx.src[lx.pos:], "<?=") {
			lx.pos += 3
			lx.emit(tOpenEc, "", lx.line, 1)
		} else {
			lx.pos += 5
		}
	}
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}
func isIdentPart(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

var castTypes = map[string]string{"int": "int", "integer": "int", "bool": "bool", "boolean": "bool", "float": "float", "double": "float", "real": "float",
	"string": "string", "binary": "string", "array": "array", "object": "object", "unset": "unset"}

var ops3 = []string{"<<=", ">>=", "**=", "...", "<=>", "===", "!==", "??=", "?->"}
var ops2 = []string{"==", "!=", "<>", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", ".=", "%=", "&=", "|=", "^=", "->", "=>", "::", "<<", ">>", "??", "**"}

func (lx *lexer) php() {
	for lx.pos < len(lx.src) {
		c := lx.src[lx.pos]
		col := 1
		switch {
		case c == '\n':
			lx.line++
			lx.pos++
		case c == ' ' || c == '\t' || c == '\r':
			lx.pos++
		case c == '#' && !strings.HasPrefix(lx.src[lx.pos:], "#["), c == '/' && strings.HasPrefix(lx.src[lx.pos:], "//"):
			for lx.pos < len(lx.src) && lx.src[lx.pos] != '\n' {
				if strings.HasPrefix(lx.src[lx.pos:], "?>") {
					break
				}
				lx.pos++
			}
		case c == '#':
			// An attribute #[...]: skipped to the closing bracket.
			depth := 0
			for lx.pos < len(lx.src) {
				if lx.src[lx.pos] == '[' {
					depth++
				} else if lx.src[lx.pos] == ']' {
					depth--
					if depth == 0 {
						lx.pos++
						break
					}
				} else if lx.src[lx.pos] == '\n' {
					lx.line++
				}
				lx.pos++
			}
		case c == '/' && strings.HasPrefix(lx.src[lx.pos:], "/*"):
			end := strings.Index(lx.src[lx.pos+2:], "*/")
			if end < 0 {
				end = len(lx.src) - lx.pos - 2
			}
			lx.line += strings.Count(lx.src[lx.pos:lx.pos+2+end], "\n")
			lx.pos += end + 4
		case strings.HasPrefix(lx.src[lx.pos:], "?>"):
			lx.emit(tOp, ";", lx.line, col)
			lx.pos += 2
			if lx.pos < len(lx.src) && lx.src[lx.pos] == '\n' {
				lx.line++
				lx.pos++
			}
			lx.inline()
		case c == '$' && lx.pos+1 < len(lx.src) && isIdentStart(lx.src[lx.pos+1]):
			j := lx.pos + 1
			for j < len(lx.src) && isIdentPart(lx.src[j]) {
				j++
			}
			lx.emit(tVar, lx.src[lx.pos+1:j], lx.line, lx.pos)
			lx.pos = j
		case isIdentStart(c) || c == '\\' && lx.pos+1 < len(lx.src) && isIdentStart(lx.src[lx.pos+1]):
			j := lx.pos
			for j < len(lx.src) && (isIdentPart(lx.src[j]) || lx.src[j] == '\\' && j+1 < len(lx.src) && isIdentStart(lx.src[j+1])) {
				j++
			}
			lx.emit(tIdent, lx.src[lx.pos:j], lx.line, lx.pos)
			lx.pos = j
		case c >= '0' && c <= '9' || c == '.' && lx.pos+1 < len(lx.src) && lx.src[lx.pos+1] >= '0' && lx.src[lx.pos+1] <= '9':
			j := lx.pos
			for j < len(lx.src) && (isIdentPart(lx.src[j]) || lx.src[j] == '.' && j+1 < len(lx.src) && lx.src[j+1] >= '0' && lx.src[j+1] <= '9') {
				j++
			}
			lx.emit(tNum, lx.src[lx.pos:j], lx.line, lx.pos)
			lx.pos = j
		case c == '\'':
			lx.single()
		case c == '"':
			lx.double()
		case c == '`':
			lx.backtick()
		case strings.HasPrefix(lx.src[lx.pos:], "<<<"):
			lx.heredoc()
		case c == '(':
			if t, n := lx.cast(); t != "" {
				lx.emit(tCast, t, lx.line, lx.pos)
				lx.pos += n
				break
			}
			lx.emit(tOp, "(", lx.line, lx.pos)
			lx.pos++
		default:
			op := string(c)
			for _, o := range ops3 {
				if strings.HasPrefix(lx.src[lx.pos:], o) {
					op = o
				}
			}
			if len(op) == 1 {
				for _, o := range ops2 {
					if strings.HasPrefix(lx.src[lx.pos:], o) {
						op = o
						break
					}
				}
			}
			lx.emit(tOp, op, lx.line, lx.pos)
			lx.pos += len(op)
		}
	}
}

// cast recognizes (int), (string) and the like at the current "(".
func (lx *lexer) cast() (string, int) {
	j := lx.pos + 1
	for j < len(lx.src) && (lx.src[j] == ' ' || lx.src[j] == '\t') {
		j++
	}
	s := j
	for j < len(lx.src) && isIdentPart(lx.src[j]) {
		j++
	}
	word := strings.ToLower(lx.src[s:j])
	for j < len(lx.src) && (lx.src[j] == ' ' || lx.src[j] == '\t') {
		j++
	}
	if j < len(lx.src) && lx.src[j] == ')' {
		if t, ok := castTypes[word]; ok {
			return t, j + 1 - lx.pos
		}
	}
	return "", 0
}

// single reads a single-quoted string: only \\ and \' are escapes.
func (lx *lexer) single() {
	line, start := lx.line, lx.pos
	var sb strings.Builder
	lx.pos++
	for lx.pos < len(lx.src) && lx.src[lx.pos] != '\'' {
		c := lx.src[lx.pos]
		if c == '\\' && lx.pos+1 < len(lx.src) && (lx.src[lx.pos+1] == '\\' || lx.src[lx.pos+1] == '\'') {
			sb.WriteByte(lx.src[lx.pos+1])
			lx.pos += 2
			continue
		}
		if c == '\n' {
			lx.line++
		}
		sb.WriteByte(c)
		lx.pos++
	}
	lx.pos++
	lx.emit(tStr, sb.String(), line, start)
}

// double reads a double-quoted string, with interpolation.
func (lx *lexer) double() {
	line, start := lx.line, lx.pos
	lx.pos++
	bodyStart := lx.pos
	for lx.pos < len(lx.src) && lx.src[lx.pos] != '"' {
		if lx.src[lx.pos] == '\\' {
			lx.pos++
		}
		if lx.pos < len(lx.src) && lx.src[lx.pos] == '\n' {
			lx.line++
		}
		lx.pos++
	}
	body := lx.src[bodyStart:min(lx.pos, len(lx.src))]
	lx.pos++
	lx.template(body, line, start, '"')
}

func (lx *lexer) backtick() {
	line, start := lx.line, lx.pos
	lx.pos++
	bodyStart := lx.pos
	for lx.pos < len(lx.src) && lx.src[lx.pos] != '`' {
		if lx.src[lx.pos] == '\n' {
			lx.line++
		}
		lx.pos++
	}
	body := lx.src[bodyStart:min(lx.pos, len(lx.src))]
	lx.pos++
	lx.template(body, line, start, '`')
	// A backtick string runs a shell command: mark it for the parser.
	lx.toks[len(lx.toks)-1].shell = true
}

// heredoc reads <<<ID ... ID and <<<'ID' (nowdoc).
func (lx *lexer) heredoc() {
	line, start := lx.line, lx.pos
	j := lx.pos + 3
	for j < len(lx.src) && (lx.src[j] == ' ' || lx.src[j] == '\t') {
		j++
	}
	nowdoc := false
	quoted := false
	if j < len(lx.src) && (lx.src[j] == '\'' || lx.src[j] == '"') {
		nowdoc = lx.src[j] == '\''
		quoted = true
		j++
	}
	s := j
	for j < len(lx.src) && isIdentPart(lx.src[j]) {
		j++
	}
	id := lx.src[s:j]
	if quoted {
		j++
	}
	if id == "" {
		lx.emit(tOp, "<<", lx.line, start)
		lx.pos += 2
		return
	}
	for j < len(lx.src) && lx.src[j] != '\n' {
		j++
	}
	j++
	lx.line++
	bodyStart := j
	end := -1
	for k := bodyStart; k <= len(lx.src); {
		eol := strings.IndexByte(lx.src[k:], '\n')
		var ln string
		if eol < 0 {
			ln = lx.src[k:]
		} else {
			ln = lx.src[k : k+eol]
		}
		if t := strings.TrimLeft(ln, " \t"); strings.HasPrefix(t, id) && (len(t) == len(id) || !isIdentPart(t[len(id)])) {
			end = k
			lx.pos = k + (len(ln) - len(t)) + len(id)
			break
		}
		if eol < 0 {
			break
		}
		k += eol + 1
	}
	if end < 0 {
		lx.pos = len(lx.src)
		return
	}
	body := ""
	if end > bodyStart {
		body = strings.TrimSuffix(lx.src[bodyStart:end], "\n")
	}
	lx.line += strings.Count(lx.src[bodyStart:end], "\n")
	if nowdoc {
		lx.emit(tStr, body, line, start)
		return
	}
	lx.template(body, line+1, start, 0)
}

// template splits the body of an interpolated string into literal and
// expression parts and emits a string token (tStr when nothing is
// interpolated).
func (lx *lexer) template(body string, line, col int, quote byte) {
	var parts []part
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, part{lit: lit.String()})
			lit.Reset()
		}
	}
	cur := line
	for i := 0; i < len(body); {
		c := body[i]
		switch {
		case c == '\\' && i+1 < len(body):
			i++
			switch body[i] {
			case 'n':
				lit.WriteByte('\n')
			case 't':
				lit.WriteByte('\t')
			case 'r':
				lit.WriteByte('\r')
			case '\\', '$':
				lit.WriteByte(body[i])
			case '"':
				if quote == '"' {
					lit.WriteByte('"')
				} else {
					lit.WriteString("\\\"")
				}
			default:
				lit.WriteByte('\\')
				lit.WriteByte(body[i])
			}
			i++
		case c == '$' && i+1 < len(body) && isIdentStart(body[i+1]):
			j := i + 1
			for j < len(body) && isIdentPart(body[j]) {
				j++
			}
			code := body[i:j]
			// $a[key] and $a->prop, one level, as PHP reads them.
			if j < len(body) && body[j] == '[' {
				if k := strings.IndexByte(body[j:], ']'); k > 0 {
					key := body[j+1 : j+k]
					switch {
					case key != "" && (key[0] == '$' || key[0] >= '0' && key[0] <= '9' || key[0] == '-'):
						code += "[" + key + "]"
					case key != "" && key[0] != '\'' && key[0] != '"':
						code += "['" + key + "']"
					default:
						code += "[" + key + "]"
					}
					j += k + 1
				}
			} else if strings.HasPrefix(body[j:], "->") && j+2 < len(body) && isIdentStart(body[j+2]) {
				k := j + 2
				for k < len(body) && isIdentPart(body[k]) {
					k++
				}
				code += body[j:k]
				j = k
			}
			flush()
			parts = append(parts, part{code: code, line: cur})
			i = j
		case (c == '{' && i+1 < len(body) && body[i+1] == '$') || (c == '$' && i+1 < len(body) && body[i+1] == '{'):
			open := i + 1
			if c == '$' {
				open = i + 2
			}
			depth, j := 1, open
			for j < len(body) && depth > 0 {
				switch body[j] {
				case '{':
					depth++
				case '}':
					depth--
				}
				j++
			}
			inner := body[open : j-1]
			if c == '$' {
				inner = "$" + inner
			}
			flush()
			parts = append(parts, part{code: inner, line: cur})
			i = j
		default:
			if c == '\n' {
				cur++
			}
			lit.WriteByte(c)
			i++
		}
	}
	flush()
	if len(parts) == 0 {
		lx.emit(tStr, "", line, col)
		return
	}
	if len(parts) == 1 && parts[0].code == "" {
		lx.emit(tStr, parts[0].lit, line, col)
		return
	}
	lx.toks = append(lx.toks, token{k: tTpl, line: line, col: col, parts: parts})
}
