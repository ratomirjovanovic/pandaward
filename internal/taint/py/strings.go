package py

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

type literal struct {
	value  string // decoded text of a plain literal
	body   string // text between the quotes, for f-strings
	offset int    // bytes from the token start to the body
	raw    bool
	bytes  bool
	fmt    bool
}

// decodeLiteral splits a string token into prefix, quotes and body and
// decodes a plain literal.
func decodeLiteral(src string) literal {
	i := 0
	for i < len(src) && src[i] != '\'' && src[i] != '"' {
		i++
	}
	prefix := strings.ToLower(src[:i])
	lit := literal{raw: strings.ContainsRune(prefix, 'r'), bytes: strings.ContainsRune(prefix, 'b'), fmt: strings.ContainsAny(prefix, "ft")}
	if i >= len(src) {
		return lit
	}
	q := src[i]
	n := 1
	if i+2 < len(src) && src[i+1] == q && src[i+2] == q {
		n = 3
	}
	body := src[i+n:]
	end := strings.Repeat(string(q), n)
	if strings.HasSuffix(body, end) && len(body) >= n {
		body = body[:len(body)-n]
	}
	lit.body, lit.offset = body, i+n
	if !lit.fmt {
		if lit.raw {
			lit.value = body
		} else {
			lit.value = unescape(body)
		}
	}
	return lit
}

// unescape decodes the backslash escapes of a non-raw literal.
func unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch e := s[i]; e {
		case '\n':
		case '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i
			for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			v, _ := strconv.ParseUint(s[i:j], 8, 32)
			b.WriteRune(rune(v))
			i = j - 1
		case 'x', 'u', 'U':
			n := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
			if i+n < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+1+n], 16, 32); err == nil {
					b.WriteRune(rune(v))
					i += n
					continue
				}
			}
			b.WriteByte('\\')
			b.WriteByte(e)
		case 'N':
			if i+1 < len(s) && s[i+1] == '{' {
				if j := strings.IndexByte(s[i:], '}'); j > 0 {
					b.WriteRune(utf8.RuneError) // named character, not looked up
					i += j
					continue
				}
			}
			b.WriteString("\\N")
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '\\', '\'', '"':
			b.WriteByte(e)
		default:
			b.WriteByte('\\')
			b.WriteByte(e)
		}
	}
	return b.String()
}

// parseFString splits an f-string body into text parts (*Const) and
// replacement fields (*FormattedValue). line and col give the position of
// the body's first byte.
func parseFString(body string, raw bool, line, col int) ([]Expr, []Error) {
	var parts []Expr
	var errs []Error
	var text strings.Builder
	l, c := line, col // position of body[i]
	flush := func() {
		if text.Len() > 0 {
			s := text.String()
			if !raw {
				s = unescape(s)
			}
			parts = append(parts, &Const{Pos{line, col}, ConstStr, s})
			text.Reset()
		}
	}
	step := func(s string) {
		for _, r := range s {
			if r == '\n' {
				l++
				c = 1
			} else {
				c += utf8.RuneLen(r)
			}
		}
	}
	for i := 0; i < len(body); {
		ch := body[i]
		switch {
		case ch == '{' && i+1 < len(body) && body[i+1] == '{':
			text.WriteByte('{')
			i += 2
			c += 2
		case ch == '}' && i+1 < len(body) && body[i+1] == '}':
			text.WriteByte('}')
			i += 2
			c += 2
		case ch == '{':
			flush()
			end := fieldEnd(body, i+1)
			field := body[i+1 : end]
			fl, fc := l, c+1
			fv, ferrs := parseField(field, raw, fl, fc)
			errs = append(errs, ferrs...)
			parts = append(parts, fv)
			step(body[i:min(end+1, len(body))])
			i = end + 1
		case ch == '\\' && !raw && i+1 < len(body):
			text.WriteString(body[i : i+2])
			step(body[i : i+2])
			i += 2
		default:
			_, n := utf8.DecodeRuneInString(body[i:])
			text.WriteString(body[i : i+n])
			step(body[i : i+n])
			i += n
		}
	}
	flush()
	return parts, errs
}

// fieldEnd returns the index of the "}" closing the field that starts at
// i (just after its "{"), skipping nested brackets and strings.
func fieldEnd(s string, i int) int {
	depth := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\'' || c == '"':
			i = skipQuoted(s, i)
			continue
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']':
			depth--
		case c == '}':
			if depth == 0 {
				return i
			}
			depth--
		}
		i++
	}
	return len(s)
}

// skipQuoted returns the index after the string literal starting at i.
func skipQuoted(s string, i int) int {
	q := s[i]
	n := 1
	if i+2 < len(s) && s[i+1] == q && s[i+2] == q {
		n = 3
	}
	j := i + n
	for j < len(s) {
		if s[j] == '\\' {
			j += 2
			continue
		}
		if s[j] == q && (n == 1 || j+2 < len(s) && s[j+1] == q && s[j+2] == q) {
			return j + n
		}
		j++
	}
	return len(s)
}

// parseField parses expr[=][!conv][:spec] of one replacement field.
func parseField(field string, raw bool, line, col int) (Expr, []Error) {
	exprEnd, conv, specStart := splitField(field)
	src := field[:exprEnd]
	trimmed := strings.TrimRight(src, " \t\n")
	if strings.HasSuffix(trimmed, "=") && !strings.HasSuffix(trimmed, "==") && !strings.HasSuffix(trimmed, "!=") &&
		!strings.HasSuffix(trimmed, "<=") && !strings.HasSuffix(trimmed, ">=") {
		src = strings.TrimSuffix(trimmed, "=") // {x=} self-documenting
	}
	fv := &FormattedValue{Pos: Pos{line, col}, Conv: conv}
	var errs []Error
	if strings.TrimSpace(src) == "" {
		errs = append(errs, Error{line, col, "empty expression in f-string"})
		fv.Value = &Bad{Pos{line, col}}
	} else {
		// Parentheses allow line breaks inside the field.
		x, e := parseExprAt("("+src+")", line, col-1)
		fv.Value, errs = x, append(errs, e...)
	}
	if specStart >= 0 {
		spec := field[specStart:]
		sp, e := parseFString(spec, raw, line, col+specStart)
		errs = append(errs, e...)
		// CPython places the spec at its colon.
		fv.Spec = &FString{Pos{line, col + specStart - 1}, sp}
	}
	return fv, errs
}

// splitField finds where the expression of a field ends, its conversion
// and where its format spec starts (-1 for none).
func splitField(f string) (exprEnd int, conv byte, specStart int) {
	depth := 0
	for i := 0; i < len(f); {
		c := f[i]
		switch {
		case c == '\'' || c == '"':
			i = skipQuoted(f, i)
			continue
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case depth == 0 && c == '!' && i+1 < len(f) && f[i+1] != '=':
			exprEnd = i
			if i+1 < len(f) {
				conv = f[i+1]
			}
			specStart = -1
			if j := strings.IndexByte(f[i:], ':'); j >= 0 {
				specStart = i + j + 1
			}
			return
		case depth == 0 && c == ':':
			return i, 0, i + 1
		}
		i++
	}
	return len(f), 0, -1
}
