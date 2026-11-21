package adapters

import (
	"regexp"
	"strings"
)

// SQL text built from parts that cannot carry a value (#589).
//
// The three SQL rules fire on any statement whose text is interpolated or
// concatenated. Most of those statements only place a table or column
// name, a list of placeholders or a number into the text and bind every
// value as a parameter. sqlSafeDemote lists such a line as information
// when every interpolated part is shown to be one of:
//
//   - a string or number literal, or a numeric conversion;
//   - a list of placeholders (a "?" literal repeated, or a variable that
//     is only ever assigned such lists);
//   - a name that is a string constant in the file, or a lookup in a
//     constant list or map;
//   - a name that the file checks against a pattern or an allowlist and
//     rejects when it does not match (the check must reject: a check
//     whose result is ignored does not count);
//   - an identifier quoting call;
//   - a list of fragments (name.join) whose every element is built from
//     such parts.
//
// Any other part, such as a request value, keeps the original severity.

const (
	sqlDemoteTitle = "SQL text built only from constants, placeholders or checked names"
	sqlDemoteMsg   = "Every part placed into the query text is a constant, a list of placeholders, a number, a quoted identifier or a name that this file checks against a pattern or allowlist and rejects otherwise. It is listed because the check is read from the code, not run."
	sqlDemoteFix   = "Keep every value bound as a parameter. If a table or column name can come from a request, check it against an allowlist right before use."
)

// sqlSafeDemote returns a listing when all interpolated parts of the SQL
// statement on the current line are safe. concat selects the rule form: a
// concatenation must use +, because other joiners (%, format, a dot) are
// not read.
func sqlSafeDemote(c lineCtx, concat bool) *demotion {
	if c.File == nil || c.Index < 0 || c.Index >= len(c.File.Lines) {
		return nil
	}
	line := c.File.Lines[c.Index]
	// A statement continued after a trailing plus is read to its end.
	for k := 1; k <= 3 && strings.HasSuffix(strings.TrimSpace(line), "+") && c.Index+k < len(c.File.Lines); k++ {
		line += " " + strings.TrimSpace(c.File.Lines[c.Index+k])
	}
	if strings.HasSuffix(strings.TrimSpace(line), "+") {
		return nil
	}
	if concat {
		if m := sqlConcatRe.FindStringSubmatch(line); m == nil || !strings.HasSuffix(strings.TrimSpace(m[0]), "+") {
			return nil
		}
	}
	exprs, ok := sqlOperands(line)
	if !ok {
		return nil
	}
	if !concat && len(exprs) == 0 {
		return nil
	}
	env := sqlEnv{lines: c.File.Lines, text: strings.Join(c.File.Lines, "\n"), at: c.Index}
	for _, e := range exprs {
		if !env.safe(e, 0) {
			return nil
		}
	}
	return &demotion{Title: sqlDemoteTitle, Message: sqlDemoteMsg, Fix: sqlDemoteFix}
}

// sqlOperands lists the parts of a statement that are not text: ${} and
// f-string expressions inside literals, and operands joined with +.
func sqlOperands(line string) ([]string, bool) {
	type token struct {
		text             string
		prevLit, nextLit bool
	}
	var exprs []string
	var toks []token
	var out strings.Builder
	prevLit := false
	n := len(line)
	flush := func(nextLit bool) {
		toks = append(toks, token{out.String(), prevLit, nextLit})
		out.Reset()
	}
	for i := 0; i < n; {
		ch := line[i]
		switch ch {
		case '\'', '"':
			quote := string(ch)
			if i+2 < n && line[i+1] == ch && line[i+2] == ch {
				quote = strings.Repeat(string(ch), 3)
			}
			isF := false
			for k := i - 1; k >= 0 && k >= i-2; k-- {
				if strings.ContainsRune("fF", rune(line[k])) {
					isF = true
				} else if !strings.ContainsRune("rRbBuU", rune(line[k])) {
					break
				}
			}
			start := i + len(quote)
			j := start
			for j < n && !strings.HasPrefix(line[j:], quote) {
				if line[j] == '\\' {
					j++
				}
				j++
			}
			if j > n {
				j = n
			}
			if isF {
				exprs = append(exprs, fstringExprs(line[start:j])...)
			}
			flush(true)
			prevLit = true
			i = j + len(quote)
		case '`':
			j := i + 1
			for j < n && line[j] != '`' {
				if line[j] == '\\' {
					j++
				} else if line[j] == '$' && j+1 < n && line[j+1] == '{' {
					d, k := 1, j+2
					for k < n && d > 0 {
						switch line[k] {
						case '{':
							d++
						case '}':
							d--
						}
						k++
					}
					if d != 0 {
						return nil, false
					}
					exprs = append(exprs, line[j+2:k-1])
					j = k
					continue
				}
				j++
			}
			flush(true)
			prevLit = true
			i = j + 1
		default:
			out.WriteByte(ch)
			i++
		}
	}
	flush(false)
	for _, t := range toks {
		if !t.prevLit && !t.nextLit {
			continue
		}
		parts := splitTop(t.text, '+')
		if len(parts) < 2 {
			continue
		}
		for pi, p := range parts {
			if pi == 0 && !(len(parts) > 1 && !t.prevLit && t.nextLit) {
				continue
			}
			if pi == 0 {
				p = afterCallPrefix(p)
			}
			if p = cutOperand(p); p != "" {
				exprs = append(exprs, p)
			}
		}
	}
	return exprs, true
}

// splitTop splits s at sep outside brackets.
func splitTop(s string, sep byte) []string {
	var parts []string
	depth, last := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case sep:
			if depth == 0 {
				parts = append(parts, s[last:i])
				last = i + 1
			}
		}
	}
	return append(parts, s[last:])
}

// afterCallPrefix drops "x = " and "run(" from the text that precedes a
// statement's first literal.
func afterCallPrefix(s string) string {
	d := 0
	cut := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[':
			d++
			cut = i + 1
		case ')', ']':
			d--
		case '=', ',':
			if s[i] == '=' && i+1 < len(s) && s[i+1] == '=' {
				i++
				continue
			}
			cut = i + 1
		}
	}
	s = s[cut:]
	for _, p := range []string{"return ", "await "} {
		s = strings.TrimPrefix(strings.TrimSpace(s), p)
	}
	return s
}

// cutOperand keeps the operand up to a top-level comma or an unmatched
// closing bracket.
func cutOperand(s string) string {
	d := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			d++
		case ')', ']', '}':
			if d == 0 {
				return strings.TrimSpace(s[:i])
			}
			d--
		case ',', ';':
			if d == 0 {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return strings.TrimSpace(s)
}

// fstringExprs returns the {expr} parts of an f-string body.
func fstringExprs(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '{' {
			i++
			continue
		}
		d, k := 1, i+1
		for k < len(s) && d > 0 {
			switch s[k] {
			case '{':
				d++
			case '}':
				d--
			}
			k++
		}
		if d != 0 {
			break
		}
		e := s[i+1 : k-1]
		dd := 0
		for j := 0; j < len(e); j++ {
			switch e[j] {
			case '(', '[', '{':
				dd++
			case ')', ']', '}':
				dd--
			case ':', '!':
				if dd == 0 && !(e[j] == '!' && j+1 < len(e) && e[j+1] == '=') {
					e = e[:j]
				}
			}
		}
		out = append(out, strings.TrimSpace(e))
		i = k - 1
	}
	return out
}

// ---- reading one part ----

type sqlEnv struct {
	lines []string
	text  string
	at    int
}

var (
	sqlLitRe        = regexp.MustCompile(`^(?:'[^'\\]*'|"[^"\\]*"|\d+(?:\.\d+)?)$`)
	sqlNumConvRe    = regexp.MustCompile(`^(?:Number|parseInt|parseFloat|int|float|len|Math\.(?:floor|ceil|round|min|max|abs|trunc)|Integer\.parseInt|Long\.parseLong|Integer\.valueOf)\s*\(`)
	sqlLengthRe     = regexp.MustCompile(`\.length$|\.size\(\)$`)
	sqlQuoteCallRe  = regexp.MustCompile(`^(?:[\w$.]*\.)?(?:escapeId|escapeIdentifier|quoteIdent\w*|quote_ident\w*|quoteName|quote_name|quoteIdentifier|identifier|ident|escape|escapeLiteral)\s*\(`)
	sqlPlaceholdRe  = regexp.MustCompile(`\.fill\(\s*['"]\?['"]\s*\)|['"]\?['"]\s*\.repeat\(|['"]\?['"]\s+for\s+\w+|['"]\?['"]\s*\*|\*\s*['"]\?['"]|\[\s*['"]\?['"]\s*\]\s*\*|=>\s*['"\x60]\?['"\x60]|=>\s*['"\x60]\$['"\x60]\s*\+|=>\s*\x60\$\$\{`)
	sqlBareChainRe  = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*$`)
	sqlLookupRe     = regexp.MustCompile(`^((?:this\.|self\.|cls\.)?[A-Za-z_$][\w$]*)\s*(?:\[[^\]]*\]|\.get\(.*\))(?:\s*(?:\?\?|\|\||\bor\b)\s*(?:'[^']*'|"[^"]*"))?$`)
	sqlTernaryRe    = regexp.MustCompile(`^.+?\s\?\s(.+?)\s:\s(.+)$`)
	sqlPyTernaryRe  = regexp.MustCompile(`^(.+?)\s+if\s+.+?\s+else\s+(.+)$`)
	sqlJoinRe       = regexp.MustCompile(`^([A-Za-z_$][\w$.]*)\.join\(.*\)$`)
	sqlPyJoinRe     = regexp.MustCompile(`^(?:'[^']*'|"[^"]*")\.join\(\s*([A-Za-z_]\w*(?:\.\w+)*)\s*\)$`)
	sqlRestrictedRe = regexp.MustCompile(`\\w|\\d|a-z|A-Z|0-9|isidentifier|isalnum|isalpha|isdigit`)
	sqlValidCallRe  = regexp.MustCompile(`\.test\(|\.match\(|\bre\.(?:match|fullmatch|search)\(|\.fullmatch\(|\.isidentifier\(|\.isalnum\(|\.isalpha\(|\.isdigit\(|\bpreg_match\(|\.matches\(`)
	sqlAllowCallRe  = regexp.MustCompile(`\.includes\(|\.has\(|\.contains\(|\.indexOf\(|\bin\s+[A-Za-z_][\w.]*|\bin\s*[(\[{]|\.containsKey\(|\.hasOwnProperty\(|\bObject\.hasOwn\(`)
	sqlNegationRe   = regexp.MustCompile(`!|\bnot\b|[=!]==?\s*-1|<\s*0|\bis\s+None\b|[=!]==?\s*null|[=!]==?\s*false|[=!]==?\s*None`)
	sqlRejectRe     = regexp.MustCompile(`\bthrow\b|\braise\b|\breturn\b|\bcontinue\b|\bprocess\.exit\b|\bsys\.exit\b|\bpanic\(|\breject\(|\babort\(|\bdie\(|\bexit\(|\bbreak\b`)
)

// safe reports whether the expression cannot carry a value into the text.
func (e sqlEnv) safe(x string, depth int) bool {
	x = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(x), ";"))
	if x == "" || sqlLitRe.MatchString(x) || depth > 6 {
		return x == "" || sqlLitRe.MatchString(x)
	}
	// Parentheses around the whole expression.
	if x[0] == '(' && matchingClose(x, 0) == len(x)-1 {
		return e.safe(x[1:len(x)-1], depth+1)
	}
	// Template literals and f-strings inside the expression.
	if strings.HasPrefix(x, "`") && strings.HasSuffix(x, "`") && len(x) >= 2 {
		inner, ok := sqlOperands(x)
		if !ok {
			return false
		}
		for _, p := range inner {
			if !e.safe(p, depth+1) {
				return false
			}
		}
		return true
	}
	if m := regexp.MustCompile(`^[fF][rR]?['"]`).FindString(x); m != "" {
		inner, ok := sqlOperands(x)
		if !ok {
			return false
		}
		for _, p := range inner {
			if !e.safe(p, depth+1) {
				return false
			}
		}
		return true
	}
	// Alternatives and sums: every branch must be safe.
	for _, sep := range []string{"||", "??", " or ", " and ", "&&"} {
		if parts := splitTopStr(x, sep); len(parts) > 1 {
			for _, p := range parts {
				if !e.safe(p, depth+1) {
					return false
				}
			}
			return true
		}
	}
	if parts := splitTop(x, '+'); len(parts) > 1 {
		for _, p := range parts {
			if !e.safe(p, depth+1) {
				return false
			}
		}
		return true
	}
	if m := sqlTernaryRe.FindStringSubmatch(x); m != nil {
		return e.safe(m[1], depth+1) && e.safe(m[2], depth+1)
	}
	if m := sqlPyTernaryRe.FindStringSubmatch(x); m != nil {
		return e.safe(m[1], depth+1) && e.safe(m[2], depth+1)
	}
	switch {
	case sqlNumConvRe.MatchString(x) && endsCall(x), sqlLengthRe.MatchString(x):
		return true
	case sqlQuoteCallRe.MatchString(x) && endsCall(x):
		return true
	case sqlPlaceholdRe.MatchString(x):
		return true
	}
	if m := sqlPyJoinRe.FindStringSubmatch(x); m != nil {
		return e.fragmentsSafe(sqlLastSegment(m[1]), depth)
	}
	if m := sqlJoinRe.FindStringSubmatch(x); m != nil {
		return e.fragmentsSafe(sqlLastSegment(m[1]), depth)
	}
	if m := sqlLookupRe.FindStringSubmatch(x); m != nil {
		return e.constCollection(sqlLastSegment(m[1]))
	}
	if sqlBareChainRe.MatchString(x) {
		return e.nameSafe(x, depth)
	}
	return false
}

func sqlLastSegment(chain string) string {
	if i := strings.LastIndexAny(chain, ".?"); i >= 0 {
		return chain[i+1:]
	}
	return chain
}

// endsCall reports whether the call that starts the text closes at its end.
func endsCall(x string) bool {
	i := strings.IndexByte(x, '(')
	return i >= 0 && matchingClose(x, i) == len(x)-1
}

func matchingClose(s string, open int) int {
	d := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			d++
		case ')', ']', '}':
			d--
			if d == 0 {
				return i
			}
		}
	}
	return -1
}

func splitTopStr(s, sep string) []string {
	var parts []string
	depth, last := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '\'', '"':
			q := s[i]
			for i++; i < len(s) && s[i] != q; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		default:
			if depth == 0 && strings.HasPrefix(s[i:], sep) {
				parts = append(parts, s[last:i])
				i += len(sep) - 1
				last = i + 1
			}
		}
	}
	if last == 0 {
		return []string{s}
	}
	return append(parts, s[last:])
}

// assignments returns the right-hand sides assigned to name in the file.
func (e sqlEnv) assignments(name string) []string {
	re := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(name) + `\s*(?::\s*[\w<>\[\], |.]+\s*)?(?:=|\+=|:=)\s*([^=\n].*)$`)
	var out []string
	for _, l := range e.lines {
		if m := re.FindStringSubmatch(l); m != nil {
			out = append(out, strings.TrimRight(strings.TrimSpace(m[1]), ";,"))
		}
	}
	return out
}

// constCollection reports whether name is declared as a literal list, map
// or dictionary.
func (e sqlEnv) constCollection(name string) bool {
	as := e.assignments(name)
	if len(as) != 1 {
		return false
	}
	return regexp.MustCompile(`^(?:\{|\[|\(|new\s+Map\b|new\s+Set\b|Object\.freeze\(|dict\(|frozenset\(|set\(|Map\.of\(|List\.of\(|Set\.of\(|Map\.ofEntries\(|Arrays\.asList\(|Collections\.unmodifiable)`).MatchString(as[0])
}

// nameSafe reads a bare name or dotted chain.
func (e sqlEnv) nameSafe(chain string, depth int) bool {
	name := sqlLastSegment(chain)
	dotted := strings.Contains(chain, ".")
	if as := e.assignments(name); len(as) > 0 {
		all := true
		for _, rhs := range as {
			if !e.safe(rhs, depth+1) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return e.validated(name, dotted)
}

// fragmentsSafe reads name.join(...): a list whose every element was
// pushed or written as a safe fragment.
func (e sqlEnv) fragmentsSafe(name string, depth int) bool {
	push := regexp.MustCompile(`(?:^|[^\w$])` + regexp.QuoteMeta(name) + `\s*\.\s*(?:push|append|add|extend)\(\s*(.+?)\s*\)\s*;?\s*$`)
	n := 0
	for _, l := range e.lines {
		if m := push.FindStringSubmatch(l); m != nil {
			n++
			if !e.safe(m[1], depth+1) {
				return false
			}
		}
	}
	as := e.assignments(name)
	for _, rhs := range as {
		if strings.HasPrefix(rhs, "[") && matchingClose(rhs, 0) == len(rhs)-1 {
			for _, el := range splitTop(rhs[1:len(rhs)-1], ',') {
				if strings.TrimSpace(el) != "" && !e.safe(el, depth+1) {
					return false
				}
			}
			n++
		} else if !(rhs == "[]" || rhs == "list()") {
			return false
		}
	}
	return n > 0
}

// validated reports whether the file rejects a value of this name that
// does not match a restrictive pattern or is not in an allowlist. The
// check must precede the use closely, or belong to a constructor or
// initializer when the name is a member (this.x, self.x).
func (e sqlEnv) validated(name string, member bool) bool {
	word := regexp.MustCompile(`(?:^|[^\w$])` + regexp.QuoteMeta(name) + `(?:[^\w$]|$)`)
	lo, hi := 0, len(e.lines)
	if !member {
		lo = e.at - 60
		if lo < 0 {
			lo = 0
		}
		hi = e.at + 1
	}
	for i := lo; i < hi && i < len(e.lines); i++ {
		l := e.lines[i]
		if !word.MatchString(l) || !sqlNegationRe.MatchString(l) {
			continue
		}
		pattern := sqlValidCallRe.MatchString(l) && (sqlRestrictedRe.MatchString(l) || e.patternDeclared(l))
		allow := sqlAllowCallRe.MatchString(l)
		if !pattern && !allow {
			continue
		}
		end := i + 4
		if end > len(e.lines) {
			end = len(e.lines)
		}
		if sqlRejectRe.MatchString(strings.Join(e.lines[i:end], " ")) {
			return true
		}
	}
	return false
}

// patternDeclared is true when the pattern used on the line is a name
// whose declaration is restrictive.
func (e sqlEnv) patternDeclared(line string) bool {
	for _, m := range regexp.MustCompile(`\b([A-Z][A-Z0-9_]{2,})\b`).FindAllStringSubmatch(line, -1) {
		for _, rhs := range e.assignments(m[1]) {
			if sqlRestrictedRe.MatchString(rhs) {
				return true
			}
		}
	}
	return false
}

func sqlTemplateDemote(c lineCtx) *demotion { return sqlSafeDemote(c, false) }

func sqlConcatDemote(c lineCtx) *demotion {
	if d := sqlSafeDemote(c, true); d != nil {
		return d
	}
	return sqlForFileOnly(c)
}
