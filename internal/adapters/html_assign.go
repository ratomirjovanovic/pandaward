package adapters

import (
	"regexp"
	"strings"
)

// Proof that an innerHTML or outerHTML assignment cannot carry markup from
// outside. The assigned expression must be built only from string literals,
// numbers, constants of the same file initialized with those, calls to a
// helper that escapes < > " and ' (or a known sanitizer), ternaries and
// concatenations of these, or a local variable that every assignment in the
// file builds the same way. Anything else is "not proven" and keeps the
// finding.

var htmlAssignStartRe = regexp.MustCompile(`\.(?:inner|outer)HTML\s*(=)(?:[^=]|$)`)

func htmlSinkOrAssignProvenSafe(c lineCtx) bool {
	return htmlSinkProvenSafe(c) || htmlAssignProvenSafe(c)
}

// semgrepHTMLSinkProven applies the same proof to a result of the bundled
// pandaward-js-html-sink rule, so the two adapters agree on one line.
func semgrepHTMLSinkProven(c *Context, rel string, line int) bool {
	if c == nil || c.Inv == nil {
		return false
	}
	f := c.Inv.FileByPath(rel)
	if f == nil || !jsLike[f.Lang] || line < 1 || line > len(f.Lines) {
		return false
	}
	return htmlAssignProvenSafe(lineCtx{Inv: c.Inv, File: f, Index: line - 1, Text: strings.Join(f.Lines, "\n")})
}

// htmlAssignProvenSafe reports whether the one innerHTML/outerHTML
// assignment on the line, and no other sink, receives proven-safe markup.
func htmlAssignProvenSafe(c lineCtx) bool {
	l := c.File.Lines[c.Index]
	locs := htmlAssignStartRe.FindAllStringSubmatchIndex(l, -1)
	if len(locs) != 1 || htmlSinkRe.MatchString(l[locs[0][3]:]) || htmlSinkRe.MatchString(l[:locs[0][0]]) {
		return false
	}
	start := c.offset() + locs[0][3]
	end := exprEnd(c.Text, start, ";", false)
	return safeMarkup(c, c.Text[start:end], start, map[string]bool{}, 0)
}

var (
	numberRe   = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	upperRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	upperMemRe = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)\.([A-Za-z_$][\w$]*)$`)
)

// safeMarkup applies the proof to expr. root is where the whole expression
// being checked starts; identifiers are resolved in its scope. seen holds
// the variables whose assignments are being checked, so a variable that
// appends to itself is not followed again.
func safeMarkup(c lineCtx, expr string, root int, seen map[string]bool, depth int) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" || depth > 6 {
		return false
	}
	if strings.HasPrefix(expr, "(") && matchClose(expr, 0) == len(expr)-1 {
		return safeMarkup(c, expr[1:len(expr)-1], root, seen, depth+1)
	}
	// The condition of a ternary only picks a branch; it is not output.
	if _, a, b, ok := splitTernary(expr); ok {
		return safeMarkup(c, a, root, seen, depth+1) && safeMarkup(c, b, root, seen, depth+1)
	}
	if parts, ok := splitTopPlus(expr); ok && len(parts) > 1 {
		for _, p := range parts {
			if !safeMarkup(c, p, root, seen, depth+1) {
				return false
			}
		}
		return true
	}
	if isWholeLiteral(expr) || numberRe.MatchString(expr) {
		return true
	}
	if callee, args, ok := wholeCall(expr); ok {
		return sanitizerCall(callee, args, jsImports(c.Text)) || safeHelper(c, callee)
	}
	if m := upperMemRe.FindStringSubmatch(expr); m != nil {
		init, ok := upperConstInit(c.Text, m[1])
		return ok && objectPropLiteral(init, m[2])
	}
	if !identRe.MatchString(expr) {
		return false
	}
	if seen[expr] {
		return true
	}
	if upperRe.MatchString(expr) {
		if init, ok := upperConstInit(c.Text, expr); ok {
			return isWholeLiteral(init) || numberRe.MatchString(init)
		}
	}
	kind, init, initAt, ok := scopedDecl(c.Text, expr, root)
	if !ok {
		return false
	}
	if kind == "const" {
		return safeMarkup(c, init, initAt, seen, depth+1)
	}
	return accumulatorSafe(c, expr, seen, depth+1)
}

// splitTopPlus splits expr at top-level binary "+". It refuses ++, += and a
// leading or doubled "+", which are not plain concatenation.
func splitTopPlus(expr string) ([]string, bool) {
	var parts []string
	depth, last, ok := 0, 0, true
	walkJS(expr, 0, func(i int) bool {
		switch expr[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '+':
			if depth != 0 {
				return false
			}
			if i+1 < len(expr) && (expr[i+1] == '+' || expr[i+1] == '=') {
				ok = false
				return true
			}
			p := strings.TrimSpace(expr[last:i])
			if p == "" {
				ok = false
				return true
			}
			parts = append(parts, p)
			last = i + 1
		}
		return false
	})
	if !ok {
		return nil, false
	}
	p := strings.TrimSpace(expr[last:])
	if p == "" {
		return nil, false
	}
	return append(parts, p), true
}

// splitTernary splits cond ? a : b at the top level. Optional chaining,
// nullish coalescing and nested ternaries in the condition are refused.
func splitTernary(expr string) (cond, a, b string, ok bool) {
	depth, q, nest, colon := 0, -1, 0, -1
	walkJS(expr, 0, func(i int) bool {
		switch c := expr[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '?':
			if depth != 0 {
				return false
			}
			if i+1 < len(expr) && (expr[i+1] == '.' || expr[i+1] == '?') || i > 0 && expr[i-1] == '?' {
				q = -2
				return true
			}
			if q == -1 {
				q = i
			} else {
				nest++
			}
		case ':':
			if depth != 0 || q < 0 {
				return false
			}
			if nest > 0 {
				nest--
				return false
			}
			colon = i
			return true
		}
		return false
	})
	if q < 0 || colon < 0 {
		return "", "", "", false
	}
	return expr[:q], expr[q+1 : colon], expr[colon+1:], true
}

var declKwRe = `(?:^|[^.\w$])(const|let|var)\s+`

// scopedDecl finds the declaration of name that is in scope at root: the
// last const/let/var declaration before root from which the code up to root
// never leaves the declaring block and ends at the same bracket depth, so no
// parameter or nested binding can shadow it. It returns the declaration
// kind and the initializer with its position.
func scopedDecl(text, name string, root int) (kind, init string, at int, ok bool) {
	re := regexp.MustCompile(declKwRe + regexp.QuoteMeta(name) + `\s*(?::[^=;]+)?=\s*`)
	locs := re.FindAllStringSubmatchIndex(text, -1)
	idx := -1
	for i, l := range locs {
		if l[1] < root {
			idx = i
		}
	}
	if idx < 0 {
		return "", "", 0, false
	}
	l := locs[idx]
	kind = text[l[2]:l[3]]
	start := l[1]
	end := exprEnd(text, start, ";,", true)
	if end >= root {
		return "", "", 0, false
	}
	depth, left := 0, false
	walkJS(text[:root], end, func(i int) bool {
		switch text[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth < 0 {
				left = true
				return true
			}
		}
		return false
	})
	if left || depth != 0 {
		return "", "", 0, false
	}
	return kind, strings.TrimSpace(text[start:end]), start, true
}

// accumulatorSafe reports whether the let/var variable name, declared once
// in the file and never a parameter, is only ever assigned proven-safe
// markup with = or +=.
func accumulatorSafe(c lineCtx, name string, seen map[string]bool, depth int) bool {
	q := regexp.QuoteMeta(name)
	decls := regexp.MustCompile(`(?:^|[^.\w$])(?:const|let|var|function|class)\s+`+q+`\b`).FindAllStringIndex(c.Text, -1)
	if len(decls) != 1 || regexp.MustCompile(`[(,]\s*`+q+`\s*[,)=:]`).MatchString(c.Text) {
		return false
	}
	next := map[string]bool{name: true}
	for k := range seen {
		next[k] = true
	}
	masked := maskLiterals(c.Text)
	for _, u := range regexp.MustCompile(`(?:^|[^.\w$])`+q+`\b`).FindAllStringIndex(masked, -1) {
		s := u[1]
		before := strings.TrimRight(masked[:u[1]-len(name)], " \t")
		if strings.HasSuffix(before, "++") || strings.HasSuffix(before, "--") {
			return false
		}
		after := masked[s:]
		trim := strings.TrimLeft(after, " \t")
		off := s + len(after) - len(trim)
		switch {
		case strings.HasPrefix(trim, "+="):
			off += 2
		case strings.HasPrefix(trim, "==") || strings.HasPrefix(trim, "=>"):
			continue
		case strings.HasPrefix(trim, "="):
			off++
		case strings.HasPrefix(trim, "++") || strings.HasPrefix(trim, "--") || len(trim) > 1 && strings.IndexByte("-*/%&|^<>?", trim[0]) >= 0 && trim[1] == '=':
			return false
		default:
			continue
		}
		end := exprEnd(c.Text, off, ";,", false)
		if !safeMarkup(c, c.Text[off:end], off, next, depth+1) {
			return false
		}
	}
	return true
}

// upperConstInit returns the initializer of an UPPER_CASE constant declared
// once in the file, never a parameter, never reassigned and with no property
// written.
func upperConstInit(text, name string) (string, bool) {
	q := regexp.QuoteMeta(name)
	all := regexp.MustCompile(`(?:^|[^.\w$])(?:const|let|var|function|class)\s+`+q+`\b`).FindAllStringIndex(text, -1)
	decl := regexp.MustCompile(`(?:^|[^.\w$])const\s+`+q+`\s*(?::[^=;]+)?=\s*`).FindAllStringIndex(text, -1)
	if len(all) != 1 || len(decl) != 1 {
		return "", false
	}
	// The declaration itself is blanked so its "=" is not read as a write.
	masked := maskLiterals(text)
	masked = masked[:decl[0][0]] + strings.Repeat(" ", decl[0][1]-decl[0][0]) + masked[decl[0][1]:]
	if regexp.MustCompile(`[(,]\s*` + q + `\s*[,)=:]|(?:^|[^.\w$])` + q + `\s*(?:\.[\w$]+\s*|\[[^\]]*\]\s*)?(?:[-+*/%&|^]|\?\?|&&|\|\|)?=[^=>]|(?:^|[^.\w$])` + q + `\s*\[`).MatchString(masked) {
		return "", false
	}
	start := decl[0][1]
	end := exprEnd(text, start, ";,", true)
	return strings.TrimSpace(text[start:end]), true
}

var objKeyRe = regexp.MustCompile(`^(?:([A-Za-z_$][\w$]*)|'([^'\\]*)'|"([^"\\]*)")\s*:\s*`)

// objectPropLiteral reports whether init is an object literal whose prop
// key holds a whole string literal or a number.
func objectPropLiteral(init, prop string) bool {
	init = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(init), "as const"))
	if !strings.HasPrefix(init, "{") || matchClose(init, 0) != len(init)-1 {
		return false
	}
	found := false
	for _, e := range splitTopArgs(init[1 : len(init)-1]) {
		if e == "" {
			continue
		}
		m := objKeyRe.FindStringSubmatchIndex(e)
		if m == nil {
			return false // spread, method or computed key: not a plain table
		}
		var key string
		for g := 1; g <= 3; g++ {
			if m[2*g] >= 0 {
				key = e[m[2*g]:m[2*g+1]]
			}
		}
		if key != prop {
			continue
		}
		v := strings.TrimSpace(e[m[1]:])
		if found || !(isWholeLiteral(v) || numberRe.MatchString(v)) {
			return false
		}
		found = true
	}
	return found
}

// isEntityEscape reports whether expr is base.replace(...) chained calls
// that together replace every <, >, " and ' with text holding none of them:
// a literal replacement without those characters or "$", or a lookup
// (c) => ({ ... }[c]) whose values are such literals.
func isEntityEscape(expr string) bool {
	expr = strings.TrimSpace(expr)
	at := -1
	depth := 0
	walkJS(expr, 0, func(i int) bool {
		switch expr[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '.':
			if depth == 0 && (strings.HasPrefix(expr[i:], ".replace(") || strings.HasPrefix(expr[i:], ".replaceAll(")) {
				at = i
				return true
			}
		}
		return false
	})
	if at <= 0 {
		return false
	}
	covered := map[byte]bool{}
	rest := expr[at:]
	for {
		rest = strings.TrimSpace(rest)
		if rest == "" {
			break
		}
		var name string
		switch {
		case strings.HasPrefix(rest, ".replace("):
			name = ".replace"
		case strings.HasPrefix(rest, ".replaceAll("):
			name = ".replaceAll"
		default:
			return false
		}
		close := matchClose(rest, len(name))
		if close < 0 {
			return false
		}
		args := splitTopArgs(rest[len(name)+1 : close])
		if len(args) != 2 {
			return false
		}
		chars, ok := globalRegexChars(args[0])
		if !ok || !safeReplacement(args[1]) {
			return false
		}
		for _, ch := range chars {
			covered[ch] = true
		}
		rest = rest[close+1:]
	}
	return covered['<'] && covered['>'] && covered['"'] && covered['\'']
}

// globalRegexChars returns the characters a /x/g or /[...]/g literal
// matches, when it is that simple.
func globalRegexChars(lit string) ([]byte, bool) {
	lit = strings.TrimSpace(lit)
	end := strings.LastIndexByte(lit, '/')
	if !strings.HasPrefix(lit, "/") || end <= 1 || !strings.Contains(lit[end+1:], "g") {
		return nil, false
	}
	body := lit[1:end]
	if strings.HasPrefix(body, "[") && strings.HasSuffix(body, "]") && !strings.HasPrefix(body, "[^") {
		body = body[1 : len(body)-1]
	} else if len(strings.ReplaceAll(body, `\`, "")) != 1 {
		return nil, false
	}
	var out []byte
	for i := 0; i < len(body); i++ {
		ch := body[i]
		switch {
		case ch == '\\':
			if i+1 >= len(body) || isIdent(body[i+1]) {
				return nil, false // \d, \w and similar classes
			}
			i++
			out = append(out, body[i])
		case ch == '-' && i > 0 && i < len(body)-1:
			return nil, false // a range
		default:
			out = append(out, ch)
		}
	}
	return out, len(out) > 0
}

var lookupRe = regexp.MustCompile(`^\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*\(?\s*(\{[\s\S]*\})\s*\[\s*([A-Za-z_$][\w$]*)\s*\]\s*\)?$`)

// safeReplacement reports whether a replace argument can only produce text
// without < > " ' (and, for a literal, no "$" pattern that reinserts the
// match).
func safeReplacement(arg string) bool {
	arg = strings.TrimSpace(arg)
	if isWholeLiteral(arg) {
		return !strings.ContainsAny(arg[1:len(arg)-1], `<>"'$`)
	}
	m := lookupRe.FindStringSubmatch(arg)
	if m == nil || m[1] != m[3] {
		return false
	}
	obj := m[2]
	if matchClose(obj, 0) != len(obj)-1 {
		return false
	}
	for _, e := range splitTopArgs(obj[1 : len(obj)-1]) {
		if e == "" {
			continue
		}
		k := objKeyRe.FindStringIndex(e)
		if k == nil {
			return false
		}
		v := strings.TrimSpace(e[k[1]:])
		if !isWholeLiteral(v) || strings.ContainsAny(v[1:len(v)-1], `<>"'`) {
			return false
		}
	}
	return true
}
