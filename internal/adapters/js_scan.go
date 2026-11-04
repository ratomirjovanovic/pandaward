package adapters

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
)

// A small JavaScript and TypeScript scanner for the structural checks in
// code_checks.go. It is not a parser: it skips strings, templates, comments
// and regular expression literals so brackets and keywords can be counted,
// and every helper answers "not proven" when the code has a shape it does
// not recognize. Errors therefore only ever keep a finding, never drop one.

func isIdent(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

var regexKeywords = map[string]bool{"return": true, "typeof": true, "case": true, "do": true, "else": true, "in": true, "of": true,
	"void": true, "yield": true, "await": true, "delete": true, "throw": true, "new": true, "instanceof": true}

// regexAllowed reports whether a slash after prev (the last significant
// byte) and word (the identifier ending there) starts a regular expression.
func regexAllowed(prev byte, word string) bool {
	return prev == 0 || strings.IndexByte("(,=:[!&|?{};+-*%~^", prev) >= 0 || regexKeywords[word]
}

// jsSkip returns the end of the string, template, comment or regex literal
// that starts at src[i], or i when none starts there. A quote that is not
// closed on its line is treated as a plain character (an apostrophe in JSX
// text), and so is a slash that does not close a regex on its line.
func jsSkip(src string, i int, prev byte, word string) int {
	c := src[i]
	switch {
	case c == '\'' || c == '"':
		for j := i + 1; j < len(src); j++ {
			switch src[j] {
			case '\\':
				j++
			case c:
				return j + 1
			case '\n':
				return i
			}
		}
		return i
	case c == '`':
		return skipTemplate(src, i)
	case c == '/' && i+1 < len(src) && src[i+1] == '/':
		if k := strings.IndexByte(src[i:], '\n'); k >= 0 {
			return i + k
		}
		return len(src)
	case c == '/' && i+1 < len(src) && src[i+1] == '*':
		if k := strings.Index(src[i+2:], "*/"); k >= 0 {
			return i + 2 + k + 2
		}
		return len(src)
	case c == '/' && regexAllowed(prev, word):
		inClass := false
		for j := i + 1; j < len(src); j++ {
			switch src[j] {
			case '\\':
				j++
			case '[':
				inClass = true
			case ']':
				inClass = false
			case '\n':
				return i
			case '/':
				if !inClass {
					j++
					for j < len(src) && isIdent(src[j]) {
						j++
					}
					return j
				}
			}
		}
		return i
	}
	return i
}

func skipTemplate(src string, i int) int {
	for j := i + 1; j < len(src); j++ {
		switch src[j] {
		case '\\':
			j++
		case '`':
			return j + 1
		case '$':
			if j+1 < len(src) && src[j+1] == '{' {
				end := matchClose(src, j+1)
				if end < 0 {
					return len(src)
				}
				j = end
			}
		}
	}
	return len(src)
}

// walkJS calls fn for every byte of src from from on that is code rather
// than a literal or comment, until fn returns true.
func walkJS(src string, from int, fn func(i int) bool) {
	var prev byte
	word := ""
	for i := from; i < len(src); {
		if j := jsSkip(src, i, prev, word); j > i {
			if c := src[i]; c != '/' || (i+1 < len(src) && src[i+1] != '/' && src[i+1] != '*') {
				prev, word = '"', ""
			}
			i = j
			continue
		}
		c := src[i]
		if fn(i) {
			return
		}
		switch {
		case isIdent(c):
			if i == from || !isIdent(src[i-1]) {
				word = ""
			}
			word += string(c)
			prev = c
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
		default:
			prev, word = c, ""
		}
		i++
	}
}

// maskLiterals returns src with the contents of strings, regex literals and
// comments replaced by spaces (line breaks kept). Template text is masked
// too, but the code inside ${...} is kept, masked the same way.
func maskLiterals(src string) string {
	b := []byte(src)
	var prev byte
	word := ""
	for i := 0; i < len(src); {
		j := jsSkip(src, i, prev, word)
		if j == i {
			c := src[i]
			switch {
			case isIdent(c):
				if i == 0 || !isIdent(src[i-1]) {
					word = ""
				}
				word += string(c)
				prev = c
			case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			default:
				prev, word = c, ""
			}
			i++
			continue
		}
		comment := src[i] == '/' && i+1 < len(src) && (src[i+1] == '/' || src[i+1] == '*')
		if !comment {
			prev, word = '"', ""
		}
		for k := i + 1; k < j-1; k++ {
			if src[i] == '`' && src[k] == '$' && k+1 < j && src[k+1] == '{' {
				end := matchClose(src, k+1)
				if end < 0 || end >= j {
					break
				}
				copy(b[k+2:end], maskLiterals(src[k+2:end]))
				k = end
				continue
			}
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
		if comment {
			b[i], b[j-1] = ' ', ' '
		}
		i = j
	}
	return string(b)
}

// matchClose returns the index of the bracket that closes the one at
// src[open], or -1.
func matchClose(src string, open int) int {
	depth, end := 0, -1
	walkJS(src, open, func(i int) bool {
		switch src[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				end = i
				return true
			}
		}
		return false
	})
	return end
}

// exprEnd returns where the expression starting at start ends: at a byte of
// stops or an unmatched closing bracket at depth zero, or, when newline is
// set, at a line break that is not followed by an operator continuing it.
func exprEnd(src string, start int, stops string, newline bool) int {
	depth, end := 0, len(src)
	walkJS(src, start, func(i int) bool {
		c := src[i]
		switch {
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth == 0 {
				end = i
				return true
			}
			depth--
		case depth == 0 && strings.IndexByte(stops, c) >= 0:
			end = i
			return true
		case depth == 0 && newline && c == '\n':
			if strings.TrimSpace(src[start:i]) == "" {
				return false
			}
			next := strings.TrimLeft(src[i:], " \t\r\n")
			if next == "" || strings.IndexByte(".?:+-*/|&=", next[0]) < 0 {
				end = i
				return true
			}
		}
		return false
	})
	return end
}

// splitTopArgs splits a call's argument text at top-level commas.
func splitTopArgs(args string) []string {
	var out []string
	depth, last := 0, 0
	walkJS(args, 0, func(i int) bool {
		switch args[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(args[last:i]))
				last = i + 1
			}
		}
		return false
	})
	if rest := strings.TrimSpace(args[last:]); rest != "" || len(out) > 0 {
		out = append(out, rest)
	}
	return out
}

// wholeCall splits expr into callee and argument text when expr is exactly
// one call, callee(args), with nothing after it.
func wholeCall(expr string) (callee, args string, ok bool) {
	open := strings.IndexByte(expr, '(')
	if open <= 0 {
		return "", "", false
	}
	callee = strings.TrimSpace(expr[:open])
	if !calleeRe.MatchString(callee) {
		return "", "", false
	}
	end := matchClose(expr, open)
	if end < 0 || strings.TrimSpace(expr[end+1:]) != "" {
		return "", "", false
	}
	return callee, expr[open+1 : end], true
}

var (
	calleeRe     = regexp.MustCompile(`^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)?$`)
	identRe      = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)
	wholeLitRe   = regexp.MustCompile(`^('(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|\x60[^\x60]*\x60)(\s+as\s+const)?$`)
	ltRegexRe    = regexp.MustCompile(`^/</[a-z]*g[a-z]*$`)
	ltStringRe   = regexp.MustCompile(`^('<'|"<"|\x60<\x60)$`)
	unsafeOptsRe = regexp.MustCompile(`(?i)allowVulnerableTags|['"\x60]script['"\x60]|allowedTags\s*:\s*false|ADD_TAGS|SAFE_FOR_TEMPLATES|allowedAttributes\s*:\s*false`)
)

// isWholeLiteral reports whether expr is one string literal, or a template
// without interpolation.
func isWholeLiteral(expr string) bool {
	m := wholeLitRe.FindStringSubmatch(strings.TrimSpace(expr))
	return m != nil && !strings.Contains(m[1], "${")
}

// isLtEscapedJSON reports whether expr is JSON.stringify(...) followed only
// by .replace/.replaceAll calls with literal replacements, one of which
// replaces every "<". No replacement may contain "<" or a "$" pattern (which
// could put the matched "<" back), so no "<" can survive the chain.
func isLtEscapedJSON(expr string) bool {
	expr = strings.TrimSpace(expr)
	if !strings.HasPrefix(expr, "JSON.stringify(") {
		return false
	}
	end := matchClose(expr, len("JSON.stringify"))
	if end < 0 {
		return false
	}
	rest, escaped := expr[end+1:], false
	for {
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return escaped
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
		if len(args) != 2 || !isWholeLiteral(args[1]) || strings.ContainsAny(args[1], "<$") {
			return false
		}
		if ltRegexRe.MatchString(args[0]) || name == ".replaceAll" && ltStringRe.MatchString(args[0]) {
			escaped = true
		}
		rest = rest[close+1:]
	}
}

// ---- imports ----

type jsBinding struct{ module, imported string }

var (
	importRe  = regexp.MustCompile(`(?m)^\s*import\s+(type\s+)?([^'";]*?)\s+from\s+['"]([^'"]+)['"]`)
	requireRe = regexp.MustCompile(`(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
)

// jsImports maps each local name a file imports to its module and the
// exported name ("default" or "*" for default and namespace imports).
// Type-only imports are left out.
func jsImports(text string) map[string]jsBinding {
	out := map[string]jsBinding{}
	for _, m := range importRe.FindAllStringSubmatch(text, -1) {
		if m[1] != "" {
			continue
		}
		clause, mod := strings.TrimSpace(m[2]), m[3]
		if i := strings.IndexByte(clause, '{'); i >= 0 {
			j := strings.IndexByte(clause, '}')
			if j < i {
				continue
			}
			for _, spec := range strings.Split(clause[i+1:j], ",") {
				f := strings.Fields(spec)
				switch {
				case len(f) == 1:
					out[f[0]] = jsBinding{mod, f[0]}
				case len(f) == 3 && f[1] == "as":
					out[f[2]] = jsBinding{mod, f[0]}
				}
			}
			clause = strings.TrimSpace(clause[:i] + clause[j+1:])
		}
		for _, part := range strings.Split(clause, ",") {
			f := strings.Fields(part)
			switch {
			case len(f) == 1:
				out[f[0]] = jsBinding{mod, "default"}
			case len(f) == 3 && f[0] == "*" && f[1] == "as":
				out[f[2]] = jsBinding{mod, "*"}
			}
		}
	}
	for _, m := range requireRe.FindAllStringSubmatch(text, -1) {
		if !strings.HasPrefix(m[1], "{") {
			out[m[1]] = jsBinding{m[2], "default"}
			continue
		}
		for _, spec := range strings.Split(strings.Trim(m[1], "{}"), ",") {
			k, v, found := strings.Cut(spec, ":")
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if !found {
				v = k
			}
			if identRe.MatchString(k) && identRe.MatchString(v) {
				out[v] = jsBinding{m[2], k}
			}
		}
	}
	return out
}

// ---- local functions ----

// funcReturn finds the single definition of name in text and returns the
// expression it returns: the body of an arrow function with an expression
// body, or the one return statement of a block body. Returns inside nested
// functions do not count; any other return (an early exit) means no answer.
func funcReturn(text, name string, exported bool) (string, bool) {
	q := regexp.QuoteMeta(name)
	ex := `(?:export\s+)?`
	if exported {
		ex = `export\s+`
	}
	decl := regexp.MustCompile(`(?m)(?:^|[^.\w$])` + ex + `(?:function\s+` + q + `\s*(?:<[^>()]*>)?\s*\(|const\s+` + q + `\s*(?::[^=]+)?=\s*)`)
	any := regexp.MustCompile(`(?:^|[^.\w$])(?:function\s+|const\s+|let\s+|var\s+|class\s+)` + q + `\b`)
	locs := decl.FindAllStringIndex(text, -1)
	if len(locs) != 1 || len(any.FindAllStringIndex(text, -1)) != 1 {
		return "", false
	}
	at := locs[0][1]
	if text[at-1] == '(' {
		// function name(params)[: Type] { body }
		close := matchClose(text, at-1)
		if close < 0 {
			return "", false
		}
		return blockReturn(text, close+1)
	}
	// const name = (params) => ... or param => ...
	rest := text[at:]
	var after int
	switch {
	case strings.HasPrefix(rest, "("):
		close := matchClose(rest, 0)
		if close < 0 {
			return "", false
		}
		after = at + close + 1
	default:
		m := regexp.MustCompile(`^[A-Za-z_$][\w$]*`).FindStringIndex(rest)
		if m == nil {
			return "", false
		}
		after = at + m[1]
	}
	arrow := regexp.MustCompile(`^\s*(?::\s*[\w$.<>\[\]| ]+?)?\s*=>\s*`).FindStringIndex(text[after:])
	if arrow == nil {
		return "", false
	}
	body := after + arrow[1]
	if strings.HasPrefix(text[body:], "{") {
		return blockReturn(text, body)
	}
	return strings.TrimSpace(text[body:exprEnd(text, body, ";,", true)]), true
}

var retTypeRe = regexp.MustCompile(`^\s*(?::\s*[\w$.<>\[\]| ]+?)?\s*\{`)

// blockReturn reads an optional return type and a block body starting at
// from and returns the expression of its only top-level return statement.
func blockReturn(text string, from int) (string, bool) {
	m := retTypeRe.FindStringIndex(text[from:])
	if m == nil {
		return "", false
	}
	open := from + m[1] - 1
	close := matchClose(text, open)
	if close < 0 {
		return "", false
	}
	body := text[open+1 : close]
	var stack []bool // true for a function body
	pendingFunc, funcDepth := false, 0
	var lastSig, lastSig2 byte
	var rets []int
	walkJS(body, 0, func(i int) bool {
		c := body[i]
		if isIdent(c) && (i == 0 || !isIdent(body[i-1])) {
			j := i
			for j < len(body) && isIdent(body[j]) {
				j++
			}
			switch body[i:j] {
			case "function":
				pendingFunc = true
			case "return":
				if funcDepth == 0 {
					rets = append(rets, j)
				}
			}
		}
		switch c {
		case '{':
			fn := pendingFunc || lastSig == '>' && lastSig2 == '='
			pendingFunc = false
			stack = append(stack, fn)
			if fn {
				funcDepth++
			}
		case '}':
			if n := len(stack); n > 0 {
				if stack[n-1] {
					funcDepth--
				}
				stack = stack[:n-1]
			}
		}
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			lastSig2, lastSig = lastSig, c
		}
		return false
	})
	if len(rets) != 1 {
		return "", false
	}
	return strings.TrimSpace(body[rets[0]:exprEnd(body, rets[0], ";", true)]), true
}

// ---- module resolution ----

var jsExts = []string{".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts"}

// resolveLocal resolves an import specifier of the file at from to a file in
// the repository: a relative path, or a path alias from the nearest
// tsconfig.json or jsconfig.json. Package imports (node_modules) do not
// resolve.
func resolveLocal(inv *inventory.Inventory, from, spec string) *inventory.File {
	var bases []string
	if strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../") {
		bases = []string{path.Join(path.Dir(from), spec)}
	} else {
		bases = aliasTargets(inv, from, spec)
	}
	for _, b := range bases {
		if b == ".." || strings.HasPrefix(b, "../") || strings.Contains("/"+b+"/", "/node_modules/") {
			continue
		}
		cands := []string{b}
		for _, e := range jsExts {
			cands = append(cands, b+e)
		}
		for _, e := range jsExts {
			cands = append(cands, b+"/index"+e)
		}
		if ext := path.Ext(b); ext == ".js" || ext == ".mjs" || ext == ".jsx" {
			stem := strings.TrimSuffix(b, ext)
			cands = append(cands, stem+".ts", stem+".tsx", stem+".mts")
		}
		for _, c := range cands {
			if f := inv.FileByPath(c); f != nil && jsLike[f.Lang] {
				return f
			}
		}
	}
	return nil
}

// aliasTargets maps spec through compilerOptions.paths of the nearest
// tsconfig.json or jsconfig.json above the importing file.
func aliasTargets(inv *inventory.Inventory, from, spec string) []string {
	for dir := path.Dir(from); ; dir = path.Dir(dir) {
		for _, name := range []string{"tsconfig.json", "jsconfig.json"} {
			f := inv.FileByPath(path.Join(dir, name))
			if f == nil {
				continue
			}
			var cfg struct {
				CompilerOptions struct {
					BaseURL string              `json:"baseUrl"`
					Paths   map[string][]string `json:"paths"`
				} `json:"compilerOptions"`
			}
			if json.Unmarshal([]byte(stripJSONC(strings.Join(f.Lines, "\n"))), &cfg) != nil {
				return nil
			}
			base := path.Join(dir, cfg.CompilerOptions.BaseURL)
			// TypeScript prefers the longest matching pattern.
			pats := make([]string, 0, len(cfg.CompilerOptions.Paths))
			for pat := range cfg.CompilerOptions.Paths {
				pats = append(pats, pat)
			}
			sort.Slice(pats, func(i, j int) bool {
				return len(pats[i]) > len(pats[j]) || len(pats[i]) == len(pats[j]) && pats[i] < pats[j]
			})
			var out []string
			for _, pat := range pats {
				targets := cfg.CompilerOptions.Paths[pat]
				star := ""
				if pre, suf, ok := strings.Cut(pat, "*"); ok {
					if !strings.HasPrefix(spec, pre) || !strings.HasSuffix(spec, suf) || len(spec) < len(pre)+len(suf) {
						continue
					}
					star = spec[len(pre) : len(spec)-len(suf)]
				} else if pat != spec {
					continue
				}
				for _, t := range targets {
					out = append(out, path.Join(base, strings.Replace(t, "*", star, 1)))
				}
			}
			return out
		}
		if dir == "." || dir == "/" || dir == "" {
			return nil
		}
	}
}

var trailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)

// stripJSONC removes comments and trailing commas from tsconfig-style JSON.
func stripJSONC(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			b.WriteString(s[i:min(j+1, len(s))])
			i = j
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			k := strings.Index(s[i+2:], "*/")
			if k < 0 {
				return b.String()
			}
			i += k + 3
		default:
			b.WriteByte(c)
		}
	}
	return trailingCommaRe.ReplaceAllString(b.String(), "$1")
}
