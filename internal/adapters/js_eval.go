package adapters

import (
	"regexp"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// Dynamic code evaluation in JavaScript (#509). A line rule cannot see a
// data flow, so it lists an eval at high severity only when nothing in the
// call or the file shows that the text is harmless. The shapes below are
// the ones that were false positives on real applications in round 1; each
// is lowered, never dropped.

var (
	// evalOpenRe finds the start of an eval or new Function call.
	evalOpenRe = regexp.MustCompile(`(?:^|[^.\w])(?:eval|Function)\s*\(`)
	// callTextRe matches a literal piece of an evaluated string that is code
	// calling a function or assigning a value: "BM1('" or " = window.open(".
	callTextRe = regexp.MustCompile(`[A-Za-z_$][\w$.]*\s*\(|[A-Za-z_$][\w$.]*\s*=[^=]`)
	// userInputRe names values that carry client input in browser and
	// server code; an evaluated string built from one of them stays high.
	userInputRe = regexp.MustCompile(`(?i)\b(req|request|params|query|body|input|location|cookies?|hash|search|href|referrer|responseText|response|payload|user\w*|param\w*|message|data|url|name|value|text|args?|argv|env|headers?)\b`)
	// definitionRe finds the declaration of a variable.
	definitionRe = func(name string) *regexp.Regexp {
		return regexp.MustCompile(`(?:^|[^.\w$])(?:const|let|var)\s+` + regexp.QuoteMeta(name) + `\s*=\s*([^;]+)`)
	}
	evalIdentRe = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	// evalChainRe matches a member chain such as a.b.c.
	evalChainRe = regexp.MustCompile(`[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+`)
	// safeNames are built-ins whose result is a number, a date or a
	// string made of them, whatever the arguments.
	safeNames = map[string]bool{
		"Math": true, "floor": true, "random": true, "round": true, "ceil": true, "abs": true, "min": true, "max": true,
		"toString": true, "parseInt": true, "parseFloat": true, "Number": true, "String": true, "Date": true, "getTime": true,
		"now": true, "length": true, "new": true, "true": true, "false": true, "null": true, "undefined": true,
	}
)

// evalCallArg returns the text between the parentheses of the first eval or
// new Function call on a line, and false when the call does not close on
// that line.
func evalCallArg(line string) (string, bool) {
	loc := evalOpenRe.FindStringIndex(line)
	if loc == nil {
		return "", false
	}
	start := loc[1]
	depth := 1
	var quote byte
	for i := start; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return line[start:i], true
			}
		}
	}
	return "", false
}

// stringLiterals returns the contents of the string literals of a text.
func stringLiterals(s string) []string {
	var out []string
	var quote byte
	begin := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				out = append(out, s[begin:i])
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote, begin = c, i+1
		}
	}
	return out
}

// safeOrigin reports whether an expression is built only from literals,
// numbers, built-in numeric calls and variables declared above it in the
// file that are themselves built that way. A parameter, a property of an
// unknown object or a call of another function is not safe.
func safeOrigin(lines []string, idx int, expr string, depth int) bool {
	if depth > 5 {
		return false
	}
	code := maskLiterals(expr)
	// A member chain a.b.c is safe through its properties when one of them
	// is not a built-in: every assignment to it in the file must store a
	// safe value (a flag set to true), and the object it hangs on is then
	// not checked. A chain of built-ins (Math.random, n.toString) is
	// checked through its first name.
	for _, loc := range evalChainRe.FindAllStringIndex(code, -1) {
		parts := strings.Split(code[loc[0]:loc[1]], ".")
		custom := false
		for _, p := range parts[1:] {
			if !safeNames[p] {
				custom = true
				if !propertySafe(lines, p, depth) {
					return false
				}
			}
		}
		if !custom && !safeNames[parts[0]] && !definedSafe(lines, idx, parts[0], depth) {
			return false
		}
		code = code[:loc[0]] + strings.Repeat(" ", loc[1]-loc[0]) + code[loc[1]:]
	}
	for _, loc := range evalIdentRe.FindAllStringIndex(code, -1) {
		name := code[loc[0]:loc[1]]
		if safeNames[name] {
			continue
		}
		if !definedSafe(lines, idx, name, depth) {
			return false
		}
	}
	// What is left once identifiers, numbers and operators are removed
	// must not contain a call of an unknown function or a member access.
	rest := evalIdentRe.ReplaceAllString(code, "")
	for _, r := range rest {
		if !strings.ContainsRune("0123456789 \t+-*/%()[],.?:<>=!&|\"'`", r) {
			return false
		}
	}
	return true
}

// propertySafe reports whether the file assigns to .name at least once and
// every assignment stores a safe value.
func propertySafe(lines []string, name string, depth int) bool {
	re := regexp.MustCompile(`\.` + regexp.QuoteMeta(name) + `\s*=\s*([^=;}][^;}]*)`)
	found := false
	for i, l := range lines {
		for _, m := range re.FindAllStringSubmatch(l, -1) {
			found = true
			if !safeOrigin(lines, i, m[1], depth+1) {
				return false
			}
		}
	}
	return found
}

// definedSafe looks up to 80 lines above idx for the declaration of name
// and checks its value.
func definedSafe(lines []string, idx int, name string, depth int) bool {
	re := definitionRe(name)
	for i := idx; i >= 0 && i > idx-80; i-- {
		m := re.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		return safeOrigin(lines, i, m[1], depth+1)
	}
	return false
}

// packedFile reports whether a file is minified or packed: a very long line.
func packedFile(lines []string) bool {
	for _, l := range lines {
		if len(l) > 1000 {
			return true
		}
	}
	return false
}

// jsEvalDemoteAt classifies the eval on line idx of a file. It returns nil
// when the call has to stay at its own severity.
func jsEvalDemoteAt(path string, lines []string, idx int) (*demotion, bool) {
	if idx < 0 || idx >= len(lines) {
		return nil, false
	}
	line := lines[idx]
	if jsEvalConstRe.MatchString(line) {
		return &demotion{Title: "Dynamic code evaluation of a constant string",
			Message: "The evaluated text is made only of literals, so nothing a user controls reaches it. It is listed for completeness.",
			Fix:     "Nothing to do; replace it with a direct call if the code is yours."}, true
	}
	if IsVendoredPath(path) {
		return &demotion{Title: "Dynamic code evaluation in bundled or third-party JavaScript",
			Message: "The file is in a vendor, static or build output directory, so it is most likely a library the project ships and not code it wrote. It is listed for review and does not decide the control.",
			Fix:     "Keep the library up to date; review the call if the file is your own code."}, true
	}
	if packedFile(lines) {
		return &demotion{Title: "Dynamic code evaluation in a minified or packed file",
			Message: "The file has lines of more than 1000 characters, so it is a packed or minified bundle and not code a person maintains. It is listed for review and does not decide the control.",
			Fix:     "Review the source the bundle was built from."}, true
	}
	if inStringLiteral(line, evalOpenRe) {
		return &demotion{Title: "Text that names a timer call",
			Message: "The match lies inside a string literal: the line builds code as text and does not run it here.",
			Fix:     "Nothing to do; review the place that evaluates the text."}, true
	}
	arg, ok := evalCallArg(line)
	if !ok {
		return nil, false
	}
	arg = strings.TrimSpace(arg)
	if safeOrigin(lines, idx, arg, 0) {
		return &demotion{Title: "Dynamic code evaluation of text built from constants and numbers",
			Message: "The evaluated text is built only from literals, numbers and values the file computes from them (Math, Date), so no client input reaches it. It is listed for completeness.",
			Fix:     "Compute the value without eval."}, true
	}
	// The legacy idiom eval("fn('" + x + "')"): a call or an assignment
	// written as text, with the variable parts spliced in. Without a
	// client input among them nothing shows a flow, so it is low; with one
	// it stays as it is.
	code := maskLiterals(arg)
	if strings.Contains(code, "+") && !userInputRe.MatchString(code) {
		texts := arg
		for _, name := range evalIdentRe.FindAllString(code, -1) {
			if m := definitionRe(name); m != nil {
				for i := idx; i >= 0 && i > idx-80; i-- {
					if d := m.FindStringSubmatch(lines[i]); d != nil {
						texts += " " + d[1]
						break
					}
				}
			}
		}
		for _, lit := range stringLiterals(texts) {
			if callTextRe.MatchString(lit) {
				return &demotion{Title: "Dynamic code evaluation of a call built from text",
					Message: "The evaluated text is a function call or assignment written as a string with variables spliced in, and none of the variables is named like client input. A flow from an untrusted source was not shown, so this is a suspicion at low severity.",
					Fix:     "Call the function directly instead of building its call as text; if any spliced value is client input this is code injection.",
					Sev:     model.SevLow}, true
			}
		}
	}
	return nil, false
}

// semgrepEvalDemotion applies the same classification to a result of the
// bundled pandaward-js-eval rule, so the two adapters agree on one line.
func semgrepEvalDemotion(c *Context, rel string, line int) *demotion {
	if c == nil || c.Inv == nil {
		return nil
	}
	f := c.Inv.FileByPath(rel)
	if f == nil {
		return nil
	}
	d, _ := jsEvalDemoteAt(f.Path, f.Lines, line-1)
	return d
}

var timerOpenRe = regexp.MustCompile("set(?:Timeout|Interval)[(][ 	]*['\"`]")

// inStringLiteral reports whether the line has a timer call with a string
// argument only inside a string literal and no eval or Function call.
func inStringLiteral(line string, evalRe *regexp.Regexp) bool {
	if evalRe.MatchString(line) {
		return false
	}
	loc := timerOpenRe.FindStringIndex(line)
	if loc == nil {
		return false
	}
	var quote byte
	for i := 0; i < loc[0]; i++ {
		c := line[i]
		if quote != 0 {
			if c == 92 {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
		}
	}
	return quote != 0
}
