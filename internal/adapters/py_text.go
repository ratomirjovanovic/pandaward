package adapters

import (
	"regexp"
	"strings"
)

// Python text that only names a call.
//
// A docstring that says "never use eval()", a pattern table in a security
// checker (`(r"os\.system\(", "os.system() call")`) and an error message
// ("shell=True is no longer supported") all match the eval and shell rules
// without running anything. pyTextDemote lists such a line as information
// when every match on it lies inside a string literal or a docstring. A
// match inside the braces of an f-string is code and keeps its severity.

var (
	pyEvalRe  = regexp.MustCompile(`(^|[^.\w])(eval|exec)\s*\(`)
	pyShellRe = regexp.MustCompile(`shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(|commands\.getoutput\(`)
)

// pyTextDemote returns the demotion for rule matches that all lie in text.
func pyTextDemote(re *regexp.Regexp, what string) func(lineCtx) *demotion {
	return func(c lineCtx) *demotion {
		if c.File == nil || c.Index < 0 || c.Index >= len(c.File.Lines) {
			return nil
		}
		line := c.File.Lines[c.Index]
		locs := re.FindAllStringIndex(line, -1)
		if len(locs) == 0 {
			return nil
		}
		spans := pyTextSpans(c.File.Lines, c.Index)
		for _, loc := range locs {
			// The eval pattern may begin with the one character before the name.
			start := loc[0]
			if c := line[start]; !(c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				start++
			}
			if !inSpans(spans, start) {
				return nil
			}
		}
		return &demotion{Title: "Text that names " + what,
			Message: "Every match on this line lies inside a string literal or a docstring: it is a message, a pattern or documentation that names the call and does not run it here.",
			Fix:     "Nothing to do; review the code that acts on the text."}
	}
}

type pySpan struct{ from, to int }

func inSpans(s []pySpan, i int) bool {
	for _, p := range s {
		if i >= p.from && i < p.to {
			return true
		}
	}
	return false
}

// pyTextSpans returns the byte ranges of line idx that are string text
// (not code): literals, docstrings, and comments. It reads the file from the
// start so a triple-quoted string that opens on an earlier line is known.
func pyTextSpans(lines []string, idx int) []pySpan {
	triple := "" // the open triple-quote delimiter, or ""
	tripleF := false
	var out []pySpan
	for n := 0; n <= idx; n++ {
		l := lines[n]
		if len(l) > 2000 {
			// A line this long is data; treat it as text only for the target
			// line decision by giving up (no spans means code).
			if n == idx {
				return nil
			}
			continue
		}
		i := 0
		var cur []pySpan
		for i < len(l) {
			if triple != "" {
				end := strings.Index(l[i:], triple)
				if end < 0 {
					cur = append(cur, pySpan{i, len(l)})
					i = len(l)
					break
				}
				cur = append(cur, pyBraceFree(l, i, i+end, tripleF)...)
				i += end + len(triple)
				triple = ""
				continue
			}
			ch := l[i]
			if ch == '#' {
				cur = append(cur, pySpan{i, len(l)})
				break
			}
			if ch == '"' || ch == '\'' {
				isF := i > 0 && pyFPrefix(l, i)
				if strings.HasPrefix(l[i:], strings.Repeat(string(ch), 3)) {
					triple = strings.Repeat(string(ch), 3)
					tripleF = isF
					i += 3
					continue
				}
				j := i + 1
				for j < len(l) && l[j] != ch {
					if l[j] == '\\' {
						j++
					}
					j++
				}
				if j > len(l) {
					j = len(l)
				}
				cur = append(cur, pyBraceFree(l, i+1, j, isF)...)
				i = j + 1
				continue
			}
			i++
		}
		if n == idx {
			out = cur
		}
	}
	return out
}

// pyFPrefix reports whether the quote at l[i] opens an f-string.
func pyFPrefix(l string, i int) bool {
	for j := i - 1; j >= 0 && j >= i-3; j-- {
		switch l[j] {
		case 'f', 'F':
			return true
		case 'r', 'R', 'b', 'B', 'u', 'U':
			continue
		default:
			return false
		}
	}
	return false
}

// pyBraceFree returns the text range [from,to) of a string, minus the
// {...} replacement fields when the string is an f-string.
func pyBraceFree(l string, from, to int, isF bool) []pySpan {
	if to > len(l) {
		to = len(l)
	}
	if from >= to {
		return nil
	}
	if !isF {
		return []pySpan{{from, to}}
	}
	var out []pySpan
	start, depth := from, 0
	for i := from; i < to; i++ {
		switch l[i] {
		case '{':
			if i+1 < to && l[i+1] == '{' && depth == 0 {
				i++
				continue
			}
			if depth == 0 {
				out = append(out, pySpan{start, i})
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 {
					start = i + 1
				}
			}
		}
	}
	if depth == 0 && start < to {
		out = append(out, pySpan{start, to})
	}
	return out
}
