package adapters

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/csp"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// ---- H-004: weak CSP declared in header config ----
//
// The same parser as the runtime header check (internal/csp) judges CSP
// values that a repository declares statically. Only values that can be read
// without evaluating code are judged: a value built from variables or
// function calls is skipped, never guessed. A config is not proof of what is
// served (a CDN, middleware or a meta tag may change it), so results are
// hypotheses; `production-observe` confirms the served header under H-003.

// cspDecl is one Content-Security-Policy value found in a config file.
type cspDecl struct {
	value string
	line  int // 1-based
}

func cspConfigSignals(f *inventory.File, collector string) []model.Signal {
	var decls []cspDecl
	switch b := strings.ToLower(path.Base(f.Path)); {
	case b == "vercel.json":
		decls = vercelCSP(f.Lines)
	case b == "netlify.toml":
		decls = netlifyCSP(f.Lines)
	case b == "_headers":
		decls = headersFileCSP(f.Lines)
	case strings.HasPrefix(b, "next.config."):
		decls = nextConfigCSP(f.Lines)
	}
	var out []model.Signal
	for _, d := range decls {
		w, weak := csp.Check(d.value)
		if !weak {
			continue
		}
		line := min(max(d.line, 1), len(f.Lines))
		out = append(out, model.Signal{
			RuleID: "code.weak-csp", ControlID: "H-004", Title: "Declared Content-Security-Policy allows " + w.Keyword + " scripts",
			Severity: model.SevMedium, Confidence: model.Hypothesis, CWE: "CWE-693",
			File: f.Path, StartLine: line, EndLine: line, Snippet: redact.Line(strings.TrimSpace(f.Lines[line-1])),
			Message:   w.Message() + " This is the value declared in the config; the served header can differ.",
			Fix:       w.Fix(),
			Retest:    "Re-run `pandaward scan`; run `pandaward test --profile production-observe` to check the served header.",
			Collector: collector, Key: w.Keyword + " " + w.Directive,
		})
	}
	return out
}

func isCSPKey(k string) bool {
	return strings.EqualFold(strings.TrimSpace(k), "Content-Security-Policy")
}

// vercelCSP reads headers[].headers[] and the legacy routes[].headers map.
func vercelCSP(lines []string) []cspDecl {
	var doc struct {
		Headers []struct {
			Headers []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"headers"`
		} `json:"headers"`
		Routes []struct {
			Headers map[string]string `json:"headers"`
		} `json:"routes"`
	}
	if json.Unmarshal([]byte(strings.Join(lines, "\n")), &doc) != nil {
		return nil
	}
	var vals []string
	for _, h := range doc.Headers {
		for _, kv := range h.Headers {
			if isCSPKey(kv.Key) {
				vals = append(vals, kv.Value)
			}
		}
	}
	for _, r := range doc.Routes {
		for k, v := range r.Headers {
			if isCSPKey(k) {
				vals = append(vals, v)
			}
		}
	}
	var out []cspDecl
	for _, v := range vals {
		out = append(out, cspDecl{value: v, line: lineOfJSONValue(lines, v)})
	}
	return out
}

// lineOfJSONValue finds the line that holds a JSON string value, falling
// back to the first line naming the header.
func lineOfJSONValue(lines []string, v string) int {
	enc, _ := json.Marshal(v)
	needle := strings.Trim(string(enc), `"`)
	if len(needle) > 40 {
		needle = needle[:40]
	}
	for i, l := range lines {
		if needle != "" && strings.Contains(l, needle) {
			return i + 1
		}
	}
	for i, l := range lines {
		if strings.Contains(strings.ToLower(l), `"content-security-policy"`) {
			return i + 1
		}
	}
	return 1
}

var netlifyKeyRe = regexp.MustCompile(`(?i)^\s*(?:"content-security-policy"|'content-security-policy'|content-security-policy)\s*=\s*(.*)$`)

// netlifyCSP reads `Content-Security-Policy = ...` keys, the form used in
// [headers.values] tables. Basic, literal and multi-line strings are read;
// anything else is skipped.
func netlifyCSP(lines []string) []cspDecl {
	var out []cspDecl
	for i := 0; i < len(lines); i++ {
		m := netlifyKeyRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		rest := strings.TrimSpace(m[1])
		for _, q := range []string{`"""`, `'''`} {
			if !strings.HasPrefix(rest, q) {
				continue
			}
			body, start := rest[3:], i
			var parts []string
			for {
				if j := strings.Index(body, q); j >= 0 {
					parts = append(parts, body[:j])
					out = append(out, cspDecl{value: tomlJoin(parts, q == `"""`), line: start + 1})
					break
				}
				parts = append(parts, body)
				i++
				if i >= len(lines) {
					break
				}
				body = lines[i]
			}
			rest = ""
		}
		if rest == "" {
			continue
		}
		if v, ok := quoted(rest, false); ok {
			out = append(out, cspDecl{value: v, line: i + 1})
		}
	}
	return out
}

// tomlJoin joins the lines of a multi-line TOML string with spaces; header
// values cannot hold newlines, and a policy treats them as whitespace.
func tomlJoin(parts []string, basic bool) string {
	for k, p := range parts {
		if basic {
			p = strings.TrimSuffix(strings.TrimRight(p, " \t"), `\`)
		}
		parts[k] = p
	}
	return strings.Join(parts, " ")
}

var headersFileRe = regexp.MustCompile(`(?i)^\s+content-security-policy\s*:\s*(.+)$`)

// headersFileCSP reads indented `Content-Security-Policy: ...` lines of a
// Netlify or Cloudflare Pages _headers file.
func headersFileCSP(lines []string) []cspDecl {
	var out []cspDecl
	for i, l := range lines {
		if m := headersFileRe.FindStringSubmatch(l); m != nil {
			out = append(out, cspDecl{value: m[1], line: i + 1})
		}
	}
	return out
}

var nextKeyRe = regexp.MustCompile(`(?i)['"]?\bkey['"]?\s*:\s*(['"\x60])content-security-policy['"\x60]\s*,\s*['"]?value['"]?\s*:\s*`)

// nextConfigCSP reads `{ key: 'Content-Security-Policy', value: ... }`
// entries of a Next.js headers() block when the value is a string literal or
// an array of string literals joined with a literal separator. Any other
// expression (variables, template substitutions, calls) is skipped.
func nextConfigCSP(lines []string) []cspDecl {
	text := strings.Join(lines, "\n")
	var out []cspDecl
	for _, loc := range nextKeyRe.FindAllStringIndex(text, -1) {
		lineStart := strings.LastIndex(text[:loc[0]], "\n") + 1
		if commentRe.MatchString(text[lineStart:loc[0]] + "x") {
			continue
		}
		v, ok := jsStaticString(text[loc[1]:])
		if !ok {
			continue
		}
		out = append(out, cspDecl{value: v, line: strings.Count(text[:loc[1]], "\n") + 1})
	}
	return out
}

// jsStaticString resolves a JavaScript expression at the start of s that is a
// string literal or `[literal, ...].join(literal)`, followed by the end of
// the property (`,` or `}`).
func jsStaticString(s string) (string, bool) {
	var v, rest string
	if strings.HasPrefix(s, "[") {
		var parts []string
		rest = s[1:]
		for {
			rest = strings.TrimLeft(rest, " \t\r\n")
			if strings.HasPrefix(rest, "]") {
				rest = rest[1:]
				break
			}
			p, r, ok := jsLiteral(rest)
			if !ok {
				return "", false
			}
			parts = append(parts, p)
			rest = strings.TrimLeft(r, " \t\r\n")
			if strings.HasPrefix(rest, ",") {
				rest = rest[1:]
			} else if !strings.HasPrefix(rest, "]") {
				return "", false
			}
		}
		rest = strings.TrimLeft(rest, " \t\r\n")
		if !strings.HasPrefix(rest, ".join(") {
			return "", false
		}
		rest = strings.TrimLeft(rest[len(".join("):], " \t\r\n")
		sep, r, ok := jsLiteral(rest)
		if !ok {
			return "", false
		}
		rest = strings.TrimLeft(r, " \t\r\n")
		if !strings.HasPrefix(rest, ")") {
			return "", false
		}
		v, rest = strings.Join(parts, sep), rest[1:]
	} else {
		lit, r, ok := jsLiteral(s)
		if !ok {
			return "", false
		}
		v, rest = lit, r
	}
	rest = strings.TrimLeft(rest, " \t\r\n")
	if rest == "" || rest[0] == ',' || rest[0] == '}' {
		return v, true
	}
	return "", false
}

// jsLiteral reads one quoted string literal at the start of s. Template
// literals with substitutions are not static and are refused.
func jsLiteral(s string) (string, string, bool) {
	if s == "" {
		return "", "", false
	}
	q := s[0]
	if q != '\'' && q != '"' && q != '`' {
		return "", "", false
	}
	v, ok := quoted(s, true)
	if !ok || (q == '`' && strings.Contains(v, "${")) {
		return "", "", false
	}
	return v, s[literalEnd(s, true):], true
}

// quoted returns the content of the quoted string at the start of s. With js
// set, backticks are accepted and may span lines. A TOML literal string
// (single quotes outside JavaScript) has no escapes.
func quoted(s string, js bool) (string, bool) {
	if s == "" || (!js && s[0] == '`') {
		return "", false
	}
	escapes := js || s[0] == '"'
	end := literalEnd(s, escapes)
	if end < 0 {
		return "", false
	}
	body := s[1 : end-1]
	if !escapes {
		return body, true
	}
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) {
			i++
		}
		b.WriteByte(body[i])
	}
	return b.String(), true
}

// literalEnd returns the index just past the closing quote of the string
// literal at the start of s, or -1. Only template literals span lines.
func literalEnd(s string, escapes bool) int {
	if s == "" {
		return -1
	}
	q := s[0]
	if q != '\'' && q != '"' && q != '`' {
		return -1
	}
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] == '\\' && escapes:
			i++
		case s[i] == '\n' && q != '`':
			return -1
		case s[i] == q:
			return i + 1
		}
	}
	return -1
}
