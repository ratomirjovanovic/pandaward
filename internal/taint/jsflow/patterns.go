package jsflow

import (
	"regexp"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

// Shape checks: escaping and URL checks that are incomplete whatever the
// data, found by the shape of the code.

var (
	// firstOnly are string patterns of replace() that, being strings, are
	// replaced only at their first occurrence.
	firstOnly = map[string]bool{"'": true, `"`: true, "<": true, ">": true, "&": true, "`": true, `\`: true, `\\`: true, "../": true, "..": true, "/../": true, "/..": true}
	// escapeRegex is a regular expression of escape characters, which
	// without the g flag replaces only the first match.
	escapeRegex = regexp.MustCompile(`^/(\[[^\]\w\s]+\]|\(?\\?[^\w\s()|]\\?[^\w\s()|]?(\|\\?[^\w\s()|]\\?[^\w\s()|]?)+\)?|\\\\)/[imsuy]*$`)
	// rebuilt are sequences a single removal pass can rebuild: removing
	// the inner "../" of "....//" leaves "../".
	rebuilt = regexp.MustCompile(`^/.*(<!--|<script|\\\.\\\.(\\/|/|\[)).*/[a-z]*$`)
	// jsScheme is a check for the javascript: scheme alone.
	jsScheme = regexp.MustCompile(`(?i)^javascript:?$`)
)

func (a *analyzer) shapes(f *js.File) {
	byID := map[string]*taint.Sink{}
	for _, k := range a.spec.Sinks {
		byID[k.ID] = k
	}
	escape, scheme := byID["taint.js-incomplete-sanitization"], byID["taint.js-incomplete-url-scheme-check"]
	report := func(k *taint.Sink, line int, what string) {
		if k == nil {
			return
		}
		key := k.ID + "|" + itoa(line)
		if a.seen[key] {
			return
		}
		a.seen[key] = true
		a.out = append(a.out, taint.Finding{Sink: k, File: a.file, Line: line, EndLine: line, Library: true,
			Steps: []taint.Step{{Line: line, What: what}, {Line: line, What: k.Title}}})
	}
	// Each function body on its own, so a data: check in another function
	// does not excuse a javascript: check here.
	bodies := [][]js.Stmt{f.Stmts}
	for _, st := range f.Stmts {
		js.Inspect(st, func(n js.Node) bool {
			if fn, ok := n.(*js.Func); ok {
				body := fn.Body
				if fn.ExprBody != nil {
					body = []js.Stmt{&js.Return{Pos: js.Pos{Line: fn.Line}, X: fn.ExprBody}}
				}
				bodies = append(bodies, body)
			}
			return true
		})
	}
	for _, body := range bodies {
		var schemeChecks []int
		dataScheme := false
		for _, st := range body {
			js.Inspect(st, func(n js.Node) bool {
				switch n := n.(type) {
				case *js.Func:
					return false // its own body
				case *js.Lit:
					if n.Kind == js.TString && strings.Contains(strings.ToLower(n.Val), "data:") {
						dataScheme = true
					}
				case *js.Call:
					m, ok := n.Callee.(*js.Member)
					if !ok || m.Computed != nil || len(n.Args) == 0 {
						return true
					}
					lit, _ := n.Args[0].(*js.Lit)
					switch m.Prop {
					case "replace":
						if what := incompleteReplace(n); what != "" {
							report(escape, n.Line, what)
						}
					case "indexOf", "startsWith", "includes":
						if lit != nil && lit.Kind == js.TString && jsScheme.MatchString(lit.Val) {
							schemeChecks = append(schemeChecks, n.Line)
						}
					}
				}
				return true
			})
		}
		if !dataScheme {
			for _, line := range schemeChecks {
				report(scheme, line, "the check looks for javascript: only")
			}
		}
	}
}

// incompleteReplace describes a replace() call that escapes or removes
// incompletely, or returns "".
func incompleteReplace(c *js.Call) string {
	if len(c.Args) == 0 {
		return ""
	}
	lit, ok := c.Args[0].(*js.Lit)
	if !ok {
		return ""
	}
	switch {
	case lit.Kind == js.TString && firstOnly[lit.Val]:
		return "replace() of the string " + lit.Val + " changes only its first occurrence"
	case lit.Kind == js.TRegex && escapeRegex.MatchString(lit.Val):
		return "replace() with " + lit.Val + " without the g flag changes only the first match"
	case lit.Kind == js.TRegex && len(c.Args) > 1 && isEmptyString(c.Args[1]) && rebuilt.MatchString(lit.Val):
		return "replace() removes " + lit.Val + " in one pass, which can rebuild it"
	}
	return ""
}

// shapeOnTainted reports an incomplete replace() of a value from a source,
// the check applications get (libraries get all of them).
func (a *analyzer) shapeOnTainted(c *js.Call, recv val) {
	t := recv.anyTaint()
	if t == nil || t.Param > 0 {
		return
	}
	what := incompleteReplace(c)
	if what == "" {
		return
	}
	for _, k := range a.spec.Sinks {
		if k.ID == "taint.js-incomplete-sanitization" {
			a.reportTrace(k, t, []taint.Step{{Line: c.Line, What: what}}, c.Line, c.Line)
		}
	}
}

func isEmptyString(x js.Expr) bool {
	l, ok := x.(*js.Lit)
	return ok && l.Kind == js.TString && l.Val == ""
}
