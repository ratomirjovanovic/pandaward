package adapters

import (
	"strings"
	"testing"
)

const (
	escArrow = "const esc = (s) =>\n  String(s).replace(/[&<>\"']/g, (c) =>\n    ({ \"&\": \"&amp;\", \"<\": \"&lt;\", \">\": \"&gt;\", '\"': \"&quot;\", \"'\": \"&#39;\" }[c])\n  );\n"
	brand    = "const BRAND = { name: \"ACME\", letter: \"A\" };\n"
)

// renderFn mirrors an overlay that builds markup in a local variable from
// escaped values and literal-only constants (#291, #292).
func renderFn(loopBody string) string {
	return "function render(data, body) {\n" +
		"  let html = \"\";\n" +
		"  for (const s of data.segments) {\n" +
		"    const color = s.speaker === \"you\" ? \"#38a6ff\" : \"#b9c3dc\";\n" +
		loopBody +
		"  }\n" +
		"  body.innerHTML = html;\n" +
		"}\n"
}

const safeLoop = "    html +=\n      '<p><span style=\"color:' +\n      color +\n      '\">' +\n      esc(s.who) +\n      \"</span> \" +\n      esc(s.text) +\n      \"</p>\";\n"

// Each case is the file ui.js; code.html-sink must fire on it or not.
func TestHTMLAssignProvenSafe(t *testing.T) {
	cases := []struct {
		name, src string
		want      bool
	}{
		{"escaped accumulator with a literal ternary const", escArrow + renderFn(safeLoop), false},
		{"accumulator with one unescaped append", escArrow + renderFn(safeLoop+"    html += s.raw;\n"), true},
		{"accumulator assigned elsewhere from input", escArrow + renderFn(safeLoop) + "function reset(x) { html = x.markup; }\n", true},
		{"const ternary with a dynamic branch", escArrow + strings.Replace(renderFn(safeLoop), `"#b9c3dc"`, "s.color", 1), true},
		{"helper escapes < > & but not quotes", strings.Replace(escArrow, `[&<>"']`, `[&<>]`, 1) + renderFn(safeLoop), true},
		{"lookup that falls back to the match", strings.Replace(escArrow, "}[c])", "}[c] || c)", 1) + renderFn(safeLoop), true},
		{"helper that is not an escape", "const esc = (s) => String(s);\n" + renderFn(safeLoop), true},
		{"literals and properties of a literal constant", brand + "function head(el) {\n  el.innerHTML = '<b>' + BRAND.letter + '</b> ' + esc(BRAND.name);\n}\n" + escArrow, false},
		{"constant property written elsewhere", brand + "BRAND.name = location.hash;\nfunction head(el) {\n  el.innerHTML = '<b>' + BRAND.name + '</b>';\n}\n", true},
		{"constant property that is not a literal", "const BRAND = { name: window.name };\nfunction head(el) {\n  el.innerHTML = '<b>' + BRAND.name + '</b>';\n}\n", true},
		{"const shadowed inside a callback", escArrow + "const row = '<i>x</i>';\nfunction list(el, rows) {\n  rows.forEach((row) => { el.innerHTML = row; });\n}\n", true},
		{"plain dynamic value", "function show(el, msg) {\n  el.innerHTML = msg;\n}\n", true},
	}
	for _, c := range cases {
		sigs := runOn(t, codeAdapter{}, map[string]string{"ui.js": c.src})
		got := false
		for _, s := range sigs {
			if s.RuleID == "code.html-sink" {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("%s: fired=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsEntityEscape(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{`String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]))`, true},
		{`s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;")`, true},
		{`s.replace(/</g, "&lt;").replace(/>/g, "&gt;")`, false},
		{`s.replace(/[<>"']/g, "$&")`, false},
		{`s.replace(/[<>"']/g, (c) => ({ "<": "<" }[c]))`, false},
		{`s.replace(/[<-z]/g, "")`, false},
		{`s.replace(/[^a-z]/g, "")`, false},
		{`s.replace(/[<>"']/, "")`, false},
	}
	for _, c := range cases {
		if got := isEntityEscape(c.expr); got != c.want {
			t.Errorf("isEntityEscape(%s) = %v, want %v", c.expr, got, c.want)
		}
	}
}
