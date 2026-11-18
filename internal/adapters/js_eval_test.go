package adapters

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// The shapes of eval that were false positives on real applications (#509)
// are lowered; an eval of client input or of a value of unknown origin stays.
func TestJSEvalShapes(t *testing.T) {
	captcha := "const operators = ['*', '+', '-']\n" +
		"const first = Math.floor((Math.random() * 10) + 1)\n" +
		"const op = operators[Math.floor((Math.random() * 3))]\n" +
		"const expression = first.toString() + op + first.toString()\n" +
		"const answer = eval(expression).toString()\n"
	sigs := runOn(t, codeAdapter{}, map[string]string{
		"routes/captcha.js":     captcha,
		"web/menu.js":           "function f(tl, sw) {\n  eval(\"trigMenu('\" + tl + \"',\" + sw + \")\");\n}\n",
		"web/window.js":         "id = day.getTime();\neval(\"page\" + id + \" = window.open(url, '\" + id + \"');\");\n",
		"web/packed.js":         "var a=['" + strings.Repeat("x", 1200) + "'];eval(a[0]);\n",
		"routes/profile.js":     "function p(username) {\n  const code = username.substring(2);\n  return eval(code);\n}\n",
		"routes/ajax.js":        "http_request.onload = function() {\n  eval(http_request.responseText);\n}\n",
		"routes/spliced.js":     "function g(req) {\n  eval(\"run('\" + req.query.cmd + \"')\");\n}\n",
		"routes/param.js":       "function g(code) {\n  eval(code);\n}\n",
		"routes/captcha-ex.js":  "function g(expression) {\n  const answer = eval(expression)\n}\n",
		"routes/by-property.js": "function g(el) {\n  if (eval(el.moved)) { stop() }\n}\n",
	})
	sev := map[string]model.Severity{}
	for _, s := range sigs {
		if s.RuleID == "code.js-eval" {
			sev[s.File] = s.Severity
		}
	}
	want := map[string]model.Severity{
		"routes/captcha.js":     model.SevInfo,
		"web/menu.js":           model.SevLow,
		"web/window.js":         model.SevLow,
		"routes/profile.js":     model.SevHigh,
		"routes/ajax.js":        model.SevHigh,
		"routes/spliced.js":     model.SevHigh,
		"routes/param.js":       model.SevHigh,
		"routes/captcha-ex.js":  model.SevHigh,
		"routes/by-property.js": model.SevHigh,
	}
	for f, w := range want {
		if sev[f] != w {
			t.Errorf("%s: got %q, want %q", f, sev[f], w)
		}
	}
}

// A packed file is skipped by the line rule; the Semgrep result for it is
// listed as information.
func TestJSEvalPacked(t *testing.T) {
	lines := []string{"var a=['" + strings.Repeat("x", 1200) + "'];eval(a[0]);"}
	if d, _ := jsEvalDemoteAt("src/high.js", lines, 0); d == nil || d.Sev != "" {
		t.Errorf("a packed file must be lowered to information, got %v", d)
	}
}

// More shapes from round 1: a property only ever set to a safe value, a
// call built in a variable, a timer call named inside a string.
func TestJSEvalMoreShapes(t *testing.T) {
	sigs := runOn(t, codeAdapter{}, map[string]string{
		"web/prop.js":  "function a(g) { g.moved=true;g.count=g.count+1 }\nfunction b(g) {\n  if (eval(g.moved)) { stop() }\n}\n",
		"web/built.js": "function f(elo, x) {\n  var t = \"g.go = go(\" + elo + \",\"\n  eval(t + x + \")\")\n}\n",
		"web/text.js":  "function f(elo) {\n  var t = 'g.BM = setTimeout(\"BM1(' + elo + ','\n}\n",
		"web/set.js":   "function a(g, v) { g.moved = v }\nfunction b(g) {\n  if (eval(g.moved)) { stop() }\n}\n",
	})
	sev := map[string]model.Severity{}
	for _, s := range sigs {
		if s.RuleID == "code.js-eval" {
			sev[s.File] = s.Severity
		}
	}
	want := map[string]model.Severity{"web/prop.js": model.SevInfo, "web/built.js": model.SevLow, "web/text.js": model.SevInfo, "web/set.js": model.SevHigh}
	for f, w := range want {
		if sev[f] != w {
			t.Errorf("%s: got %q, want %q", f, sev[f], w)
		}
	}
}
