package flow

import (
	"strings"
	"testing"
)

// TestRegexFromInput checks that a pattern from input is reported, and a
// constant pattern or an escaped one is not.
func TestRegexFromInput(t *testing.T) {
	head := "import re\nfrom flask import request\n\ndef h():\n"
	for _, c := range []struct{ name, body, want string }{
		{"pattern from input", "    p = request.form['p']\n    return str(re.match(p, 'x'))\n", "regex-dos:6"},
		{"input as text", "    t = request.form['t']\n    return str(re.match('^a+$', t))\n", ""},
		{"escaped", "    p = request.form['p']\n    return str(re.match(re.escape(p), 'x'))\n", ""},
	} {
		if got := strings.Join(sinks(analyze(t, head+c.body)), " "); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
