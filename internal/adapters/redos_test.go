package adapters

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

func TestAnalyzeRegex(t *testing.T) {
	for _, c := range []struct {
		pattern, flags string
		want           redosKind
	}{
		// Exponential: a repetition whose body matches the same text in two
		// ways, with a way for the match to fail afterwards.
		{`^(a+)+$`, "", redosExponential},
		{`^(a*)*$`, "", redosExponential},
		{`^(a|a)*$`, "", redosExponential},
		{`^(.*,)+(.+)?$`, "", redosExponential},
		{`^(?:\.?[a-zA-Z_][a-zA-Z_0-9]*)+$`, "", redosExponential},
		{`"((?:\\[\x00-\x7f]|[^\x00-\x08\x0a-\x1f\x7f"])*)"`, "", redosExponential},
		{`^(\w+\s?)+$`, "", redosExponential},
		// Polynomial: two repetitions in a row over the same characters, or
		// one the unanchored search can start anywhere in.
		{`^\s+|\s+$`, "g", redosPolynomial},
		{` *, *`, "", redosPolynomial},
		{`.*[/\\]`, "", redosPolynomial},
		{`^(([^=;]+))\s*=\s*([^\n\r\0]*)`, "", redosPolynomial},
		{`^(\-|\+)?([1-9]+[0-9]*)$`, "", redosPolynomial},
		{`[A-Z]{2,}[a-z]`, "", redosPolynomial},
		{`^\s*(?:''|"")?\s*(?:,\s*(?:''|"")?\s*)*$`, "", redosPolynomial},
		// Linear: anchored, disjoint, or the match can always end.
		{`^[a-z]+$`, "", redosNone},
		{`\s+`, "g", redosNone},
		{`^(a+)+`, "", redosNone},
		{`^\d+\.\d+$`, "", redosNone},
		{`^[^\s@]+$`, "", redosNone},
		{`^(?:[a-z0-9-]+\.)+[a-z]{2,}$`, "i", redosNone},
		{`^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$`, "i", redosNone},
		{`^[\w.-]{1,64}$`, "", redosNone},
		{`^(\w+)\1$`, "", redosNone},
		{`^([^-]+)-([A-Za-z0-9+/=]{44,88})$`, "", redosNone},
		// Not understood: no finding.
		{`(?<x`, "", redosNone},
		{`a**`, "", redosNone},
	} {
		if got := analyzeRegex(c.pattern, c.flags); got.Kind != c.want {
			t.Errorf("/%s/%s = %d, want %d", c.pattern, c.flags, got.Kind, c.want)
		}
	}
}

func TestAnalyzeRegexFlags(t *testing.T) {
	// With i, [a-z] and [A-Z] overlap, so the second loop can take over
	// what the first matched.
	if got := analyzeRegex(`^[a-z]+[A-Z]+$`, ""); got.Kind != redosNone {
		t.Errorf("case-sensitive = %d", got.Kind)
	}
	if got := analyzeRegex(`^[a-z]+[A-Z]+$`, "i"); got.Kind != redosPolynomial {
		t.Errorf("case-insensitive = %d", got.Kind)
	}
	// A sticky regex does not search, so it has no implicit leading loop.
	if got := analyzeRegex(`\s+$`, "y"); got.Kind != redosNone {
		t.Errorf("sticky = %d", got.Kind)
	}
	// Without s a dot does not match a line break.
	if got := analyzeRegex(`^.*\n.*$`, ""); got.Kind != redosNone {
		t.Errorf("dot = %d", got.Kind)
	}
}

func TestJSRegexLiterals(t *testing.T) {
	src := "const a = x / y / z; // not /a+/ here\n" +
		"const b = /(a+)+$/i.test(s);\n" +
		"const c = new RegExp('^(\\\\d+)+$', 'g');\n" +
		"const d = \"/(a+)+$/\";\n" +
		"/* /(a+)+$/ */ if (s.match(/x*y/)) {}\n"
	got := jsRegexLiterals(src)
	want := []jsRegexLiteral{{`(a+)+$`, "i", 0}, {`^(\d+)+$`, "g", 0}, {`x*y`, "", 0}}
	if len(got) != len(want) {
		t.Fatalf("literals = %+v", got)
	}
	for i := range want {
		if got[i].Pattern != want[i].Pattern || got[i].Flags != want[i].Flags {
			t.Errorf("literal %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRedosSignals(t *testing.T) {
	text := "// header\n" +
		"const ok = /^[a-z]+$/;\n" +
		"const bad = /^(a+)+$/;\n" +
		"const trim = s => s.replace(/\\s+$/, '');\n"
	f := &inventory.File{Path: "lib/x.js", Lang: "javascript", Lines: strings.Split(text, "\n")}
	sigs := redosSignals(f, text, "builtin-code")
	if len(sigs) != 2 {
		t.Fatalf("signals = %+v", sigs)
	}
	if s := sigs[0]; s.StartLine != 3 || s.RuleID != "code.js-redos" || s.Severity != model.SevMedium || s.ControlID != "D-007" {
		t.Errorf("exponential = %+v", s)
	}
	if s := sigs[1]; s.StartLine != 4 || s.RuleID != "code.js-redos-polynomial" || s.Severity != model.SevInfo || !strings.Contains(s.Message, "whitespace") {
		t.Errorf("polynomial = %+v", s)
	}
}
