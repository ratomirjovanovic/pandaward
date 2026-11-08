package adapters

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// Rules matched inside Go string literals: a regexp pattern is dropped,
// other strings are info, and Go code outside strings keeps its severity.
func TestCodeRulesInGoStringLiterals(t *testing.T) {
	src := "package x\n\n" +
		"import (\n\t\"crypto/tls\"\n\t\"regexp\"\n)\n\n" +
		"var tlsOff = regexp.MustCompile(`InsecureSkipVerify\\s*:\\s*true|rejectUnauthorized\\s*:\\s*false`)\n" +
		"var sample = \"jwt.verify(t, k, { algorithms: ['none'] })\"\n" +
		"var page = `<script>\n" +
		"el.innerHTML = location.hash\n" +
		"</script>`\n" +
		"var cfg = &tls.Config{InsecureSkipVerify: true}\n"
	sigs := runOn(t, codeAdapter{}, map[string]string{"x/x.go": src})
	byLine := map[int]model.Signal{}
	for _, s := range sigs {
		byLine[s.StartLine] = s
	}
	if s, ok := byLine[8]; ok {
		t.Errorf("regexp pattern must not fire, got %s", s.RuleID)
	}
	for _, line := range []int{9, 11} {
		s, ok := byLine[line]
		if !ok {
			t.Errorf("line %d: a pattern inside a string literal must stay listed", line)
			continue
		}
		if s.Severity != model.SevInfo {
			t.Errorf("line %d: %s is %s, want info", line, s.RuleID, s.Severity)
		}
	}
	if s, ok := byLine[13]; !ok || s.RuleID != "code.tls-verify-off" || s.Severity != model.SevHigh {
		t.Errorf("Go code outside a string must keep its finding, got %+v", s)
	}
}

func TestScanGoLiteralsSurvivesBrokenSource(t *testing.T) {
	src := "package x\nfunc ( {\nvar s = \"a.innerHTML = b\"\n"
	g := scanGoLiterals(src)
	at := strings.Index(src, "innerHTML")
	if len(g.spans) != 1 || g.verdict(at, at+len("innerHTML")) != "string" || g.verdict(0, 7) != "" {
		t.Fatalf("spans %v", g.spans)
	}
}

// A match that runs from one string argument into the next is still data,
// but not when code sits between the strings.
func TestGoLiteralsAcrossArguments(t *testing.T) {
	src := "package x\nvar a = f(\"pass-word\", \"md5(x)\")\nvar b = g(\"password\") + md5(x)\n"
	g := scanGoLiterals(src)
	s, e := strings.Index(src, "pass-word"), strings.Index(src, "md5(x)\")")+len("md5(x)")
	if v := g.verdict(s, e); v != "string" {
		t.Errorf("across string arguments: %q", v)
	}
	s, e = strings.Index(src, "password\")"), strings.LastIndex(src, "md5(x)")+len("md5(x)")
	if v := g.verdict(s, e); v != "" {
		t.Errorf("string then code: %q", v)
	}
}
