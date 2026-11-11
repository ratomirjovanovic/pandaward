package adapters

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/rules"
)

// Every pandaward-supersedes entry names a built-in rule. Java and Python
// rules replace built-in ones; in JavaScript and TypeScript only the SQL
// heuristics are replaced, by a taint rule: the line heuristics reported
// dynamic SQL built from constants on real code (#352), while for the other
// classes the JavaScript built-in rules find more real CVEs than the bundled
// ones (docs/BENCHMARKS.md).
func TestSupersedesNameBuiltinRules(t *testing.T) {
	builtin := map[string]bool{}
	for _, id := range RuleIDs() {
		builtin[id] = true
	}
	rs, err := rules.SemgrepRules()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rs {
		for _, b := range r.Metadata.Supersedes {
			n++
			if !builtin[b] {
				t.Errorf("%s supersedes %q, which is not a built-in rule", r.ID, b)
			}
			for _, l := range r.Languages {
				js := (l == "javascript" || l == "typescript") && strings.HasPrefix(b, "code.sql-")
				if l != "java" && l != "python" && !js {
					t.Errorf("%s supersedes %s in %s; only Java and Python bundled rules are measured to be better", r.ID, b, l)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no bundled rule supersedes a built-in rule")
	}
}

func TestSupersessionsBy(t *testing.T) {
	sup, err := LoadSupersessions()
	if err != nil {
		t.Fatal(err)
	}
	code := (codeAdapter{}).Name()
	for _, c := range []struct {
		sig  model.Signal
		lang string
		want string
	}{
		{model.Signal{RuleID: "code.sql-concat", Collector: code}, "java", "semgrep.pandaward-java-sql-injection"},
		{model.Signal{RuleID: "code.sql-concat", Collector: code}, "python", "semgrep.pandaward-py-sql-injection"},
		{model.Signal{RuleID: "code.py-shell", Collector: code}, "python", "semgrep.pandaward-py-shell"},
		// JavaScript SQL heuristics give way to the taint rule (#352); the
		// other JavaScript built-in rules stay.
		{model.Signal{RuleID: "code.sql-concat", Collector: code}, "javascript", "semgrep.pandaward-js-sql-injection"},
		{model.Signal{RuleID: "code.js-shell", Collector: code}, "javascript", ""},
		// A rule nothing lists, and a signal of another adapter, stay.
		{model.Signal{RuleID: "code.tls-verify-off", Collector: code}, "python", ""},
		{model.Signal{RuleID: "code.sql-concat", Collector: "semgrep"}, "java", ""},
	} {
		if got := sup.By(c.sig, c.lang); got != c.want {
			t.Errorf("By(%s, %s) = %q, want %q", c.sig.RuleID, c.lang, got, c.want)
		}
	}
}
