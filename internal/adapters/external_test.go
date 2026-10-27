package adapters

import (
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/model"
)

func TestSemgrepNormalizeMapsControlsAndStableIDs(t *testing.T) {
	raw := []byte(`{"results":[
	 {"check_id":"tmp.home.pensec-semgrep-rules.pensec-js-eval","path":"src/a.js","start":{"line":3},"end":{"line":3},
	  "extra":{"message":"eval","severity":"ERROR","lines":"eval(x)","metadata":{"cwe":"CWE-95: x","pensec-control":"D-001"}}},
	 {"check_id":"custom.rule","path":"src/b.js","start":{"line":1},"end":{"line":1},
	  "extra":{"message":"m","severity":"WARNING","lines":"y","metadata":{"cwe":["CWE-918: SSRF"]}}},
	 {"check_id":"bad.mapping","path":"src/c.js","start":{"line":1},"end":{"line":1},
	  "extra":{"message":"m","severity":"INFO","lines":"z","metadata":{"pensec-control":"R-001"}}}
	],"errors":[]}`)
	sigs, err := semgrep().(*externalTool).normalize(&Context{Root: "."}, raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ rule, control, cwe string }{
		{"semgrep.pensec-js-eval", "D-001", "CWE-95"},
		{"semgrep.rule", "D-006", "CWE-918"},
		{"semgrep.mapping", "D-006", ""},
	}
	for i, w := range want {
		s := sigs[i]
		if s.RuleID != w.rule || s.ControlID != w.control || s.CWE != w.cwe || s.Confidence != model.Hypothesis {
			t.Errorf("signal %d: got %s %s %s %s", i, s.RuleID, s.ControlID, s.CWE, s.Confidence)
		}
	}
}
