package adapters

import (
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// #470: a Python line whose eval, exec or shell match lies wholly in a string
// literal or a docstring is listed as information; a match in code, or in an
// f-string replacement field, keeps its severity.
func TestPythonTextMatchesDemotion(t *testing.T) {
	cases := []struct {
		name, src string
		rule      string
		text      bool
	}{
		{"pattern table", "PATTERNS = [\n    (r\"eval\\s*\\(\", \"eval() usage\", \"critical\"),\n]\n", "code.py-eval", true},
		{"docstring one line", "def f():\n    \"\"\"Safely evaluate AST node without using eval().\"\"\"\n    return 1\n", "code.py-eval", true},
		{"docstring block", "def f():\n    \"\"\"\n    Run the thing.\n    Never call eval(x) on input.\n    \"\"\"\n    return 1\n", "code.py-eval", true},
		{"error message shell", "raise ValueError(\"shell=True is no longer supported for security reasons\")\n", "code.py-shell", true},
		{"message names os.system", "msg = 'os.system() call detected'\n", "code.py-shell", true},
		{"comment", "x = 1  # exec(code) would be unsafe\n", "code.py-eval", true},
		{"real eval", "result = eval(user_text)\n", "code.py-eval", false},
		{"real exec after string", "msg = 'run'; exec(code)\n", "code.py-eval", false},
		{"eval in f-string field", "x = f\"value {eval(user_text)}\"\n", "code.py-eval", false},
		{"real shell", "subprocess.run(cmd, shell=True)\n", "code.py-shell", false},
		{"real os.system", "os.system(cmd)\n", "code.py-shell", false},
		{"code after a docstring", "def f():\n    \"\"\"Doc.\"\"\"\n    return eval(x)\n", "code.py-eval", false},
		{"code after a block docstring", "def f():\n    \"\"\"\n    text\n    \"\"\"\n    os.system(cmd)\n", "code.py-shell", false},
	}
	for _, c := range cases {
		sigs := runOn(t, codeAdapter{}, map[string]string{"src/a.py": c.src})
		var got model.Severity
		seen := false
		for _, s := range sigs {
			if s.RuleID == c.rule {
				got, seen = s.Severity, true
			}
		}
		if !seen {
			// A comment line is skipped before the rules run: that is also
			// not a finding.
			if c.name != "comment" {
				t.Errorf("%s: no %s signal", c.name, c.rule)
			}
			continue
		}
		if c.text && got != model.SevInfo {
			t.Errorf("%s: want information, got %q", c.name, got)
		}
		if !c.text && got != model.SevHigh {
			t.Errorf("%s: want high, got %q", c.name, got)
		}
	}
}
