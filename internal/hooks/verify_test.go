package hooks

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

func stopWith(t *testing.T, message string, active bool) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"last_assistant_message": message, "stop_hook_active": active})
	return runHook(t, "stop", string(b))
}

// The Stop hook hands a PASS the ledger does not support back to Claude.
func TestStopBlocksFalseAssurance(t *testing.T) {
	assessed(t, true)
	out := stopWith(t, "Review done.\nE-001: PASS\nAll good.", false)
	var o struct{ Decision, Reason string }
	if err := json.Unmarshal([]byte(out), &o); err != nil || o.Decision != "block" {
		t.Fatalf("a false PASS must be blocked, got %q", out)
	}
	for _, want := range []string{"false assurance", "E-001 unsupported_pass", "Do not change finding dispositions"} {
		if !strings.Contains(o.Reason, want) {
			t.Errorf("reason lacks %q: %s", want, o.Reason)
		}
	}
	if o := stopWith(t, "Everything is secure and all controls passed.", false); !strings.Contains(o, `"decision":"block"`) || !strings.Contains(o, "blanket") {
		t.Fatalf("an all-clear claim must be blocked: %q", o)
	}
}

// blockedControl returns a control the ledger has as BLOCKED.
func blockedControl(t *testing.T, root string) string {
	t.Helper()
	e, err := engine.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil || a == nil {
		t.Fatal("no assessment")
	}
	cs, err := e.St.Controls(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Status == model.StatusBlocked {
			return c.ID
		}
	}
	t.Skip("the fixture has no BLOCKED control")
	return ""
}

func TestStopAllowsHonestAndCautiousReports(t *testing.T) {
	root := assessed(t, true)
	blocked := blockedControl(t, root)
	for _, msg := range []string{
		"E-001: FAIL, a token is committed.",
		"I fixed the typo in the readme.",
		"E-001: FAIL\n" + blocked + ": INCONCLUSIVE, I could not decide it.", // undecided is undecided
		"E-001: FAIL\n" + blocked + ": FAIL, I think this one fails too.",    // more careful than the ledger
		"",
	} {
		if out := stopWith(t, msg, false); out != "" {
			t.Errorf("%q must not be blocked, got %q", msg, out)
		}
	}
}

func TestStopDoesNotLoopOrRunWhenSwitchedOff(t *testing.T) {
	root := assessed(t, true)
	// Claude is already continuing because of a Stop hook: let it finish.
	if out := stopWith(t, "E-001: PASS", true); out != "" {
		t.Fatalf("stop_hook_active must end the loop, got %q", out)
	}
	cfg, _, err := config.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Hooks.VerifyReport = false
	if err := config.Write(root, cfg, true); err != nil {
		t.Fatal(err)
	}
	if out := stopWith(t, "E-001: PASS", false); out != "" {
		t.Fatalf("hooks.verify_report: false must switch it off, got %q", out)
	}
}

func TestStopWithoutAnAssessmentIsSilent(t *testing.T) {
	t.Setenv("CLAUDE_PROJECT_DIR", t.TempDir())
	if out := stopWith(t, "E-001: PASS", false); out != "" {
		t.Fatalf("no ledger, nothing to check against: %q", out)
	}
}
