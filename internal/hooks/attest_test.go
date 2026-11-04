package hooks

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func TestAttestDecisionAsksTheHuman(t *testing.T) {
	cmd := func(c string) json.RawMessage { b, _ := json.Marshal(map[string]string{"command": c}); return b }
	for c, want := range map[string]string{
		`pandaward attest C-003 --accept --by Ana`:                               "ask",
		`pandaward attest C-003 --by Ana --note "reviewed" --accept`:             "ask",
		`pandaward attest C-003 --reject --by Ana --note "admin routes missing"`: "ask",
		`pandaward attest C-003 -accept=true -by Ana`:                            "ask",
		`& "C:\pandaward\bin\pandaward.exe" attest A-004 --accept --by Ana`:      "ask",
		`"${CLAUDE_PLUGIN_ROOT}/bin/pandaward" attest O-001 --reject --by Ana`:   "ask",
		`pandaward attest --list`:                                                "",
		`pandaward attest C-003 --show`:                                          "",
		`pandaward attest C-003 --propose --file /tmp/p.json`:                    "",
	} {
		tool := "Bash"
		if strings.HasPrefix(c, "&") {
			tool = "PowerShell"
		}
		if got, _ := GuardDecision(tool, cmd(c)); got != want {
			t.Errorf("%s: got %q want %q", c, got, want)
		}
	}
}

func TestAttestPromptShowsTheProposal(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/auth.js", "function requireOwner(req, res, next) {\n  if (req.order.userId !== req.user.id) return res.sendStatus(403);\n  next();\n}\n")
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ProposeAttestation(engine.AttestationInput{ControlID: "C-003", Verdict: "PASS", Proposer: "pandaward:identity",
		Evidence: []engine.CitationInput{{File: "src/auth.js", Line: 2, Why: "owner check returns 403"}}}); err != nil {
		t.Fatal(err)
	}
	e.Close()
	t.Setenv("CLAUDE_PROJECT_DIR", root)
	b, _ := json.Marshal(map[string]any{"cwd": root, "tool_name": "Bash", "tool_input": map[string]string{"command": `pandaward attest C-003 --accept --by Ana`}})
	var out bytes.Buffer
	Run("pre-tool", bytes.NewReader(b), &out)
	var d decision
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	r := d.HookSpecificOutput.PermissionDecisionReason
	if d.HookSpecificOutput.PermissionDecision != "ask" || !strings.Contains(r, "C-003 PASS, proposed by pandaward:identity") || !strings.Contains(r, "src/auth.js:2 owner check returns 403") {
		t.Fatalf("the prompt must show the proposal and its evidence, got %+v", d)
	}
}
