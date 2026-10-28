package hooks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/engine"
)

func TestSessionStartIsHandsFree(t *testing.T) {
	root := t.TempDir()
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	t.Setenv("CLAUDE_PROJECT_DIR", root)
	var out bytes.Buffer
	Run("session-start", strings.NewReader(`{}`), &out)
	got := out.String()
	if !strings.Contains(got, "pensec:start") {
		t.Errorf("expected the guided assessment to be offered, got %q", got)
	}
	if strings.Contains(got, "Next: /pensec") {
		t.Errorf("hook must not ask the user to type a command, got %q", got)
	}
}

func TestGuardDecision(t *testing.T) {
	cmd := func(c string) json.RawMessage { b, _ := json.Marshal(map[string]string{"command": c}); return b }
	file := func(p string) json.RawMessage { b, _ := json.Marshal(map[string]string{"file_path": p}); return b }
	cases := []struct {
		tool  string
		input json.RawMessage
		want  string
	}{
		{"Bash", cmd(`pensec scope approve --by me`), "ask"},
		{"Bash", cmd(`./bin/pensec.exe test --profile production-observe`), "ask"},
		{"Bash", cmd(`pensec findings false-positive PSEC-0001 --by x --note y`), "ask"},
		{"Bash", cmd(`sqlite3 .pensec/private/state.db "update findings set status='REMEDIATED'"`), "ask"},
		{"Bash", cmd(`echo "acknowledged: true" >> .pensec/scope.yaml`), "ask"},
		{"Bash", cmd(`cat .pensec/scope.yaml`), ""},
		{"Bash", cmd(`pensec scan --json`), ""},
		{"Bash", cmd(`pensec findings list`), ""},
		{"Bash", cmd(`pensec findings apply --file /tmp/d.json --by me`), "ask"},
		{"PowerShell", cmd(`& "C:\pensec\bin\pensec.exe" findings apply --file d.json --by me`), "ask"},
		{"Write", file(`D:\proj\.pensec\private\state.db`), "deny"},
		{"Edit", file(`/proj/.pensec/scope.yaml`), "ask"},
		{"Edit", file(`/proj/src/app.ts`), ""},
	}
	for _, c := range cases {
		got, _ := GuardDecision(c.tool, c.input)
		if got != c.want {
			t.Errorf("%s %s: got %q want %q", c.tool, c.input, got, c.want)
		}
	}
}

func TestApplyPromptListsDecisions(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "d.json"), []byte(`[
		{"finding_id":"PSEC-0003","action":"confirm","note":"reachable"},
		{"finding_id":"PSEC-0007","action":"accept-risk","note":"internal only","expires":"2027-01-31"}]`), 0o644)
	b, _ := json.Marshal(map[string]any{"cwd": dir, "tool_name": "Bash", "tool_input": map[string]string{"command": `pensec findings apply --file "d.json" --by me`}})
	t.Setenv("CLAUDE_PROJECT_DIR", dir)
	var out bytes.Buffer
	Run("pre-tool", bytes.NewReader(b), &out)
	var d decision
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	r := d.HookSpecificOutput.PermissionDecisionReason
	if d.HookSpecificOutput.PermissionDecision != "ask" || !strings.Contains(r, "PSEC-0003 confirm: reachable") || !strings.Contains(r, "PSEC-0007 accept-risk: internal only (until 2027-01-31)") {
		t.Fatalf("the prompt must list every decision, got %+v", d)
	}
}
