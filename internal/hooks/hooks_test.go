package hooks

import (
	"bytes"
	"encoding/json"
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
