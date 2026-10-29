package hooks

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/progress"
)

func TestReviewerProgressHooks(t *testing.T) {
	root := t.TempDir()
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	t.Setenv("CLAUDE_PROJECT_DIR", root)

	hook := func(name string, in map[string]any) {
		t.Helper()
		b, _ := json.Marshal(in)
		var out bytes.Buffer
		if code := Run(name, bytes.NewReader(b), &out); code != 0 || out.Len() != 0 {
			t.Fatalf("%s: exit %d, output %q", name, code, out.String())
		}
	}
	api := map[string]any{"agent_id": "a1", "agent_type": "pandaward:api"}
	with := func(m map[string]any, kv ...any) map[string]any {
		out := map[string]any{}
		for k, v := range m {
			out[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}

	hook("subagent-start", api)
	hook("reviewer-tool", with(api, "tool_name", "Read", "tool_input", map[string]any{"file_path": filepath.Join(root, "src", "server.js")}))
	hook("reviewer-tool", with(api, "tool_name", "Grep", "tool_input", map[string]any{"pattern": "verify(Signature|Webhook)", "path": filepath.Join(root, "src")}))
	hook("reviewer-tool", with(api, "tool_name", "mcp__plugin_pandaward_pandaward__pandaward_record_hypothesis",
		"tool_input", map[string]any{"title": "Webhook without signature check"},
		"tool_response", []any{map[string]any{"type": "text", "text": `{"finding_id":"PW-0042","confidence":"HYPOTHESIS"}`}}))
	// Not tracked: other tools, other agents and the main session.
	hook("reviewer-tool", with(api, "tool_name", "mcp__plugin_pandaward_pandaward__pandaward_get_status"))
	hook("reviewer-tool", map[string]any{"agent_id": "x", "agent_type": "Explore", "tool_name": "Read", "tool_input": map[string]any{"file_path": "a.go"}})
	hook("reviewer-tool", map[string]any{"tool_name": "Read", "tool_input": map[string]any{"file_path": "a.go"}})
	hook("subagent-start", map[string]any{"agent_id": "x", "agent_type": "general-purpose"})
	hook("subagent-stop", api)

	evs, err := progress.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 5 {
		t.Fatalf("events = %+v, want 5", evs)
	}
	if evs[1].Target != "src/server.js" || evs[2].Target != "verify(Signature|Webhook) in src" {
		t.Errorf("targets = %q, %q", evs[1].Target, evs[2].Target)
	}
	if evs[3].Kind != progress.KindHypothesis || evs[3].Finding != "PW-0042" || evs[3].Title != "Webhook without signature check" {
		t.Errorf("hypothesis event = %+v", evs[3])
	}
	r := progress.Fold(evs)[0]
	if !r.Done || r.Reads != 1 || r.Searches != 1 || strings.Join(r.Hypotheses, ",") != "PW-0042" {
		t.Errorf("reviewer = %+v", r)
	}
}

func TestReviewerProgressNeedsAProject(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLAUDE_PROJECT_DIR", dir)
	b, _ := json.Marshal(map[string]any{"agent_id": "a1", "agent_type": "pandaward:api"})
	if code := Run("subagent-start", bytes.NewReader(b), &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if evs, _ := progress.Load(dir); len(evs) != 0 {
		t.Fatalf("wrote progress outside an initialized project: %+v", evs)
	}
}
