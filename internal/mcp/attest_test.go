package mcp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// Agents may propose an attestation; nothing in MCP can accept, reject or
// otherwise decide one.
func TestNoAttestationDecisionTool(t *testing.T) {
	found := false
	for _, tl := range tools() {
		n := strings.ToLower(tl.Name + " " + fmt.Sprint(tl.InputSchema))
		for _, bad := range []string{"accept", "reject", "decide", "approve"} {
			if strings.Contains(strings.ToLower(tl.Name), bad) {
				t.Errorf("MCP must not expose %s", tl.Name)
			}
		}
		if tl.Name == "pandaward_propose_attestation" {
			found = true
			props := tl.InputSchema["properties"].(map[string]any)
			for _, k := range []string{"accept", "decided_by", "status", "by"} {
				if _, ok := props[k]; ok {
					t.Errorf("the proposal tool must not take %q", k)
				}
			}
			if !strings.Contains(n, "evidence") {
				t.Errorf("the proposal tool must require evidence: %v", tl.InputSchema)
			}
		}
	}
	if !found {
		t.Fatal("pandaward_propose_attestation is missing")
	}
}

func TestProposeAttestationTool(t *testing.T) {
	root := t.TempDir()
	testfixture.Write(t, root, "src/auth.js", "function requireOwner(req, res, next) {\n  if (req.order.userId !== req.user.id) return res.sendStatus(403);\n  next();\n}\n")
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	s := &Server{Root: root}
	call := func(id int, name, args string) map[string]any {
		t.Helper()
		res := rpc(t, s, `{"jsonrpc":"2.0","id":`+fmt.Sprint(id)+`,"method":"tools/call","params":{"name":"`+name+`","arguments":`+args+`}}`)
		return res[0]["result"].(map[string]any)
	}
	text := func(r map[string]any) string { return r["content"].([]any)[0].(map[string]any)["text"].(string) }
	for i, bad := range []string{
		`{"control_id":"C-003","verdict":"PASS","evidence":[]}`,
		`{"control_id":"C-003","verdict":"PASS"}`,
		`{"control_id":"C-003","verdict":"PASS","evidence":[{"file":"../x.js","line":1,"why":"x"}]}`,
		`{"control_id":"D-001","verdict":"PASS","evidence":[{"file":"src/auth.js","line":2,"why":"x"}]}`,
		`{"control_id":"C-003","verdict":"PASS","evidence":[{"file":"src/auth.js","line":2,"why":"x"}],"status":"accepted"}`,
	} {
		if r := call(i+1, "pandaward_propose_attestation", bad); r["isError"] != true {
			t.Errorf("%s must be rejected: %v", bad, r)
		}
	}
	r := call(10, "pandaward_propose_attestation", `{"control_id":"C-003","verdict":"PASS","proposer":"pandaward:identity","evidence":[{"file":"src/auth.js","line":2,"why":"owner check returns 403"}]}`)
	if r["isError"] == true || !strings.Contains(text(r), `"status":"pending"`) || !strings.Contains(text(r), `"decided":false`) {
		t.Fatalf("proposal: %v", r)
	}
	if st := text(call(11, "pandaward_get_status", `{}`)); !strings.Contains(st, `"pending_attestations":[{`) {
		t.Errorf("status must list the pending proposal: %s", st)
	}
}
