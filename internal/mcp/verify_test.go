package mcp

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func TestVerifyReportTool(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Scan(context.Background(), nil); err != nil {
		e.Close()
		t.Fatal(err)
	}
	e.Close()
	s := &Server{Root: root}
	call := func(args string) (string, bool) {
		t.Helper()
		res := rpc(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pandaward_verify_report","arguments":`+args+`}}`)
		r := res[0]["result"].(map[string]any)
		return r["content"].([]any)[0].(map[string]any)["text"].(string), r["isError"] == true
	}
	if out, bad := call(`{"report":"E-001: PASS"}`); bad || !strings.Contains(out, `"unsupported":true`) || !strings.Contains(out, "unsupported_pass") {
		t.Fatalf("a false PASS must be reported: %v\n%s", bad, out)
	}
	if out, bad := call(`{"report":"E-001: FAIL, a token is committed."}`); bad || !strings.Contains(out, `"unsupported":false`) {
		t.Fatalf("an honest report verifies: %v\n%s", bad, out)
	}
	for i, args := range []string{`{}`, `{"report":""}`, `{"report":"x","extra":1}`, `{"report":"` + strings.Repeat("a", 200001) + `"}`} {
		if _, bad := call(args); !bad {
			t.Errorf("case %d must be an error", i)
		}
	}
	// The tool only reads: it is declared read-only.
	for _, tl := range tools() {
		if tl.Name == "pandaward_verify_report" {
			if fmt.Sprint(tl.Annotations) == "" {
				t.Error("annotations missing")
			}
			return
		}
	}
	t.Fatal("pandaward_verify_report is missing")
}
