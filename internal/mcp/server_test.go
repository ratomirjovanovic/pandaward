package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/engine"
	"github.com/ratomirjovanovic/pensec/internal/testfixture"
)

func rpc(t *testing.T, s *Server, msgs ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(msgs, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var res []map[string]any
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		res = append(res, m)
	}
	return res
}

func TestProtocol(t *testing.T) {
	root := t.TempDir()
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	s := &Server{Root: root}
	res := rpc(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pensec_get_status","arguments":{"extra":"x"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pensec_get_evidence","arguments":{"evidence_id":"../../etc/passwd"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"pensec_request_active_test","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"pensec_scan_passive","arguments":{}}}`,
		`not json`,
	)
	if len(res) != 7 {
		t.Fatalf("expected 7 responses (notification gets none), got %d", len(res))
	}
	tools := res[1]["result"].(map[string]any)["tools"].([]any)
	for _, tl := range tools {
		name := tl.(map[string]any)["name"].(string)
		if strings.Contains(name, "approve") || strings.Contains(name, "confirm") {
			t.Errorf("MCP must not expose %s", name)
		}
	}
	for _, i := range []int{2, 3} {
		if res[i]["result"].(map[string]any)["isError"] != true {
			t.Errorf("response %d should be a tool error: %v", i, res[i])
		}
	}
	txt := res[4]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(txt, `"executed":false`) {
		t.Errorf("active test request must not execute: %s", txt)
	}
	if res[5]["result"].(map[string]any)["isError"] == true {
		t.Errorf("passive scan failed: %v", res[5])
	}
	if res[6]["error"] == nil {
		t.Errorf("parse error expected")
	}
}

func TestRetestTool(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	s := &Server{Root: root}
	call := func(id int, args string) map[string]any {
		t.Helper()
		res := rpc(t, s, `{"jsonrpc":"2.0","id":`+fmt.Sprint(id)+`,"method":"tools/call","params":{"name":"pensec_retest","arguments":`+args+`}}`)
		return res[0]["result"].(map[string]any)
	}
	if r := call(1, `{"changed_only":"yes"}`); r["isError"] != true {
		t.Fatalf("non-boolean changed_only must be rejected: %v", r)
	}
	if r := call(2, `{"other":true}`); r["isError"] != true {
		t.Fatalf("unknown arguments must be rejected: %v", r)
	}
	if r := call(3, `{}`); r["isError"] == true {
		t.Fatalf("first retest (full scan fallback) failed: %v", r)
	}
	testfixture.Write(t, root, "Dockerfile", "FROM node:20.11.1\nUSER node\n")
	r := call(4, `{}`)
	var resp struct {
		Result struct {
			Changed []string `json:"changed_files"`
			Scan    struct {
				Runs []struct {
					Adapter   string `json:"adapter"`
					ExitClass string `json:"exit_class"`
				} `json:"runs"`
			} `json:"scan"`
		} `json:"result"`
	}
	txt := r["content"].([]any)[0].(map[string]any)["text"].(string)
	if err := json.Unmarshal([]byte(txt), &resp); err != nil {
		t.Fatal(err, txt)
	}
	out := resp.Result
	runs := map[string]string{}
	for _, x := range out.Scan.Runs {
		runs[x.Adapter] = x.ExitClass
	}
	if len(out.Changed) != 1 || out.Changed[0] != "Dockerfile" || runs["builtin-infra"] != "OK" || runs["builtin-code"] != "CARRIED" {
		t.Fatalf("targeted retest over MCP: changed=%v runs=%v", out.Changed, runs)
	}
	for _, tl := range tools() {
		if tl.Name == "pensec_retest" && tl.Annotations["readOnlyHint"] != false {
			t.Fatal("pensec_retest writes to the ledger and must not be marked read-only")
		}
	}
}
