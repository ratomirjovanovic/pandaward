package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
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
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pandaward_get_status","arguments":{"extra":"x"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pandaward_get_evidence","arguments":{"evidence_id":"../../etc/passwd"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"pandaward_request_active_test","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"pandaward_scan_passive","arguments":{}}}`,
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
		res := rpc(t, s, `{"jsonrpc":"2.0","id":`+fmt.Sprint(id)+`,"method":"tools/call","params":{"name":"pandaward_retest","arguments":`+args+`}}`)
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
		if tl.Name == "pandaward_retest" && tl.Annotations["readOnlyHint"] != false {
			t.Fatal("pandaward_retest writes to the ledger and must not be marked read-only")
		}
	}
}

func TestListEntrypoints(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	s := &Server{Root: root}
	res := rpc(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pandaward_list_entrypoints","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pandaward_scan_passive","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pandaward_list_entrypoints","arguments":{"kind":"bogus"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pandaward_list_entrypoints","arguments":{"kind":"route"}}}`,
	)
	for _, i := range []int{0, 2} {
		if res[i]["result"].(map[string]any)["isError"] != true {
			t.Errorf("response %d must be an error (no assessment yet / unknown kind): %v", i, res[i])
		}
	}
	txt := res[3]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var out struct {
		Result struct {
			Total       int `json:"total"`
			Entrypoints []struct {
				Kind    string            `json:"kind"`
				Locator string            `json:"locator"`
				Line    int               `json:"line"`
				Meta    map[string]string `json:"meta"`
			} `json:"entrypoints"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(txt), &out); err != nil {
		t.Fatal(err, txt)
	}
	if out.Result.Total == 0 || out.Result.Total != len(out.Result.Entrypoints) {
		t.Fatalf("expected routes from the fixture: %s", txt)
	}
	for _, ep := range out.Result.Entrypoints {
		if ep.Kind != "route" || ep.Locator == "" || ep.Line == 0 || ep.Meta["path"] == "" {
			t.Errorf("entrypoint without kind filter, file or line: %+v", ep)
		}
	}
}

func TestPrepareFeedbackTool(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	fs, _ := e.St.Findings(e.ProjectID)
	e.Close()
	var id string
	for _, f := range fs {
		if f.File != "" && f.StartLine > 0 {
			id = f.ID
			break
		}
	}
	s := &Server{Root: root}
	call := func(n int, args string) map[string]any {
		t.Helper()
		res := rpc(t, s, `{"jsonrpc":"2.0","id":`+fmt.Sprint(n)+`,"method":"tools/call","params":{"name":"pandaward_prepare_feedback","arguments":`+args+`}}`)
		return res[0]["result"].(map[string]any)
	}
	for i, bad := range []string{`{}`, `{"kind":"other"}`, `{"kind":"false-positive","finding_id":"PW-9999"}`, `{"kind":"false-negative"}`, `{"kind":"false-positive","finding_id":"` + id + `","send":true}`} {
		if r := call(i+1, bad); r["isError"] != true {
			t.Errorf("%s must be rejected: %v", bad, r)
		}
	}
	r := call(10, `{"kind":"false-positive","finding_id":"`+id+`","note":"constant value"}`)
	txt := r["content"].([]any)[0].(map[string]any)["text"].(string)
	if r["isError"] == true || !strings.Contains(txt, `"sent":false`) || !strings.Contains(txt, "issues/new?") || !strings.Contains(txt, "existing_reports_url") {
		t.Fatalf("unexpected result: %s", txt)
	}
	for _, f := range fs {
		if f.ID == id && strings.Contains(txt, f.File) {
			t.Fatalf("default report must not contain the path %s", f.File)
		}
	}

	// A finding closed as a false positive becomes a pending report.
	e, err = engine.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Triage(id, "false-positive", "tester", "constant value", time.Time{}); err != nil {
		t.Fatal(err)
	}
	e.Close()
	res := rpc(t, s, `{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"pandaward_pending_feedback","arguments":{}}}`)[0]["result"].(map[string]any)
	txt = res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] == true || !strings.Contains(txt, `"sent":false`) || !strings.Contains(txt, id) || !strings.Contains(txt, `"kind":"false-positive"`) {
		t.Fatalf("pending feedback: %s", txt)
	}
}
