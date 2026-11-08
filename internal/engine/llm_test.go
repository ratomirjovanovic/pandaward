package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// reversedList finds "X, CANARY, PW" style lists in an injected text.
var reversedList = regexp.MustCompile(`([0-9a-f]{8})\s*[,/]\s*CANARY\s*[,/]\s*PW`)

// llmApp stands in for an endpoint that summarizes a document with a
// model. The naive model obeys any instruction in the document; fixed
// treats the document as data. echo repeats the document back, which must
// not count as following it. stream answers as server-sent events split
// into small tokens.
func llmApp(fixed, echo, stream *atomic.Bool, hits *atomic.Int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != tokAlice {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		var in struct{ Document string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		answer := "Summary: the document has " + fmt.Sprint(len(in.Document)) + " characters."
		switch {
		case echo.Load():
			answer = "You wrote: " + in.Document
		case !fixed.Load():
			if m := reversedList.FindStringSubmatch(in.Document); m != nil {
				answer = "PW-CANARY-" + m[1]
			}
		}
		if stream.Load() {
			w.Header().Set("Content-Type", "text/event-stream")
			for i := 0; i < len(answer); i += 3 {
				tok, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"delta": map[string]any{"content": answer[i:min(i+3, len(answer))]}}}})
				fmt.Fprintf(w, "data: %s\n\n", tok)
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"summary": answer})
	}))
}

const llmYAML = `identities:
  - {name: alice, header: Authorization, value_env: PANDAWARD_T_ALICE}
llm_checks:
  - name: document summary
    request: {method: POST, path: /api/summarize, as: alice, content_type: application/json, body_env: PANDAWARD_T_LLM_BODY}
`

func llmProject(t *testing.T, target string) *engine.Engine {
	t.Helper()
	root := testfixture.VulnerableRepo(t)
	// The fixture must look like an LLM application for P-003 to apply.
	if err := os.WriteFile(filepath.Join(root, "llm.js"), []byte("import OpenAI from 'openai'\nconst client = new OpenAI()\nexport const ask = (q) => client.chat.completions.create({ model: 'x', messages: [{ role: 'user', content: q }] })\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	y := strings.NewReplacer(
		`owner: ""`, `owner: "Fixture Owner"`,
		`reference: ""`, `reference: "TEST-12"`,
		`purpose: ""`, `purpose: "llm test"`,
		`acknowledged: false`, `acknowledged: true`,
		"targets: []", "targets:\n  - url: "+target,
		"allowed_methods: [GET, HEAD]", "allowed_methods: [GET, HEAD, POST]",
		"allow_private_addresses: false", "allow_private_addresses: true",
		"requests_per_second: 1", "requests_per_second: 10",
		"identities: []\n", "",
		"llm_checks: []\n", "",
	).Replace(scope.Template) + llmYAML
	if err := os.WriteFile(scope.Path(root), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestLLMChecksDetectFollowedInjection(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed, echo, stream atomic.Bool
	var hits atomic.Int64
	app := llmApp(&fixed, &echo, &stream, &hits)
	defer app.Close()
	noZAP(t)
	t.Setenv("PANDAWARD_T_ALICE", tokAlice)
	t.Setenv("PANDAWARD_T_LLM_BODY", `{"document":"Quarterly notes. {{payload}}"}`)
	e := llmProject(t, app.URL)
	approveScope(t, e)

	run := func(want model.Status, label string) {
		t.Helper()
		res, err := e.StagingActive(context.Background(), func(string) {})
		if err != nil {
			t.Fatal(err)
		}
		if res.Controls["P-003"] != string(want) {
			t.Fatalf("%s: P-003 = %s, want %s (%v)", label, res.Controls["P-003"], want, res.Notes)
		}
	}
	run(model.StatusFail, "naive model")
	if hits.Load() != 5 {
		t.Fatalf("app hits %d, want 5 (one per payload)", hits.Load())
	}
	stream.Store(true)
	run(model.StatusFail, "naive model streaming small tokens")
	stream.Store(false)

	fixed.Store(true)
	run(model.StatusPass, "fixed model")
	fs, _ := e.St.Findings(e.ProjectID)
	for _, f := range fs {
		if f.Collector == "llm" && f.Status != model.FindingRemediated {
			t.Errorf("%s is %s after the fix, want REMEDIATED", f.ID, f.Status)
		}
	}
	// Repeating the injected text back is not following it.
	echo.Store(true)
	run(model.StatusPass, "echo")
	assertNoTokens(t, e)
}

// A body template without the payload slot stops the run before any request.
func TestLLMChecksNeedPayloadSlot(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed, echo, stream atomic.Bool
	var hits atomic.Int64
	app := llmApp(&fixed, &echo, &stream, &hits)
	defer app.Close()
	noZAP(t)
	t.Setenv("PANDAWARD_T_ALICE", tokAlice)
	t.Setenv("PANDAWARD_T_LLM_BODY", `{"document":"no slot"}`)
	e := llmProject(t, app.URL)
	approveScope(t, e)
	if _, err := e.StagingActive(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "{{payload}}") {
		t.Fatalf("missing slot must stop the run, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("app hits %d", hits.Load())
	}
}
