package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// Inputs of the flow fixture. They must never appear in the ledger,
// evidence or reports.
const (
	bodyBadLogin = `{"email":"alice@example.test","password":"wrong-pw-5c1e"}`
	bodyReset    = `{"token":"reset-tok-93fa0b","password":"new-pw-77de"}`
	headerOTP    = "otp-000000-skip"
)

// authApp accepts any password and lets a reset token be used twice;
// fixed makes both refuse.
func authApp(fixed *atomic.Bool, hits *atomic.Int64) *httptest.Server {
	var mu sync.Mutex
	used := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var in struct{ Email, Password string }
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if fixed.Load() && in.Password != "right-pw" {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"session":"s1"}`)
	})
	mux.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var in struct{ Token string }
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if fixed.Load() && used[in.Token] {
			http.Error(w, "token already used", http.StatusGone)
			return
		}
		used[in.Token] = true
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/api/mfa", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("X-OTP") != "123456" {
			http.Error(w, "wrong code", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})
	return httptest.NewServer(mux)
}

const flowYAML = `flow_checks:
  - name: wrong password refused
    control: B-003
    steps:
      - {method: POST, path: /api/login, content_type: application/json, body_env: PANDAWARD_T_BAD_LOGIN, expect: denied}
  - name: reset token works once
    control: B-003
    steps:
      - {method: POST, path: /api/reset, body_env: PANDAWARD_T_RESET, expect: allowed}
      - {method: POST, path: /api/reset, body_env: PANDAWARD_T_RESET, expect: denied}
  - name: wrong otp refused
    control: B-003
    steps:
      - {method: POST, path: /api/mfa, header_env: {X-OTP: PANDAWARD_T_OTP}, expect: denied}
`

func flowProject(t *testing.T, target string) *engine.Engine {
	t.Helper()
	root := testfixture.VulnerableRepo(t)
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
		`purpose: ""`, `purpose: "flow test"`,
		`acknowledged: false`, `acknowledged: true`,
		"targets: []", "targets:\n  - url: "+target,
		"allowed_methods: [GET, HEAD]", "allowed_methods: [GET, HEAD, POST]",
		"allow_private_addresses: false", "allow_private_addresses: true",
		"requests_per_second: 1", "requests_per_second: 10",
		"flow_checks: []\n", "",
	).Replace(scope.Template) + flowYAML
	if err := os.WriteFile(scope.Path(root), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func setFlowInputs(t *testing.T) {
	t.Setenv("PANDAWARD_T_BAD_LOGIN", bodyBadLogin)
	t.Setenv("PANDAWARD_T_RESET", bodyReset)
	t.Setenv("PANDAWARD_T_OTP", headerOTP)
}

func TestFlowChecksFailAcceptedNegativeCasesAndPassWhenFixed(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	var hits atomic.Int64
	app := authApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	setFlowInputs(t)
	e := flowProject(t, app.URL)
	approveScope(t, e)

	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["B-003"] != string(model.StatusFail) {
		t.Fatalf("B-003 = %s, want FAIL (%v)", res.Controls["B-003"], res.Notes)
	}
	if hits.Load() != 4 {
		t.Fatalf("app hits %d, want 4", hits.Load())
	}
	fs, _ := e.St.Findings(e.ProjectID)
	var got []string
	for _, f := range fs {
		if f.Collector == "flow" {
			got = append(got, f.RuleID+" "+f.File[strings.LastIndex(f.File, "/api/"):])
		}
	}
	sort.Strings(got)
	// The wrong password and the reused token are accepted; the wrong OTP is refused.
	if fmt.Sprint(got) != "[flow.negative-case-accepted /api/login flow.negative-case-accepted /api/reset]" {
		t.Fatalf("flow findings %v", got)
	}
	assertNoInputs(t, e)

	// A reset token works once, so the next run gets a fresh one, as an
	// identity_provisioning command would hand out.
	fixed.Store(true)
	t.Setenv("PANDAWARD_T_RESET", strings.Replace(bodyReset, "reset-tok-93fa0b", "reset-tok-1d2c3b", 1))
	res, err = e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["B-003"] != string(model.StatusPass) {
		t.Fatalf("fixed: B-003 = %s, want PASS (%v)", res.Controls["B-003"], res.Notes)
	}
	fs, _ = e.St.Findings(e.ProjectID)
	for _, f := range fs {
		if f.Collector == "flow" && f.Status != model.FindingRemediated {
			t.Errorf("%s is %s after the fix, want REMEDIATED", f.ID, f.Status)
		}
	}
	assertNoInputs(t, e)
}

// A missing input stops the run before any request.
func TestFlowChecksNeedInputsBeforeAnyRequest(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	var hits atomic.Int64
	app := authApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	setFlowInputs(t)
	t.Setenv("PANDAWARD_T_RESET", "")
	e := flowProject(t, app.URL)
	approveScope(t, e)
	if _, err := e.StagingActive(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "PANDAWARD_T_RESET") {
		t.Fatalf("missing input must stop the run, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("app hits %d before the inputs were complete", hits.Load())
	}
}

func assertNoInputs(t *testing.T, e *engine.Engine) {
	t.Helper()
	assertNoTokens(t, e)
	err := filepath.Walk(filepath.Join(e.Root, ".pandaward"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.HasSuffix(p, "scope.yaml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, v := range []string{"wrong-pw-5c1e", "reset-tok-93fa0b", "reset-tok-1d2c3b", "new-pw-77de", headerOTP} {
			if strings.Contains(string(b), v) {
				t.Errorf("input %q found in %s", v, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
