package engine_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pensec/internal/engine"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/report"
	"github.com/ratomirjovanovic/pensec/internal/scope"
	"github.com/ratomirjovanovic/pensec/internal/store"
	"github.com/ratomirjovanovic/pensec/internal/testfixture"
)

// Credentials of the fixture app. They must never appear in the ledger,
// evidence or reports.
const (
	tokAlice = "Bearer tok-alice-6b1f0c2e9d"
	tokBob   = "Bearer tok-bob-41c7aa09e3"
	tokCarol = "Bearer tok-carol-0d93e1b7f5"
	tokOld   = "Bearer tok-old-alice-77a2c9"
)

// invoiceApp is a small API with a seeded BOLA, a privileged route without
// a role check and a logout that does not revoke the token. fixed switches
// all three to correct behavior.
func invoiceApp(fixed *atomic.Bool, hits *atomic.Int64) *httptest.Server {
	type user struct{ name, tenant, role string }
	users := map[string]user{tokAlice: {"alice", "acme", "user"}, tokBob: {"bob", "beta", "user"}, tokCarol: {"carol", "acme", "admin"}, tokOld: {"alice", "acme", "user"}}
	revoked := map[string]bool{tokOld: true}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) (user, bool) {
		hits.Add(1)
		tok := r.Header.Get("Authorization")
		u, ok := users[tok]
		if !ok || (fixed.Load() && revoked[tok]) {
			http.Error(w, "login required", http.StatusUnauthorized)
			return user{}, false
		}
		return u, true
	}
	mux.HandleFunc("/api/invoices/inv_acme_1", func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth(w, r)
		if !ok {
			return
		}
		if fixed.Load() && u.tenant != "acme" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"id":"inv_acme_1","tenant":"acme","total":1200}`)
	})
	mux.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		u, ok := auth(w, r)
		if !ok {
			return
		}
		if fixed.Load() && u.role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `[{"name":"alice"},{"name":"bob"}]`)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "http://evil.example/login", http.StatusFound)
	})
	return httptest.NewServer(mux)
}

const authzYAML = `identities:
  - name: alice
    tenant: acme
    header: Authorization
    value_env: PENSEC_T_ALICE
  - name: bob
    tenant: beta
    header: Authorization
    value_env: PENSEC_T_BOB
  - name: carol
    tenant: acme
    header: Authorization
    value_env: PENSEC_T_CAROL
  - name: old-alice
    tenant: acme
    header: Authorization
    value_env: PENSEC_T_OLD
    revoked: true
authorization_checks:
  - name: acme invoice
    kind: object
    method: GET
    path: /api/invoices/inv_acme_1
    allowed: [alice, carol]
  - name: user admin
    kind: function
    method: GET
    path: /admin/users
    allowed: [carol]
`

func authzProject(t *testing.T, target string, extra string) *engine.Engine {
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
		`purpose: ""`, `purpose: "authorization test"`,
		`acknowledged: false`, `acknowledged: true`,
		"targets: []", "targets:\n  - url: "+target,
		"allow_private_addresses: false", "allow_private_addresses: true",
		"requests_per_second: 1", "requests_per_second: 10",
		"identities: []\n", "",
		"authorization_checks: []\n", "",
	).Replace(scope.Template) + authzYAML + extra
	if err := os.WriteFile(scope.Path(root), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func approveScope(t *testing.T, e *engine.Engine) {
	t.Helper()
	m, err := scope.Load(e.Root)
	if err != nil {
		t.Fatal(err)
	}
	if probs := m.Validate(time.Now()); len(probs) > 0 {
		t.Fatalf("fixture manifest invalid: %v", probs)
	}
	subject, err := e.ApprovalSubject(m, true)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("apr_%d", time.Now().UnixNano())
	if err := e.St.PutApproval(e.ProjectID, store.Approval{ID: id, Kind: engine.ApprovalKind, SubjectHash: subject, ApprovedBy: "tester", ApprovedAt: store.Now(),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
}

func noZAP(t *testing.T) {
	old := engine.ZAPLocator
	t.Cleanup(func() { engine.ZAPLocator = old })
	engine.ZAPLocator = func(string) (string, error) { return "", errors.New("ZAP is not installed") }
}

func setCreds(t *testing.T) {
	t.Setenv("PENSEC_T_ALICE", tokAlice)
	t.Setenv("PENSEC_T_BOB", tokBob)
	t.Setenv("PENSEC_T_CAROL", tokCarol)
	t.Setenv("PENSEC_T_OLD", tokOld)
}

func TestAuthzDetectsSeededBOLAAndPassesWhenFixed(t *testing.T) {
	t.Setenv("PENSEC_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	var hits atomic.Int64
	app := invoiceApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	setCreds(t)
	e := authzProject(t, app.URL, "")
	approveScope(t, e)

	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	for cid, want := range map[string]model.Status{"C-001": model.StatusFail, "C-002": model.StatusFail, "B-004": model.StatusFail, "M-001": model.StatusBlocked} {
		if res.Controls[cid] != string(want) {
			t.Errorf("vulnerable app: %s = %s, want %s (%v)", cid, res.Controls[cid], want, res.Notes)
		}
	}
	// 2 checks x (4 identities + anonymous)
	if res.Requests != 10 || hits.Load() != 10 {
		t.Fatalf("requests %d, app hits %d; want 10", res.Requests, hits.Load())
	}
	fs, _ := e.St.Findings(e.ProjectID)
	rules := map[string]int{}
	for _, f := range fs {
		if f.Collector == "authz" {
			rules[f.RuleID+" "+string(f.Confidence)]++
		}
	}
	// bob reads acme's invoice; bob and alice reach the admin route; the
	// revoked token still works on both checks.
	want := map[string]int{"authz.object-access CONFIRMED": 1, "authz.function-access CONFIRMED": 2, "authz.revoked-credential CONFIRMED": 2}
	if fmt.Sprint(rules) != fmt.Sprint(want) {
		t.Fatalf("authz findings %v, want %v", rules, want)
	}
	assertNoTokens(t, e)

	fixed.Store(true)
	res, err = e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	for _, cid := range []string{"C-001", "C-002", "B-004"} {
		if res.Controls[cid] != string(model.StatusPass) {
			t.Errorf("fixed app: %s = %s, want PASS (%v)", cid, res.Controls[cid], res.Notes)
		}
	}
	fs, _ = e.St.Findings(e.ProjectID)
	for _, f := range fs {
		if f.Collector == "authz" && f.Status != model.FindingRemediated {
			t.Errorf("%s %s is %s after the fix, want REMEDIATED", f.ID, f.RuleID, f.Status)
		}
	}
	assertNoTokens(t, e)
}

// assertNoTokens checks the ledger, every evidence file and every report.
func assertNoTokens(t *testing.T, e *engine.Engine) {
	t.Helper()
	r, err := report.Build(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := report.Write(r, report.DefaultDir(e.Root), []string{"html", "markdown", "json", "sarif", "csv"}); err != nil {
		t.Fatal(err)
	}
	err = filepath.Walk(filepath.Join(e.Root, ".pensec"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.HasSuffix(p, "scope.yaml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, tok := range []string{tokAlice, tokBob, tokCarol, tokOld, "tok-alice", "tok-bob", "tok-carol", "tok-old"} {
			if strings.Contains(string(b), tok) {
				t.Errorf("credential %q found in %s", tok, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthzNeedsApprovalAndCredentialsBeforeAnyRequest(t *testing.T) {
	t.Setenv("PENSEC_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	var hits atomic.Int64
	app := invoiceApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	setCreds(t)
	e := authzProject(t, app.URL, "")
	if _, err := e.StagingActive(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("missing approval must stop the run, got %v", err)
	}
	approveScope(t, e)
	t.Setenv("PENSEC_T_BOB", "")
	if _, err := e.StagingActive(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "PENSEC_T_BOB") {
		t.Fatalf("a missing credential must stop the run, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests were sent before the checks could run", hits.Load())
	}
}

func TestAuthzRedirectNotFollowedAndOutOfScopeRejected(t *testing.T) {
	t.Setenv("PENSEC_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	fixed.Store(true)
	var hits atomic.Int64
	app := invoiceApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	setCreds(t)

	// A check aimed at another origin is a manifest error.
	e := authzProject(t, app.URL, "  - name: elsewhere\n    kind: object\n    target: http://evil.example\n    method: GET\n    path: /x\n    allowed: [alice]\n")
	m, _ := scope.Load(e.Root)
	if probs := strings.Join(m.Validate(time.Now()), "; "); !strings.Contains(probs, "not in scope") {
		t.Fatalf("out-of-scope check target must be rejected, got %q", probs)
	}

	// A redirect to another origin is recorded and not followed.
	e = authzProject(t, app.URL, "  - name: account\n    kind: function\n    method: GET\n    path: /account\n    allowed: [anonymous]\n")
	approveScope(t, e)
	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Refused != nil && len(res.Refused) > 0 {
		t.Fatalf("nothing should reach the guard's refusal path: %v", res.Refused)
	}
	found := false
	for _, n := range res.Notes {
		if strings.Contains(n, "account") && strings.Contains(n, "2xx") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a redirect for the allowed identity must make the check unjudgeable: %v", res.Notes)
	}
	// Only the fixture app was contacted: evil.example is not resolvable
	// in tests, and the guard never follows redirects.
	if res.Requests != int(hits.Load()) {
		t.Fatalf("guard sent %d, app saw %d", res.Requests, hits.Load())
	}
}
