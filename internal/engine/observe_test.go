package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/scope"
	"github.com/ratomirjovanovic/pensec/internal/store"
	"github.com/ratomirjovanovic/pensec/internal/testfixture"
)

func writeScope(t *testing.T, root, target string, allowPrivate bool) *scope.Manifest {
	t.Helper()
	m := strings.NewReplacer(
		`owner: ""`, `owner: "Fixture Owner"`,
		`reference: ""`, `reference: "TEST-1"`,
		`purpose: ""`, `purpose: "unit test"`,
		`acknowledged: false`, `acknowledged: true`,
		"targets: []", "targets:\n  - url: "+target,
		"allow_private_addresses: false", "allow_private_addresses: "+map[bool]string{true: "true", false: "false"}[allowPrivate],
	).Replace(scope.Template)
	if err := os.WriteFile(scope.Path(root), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	man, err := scope.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return man
}

func approve(t *testing.T, e *Engine, m *scope.Manifest) {
	t.Helper()
	subject, err := e.ApprovalSubject(m, true)
	if err != nil {
		t.Fatal(err)
	}
	err = e.St.PutApproval(e.ProjectID, store.Approval{ID: "apr_test", Kind: ApprovalKind, SubjectHash: subject, ApprovedBy: "tester", ApprovedAt: store.Now(),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
}

func TestObserveRequiresApproval(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _ := scan(t, root)
	defer e.Close()
	if _, err := e.Observe(context.Background(), func(string) {}); err == nil {
		t.Fatal("observe must fail without scope manifest")
	}
	writeScope(t, root, "http://127.0.0.1:1", true)
	if _, err := e.Observe(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("observe must fail without approval, got %v", err)
	}
}

func TestObserveHeadersAndRedirectGuard(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Add("Set-Cookie", "sid=supersecretvalue; Path=/")
		http.Redirect(w, r, "http://evil.example/steal", http.StatusFound)
	}))
	defer srv.Close()
	root := testfixture.VulnerableRepo(t)
	e, _ := scan(t, root)
	defer e.Close()
	m := writeScope(t, root, srv.URL, true)
	approve(t, e, m)
	res, err := e.Observe(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 || res.Requests != 1 {
		t.Fatalf("expected exactly one request, server saw %d", hits)
	}
	if res.Findings == 0 {
		t.Fatal("expected header findings")
	}
	found := false
	for _, er := range res.Errors {
		if strings.Contains(er, "out-of-scope") {
			found = true
		}
	}
	if !found {
		t.Fatalf("redirect to evil.example must be reported and not followed: %v", res.Errors)
	}
	fs, _ := e.St.Findings(e.ProjectID)
	for _, f := range fs {
		if strings.Contains(f.Message, "supersecretvalue") {
			t.Fatal("cookie value leaked")
		}
	}
	// Editing the manifest invalidates the approval.
	b, _ := os.ReadFile(scope.Path(root))
	os.WriteFile(scope.Path(root), append(b, []byte("\n# edited\n")...), 0o644)
	if _, err := e.Observe(context.Background(), func(string) {}); err == nil {
		t.Fatal("edited manifest must require a new approval")
	}
}

func TestObservePrivateAddressBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request must not reach a private address without allow_private_addresses")
	}))
	defer srv.Close()
	root := testfixture.VulnerableRepo(t)
	e, _ := scan(t, root)
	defer e.Close()
	m := writeScope(t, root, srv.URL, false)
	approve(t, e, m)
	res, err := e.Observe(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != string(model.StatusInconclusive) {
		t.Fatalf("expected INCONCLUSIVE when the guard blocks, got %s (%v)", res.Status, res.Errors)
	}
}
