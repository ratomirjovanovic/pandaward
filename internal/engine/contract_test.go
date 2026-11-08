package engine_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

const contractSpec = `openapi: 3.0.3
info: {title: fixture, version: "1"}
servers:
  - url: https://api.example.com/v1
security:
  - bearer: []
paths:
  /me:
    get:
      responses:
        "200":
          content:
            application/json: {}
  /reports:
    get:
      responses:
        "200":
          content:
            application/json: {}
  /health:
    get:
      security: []
      responses: {"200": {description: ok}}
  /items/{id}:
    get:
      responses: {"200": {description: ok}}
  /search:
    get:
      parameters:
        - {name: q, in: query, required: true}
      responses: {"200": {description: ok}}
`

// contractApp serves /v1/me behind a token check and /v1/reports without
// one; fixed adds the check to /v1/reports. /v1/health is public.
func contractApp(fixed *atomic.Bool, hits *atomic.Int64) *httptest.Server {
	mux := http.NewServeMux()
	secured := func(always bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if (always || fixed.Load()) && r.Header.Get("Authorization") == "" {
				http.Error(w, "login required", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"ok":true}`)
		}
	}
	mux.HandleFunc("/v1/me", secured(true))
	mux.HandleFunc("/v1/reports", secured(false))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	})
	return httptest.NewServer(mux)
}

func contractProject(t *testing.T, target, spec string, check bool) *engine.Engine {
	t.Helper()
	root := testfixture.VulnerableRepo(t)
	// The fixture has an openapi.yaml; "" removes it.
	specPath := filepath.Join(root, "openapi.yaml")
	if spec == "" {
		if err := os.Remove(specPath); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
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
		`purpose: ""`, `purpose: "contract test"`,
		`acknowledged: false`, `acknowledged: true`,
		"targets: []", "targets:\n  - url: "+target,
		"allow_private_addresses: false", "allow_private_addresses: true",
		"requests_per_second: 1", "requests_per_second: 10",
		"  check: false ", fmt.Sprintf("  check: %v ", check),
	).Replace(scope.Template)
	if err := os.WriteFile(scope.Path(root), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestContractCheckFailsOpenOperationAndPassesWhenFixed(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	var hits atomic.Int64
	app := contractApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	e := contractProject(t, app.URL, contractSpec, true)
	approveScope(t, e)

	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["G-002"] != string(model.StatusFail) {
		t.Fatalf("G-002 = %s, want FAIL (%v)", res.Controls["G-002"], res.Notes)
	}
	// Only /v1/me and /v1/reports are sent: /health is public, /items/{id}
	// needs a value and /search a required query parameter.
	if hits.Load() != 2 {
		t.Fatalf("app hits %d, want 2", hits.Load())
	}
	fs, _ := e.St.Findings(e.ProjectID)
	var open []string
	for _, f := range fs {
		if f.Collector == "contract" {
			open = append(open, f.RuleID+" "+string(f.Confidence)+" "+f.File)
		}
	}
	if len(open) != 1 || !strings.Contains(open[0], "contract.unauthenticated-access CONFIRMED GET ") || !strings.HasSuffix(open[0], "/v1/reports") {
		t.Fatalf("contract findings %v, want one confirmed on /v1/reports", open)
	}

	fixed.Store(true)
	res, err = e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["G-002"] != string(model.StatusPass) {
		t.Fatalf("fixed: G-002 = %s, want PASS (%v)", res.Controls["G-002"], res.Notes)
	}
	fs, _ = e.St.Findings(e.ProjectID)
	for _, f := range fs {
		if f.Collector == "contract" && f.Status != model.FindingRemediated {
			t.Errorf("%s is %s after the fix, want REMEDIATED", f.ID, f.Status)
		}
	}
}

// An HTML answer the contract does not declare may be a fallback page, so
// it is suspected, not confirmed; a 404 says nothing about authorization.
func TestContractCheckHTMLFallbackAndNotFound(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/me" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "<html>app shell</html>")
			return
		}
		http.NotFound(w, r)
	}))
	defer app.Close()
	noZAP(t)
	e := contractProject(t, app.URL, contractSpec, true)
	approveScope(t, e)
	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["G-002"] != string(model.StatusSuspected) {
		t.Fatalf("G-002 = %s, want SUSPECTED (%v)", res.Controls["G-002"], res.Notes)
	}
}

func TestContractCheckNeedsSpecAndOptIn(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	var hits atomic.Int64
	app := contractApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)

	// Not opted in: nothing is sent and G-002 is left to the plan.
	e := contractProject(t, app.URL, contractSpec, false)
	approveScope(t, e)
	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Controls["G-002"]; ok || hits.Load() != 0 {
		t.Fatalf("without contract.check: G-002 = %q, hits %d; want untouched and 0", res.Controls["G-002"], hits.Load())
	}

	// Opted in without an OpenAPI document: BLOCKED with the reason.
	e = contractProject(t, app.URL, "", true)
	approveScope(t, e)
	res, err = e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["G-002"] != string(model.StatusBlocked) || hits.Load() != 0 {
		t.Fatalf("without a spec: G-002 = %s, hits %d; want BLOCKED and 0", res.Controls["G-002"], hits.Load())
	}
}
