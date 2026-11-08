package scope

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const flowBase = `schema_version: 1
authorization: {owner: o, reference: r, purpose: p, acknowledged: true}
environment: staging
targets: [{url: "https://staging.example.com"}]
allowed_methods: [GET, HEAD, POST]
limits: {requests_per_second: 1, max_requests_total: 20, timeout_seconds: 10}
identities:
  - {name: alice, header: Authorization, value_env: PANDAWARD_ID_ALICE}
`

func flowManifest(t *testing.T, extra string) *Manifest {
	t.Helper()
	m := &Manifest{}
	if err := yaml.Unmarshal([]byte(flowBase+extra), m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFlowValidation(t *testing.T) {
	ok := `flow_checks:
  - name: wrong password
    control: B-003
    steps:
      - {method: POST, path: /api/login, body_env: PANDAWARD_BODY_BAD, expect: denied}
`
	if p := flowManifest(t, ok).Validate(time.Now()); len(p) > 0 {
		t.Fatalf("valid flow manifest rejected: %v", p)
	}
	cases := map[string]struct{ yaml, want string }{
		"no negative case": {`flow_checks:
  - {name: x, control: B-003, steps: [{method: POST, path: /a, expect: allowed}]}
`, "needs at least one step with expect: denied"},
		"other control": {`flow_checks:
  - {name: x, control: F-002, steps: [{method: POST, path: /a, expect: denied}]}
`, "control must be B-003"},
		"body on GET": {`flow_checks:
  - {name: x, control: B-003, steps: [{method: GET, path: /a, body_env: PANDAWARD_B, expect: denied}]}
`, "GET cannot carry a body"},
		"method not allowed": {`flow_checks:
  - {name: x, control: B-003, steps: [{method: DELETE, path: /a, expect: denied}]}
`, "DELETE is not in allowed_methods"},
		"inline secret instead of env": {`flow_checks:
  - {name: x, control: B-003, steps: [{method: POST, path: /a, body_env: "{\"password\":\"x\"}", expect: denied}]}
`, "body_env must name an environment variable"},
		"header overrides the credential": {`flow_checks:
  - {name: x, control: B-003, steps: [{method: POST, path: /a, as: alice, header_env: {authorization: PANDAWARD_H}, expect: denied}]}
`, "carries the identity's credential"},
		"reserved header": {`flow_checks:
  - {name: x, control: B-003, steps: [{method: POST, path: /a, header_env: {Host: PANDAWARD_H}, expect: denied}]}
`, "header_env cannot set Host"},
		"unknown identity": {`flow_checks:
  - {name: x, control: B-003, steps: [{method: POST, path: /a, as: mallory, expect: denied}]}
`, "unknown identity mallory"},
		"out of scope target": {`flow_checks:
  - {name: x, control: B-003, steps: [{method: POST, path: /a, target: "https://evil.example", expect: denied}]}
`, "not in scope"},
	}
	for name, c := range cases {
		p := strings.Join(flowManifest(t, c.yaml).Validate(time.Now()), "; ")
		if !strings.Contains(p, c.want) {
			t.Errorf("%s: problems %q, want one containing %q", name, p, c.want)
		}
	}
	m := flowManifest(t, ok)
	m.Environment = "production"
	p := strings.Join(m.Validate(time.Now()), "; ")
	if !strings.Contains(p, "POST changes state and is allowed only when environment is staging or local") {
		t.Errorf("production with POST: %q", p)
	}
}

// The guard sends a state-changing method only for a request marked by a
// flow check, and never to production.
func TestGuardStateChangingNeedsMark(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	m := flowManifest(t, "")
	m.Targets[0].URL = srv.URL
	m.AllowPrivateAddresses = true
	m.Limits.RequestsPerSecond = 10
	g := NewGuard(m, nil)
	send := func(ctx context.Context) error {
		req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/api/login", strings.NewReader("{}"))
		resp, err := g.Client().Do(req)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := send(context.Background()); !errors.Is(err, ErrRefused) {
		t.Fatalf("unmarked POST: %v, want refused", err)
	}
	if err := send(WithStateChange(context.Background())); err != nil {
		t.Fatalf("marked POST: %v", err)
	}
	m.Environment = "production"
	if err := send(WithStateChange(context.Background())); !errors.Is(err, ErrRefused) {
		t.Fatalf("marked POST to production: %v, want refused", err)
	}
}
