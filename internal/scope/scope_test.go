package scope

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestParseTarget(t *testing.T) {
	for _, bad := range []string{"ftp://x.example", "https://*.example.com", "https://user:pw@x.example", "https://x.example.", "https://x.example/?q=1", "x.example", "https://"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
	if _, err := ParseTarget("https://staging.example.com/app"); err != nil {
		t.Fatal(err)
	}
}

func TestInScope(t *testing.T) {
	m := &Manifest{ExcludedPaths: []string{"/app/admin"}}
	m.Targets = append(m.Targets, struct {
		URL string `yaml:"url"`
	}{"https://staging.example.com/app"})
	cases := map[string]bool{
		"https://staging.example.com/app":          true,
		"https://staging.example.com/app/x":        true,
		"https://staging.example.com/application":  false,
		"https://staging.example.com/app/admin/x":  false,
		"http://staging.example.com/app":           false,
		"https://staging.example.com:8443/app":     false,
		"https://evil.example/app":                 false,
		"https://staging.example.com.evil.com/app": false,
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		if got := m.InScope(u) == nil; got != want {
			t.Errorf("%s: got %v want %v", raw, got, want)
		}
	}
}

func TestAddrAllowed(t *testing.T) {
	m := &Manifest{}
	for _, a := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1", "fd00:ec2::254", "100.64.0.1", "0.0.0.0", "::ffff:127.0.0.1"} {
		if m.AddrAllowed(netip.MustParseAddr(a)) == nil {
			t.Errorf("%s must be blocked by default", a)
		}
	}
	if m.AddrAllowed(netip.MustParseAddr("93.184.215.14")) != nil {
		t.Error("public address must be allowed")
	}
	m.AllowPrivateAddresses = true
	if m.AddrAllowed(netip.MustParseAddr("127.0.0.1")) != nil {
		t.Error("loopback allowed when explicitly enabled")
	}
	if m.AddrAllowed(netip.MustParseAddr("169.254.169.254")) == nil {
		t.Error("metadata address must always be blocked")
	}
}

func TestTemplateIsNotValid(t *testing.T) {
	m := &Manifest{}
	if err := yaml.Unmarshal([]byte(Template), m); err != nil {
		t.Fatal(err)
	}
	if len(m.Validate(time.Now())) == 0 {
		t.Fatal("the shipped template must not be usable without human edits")
	}
}

func TestAuthzValidation(t *testing.T) {
	base := `schema_version: 1
authorization: {owner: o, reference: r, purpose: p, acknowledged: true}
environment: staging
targets: [{url: "https://staging.example.com"}]
allowed_methods: [GET, HEAD]
limits: {requests_per_second: 1, max_requests_total: 20, timeout_seconds: 10}
identities:
  - {name: alice, header: Authorization, value_env: PANDAWARD_ALICE}
  - {name: old, header: Authorization, value_env: PANDAWARD_OLD, revoked: true}
authorization_checks:
`
	for check, want := range map[string]string{
		`  - {name: ok, kind: object, method: GET, path: /api/x/1, allowed: [alice]}`:                               "",
		`  - {name: ok, kind: object, method: GET, path: /api/x/1, allowed: [anonymous]}`:                           "",
		`  - {name: w, kind: object, method: POST, path: /api/x/1, allowed: [alice]}`:                               "only read",
		`  - {name: w, kind: thing, method: GET, path: /api/x/1, allowed: [alice]}`:                                 "kind must be",
		`  - {name: w, kind: object, method: GET, path: /api/../x, allowed: [alice]}`:                               "path must",
		`  - {name: w, kind: object, method: GET, path: /x, allowed: [mallory]}`:                                    "unknown identity",
		`  - {name: w, kind: object, method: GET, path: /x, allowed: [old]}`:                                        "revoked identity",
		`  - {name: w, kind: object, method: GET, path: /x, allowed: []}`:                                           "allowed is empty",
		`  - {name: w, kind: object, target: "https://other.example.com", method: GET, path: /x, allowed: [alice]}`: "not in scope",
	} {
		m := &Manifest{}
		if err := yaml.Unmarshal([]byte(base+check+"\n"), m); err != nil {
			t.Fatal(err)
		}
		got := strings.Join(m.Validate(time.Now()), "; ")
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s\n  got %q, want %q", check, got, want)
		}
	}
	m := &Manifest{}
	yaml.Unmarshal([]byte(strings.Replace(base, "value_env: PANDAWARD_ALICE", "value_env: \"Bearer abc\"", 1)+"  - {name: ok, kind: object, method: GET, path: /x, allowed: [alice]}\n"), m)
	if got := strings.Join(m.Validate(time.Now()), "; "); !strings.Contains(got, "value_env") {
		t.Errorf("a credential pasted into value_env must be rejected: %q", got)
	}
	m = &Manifest{}
	many := base
	for i := 0; i < 7; i++ {
		many += fmt.Sprintf("  - {name: c%d, kind: object, method: GET, path: /x/%d, allowed: [alice]}\n", i, i)
	}
	yaml.Unmarshal([]byte(many), m)
	if got := strings.Join(m.Validate(time.Now()), "; "); !strings.Contains(got, "max_requests_total") {
		t.Errorf("checks beyond the budget must be rejected: %q", got)
	}
}
