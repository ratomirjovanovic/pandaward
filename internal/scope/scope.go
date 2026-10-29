// Package scope loads and enforces the authorization manifest for any test
// that sends network traffic. Every check fails closed.
package scope

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FileName is the scope manifest name inside .pandaward/.
const FileName = "scope.yaml"

// Manifest is the authorization record for network-active tests.
type Manifest struct {
	SchemaVersion int `yaml:"schema_version"`
	Authorization struct {
		Owner        string `yaml:"owner"`
		Reference    string `yaml:"reference"`
		Purpose      string `yaml:"purpose"`
		Contact      string `yaml:"contact"`
		Acknowledged bool   `yaml:"acknowledged"`
	} `yaml:"authorization"`
	Environment string `yaml:"environment"`
	Window      struct {
		Start string `yaml:"start"`
		End   string `yaml:"end"`
	} `yaml:"window"`
	Targets []struct {
		URL string `yaml:"url"`
	} `yaml:"targets"`
	ExcludedPaths         []string `yaml:"excluded_paths"`
	AllowedMethods        []string `yaml:"allowed_methods"`
	AllowPrivateAddresses bool     `yaml:"allow_private_addresses"`
	Limits                struct {
		RequestsPerSecond float64 `yaml:"requests_per_second"`
		MaxRequestsTotal  int     `yaml:"max_requests_total"`
		TimeoutSeconds    int     `yaml:"timeout_seconds"`
	} `yaml:"limits"`
	ZAP struct {
		ActiveScan         bool `yaml:"active_scan"`
		MaxDurationMinutes int  `yaml:"max_duration_minutes"`
	} `yaml:"zap"`
	Identities          []Identity  `yaml:"identities"`
	AuthorizationChecks []AuthCheck `yaml:"authorization_checks"`

	hash string
}

// Identity is a test account used by authorization checks. The credential
// itself is never written to the manifest: ValueEnv names the environment
// variable that holds the full header value when the test runs.
type Identity struct {
	Name     string `yaml:"name"`
	Tenant   string `yaml:"tenant"`
	Header   string `yaml:"header"`
	ValueEnv string `yaml:"value_env"`
	// Revoked marks a credential that was logged out, expired or revoked;
	// every check must refuse it (control B-004).
	Revoked bool `yaml:"revoked"`
}

// AuthCheck is one read-only request that only the Allowed identities may
// make successfully. Kind object decides C-001, function decides C-002.
type AuthCheck struct {
	Name    string   `yaml:"name"`
	Kind    string   `yaml:"kind"`
	Target  string   `yaml:"target"`
	Method  string   `yaml:"method"`
	Path    string   `yaml:"path"`
	Allowed []string `yaml:"allowed"`
}

// Anonymous is the implicit identity without credentials.
const Anonymous = "anonymous"

// Template is written by `pandaward scope init`. All targets are empty and
// acknowledged is false, so nothing can run until a human fills it in.
const Template = `# PandaWard scope manifest (schema v1)
# Required before ANY network-active test. Fill in, then approve it yourself
# from an interactive terminal:  pandaward scope approve --by "<your name>"
# Editing this file invalidates any previous approval.
schema_version: 1
authorization:
  owner: ""          # person or organization that owns the targets or granted permission
  reference: ""      # written permission, ticket or contract reference
  purpose: ""        # why this test is run
  contact: ""        # incident contact during the test window
  acknowledged: false  # set true only if you are authorized to test every target below
environment: staging   # staging | production | local
window:
  start: ""          # RFC3339, optional
  end: ""            # RFC3339, optional
targets: []
#  - url: https://staging.example.com
excluded_paths: []
allowed_methods: [GET, HEAD]
allow_private_addresses: false   # true only for a controlled local fixture
limits:
  requests_per_second: 1
  max_requests_total: 20
  timeout_seconds: 10
zap:                 # ZAP baseline, run by: pandaward test --profile staging-active
  active_scan: false   # true sends ZAP attack payloads; never on production
  max_duration_minutes: 10
# Authorization checks (staging-active). Each check is one read-only request
# to an object or function that exists for the test; it is sent as every
# identity and without credentials, and only "allowed" may succeed.
identities: []
#  - name: alice
#    tenant: acme
#    header: Authorization           # header that carries the credential
#    value_env: PANDAWARD_ID_ALICE      # environment variable with the full header value
#    revoked: false                  # true for a logged-out token that must be refused
authorization_checks: []
#  - name: acme invoice
#    kind: object                    # object (C-001) or function (C-002)
#    method: GET
#    path: /api/invoices/inv_acme_1
#    allowed: [alice]                # every other identity and anonymous must be denied
`

// Path returns the manifest path.
func Path(root string) string { return filepath.Join(root, ".pandaward", FileName) }

// Load reads and validates the manifest.
func Load(root string) (*Manifest, error) {
	b, err := os.ReadFile(Path(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no scope manifest at %s: run `pandaward scope init` and fill it in", Path(root))
	}
	if err != nil {
		return nil, err
	}
	m := &Manifest{}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(m); err != nil {
		return nil, fmt.Errorf("invalid scope manifest: %w", err)
	}
	sum := sha256.Sum256(b)
	m.hash = hex.EncodeToString(sum[:])
	return m, nil
}

// Hash is the SHA-256 of the manifest bytes; approvals bind to it.
func (m *Manifest) Hash() string { return m.hash }

// Validate returns every problem that blocks network-active testing.
func (m *Manifest) Validate(now time.Time) []string {
	var p []string
	if m.SchemaVersion != 1 {
		p = append(p, "schema_version must be 1")
	}
	if strings.TrimSpace(m.Authorization.Owner) == "" {
		p = append(p, "authorization.owner is empty")
	}
	if strings.TrimSpace(m.Authorization.Reference) == "" {
		p = append(p, "authorization.reference is empty")
	}
	if strings.TrimSpace(m.Authorization.Purpose) == "" {
		p = append(p, "authorization.purpose is empty")
	}
	if !m.Authorization.Acknowledged {
		p = append(p, "authorization.acknowledged is false")
	}
	switch m.Environment {
	case "staging", "production", "local":
	default:
		p = append(p, "environment must be staging, production or local")
	}
	if len(m.Targets) == 0 {
		p = append(p, "targets is empty")
	}
	for _, t := range m.Targets {
		if _, err := ParseTarget(t.URL); err != nil {
			p = append(p, fmt.Sprintf("target %q: %v", t.URL, err))
		}
	}
	for _, meth := range m.AllowedMethods {
		if meth != "GET" && meth != "HEAD" && meth != "OPTIONS" {
			p = append(p, fmt.Sprintf("allowed_methods: %s is not supported by any implemented adapter; only GET, HEAD, OPTIONS", meth))
		}
	}
	if m.Limits.RequestsPerSecond <= 0 || m.Limits.RequestsPerSecond > 10 {
		p = append(p, "limits.requests_per_second must be >0 and <=10")
	}
	if m.Limits.MaxRequestsTotal <= 0 || m.Limits.MaxRequestsTotal > 1000 {
		p = append(p, "limits.max_requests_total must be between 1 and 1000")
	}
	if m.Limits.TimeoutSeconds <= 0 || m.Limits.TimeoutSeconds > 60 {
		p = append(p, "limits.timeout_seconds must be between 1 and 60")
	}
	if m.ZAP.MaxDurationMinutes < 0 || m.ZAP.MaxDurationMinutes > 120 {
		p = append(p, "zap.max_duration_minutes must be between 0 and 120")
	}
	if m.ZAP.ActiveScan && m.Environment == "production" {
		p = append(p, "zap.active_scan is not allowed when environment is production")
	}
	p = append(p, m.validateAuthz()...)
	if m.Window.Start != "" {
		st, err := time.Parse(time.RFC3339, m.Window.Start)
		if err != nil {
			p = append(p, "window.start is not RFC3339")
		} else if now.Before(st) {
			p = append(p, "test window has not started")
		}
	}
	if m.Window.End != "" {
		en, err := time.Parse(time.RFC3339, m.Window.End)
		if err != nil {
			p = append(p, "window.end is not RFC3339")
		} else if now.After(en) {
			p = append(p, "test window has ended")
		}
	}
	return p
}

// ParseTarget validates a target URL. Only http(s) origins with an explicit
// host are accepted; credentials in URLs and wildcards are rejected.
func ParseTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("scheme must be http or https")
	}
	if u.User != nil {
		return nil, errors.New("credentials in URL are not allowed")
	}
	h := u.Hostname()
	if h == "" || strings.ContainsAny(h, "*?") {
		return nil, errors.New("explicit host required, wildcards are not allowed")
	}
	if strings.HasSuffix(h, ".") {
		return nil, errors.New("trailing dot hosts are ambiguous")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("query and fragment are not allowed in a scope target")
	}
	return u, nil
}

// InScope reports whether a request URL is inside the manifest.
func (m *Manifest) InScope(u *url.URL) error {
	if u.User != nil {
		return errors.New("credentials in URL")
	}
	for _, t := range m.Targets {
		tu, err := ParseTarget(t.URL)
		if err != nil {
			continue
		}
		if !strings.EqualFold(tu.Scheme, u.Scheme) || !strings.EqualFold(tu.Hostname(), u.Hostname()) || effPort(tu) != effPort(u) {
			continue
		}
		base := strings.TrimSuffix(tu.EscapedPath(), "/")
		p := u.EscapedPath()
		if base != "" && p != base && !strings.HasPrefix(p, base+"/") {
			continue
		}
		for _, ex := range m.ExcludedPaths {
			if ex != "" && (p == ex || strings.HasPrefix(p, strings.TrimSuffix(ex, "/")+"/")) {
				return fmt.Errorf("path %s is excluded", p)
			}
		}
		return nil
	}
	return fmt.Errorf("%s is not in scope", u.Redacted())
}

// MethodAllowed reports whether an HTTP method is allowed.
func (m *Manifest) MethodAllowed(method string) bool {
	for _, a := range m.AllowedMethods {
		if a == method {
			return true
		}
	}
	return false
}

func effPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// AddrAllowed rejects loopback, private, link-local, metadata and other
// special addresses unless the manifest explicitly allows a private fixture.
// Cloud metadata addresses are rejected unconditionally.
func (m *Manifest) AddrAllowed(a netip.Addr) error {
	a = a.Unmap()
	meta := []netip.Prefix{
		netip.MustParsePrefix("169.254.169.254/32"),
		netip.MustParsePrefix("169.254.170.2/32"),
		netip.MustParsePrefix("100.100.100.200/32"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
	}
	for _, p := range meta {
		if p.Contains(a) {
			return fmt.Errorf("%s is a cloud metadata address", a)
		}
	}
	if a.IsUnspecified() || a.IsMulticast() || a.IsInterfaceLocalMulticast() || a.IsLinkLocalMulticast() {
		return fmt.Errorf("%s is not a unicast address", a)
	}
	special := a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || netip.MustParsePrefix("100.64.0.0/10").Contains(a) || netip.MustParsePrefix("0.0.0.0/8").Contains(a)
	if special && !m.AllowPrivateAddresses {
		return fmt.Errorf("%s is a private/loopback address; set allow_private_addresses only for a controlled local fixture", a)
	}
	return nil
}

// DialContext resolves and validates the address at connection time, so a
// DNS answer that changes between checks cannot redirect traffic.
func (m *Manifest) DialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses for %s", host)
		}
		for _, ip := range ips {
			if err := m.AddrAllowed(ip); err != nil {
				return nil, fmt.Errorf("scope guard: %s resolves to blocked address: %w", host, err)
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
}

var (
	identityNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	headerNameRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	envNameRe      = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
)

// reservedHeaders cannot carry a credential.
var reservedHeaders = map[string]bool{"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "upgrade": true, "te": true, "trailer": true, "proxy-authorization": true}

func (m *Manifest) validateAuthz() []string {
	var p []string
	ids := map[string]*Identity{}
	for i := range m.Identities {
		id := &m.Identities[i]
		switch {
		case !identityNameRe.MatchString(id.Name) || id.Name == Anonymous:
			p = append(p, fmt.Sprintf("identities[%d].name %q must be lowercase letters, digits, - or _ (and not %q)", i, id.Name, Anonymous))
		case ids[id.Name] != nil:
			p = append(p, fmt.Sprintf("identity %q is listed twice", id.Name))
		}
		ids[id.Name] = id
		if !headerNameRe.MatchString(id.Header) || reservedHeaders[strings.ToLower(id.Header)] {
			p = append(p, fmt.Sprintf("identity %q: header %q is not usable for a credential", id.Name, id.Header))
		}
		if !envNameRe.MatchString(id.ValueEnv) {
			p = append(p, fmt.Sprintf("identity %q: value_env must name an environment variable (A-Z, 0-9, _); the credential itself never goes in this file", id.Name))
		}
	}
	names := map[string]bool{}
	requests := 0
	for i, c := range m.AuthorizationChecks {
		where := fmt.Sprintf("authorization_checks[%d] %q", i, c.Name)
		if strings.TrimSpace(c.Name) == "" {
			p = append(p, fmt.Sprintf("authorization_checks[%d].name is empty", i))
		} else if names[c.Name] {
			p = append(p, where+" is listed twice")
		}
		names[c.Name] = true
		if c.Kind != "object" && c.Kind != "function" {
			p = append(p, where+": kind must be object or function")
		}
		if c.Method != "GET" && c.Method != "HEAD" {
			p = append(p, where+": method must be GET or HEAD; authorization checks only read")
		} else if !m.MethodAllowed(c.Method) {
			p = append(p, where+": method "+c.Method+" is not in allowed_methods")
		}
		if u, err := m.CheckURL(c); err != nil {
			p = append(p, where+": "+err.Error())
		} else if err := m.InScope(u); err != nil {
			p = append(p, where+": "+err.Error())
		}
		if len(c.Allowed) == 0 {
			p = append(p, where+": allowed is empty")
		}
		for _, a := range c.Allowed {
			switch id := ids[a]; {
			case a == Anonymous:
			case id == nil:
				p = append(p, where+": allowed names unknown identity "+a)
			case id.Revoked:
				p = append(p, where+": revoked identity "+a+" cannot be allowed")
			}
		}
		requests += len(m.Identities) + 1
	}
	if len(m.AuthorizationChecks) > 0 && len(m.Identities) == 0 {
		p = append(p, "authorization_checks need at least one identity")
	}
	if requests > m.Limits.MaxRequestsTotal && m.Limits.MaxRequestsTotal > 0 {
		p = append(p, fmt.Sprintf("authorization checks need %d requests (each check once per identity and once anonymous); raise limits.max_requests_total", requests))
	}
	return p
}

// CheckURL is the request URL of an authorization check: its target (or
// the first target) with the check path.
func (m *Manifest) CheckURL(c AuthCheck) (*url.URL, error) {
	base := c.Target
	if base == "" {
		if len(m.Targets) == 0 {
			return nil, errors.New("no target")
		}
		base = m.Targets[0].URL
	}
	bu, err := ParseTarget(base)
	if err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	if !strings.HasPrefix(c.Path, "/") || strings.Contains(c.Path, "..") || strings.ContainsAny(c.Path, "#\\ ") {
		return nil, errors.New("path must start with / and contain no .., #, backslash or space")
	}
	u, err := url.Parse(bu.Scheme + "://" + bu.Host + c.Path)
	if err != nil {
		return nil, err
	}
	return u, nil
}
