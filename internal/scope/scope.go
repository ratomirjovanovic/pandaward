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
	// Contract turns on the G-002 check: every secured GET/HEAD operation
	// of the repository's OpenAPI contract is sent once without credentials.
	Contract struct {
		Check bool `yaml:"check"`
	} `yaml:"contract"`
	Identities           []Identity            `yaml:"identities"`
	IdentityProvisioning *IdentityProvisioning `yaml:"identity_provisioning"`
	AuthorizationChecks  []AuthCheck           `yaml:"authorization_checks"`
	FlowChecks           []FlowCheck           `yaml:"flow_checks"`
	EffectChecks         []EffectCheck         `yaml:"effect_checks"`
	LLMChecks            []LLMCheck            `yaml:"llm_checks"`

	hash     string
	bindHash string
}

// IdentityProvisioning names project commands that create the test
// identities before a staging-active run and remove them after it. Each
// command is an argument list, run without a shell from the project root.
// Provision prints {"credentials": {"<value_env>": "<header value>"}} on
// stdout; cleanup gets that same JSON on stdin.
type IdentityProvisioning struct {
	Provision      []string `yaml:"provision"`
	Cleanup        []string `yaml:"cleanup"`
	TimeoutSeconds int      `yaml:"timeout_seconds"`
}

// DefaultProvisionTimeout applies when timeout_seconds is 0.
const DefaultProvisionTimeout = 60

// Timeout is the per-command limit.
func (p *IdentityProvisioning) Timeout() time.Duration {
	if p.TimeoutSeconds == 0 {
		return DefaultProvisionTimeout * time.Second
	}
	return time.Duration(p.TimeoutSeconds) * time.Second
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

// Template is the blank manifest the tests and the adversarial suite start
// from; `pandaward scope init` drafts one from the project instead. All
// targets are empty and acknowledged is false, so nothing can run until a
// human fills it in.
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
contract:            # G-002, run by: pandaward test --profile staging-active
  check: false         # true sends each secured GET/HEAD operation of the repository's
                       # OpenAPI contract once without credentials; it must be refused
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
# Flow checks (staging-active, B-003): ordered requests of a login, reset or
# MFA flow; each step marked denied is a negative case the server must
# refuse. State-changing methods (POST, PUT, PATCH, DELETE) must be listed
# in allowed_methods and work only with environment staging or local; only
# these checks may send them. Bodies and extra header values come from
# environment variables, never from this file.
flow_checks: []
#  - name: wrong password refused
#    control: B-003
#    steps:
#      - method: POST
#        path: /api/auth/login
#        content_type: application/json
#        body_env: PANDAWARD_BODY_BAD_LOGIN   # {"email":"...","password":"wrong"}
#        expect: denied
#  - name: reset token works once
#    control: B-003
#    steps:
#      - {method: POST, path: /api/auth/reset, content_type: application/json, body_env: PANDAWARD_BODY_RESET, expect: allowed}
#      - {method: POST, path: /api/auth/reset, content_type: application/json, body_env: PANDAWARD_BODY_RESET, expect: denied}
# Effect checks (staging-active): one action sent repeat times, in sequence
# for F-002 (idempotency, webhook replay) or at once for Q-002 (concurrency).
# A read-only probe reads a number before and after; it must change by
# expect_delta, the effect of exactly one action.
effect_checks: []
#  - name: webhook replay credits once
#    control: F-002
#    action: {method: POST, path: /api/webhooks/payment, body_env: PANDAWARD_BODY_EVENT, header_env: {Webhook-Signature: PANDAWARD_SIG_EVENT}}
#    repeat: 3
#    probe: {method: GET, path: /api/me, as: alice, json: credits}
#    expect_delta: 10
#  - name: coupon redeemed once under concurrency
#    control: Q-002
#    action: {method: POST, path: /api/coupons/redeem, as: alice, body_env: PANDAWARD_BODY_COUPON}
#    repeat: 5
#    probe: {method: GET, path: /api/me, as: alice, json: balance}
#    expect_delta: 5
# Prompt-injection checks (staging-active, P-003): built-in payloads sent in
# a field the application treats as data (a document, a transcript, a
# retrieved page), never the user's own instruction field. The body
# template comes from body_env and must contain {{payload}}.
llm_checks: []
#  - name: document summary
#    request: {method: POST, path: /api/summarize, as: alice, content_type: application/json, body_env: PANDAWARD_LLM_BODY}
#    # PANDAWARD_LLM_BODY={"document":"Quarterly notes. {{payload}}"}
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
	m.bindHash = m.hash
	if m.IdentityProvisioning != nil {
		h := sha256.New()
		h.Write(sum[:])
		for _, part := range m.ProvisionParts(root) {
			h.Write([]byte("\x00" + part))
		}
		m.bindHash = hex.EncodeToString(h.Sum(nil))
	}
	return m, nil
}

// Hash is the SHA-256 of the manifest bytes.
func (m *Manifest) Hash() string { return m.hash }

// BindHash is what an approval binds to: the manifest bytes and, when the
// manifest provisions identities, the content of every project file the
// provision and cleanup commands name. Editing such a script after the
// approval invalidates it. Without provisioning it equals Hash.
func (m *Manifest) BindHash() string { return m.bindHash }

// ProvisionParts describes each argument of the provisioning commands: a
// project file as file:<path>:<sha256>, anything else as arg:<text>. A
// script that appears or changes later therefore changes BindHash.
func (m *Manifest) ProvisionParts(root string) []string {
	p := m.IdentityProvisioning
	if p == nil {
		return nil
	}
	var out []string
	for i, argv := range [][]string{p.Provision, p.Cleanup} {
		out = append(out, fmt.Sprintf("cmd:%d", i))
		for _, a := range argv {
			out = append(out, provisionPart(root, a))
		}
	}
	return out
}

func provisionPart(root, a string) string {
	if a == "" || filepath.IsAbs(a) || strings.HasPrefix(a, "-") || strings.Contains(a, "..") {
		return "arg:" + a
	}
	full := filepath.Join(root, filepath.FromSlash(a))
	st, err := os.Stat(full)
	if err != nil || !st.Mode().IsRegular() {
		return "arg:" + a
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "arg:" + a
	}
	sum := sha256.Sum256(b)
	return "file:" + filepath.ToSlash(a) + ":" + hex.EncodeToString(sum[:])
}

// ProvisionFiles lists the project files the provisioning commands name,
// with their SHA-256, for the approval prompt and evidence.
func (m *Manifest) ProvisionFiles(root string) []string {
	var out []string
	for _, part := range m.ProvisionParts(root) {
		if f, ok := strings.CutPrefix(part, "file:"); ok {
			out = append(out, f)
		}
	}
	return out
}

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
	p = append(p, m.validateMethods()...)
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
	fp, flowRequests := m.validateFlows()
	p = append(p, fp...)
	ep, effectRequests := m.validateEffects()
	p = append(p, ep...)
	lp, llmRequests := m.validateLLM()
	p = append(p, lp...)
	flowRequests += effectRequests + llmRequests
	if authz := len(m.AuthorizationChecks) * (len(m.Identities) + 1); flowRequests > 0 && authz+flowRequests > m.Limits.MaxRequestsTotal && m.Limits.MaxRequestsTotal > 0 {
		p = append(p, fmt.Sprintf("authorization, flow, effect and LLM checks need %d requests together; raise limits.max_requests_total", authz+flowRequests))
	}
	if m.StateMethodsUsed() && m.Environment != "staging" && m.Environment != "local" {
		p = append(p, "flow, effect and LLM checks with state-changing methods run only when environment is staging or local")
	}
	p = append(p, m.validateProvisioning()...)
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

func (m *Manifest) validateProvisioning() []string {
	ip := m.IdentityProvisioning
	if ip == nil {
		return nil
	}
	var p []string
	if len(ip.Provision) == 0 || strings.TrimSpace(ip.Provision[0]) == "" {
		p = append(p, "identity_provisioning.provision must be a command as a list, such as [node, scripts/identities.mjs]")
	}
	if len(ip.Cleanup) > 0 && strings.TrimSpace(ip.Cleanup[0]) == "" {
		p = append(p, "identity_provisioning.cleanup must start with a program")
	}
	for _, argv := range [][]string{ip.Provision, ip.Cleanup} {
		for _, a := range argv {
			if strings.ContainsAny(a, "\r\n\x00") {
				p = append(p, "identity_provisioning: arguments cannot contain line breaks or NUL")
			}
		}
	}
	if ip.TimeoutSeconds < 0 || ip.TimeoutSeconds > 300 {
		p = append(p, "identity_provisioning.timeout_seconds must be between 1 and 300 (0 means 60)")
	}
	if len(m.Identities) == 0 && len(m.InputEnvs()) == 0 {
		p = append(p, "identity_provisioning needs at least one identity or check input to provision")
	}
	return p
}
