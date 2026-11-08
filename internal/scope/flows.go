package scope

import (
	"context"
	"fmt"
	"mime"
	"net/url"
	"sort"
	"strings"
)

// State-changing requests (POST, PUT, PATCH, DELETE) are allowed only when
// the manifest lists the method, the environment is staging or local, and
// the request comes from a check that declares it (flow checks today). The
// guard refuses them from anything else, so ZAP, its spider and the
// authorization checks stay read-only whatever allowed_methods says.

// readOnlyMethods never change state.
var readOnlyMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

// stateMethods change state and need a declaring check.
var stateMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// StateChanging reports whether method may change state on the target.
func StateChanging(method string) bool { return !readOnlyMethods[method] }

type stateKey struct{}

// WithStateChange marks a request context as coming from a check that
// declares its state-changing requests. Only such requests may use a
// state-changing method.
func WithStateChange(ctx context.Context) context.Context {
	return context.WithValue(ctx, stateKey{}, true)
}

func stateAllowed(ctx context.Context) bool {
	v, _ := ctx.Value(stateKey{}).(bool)
	return v
}

// FlowStep is one request of a flow check. The body and extra header values
// come from environment variables (or the identity provisioning output),
// never from the manifest.
type FlowStep struct {
	Method      string            `yaml:"method"`
	Path        string            `yaml:"path"`
	Target      string            `yaml:"target"`
	As          string            `yaml:"as"` // identity name; empty or "anonymous" sends no credential
	ContentType string            `yaml:"content_type"`
	BodyEnv     string            `yaml:"body_env"`
	HeaderEnv   map[string]string `yaml:"header_env"` // header name -> environment variable
	Expect      string            `yaml:"expect"`     // allowed or denied
}

// FlowCheck is an ordered sequence of requests for one control: a login,
// reset or MFA flow where the steps marked denied are the negative cases
// the server must refuse (B-003).
type FlowCheck struct {
	Name    string     `yaml:"name"`
	Control string     `yaml:"control"`
	Steps   []FlowStep `yaml:"steps"`
}

// flowControls are the controls flow checks may decide.
var flowControls = map[string]bool{"B-003": true}

// MaxFlowSteps caps the steps of one flow check.
const MaxFlowSteps = 10

// StepURL is the request URL of a step: its target (or the first target)
// with the step path, which may carry a query.
func (m *Manifest) StepURL(target, path string) (*url.URL, error) {
	p, q, _ := strings.Cut(path, "?")
	u, err := m.CheckURL(AuthCheck{Target: target, Path: p})
	if err != nil {
		return nil, err
	}
	if q != "" {
		if strings.ContainsAny(q, "#\\ ") {
			return nil, fmt.Errorf("query must contain no #, backslash or space")
		}
		u.RawQuery = q
	}
	return u, nil
}

// StateMethodsUsed reports whether any check sends a state-changing method.
func (m *Manifest) StateMethodsUsed() bool {
	for _, c := range m.FlowChecks {
		for _, s := range c.Steps {
			if StateChanging(s.Method) {
				return true
			}
		}
	}
	return false
}

// NeedsIdentities reports whether any check sends a request as an identity.
func (m *Manifest) NeedsIdentities() bool {
	if len(m.AuthorizationChecks) > 0 {
		return true
	}
	for _, c := range m.FlowChecks {
		for _, s := range c.Steps {
			if s.As != "" && s.As != Anonymous {
				return true
			}
		}
	}
	return false
}

// InputEnvs lists the environment variables checks read request bodies and
// header values from, each with whether it is a header value (which cannot
// hold a line break).
func (m *Manifest) InputEnvs() map[string]bool {
	out := map[string]bool{}
	for _, c := range m.FlowChecks {
		for _, s := range c.Steps {
			if _, seen := out[s.BodyEnv]; s.BodyEnv != "" && !seen {
				out[s.BodyEnv] = false
			}
			for _, env := range s.HeaderEnv {
				out[env] = true
			}
		}
	}
	return out
}

func (m *Manifest) validateMethods() []string {
	var p []string
	for _, meth := range m.AllowedMethods {
		switch {
		case readOnlyMethods[meth]:
		case stateMethods[meth]:
			if m.Environment != "staging" && m.Environment != "local" {
				p = append(p, fmt.Sprintf("allowed_methods: %s changes state and is allowed only when environment is staging or local", meth))
			}
		default:
			p = append(p, fmt.Sprintf("allowed_methods: %s is not supported; use GET, HEAD, OPTIONS, or POST, PUT, PATCH, DELETE for flow checks", meth))
		}
	}
	return p
}

// validateFlows checks the flow checks and returns how many requests they
// need at most.
func (m *Manifest) validateFlows() ([]string, int) {
	var p []string
	ids := map[string]*Identity{}
	for i := range m.Identities {
		ids[m.Identities[i].Name] = &m.Identities[i]
	}
	names := map[string]bool{}
	requests := 0
	for i, c := range m.FlowChecks {
		where := fmt.Sprintf("flow_checks[%d] %q", i, c.Name)
		if strings.TrimSpace(c.Name) == "" {
			p = append(p, fmt.Sprintf("flow_checks[%d].name is empty", i))
		} else if names[c.Name] {
			p = append(p, where+" is listed twice")
		}
		names[c.Name] = true
		if !flowControls[c.Control] {
			p = append(p, where+": control must be B-003")
		}
		if len(c.Steps) == 0 || len(c.Steps) > MaxFlowSteps {
			p = append(p, fmt.Sprintf("%s: needs 1 to %d steps", where, MaxFlowSteps))
		}
		denied := false
		for j, s := range c.Steps {
			sw := fmt.Sprintf("%s step %d", where, j+1)
			p = append(p, m.validateStep(sw, s, ids)...)
			switch s.Expect {
			case "denied":
				denied = true
			case "allowed":
			default:
				p = append(p, sw+": expect must be allowed or denied")
			}
		}
		if len(c.Steps) > 0 && !denied {
			p = append(p, where+": needs at least one step with expect: denied (the negative case)")
		}
		requests += len(c.Steps)
	}
	return p, requests
}

func (m *Manifest) validateStep(where string, s FlowStep, ids map[string]*Identity) []string {
	var p []string
	switch {
	case !readOnlyMethods[s.Method] && !stateMethods[s.Method]:
		p = append(p, where+": method "+s.Method+" is not supported")
	case !m.MethodAllowed(s.Method):
		p = append(p, where+": method "+s.Method+" is not in allowed_methods")
	}
	if u, err := m.StepURL(s.Target, s.Path); err != nil {
		p = append(p, where+": "+err.Error())
	} else if err := m.InScope(u); err != nil {
		p = append(p, where+": "+err.Error())
	}
	if s.As != "" && s.As != Anonymous {
		switch id := ids[s.As]; {
		case id == nil:
			p = append(p, where+": as names unknown identity "+s.As)
		case id.Revoked:
			p = append(p, where+": as names revoked identity "+s.As+"; flow checks run as working identities")
		}
	}
	if s.BodyEnv != "" {
		if !envNameRe.MatchString(s.BodyEnv) {
			p = append(p, where+": body_env must name an environment variable (A-Z, 0-9, _); the body itself never goes in this file")
		}
		if !StateChanging(s.Method) {
			p = append(p, where+": "+s.Method+" cannot carry a body")
		}
	}
	if s.ContentType != "" {
		if _, _, err := mime.ParseMediaType(s.ContentType); err != nil || strings.ContainsAny(s.ContentType, "\r\n") {
			p = append(p, where+": content_type is not a media type")
		}
	}
	keys := make([]string, 0, len(s.HeaderEnv))
	for h := range s.HeaderEnv {
		keys = append(keys, h)
	}
	sort.Strings(keys)
	for _, h := range keys {
		lh := strings.ToLower(h)
		if !headerNameRe.MatchString(h) || reservedHeaders[lh] || lh == "content-type" || lh == "user-agent" || lh == "cookie" && s.As != "" && s.As != Anonymous {
			p = append(p, where+": header_env cannot set "+h)
		}
		if id := ids[s.As]; id != nil && strings.EqualFold(id.Header, h) {
			p = append(p, where+": header_env sets "+h+", which carries the identity's credential")
		}
		if !envNameRe.MatchString(s.HeaderEnv[h]) {
			p = append(p, where+": header_env value for "+h+" must name an environment variable")
		}
	}
	return p
}
