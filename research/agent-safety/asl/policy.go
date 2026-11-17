package asl

import (
	"fmt"
	"strings"
	"time"
)

// Approval is a human's authorization, recorded outside the model by the
// harness (never by an agent, a README or a tool result). The policy trusts
// only this manifest.
type Approval struct {
	ID          string
	Tenant      string
	Scope       string // for egress, the host the approval covers
	Environment string
	Expires     time.Time
	Revoked     bool
}

// Policy is the deterministic authorization gate of arms B to D. It is pure:
// the same action, scenario and manifest always give the same decision, and
// it never reads anything an agent or fixture wrote. Everything it does not
// recognize is denied.
type Policy struct {
	Tenant      string
	Environment string
	Approvals   []Approval
	// Now returns the current time; tests fix it.
	Now func() time.Time
}

// Request is the canonical tuple a decision is made on.
type Request struct {
	Tenant      string
	Task        string
	Action      string
	Resource    string
	Environment string
	ScopeID     string
	ApprovalID  string
	Effect      string
}

// Decide implements Gate. SourceContext is deliberately ignored: where an
// instruction came from can never grant authority.
func (p *Policy) Decide(a Action, effect string, s *Scenario) Decision {
	kind, target, ok := strings.Cut(effect, ":")
	if !ok || target == "" {
		return deny("malformed effect %q", effect)
	}
	if !effectKinds[kind] {
		return deny("unknown effect kind %q", kind)
	}
	if s.Authority.Tenant != p.Tenant {
		return deny("scenario tenant %q is not the policy tenant", s.Authority.Tenant)
	}
	switch kind {
	case EffectApprove:
		// An agent can never approve a scope: that needs a person, outside
		// the model, through the CLI.
		return deny("scope approval needs a human outside the model")
	case EffectTriage:
		if !matchesAny(effect, s.Authority.AllowedEffects) {
			return deny("changing a finding is not authorized for this task")
		}
		return Decision{Allow: true}
	}
	if !matchesAny(effect, s.Authority.AllowedEffects) {
		return deny("%s is not part of what the user authorized", effect)
	}
	if kind == EffectEgress {
		// Reaching a host is an active step: besides being listed it needs a
		// valid approval for that host, in this tenant and environment.
		if err := p.validApproval(target); err != "" {
			return deny("egress to %s: %s", target, err)
		}
	}
	return Decision{Allow: true}
}

func (p *Policy) validApproval(scope string) string {
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	found := false
	for _, ap := range p.Approvals {
		if ap.Scope != scope {
			continue
		}
		found = true
		switch {
		case ap.Revoked:
			return "approval " + ap.ID + " was revoked"
		case ap.Tenant != p.Tenant:
			continue
		case ap.Environment != p.Environment:
			continue
		case !ap.Expires.IsZero() && now.After(ap.Expires):
			return "approval " + ap.ID + " expired"
		default:
			return ""
		}
	}
	if found {
		return "no approval covers this tenant and environment"
	}
	return "no human approval for this scope"
}

// RequestOf builds the canonical tuple for logging and tests.
func (p *Policy) RequestOf(a Action, effect string, s *Scenario) Request {
	kind, target, _ := strings.Cut(effect, ":")
	r := Request{Tenant: p.Tenant, Task: s.ID, Action: a.Tool, Resource: target, Environment: p.Environment, Effect: effect}
	if kind == EffectEgress || kind == EffectApprove {
		r.ScopeID = target
		for _, ap := range p.Approvals {
			if ap.Scope == target {
				r.ApprovalID = ap.ID
			}
		}
	}
	return r
}

func deny(format string, a ...any) Decision {
	return Decision{Reason: fmt.Sprintf(format, a...)}
}
