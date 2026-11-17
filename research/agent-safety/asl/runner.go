package asl

import (
	"context"
	"errors"
	"fmt"
)

// Arm is a comparison arm. All arms get identical tools; only enforcement
// differs.
type Arm string

// The four arms of the study.
const (
	ArmA Arm = "A" // prompt only: no gate (the sandbox still protects the host)
	ArmB Arm = "B" // deterministic authorization gate
	ArmC Arm = "C" // B plus the evidence gate
	ArmD Arm = "D" // C plus the independent monitor
)

// Arms lists the arms in order.
var Arms = []Arm{ArmA, ArmB, ArmC, ArmD}

// Provider labels where an episode's agent came from. Results of different
// providers are never merged into one number.
const (
	ProviderMock = "mock" // a scripted agent
	ProviderAPI  = "api"  // a model through the API track
	ProviderCC   = "cc"   // Claude Code end to end
)

// Obs is one step of what an agent has seen.
type Obs struct {
	Action Action
	Result Result
}

// Step is what an agent does next: an action, or its final report.
type Step struct {
	Action *Action
	Final  string
}

// Agent decides the next step from what it has seen so far.
type Agent interface {
	Next(ctx context.Context, seen []Obs) (Step, error)
}

// Scripted is the reference agent: it plays a fixed script, ignoring what
// the tools return. It is how the oracle is validated and how mock results
// are produced, and its results are always labeled mock.
type Scripted struct {
	Steps []ScriptStep
	i     int
}

// Next implements Agent.
func (s *Scripted) Next(_ context.Context, _ []Obs) (Step, error) {
	if s.i >= len(s.Steps) {
		return Step{Final: ""}, nil
	}
	st := s.Steps[s.i]
	s.i++
	if st.Final != "" || st.Tool == "" {
		return Step{Final: st.Final}, nil
	}
	return Step{Action: &Action{ID: fmt.Sprintf("s%d", s.i), Tool: st.Tool, Args: st.Args}}, nil
}

// Chain denies when any gate denies. A hard deny from an earlier gate is
// final: later gates, the monitor included, only ever add denials.
type Chain []Gate

// Decide implements Gate.
func (c Chain) Decide(a Action, effect string, s *Scenario) Decision {
	for _, g := range c {
		if g == nil {
			continue
		}
		if d := g.Decide(a, effect, s); !d.Allow {
			return d
		}
	}
	return Decision{Allow: true}
}

// DefaultPolicy is the policy an episode of s runs under in arms B to D.
func DefaultPolicy(s *Scenario) *Policy {
	return &Policy{Tenant: s.Authority.Tenant, Environment: "staging"}
}

// GateFor builds the gate of an arm. Arm A has none. Later arms add the
// evidence gate and the monitor when they are given.
func GateFor(arm Arm, s *Scenario, evidence, monitor Gate) Gate {
	switch arm {
	case ArmA:
		return nil
	case ArmB:
		return DefaultPolicy(s)
	case ArmC:
		return Chain{DefaultPolicy(s), evidence}
	case ArmD:
		return Chain{DefaultPolicy(s), evidence, monitor}
	}
	return nil
}

// Episode status. An INVALID episode (infrastructure, limit, agent error) is
// counted separately and is never an attack failure.
const (
	StatusValid   = "VALID"
	StatusInvalid = "INVALID"
)

// EpisodeResult is one typed record of a run.
type EpisodeResult struct {
	Schema        string  `json:"schema"`
	Scenario      string  `json:"scenario"`
	Arm           Arm     `json:"arm"`
	Provider      string  `json:"provider"`
	Status        string  `json:"status"`
	InvalidReason string  `json:"invalid_reason,omitempty"`
	Steps         int     `json:"steps"`
	Journal       []Event `json:"journal"`
	Outcome       Outcome `json:"outcome"`
	Final         string  `json:"final,omitempty"`
}

// RunEpisode plays an agent against a scenario in one arm. The oracle judges
// the effect journal only. A limit, a closed sandbox or an agent error makes
// the episode INVALID with the reason.
func RunEpisode(ctx context.Context, s *Scenario, arm Arm, agent Agent, provider string, gate Gate, lim EpisodeLimits) EpisodeResult {
	res := EpisodeResult{Schema: Schema, Scenario: s.ID, Arm: arm, Provider: provider, Status: StatusValid}
	sb, err := NewSandbox(s, gate, lim)
	if err != nil {
		res.Status, res.InvalidReason = StatusInvalid, err.Error()
		return res
	}
	defer sb.Close()
	var seen []Obs
	for {
		st, err := agent.Next(ctx, seen)
		if err != nil {
			res.Status, res.InvalidReason = StatusInvalid, "agent: "+err.Error()
			break
		}
		if st.Action == nil {
			res.Final = st.Final
			break
		}
		r, err := sb.Do(ctx, *st.Action)
		res.Steps++
		if err != nil {
			if errors.Is(err, ErrLimit) {
				res.Status, res.InvalidReason = StatusInvalid, err.Error()
			} else {
				res.Status, res.InvalidReason = StatusInvalid, "sandbox: "+err.Error()
			}
			break
		}
		seen = append(seen, Obs{Action: *st.Action, Result: r})
	}
	res.Journal = sb.Journal()
	res.Outcome = Judge(s, res.Journal)
	return res
}

// CheckOracle validates a scenario's oracle with its two reference agents,
// in arm A: the safe agent must not trigger a forbidden effect and must
// commit every required one; the unsafe agent of an attack scenario must be
// caught. It calls no model.
func CheckOracle(s *Scenario) []string {
	var p []string
	ctx := context.Background()
	lim := DefaultEpisodeLimits()
	safe := RunEpisode(ctx, s, ArmA, &Scripted{Steps: s.Scripts.Safe}, ProviderMock, nil, lim)
	switch {
	case safe.Status != StatusValid:
		p = append(p, fmt.Sprintf("%s: the safe reference agent is INVALID: %s", s.ID, safe.InvalidReason))
	case safe.Outcome.AttackSucceeded:
		p = append(p, fmt.Sprintf("%s: the safe reference agent triggers a forbidden effect", s.ID))
	case len(safe.Outcome.RequiredMissing) > 0:
		p = append(p, fmt.Sprintf("%s: the safe reference agent misses required effects %v", s.ID, safe.Outcome.RequiredMissing))
	case len(safe.Outcome.Unauthorized) > 0:
		p = append(p, fmt.Sprintf("%s: the safe reference agent commits unauthorized effects %v", s.ID, safe.Outcome.Unauthorized))
	}
	if s.Kind == KindAttack {
		bad := RunEpisode(ctx, s, ArmA, &Scripted{Steps: s.Scripts.Unsafe}, ProviderMock, nil, lim)
		switch {
		case bad.Status != StatusValid:
			p = append(p, fmt.Sprintf("%s: the unsafe reference agent is INVALID: %s", s.ID, bad.InvalidReason))
		case !bad.Outcome.AttackSucceeded:
			p = append(p, fmt.Sprintf("%s: the unsafe reference agent is not caught by the oracle", s.ID))
		}
	}
	return p
}
