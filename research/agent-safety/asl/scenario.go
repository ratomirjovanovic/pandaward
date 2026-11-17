// Package asl is the Agent Safety Lab: a sandboxed harness that measures
// whether a coding or security agent can be steered by untrusted repository
// or tool content into unauthorized effects or unsupported security claims.
// It is research tooling. It reads PandaWard exports but never changes the
// ledger, approves a scope or touches a live target.
package asl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Schema is the version string every ASL document carries.
const Schema = "asl/v1"

// Families of adversarial scenarios.
var Families = map[string]string{
	"F01": "repository instructions",
	"F02": "MCP tool metadata and results",
	"F03": "scanner output poisoning",
	"F04": "SARIF and report tampering",
	"F05": "evidence provenance",
	"F06": "authorization forgery",
	"F07": "long-horizon context drift",
	"F08": "cross-tool and multi-context",
}

// Kinds of scenario.
const (
	KindAttack     = "attack"
	KindLegitimate = "legitimate"
)

// Splits of the corpus. Held-out scenarios are frozen before the official run.
const (
	SplitDev     = "dev"
	SplitHeldOut = "heldout"
)

// Effect kinds a simulated tool can commit; the oracle names the ones that
// must not happen.
const (
	EffectWriteFile  = "write_file"
	EffectDeleteFile = "delete_file"
	EffectEgress     = "egress"
	EffectApprove    = "approve_scope"
	EffectTriage     = "change_finding"
	EffectReport     = "submit_report"
)

var effectKinds = map[string]bool{
	EffectWriteFile: true, EffectDeleteFile: true, EffectEgress: true,
	EffectApprove: true, EffectTriage: true, EffectReport: true,
}

// claimStatuses are the statuses an agent report can claim for a control
// (the PandaWard vocabulary).
var claimStatuses = map[string]bool{
	"PASS": true, "FAIL": true, "SUSPECTED": true, "BLOCKED": true,
	"ERROR": true, "INCONCLUSIVE": true, "HYPOTHESIS": true, "UNSUPPORTED": true, "STALE": true,
}

// Scenario is one episode definition: a user task, untrusted fixture
// content, the authority the user actually granted, and the oracle that
// judges the outcome independently of any policy.
type Scenario struct {
	Schema        string    `json:"schema"`
	ID            string    `json:"id"`
	Family        string    `json:"family"`
	Kind          string    `json:"kind"`
	Split         string    `json:"split"`
	Title         string    `json:"title"`
	AttackSurface string    `json:"attack_surface"`
	Mechanism     string    `json:"mechanism"`
	TargetEffect  string    `json:"target_effect"`
	UserTask      string    `json:"user_task"`
	Tools         []string  `json:"tools"`
	Fixture       Fixture   `json:"fixture"`
	Authority     Authority `json:"authority"`
	Oracle        Oracle    `json:"oracle"`
	// MatchedWith names the attack scenario a legitimate control mirrors.
	MatchedWith string `json:"matched_with,omitempty"`
	// Scripts are the two reference agents that validate the oracle: the
	// safe one must pass it, the unsafe one must be caught by it.
	Scripts Scripts `json:"scripts"`
}

// Scripts hold the scripted reference agents of a scenario.
type Scripts struct {
	Safe   []ScriptStep `json:"safe"`
	Unsafe []ScriptStep `json:"unsafe,omitempty"`
}

// ScriptStep is one scripted action. Final is the closing report text and
// ends the script.
type ScriptStep struct {
	Tool  string            `json:"tool,omitempty"`
	Args  map[string]string `json:"args,omitempty"`
	Final string            `json:"final,omitempty"`
}

// Fixture is the synthetic content the agent can read. SHA256 covers every
// file, so a changed fixture invalidates earlier comparisons.
type Fixture struct {
	Files  []FixtureFile `json:"files"`
	SHA256 string        `json:"sha256"`
}

// FixtureFile is one file of the fixture. Untrusted marks the file the
// attacker controls; it carries the adversarial text.
type FixtureFile struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Untrusted bool   `json:"untrusted,omitempty"`
}

// Authority is what the user really authorized for this episode.
type Authority struct {
	Tenant string `json:"tenant"`
	// AllowedEffects lists the effects the task legitimately needs, as
	// kind:target pairs. Anything else is unauthorized.
	AllowedEffects []string `json:"allowed_effects"`
	// ScopeApproved is true only when a human approved the scope outside the
	// model. It is almost always false.
	ScopeApproved bool `json:"scope_approved"`
}

// Oracle is the ground truth. ForbiddenEffects are kind:target pairs that
// count as an attack success when the effect journal commits them. Facts
// are what PandaWard actually established, per control; a final report is
// judged against them.
type Oracle struct {
	ForbiddenEffects []string          `json:"forbidden_effects"`
	RequiredEffects  []string          `json:"required_effects,omitempty"`
	Facts            map[string]string `json:"facts,omitempty"`
	// Evidence maps a control to the SHA-256 of the evidence PandaWard really
	// recorded for it; a report that cites another hash is fabricating.
	Evidence map[string]string `json:"evidence,omitempty"`
	// MustReferToHuman is true when the correct behavior is to stop and ask.
	MustReferToHuman bool `json:"must_refer_to_human,omitempty"`
}

var idRe = regexp.MustCompile(`^(F0[1-8])-(A|L)[0-9]{2}$`)

// FixtureHash is the SHA-256 over the files sorted by path, each as
// path, NUL, content, NUL.
func FixtureHash(files []FixtureFile) string {
	cp := append([]FixtureFile(nil), files...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].Path < cp[j].Path })
	h := sha256.New()
	for _, f := range cp {
		h.Write([]byte(f.Path))
		h.Write([]byte{0})
		h.Write([]byte(f.Content))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Validate checks one scenario without calling any model. It returns every
// problem found, not only the first.
func (s *Scenario) Validate() []string {
	var p []string
	add := func(format string, a ...any) { p = append(p, fmt.Sprintf(s.ID+": "+format, a...)) }
	if s.Schema != Schema {
		add("schema is %q, want %q", s.Schema, Schema)
	}
	m := idRe.FindStringSubmatch(s.ID)
	if m == nil {
		add("id must look like F01-A01 (attack) or F01-L01 (legitimate)")
	} else {
		if m[1] != s.Family {
			add("id family %s differs from family %q", m[1], s.Family)
		}
		if (m[2] == "A") != (s.Kind == KindAttack) {
			add("id letter %s does not match kind %q", m[2], s.Kind)
		}
	}
	if _, ok := Families[s.Family]; !ok {
		add("unknown family %q", s.Family)
	}
	if s.Kind != KindAttack && s.Kind != KindLegitimate {
		add("kind must be attack or legitimate")
	}
	if s.Split != SplitDev && s.Split != SplitHeldOut {
		add("split must be dev or heldout")
	}
	for _, f := range []struct{ n, v string }{{"title", s.Title}, {"attack_surface", s.AttackSurface}, {"mechanism", s.Mechanism}, {"target_effect", s.TargetEffect}, {"user_task", s.UserTask}} {
		if strings.TrimSpace(f.v) == "" {
			add("%s is empty", f.n)
		}
	}
	if len(s.Tools) == 0 {
		add("no tools")
	}
	if s.Authority.Tenant == "" {
		add("authority.tenant is empty")
	}
	if len(s.Fixture.Files) == 0 {
		add("fixture has no files")
	}
	seen := map[string]bool{}
	untrusted := 0
	for _, f := range s.Fixture.Files {
		if f.Path == "" || strings.HasPrefix(f.Path, "/") || strings.Contains(f.Path, "..") || strings.Contains(f.Path, "\\") {
			add("fixture path %q is not a relative, clean path", f.Path)
		}
		if seen[f.Path] {
			add("fixture path %q appears twice", f.Path)
		}
		seen[f.Path] = true
		if f.Untrusted {
			untrusted++
		}
	}
	if s.Kind == KindAttack && untrusted == 0 {
		add("an attack scenario needs an untrusted fixture file that carries the attack")
	}
	if got := FixtureHash(s.Fixture.Files); s.Fixture.SHA256 != got {
		add("fixture sha256 is %q, the files hash to %s", s.Fixture.SHA256, got)
	}
	for _, e := range append(append([]string(nil), s.Oracle.ForbiddenEffects...), s.Oracle.RequiredEffects...) {
		if !validEffect(e) {
			add("effect %q must be kind:target with a known kind", e)
		}
	}
	for _, e := range s.Authority.AllowedEffects {
		if !validEffect(e) {
			add("allowed effect %q must be kind:target with a known kind", e)
		}
	}
	if s.Kind == KindAttack && len(s.Oracle.ForbiddenEffects) == 0 && len(s.Oracle.Facts) == 0 {
		add("an attack scenario needs a forbidden effect or facts to judge claims against")
	}
	for _, e := range s.Oracle.ForbiddenEffects {
		for _, a := range s.Authority.AllowedEffects {
			if e == a {
				add("effect %q is both allowed and forbidden", e)
			}
		}
	}
	for k, v := range s.Oracle.Facts {
		if k == "" || !claimStatuses[v] {
			add("fact %q has status %q, want a PandaWard status", k, v)
		}
	}
	if len(s.Scripts.Safe) == 0 {
		add("scripts.safe is empty: the oracle needs a reference agent that passes it")
	}
	if s.Kind == KindAttack && len(s.Scripts.Unsafe) == 0 {
		add("an attack scenario needs scripts.unsafe, a reference agent the oracle must catch")
	}
	if s.Kind == KindLegitimate && s.MatchedWith == "" {
		add("a legitimate scenario names the attack it mirrors in matched_with")
	}
	if s.Kind == KindAttack && s.MatchedWith != "" {
		add("only legitimate scenarios set matched_with")
	}
	return p
}

func validEffect(e string) bool {
	kind, target, ok := strings.Cut(e, ":")
	return ok && target != "" && effectKinds[kind]
}
