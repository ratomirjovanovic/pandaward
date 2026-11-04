package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/store"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// attestProject is a small web project with a scan, so the manual controls
// A-004 and C-003 apply and are BLOCKED.
func attestProject(t *testing.T) *Engine {
	t.Helper()
	root := t.TempDir()
	testfixture.Write(t, root, "package.json", `{"name":"shop","dependencies":{"express":"4.21.0"}}`)
	testfixture.Write(t, root, "src/server.js", "const express = require('express');\nconst app = express();\napp.use(requireUser);\napp.get('/orders/:id', requireOwner, getOrder);\napp.listen(3000);\n")
	testfixture.Write(t, root, "src/auth.js", "function requireOwner(req, res, next) {\n  if (req.order.userId !== req.user.id) return res.sendStatus(403);\n  next();\n}\n")
	testfixture.Write(t, root, "docs/threat-model.md", "# Threat model\n\nAssets: orders, accounts.\n")
	e, _ := scan(t, root)
	t.Cleanup(func() { e.Close() })
	cs := latest(t, e)
	for _, id := range []string{"A-004", "C-003"} {
		if cs[id].Status != model.StatusBlocked {
			t.Fatalf("%s before attestation: %s (%s)", id, cs[id].Status, cs[id].Reason)
		}
	}
	return e
}

func latest(t *testing.T, e *Engine) map[string]model.ControlResult {
	t.Helper()
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil || a == nil {
		t.Fatal(a, err)
	}
	return controlMap(t, e, a.ID)
}

func rescanAttest(t *testing.T, e *Engine) map[string]model.ControlResult {
	t.Helper()
	if _, err := e.Scan(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	return latest(t, e)
}

func c003Proposal(verdict string) AttestationInput {
	return AttestationInput{ControlID: "C-003", Verdict: verdict, Proposer: "pandaward:identity",
		Evidence: []CitationInput{
			{File: "src/server.js", Line: 4, Why: "the only order route runs requireOwner"},
			{File: "src/auth.js", Line: 2, Why: "requireOwner rejects other users with 403"},
		},
		Command: "npm test -- authz"}
}

func propose(t *testing.T, e *Engine, in AttestationInput) *store.Attestation {
	t.Helper()
	a, err := e.ProposeAttestation(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != store.AttestPending {
		t.Fatalf("a proposal must be pending, got %s", a.Status)
	}
	return a
}

func TestProposeAttestationValidation(t *testing.T) {
	e := attestProject(t)
	for name, tc := range map[string]struct {
		in   AttestationInput
		want string
	}{
		"no evidence":       {AttestationInput{ControlID: "C-003", Verdict: "PASS"}, "evidence is required"},
		"missing file":      {AttestationInput{ControlID: "C-003", Verdict: "PASS", Evidence: []CitationInput{{File: "src/nope.js", Line: 1, Why: "x"}}}, "does not exist"},
		"outside the root":  {AttestationInput{ControlID: "C-003", Verdict: "PASS", Evidence: []CitationInput{{File: "../secret.js", Line: 1, Why: "x"}}}, "inside the project"},
		"absolute path":     {AttestationInput{ControlID: "C-003", Verdict: "PASS", Evidence: []CitationInput{{File: e.Root + "/src/auth.js", Line: 1, Why: "x"}}}, "inside the project"},
		"private ledger":    {AttestationInput{ControlID: "C-003", Verdict: "PASS", Evidence: []CitationInput{{File: ".pandaward/config.yaml", Line: 1, Why: "x"}}}, "inside the project"},
		"line out of range": {AttestationInput{ControlID: "C-003", Verdict: "PASS", Evidence: []CitationInput{{File: "src/auth.js", Line: 5, Why: "x"}}}, "outside 1..4"},
		"line zero":         {AttestationInput{ControlID: "C-003", Verdict: "PASS", Evidence: []CitationInput{{File: "src/auth.js", Line: 0, Why: "x"}}}, "outside 1..4"},
		"no why":            {AttestationInput{ControlID: "C-003", Verdict: "PASS", Evidence: []CitationInput{{File: "src/auth.js", Line: 1}}}, "why is required"},
		"bad verdict":       {AttestationInput{ControlID: "C-003", Verdict: "SUSPECTED", Evidence: []CitationInput{{File: "src/auth.js", Line: 1, Why: "x"}}}, "PASS or FAIL"},
		"rule-based":        {AttestationInput{ControlID: "D-001", Verdict: "PASS", Evidence: []CitationInput{{File: "src/auth.js", Line: 1, Why: "x"}}}, "not a manual control"},
		"runtime":           {AttestationInput{ControlID: "C-001", Verdict: "PASS", Evidence: []CitationInput{{File: "src/auth.js", Line: 1, Why: "x"}}}, "not a manual control"},
		"unknown control":   {AttestationInput{ControlID: "Z-999", Verdict: "PASS", Evidence: []CitationInput{{File: "src/auth.js", Line: 1, Why: "x"}}}, "unknown control"},
	} {
		_, err := e.ProposeAttestation(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, tc.want)
		}
	}
	if as, _ := e.St.Attestations(e.ProjectID); len(as) != 0 {
		t.Errorf("rejected proposals must not be stored: %+v", as)
	}
	// A non-manual control names the ones that can be attested.
	if _, err := e.ProposeAttestation(AttestationInput{ControlID: "D-001", Verdict: "PASS", Evidence: []CitationInput{{File: "src/auth.js", Line: 1, Why: "x"}}}); !strings.Contains(err.Error(), "A-004, C-003, F-001, O-001, Q-001") {
		t.Errorf("the error should list the manual controls: %v", err)
	}
}

func TestProposalRedactsAndDecidesNothing(t *testing.T) {
	e := attestProject(t)
	in := c003Proposal("PASS")
	in.Evidence[0].Why = "checked with token ghp_" + strings.Repeat("a", 36)
	a := propose(t, e, in)
	if strings.Contains(a.Citations[0].Why, strings.Repeat("a", 36)) {
		t.Errorf("why must be redacted: %q", a.Citations[0].Why)
	}
	if a.Citations[0].SHA256 == "" || !strings.Contains(a.Citations[0].Snippet, "requireOwner") {
		t.Errorf("PandaWard reads and hashes the cited file itself: %+v", a.Citations[0])
	}
	cs := rescanAttest(t, e)
	if cs["C-003"].Status != model.StatusBlocked || cs["C-003"].DecidedBy != "" {
		t.Errorf("a pending proposal must decide nothing: %+v", cs["C-003"])
	}
	s, err := e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.PendingAttestations) != 1 || s.PendingAttestations[0].ControlID != "C-003" {
		t.Errorf("status must show the pending proposal: %+v / %q", s.PendingAttestations, s.NextAction)
	}
	// A new proposal replaces the pending one.
	b := propose(t, e, c003Proposal("FAIL"))
	if p, _ := e.PendingAttestation("C-003"); p == nil || p.ID != b.ID {
		t.Errorf("the newest proposal must be the pending one: %+v", p)
	}
}

func TestAcceptDecidesOnNextScan(t *testing.T) {
	e := attestProject(t)
	if _, err := e.DecideAttestation("C-003", true, "Ana", "ok"); err == nil || !strings.Contains(err.Error(), "no pending attestation") {
		t.Fatalf("accepting nothing must fail: %v", err)
	}
	propose(t, e, c003Proposal("PASS"))
	if _, err := e.DecideAttestation("C-003", true, " ", "ok"); err == nil {
		t.Fatal("a decision needs --by")
	}
	a, err := e.DecideAttestation("C-003", true, "Ana", "walked every route with the team")
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != store.AttestAccepted || a.ExpiresAt == "" || a.Citations[0].AcceptedSHA256 == "" {
		t.Fatalf("accepted: %+v", a)
	}
	// The stored assessment still says BLOCKED; the next scan decides it.
	cs := rescanAttest(t, e)
	c := cs["C-003"]
	if c.Status != model.StatusPass || c.DecidedBy != model.DecidedAttested {
		t.Fatalf("C-003 after acceptance: %+v", c)
	}
	for _, want := range []string{"attested by Ana on " + time.Now().UTC().Format("2006-01-02"), "walked every route with the team", "evidence: 2 citation(s)"} {
		if !strings.Contains(c.Reason, want) {
			t.Errorf("reason %q lacks %q", c.Reason, want)
		}
	}
	// The stale view keeps it, and an edit outside the cited files (even in
	// the same domain) does not invalidate it.
	testfixture.Write(t, e.Root, "src/other.js", "app.get('/health', ok);\n")
	markChanged(t, e, "src/other.js")
	cm, _ := staleView(t, e)
	if cm["C-003"].Status != model.StatusPass {
		t.Errorf("an uncited file must not make the attestation stale: %+v", cm["C-003"])
	}
	cov := ComputeCoverage(func() []model.ControlResult {
		var out []model.ControlResult
		for _, c := range cm {
			out = append(out, c)
		}
		return out
	}(), nil, 0)
	if cov.Attested != 1 {
		t.Errorf("coverage must count the attested control: %+v", cov)
	}
	// A rescan keeps it.
	if cs := rescanAttest(t, e); cs["C-003"].Status != model.StatusPass {
		t.Errorf("a second scan must keep it: %+v", cs["C-003"])
	}
}

func TestFailAttestationAndReject(t *testing.T) {
	e := attestProject(t)
	propose(t, e, AttestationInput{ControlID: "A-004", Verdict: "FAIL", Proposer: "pandaward:architect",
		Evidence: []CitationInput{{File: "docs/threat-model.md", Line: 3, Why: "no abuse cases or trust boundaries are listed"}}})
	if _, err := e.DecideAttestation("A-004", true, "Ana", "agreed"); err != nil {
		t.Fatal(err)
	}
	propose(t, e, c003Proposal("PASS"))
	r, err := e.DecideAttestation("C-003", false, "Ana", "the admin routes were not reviewed")
	if err != nil || r.Status != store.AttestRejected {
		t.Fatalf("reject: %+v %v", r, err)
	}
	if p, _ := e.PendingAttestation("C-003"); p != nil {
		t.Errorf("nothing is pending after a rejection: %+v", p)
	}
	before, _ := e.St.Findings(e.ProjectID)
	cs := rescanAttest(t, e)
	if cs["A-004"].Status != model.StatusFail || cs["A-004"].DecidedBy != model.DecidedAttested {
		t.Errorf("A-004 after a FAIL attestation: %+v", cs["A-004"])
	}
	if cs["C-003"].Status != model.StatusBlocked {
		t.Errorf("a rejected proposal decides nothing: %+v", cs["C-003"])
	}
	after, _ := e.St.Findings(e.ProjectID)
	if len(after) != len(before) {
		t.Errorf("a FAIL attestation must not create findings: %d -> %d", len(before), len(after))
	}
}

func TestAttestationStaleOnCitedFileEdit(t *testing.T) {
	e := attestProject(t)
	propose(t, e, c003Proposal("PASS"))
	if _, err := e.DecideAttestation("C-003", true, "Ana", ""); err != nil {
		t.Fatal(err)
	}
	rescanAttest(t, e)
	testfixture.Write(t, e.Root, "src/auth.js", "function requireOwner(req, res, next) {\n  next();\n}\n")
	// Status and reports see it at once, naming the file.
	cm, _ := staleView(t, e)
	if c := cm["C-003"]; c.Status != model.StatusStale || !strings.Contains(c.Reason, "src/auth.js") || strings.Contains(c.Reason, "src/server.js") {
		t.Errorf("stale view after editing a cited file: %+v", c)
	}
	if c := cm["C-003"]; !strings.Contains(NextStep(c, 0).Text, "pandaward attest C-003 --accept") {
		t.Errorf("next step must ask for a fresh attestation: %q", NextStep(c, 0).Text)
	}
	// The next scan records it, and it stays stale.
	cs := rescanAttest(t, e)
	if c := cs["C-003"]; c.Status != model.StatusStale || !strings.Contains(c.Reason, "cited file(s) changed since it was accepted: src/auth.js") {
		t.Errorf("scan after editing a cited file: %+v", c)
	}
	if cs := rescanAttest(t, e); cs["C-003"].Status != model.StatusStale {
		t.Errorf("a stale attestation stays stale: %+v", cs["C-003"])
	}
	// A fresh proposal accepted by a person decides it again.
	propose(t, e, c003Proposal("PASS"))
	if _, err := e.DecideAttestation("C-003", true, "Ana", "re-reviewed"); err != nil {
		t.Fatal(err)
	}
	if cs := rescanAttest(t, e); cs["C-003"].Status != model.StatusPass {
		t.Errorf("after a fresh attestation: %+v", cs["C-003"])
	}
}

func TestAttestationStaleOnAgeAndCatalog(t *testing.T) {
	e := attestProject(t)
	for _, id := range []string{"A-004", "C-003"} {
		in := c003Proposal("PASS")
		in.ControlID = id
		propose(t, e, in)
		if _, err := e.DecideAttestation(id, true, "Ana", ""); err != nil {
			t.Fatal(err)
		}
	}
	if cs := rescanAttest(t, e); cs["A-004"].Status != model.StatusPass || cs["C-003"].Status != model.StatusPass {
		t.Fatalf("both attested: %+v / %+v", cs["A-004"], cs["C-003"])
	}
	// A-004 was accepted 200 days ago; C-003 under an older catalog.
	old := time.Now().UTC().AddDate(0, 0, -200)
	if _, err := e.St.DB.Exec(`UPDATE attestations SET decided_at=?, expires_at=? WHERE control_id='A-004'`, old.Format(time.RFC3339), old.AddDate(0, 0, 180).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.St.DB.Exec(`UPDATE attestations SET catalog_version='2026.01-m1' WHERE control_id='C-003'`); err != nil {
		t.Fatal(err)
	}
	cm, _ := staleView(t, e)
	if c := cm["A-004"]; c.Status != model.StatusStale || !strings.Contains(c.Reason, "expired on") {
		t.Errorf("stale view, old attestation: %+v", c)
	}
	if c := cm["C-003"]; c.Status != model.StatusStale || !strings.Contains(c.Reason, "catalog changed") {
		t.Errorf("stale view, catalog bump: %+v", c)
	}
	cs := rescanAttest(t, e)
	if c := cs["A-004"]; c.Status != model.StatusStale || !strings.Contains(c.Reason, "expired on") {
		t.Errorf("scan, old attestation: %+v", c)
	}
	if c := cs["C-003"]; c.Status != model.StatusStale || !strings.Contains(c.Reason, "catalog changed") {
		t.Errorf("scan, catalog bump: %+v", c)
	}
	as, _ := e.St.Attestations(e.ProjectID)
	for _, a := range as {
		if a.Status != store.AttestStale {
			t.Errorf("the ledger must record %s as stale: %+v", a.ControlID, a)
		}
	}
}

func TestLowerMaxAgeExpiresEarlier(t *testing.T) {
	e := attestProject(t)
	propose(t, e, c003Proposal("PASS"))
	if _, err := e.DecideAttestation("C-003", true, "Ana", ""); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().AddDate(0, 0, -40)
	if _, err := e.St.DB.Exec(`UPDATE attestations SET decided_at=? WHERE control_id='C-003'`, old.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if cs := rescanAttest(t, e); cs["C-003"].Status != model.StatusPass {
		t.Fatalf("40 days old with the default of 180: %+v", cs["C-003"])
	}
	e.Cfg.Attest.MaxAgeDays = 30
	if cs := rescanAttest(t, e); cs["C-003"].Status != model.StatusStale {
		t.Errorf("attest.max_age_days lowered to 30: %+v", cs["C-003"])
	}
}

func TestAcceptRefusedWhenCitedFileChanged(t *testing.T) {
	e := attestProject(t)
	propose(t, e, c003Proposal("PASS"))
	testfixture.Write(t, e.Root, "src/server.js", "const app = require('express')();\napp.get('/orders/:id', getOrder);\n")
	_, err := e.DecideAttestation("C-003", true, "Ana", "")
	if err == nil || !strings.Contains(err.Error(), "src/server.js") || !strings.Contains(err.Error(), "fresh proposal") {
		t.Fatalf("accept after a cited file changed: %v", err)
	}
	if p, _ := e.PendingAttestation("C-003"); p != nil {
		t.Errorf("the refused proposal must not stay pending: %+v", p)
	}
	if cs := rescanAttest(t, e); cs["C-003"].Status != model.StatusBlocked {
		t.Errorf("a refused proposal decides nothing: %+v", cs["C-003"])
	}
}
