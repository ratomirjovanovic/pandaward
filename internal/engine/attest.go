package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/store"
)

// Manual controls (catalog method manual) cannot be decided by automation.
// A reviewer, usually a PandaWard review agent, proposes a PASS or FAIL
// verdict with file:line evidence; the proposal is stored as pending and
// decides nothing. Only a person accepts or rejects it with `pandaward
// attest`, which the PreToolUse hook turns into a confirmation prompt when
// an agent runs it, and which no MCP tool exposes.
//
// An accepted attestation decides its control in every later scan and in
// reports, with decided_by attested, while it is valid: every cited file
// still has the content the person accepted, the catalog version is the
// same and it is younger than attest.max_age_days (180 by default, at most
// a year). Otherwise the control is STALE, with a reason naming what
// changed, and stays STALE until a new attestation is accepted.
//
// A FAIL attestation decides the control as FAIL but creates no finding:
// the concrete problem is a separate hypothesis the reviewer records with
// pandaward_record_hypothesis, and a person confirms it with `pandaward
// findings apply` as for any other reviewer finding.

// Limits for one proposal.
const (
	maxCitations  = 20
	maxWhyLen     = 1000
	maxCommandLen = 500
)

// CitationInput is one piece of evidence of a proposal.
type CitationInput struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Why  string `json:"why"`
}

// AttestationInput is a proposed verdict for a manual control.
type AttestationInput struct {
	ControlID string          `json:"control_id"`
	Verdict   string          `json:"verdict"`
	Evidence  []CitationInput `json:"evidence"`
	// Command optionally names a test or command that shows the verdict.
	Command  string `json:"command,omitempty"`
	Proposer string `json:"proposer,omitempty"`
}

// ManualControls lists the IDs of the controls that can be attested.
func ManualControls() []string {
	var out []string
	for _, c := range catalog.Controls {
		if c.Method == catalog.MethodManual {
			out = append(out, c.ID)
		}
	}
	return out
}

// attestable returns the catalog control when it can be attested.
func attestable(id string) (*catalog.Control, error) {
	c := catalog.ControlByID(id)
	if c == nil {
		return nil, fmt.Errorf("unknown control %q", id)
	}
	if c.Method != catalog.MethodManual {
		how := "the " + c.Method + " checks"
		if c.Adapter != "" {
			how += " of " + c.Adapter
		}
		return nil, fmt.Errorf("%s is not a manual control and cannot be attested: it is decided by %s. Only manual controls can be attested: %s", id, how, strings.Join(ManualControls(), ", "))
	}
	return c, nil
}

func newAttestationID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "att_" + hex.EncodeToString(b), nil
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// lineCount counts the lines of a file; a final newline does not start one.
func lineCount(lines []string) int {
	n := len(lines)
	if n > 1 && lines[n-1] == "" {
		n--
	}
	return n
}

// ProposeAttestation validates a proposal and stores it as pending. It
// replaces an earlier pending proposal for the same control. It never
// decides anything.
func (e *Engine) ProposeAttestation(in AttestationInput) (*store.Attestation, error) {
	if _, err := attestable(in.ControlID); err != nil {
		return nil, err
	}
	verdict := model.Status(strings.ToUpper(strings.TrimSpace(in.Verdict)))
	if verdict != model.StatusPass && verdict != model.StatusFail {
		return nil, errors.New("verdict must be PASS or FAIL")
	}
	if len(in.Evidence) == 0 {
		return nil, errors.New("evidence is required: cite at least one file and line that shows the verdict")
	}
	if len(in.Evidence) > maxCitations {
		return nil, fmt.Errorf("at most %d citations per proposal", maxCitations)
	}
	if len(in.Command) > maxCommandLen {
		return nil, fmt.Errorf("command is limited to %d characters", maxCommandLen)
	}
	if a, err := e.St.LatestAssessment(e.ProjectID); err != nil {
		return nil, err
	} else if a != nil {
		cs, err := e.St.Controls(a.ID)
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			if c.ID == in.ControlID && c.Status == model.StatusNotApplicable {
				return nil, fmt.Errorf("%s is not applicable to this project (%s); there is nothing to attest", c.ID, c.Reason)
			}
		}
	}
	var cites []store.Citation
	for i, ev := range in.Evidence {
		why := strings.TrimSpace(redact.Text(ev.Why))
		if why == "" {
			return nil, fmt.Errorf("evidence %d: why is required: say what the cited line shows", i+1)
		}
		if len(why) > maxWhyLen {
			return nil, fmt.Errorf("evidence %d: why is limited to %d characters", i+1, maxWhyLen)
		}
		clean, b, err := e.readCited(ev.File)
		if err != nil {
			return nil, fmt.Errorf("evidence %d: %w", i+1, err)
		}
		lines := strings.Split(string(b), "\n")
		if n := lineCount(lines); ev.Line < 1 || ev.Line > n {
			return nil, fmt.Errorf("evidence %d: line %d of %s is outside 1..%d", i+1, ev.Line, clean, n)
		}
		cites = append(cites, store.Citation{File: clean, Line: ev.Line, Why: why, SHA256: sha(b),
			Snippet: redact.Line(strings.TrimSpace(strings.TrimRight(lines[ev.Line-1], "\r")))})
	}
	proposer := strings.TrimSpace(redact.Line(in.Proposer))
	if proposer == "" {
		proposer = "unspecified"
	}
	all, err := e.St.Attestations(e.ProjectID)
	if err != nil {
		return nil, err
	}
	id, err := newAttestationID()
	if err != nil {
		return nil, err
	}
	a := store.Attestation{ID: id, ControlID: in.ControlID, Verdict: verdict, Status: store.AttestPending, ProposedBy: proposer, Citations: cites,
		Command: redact.Line(strings.TrimSpace(in.Command)), CatalogVersion: catalog.Version, CreatedAt: store.Now()}
	for _, old := range all {
		if old.ControlID == in.ControlID && old.Status == store.AttestPending {
			old.Status, old.StaleReason = store.AttestStale, "superseded by proposal "+id
			if err := e.St.PutAttestation(e.ProjectID, old); err != nil {
				return nil, err
			}
		}
	}
	if err := e.St.PutAttestation(e.ProjectID, a); err != nil {
		return nil, err
	}
	return &a, e.St.Event(e.ProjectID, "attest:"+a.ControlID, "", "PENDING", fmt.Sprintf("%s proposed %s by %s with %d citation(s)", a.ID, a.Verdict, proposer, len(cites)))
}

// PendingAttestation returns the pending proposal of a control, or nil.
func (e *Engine) PendingAttestation(controlID string) (*store.Attestation, error) {
	all, err := e.St.Attestations(e.ProjectID)
	if err != nil {
		return nil, err
	}
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].ControlID == controlID && all[i].Status == store.AttestPending {
			return &all[i], nil
		}
	}
	return nil, nil
}

// changedCitations re-hashes every cited file against the hash in want and
// names the ones that changed or are gone.
func (e *Engine) changedCitations(cs []store.Citation, want func(store.Citation) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cs {
		if seen[c.File] {
			continue
		}
		seen[c.File] = true
		_, b, err := e.readCited(c.File)
		switch {
		case err != nil:
			out = append(out, c.File+" (deleted or unreadable)")
		case sha(b) != want(c):
			out = append(out, c.File)
		}
	}
	sort.Strings(out)
	return out
}

// DecideAttestation records a person's decision on the pending proposal of
// a control. Accepting re-hashes every cited file and refuses when one
// changed since the proposal, because the person would be accepting
// evidence that is no longer there; that proposal becomes stale.
func (e *Engine) DecideAttestation(controlID string, accept bool, by, note string) (*store.Attestation, error) {
	if _, err := attestable(controlID); err != nil {
		return nil, err
	}
	by = strings.TrimSpace(redact.Line(by))
	if by == "" {
		return nil, errors.New("--by <name> is required: the person who decides")
	}
	a, err := e.PendingAttestation(controlID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("no pending attestation for %s: a reviewer proposes one first (/pandaward:review)", controlID)
	}
	now := time.Now().UTC()
	if !accept {
		a.Status, a.DecidedBy, a.Note, a.DecidedAt = store.AttestRejected, by, redact.Text(strings.TrimSpace(note)), now.Format(time.RFC3339)
		if err := e.St.PutAttestation(e.ProjectID, *a); err != nil {
			return nil, err
		}
		return a, e.St.Event(e.ProjectID, "attest:"+controlID, "PENDING", "REJECTED", a.ID+" rejected by "+by)
	}
	refuse := ""
	if a.CatalogVersion != catalog.Version {
		refuse = "the control catalog changed since the proposal (" + a.CatalogVersion + " -> " + catalog.Version + ")"
	} else if changed := e.changedCitations(a.Citations, func(c store.Citation) string { return c.SHA256 }); len(changed) > 0 {
		refuse = "cited file(s) changed since the proposal: " + strings.Join(changed, ", ")
	}
	if refuse != "" {
		a.Status, a.StaleReason = store.AttestStale, refuse
		if err := e.St.PutAttestation(e.ProjectID, *a); err != nil {
			return nil, err
		}
		_ = e.St.Event(e.ProjectID, "attest:"+controlID, "PENDING", "STALE", a.ID+": "+refuse)
		return nil, fmt.Errorf("not accepted: %s. Ask the reviewer for a fresh proposal (/pandaward:review) and decide that one", refuse)
	}
	for i := range a.Citations {
		a.Citations[i].AcceptedSHA256 = a.Citations[i].SHA256
	}
	a.Status, a.DecidedBy, a.Note = store.AttestAccepted, by, redact.Text(strings.TrimSpace(note))
	a.DecidedAt = now.Format(time.RFC3339)
	a.ExpiresAt = now.AddDate(0, 0, e.Cfg.Attest.MaxAgeDays).Format(time.RFC3339)
	all, err := e.St.Attestations(e.ProjectID)
	if err != nil {
		return nil, err
	}
	for _, old := range all {
		if old.ControlID == controlID && old.Status == store.AttestAccepted {
			old.Status, old.StaleReason = store.AttestStale, "superseded by "+a.ID
			if err := e.St.PutAttestation(e.ProjectID, old); err != nil {
				return nil, err
			}
		}
	}
	if err := e.St.PutAttestation(e.ProjectID, *a); err != nil {
		return nil, err
	}
	return a, e.St.Event(e.ProjectID, "attest:"+controlID, "PENDING", "ACCEPTED", fmt.Sprintf("%s accepted by %s: %s", a.ID, by, a.Verdict))
}

// DecidingAttestations returns, per control, the attestation that decides
// it or last decided it: the latest accepted one, or the latest that went
// stale after it was accepted. Superseded and rejected ones are left out.
func (e *Engine) DecidingAttestations() (map[string]store.Attestation, error) {
	all, err := e.St.Attestations(e.ProjectID)
	if err != nil {
		return nil, err
	}
	out := map[string]store.Attestation{}
	for _, a := range all {
		if a.DecidedAt == "" || (a.Status != store.AttestAccepted && a.Status != store.AttestStale) || strings.HasPrefix(a.StaleReason, "superseded") {
			continue
		}
		if cur, ok := out[a.ControlID]; !ok || a.DecidedAt >= cur.DecidedAt {
			out[a.ControlID] = a
		}
	}
	return out, nil
}

// attestInvalid returns why an accepted attestation no longer holds, or ""
// while it does.
func (e *Engine) attestInvalid(a store.Attestation, now time.Time) string {
	if a.Status == store.AttestStale {
		return a.StaleReason
	}
	if a.CatalogVersion != catalog.Version {
		return "the control catalog changed since the attestation (" + a.CatalogVersion + " -> " + catalog.Version + ")"
	}
	decided, err := time.Parse(time.RFC3339, a.DecidedAt)
	if err != nil {
		return "its decision date cannot be read"
	}
	exp := decided.AddDate(0, 0, e.Cfg.Attest.MaxAgeDays)
	if t, err := time.Parse(time.RFC3339, a.ExpiresAt); err == nil && t.Before(exp) {
		exp = t
	}
	if !now.Before(exp) {
		return fmt.Sprintf("it expired on %s (attest.max_age_days is %d)", exp.Format("2006-01-02"), e.Cfg.Attest.MaxAgeDays)
	}
	changed := e.changedCitations(a.Citations, func(c store.Citation) string {
		if c.AcceptedSHA256 != "" {
			return c.AcceptedSHA256
		}
		return c.SHA256
	})
	if len(changed) > 0 {
		return "cited file(s) changed since it was accepted: " + strings.Join(changed, ", ")
	}
	return ""
}

// AttestedReason is the control reason of a valid attestation.
func AttestedReason(a store.Attestation) string {
	r := "attested by " + a.DecidedBy + " on " + day(a.DecidedAt)
	if a.Note != "" {
		r += ": " + a.Note
	}
	return fmt.Sprintf("%s; evidence: %d citation(s), proposed by %s", r, len(a.Citations), a.ProposedBy)
}

func staleAttestReason(a store.Attestation, why string) string {
	return "was " + string(a.Verdict) + " (attested by " + a.DecidedBy + " on " + day(a.DecidedAt) + "): " + why +
		"; a reviewer proposes a fresh attestation (/pandaward:review) and a person accepts it with `pandaward attest " + a.ControlID + " --accept --by <name>`"
}

func day(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

// applyAttestations decides manual controls of a new assessment from their
// accepted attestations. An attestation that no longer holds is marked
// stale in the ledger, once, and its control is STALE.
func (e *Engine) applyAttestations(results map[string]*model.ControlResult, now time.Time) error {
	as, err := e.DecidingAttestations()
	if err != nil {
		return err
	}
	for cid, a := range as {
		r := results[cid]
		if r == nil || r.Method != catalog.MethodManual || r.Status == model.StatusNotApplicable {
			continue
		}
		r.DecidedBy = model.DecidedAttested
		if why := e.attestInvalid(a, now); why != "" {
			if a.Status != store.AttestStale {
				a.Status, a.StaleReason = store.AttestStale, why
				if err := e.St.PutAttestation(e.ProjectID, a); err != nil {
					return err
				}
				if err := e.St.Event(e.ProjectID, "attest:"+cid, "ACCEPTED", "STALE", a.ID+": "+why); err != nil {
					return err
				}
			}
			r.Status, r.Reason = model.StatusStale, staleAttestReason(a, why)
			continue
		}
		r.Status, r.Reason = a.Verdict, AttestedReason(a)
	}
	return nil
}

// attestedControls returns the controls an attestation decided in cs.
func attestedControls(cs []model.ControlResult) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		if c.DecidedBy == model.DecidedAttested && c.Status.Decisive() {
			out[c.ID] = true
		}
	}
	return out
}

// attestStaleView marks attested controls STALE when their attestation no
// longer holds: a cited file changed, the catalog changed or it expired.
// It only reads.
func (e *Engine) attestStaleView(cs []model.ControlResult, es []model.Edge, now time.Time) ([]model.ControlResult, []model.Edge, error) {
	if len(attestedControls(cs)) == 0 {
		return cs, es, nil
	}
	as, err := e.DecidingAttestations()
	if err != nil {
		return nil, nil, err
	}
	why := map[string]string{}
	for _, c := range cs {
		a, ok := as[c.ID]
		if !ok || c.DecidedBy != model.DecidedAttested || !c.Status.Decisive() {
			continue
		}
		if w := e.attestInvalid(a, now); w != "" {
			why[c.ID] = staleAttestReason(a, w)
		}
	}
	cs, es = markStale(cs, es, why)
	return cs, es, nil
}

// markStale returns copies of cs and es with the controls in why STALE,
// each with its reason, and the edges that test them STALE.
func markStale(cs []model.ControlResult, es []model.Edge, why map[string]string) ([]model.ControlResult, []model.Edge) {
	if len(why) == 0 {
		return cs, es
	}
	outC := make([]model.ControlResult, len(cs))
	for i, c := range cs {
		outC[i] = c
		if w, ok := why[c.ID]; ok {
			outC[i].Status, outC[i].Reason = model.StatusStale, w
		}
	}
	outE := make([]model.Edge, len(es))
	for i, ed := range es {
		outE[i] = ed
		var hit []string
		for _, t := range ed.Tests {
			if _, ok := why[t]; ok {
				hit = append(hit, t)
			}
		}
		if len(hit) > 0 && ed.Status != model.StatusStale {
			sort.Strings(hit)
			outE[i].Reason = "was " + string(ed.Status) + "; stale linked controls: " + strings.Join(hit, ", ")
			outE[i].Status = model.StatusStale
		}
	}
	return outC, outE
}

// ReportAttestations returns the attestations that decide or last decided
// a control, then the pending proposals. An accepted attestation that no
// longer holds (a cited file changed, the catalog changed or it expired)
// is shown with status stale and the reason, even before the next scan
// records that.
func (e *Engine) ReportAttestations() ([]store.Attestation, error) {
	dec, err := e.DecidingAttestations()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []store.Attestation
	for _, a := range dec {
		if a.Status == store.AttestAccepted {
			if why := e.attestInvalid(a, now); why != "" {
				a.Status, a.StaleReason = store.AttestStale, why
			}
		}
		out = append(out, a)
	}
	pend, err := e.PendingAttestations()
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ControlID < out[j].ControlID })
	return append(out, pend...), nil
}

// PendingAttestations returns the proposals that wait for a person.
func (e *Engine) PendingAttestations() ([]store.Attestation, error) {
	all, err := e.St.Attestations(e.ProjectID)
	if err != nil {
		return nil, err
	}
	var out []store.Attestation
	for _, a := range all {
		if a.Status == store.AttestPending {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ControlID < out[j].ControlID })
	return out, nil
}
