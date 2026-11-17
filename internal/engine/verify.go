package engine

import (
	"errors"
	"sort"

	"github.com/ratomirjovanovic/pandaward/internal/claims"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// VerifyMismatch is one way a report disagrees with the ledger.
type VerifyMismatch struct {
	Control string `json:"control,omitempty"`
	Kind    string `json:"kind"`
	Detail  string `json:"detail"`
	// FalseAssurance is true when the report reassures more than the ledger
	// allows. A more careful report is listed but is not false assurance.
	FalseAssurance bool `json:"false_assurance"`
}

// VerifyResult is the outcome of comparing a report with the ledger.
type VerifyResult struct {
	Assessment string           `json:"assessment"`
	Claims     int              `json:"claims"`
	Mismatches []VerifyMismatch `json:"mismatches"`
	// Unsupported is true when the report contains false assurance.
	Unsupported bool   `json:"unsupported"`
	Note        string `json:"note,omitempty"`
}

// VerifyReport compares the control claims of a report with the latest
// assessment in the ledger: a PASS where PandaWard established something else,
// a more reassuring status than the ledger has, an evidence hash that is not
// one the ledger recorded for that control, and an all-clear claim while
// controls are not PASS. With complete set, the report presents itself as a
// full review and may not leave out an open finding (FAIL or SUSPECTED); a
// report about one fix is not held to that. Controls that file changes made
// STALE count as undecided. It reads the ledger only and changes nothing.
func (e *Engine) VerifyReport(report string, complete bool) (*VerifyResult, error) {
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("there is no assessment in the ledger to check the report against: run `pandaward scan` first")
	}
	cs, err := e.St.Controls(a.ID)
	if err != nil {
		return nil, err
	}
	es, err := e.St.Edges(a.ID)
	if err != nil {
		return nil, err
	}
	cs, _, _, err = e.StaleView(a.ID, cs, es)
	if err != nil {
		return nil, err
	}
	ev, err := e.St.EvidenceFor(a.ID)
	if err != nil {
		return nil, err
	}
	hashOf := map[string]string{}
	for _, r := range ev {
		hashOf[r.ID] = r.SHA256
	}
	facts := map[string]string{}
	evidence := map[string][]string{}
	for _, c := range cs {
		if c.Status == model.StatusNotApplicable {
			continue
		}
		facts[c.ID] = string(c.Status)
		for _, id := range c.EvidenceIDs {
			if h, ok := hashOf[id]; ok && h != "" {
				evidence[c.ID] = append(evidence[c.ID], h)
			}
		}
	}
	res := &VerifyResult{Assessment: a.ID, Mismatches: []VerifyMismatch{}}
	parsed := claims.Parse(report)
	res.Claims = len(parsed)
	opt := claims.Options{MustMention: map[string]bool{}}
	if complete {
		opt.MustMention = map[string]bool{"FAIL": true, "SUSPECTED": true}
	}
	if len(parsed) == 0 {
		res.Note = "the report has no control claims (a line that starts with a control id and a status), so only an all-clear statement can be checked"
	}
	for _, m := range claims.Check(report, facts, evidence, opt) {
		res.Mismatches = append(res.Mismatches, VerifyMismatch{Control: m.Control, Kind: m.Kind, Detail: m.Detail, FalseAssurance: m.Assurance()})
		if m.Assurance() {
			res.Unsupported = true
		}
	}
	sort.SliceStable(res.Mismatches, func(i, j int) bool {
		if res.Mismatches[i].FalseAssurance != res.Mismatches[j].FalseAssurance {
			return res.Mismatches[i].FalseAssurance
		}
		return res.Mismatches[i].Control < res.Mismatches[j].Control
	})
	return res, nil
}
