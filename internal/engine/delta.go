package engine

import (
	"fmt"
	"sort"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// DeltaItem is one finding in a delta between two assessments.
type DeltaItem struct {
	FindingID string         `json:"finding_id"`
	RuleID    string         `json:"rule_id"`
	ControlID string         `json:"control_id"`
	Title     string         `json:"title"`
	Severity  model.Severity `json:"severity"`
	File      string         `json:"file,omitempty"`
	Line      int            `json:"line,omitempty"`
	Note      string         `json:"note,omitempty"`
}

// Delta compares the findings observed by two assessments. It depends only
// on the ledger, so rerunning an unchanged assessment gives the same delta.
type Delta struct {
	From       string      `json:"from"`
	To         string      `json:"to"`
	New        []DeltaItem `json:"new"`
	Reopened   []DeltaItem `json:"reopened"`
	Remediated []DeltaItem `json:"remediated"`
	Moved      []DeltaItem `json:"moved"`
	Stale      []DeltaItem `json:"stale"`
	Waived     []DeltaItem `json:"waived"`
	Unchanged  int         `json:"unchanged"`
	Note       string      `json:"note"`
}

// Diff compares assessment from (older) with assessment to (newer).
//   - new: observed in to, never observed up to and including from
//   - reopened: observed in to, not in from, but observed before from
//   - remediated: observed in from, not in to, and its collector completed in to
//   - stale: observed in from, not in to, but its collector did not complete in to
//   - moved: observed in both, under a new fingerprint because its file moved
//   - waived: marked false positive or risk accepted between the two assessments
func (e *Engine) Diff(fromID, toID string) (*Delta, error) {
	from, err := e.St.Assessment(e.ProjectID, fromID)
	if err != nil {
		return nil, err
	}
	to, err := e.St.Assessment(e.ProjectID, toID)
	if err != nil {
		return nil, err
	}
	if from == nil || to == nil {
		return nil, fmt.Errorf("unknown assessment %q or %q", fromID, toID)
	}
	if from.Seq >= to.Seq {
		return nil, fmt.Errorf("%s must be older than %s", fromID, toID)
	}
	obsFrom, okFrom, err := e.St.Observations(from.ID)
	if err != nil {
		return nil, err
	}
	obsTo, okTo, err := e.St.Observations(to.ID)
	if err != nil {
		return nil, err
	}
	if !okFrom || !okTo {
		return nil, fmt.Errorf("%s or %s was recorded by an older pandaward without observation tracking; compare newer assessments", fromID, toID)
	}
	before, err := e.St.ObservedBefore(e.ProjectID, from.Seq)
	if err != nil {
		return nil, err
	}
	runs, err := e.St.Runs(to.ID)
	if err != nil {
		return nil, err
	}
	completed := map[string]bool{"manual-assisted": false}
	for _, r := range runs {
		completed[r.Adapter] = r.ExitClass == model.ExitOK || r.ExitClass == model.ExitCarried
	}
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		return nil, err
	}
	byID := map[string]model.Finding{}
	for _, f := range fs {
		byID[f.ID] = f
	}
	item := func(f model.Finding, note string) DeltaItem {
		return DeltaItem{FindingID: f.ID, RuleID: f.RuleID, ControlID: f.ControlID, Title: f.Title, Severity: f.Severity, File: f.File, Line: f.StartLine, Note: note}
	}
	d := &Delta{From: from.ID, To: to.ID,
		Note: "Compares findings observed by automated collectors in each assessment. Remediated means the collector ran again and no longer observed it; stale means it did not run, so the finding is not confirmed fixed; moved means the same finding now lives in another file."}
	// Compare by finding ID: a finding keeps its ID when its file moves,
	// while its fingerprint changes with the file.
	idsFrom, idsTo := map[string]string{}, map[string]string{}
	for fp, o := range obsFrom {
		idsFrom[o.FindingID] = fp
	}
	for fp, o := range obsTo {
		idsTo[o.FindingID] = fp
	}
	for id, fpTo := range idsTo {
		f, ok := byID[id]
		if !ok {
			continue
		}
		fpFrom, inFrom := idsFrom[id]
		switch {
		case inFrom && fpFrom != fpTo:
			d.Moved = append(d.Moved, item(f, "same finding, now in "+f.File))
		case inFrom:
			d.Unchanged++
		case before[id]:
			d.Reopened = append(d.Reopened, item(f, ""))
		default:
			d.New = append(d.New, item(f, ""))
		}
	}
	for id := range idsFrom {
		if _, ok := idsTo[id]; ok {
			continue
		}
		f, ok := byID[id]
		if !ok {
			continue
		}
		if completed[f.Collector] {
			d.Remediated = append(d.Remediated, item(f, f.Collector+" completed in "+to.ID+" and no longer observed it"))
		} else {
			d.Stale = append(d.Stale, item(f, f.Collector+" did not complete in "+to.ID))
		}
	}
	waived, err := e.St.Waivers(e.ProjectID, from.EndedAt, to.EndedAt)
	if err != nil {
		return nil, err
	}
	for id, st := range waived {
		if f, ok := byID[id]; ok {
			d.Waived = append(d.Waived, item(f, "marked "+st))
		}
	}
	for _, l := range [][]DeltaItem{d.New, d.Reopened, d.Remediated, d.Moved, d.Stale, d.Waived} {
		sort.Slice(l, func(i, j int) bool { return l[i].FindingID < l[j].FindingID })
	}
	return d, nil
}

// DeltaToPrevious compares an assessment with the latest earlier one that
// tracked observations. It returns nil when there is none.
func (e *Engine) DeltaToPrevious(toID string) (*Delta, error) {
	to, err := e.St.Assessment(e.ProjectID, toID)
	if err != nil || to == nil {
		return nil, err
	}
	prev, err := e.St.PreviousObserved(e.ProjectID, to.Seq)
	if err != nil || prev == nil {
		return nil, err
	}
	if _, ok, err := e.St.Observations(to.ID); err != nil || !ok {
		return nil, err
	}
	return e.Diff(prev.ID, to.ID)
}
