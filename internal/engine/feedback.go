package engine

import (
	"math"

	"github.com/ratomirjovanovic/pandaward/internal/feedback"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// PendingFeedback returns the feedback state of the project and the reports
// it has not sent yet.
func (e *Engine) PendingFeedback() (feedback.State, []feedback.Group, error) {
	st, err := feedback.LoadState(e.Private())
	if err != nil {
		return st, nil, err
	}
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		return st, nil, err
	}
	cache := map[string][]model.Run{}
	runs := func(id string) []model.Run {
		if rs, ok := cache[id]; ok {
			return rs
		}
		rs, _ := e.St.Runs(id)
		cache[id] = rs
		return rs
	}
	var observed func(string) bool
	if a, err := e.St.PreviousObserved(e.ProjectID, math.MaxInt32); err == nil && a != nil {
		if obs, tracked, err := e.St.Observations(a.ID); err == nil && tracked {
			observed = func(fp string) bool { _, ok := obs[fp]; return ok }
		}
	}
	return st, feedback.Pending(fs, runs, observed, st), nil
}
