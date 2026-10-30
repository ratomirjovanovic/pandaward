package engine

import (
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
	return st, feedback.Pending(fs, runs, st), nil
}
