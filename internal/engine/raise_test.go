package engine

import (
	"context"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

type ownsD006 struct{}

func (ownsD006) Name() string       { return "semgrep" }
func (ownsD006) Controls() []string { return []string{"D-006"} }
func (ownsD006) Maturity() string   { return "test" }
func (ownsD006) Network() bool      { return false }
func (ownsD006) Run(context.Context, *adapters.Context) (adapters.Result, model.Run) {
	return adapters.Result{}, model.Run{}
}

func TestForeignSignalsRaiseButNeverLower(t *testing.T) {
	results := map[string]*model.ControlResult{
		"D-001": {ID: "D-001", Status: model.StatusPass, Reason: "builtin clean"},
		"D-003": {ID: "D-003", Status: model.StatusFail, Reason: "builtin confirmed"},
		"H-001": {ID: "H-001", Status: model.StatusNotApplicable},
		"B-001": {ID: "B-001", Status: model.StatusBlocked},
		"D-006": {ID: "D-006", Status: "PLANNED"},
	}
	sig := func(cid string) model.Signal {
		return model.Signal{ControlID: cid, Collector: "semgrep", Severity: model.SevHigh, Confidence: model.Hypothesis}
	}
	sigs := []model.Signal{sig("D-001"), sig("D-003"), sig("H-001"), sig("B-001"), sig("D-006")}
	foreign := routeForeign(ownsD006{}, sigs, results)
	if len(foreign) != 2 {
		t.Fatalf("want D-001 and D-003 as foreign, got %+v", foreign)
	}
	if sigs[2].ControlID != "D-006" || sigs[3].ControlID != "D-006" {
		t.Fatalf("signals for N/A or blocked controls must move to D-006: %s %s", sigs[2].ControlID, sigs[3].ControlID)
	}
	raise(results, foreign)
	if results["D-001"].Status != model.StatusSuspected {
		t.Errorf("PASS must be raised to SUSPECTED, got %s", results["D-001"].Status)
	}
	if results["D-003"].Status != model.StatusFail || results["D-003"].Reason != "builtin confirmed" {
		t.Errorf("FAIL must not be lowered or rewritten: %+v", results["D-003"])
	}
	if results["B-001"].Status != model.StatusBlocked || results["H-001"].Status != model.StatusNotApplicable {
		t.Error("undecided and N/A controls must not change")
	}
}
