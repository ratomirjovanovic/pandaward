package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

var skillRef = regexp.MustCompile(`/pandaward:([a-z-]+)`)

// TestNextStepCommandsExist builds the next step of every catalog control in
// every undecided status, with the reasons the scan really stores, and
// checks that each command, subcommand, flag and skill it names exists.
func TestNextStepCommandsExist(t *testing.T) {
	cmds := cliSurface(t)
	reasons := []string{
		"some reason",
		"adapter builtin-code disabled in config",
		"planned but not executed",
		"osv-scanner is not installed (optional; run `pandaward doctor`)",
		"trivy needs network access: it downloads its vulnerability database and sends nothing about the project. Set scan.allow_tool_network: true in .pandaward/config.yaml to allow it; no project target is contacted",
		"scan.mobsf_url is not set; run MobSF on a loopback address (optional) and set it",
		"semgrep exceeded 5m0s",
		"needs `pandaward test --profile staging-active` with an approved scope manifest and ZAP installed",
	}
	statuses := []model.Status{model.StatusBlocked, model.StatusUnsupported, model.StatusSuspected, model.StatusInconclusive, model.StatusError, model.StatusStale}
	for _, c := range catalog.Controls {
		for _, st := range statuses {
			for _, r := range reasons {
				cr := model.ControlResult{ID: c.ID, Method: c.Method, Adapter: c.Adapter, Status: st, Reason: r}
				s := engine.NextStep(cr, 1)
				for _, text := range []string{s.Text, s.Group} {
					for _, p := range checkLine(cmds, text) {
						t.Errorf("%s %s: %s in %q", c.ID, st, p, text)
					}
					for _, m := range skillRef.FindAllStringSubmatch(text, -1) {
						if _, err := os.Stat(filepath.Join("..", "..", "skills", m[1], "SKILL.md")); err != nil {
							t.Errorf("%s %s: no skill %s in %q", c.ID, st, m[1], text)
						}
					}
				}
			}
		}
	}
}
