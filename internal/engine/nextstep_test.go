package engine

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// ctl builds a control result from the catalog entry with the given status
// and reason, as the scan stores it.
func ctl(t *testing.T, id string, st model.Status, reason string) model.ControlResult {
	t.Helper()
	c := catalog.ControlByID(id)
	if c == nil {
		t.Fatalf("no control %s", id)
	}
	return model.ControlResult{ID: c.ID, Domain: c.Domain, Title: c.Title, Method: c.Method, Adapter: c.Adapter, Status: st, Reason: reason}
}

func TestNextStep(t *testing.T) {
	for _, tc := range []struct {
		name    string
		id      string
		status  model.Status
		reason  string
		susp    int
		want    string // exact Text
		group   string // exact Group; "" means equal to want
		noGroup bool   // zero Step expected
	}{
		// Decided and not applicable controls have no next step.
		{name: "pass", id: "D-001", status: model.StatusPass, reason: "check completed", noGroup: true},
		{name: "fail", id: "H-003", status: model.StatusFail, reason: "2 confirmed observation(s)", noGroup: true},
		{name: "not applicable", id: "K-001", status: model.StatusNotApplicable, reason: "auto: no 'android' assets found", noGroup: true},

		// static
		{name: "static blocked disabled", id: "D-001", status: model.StatusBlocked, reason: "adapter builtin-code disabled in config",
			want: "add builtin-code to scan.adapters in .pandaward/config.yaml, then run `pandaward retest`"},
		{name: "static blocked not executed", id: "R-001", status: model.StatusBlocked, reason: "planned but not executed",
			want: "run `pandaward retest` (the check was planned but did not run)"},
		{name: "static suspected", id: "D-003", status: model.StatusSuspected, reason: "3 heuristic signal(s) need review; not confirmed", susp: 3,
			want:  "triage 3 open suspected finding(s) of this control (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then run `pandaward retest`",
			group: "triage the open suspected findings (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then run `pandaward retest`"},
		{name: "static suspected unknown count", id: "D-003", status: model.StatusSuspected, reason: "1 heuristic signal(s) need review",
			want:  "triage the open suspected findings of this control (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then run `pandaward retest`",
			group: "triage the open suspected findings (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then run `pandaward retest`"},
		{name: "static inconclusive skipped files", id: "A-001", status: model.StatusInconclusive, reason: "10 files analyzed, 1 skipped (e.g. big.bin: larger than max_file_bytes)",
			want:  "deal with the skipped files (10 files analyzed, 1 skipped (e.g. big.bin: larger than max_file_bytes)): make them readable, exclude them with inventory.exclude or raise inventory.max_file_bytes or inventory.max_files in .pandaward/config.yaml, then run `pandaward retest`",
			group: "make the skipped files readable, exclude them with inventory.exclude or raise inventory.max_file_bytes or inventory.max_files in .pandaward/config.yaml, then run `pandaward retest`"},
		{name: "static inconclusive routes", id: "A-002", status: model.StatusInconclusive, reason: "12 HTTP routes ... completeness is not proven",
			want: "route completeness cannot be proven automatically in this release; compare `pandaward routes` with the real routing manually (/pandaward:review)"},
		{name: "static inconclusive other", id: "A-003", status: model.StatusInconclusive, reason: "openapi.yaml could not be parsed",
			want:  "resolve what made it inconclusive (openapi.yaml could not be parsed), then run `pandaward retest`",
			group: "resolve what made the builtin-inventory result inconclusive (see the control reason), then run `pandaward retest`"},
		{name: "static error", id: "E-001", status: model.StatusError, reason: "adapter crashed: boom",
			want:  "fix the builtin-secrets error (adapter crashed: boom), then run `pandaward retest`",
			group: "fix the builtin-secrets error shown in the control reason, then run `pandaward retest`"},
		{name: "static stale", id: "D-002", status: model.StatusStale, reason: "was PASS: src/a.ts changed",
			want: "run `pandaward retest --changed` (a file the decision depends on changed)"},
		{name: "static unsupported", id: "K-005", status: model.StatusUnsupported, reason: "no .apk files in the project",
			want:  "apktool cannot decide it (no .apk files in the project); fix that and run `pandaward retest`, or review it manually with /pandaward:review",
			group: "apktool cannot decide it for this project; give it input it can read and run `pandaward retest`, or review it manually with /pandaward:review"},

		// external
		{name: "external not installed", id: "I-003", status: model.StatusBlocked, reason: "osv-scanner is not installed (optional; run `pandaward doctor`)",
			want: "install osv-scanner (see `pandaward doctor`), then run `pandaward retest`"},
		{name: "external network off", id: "I-003", status: model.StatusBlocked,
			reason: "osv-scanner needs network access: it sends the package names and versions from your lockfiles to api.osv.dev to look up advisories. Set scan.allow_tool_network: true in .pandaward/config.yaml to allow it; no project target is contacted",
			want:   "allow scan.allow_tool_network: true in .pandaward/config.yaml (osv-scanner then sends the package names and versions from your lockfiles to api.osv.dev to look up advisories), then run `pandaward retest`"},
		{name: "external mobsf url", id: "K-006", status: model.StatusBlocked, reason: "scan.mobsf_url is not set; run MobSF on a loopback address (optional) and set it",
			want: "run MobSF on a loopback address and set scan.mobsf_url in .pandaward/config.yaml, then run `pandaward retest`"},
		{name: "external blocked other", id: "K-006", status: model.StatusBlocked, reason: "PANDAWARD_MOBSF_KEY is not set; export the MobSF REST API key",
			want:  "resolve the blocker (PANDAWARD_MOBSF_KEY is not set; export the MobSF REST API key), then run `pandaward retest`",
			group: "resolve the mobsf blocker shown in the control reason, then run `pandaward retest`"},
		{name: "external timeout", id: "D-006", status: model.StatusError, reason: "semgrep exceeded 5m0s",
			want: "raise scan.adapter_timeout_seconds in .pandaward/config.yaml, then run `pandaward retest` (semgrep timed out)"},
		{name: "external error", id: "D-006", status: model.StatusError, reason: "semgrep exited 2: bad rule",
			want:  "fix the semgrep error (semgrep exited 2: bad rule), then run `pandaward retest`",
			group: "fix the semgrep error shown in the control reason, then run `pandaward retest`"},
		{name: "external unsupported", id: "I-003", status: model.StatusUnsupported, reason: "osv-scanner found no lockfile or SBOM it can read (exit 128)",
			want:  "osv-scanner cannot decide it (osv-scanner found no lockfile or SBOM it can read (exit 128)); fix that and run `pandaward retest`, or review it manually with /pandaward:review",
			group: "osv-scanner cannot decide it for this project; give it input it can read and run `pandaward retest`, or review it manually with /pandaward:review"},
		{name: "external suspected", id: "E-005", status: model.StatusSuspected, reason: "1 heuristic signal(s)", susp: 1,
			want:  "triage 1 open suspected finding(s) of this control (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then run `pandaward retest`",
			group: "triage the open suspected findings (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then run `pandaward retest`"},
		{name: "external stale", id: "E-005", status: model.StatusStale, reason: "was PASS",
			want: "run `pandaward retest --changed` (a file the decision depends on changed)"},
		{name: "external inconclusive", id: "R-002", status: model.StatusInconclusive, reason: "SARIF file truncated",
			want:  "resolve what made it inconclusive (SARIF file truncated), then run `pandaward retest`",
			group: "resolve what made the sarif-import result inconclusive (see the control reason), then run `pandaward retest`"},

		// runtime
		{name: "runtime observe planned", id: "H-003", status: model.StatusBlocked, reason: "needs `pandaward test --profile production-observe` with an approved scope manifest",
			want:  "fill in .pandaward/scope.yaml (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile production-observe`",
			group: "fill in .pandaward/scope.yaml (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile production-observe`"},
		{name: "runtime zap active planned", id: "D-005", status: model.StatusBlocked, reason: "needs zap.active_scan: true in an approved scope manifest",
			want:  "install ZAP, fill in .pandaward/scope.yaml with zap.active_scan: true (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile staging-active`",
			group: "fill in .pandaward/scope.yaml (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile staging-active`"},
		{name: "runtime zap planned", id: "M-001", status: model.StatusBlocked, reason: "needs `pandaward test --profile staging-active` with an approved scope manifest and ZAP installed",
			want:  "install ZAP, fill in .pandaward/scope.yaml (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile staging-active`",
			group: "fill in .pandaward/scope.yaml (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile staging-active`"},
		{name: "runtime authz revoked planned", id: "B-004", status: model.StatusBlocked, reason: "needs an identity with revoked: true",
			want:  "fill in .pandaward/scope.yaml with an identity marked revoked: true and authorization_checks (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile staging-active`",
			group: "fill in .pandaward/scope.yaml (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile staging-active`"},
		{name: "runtime authz planned", id: "C-001", status: model.StatusBlocked, reason: "needs identities and authorization_checks",
			want:  "fill in .pandaward/scope.yaml with identities and authorization_checks (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile staging-active`",
			group: "fill in .pandaward/scope.yaml (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile staging-active`"},
		{name: "runtime zap missing after run", id: "M-001", status: model.StatusBlocked, reason: "ZAP not found; set runtime.zap_path",
			want:  "resolve the blocker (ZAP not found; set runtime.zap_path), then run `pandaward test --profile staging-active`",
			group: "fill in .pandaward/scope.yaml (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then run `pandaward test --profile staging-active`"},
		{name: "runtime android planned", id: "K-003", status: model.StatusBlocked, reason: "needs runtime.android_package, a running emulator",
			want:  "set runtime.android_package in .pandaward/config.yaml and start an emulator with the debuggable test build installed, then run `pandaward test --profile local-runtime`",
			group: "prepare the emulator or simulator test build named in the runtime section of .pandaward/config.yaml, then run `pandaward test --profile local-runtime`"},
		{name: "runtime ios planned", id: "L-002", status: model.StatusBlocked, reason: "needs runtime.ios_bundle_id, a booted simulator",
			want:  "on macOS with Xcode, set runtime.ios_bundle_id in .pandaward/config.yaml and boot a simulator with the test build installed, then run `pandaward test --profile local-runtime`",
			group: "prepare the emulator or simulator test build named in the runtime section of .pandaward/config.yaml, then run `pandaward test --profile local-runtime`"},
		{name: "runtime ios after run", id: "L-002", status: model.StatusBlocked, reason: "iOS simulator checks need macOS with Xcode; this host is windows",
			want:  "resolve the blocker (iOS simulator checks need macOS with Xcode; this host is windows), then run `pandaward test --profile local-runtime`",
			group: "prepare the emulator or simulator test build named in the runtime section of .pandaward/config.yaml, then run `pandaward test --profile local-runtime`"},
		{name: "runtime unsupported", id: "B-003", status: model.StatusUnsupported, reason: "runtime adapter for profile staging-active is not implemented in this release",
			want: reviewNoAdapter},
		{name: "runtime inconclusive", id: "C-001", status: model.StatusInconclusive, reason: "2 request(s) could not be judged",
			want:  "resolve what made it inconclusive (2 request(s) could not be judged), then run `pandaward test --profile staging-active`",
			group: "resolve what made the authz result inconclusive (see the control reason), then run `pandaward test --profile staging-active`"},
		{name: "runtime error", id: "M-001", status: model.StatusError, reason: "ZAP run failed: exit 1",
			want:  "fix the zap error (ZAP run failed: exit 1), then run `pandaward test --profile staging-active`",
			group: "fix the zap error shown in the control reason, then run `pandaward test --profile staging-active`"},
		{name: "runtime suspected", id: "M-001", status: model.StatusSuspected, reason: "2 heuristic signal(s)", susp: 2,
			want:  "triage 2 open suspected finding(s) of this control (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then run `pandaward test --profile staging-active`",
			group: "triage the open suspected findings (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then run `pandaward test --profile staging-active`"},
		{name: "runtime stale", id: "H-003", status: model.StatusStale, reason: "was PASS",
			want: "run `pandaward retest --changed`, then `pandaward test --profile production-observe` (a file the decision depends on changed)"},

		// manual
		{name: "manual blocked", id: "A-004", status: model.StatusBlocked, reason: "manual-assisted review required (/pandaward:review); not decided by automation",
			want: reviewManually},
		{name: "manual stale", id: "C-003", status: model.StatusStale, reason: "was BLOCKED",
			want: "run `pandaward retest --changed` (a file the decision depends on changed)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NextStep(ctl(t, tc.id, tc.status, tc.reason), tc.susp)
			if tc.noGroup {
				if got != (Step{}) {
					t.Fatalf("want no step, got %+v", got)
				}
				return
			}
			if got.Text != tc.want {
				t.Errorf("text\n got %q\nwant %q", got.Text, tc.want)
			}
			group := tc.group
			if group == "" {
				group = tc.want
			}
			if got.Group != group {
				t.Errorf("group\n got %q\nwant %q", got.Group, group)
			}
		})
	}
}

// Every control of the catalog, in every undecided status, has a next step,
// and every decided or not applicable one has none. The sweep covers each
// status and method combination the catalog can produce.
func TestNextStepCoversCatalog(t *testing.T) {
	undecided := []model.Status{model.StatusBlocked, model.StatusUnsupported, model.StatusSuspected, model.StatusInconclusive, model.StatusError, model.StatusStale}
	seen := map[string]bool{}
	for _, c := range catalog.Controls {
		for _, st := range undecided {
			s := NextStep(ctl(t, c.ID, st, "some reason"), 2)
			if s.Group == "" || s.Text == "" {
				t.Errorf("%s %s: empty step %+v", c.ID, st, s)
			}
			if !strings.Contains(s.Text, "pandaward") {
				t.Errorf("%s %s: step names no command: %q", c.ID, st, s.Text)
			}
			if strings.ContainsRune(s.Text, 0x2013) || strings.ContainsRune(s.Text, 0x2014) {
				t.Errorf("%s %s: dash in %q", c.ID, st, s.Text)
			}
			seen[c.Method+"/"+string(st)] = true
		}
		for _, st := range []model.Status{model.StatusPass, model.StatusFail, model.StatusNotApplicable} {
			if s := NextStep(ctl(t, c.ID, st, "x"), 0); s != (Step{}) {
				t.Errorf("%s %s: want no step, got %+v", c.ID, st, s)
			}
		}
	}
	for _, m := range []string{catalog.MethodStatic, catalog.MethodExternal, catalog.MethodRuntime, catalog.MethodManual} {
		for _, st := range undecided {
			if !seen[m+"/"+string(st)] {
				t.Errorf("combination %s/%s not covered", m, st)
			}
		}
	}
}

func TestDecidedByAndBreakdown(t *testing.T) {
	cs := []model.ControlResult{
		ctl(t, "D-001", model.StatusPass, ""),
		ctl(t, "I-003", model.StatusFail, ""),
		ctl(t, "H-003", model.StatusPass, ""),
		ctl(t, "A-004", model.StatusBlocked, ""),
		ctl(t, "K-001", model.StatusNotApplicable, ""),
		ctl(t, "L-001", model.StatusNotApplicable, ""),
	}
	att := ctl(t, "C-003", model.StatusPass, "")
	cs = append(cs, att)
	recorded := ctl(t, "D-002", model.StatusPass, "")
	recorded.DecidedBy = model.DecidedAttested
	cs = append(cs, recorded)
	want := map[string]string{"D-001": "automatic", "I-003": "automatic", "H-003": "runtime", "A-004": "", "K-001": "", "C-003": "attested", "D-002": "attested"}
	for _, c := range cs {
		if got := DecidedBy(c); got != want[c.ID] {
			t.Errorf("%s: DecidedBy = %q, want %q", c.ID, got, want[c.ID])
		}
	}
	cov := ComputeCoverage(cs, nil, 0)
	if cov.Applicable != 6 || cov.Decisive != 5 || cov.Automatic != 2 || cov.Runtime != 1 || cov.Attested != 2 || cov.NotApplicable != 2 {
		t.Errorf("coverage %+v", cov)
	}
	if cov.Automatic+cov.Runtime+cov.Attested != cov.Decisive {
		t.Errorf("breakdown does not add up: %+v", cov)
	}
}

func TestPathTo100(t *testing.T) {
	cs := []model.ControlResult{
		ctl(t, "D-001", model.StatusPass, ""),
		ctl(t, "A-004", model.StatusBlocked, ""),
		ctl(t, "C-003", model.StatusBlocked, ""),
		ctl(t, "O-001", model.StatusBlocked, ""),
		ctl(t, "D-003", model.StatusSuspected, ""),
		ctl(t, "H-001", model.StatusSuspected, ""),
		ctl(t, "I-003", model.StatusBlocked, "osv-scanner is not installed (optional; run `pandaward doctor`)"),
		ctl(t, "K-001", model.StatusNotApplicable, ""),
	}
	fs := []model.Finding{
		{ControlID: "D-003", Status: model.FindingOpen, Confidence: model.Hypothesis, Severity: model.SevHigh},
		{ControlID: "D-003", Status: model.FindingOpen, Confidence: model.StronglySupported, Severity: model.SevLow},
		{ControlID: "D-003", Status: model.FindingOpen, Confidence: model.Hypothesis, Severity: model.SevInfo},
		{ControlID: "D-003", Status: model.FindingFalsePositive, Confidence: model.Hypothesis, Severity: model.SevHigh},
		{ControlID: "H-001", Status: model.FindingReopened, Confidence: model.Hypothesis, Severity: model.SevMedium},
	}
	if n := SuspectedCounts(fs); n["D-003"] != 2 || n["H-001"] != 1 {
		t.Errorf("SuspectedCounts = %v", n)
	}
	got := PathTo100(cs, fs)
	if len(got) != 3 {
		t.Fatalf("groups %+v", got)
	}
	if got[0].Count != 3 || got[0].Step != reviewManually || strings.Join(got[0].Controls, ",") != "A-004,C-003,O-001" {
		t.Errorf("first group %+v", got[0])
	}
	if got[1].Count != 2 || strings.Join(got[1].Controls, ",") != "D-003,H-001" || !strings.HasPrefix(got[1].Step, "triage the open suspected findings") {
		t.Errorf("second group %+v", got[1])
	}
	if got[2].Count != 1 || got[2].Controls[0] != "I-003" {
		t.Errorf("third group %+v", got[2])
	}
	Annotate(cs, fs)
	if !strings.HasPrefix(cs[4].NextStep, "triage 2 open suspected finding(s)") || cs[0].DecidedBy != "automatic" || cs[0].NextStep != "" {
		t.Errorf("annotate: %+v / %+v", cs[4], cs[0])
	}
}
