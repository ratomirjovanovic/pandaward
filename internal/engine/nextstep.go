package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// DecidedBy says how a decisive control was reached: a recorded value wins,
// otherwise runtime controls count as runtime, manual controls as attested
// (only an accepted attestation decides one) and static or external
// controls as automatic. It is "" for undecided and not applicable controls.
func DecidedBy(c model.ControlResult) string {
	if !c.Status.Decisive() {
		return ""
	}
	if c.DecidedBy != "" {
		return c.DecidedBy
	}
	switch c.Method {
	case catalog.MethodRuntime:
		return model.DecidedRuntime
	case catalog.MethodManual:
		return model.DecidedAttested
	}
	return model.DecidedAutomatic
}

// Step is what must happen for one undecided control to be decided.
type Step struct {
	// Group is shared by every control with the same next step; the path
	// to 100% groups by it.
	Group string
	// Text is the sentence for this control. It may add control-specific
	// detail, such as the number of findings to triage or the stored reason.
	Text string
}

func same(s string) Step { return Step{Group: s, Text: s} }

const (
	stepRetest = "run `pandaward retest`"
	// reviewManually is the group of the manual controls a person has not
	// attested yet; attestStep fills in the control.
	reviewManually  = "review it with /pandaward:review: the reviewer proposes an attestation with file:line evidence, then a person accepts or rejects it with `pandaward attest <control> --accept --by <name>` or `--reject`"
	reattest        = "a cited file changed, the catalog changed or the attestation expired: a reviewer proposes a fresh attestation (/pandaward:review), then a person accepts it with `pandaward attest <control> --accept --by <name>`"
	reviewNoAdapter = "no adapter decides it in this release and only manual controls can be attested; review it manually with /pandaward:review and record what you find as hypotheses (it stays undecided)"
)

// attestStep is a manual-control step with the control ID filled in.
func attestStep(group, id string) Step {
	return Step{Group: group, Text: strings.ReplaceAll(group, "<control>", id)}
}

// NextStep returns the next step for a control from its catalog method,
// profile and adapter, its status and its stored reason. openSuspected is
// the number of open non-confirmed, non-info findings of the control, used
// for SUSPECTED. It returns a zero Step for PASS, FAIL and NOT_APPLICABLE.
// Every command named here exists in the CLI or as a plugin skill.
func NextStep(c model.ControlResult, openSuspected int) Step {
	if c.Status.Decisive() || c.Status == model.StatusNotApplicable {
		return Step{}
	}
	profile := ""
	if cc := catalog.ControlByID(c.ID); cc != nil {
		profile = cc.Profile
	}
	runtime := c.Method == catalog.MethodRuntime
	rerun := stepRetest
	if runtime && profile != "" {
		rerun = "run `pandaward test --profile " + profile + "`"
	}
	reason := strings.TrimSpace(c.Reason)
	if c.Method == catalog.MethodManual {
		// Only an accepted attestation decides a manual control; a scan
		// cannot.
		if c.Status == model.StatusStale && c.DecidedBy == model.DecidedAttested {
			return attestStep(reattest, c.ID)
		}
		return attestStep(reviewManually, c.ID)
	}
	switch c.Status {
	case model.StatusStale:
		if runtime && profile != "" {
			return same("run `pandaward retest --changed`, then `pandaward test --profile " + profile + "` (a file the decision depends on changed)")
		}
		return same("run `pandaward retest --changed` (a file the decision depends on changed)")

	case model.StatusSuspected:
		group := "triage the open suspected findings (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then " + rerun
		what := "the open suspected findings"
		if openSuspected > 0 {
			what = fmt.Sprintf("%d open suspected finding(s)", openSuspected)
		}
		return Step{Group: group, Text: "triage " + what + " of this control (`pandaward findings`): fix the real ones, mark the rest with `pandaward findings false-positive <PW-ID> --by <name> --note <why>`, then " + rerun}

	case model.StatusUnsupported:
		if runtime || c.Adapter == "" {
			return same(reviewNoAdapter)
		}
		return Step{Group: c.Adapter + " cannot decide it for this project; give it input it can read and " + stepRetest + ", or review it manually with /pandaward:review",
			Text: c.Adapter + " cannot decide it (" + reason + "); fix that and " + stepRetest + ", or review it manually with /pandaward:review"}

	case model.StatusError:
		if strings.Contains(reason, " exceeded ") && !runtime {
			return same("raise scan.adapter_timeout_seconds in .pandaward/config.yaml, then " + stepRetest + " (" + orAdapter(c.Adapter) + " timed out)")
		}
		return Step{Group: "fix the " + orAdapter(c.Adapter) + " error shown in the control reason, then " + rerun,
			Text: "fix the " + orAdapter(c.Adapter) + " error (" + reason + "), then " + rerun}

	case model.StatusInconclusive:
		switch {
		case c.ID == "A-001":
			return Step{Group: "make the skipped files readable, exclude them with inventory.exclude or raise inventory.max_file_bytes or inventory.max_files in .pandaward/config.yaml, then " + stepRetest,
				Text: "deal with the skipped files (" + reason + "): make them readable, exclude them with inventory.exclude or raise inventory.max_file_bytes or inventory.max_files in .pandaward/config.yaml, then " + stepRetest}
		case c.ID == "A-002":
			return same("route completeness cannot be proven automatically in this release; compare `pandaward routes` with the real routing manually (/pandaward:review)")
		}
		return Step{Group: "resolve what made the " + orAdapter(c.Adapter) + " result inconclusive (see the control reason), then " + rerun,
			Text: "resolve what made it inconclusive (" + reason + "), then " + rerun}

	case model.StatusBlocked:
		if runtime {
			return runtimeBlocked(c, profile, reason, rerun)
		}
		return staticBlocked(c, reason)
	}
	return same(stepRetest)
}

func orAdapter(a string) string {
	if a == "" {
		return "adapter"
	}
	return a
}

// staticBlocked covers BLOCKED static and external controls. The reasons are
// the ones Plan and the adapters store.
func staticBlocked(c model.ControlResult, reason string) Step {
	const netKey = " needs network access: it "
	switch {
	case reason == "adapter "+c.Adapter+" disabled in config":
		return same("add " + c.Adapter + " to scan.adapters in .pandaward/config.yaml, then " + stepRetest)
	case strings.Contains(reason, " is not installed"):
		bin := strings.TrimSpace(reason[:strings.Index(reason, " is not installed")])
		return same("install " + bin + " (see `pandaward doctor`), then " + stepRetest)
	case strings.Contains(reason, netKey):
		i := strings.Index(reason, netKey)
		tool, sends := reason[:i], reason[i+len(netKey):]
		if j := strings.Index(sends, ". Set "); j >= 0 {
			sends = sends[:j]
		}
		return same("allow scan.allow_tool_network: true in .pandaward/config.yaml (" + tool + " then " + sends + "), then " + stepRetest)
	case strings.Contains(reason, "scan.mobsf_url is not set"):
		return same("run MobSF on a loopback address and set scan.mobsf_url in .pandaward/config.yaml, then " + stepRetest)
	case reason == "planned but not executed":
		return same(stepRetest + " (the check was planned but did not run)")
	}
	return Step{Group: "resolve the " + orAdapter(c.Adapter) + " blocker shown in the control reason, then " + stepRetest,
		Text: "resolve the blocker (" + reason + "), then " + stepRetest}
}

// runtimeBlocked covers BLOCKED runtime controls: before any run the reason
// is the planned one ("needs ..."); after a run it says what was missing.
func runtimeBlocked(c model.ControlResult, profile, reason, rerun string) Step {
	switch profile {
	case "production-observe", "staging-active":
		group := "fill in .pandaward/scope.yaml (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then " + rerun
		if !strings.HasPrefix(reason, "needs ") {
			return Step{Group: group, Text: "resolve the blocker (" + reason + "), then " + rerun}
		}
		var pre, need string
		switch {
		case c.ID == "D-005":
			pre, need = "install ZAP, ", " with zap.active_scan: true"
		case c.Adapter == "zap":
			pre = "install ZAP, "
		case c.ID == "B-004":
			need = " with an identity marked revoked: true and authorization_checks"
		case c.Adapter == "authz":
			need = " with identities and authorization_checks"
		}
		return Step{Group: group, Text: pre + "fill in .pandaward/scope.yaml" + need + " (`pandaward scope init` creates it), have a human approve it (`pandaward scope approve --by <name>`), then " + rerun}
	case "local-runtime":
		group := "prepare the emulator or simulator test build named in the runtime section of .pandaward/config.yaml, then " + rerun
		if !strings.HasPrefix(reason, "needs ") {
			return Step{Group: group, Text: "resolve the blocker (" + reason + "), then " + rerun}
		}
		if c.ID == "L-002" {
			return Step{Group: group, Text: "on macOS with Xcode, set runtime.ios_bundle_id in .pandaward/config.yaml and boot a simulator with the test build installed, then " + rerun}
		}
		return Step{Group: group, Text: "set runtime.android_package in .pandaward/config.yaml and start an emulator with the debuggable test build installed, then " + rerun}
	}
	return same(reviewNoAdapter)
}

// SuspectedCounts counts, per control, the open findings that keep it
// SUSPECTED: active, not confirmed and not informational, as decide counts.
func SuspectedCounts(fs []model.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		if f.Status.Active() && f.Confidence != model.Confirmed && f.Severity != model.SevInfo {
			out[f.ControlID]++
		}
	}
	return out
}

// Annotate fills DecidedBy and NextStep on every control.
func Annotate(cs []model.ControlResult, fs []model.Finding) {
	n := SuspectedCounts(fs)
	for i := range cs {
		cs[i].DecidedBy = DecidedBy(cs[i])
		cs[i].NextStep = NextStep(cs[i], n[cs[i].ID]).Text
	}
}

// PathGroup is one next step and the undecided controls it would decide.
type PathGroup struct {
	Step     string   `json:"step"`
	Count    int      `json:"count"`
	Controls []string `json:"controls"`
}

// PathTo100 groups the undecided applicable controls by next step, largest
// group first. Deciding every group would bring decisive coverage to 100%,
// except where a step says the control cannot be decided in this release.
// Attested manual controls are decided, so they are not listed; a manual
// control waits in the attestation group until a person accepts a proposal.
func PathTo100(cs []model.ControlResult, fs []model.Finding) []PathGroup {
	n := SuspectedCounts(fs)
	by := map[string]*PathGroup{}
	var out []*PathGroup
	for _, c := range cs {
		st := NextStep(c, n[c.ID])
		if st.Group == "" {
			continue
		}
		g := by[st.Group]
		if g == nil {
			g = &PathGroup{Step: st.Group}
			by[st.Group] = g
			out = append(out, g)
		}
		g.Controls = append(g.Controls, c.ID)
		g.Count++
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Step < out[j].Step
	})
	res := make([]PathGroup, len(out))
	for i, g := range out {
		sort.Strings(g.Controls)
		res[i] = *g
	}
	return res
}
