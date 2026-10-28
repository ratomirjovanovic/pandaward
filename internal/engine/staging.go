package engine

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/evidence"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/scope"
	"github.com/ratomirjovanovic/pandaward/internal/store"
	"github.com/ratomirjovanovic/pandaward/internal/zap"
)

// StagingResult summarizes a staging-active run.
type StagingResult struct {
	AssessmentID string            `json:"assessment_id"`
	Requests     int               `json:"requests_sent"`
	Budget       int               `json:"request_budget"`
	Refused      map[string]int    `json:"refused_by_guard,omitempty"`
	Controls     map[string]string `json:"controls"`
	Findings     int               `json:"findings"`
	ZAPVersion   string            `json:"zap_version,omitempty"`
	ActiveScan   bool              `json:"active_scan"`
	Notes        []string          `json:"notes,omitempty"`
}

// ZAPLocator finds the ZAP launcher; tests replace it.
var ZAPLocator = zap.Locate

// ZAPRunner runs ZAP; tests replace it.
var ZAPRunner = zap.Run

// injectionCWEs are alert classes the active scan decides under D-005.
var injectionCWEs = map[int]bool{22: true, 74: true, 77: true, 78: true, 79: true, 89: true, 90: true, 91: true, 94: true, 95: true, 97: true, 113: true, 611: true, 643: true, 917: true, 943: true, 1336: true}

// StagingActive runs the staging-active profile against the approved
// manifest: the authorization checks (C-001, C-002, B-004) first, then a
// ZAP spider and passive scan (M-001) and, when the manifest sets
// zap.active_scan, the ZAP active scan (D-005). Every request goes through
// one scope guard, so all of them share the request budget.
func (e *Engine) StagingActive(ctx context.Context, progress func(string)) (*StagingResult, error) {
	m, ap, err := e.CheckScope(time.Now())
	if err != nil {
		return nil, err
	}
	if m.Environment == "production" {
		return nil, errors.New("staging-active refuses targets marked environment: production; use production-observe there")
	}
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("run `pandaward scan` first; runtime results attach to the latest assessment")
	}
	var creds map[string]authzCred
	if len(m.AuthorizationChecks) > 0 {
		if creds, err = credentials(m); err != nil {
			return nil, err
		}
	}
	g := scope.NewGuard(m, guardRoots)
	res := &StagingResult{AssessmentID: a.ID, Budget: m.Limits.MaxRequestsTotal, Controls: map[string]string{}, ActiveScan: m.ZAP.ActiveScan}
	_ = e.St.Event(e.ProjectID, a.ID, "", "NETWORK_TEST_STARTED", fmt.Sprintf("staging-active under approval %s by %s", ap.ID, ap.ApprovedBy))
	if len(m.AuthorizationChecks) > 0 {
		err = e.runAuthz(ctx, a, m, ap, g, creds, res, progress)
	}
	if err == nil {
		err = e.runZAP(ctx, a, m, ap, g, res, progress)
	}
	res.Requests, res.Refused = g.Sent(), g.Refused()
	_ = e.St.Event(e.ProjectID, a.ID, "NETWORK_TEST_STARTED", "NETWORK_TEST_FINISHED", fmt.Sprintf("%d requests of budget %d", res.Requests, res.Budget))
	if err != nil {
		return nil, err
	}
	if inv, err := e.Inventory(); err == nil {
		if cs, err := e.St.Controls(a.ID); err == nil {
			_ = e.St.PutEdges(a.ID, BuildEdges(inv, cs))
		}
	}
	return res, nil
}

// guardRoots replaces the system roots in tests that use TLS fixtures;
// nil means the system pool.
var guardRoots *x509.CertPool

func (e *Engine) runZAP(ctx context.Context, a *store.Assessment, m *scope.Manifest, ap *store.Approval, g *scope.Guard, res *StagingResult, progress func(string)) error {
	set := func(cid string, st model.Status, reason string) error {
		res.Controls[cid] = string(st)
		return e.St.SetControlStatus(e.ProjectID, a.ID, cid, st, reason)
	}
	decided := []string{"M-001"}
	if m.ZAP.ActiveScan {
		decided = append(decided, "D-005")
	}
	setAll := func(st model.Status, reason string) error {
		for _, cid := range decided {
			if err := set(cid, st, reason); err != nil {
				return err
			}
		}
		return nil
	}
	launcher, err := ZAPLocator(e.Cfg.Runtime.ZAPPath)
	if err != nil {
		res.Notes = append(res.Notes, err.Error())
		return setAll(model.StatusBlocked, err.Error())
	}
	work := filepath.Join(e.Private(), "runs", a.ID, "zap-"+time.Now().UTC().Format("20060102T150405"))
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	progress("ZAP " + zap.Version(launcher) + " (spider, passive scan" + map[bool]string{true: ", active scan", false: ""}[m.ZAP.ActiveScan] + ")")
	zr, err := ZAPRunner(ctx, zap.Options{Launcher: launcher, Manifest: m, Guard: g, WorkDir: work, Active: m.ZAP.ActiveScan, Minutes: m.ZAP.MaxDurationMinutes, Progress: progress})
	if err != nil {
		why := redact.Line(err.Error())
		res.Notes = append(res.Notes, why)
		return setAll(model.StatusError, "ZAP run failed: "+why)
	}
	res.ZAPVersion = zr.Version
	if g.Sent() == 0 {
		why := "ZAP finished without sending any request through the scope guard; the target was not reached"
		res.Notes = append(res.Notes, why)
		return setAll(model.StatusInconclusive, why)
	}

	var sigs []model.Signal
	var evIDs []string
	for _, al := range zr.Alerts {
		s, ok := zapSignal(al, m.ZAP.ActiveScan)
		if !ok {
			continue
		}
		ev, err := evidence.Write(e.St, e.Private(), evidence.Record{AssessmentID: a.ID, Kind: "zap-alert", Collector: "zap", RuleID: s.RuleID, File: s.File,
			Observation: fmt.Sprintf("ZAP %s alert %s %q on %d URL(s)", zr.Version, al.PluginID, al.Name, len(al.Instances)),
			Data:        map[string]any{"plugin_id": al.PluginID, "risk": al.Risk, "confidence": al.Confidence, "cwe": al.CWE, "instances": zapInstances(al.Instances), "approval_id": ap.ID}})
		if err != nil {
			return err
		}
		sigs = append(sigs, s)
		evIDs = append(evIDs, ev)
	}
	seen := map[string]bool{}
	for i, s := range sigs {
		fp := fingerprint(s.RuleID+"|"+s.File+"|"+s.Key, 1)
		seen[fp] = true
		if _, _, err := e.upsertFinding(a.ID, fp, s, evIDs[i]); err != nil {
			return err
		}
	}
	res.Findings = len(sigs)

	partial := g.Halted()
	if partial == "" {
		for why := range g.Refused() {
			if strings.Contains(why, "budget") {
				partial = why
			}
		}
	}
	if partial != "" {
		res.Notes = append(res.Notes, partial)
	}
	sites := map[string]bool{}
	for _, t := range m.Targets {
		sites[zap.Origin(t.URL)] = true
	}
	if partial == "" {
		fs, _ := e.St.Findings(e.ProjectID)
		for _, f := range fs {
			if f.Collector == "zap" && f.Status.Active() && !seen[f.Fingerprint] && sites[f.File] && (f.ControlID == "M-001" || m.ZAP.ActiveScan) {
				old := f.Status
				f.Status = model.FindingRemediated
				f.AssessmentID = a.ID
				_ = e.St.UpsertFinding(e.ProjectID, f)
				_ = e.St.Event(e.ProjectID, f.ID, string(old), string(f.Status), "ZAP no longer raised it on a complete run")
			}
		}
	}
	for _, cid := range decided {
		st, reason := decide(sigs, cid, fmt.Sprintf("ZAP %s, %d requests", zr.Version, g.Sent()))
		if partial != "" && st != model.StatusFail {
			st, reason = model.StatusInconclusive, "ZAP run incomplete: "+partial
		}
		if err := set(cid, st, reason); err != nil {
			return err
		}
	}
	return nil
}

// zapSignal maps one ZAP alert to a finding signal. Alerts ZAP itself marks
// as false positives are dropped.
func zapSignal(al zap.Alert, active bool) (model.Signal, bool) {
	if al.Confidence <= 0 {
		return model.Signal{}, false
	}
	sev := map[int]model.Severity{3: model.SevHigh, 2: model.SevMedium, 1: model.SevLow}[al.Risk]
	if sev == "" {
		sev = model.SevInfo
	}
	conf := model.Hypothesis
	switch {
	case al.Confidence >= 3:
		conf = model.Confirmed
	case al.Confidence == 2:
		conf = model.StronglySupported
	}
	cid := "M-001"
	if active && injectionCWEs[al.CWE] {
		cid = "D-005"
	}
	cwe := ""
	if al.CWE > 0 {
		cwe = fmt.Sprintf("CWE-%d", al.CWE)
	}
	where := ""
	if len(al.Instances) > 0 {
		where = " First at " + redact.Line(al.Instances[0].Method+" "+al.Instances[0].URI) + "."
	}
	return model.Signal{RuleID: "zap." + al.PluginID, ControlID: cid, Title: redact.Line(al.Name), Severity: sev, Confidence: conf, CWE: cwe, File: redact.Line(zap.Origin(al.Site)),
		Message: redact.Line(fmt.Sprintf("ZAP raised this on %d URL(s).%s %s", len(al.Instances), where, clip(al.Desc, 400))),
		Fix:     redact.Line(clip(al.Solution, 500)), Collector: "zap", Key: al.PluginID,
		Retest: "Deploy the fix to the approved target, then run `pandaward test --profile staging-active` again (needs a valid approval)."}, true
}

func zapInstances(in []zap.Instance) []zap.Instance {
	sort.SliceStable(in, func(i, j int) bool { return in[i].URI < in[j].URI })
	if len(in) > 20 {
		in = in[:20]
	}
	out := make([]zap.Instance, len(in))
	for i, x := range in {
		out[i] = zap.Instance{URI: redact.Line(x.URI), Method: x.Method, Param: redact.Line(x.Param), Evidence: redact.Line(clip(x.Evidence, 200))}
	}
	return out
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}
