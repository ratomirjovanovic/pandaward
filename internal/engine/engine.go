// Package engine coordinates inventory, planning, adapters, findings and
// coverage. It is the only component that writes assessment state.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pensec/internal/adapters"
	"github.com/ratomirjovanovic/pensec/internal/catalog"
	"github.com/ratomirjovanovic/pensec/internal/config"
	"github.com/ratomirjovanovic/pensec/internal/evidence"
	"github.com/ratomirjovanovic/pensec/internal/inventory"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
	"github.com/ratomirjovanovic/pensec/internal/store"
	"github.com/ratomirjovanovic/pensec/internal/version"
)

// Engine is bound to one project root.
type Engine struct {
	Root       string
	ProjectID  string
	Cfg        *config.Config
	ConfigHash string
	St         *store.Store
}

// ProjectID derives a stable local project ID from the absolute root.
func ProjectID(root string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.ToSlash(root))))
	return "prj_" + hex.EncodeToString(sum[:])[:12]
}

// FindRoot walks up from dir to the directory that holds .pensec/config.yaml.
func FindRoot(dir string) (string, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(config.Path(d)); err == nil {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", config.ErrNotInitialized
		}
		d = parent
	}
}

// Init creates the project layout and database.
func Init(root string, force bool) (*Engine, bool, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, false, err
	}
	created := false
	if _, err := os.Stat(config.Path(abs)); errors.Is(err, os.ErrNotExist) || force {
		if err := config.Write(abs, config.Default(filepath.Base(abs)), force); err != nil {
			return nil, false, err
		}
		created = true
	}
	if err := config.EnsureLayout(abs); err != nil {
		return nil, false, err
	}
	e, err := Open(abs)
	return e, created, err
}

// Open opens an initialized project.
func Open(root string) (*Engine, error) {
	cfg, h, err := config.Load(root)
	if err != nil {
		return nil, err
	}
	if err := config.EnsureLayout(root); err != nil {
		return nil, err
	}
	st, err := store.Open(config.PrivateDir(root))
	if err != nil {
		return nil, err
	}
	e := &Engine{Root: root, ProjectID: ProjectID(root), Cfg: cfg, ConfigHash: h, St: st}
	if err := st.EnsureProject(e.ProjectID, root, cfg.Project.Name); err != nil {
		st.Close()
		return nil, err
	}
	return e, nil
}

// Close releases the database.
func (e *Engine) Close() error { return e.St.Close() }

// Private returns the private directory.
func (e *Engine) Private() string { return config.PrivateDir(e.Root) }

// Inventory walks the repository.
func (e *Engine) Inventory() (*inventory.Inventory, error) {
	return inventory.Walk(e.Root, inventory.Options{Exclude: e.Cfg.Inventory.Exclude, MaxFileBytes: e.Cfg.Inventory.MaxFileBytes, MaxFiles: e.Cfg.Inventory.MaxFiles})
}

// PlanItem is one control decision before execution.
type PlanItem struct {
	Control  catalog.Control `json:"control"`
	Status   model.Status    `json:"planned_status"`
	Reason   string          `json:"reason"`
	Adapter  string          `json:"adapter,omitempty"`
	Evidence []string        `json:"applicability_evidence,omitempty"`
}

// Plan maps the catalog onto the inventory.
func (e *Engine) Plan(inv *inventory.Inventory) []PlanItem {
	enabled := map[string]bool{}
	for _, a := range e.Cfg.Scan.Adapters {
		enabled[a] = true
	}
	var out []PlanItem
	for _, c := range catalog.Controls {
		it := PlanItem{Control: c, Adapter: c.Adapter}
		if !inv.Has(c.Requires) {
			it.Status = model.StatusNotApplicable
			it.Reason = fmt.Sprintf("auto: no '%s' assets found in inventory (review this decision)", c.Requires)
			out = append(out, it)
			continue
		}
		ev := inv.Features[c.Requires]
		if len(ev) > 3 {
			ev = ev[:3]
		}
		it.Evidence = ev
		switch c.Method {
		case catalog.MethodStatic, catalog.MethodExternal:
			if c.Adapter == "builtin-evidence" {
				it.Status, it.Reason = "PLANNED", "verified after the scan"
			} else if !enabled[c.Adapter] {
				it.Status, it.Reason = model.StatusBlocked, "adapter "+c.Adapter+" disabled in config"
			} else {
				it.Status, it.Reason = "PLANNED", "runs in passive scan via "+c.Adapter
			}
		case catalog.MethodRuntime:
			if c.Adapter == "observe-headers" {
				it.Status, it.Reason = model.StatusBlocked, "needs `pensec test --profile production-observe` with an approved scope manifest"
			} else {
				it.Status, it.Reason = model.StatusUnsupported, "runtime adapter for profile "+c.Profile+" is not implemented in this release; use manual-assisted review"
			}
		case catalog.MethodManual:
			it.Status, it.Reason = model.StatusBlocked, "manual-assisted review required (/pensec:review); not decided by automation"
		}
		out = append(out, it)
	}
	return out
}

// ScanResult summarizes a passive scan.
type ScanResult struct {
	AssessmentID string         `json:"assessment_id"`
	Status       string         `json:"status"`
	Runs         []model.Run    `json:"runs"`
	New          int            `json:"new_findings"`
	Reopened     int            `json:"reopened"`
	Remediated   int            `json:"remediated"`
	Open         int            `json:"open_findings"`
	Coverage     Coverage       `json:"coverage"`
	Errors       []string       `json:"errors,omitempty"`
	Controls     map[string]int `json:"control_status_counts"`
}

// Coverage is the coverage arithmetic from PRD 15.2.
type Coverage struct {
	Applicable    int     `json:"applicable_controls"`
	Decisive      int     `json:"decisive_controls"`
	Ratio         float64 `json:"decisive_control_coverage"`
	EdgesTotal    int     `json:"edges_total"`
	EdgesVerified int     `json:"edges_verified"`
	EdgesFailed   int     `json:"edges_failed"`
	EdgesOpen     int     `json:"edges_blocked_or_inconclusive"`
	Stale         int     `json:"stale_files"`
	Note          string  `json:"note"`
}

// ComputeCoverage computes coverage from controls and edges. Pass the stale
// view (see StaleView) so invalidated controls count as not decisive; stale
// is the number of changed files and only feeds the note.
func ComputeCoverage(cs []model.ControlResult, es []model.Edge, stale int) Coverage {
	var c Coverage
	for _, x := range cs {
		if x.Status == model.StatusNotApplicable {
			continue
		}
		c.Applicable++
		if x.Status.Decisive() {
			c.Decisive++
		}
	}
	if c.Applicable > 0 {
		c.Ratio = float64(c.Decisive) / float64(c.Applicable)
	}
	for _, x := range es {
		c.EdgesTotal++
		switch x.Status {
		case model.StatusPass:
			c.EdgesVerified++
		case model.StatusFail:
			c.EdgesFailed++
		default:
			c.EdgesOpen++
		}
	}
	c.Stale = stale
	c.Note = "Coverage counts decisively tested controls (PASS/FAIL) over applicable controls. It is not a percentage of vulnerabilities found. BLOCKED, UNSUPPORTED, SUSPECTED, INCONCLUSIVE, ERROR and STALE never count as secure."
	if stale > 0 {
		c.Note += fmt.Sprintf(" %d file(s) changed since the assessment; controls and edges that depend on them are STALE until `pensec retest`.", stale)
	}
	return c
}

// Scan runs the passive local assessment.
func (e *Engine) Scan(ctx context.Context, progress func(string)) (*ScanResult, error) {
	return e.scan(ctx, progress, nil)
}

// carryState is what a targeted retest reuses from the previous assessment.
type carryState struct {
	from     string
	adapters map[string]bool // adapters whose inputs did not change
	controls map[string]model.ControlResult
	runs     map[string]model.Run
}

// Retest re-runs only the adapters that watch a changed path. Every other
// adapter is recorded as CARRIED and keeps its previous decisions, evidence
// and findings. Edges and evidence integrity are always recomputed. It falls
// back to a full scan when there is no comparable previous assessment.
func (e *Engine) Retest(ctx context.Context, progress func(string), changed []string) (*ScanResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	prev, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		return nil, err
	}
	switch {
	case prev == nil:
		progress("retest: no previous assessment; running a full scan")
		return e.scan(ctx, progress, nil)
	case prev.Profile != "local-passive" || prev.ConfigHash != e.ConfigHash || prev.CatalogVersion != catalog.Version:
		progress("retest: config, catalog or profile changed since " + prev.ID + "; running a full scan")
		return e.scan(ctx, progress, nil)
	}
	cs, err := e.St.Controls(prev.ID)
	if err != nil {
		return nil, err
	}
	runs, err := e.St.Runs(prev.ID)
	if err != nil {
		return nil, err
	}
	cy := &carryState{from: prev.ID, adapters: map[string]bool{}, controls: map[string]model.ControlResult{}, runs: map[string]model.Run{}}
	for _, c := range cs {
		cy.controls[c.ID] = c
	}
	for _, r := range runs {
		cy.runs[r.Adapter] = r
	}
	affected := AffectedAdapters(e.Cfg.Scan.Adapters, changed)
	for _, a := range e.Cfg.Scan.Adapters {
		if r, ok := cy.runs[a]; ok && r.ExitClass == model.ExitOK && !affected[a] {
			cy.adapters[a] = true
		}
	}
	return e.scan(ctx, progress, cy)
}

// RetestChanged lists the files changed since the last assessment and then
// runs a targeted retest (changedOnly) or a full scan.
func (e *Engine) RetestChanged(ctx context.Context, progress func(string), changedOnly bool) ([]string, *ScanResult, error) {
	inv, err := e.Inventory()
	if err != nil {
		return nil, nil, err
	}
	changed, err := e.ChangedSinceLast(inv)
	if err != nil {
		return nil, nil, err
	}
	var res *ScanResult
	if changedOnly {
		res, err = e.Retest(ctx, progress, changed)
	} else {
		res, err = e.Scan(ctx, progress)
	}
	return changed, res, err
}

// carry copies an adapter's previous decisions into results. It refuses when
// a control's applicability changed, because the old run never decided it.
func (cy *carryState) carry(ad adapters.Adapter, results map[string]*model.ControlResult, ctrlEvidence map[string][]string) (model.Run, bool) {
	if cy == nil || !cy.adapters[ad.Name()] {
		return model.Run{}, false
	}
	for _, cid := range ad.Controls() {
		r, old := results[cid], cy.controls[cid]
		if r == nil {
			continue
		}
		if old.ID == "" || (r.Status == model.StatusNotApplicable) != (old.Status == model.StatusNotApplicable) {
			return model.Run{}, false
		}
	}
	for _, cid := range ad.Controls() {
		if r := results[cid]; r != nil && r.Status != model.StatusNotApplicable {
			old := cy.controls[cid]
			r.Status, r.Reason = old.Status, old.Reason
			ctrlEvidence[cid] = old.EvidenceIDs
		}
	}
	prev := cy.runs[ad.Name()]
	now := store.Now()
	return model.Run{ID: ad.Name() + "-carried", Adapter: ad.Name(), ToolVersion: prev.ToolVersion, StartedAt: now, EndedAt: now, ExitClass: model.ExitCarried,
		Detail: "inputs unchanged since " + cy.from + "; decisions carried over", SignalsCount: prev.SignalsCount}, true
}

func (e *Engine) scan(ctx context.Context, progress func(string), cy *carryState) (*ScanResult, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if n, _ := e.St.MarkInterrupted(e.ProjectID); n > 0 {
		progress(fmt.Sprintf("recovered %d interrupted assessment(s); they are kept as INTERRUPTED and not used", n))
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(e.Cfg.Scan.MaxDurationMinutes)*time.Minute)
	defer cancel()

	progress("inventory: walking repository (read-only, symlinks not followed)")
	inv, err := e.Inventory()
	if err != nil {
		return nil, err
	}
	asmt, err := e.St.NewAssessment(e.ProjectID, store.Assessment{GitCommit: inv.GitCommit, GitDirty: inv.GitDirty, Profile: "local-passive", ConfigHash: e.ConfigHash, CatalogVersion: catalog.Version})
	if err != nil {
		return nil, err
	}
	if err := e.St.PutAssets(asmt.ID, inv.Assets); err != nil {
		return nil, err
	}
	hashes, domains := map[string]string{}, map[string][]string{}
	for _, f := range inv.Files {
		hashes[f.Path] = f.SHA256
		domains[f.Path] = f.Domains
	}
	if err := e.St.PutFileHashes(asmt.ID, hashes, domains); err != nil {
		return nil, err
	}

	plan := e.Plan(inv)
	results := map[string]*model.ControlResult{}
	for _, p := range plan {
		cr := &model.ControlResult{ID: p.Control.ID, Domain: p.Control.Domain, Title: p.Control.Title, Method: p.Control.Method, Adapter: p.Adapter, Refs: p.Control.Refs, Status: p.Status, Reason: p.Reason}
		results[p.Control.ID] = cr
	}

	runDir := filepath.Join(e.Private(), "runs", asmt.ID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, err
	}
	actx := &adapters.Context{Root: e.Root, Inv: inv, Cfg: e.Cfg, RunDir: runDir, ToolHome: filepath.Join(e.Private(), "tool-home"),
		Timeout: time.Duration(e.Cfg.Scan.AdapterTimeoutSec) * time.Second}
	enabled := map[string]bool{}
	for _, a := range e.Cfg.Scan.Adapters {
		enabled[a] = true
	}
	res := &ScanResult{AssessmentID: asmt.ID, Controls: map[string]int{}}
	var allSignals []model.Signal
	ranOK := map[string]bool{}   // adapter -> completed OK
	carried := map[string]bool{} // adapter -> decisions carried over
	ctrlEvidence := map[string][]string{}
	for _, ad := range adapters.Registry() {
		if !enabled[ad.Name()] {
			continue
		}
		applicable := false
		for _, cid := range ad.Controls() {
			if r := results[cid]; r != nil && r.Status != model.StatusNotApplicable {
				applicable = true
			}
		}
		if !applicable {
			continue
		}
		if run, ok := cy.carry(ad, results, ctrlEvidence); ok {
			progress("adapter: " + ad.Name() + " (inputs unchanged, carried over)")
			if err := e.St.PutRun(asmt.ID, run); err != nil {
				return nil, err
			}
			res.Runs = append(res.Runs, run)
			carried[ad.Name()] = true
			continue
		}
		progress("adapter: " + ad.Name())
		out, run := safeRun(ctx, ad, actx)
		if err := e.St.PutRun(asmt.ID, run); err != nil {
			return nil, err
		}
		res.Runs = append(res.Runs, run)
		if run.ExitClass != model.ExitOK {
			st := model.StatusError
			switch run.ExitClass {
			case model.ExitBlocked:
				st = model.StatusBlocked
			case model.ExitUnsupported:
				st = model.StatusUnsupported
			}
			for _, cid := range ad.Controls() {
				if r := results[cid]; r != nil && r.Status != model.StatusNotApplicable {
					r.Status, r.Reason = st, run.Detail
				}
			}
			if run.ExitClass == model.ExitError || run.ExitClass == model.ExitTimeout {
				res.Errors = append(res.Errors, ad.Name()+": "+run.Detail)
			}
			continue
		}
		ranOK[ad.Name()] = true
		allSignals = append(allSignals, out.Signals...)
		for _, cid := range ad.Controls() {
			r := results[cid]
			if r == nil || r.Status == model.StatusNotApplicable {
				continue
			}
			if d, ok := out.Decisions[cid]; ok {
				r.Status, r.Reason = d.Status, d.Reason
				continue
			}
			r.Status, r.Reason = decide(out.Signals, cid, run.Detail)
		}
		for cid, d := range out.Decisions {
			if r := results[cid]; r != nil && r.Status != model.StatusNotApplicable {
				r.Status, r.Reason = d.Status, d.Reason
			}
		}
	}

	// Persist findings with evidence.
	progress("findings: normalizing, fingerprinting and writing redacted evidence")
	seen := map[string]bool{}
	occurrence := map[string]int{}
	for _, s := range allSignals {
		base := s.RuleID + "|" + s.File + "|" + s.Key + "|" + normalizeSnippet(s.Snippet)
		occurrence[base]++
		fp := fingerprint(base, occurrence[base])
		if seen[fp] {
			continue
		}
		seen[fp] = true
		var fileSHA string
		if f := inv.FileByPath(s.File); f != nil {
			fileSHA = f.SHA256
		}
		evID, err := evidence.Write(e.St, e.Private(), evidence.Record{AssessmentID: asmt.ID, Kind: "source-observation", Collector: s.Collector, RuleID: s.RuleID, File: s.File,
			StartLine: s.StartLine, EndLine: s.EndLine, FileSHA256: fileSHA, Snippet: s.Snippet, Observation: s.Message, GitCommit: inv.GitCommit})
		if err != nil {
			return nil, err
		}
		ctrlEvidence[s.ControlID] = append(ctrlEvidence[s.ControlID], evID)
		n, r, err := e.upsertFinding(asmt.ID, fp, s, evID)
		if err != nil {
			return nil, err
		}
		if n {
			res.New++
		}
		if r {
			res.Reopened++
		}
	}
	// Findings not seen again whose adapter completed OK and whose file was scanned are remediated.
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		if seen[f.Fingerprint] || !f.Status.Active() || f.Collector == "manual-assisted" || carried[f.Collector] {
			continue
		}
		if !ranOK[f.Collector] {
			f.Stale = true
			_ = e.St.UpsertFinding(e.ProjectID, f)
			continue
		}
		old := f.Status
		f.Status = model.FindingRemediated
		f.Stale = false
		f.AssessmentID = asmt.ID
		f.Note = strings.TrimSpace(f.Note + " Not observed in " + asmt.ID + " (" + f.Collector + " completed OK).")
		if err := e.St.UpsertFinding(e.ProjectID, f); err != nil {
			return nil, err
		}
		_ = e.St.Event(e.ProjectID, f.ID, string(old), string(f.Status), "signal no longer observed by "+f.Collector+" in "+asmt.ID)
		res.Remediated++
	}

	// Evidence integrity (R-001).
	okN, bad, err := evidence.Verify(e.St, e.Private(), asmt.ID)
	if err != nil {
		return nil, err
	}
	if r := results["R-001"]; r != nil {
		if len(bad) == 0 {
			r.Status, r.Reason = model.StatusPass, fmt.Sprintf("%d evidence artifacts verified against SHA-256", okN)
		} else {
			r.Status, r.Reason = model.StatusFail, "integrity failure: "+strings.Join(bad, ", ")
		}
	}
	var crs []model.ControlResult
	for _, c := range catalog.Controls {
		r := results[c.ID]
		r.EvidenceIDs = ctrlEvidence[c.ID]
		if r.Status == "PLANNED" {
			r.Status, r.Reason = model.StatusBlocked, "planned but not executed"
		}
		crs = append(crs, *r)
		res.Controls[string(r.Status)]++
	}
	if err := e.St.PutControls(asmt.ID, crs); err != nil {
		return nil, err
	}
	edges := BuildEdges(inv, crs)
	if err := e.St.PutEdges(asmt.ID, edges); err != nil {
		return nil, err
	}
	if err := e.St.ClearStale(e.ProjectID); err != nil {
		return nil, err
	}
	res.Coverage = ComputeCoverage(crs, edges, 0)
	fs, _ = e.St.Findings(e.ProjectID)
	for _, f := range fs {
		if f.Status.Active() {
			res.Open++
		}
	}
	status := "COMPLETE"
	if len(res.Errors) > 0 || ctx.Err() != nil {
		status = "INCOMPLETE"
	}
	res.Status = status
	manifest, _ := json.Marshal(map[string]any{"schema_version": model.SchemaVersion, "pensec_version": version.Version, "catalog_version": catalog.Version, "profile": "local-passive",
		"git_commit": inv.GitCommit, "git_dirty": inv.GitDirty, "config_sha256": e.ConfigHash, "runs": res.Runs, "files_analyzed": len(inv.Files), "files_skipped": len(inv.Skipped),
		"network_requests_to_targets": 0})
	if err := e.St.FinishAssessment(e.ProjectID, asmt.ID, status, string(manifest)); err != nil {
		return nil, err
	}
	return res, nil
}

// safeRun isolates adapter panics so a crashing scanner is recorded as ERROR,
// never as a clean result.
func safeRun(ctx context.Context, ad adapters.Adapter, c *adapters.Context) (out adapters.Result, run model.Run) {
	defer func() {
		if r := recover(); r != nil {
			out = adapters.Result{}
			run = model.Run{ID: ad.Name() + "-panic", Adapter: ad.Name(), StartedAt: store.Now(), EndedAt: store.Now(), ExitClass: model.ExitError, Detail: redact.Line(fmt.Sprint("adapter crashed: ", r))}
		}
	}()
	return ad.Run(ctx, c)
}

// decide maps signals of one control to a status. Info-only signals are
// listings and do not fail a control. Hypotheses only make it SUSPECTED.
func decide(sigs []model.Signal, cid, detail string) (model.Status, string) {
	var confirmed, hyp, info int
	for _, s := range sigs {
		if s.ControlID != cid {
			continue
		}
		switch {
		case s.Severity == model.SevInfo:
			info++
		case s.Confidence == model.Confirmed:
			confirmed++
		default:
			hyp++
		}
	}
	switch {
	case confirmed > 0:
		return model.StatusFail, fmt.Sprintf("%d confirmed observation(s)%s", confirmed, plus(hyp, " suspected"))
	case hyp > 0:
		return model.StatusSuspected, fmt.Sprintf("%d heuristic signal(s) need review; not confirmed", hyp)
	case info > 0:
		return model.StatusPass, fmt.Sprintf("check completed; %d item(s) listed for review", info)
	}
	return model.StatusPass, "check completed with no signal (" + detail + "); PASS applies to this check only"
}

func plus(n int, s string) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", %d%s", n, s)
}

func normalizeSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func fingerprint(base string, occ int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", base, occ)))
	return hex.EncodeToString(sum[:])[:32]
}

func (e *Engine) upsertFinding(asmt, fp string, s model.Signal, evID string) (isNew, reopened bool, err error) {
	now := store.Now()
	old, err := e.St.FindingByFingerprint(e.ProjectID, fp)
	if err != nil {
		return false, false, err
	}
	f := model.Finding{Fingerprint: fp, RuleID: s.RuleID, ControlID: s.ControlID, Title: s.Title, Severity: s.Severity, Confidence: s.Confidence, CWE: s.CWE, File: s.File,
		StartLine: s.StartLine, EndLine: s.EndLine, Message: s.Message, Fix: s.Fix, Retest: s.Retest, Collector: s.Collector, LastSeen: now, EvidenceIDs: []string{evID}, AssessmentID: asmt}
	if f.Retest == "" {
		f.Retest = "Apply the fix, then run `pensec retest`; the finding becomes REMEDIATED only when " + s.Collector + " completes and no longer observes it."
	}
	if old == nil {
		id, err := e.St.NextFindingID(e.ProjectID)
		if err != nil {
			return false, false, err
		}
		f.ID, f.FirstSeen, f.Status = id, now, model.FindingOpen
		if err := e.St.UpsertFinding(e.ProjectID, f); err != nil {
			return false, false, err
		}
		return true, false, e.St.Event(e.ProjectID, id, "", string(f.Status), "first observed in "+asmt)
	}
	f.ID, f.FirstSeen, f.Reviewer, f.Note, f.ExpiresAt = old.ID, old.FirstSeen, old.Reviewer, old.Note, old.ExpiresAt
	f.Status = old.Status
	switch old.Status {
	case model.FindingRemediated:
		f.Status = model.FindingReopened
		reopened = true
	case model.FindingRiskAccepted:
		if exp, err := time.Parse(time.RFC3339, old.ExpiresAt); err == nil && time.Now().After(exp) {
			f.Status = model.FindingReopened
			reopened = true
		}
	}
	if err := e.St.UpsertFinding(e.ProjectID, f); err != nil {
		return false, false, err
	}
	if f.Status != old.Status {
		err = e.St.Event(e.ProjectID, f.ID, string(old.Status), string(f.Status), "observed again in "+asmt)
	}
	return false, reopened, err
}

// BuildEdges instantiates seed edges only where both sides have concrete
// assets, and derives each edge status from its linked controls.
func BuildEdges(inv *inventory.Inventory, crs []model.ControlResult) []model.Edge {
	byID := map[string]model.ControlResult{}
	for _, c := range crs {
		byID[c.ID] = c
	}
	feat := func(name string) []string {
		switch name {
		case "route_files_with_sinks":
			rf := inv.RouteFiles()
			var out []string
			for _, c := range crs {
				if c.Domain == "D" && (c.Status == model.StatusFail || c.Status == model.StatusSuspected) {
					out = append(out, "control:"+c.ID)
				}
			}
			if len(out) == 0 || len(rf) == 0 {
				return nil
			}
			for f := range rf {
				out = append(out, "file:"+f)
			}
			sort.Strings(out)
			return out
		case "secrets_in_config":
			var out []string
			for _, c := range crs {
				if (c.ID == "E-001" || c.ID == "E-002") && c.Status == model.StatusFail {
					out = append(out, "control:"+c.ID)
				}
			}
			return out
		case "html_sinks":
			if c, ok := byID["H-001"]; ok && (c.Status == model.StatusFail || c.Status == model.StatusSuspected) {
				return []string{"control:H-001"}
			}
			return nil
		case "headers_observed":
			if c, ok := byID["H-003"]; ok && c.Status.Decisive() {
				return []string{"control:H-003"}
			}
			return nil
		}
		return inv.Features[name]
	}
	var out []model.Edge
	for _, r := range catalog.Edges {
		var prov []string
		ok := true
		for _, n := range r.Needs {
			p := feat(n)
			if len(p) == 0 {
				ok = false
				break
			}
			if len(p) > 5 {
				p = append(p[:5:5], fmt.Sprintf("(+%d more)", len(p)-5))
			}
			prov = append(prov, p...)
		}
		if !ok {
			continue
		}
		e := model.Edge{ID: r.ID, Domains: r.ID[:2], Title: r.Title, Scenario: r.Scenario, Provenance: prov, Tests: r.Tests}
		e.Status, e.Reason = edgeStatus(r.Tests, byID)
		out = append(out, e)
	}
	return out
}

func edgeStatus(tests []string, byID map[string]model.ControlResult) (model.Status, string) {
	var fail, susp, pass, open []string
	for _, t := range tests {
		c, ok := byID[t]
		if !ok {
			open = append(open, t+"=missing")
			continue
		}
		switch c.Status {
		case model.StatusFail:
			fail = append(fail, t)
		case model.StatusSuspected:
			susp = append(susp, t)
		case model.StatusPass:
			pass = append(pass, t)
		case model.StatusNotApplicable:
		default:
			open = append(open, t+"="+string(c.Status))
		}
	}
	switch {
	case len(fail) > 0:
		return model.StatusFail, "failed controls: " + strings.Join(fail, ", ")
	case len(open) > 0:
		return model.StatusBlocked, "not decided: " + strings.Join(open, ", ")
	case len(susp) > 0:
		return model.StatusSuspected, "suspected: " + strings.Join(susp, ", ")
	case len(pass) > 0:
		return model.StatusPass, "all linked controls passed: " + strings.Join(pass, ", ")
	}
	return model.StatusInconclusive, "no decisive linked control"
}
