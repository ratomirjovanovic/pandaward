// Package report renders the assessment ledger as JSON, Markdown, HTML and
// SARIF 2.1.0. Reports only contain redacted data from the ledger.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/evidence"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/store"
	"github.com/ratomirjovanovic/pandaward/internal/version"
)

// Attestation is printed on every report (PRD 23.2).
const Attestation = "Automated technical security assessment. Not a certification, attestation, legal opinion or independently signed penetration test, and not a guarantee that no vulnerabilities exist. Only the controls listed as PASS were decisively checked, and only for the stated scope, method and point in time."

// Report is the full report model.
type Report struct {
	SchemaVersion int              `json:"schema_version"`
	Generator     string           `json:"generator"`
	GeneratedAt   string           `json:"generated_at"`
	Project       string           `json:"project"`
	Assessment    store.Assessment `json:"assessment"`
	Attestation   string           `json:"attestation"`
	Coverage      engine.Coverage  `json:"coverage"`
	// PathTo100 groups the undecided applicable controls by next step.
	PathTo100 []engine.PathGroup `json:"path_to_100,omitempty"`
	// Attestations are the human attestations that decide (or decided,
	// when stale) manual controls, then the pending proposals, which
	// decide nothing.
	Attestations  []store.Attestation       `json:"attestations,omitempty"`
	StaleFiles    []string                  `json:"stale_files,omitempty"`
	Controls      []model.ControlResult     `json:"controls"`
	Edges         []model.Edge              `json:"edges"`
	Findings      []model.Finding           `json:"findings"`
	Runs          []model.Run               `json:"runs"`
	EvidenceIndex []store.EvidenceRow       `json:"evidence_index"`
	Domains       []catalog.Domain          `json:"domains"`
	DomainSummary map[string]map[string]int `json:"domain_summary"`
	Manifest      json.RawMessage           `json:"assessment_manifest,omitempty"`
	// Delta compares with the previous assessment that tracked observations.
	Delta *engine.Delta `json:"delta,omitempty"`
}

// Build loads the latest assessment into a report.
func Build(e *engine.Engine) (*Report, error) {
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("no completed assessment: run `pandaward scan` first")
	}
	return BuildFor(e, a)
}

// BuildFor loads one assessment into a report.
func BuildFor(e *engine.Engine, a *store.Assessment) (*Report, error) {
	delta, err := e.DeltaToPrevious(a.ID)
	if err != nil {
		return nil, err
	}
	r := &Report{Delta: delta, SchemaVersion: model.SchemaVersion, Generator: "pandaward " + version.Version, GeneratedAt: store.Now(), Project: e.Cfg.Project.Name, Assessment: *a, Attestation: Attestation, Domains: catalog.Domains}
	if a.ManifestJSON != "" {
		r.Manifest = json.RawMessage(a.ManifestJSON)
	}
	if r.Controls, err = e.St.Controls(a.ID); err != nil {
		return nil, err
	}
	if r.Edges, err = e.St.Edges(a.ID); err != nil {
		return nil, err
	}
	if r.Runs, err = e.St.Runs(a.ID); err != nil {
		return nil, err
	}
	// Include evidence carried over from earlier assessments so every
	// evidence ID a control cites is listed.
	if r.EvidenceIndex, _, err = evidence.Collect(e.St, a.ID, evidence.Referenced(r.Controls)); err != nil {
		return nil, err
	}
	var ch engine.Changes
	if r.Controls, r.Edges, ch, err = e.StaleView(a.ID, r.Controls, r.Edges); err != nil {
		return nil, err
	}
	r.StaleFiles = ch.Files
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(fs, func(i, j int) bool {
		ai, aj := fs[i].Status.Active(), fs[j].Status.Active()
		if ai != aj {
			return ai
		}
		ci, cj := fs[i].Confidence == model.Hypothesis, fs[j].Confidence == model.Hypothesis
		if ci != cj {
			return !ci
		}
		if model.SeverityRank(fs[i].Severity) != model.SeverityRank(fs[j].Severity) {
			return model.SeverityRank(fs[i].Severity) > model.SeverityRank(fs[j].Severity)
		}
		return fs[i].ID < fs[j].ID
	})
	r.Findings = fs
	engine.Annotate(r.Controls, fs)
	r.Coverage = engine.ComputeCoverage(r.Controls, r.Edges, len(r.StaleFiles))
	r.PathTo100 = engine.PathTo100(r.Controls, fs)
	if r.Attestations, err = e.ReportAttestations(); err != nil {
		return nil, err
	}
	r.DomainSummary = map[string]map[string]int{}
	for _, c := range r.Controls {
		if r.DomainSummary[c.Domain] == nil {
			r.DomainSummary[c.Domain] = map[string]int{}
		}
		r.DomainSummary[c.Domain][string(c.Status)]++
	}
	return r, nil
}

// Confirmed returns active non-hypothesis findings.
func (r *Report) Confirmed() []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if f.Status.Active() && f.Confidence != model.Hypothesis {
			out = append(out, f)
		}
	}
	return out
}

// Suspected returns active hypothesis findings.
func (r *Report) Suspected() []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if f.Status.Active() && f.Confidence == model.Hypothesis {
			out = append(out, f)
		}
	}
	return out
}

// Closed returns non-active findings.
func (r *Report) Closed() []model.Finding {
	var out []model.Finding
	for _, f := range r.Findings {
		if !f.Status.Active() {
			out = append(out, f)
		}
	}
	return out
}

// Untested returns controls that are applicable but not decided.
func (r *Report) Untested() []model.ControlResult {
	var out []model.ControlResult
	for _, c := range r.Controls {
		if !c.Status.Decisive() && c.Status != model.StatusNotApplicable {
			out = append(out, c)
		}
	}
	return out
}

func (r *Report) staleControls() int {
	n := 0
	for _, c := range r.Controls {
		if c.Status == model.StatusStale {
			n++
		}
	}
	return n
}

// Write renders the requested formats into dir and returns the paths.
func Write(r *Report, dir string, formats []string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	var out []string
	for _, f := range formats {
		var b []byte
		var err error
		var ext string
		switch f {
		case "json":
			b, err = json.MarshalIndent(r, "", "  ")
			ext = "json"
		case "markdown", "md":
			b, ext = []byte(Markdown(r)), "md"
		case "html":
			b, err = HTML(r)
			ext = "html"
		case "sarif":
			b, err = SARIF(r)
			ext = "sarif"
		case "csv":
			b, ext = []byte(CoverageCSV(r)), "csv"
		default:
			return out, fmt.Errorf("unknown report format %q (html, markdown, json, sarif, csv)", f)
		}
		if err != nil {
			return out, err
		}
		p := filepath.Join(dir, fmt.Sprintf("pandaward-%s-%s.%s", r.Assessment.ID, stamp, ext))
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return out, err
		}
		out = append(out, p)
	}
	return out, nil
}

// DefaultDir returns the report directory of a project.
func DefaultDir(root string) string { return config.ReportsDir(root) }

func pct(f float64) string { return fmt.Sprintf("%.0f%%", f*100) }

func esc(s string) string {
	r := strings.NewReplacer("|", "\\|", "\n", " ", "`", "'", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// Markdown renders the technical report.
func Markdown(r *Report) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("# PandaWard assessment report: %s\n\n", esc(r.Project))
	w("> %s\n\n", Attestation)
	w("| Field | Value |\n|---|---|\n")
	w("| Assessment | %s (%s) |\n", r.Assessment.ID, r.Assessment.Status)
	w("| Profile | %s |\n", r.Assessment.Profile)
	commit := r.Assessment.GitCommit
	if commit == "" {
		commit = "not a git repository"
	}
	if r.Assessment.GitDirty {
		commit += " (uncommitted changes present)"
	}
	w("| Code revision | %s |\n", commit)
	w("| Window | %s to %s |\n", r.Assessment.StartedAt, r.Assessment.EndedAt)
	w("| Catalog | %s |\n| Generator | %s |\n\n", r.Assessment.CatalogVersion, r.Generator)

	w("## Executive summary\n\n")
	conf, susp := r.Confirmed(), r.Suspected()
	sev := map[model.Severity]int{}
	for _, f := range conf {
		sev[f.Severity]++
	}
	w("- Confirmed observations (open): **%d** (critical %d, high %d, medium %d, low %d, info %d)\n", len(conf), sev[model.SevCritical], sev[model.SevHigh], sev[model.SevMedium], sev[model.SevLow], sev[model.SevInfo])
	w("- Suspected signals needing review: **%d** (never counted as confirmed)\n", len(susp))
	w("- Controls: %d applicable, %d decisive (%s decisive coverage), %d not decided\n", r.Coverage.Applicable, r.Coverage.Decisive, pct(r.Coverage.Ratio), len(r.Untested()))
	w("- %s\n", Breakdown(r.Coverage))
	w("- Cross-domain edges: %d instantiated, %d verified, %d failed, %d blocked/inconclusive/suspected\n", r.Coverage.EdgesTotal, r.Coverage.EdgesVerified, r.Coverage.EdgesFailed, r.Coverage.EdgesOpen)
	if len(r.StaleFiles) > 0 {
		w("- **%d file(s) changed after this assessment; %d dependent control(s) and their edges are STALE until `pandaward retest`.**\n", len(r.StaleFiles), r.staleControls())
	}
	w("\n**Important:** %d applicable controls were not decisively tested. They must not be read as secure.\n\n", len(r.Untested()))
	w("%s\n\n", r.Coverage.Note)

	w("## Path to 100%%\n\n")
	if len(r.PathTo100) == 0 {
		w("Every applicable control is decided.\n\n")
	} else {
		w("What must happen for each undecided control to be decided, grouped by next step. A step that says a control cannot be decided in this release keeps coverage below 100%%.\n\n")
		w("| Controls | Next step | Which |\n|---|---|---|\n")
		for _, g := range r.PathTo100 {
			w("| %d | %s | %s |\n", g.Count, esc(g.Step), strings.Join(g.Controls, ", "))
		}
		w("\n")
	}

	if len(r.Attestations) > 0 {
		w("## Attested controls\n\n")
		w("Manual controls are decided only when a person accepts a reviewer's proposal with `pandaward attest`. A pending proposal decides nothing; a stale attestation no longer decides its control.\n\n")
		w("| Control | Verdict | State | Reviewer | Date | Evidence |\n|---|---|---|---|---|---|\n")
		for _, a := range r.Attestations {
			w("| %s | %s | %s | %s | %s | %s |\n", a.ControlID, a.Verdict, esc(AttestState(a)), esc(AttestReviewer(a)), AttestDate(a), esc(AttestEvidence(a)))
		}
		w("\n")
	}

	if d := r.Delta; d != nil {
		w("## Changes since %s\n\n", d.From)
		w("New %d, reopened %d, remediated %d, moved %d, stale %d, waived %d, unchanged %d.\n\n", len(d.New), len(d.Reopened), len(d.Remediated), len(d.Moved), len(d.Stale), len(d.Waived), d.Unchanged)
		for _, sec := range deltaSections(d) {
			for _, it := range sec.Items {
				loc := it.File
				if it.Line > 0 {
					loc = fmt.Sprintf("%s:%d", it.File, it.Line)
				}
				w("- **%s** %s %s (%s) `%s`", sec.Title, it.FindingID, esc(it.Title), it.Severity, esc(loc))
				if it.Note != "" {
					w(": %s", esc(it.Note))
				}
				w("\n")
			}
		}
		w("\n%s\n\n", d.Note)
	}

	writeFindings := func(title string, fs []model.Finding) {
		w("## %s (%d)\n\n", title, len(fs))
		if len(fs) == 0 {
			w("None.\n\n")
			return
		}
		for _, f := range fs {
			loc := f.File
			if f.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.StartLine)
			}
			w("### %s %s\n\n", f.ID, esc(f.Title))
			w("| | |\n|---|---|\n| Severity | %s |\n| Confidence | %s |\n| Status | %s |\n| Control | %s %s |\n| CWE | %s |\n| Location | `%s` |\n| Evidence | %s |\n| Collector | %s |\n",
				f.Severity, f.Confidence, f.Status, f.ControlID, esc(ctrlTitle(f.ControlID)), orDash(f.CWE), esc(loc), strings.Join(f.EvidenceIDs, ", "), f.Collector)
			if f.Stale {
				w("| Note | STALE: the file changed or the collector did not run since last observation |\n")
			}
			w("\n**Why:** %s\n\n**Fix:** %s\n\n**Retest:** %s\n\n", esc(f.Message), esc(f.Fix), esc(f.Retest))
			if f.Note != "" {
				w("**History:** %s\n\n", esc(f.Note))
			}
		}
	}
	writeFindings("Confirmed observations", conf)
	writeFindings("Suspected signals (hypotheses, not confirmed)", susp)

	w("## Coverage by domain\n\n| Domain | PASS | FAIL | SUSPECTED | BLOCKED | UNSUPPORTED | INCONCLUSIVE | ERROR | STALE | N/A |\n|---|---|---|---|---|---|---|---|---|---|\n")
	for _, d := range r.Domains {
		s := r.DomainSummary[d.ID]
		w("| %s %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |\n", d.ID, esc(d.Name), s["PASS"], s["FAIL"], s["SUSPECTED"], s["BLOCKED"], s["UNSUPPORTED"], s["INCONCLUSIVE"], s["ERROR"], s["STALE"], s["NOT_APPLICABLE"])
	}
	w("\n## Cross-domain edges\n\n")
	if len(r.Edges) == 0 {
		w("No seed edge had concrete assets on both sides.\n\n")
	} else {
		w("| Edge | Scenario | Status | Reason | Provenance |\n|---|---|---|---|---|\n")
		for _, e := range r.Edges {
			w("| %s | %s | %s | %s | %s |\n", e.ID, esc(e.Scenario), e.Status, esc(e.Reason), esc(strings.Join(e.Provenance, ", ")))
		}
		w("\nA domain passing in isolation never hides a failed or blocked edge.\n\n")
	}
	w("## Control ledger\n\n| Control | Title | Method | Status | Decided by | Reason | Next step |\n|---|---|---|---|---|---|---|\n")
	for _, c := range r.Controls {
		w("| %s | %s | %s | %s | %s | %s | %s |\n", c.ID, esc(c.Title), c.Method, c.Status, orDash(c.DecidedBy), esc(c.Reason), orDash(esc(c.NextStep)))
	}
	w("\n## Tool runs\n\n| Adapter | Version | Result | Signals | Detail |\n|---|---|---|---|---|\n")
	for _, run := range r.Runs {
		w("| %s | %s | %s | %d | %s |\n", run.Adapter, orDash(esc(run.ToolVersion)), run.ExitClass, run.SignalsCount, esc(run.Detail))
	}
	if closed := r.Closed(); len(closed) > 0 {
		w("\n## Closed findings\n\n| ID | Title | Status | Reviewer | Note |\n|---|---|---|---|---|\n")
		for _, f := range closed {
			w("| %s | %s | %s | %s | %s |\n", f.ID, esc(f.Title), f.Status, orDash(esc(f.Reviewer)), esc(f.Note))
		}
	}
	w("\n## Evidence index\n\n%d redacted artifacts, each stored as `<sha256>.json` under `.pandaward/private/evidence/`.\n\n", len(r.EvidenceIndex))
	w("| Evidence | SHA-256 | Collector | Source |\n|---|---|---|---|\n")
	for _, e := range r.EvidenceIndex {
		w("| %s | `%s` | %s | %s |\n", e.ID, e.SHA256, esc(e.Collector), esc(e.SourceRef))
	}
	return b.String()
}

// CoverageCSV renders the per-control and per-edge coverage ledger.
func CoverageCSV(r *Report) string {
	var b strings.Builder
	q := func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
	b.WriteString("kind,id,domain,title,method,status,reason,evidence\n")
	for _, c := range r.Controls {
		b.WriteString(strings.Join([]string{"control", c.ID, c.Domain, q(c.Title), c.Method, string(c.Status), q(c.Reason), q(strings.Join(c.EvidenceIDs, " "))}, ",") + "\n")
	}
	for _, e := range r.Edges {
		b.WriteString(strings.Join([]string{"edge", e.ID, e.Domains, q(e.Title), "graph", string(e.Status), q(e.Reason), q(strings.Join(e.Provenance, " "))}, ",") + "\n")
	}
	return b.String()
}

// AttestState describes where an attestation stands.
func AttestState(a store.Attestation) string {
	switch a.Status {
	case store.AttestPending:
		return "pending: decides nothing until a person accepts it"
	case store.AttestStale:
		return "STALE: " + a.StaleReason
	}
	s := "accepted, valid until " + dateOf(a.ExpiresAt)
	if a.Note != "" {
		s += ": " + a.Note
	}
	return s
}

// AttestReviewer names who proposed and who decided.
func AttestReviewer(a store.Attestation) string {
	if a.DecidedBy == "" {
		return "proposed by " + a.ProposedBy
	}
	return a.DecidedBy + " (proposed by " + a.ProposedBy + ")"
}

// AttestDate is the decision date, or the proposal date while pending.
func AttestDate(a store.Attestation) string {
	if a.DecidedAt != "" {
		return dateOf(a.DecidedAt)
	}
	return dateOf(a.CreatedAt)
}

// AttestEvidence lists the citations as file:line (why), and the command.
func AttestEvidence(a store.Attestation) string {
	var parts []string
	for _, c := range a.Citations {
		parts = append(parts, fmt.Sprintf("%s:%d (%s)", c.File, c.Line, c.Why))
	}
	if a.Command != "" {
		parts = append(parts, "shown by: "+a.Command)
	}
	return strings.Join(parts, "; ")
}

func dateOf(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

// Breakdown says how the decisive controls were decided and how many
// controls are not applicable, and so outside the denominator.
func Breakdown(c engine.Coverage) string {
	return fmt.Sprintf("Decided by: %d automatic (static and external adapters), %d runtime (approved runtime profiles), %d attested (manual controls a person accepted after review); %d not applicable, outside the denominator",
		c.Automatic, c.Runtime, c.Attested, c.NotApplicable)
}

func ctrlTitle(id string) string {
	if c := catalog.ControlByID(id); c != nil {
		return c.Title
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// DeltaSection is one labelled list of a delta, in display order.
type DeltaSection struct {
	Title string
	Items []engine.DeltaItem
}

func deltaSections(d *engine.Delta) []DeltaSection {
	return []DeltaSection{{"New", d.New}, {"Reopened", d.Reopened}, {"Remediated", d.Remediated}, {"Moved", d.Moved}, {"Stale", d.Stale}, {"Waived", d.Waived}}
}
