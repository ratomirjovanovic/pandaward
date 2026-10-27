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

	"github.com/ratomirjovanovic/pensec/internal/catalog"
	"github.com/ratomirjovanovic/pensec/internal/config"
	"github.com/ratomirjovanovic/pensec/internal/engine"
	"github.com/ratomirjovanovic/pensec/internal/evidence"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/store"
	"github.com/ratomirjovanovic/pensec/internal/version"
)

// Attestation is printed on every report (PRD 23.2).
const Attestation = "Automated technical security assessment. Not a certification, attestation, legal opinion or independently signed penetration test, and not a guarantee that no vulnerabilities exist. Only the controls listed as PASS were decisively checked, and only for the stated scope, method and point in time."

// Report is the full report model.
type Report struct {
	SchemaVersion int                       `json:"schema_version"`
	Generator     string                    `json:"generator"`
	GeneratedAt   string                    `json:"generated_at"`
	Project       string                    `json:"project"`
	Assessment    store.Assessment          `json:"assessment"`
	Attestation   string                    `json:"attestation"`
	Coverage      engine.Coverage           `json:"coverage"`
	StaleFiles    []string                  `json:"stale_files,omitempty"`
	Controls      []model.ControlResult     `json:"controls"`
	Edges         []model.Edge              `json:"edges"`
	Findings      []model.Finding           `json:"findings"`
	Runs          []model.Run               `json:"runs"`
	EvidenceIndex []store.EvidenceRow       `json:"evidence_index"`
	Domains       []catalog.Domain          `json:"domains"`
	DomainSummary map[string]map[string]int `json:"domain_summary"`
	Manifest      json.RawMessage           `json:"assessment_manifest,omitempty"`
}

// Build loads the latest assessment into a report.
func Build(e *engine.Engine) (*Report, error) {
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("no completed assessment: run `pensec scan` first")
	}
	r := &Report{SchemaVersion: model.SchemaVersion, Generator: "pensec " + version.Version, GeneratedAt: store.Now(), Project: e.Cfg.Project.Name, Assessment: *a, Attestation: Attestation, Domains: catalog.Domains}
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
	if r.Controls, r.Edges, r.StaleFiles, err = e.StaleView(a.ID, r.Controls, r.Edges); err != nil {
		return nil, err
	}
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
	r.Coverage = engine.ComputeCoverage(r.Controls, r.Edges, len(r.StaleFiles))
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
		p := filepath.Join(dir, fmt.Sprintf("pensec-%s-%s.%s", r.Assessment.ID, stamp, ext))
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
	w("# PenSec assessment report: %s\n\n", esc(r.Project))
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
	w("- Cross-domain edges: %d instantiated, %d verified, %d failed, %d blocked/inconclusive/suspected\n", r.Coverage.EdgesTotal, r.Coverage.EdgesVerified, r.Coverage.EdgesFailed, r.Coverage.EdgesOpen)
	if len(r.StaleFiles) > 0 {
		w("- **%d file(s) changed after this assessment; %d dependent control(s) and their edges are STALE until `pensec retest`.**\n", len(r.StaleFiles), r.staleControls())
	}
	w("\n**Important:** %d applicable controls were not decisively tested. They must not be read as secure.\n\n", len(r.Untested()))
	w("%s\n\n", r.Coverage.Note)

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
	w("## Control ledger\n\n| Control | Title | Method | Status | Reason |\n|---|---|---|---|---|\n")
	for _, c := range r.Controls {
		w("| %s | %s | %s | %s | %s |\n", c.ID, esc(c.Title), c.Method, c.Status, esc(c.Reason))
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
	w("\n## Evidence index\n\n%d redacted artifacts, each stored as `<sha256>.json` under `.pensec/private/evidence/`.\n\n", len(r.EvidenceIndex))
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
