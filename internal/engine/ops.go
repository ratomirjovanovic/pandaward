package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pensec/internal/catalog"
	"github.com/ratomirjovanovic/pensec/internal/evidence"
	"github.com/ratomirjovanovic/pensec/internal/inventory"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
	"github.com/ratomirjovanovic/pensec/internal/store"
)

// Status is the compact resumable state.
type Status struct {
	Initialized bool              `json:"initialized"`
	Project     string            `json:"project"`
	Assessment  *store.Assessment `json:"assessment,omitempty"`
	Coverage    *Coverage         `json:"coverage,omitempty"`
	Findings    map[string]int    `json:"open_findings_by_severity"`
	Suspected   int               `json:"open_hypotheses"`
	Confirmed   int               `json:"open_confirmed"`
	StaleFiles  []string          `json:"stale_files,omitempty"`
	// StaleControls are the controls whose decision depends on a stale file.
	StaleControls []string `json:"stale_controls,omitempty"`
	// ChangedOutside are stale files found by comparing content hashes, that
	// is, changed without going through Claude Code's edit tools.
	ChangedOutside []string `json:"changed_outside_claude,omitempty"`
	// ChangeCheck is set when the hash comparison was skipped.
	ChangeCheck string   `json:"change_check,omitempty"`
	Blockers    []string `json:"blockers,omitempty"`
	NextAction  string   `json:"next_action"`
}

// Status returns the current state from the ledger.
func (e *Engine) Status() (*Status, error) {
	s := &Status{Initialized: true, Project: e.Cfg.Project.Name, Findings: map[string]int{}}
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		if s.StaleFiles, err = e.St.StaleFiles(e.ProjectID); err != nil {
			return nil, err
		}
		s.NextAction = "run `pensec scan` (/pensec:scan) for the first passive assessment"
		return s, nil
	}
	s.Assessment = a
	cs, err := e.St.Controls(a.ID)
	if err != nil {
		return nil, err
	}
	es, err := e.St.Edges(a.ID)
	if err != nil {
		return nil, err
	}
	cs, es, ch, err := e.StaleView(a.ID, cs, es)
	if err != nil {
		return nil, err
	}
	s.StaleFiles, s.ChangedOutside, s.ChangeCheck = ch.Files, ch.Outside, ch.Note
	for _, c := range cs {
		if c.Status == model.StatusStale {
			s.StaleControls = append(s.StaleControls, c.ID)
		}
	}
	cov := ComputeCoverage(cs, es, len(s.StaleFiles))
	s.Coverage = &cov
	for _, c := range cs {
		if c.Status == model.StatusError {
			s.Blockers = append(s.Blockers, c.ID+": "+c.Reason)
		}
	}
	runs, _ := e.St.Runs(a.ID)
	for _, r := range runs {
		if r.ExitClass == model.ExitBlocked {
			s.Blockers = append(s.Blockers, r.Adapter+": "+r.Detail)
		}
	}
	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		if !f.Status.Active() {
			continue
		}
		s.Findings[string(f.Severity)]++
		if f.Confidence == model.Hypothesis {
			s.Suspected++
		} else {
			s.Confirmed++
		}
	}
	switch {
	case len(s.StaleFiles) > 0:
		s.NextAction = fmt.Sprintf("%d file(s) changed since %s, %d control(s) STALE: run `pensec retest --changed`", len(s.StaleFiles), a.ID, len(s.StaleControls))
	case s.Confirmed > 0:
		s.NextAction = "review findings (`pensec findings`) and build a fix plan (/pensec:fix-plan)"
	case s.Suspected > 0:
		s.NextAction = "triage suspected signals (/pensec:review triage)"
	default:
		s.NextAction = "run manual-assisted review for BLOCKED controls (/pensec:review) and generate a report"
	}
	return s, nil
}

// MarkChanged records a changed file (called by the PostToolUse hook).
// Paths outside the project root are ignored.
func (e *Engine) MarkChanged(p string) (bool, error) {
	if p == "" {
		return false, nil
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(e.Root, p)
	}
	rel, err := filepath.Rel(e.Root, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false, nil
	}
	rel = filepath.ToSlash(rel)
	if strings.HasPrefix(rel, ".pensec/") {
		return false, nil
	}
	return true, e.St.MarkStale(e.ProjectID, rel)
}

// RecordHypothesis stores a manual-assisted or agent-proposed finding. The
// engine reads and redacts the cited lines itself; the caller cannot supply
// evidence text. The result is always a HYPOTHESIS until a human confirms it.
type HypothesisInput struct {
	ControlID string `json:"control_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Rationale string `json:"rationale"`
	Fix       string `json:"fix"`
	Proposer  string `json:"proposer"`
}

var safeText = regexp.MustCompile(`^[\pL\pN\pP\pZ\pS]*$`)

// RecordHypothesis validates and persists a hypothesis finding.
func (e *Engine) RecordHypothesis(in HypothesisInput) (*model.Finding, error) {
	if catalog.ControlByID(in.ControlID) == nil {
		return nil, fmt.Errorf("unknown control_id %q", in.ControlID)
	}
	sev := model.Severity(strings.ToLower(in.Severity))
	if model.SeverityRank(sev) == 0 {
		return nil, fmt.Errorf("severity must be critical, high, medium, low or info")
	}
	in.Title = strings.TrimSpace(redact.Line(in.Title))
	if len(in.Title) < 5 || len(in.Title) > 160 || !safeText.MatchString(in.Title) {
		return nil, errors.New("title must be 5-160 printable characters")
	}
	if len(in.Rationale) > 4000 || len(in.Fix) > 4000 {
		return nil, errors.New("rationale and fix are limited to 4000 characters")
	}
	clean := filepath.ToSlash(filepath.Clean(in.File))
	if in.File == "" || filepath.IsAbs(in.File) || strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, ".pensec/") || strings.HasPrefix(clean, ".git/") {
		return nil, errors.New("file must be a relative path inside the project")
	}
	abs := filepath.Join(e.Root, filepath.FromSlash(clean))
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("file %s does not exist", clean)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, errors.New("file must be a regular file (symlinks are not followed)")
	}
	if fi.Size() > e.Cfg.Inventory.MaxFileBytes {
		return nil, errors.New("file is larger than inventory.max_file_bytes")
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	if in.StartLine < 1 || in.StartLine > len(lines) {
		return nil, fmt.Errorf("start_line must be within 1..%d", len(lines))
	}
	if in.EndLine < in.StartLine {
		in.EndLine = in.StartLine
	}
	if in.EndLine > len(lines) || in.EndLine-in.StartLine > 40 {
		return nil, errors.New("end_line out of range or span longer than 40 lines")
	}
	var snip []string
	for i := in.StartLine - 1; i < in.EndLine; i++ {
		snip = append(snip, redact.Line(strings.TrimRight(lines[i], "\r")))
	}
	sum := sha256.Sum256(b)
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("run a passive scan before recording hypotheses")
	}
	proposer := redact.Line(in.Proposer)
	if proposer == "" {
		proposer = "unspecified"
	}
	evID, err := evidence.Write(e.St, e.Private(), evidence.Record{AssessmentID: a.ID, Kind: "manual-assisted-citation", Collector: "manual-assisted:" + proposer, RuleID: "review." + in.ControlID,
		File: clean, StartLine: in.StartLine, EndLine: in.EndLine, FileSHA256: hex.EncodeToString(sum[:]), Snippet: strings.Join(snip, " ⏎ "), Observation: redact.Line(in.Rationale)})
	if err != nil {
		return nil, err
	}
	fpSum := sha256.Sum256([]byte("review|" + in.ControlID + "|" + clean + "|" + strings.ToLower(in.Title)))
	fp := hex.EncodeToString(fpSum[:])[:32]
	if old, _ := e.St.FindingByFingerprint(e.ProjectID, fp); old != nil {
		return old, nil
	}
	id, err := e.St.NextFindingID(e.ProjectID)
	if err != nil {
		return nil, err
	}
	now := store.Now()
	f := model.Finding{ID: id, Fingerprint: fp, RuleID: "review." + in.ControlID, ControlID: in.ControlID, Title: in.Title, Severity: sev, Confidence: model.Hypothesis, Status: model.FindingOpen,
		File: clean, StartLine: in.StartLine, EndLine: in.EndLine, Message: redact.Text(in.Rationale), Fix: redact.Text(in.Fix), Collector: "manual-assisted", FirstSeen: now, LastSeen: now,
		EvidenceIDs: []string{evID}, Note: "Proposed by " + proposer + "; requires human verification before it may be treated as confirmed.", AssessmentID: a.ID,
		Retest: "Verify manually or with a deterministic test; then mark false-positive, or fix and re-review."}
	if err := e.St.UpsertFinding(e.ProjectID, f); err != nil {
		return nil, err
	}
	return &f, e.St.Event(e.ProjectID, id, "", "OPEN", "hypothesis recorded by "+proposer)
}

// Triage changes the disposition of a finding. Only humans should call this;
// the plugin hooks require interactive confirmation for these commands.
func (e *Engine) Triage(id, action, reviewer, note string, expires time.Time) (*model.Finding, error) {
	u, err := e.triage(id, action, reviewer, note, expires)
	if err != nil {
		return nil, err
	}
	if err := e.St.ApplyTriage(e.ProjectID, []store.TriageUpdate{u}); err != nil {
		return nil, err
	}
	return &u.Finding, nil
}

// TriageDecision is one entry of a batch applied with TriageBatch.
type TriageDecision struct {
	FindingID string `json:"finding_id"`
	Action    string `json:"action"`
	Note      string `json:"note"`
	// Expires is YYYY-MM-DD and only used by accept-risk.
	Expires string `json:"expires,omitempty"`
}

// MaxTriageDecisions caps one batch so a confirmation prompt stays readable.
const MaxTriageDecisions = 200

// ReadTriageDecisions reads a JSON array of decisions, rejecting unknown
// fields, oversized files and batches over MaxTriageDecisions.
func ReadTriageDecisions(path string) ([]TriageDecision, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("%s is larger than 1 MiB", path)
	}
	var ds []TriageDecision
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ds); err != nil {
		return nil, fmt.Errorf("%s: expected a JSON array of {finding_id, action, note, expires}: %w", path, err)
	}
	if len(ds) > MaxTriageDecisions {
		return nil, fmt.Errorf("%s has %d decisions; apply at most %d at a time", path, len(ds), MaxTriageDecisions)
	}
	return ds, nil
}

// TriageBatch validates every decision first and then records all of them
// in one transaction, so an invalid entry rejects the whole batch.
func (e *Engine) TriageBatch(ds []TriageDecision, reviewer string) ([]model.Finding, error) {
	if len(ds) == 0 {
		return nil, errors.New("no decisions to apply")
	}
	seen := map[string]bool{}
	us := make([]store.TriageUpdate, 0, len(ds))
	for i, d := range ds {
		if seen[d.FindingID] {
			return nil, fmt.Errorf("decision %d: %s appears more than once", i+1, d.FindingID)
		}
		seen[d.FindingID] = true
		var exp time.Time
		if d.Expires != "" {
			var err error
			if exp, err = time.Parse("2006-01-02", d.Expires); err != nil {
				return nil, fmt.Errorf("decision %d (%s): expires must be YYYY-MM-DD", i+1, d.FindingID)
			}
		}
		u, err := e.triage(d.FindingID, d.Action, reviewer, d.Note, exp)
		if err != nil {
			return nil, fmt.Errorf("decision %d (%s): %w", i+1, d.FindingID, err)
		}
		us = append(us, u)
	}
	if err := e.St.ApplyTriage(e.ProjectID, us); err != nil {
		return nil, err
	}
	out := make([]model.Finding, len(us))
	for i, u := range us {
		out[i] = u.Finding
	}
	return out, nil
}

// triage validates one decision and returns the changed finding without
// writing it.
func (e *Engine) triage(id, action, reviewer, note string, expires time.Time) (store.TriageUpdate, error) {
	var u store.TriageUpdate
	f, err := e.St.Finding(e.ProjectID, id)
	if err != nil {
		return u, err
	}
	if f == nil {
		return u, fmt.Errorf("finding %s not found", id)
	}
	reviewer = strings.TrimSpace(redact.Line(reviewer))
	if reviewer == "" {
		return u, errors.New("--by <reviewer name> is required")
	}
	if strings.TrimSpace(note) == "" {
		return u, errors.New("--note <justification> is required")
	}
	old := f.Status
	switch action {
	case "false-positive":
		f.Status = model.FindingFalsePositive
	case "accept-risk":
		if expires.IsZero() || expires.Before(time.Now()) || expires.After(time.Now().AddDate(1, 0, 1)) {
			return u, errors.New("--expires must be a future date within one year (YYYY-MM-DD)")
		}
		f.Status = model.FindingRiskAccepted
		f.ExpiresAt = expires.UTC().Format(time.RFC3339)
	case "reopen":
		f.Status = model.FindingReopened
		f.ExpiresAt = ""
	case "confirm":
		if f.Confidence == model.Hypothesis {
			f.Confidence = model.StronglySupported
		}
	default:
		return u, fmt.Errorf("unknown triage action %q", action)
	}
	f.Reviewer = reviewer
	f.Note = strings.TrimSpace(f.Note + " [" + store.Now() + " " + reviewer + ": " + action + "] " + redact.Line(note))
	return store.TriageUpdate{Finding: *f, OldStatus: string(old), Reason: action + " by " + reviewer}, nil
}

// ChangedSinceLast compares the working tree to the last assessment hashes.
func (e *Engine) ChangedSinceLast(inv *inventory.Inventory) ([]string, error) {
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil || a == nil {
		return nil, err
	}
	old, err := e.St.FileHashes(a.ID)
	if err != nil {
		return nil, err
	}
	cur := map[string]string{}
	for _, f := range inv.Files {
		cur[f.Path] = f.SHA256
	}
	return diffHashes(old, cur), nil
}

// diffHashes lists paths whose hash changed or that are new, plus removed
// paths with a " (deleted)" suffix, sorted.
func diffHashes(old, cur map[string]string) []string {
	var changed []string
	for p, h := range cur {
		if old[p] != h {
			changed = append(changed, p)
		}
	}
	for p := range old {
		if _, ok := cur[p]; !ok {
			changed = append(changed, p+" (deleted)")
		}
	}
	sort.Strings(changed)
	return changed
}

// EntrypointKinds are the asset kinds Entrypoints lists, in display order.
var EntrypointKinds = []string{"route", "graphql_operation", "grpc_method", "queue_consumer", "cron_job"}

// Entrypoints lists the entrypoints found by the latest assessment, each with
// its file and line, optionally limited to one service root or kind.
func (e *Engine) Entrypoints(service, kind string) ([]model.Asset, *store.Assessment, error) {
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil || a == nil {
		return nil, a, err
	}
	all, err := e.St.Assets(a.ID)
	if err != nil {
		return nil, a, err
	}
	order := map[string]int{}
	for i, k := range EntrypointKinds {
		order[k] = i + 1
	}
	var out []model.Asset
	for _, as := range all {
		if order[as.Kind] == 0 || (kind != "" && as.Kind != kind) || (service != "" && as.Meta["service"] != service) {
			continue
		}
		out = append(out, as)
	}
	sort.SliceStable(out, func(i, j int) bool {
		x, y := out[i], out[j]
		if x.Meta["service"] != y.Meta["service"] {
			return x.Meta["service"] < y.Meta["service"]
		}
		if x.Kind != y.Kind {
			return order[x.Kind] < order[y.Kind]
		}
		if x.Meta["path"] != y.Meta["path"] {
			return x.Meta["path"] < y.Meta["path"]
		}
		return x.Meta["method"] < y.Meta["method"]
	})
	return out, a, nil
}
