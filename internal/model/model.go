// Package model holds the shared types of the Pandaward assessment ledger.
package model

// SchemaVersion is written into every exported object.
const SchemaVersion = 1

// Status is the state of a control or a cross-domain edge.
// Only PASS and FAIL are decisive; nothing else may be read as secure.
type Status string

const (
	StatusPass          Status = "PASS"
	StatusFail          Status = "FAIL"
	StatusSuspected     Status = "SUSPECTED"
	StatusInconclusive  Status = "INCONCLUSIVE"
	StatusBlocked       Status = "BLOCKED"
	StatusUnsupported   Status = "UNSUPPORTED"
	StatusStale         Status = "STALE"
	StatusNotApplicable Status = "NOT_APPLICABLE"
	StatusError         Status = "ERROR"
)

// Decisive reports whether the status counts toward decisive coverage.
func (s Status) Decisive() bool { return s == StatusPass || s == StatusFail }

// Severity of a finding. Severity is kept separate from confidence.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// SeverityRank orders severities for sorting, higher is worse.
func SeverityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

// Confidence is the proof level of a finding.
type Confidence string

const (
	// Confirmed means a deterministic validator observed the condition and
	// recorded evidence. It does not by itself prove exploitability.
	Confirmed Confidence = "CONFIRMED"
	// StronglySupported means a specific signal with a low false positive rate.
	StronglySupported Confidence = "STRONGLY_SUPPORTED"
	// Hypothesis means heuristic or AI-proposed; never shown as confirmed.
	Hypothesis Confidence = "HYPOTHESIS"
)

// FindingStatus is the lifecycle state of a finding.
type FindingStatus string

const (
	FindingOpen          FindingStatus = "OPEN"
	FindingReopened      FindingStatus = "REOPENED"
	FindingRemediated    FindingStatus = "REMEDIATED"
	FindingFalsePositive FindingStatus = "FALSE_POSITIVE"
	FindingRiskAccepted  FindingStatus = "RISK_ACCEPTED"
)

// Active reports whether the finding still needs attention.
func (s FindingStatus) Active() bool { return s == FindingOpen || s == FindingReopened }

// Asset is an inventory item with a stable identifier.
type Asset struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Locator     string            `json:"locator"`
	Line        int               `json:"line,omitempty"`
	ContentHash string            `json:"content_hash,omitempty"`
	Domains     []string          `json:"domains,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
}

// Signal is a normalized observation emitted by an adapter.
type Signal struct {
	RuleID     string     `json:"rule_id"`
	ControlID  string     `json:"control_id"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	CWE        string     `json:"cwe,omitempty"`
	File       string     `json:"file,omitempty"`
	StartLine  int        `json:"start_line,omitempty"`
	EndLine    int        `json:"end_line,omitempty"`
	Snippet    string     `json:"snippet,omitempty"`
	Message    string     `json:"message"`
	Fix        string     `json:"fix,omitempty"`
	Retest     string     `json:"retest,omitempty"`
	Collector  string     `json:"collector"`
	// Key distinguishes several hits of one rule in one file when the
	// redacted line text alone is ambiguous. Optional.
	Key string `json:"key,omitempty"`
}

// ControlResult is the outcome of one control in one assessment.
type ControlResult struct {
	ID          string   `json:"id"`
	Domain      string   `json:"domain"`
	Title       string   `json:"title"`
	Method      string   `json:"method"`
	Status      Status   `json:"status"`
	Reason      string   `json:"reason"`
	Adapter     string   `json:"adapter,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Refs        []string `json:"refs,omitempty"`
}

// Edge is an instantiated cross-domain dependency (AB1, CG1, ...).
type Edge struct {
	ID         string   `json:"id"`
	Domains    string   `json:"domains"`
	Title      string   `json:"title"`
	Scenario   string   `json:"scenario"`
	Status     Status   `json:"status"`
	Reason     string   `json:"reason"`
	Provenance []string `json:"provenance"`
	Tests      []string `json:"tests"`
}

// Finding is a persisted finding with its lifecycle.
type Finding struct {
	ID           string        `json:"id"`
	Fingerprint  string        `json:"fingerprint"`
	RuleID       string        `json:"rule_id"`
	ControlID    string        `json:"control_id"`
	Title        string        `json:"title"`
	Severity     Severity      `json:"severity"`
	Confidence   Confidence    `json:"confidence"`
	Status       FindingStatus `json:"status"`
	CWE          string        `json:"cwe,omitempty"`
	File         string        `json:"file,omitempty"`
	StartLine    int           `json:"start_line,omitempty"`
	EndLine      int           `json:"end_line,omitempty"`
	Message      string        `json:"message"`
	Fix          string        `json:"fix,omitempty"`
	Retest       string        `json:"retest,omitempty"`
	Collector    string        `json:"collector"`
	FirstSeen    string        `json:"first_seen"`
	LastSeen     string        `json:"last_seen"`
	EvidenceIDs  []string      `json:"evidence_ids,omitempty"`
	Reviewer     string        `json:"reviewer,omitempty"`
	Note         string        `json:"note,omitempty"`
	ExpiresAt    string        `json:"expires_at,omitempty"`
	Stale        bool          `json:"stale,omitempty"`
	AssessmentID string        `json:"assessment_id"`
}

// Run records one adapter execution.
type Run struct {
	ID           string `json:"id"`
	Adapter      string `json:"adapter"`
	ToolVersion  string `json:"tool_version"`
	StartedAt    string `json:"started_at"`
	EndedAt      string `json:"ended_at"`
	ExitClass    string `json:"exit_class"`
	Detail       string `json:"detail,omitempty"`
	SignalsCount int    `json:"signals"`
}

// Exit classes for adapter runs.
const (
	ExitOK          = "OK"
	ExitError       = "ERROR"
	ExitBlocked     = "BLOCKED"
	ExitTimeout     = "TIMED_OUT"
	ExitUnsupported = "UNSUPPORTED"
	// ExitCarried marks an adapter that was not re-run because none of its
	// inputs changed; its previous decisions were carried over.
	ExitCarried = "CARRIED"
)
