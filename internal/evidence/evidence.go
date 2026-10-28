// Package evidence writes immutable, redacted, content-addressed artifacts.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/store"
)

// Record is the on-disk evidence document.
type Record struct {
	SchemaVersion int    `json:"schema_version"`
	AssessmentID  string `json:"assessment_id"`
	Kind          string `json:"kind"`
	Collector     string `json:"collector"`
	RuleID        string `json:"rule_id,omitempty"`
	File          string `json:"file,omitempty"`
	StartLine     int    `json:"start_line,omitempty"`
	EndLine       int    `json:"end_line,omitempty"`
	FileSHA256    string `json:"file_sha256,omitempty"`
	Snippet       string `json:"snippet,omitempty"`
	Observation   string `json:"observation"`
	GitCommit     string `json:"git_commit,omitempty"`
	CapturedAt    string `json:"captured_at"`
	Redaction     string `json:"redaction"`
	Data          any    `json:"data,omitempty"`
}

// Dir returns the evidence directory.
func Dir(private string) string { return filepath.Join(private, "evidence") }

// Write stores a record and returns its evidence ID. Every text field is
// redacted again here so no caller can bypass redaction.
func Write(st *store.Store, private string, r Record) (string, error) {
	r.SchemaVersion = model.SchemaVersion
	r.Snippet = redact.Line(r.Snippet)
	r.Observation = redact.Line(r.Observation)
	r.File = redact.Sanitize(r.File)
	r.Redaction = "pandaward-redact-v1"
	if r.CapturedAt == "" {
		r.CapturedAt = store.Now()
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	id := "ev_" + h[:16]
	p := filepath.Join(Dir(private), h+".json")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return "", err
		}
	}
	src := r.File
	if r.StartLine > 0 {
		src = fmt.Sprintf("%s#L%d-L%d", r.File, r.StartLine, r.EndLine)
	}
	return id, st.PutEvidence(store.EvidenceRow{ID: id, AssessmentID: r.AssessmentID, Kind: r.Kind, SHA256: h, Path: filepath.Base(p), RedactionState: "REDACTED",
		CreatedAt: r.CapturedAt, Collector: r.Collector, SourceRef: src})
}

// Read returns the redacted record bytes after verifying their hash.
func Read(private string, e *store.EvidenceRow) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(Dir(private), filepath.Base(e.Path)))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != e.SHA256 {
		return nil, fmt.Errorf("integrity check failed for %s: content does not match recorded SHA-256", e.ID)
	}
	return b, nil
}

// Referenced returns the evidence IDs that control results point to.
func Referenced(cs []model.ControlResult) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.EvidenceIDs...)
	}
	return out
}

// Collect returns the evidence rows of an assessment plus the rows for extra
// IDs written by earlier assessments, such as evidence a targeted retest
// carried over. Extra IDs without a stored row are returned as missing.
func Collect(st *store.Store, asmt string, extra []string) (rows []store.EvidenceRow, missing []string, err error) {
	if rows, err = st.EvidenceFor(asmt); err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.ID] = true
	}
	for _, id := range extra {
		if seen[id] {
			continue
		}
		seen[id] = true
		row, err := st.Evidence(id)
		if err != nil {
			return nil, nil, err
		}
		if row == nil {
			missing = append(missing, id)
			continue
		}
		rows = append(rows, *row)
	}
	return rows, missing, nil
}

// Verify checks all evidence of an assessment, plus the extra IDs it carries
// from earlier assessments, and returns failing or missing IDs.
func Verify(st *store.Store, private, asmt string, extra []string) (ok int, bad []string, err error) {
	rows, bad, err := Collect(st, asmt, extra)
	if err != nil {
		return 0, nil, err
	}
	for i := range rows {
		if _, err := Read(private, &rows[i]); err != nil {
			bad = append(bad, rows[i].ID)
			continue
		}
		ok++
	}
	return ok, bad, nil
}
