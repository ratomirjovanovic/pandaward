// Package store is the local SQLite ledger. It is the source of truth for
// assessment state; model summaries never are.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/model"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database.
type Store struct {
	DB *sql.DB
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, root TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, seq INTEGER NOT NULL, git_commit TEXT, git_dirty INTEGER, profile TEXT NOT NULL,
		config_hash TEXT, catalog_version TEXT, started_at TEXT NOT NULL, ended_at TEXT, status TEXT NOT NULL, manifest_json TEXT);
	CREATE TABLE IF NOT EXISTS assets(assessment_id TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, locator TEXT NOT NULL, line INTEGER, content_hash TEXT, domains TEXT, meta_json TEXT,
		PRIMARY KEY(assessment_id, id));
	CREATE TABLE IF NOT EXISTS file_hashes(assessment_id TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, domains TEXT, PRIMARY KEY(assessment_id, path));
	CREATE TABLE IF NOT EXISTS controls(assessment_id TEXT NOT NULL, id TEXT NOT NULL, domain TEXT NOT NULL, title TEXT NOT NULL, method TEXT NOT NULL, status TEXT NOT NULL,
		reason TEXT, adapter TEXT, evidence_json TEXT, refs_json TEXT, PRIMARY KEY(assessment_id, id));
	CREATE TABLE IF NOT EXISTS edges(assessment_id TEXT NOT NULL, id TEXT NOT NULL, domains TEXT NOT NULL, title TEXT NOT NULL, scenario TEXT, status TEXT NOT NULL, reason TEXT,
		provenance_json TEXT, tests_json TEXT, PRIMARY KEY(assessment_id, id));
	CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, adapter TEXT NOT NULL, tool_version TEXT, started_at TEXT, ended_at TEXT, exit_class TEXT NOT NULL,
		detail TEXT, signals INTEGER);
	CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, fingerprint TEXT NOT NULL, rule_id TEXT, control_id TEXT, title TEXT NOT NULL, severity TEXT NOT NULL,
		confidence TEXT NOT NULL, status TEXT NOT NULL, cwe TEXT, file TEXT, start_line INTEGER, end_line INTEGER, message TEXT, fix TEXT, retest TEXT, collector TEXT,
		first_seen TEXT, last_seen TEXT, last_assessment TEXT, evidence_json TEXT, reviewer TEXT, note TEXT, expires_at TEXT, stale INTEGER DEFAULT 0,
		UNIQUE(project_id, fingerprint));
	CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, kind TEXT NOT NULL, sha256 TEXT NOT NULL, path TEXT NOT NULL, redaction_state TEXT NOT NULL,
		created_at TEXT NOT NULL, collector TEXT, source_ref TEXT);
	CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL, entity_id TEXT NOT NULL, old_state TEXT, new_state TEXT, ts TEXT NOT NULL, reason TEXT);
	CREATE TABLE IF NOT EXISTS stale_files(project_id TEXT NOT NULL, path TEXT NOT NULL, changed_at TEXT NOT NULL, PRIMARY KEY(project_id, path));
	CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, kind TEXT NOT NULL, subject_hash TEXT NOT NULL, approved_by TEXT NOT NULL, approved_at TEXT NOT NULL,
		expires_at TEXT NOT NULL, revoked INTEGER DEFAULT 0);
	CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, status);
	CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id, seq);`,
	// 2: which findings each assessment observed, for stable deltas.
	`CREATE TABLE IF NOT EXISTS observations(assessment_id TEXT NOT NULL, fingerprint TEXT NOT NULL, finding_id TEXT NOT NULL, carried INTEGER DEFAULT 0,
		PRIMARY KEY(assessment_id, fingerprint));
	ALTER TABLE assessments ADD COLUMN observed INTEGER DEFAULT 0;`,
}

// Open opens (and migrates) the database under the private directory.
func Open(privateDir string) (*Store, error) {
	p := filepath.Join(privateDir, "state.db")
	dsn := "file:" + filepath.ToSlash(p) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return err
	}
	var v int
	_ = s.DB.QueryRow(`SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'`).Scan(&v)
	if v > len(migrations) {
		return fmt.Errorf("database schema %d is newer than this binary (%d); upgrade pandaward", v, len(migrations))
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO meta(key,value) VALUES('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, fmt.Sprint(i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Now returns the current UTC time in RFC3339.
func Now() string { return time.Now().UTC().Format(time.RFC3339) }

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func unjs[T any](s sql.NullString) T {
	var v T
	if s.Valid && s.String != "" {
		_ = json.Unmarshal([]byte(s.String), &v)
	}
	return v
}

// EnsureProject creates the project row if missing and returns its ID.
func (s *Store) EnsureProject(id, root, name string) error {
	_, err := s.DB.Exec(`INSERT INTO projects(id,root,name,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET root=excluded.root, name=excluded.name`, id, root, name, Now())
	return err
}

// Assessment is a row of the assessments table.
type Assessment struct {
	ID             string `json:"id"`
	Seq            int    `json:"seq"`
	GitCommit      string `json:"git_commit"`
	GitDirty       bool   `json:"git_dirty"`
	Profile        string `json:"profile"`
	ConfigHash     string `json:"config_hash"`
	CatalogVersion string `json:"catalog_version"`
	StartedAt      string `json:"started_at"`
	EndedAt        string `json:"ended_at"`
	Status         string `json:"status"`
	ManifestJSON   string `json:"-"`
}

// NewAssessment inserts a RUNNING assessment and returns it.
func (s *Store) NewAssessment(projectID string, a Assessment) (Assessment, error) {
	var seq int
	if err := s.DB.QueryRow(`SELECT COALESCE(MAX(seq),0)+1 FROM assessments WHERE project_id=?`, projectID).Scan(&seq); err != nil {
		return a, err
	}
	a.Seq = seq
	a.ID = fmt.Sprintf("asmt_%04d_%s", seq, time.Now().UTC().Format("20060102T150405Z"))
	a.StartedAt = Now()
	a.Status = "RUNNING"
	_, err := s.DB.Exec(`INSERT INTO assessments(id,project_id,seq,git_commit,git_dirty,profile,config_hash,catalog_version,started_at,status) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		a.ID, projectID, a.Seq, a.GitCommit, a.GitDirty, a.Profile, a.ConfigHash, a.CatalogVersion, a.StartedAt, a.Status)
	if err == nil {
		err = s.Event(projectID, a.ID, "", "RUNNING", "assessment started")
	}
	return a, err
}

// FinishAssessment marks an assessment finished with a status.
func (s *Store) FinishAssessment(projectID, id, status, manifest string) error {
	_, err := s.DB.Exec(`UPDATE assessments SET ended_at=?, status=?, manifest_json=? WHERE id=?`, Now(), status, manifest, id)
	if err == nil {
		err = s.Event(projectID, id, "RUNNING", status, "assessment finished")
	}
	return err
}

// MarkInterrupted turns RUNNING assessments into INTERRUPTED (crash recovery).
func (s *Store) MarkInterrupted(projectID string) (int64, error) {
	r, err := s.DB.Exec(`UPDATE assessments SET status='INTERRUPTED', ended_at=? WHERE project_id=? AND status='RUNNING'`, Now(), projectID)
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// LatestAssessment returns the latest completed assessment, or nil.
func (s *Store) LatestAssessment(projectID string) (*Assessment, error) {
	row := s.DB.QueryRow(`SELECT id,seq,COALESCE(git_commit,''),COALESCE(git_dirty,0),profile,COALESCE(config_hash,''),COALESCE(catalog_version,''),started_at,COALESCE(ended_at,''),status,COALESCE(manifest_json,'')
		FROM assessments WHERE project_id=? AND status IN ('COMPLETE','INCOMPLETE') ORDER BY seq DESC LIMIT 1`, projectID)
	a := &Assessment{}
	err := row.Scan(&a.ID, &a.Seq, &a.GitCommit, &a.GitDirty, &a.Profile, &a.ConfigHash, &a.CatalogVersion, &a.StartedAt, &a.EndedAt, &a.Status, &a.ManifestJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return a, err
}

// Event appends an audit event.
func (s *Store) Event(projectID, entity, oldState, newState, reason string) error {
	return event(s.DB, projectID, entity, oldState, newState, reason)
}

// execer is what *sql.DB and *sql.Tx have in common for writes.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func event(x execer, projectID, entity, oldState, newState, reason string) error {
	_, err := x.Exec(`INSERT INTO events(project_id,entity_id,old_state,new_state,ts,reason) VALUES(?,?,?,?,?,?)`, projectID, entity, oldState, newState, Now(), reason)
	return err
}

// TriageUpdate is one changed finding with the audit event that records it.
type TriageUpdate struct {
	Finding   model.Finding
	OldStatus string
	Reason    string
}

// ApplyTriage writes finding changes and their events in one transaction,
// so a batch is recorded completely or not at all.
func (s *Store) ApplyTriage(projectID string, us []TriageUpdate) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	for _, u := range us {
		if err := upsertFinding(tx, projectID, u.Finding); err != nil {
			tx.Rollback()
			return err
		}
		if err := event(tx, projectID, u.Finding.ID, u.OldStatus, string(u.Finding.Status), u.Reason); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// PutAssets stores inventory assets in one transaction.
func (s *Store) PutAssets(asmt string, assets []model.Asset) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT OR REPLACE INTO assets(assessment_id,id,kind,locator,line,content_hash,domains,meta_json) VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer st.Close()
	for _, a := range assets {
		if _, err := st.Exec(asmt, a.ID, a.Kind, a.Locator, a.Line, a.ContentHash, strings.Join(a.Domains, ","), js(a.Meta)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Assets lists the assets of an assessment.
func (s *Store) Assets(asmt string) ([]model.Asset, error) {
	rows, err := s.DB.Query(`SELECT id,kind,locator,COALESCE(line,0),COALESCE(content_hash,''),COALESCE(domains,''),meta_json FROM assets WHERE assessment_id=? ORDER BY kind,id`, asmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Asset
	for rows.Next() {
		var a model.Asset
		var d string
		var meta sql.NullString
		if err := rows.Scan(&a.ID, &a.Kind, &a.Locator, &a.Line, &a.ContentHash, &d, &meta); err != nil {
			return nil, err
		}
		if d != "" {
			a.Domains = strings.Split(d, ",")
		}
		a.Meta = unjs[map[string]string](meta)
		out = append(out, a)
	}
	return out, rows.Err()
}

// PutFileHashes stores the content hashes used for invalidation.
func (s *Store) PutFileHashes(asmt string, hashes map[string]string, domains map[string][]string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT OR REPLACE INTO file_hashes(assessment_id,path,sha256,domains) VALUES(?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer st.Close()
	for p, h := range hashes {
		if _, err := st.Exec(asmt, p, h, strings.Join(domains[p], ",")); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// FileHashes returns path -> SHA-256 for the files of an assessment.
func (s *Store) FileHashes(asmt string) (map[string]string, error) {
	rows, err := s.DB.Query(`SELECT path, sha256 FROM file_hashes WHERE assessment_id=?`, asmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var p, h string
		if err := rows.Scan(&p, &h); err != nil {
			return nil, err
		}
		out[p] = h
	}
	return out, rows.Err()
}

// FileDomains returns the domains linked to a file in an assessment.
func (s *Store) FileDomains(asmt, path string) ([]string, bool, error) {
	var d string
	err := s.DB.QueryRow(`SELECT COALESCE(domains,'') FROM file_hashes WHERE assessment_id=? AND path=?`, asmt, path).Scan(&d)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if d == "" {
		return nil, true, nil
	}
	return strings.Split(d, ","), true, nil
}

// PutControls stores control results.
func (s *Store) PutControls(asmt string, cs []model.ControlResult) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	for _, c := range cs {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO controls(assessment_id,id,domain,title,method,status,reason,adapter,evidence_json,refs_json) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			asmt, c.ID, c.Domain, c.Title, c.Method, string(c.Status), c.Reason, c.Adapter, js(c.EvidenceIDs), js(c.Refs)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Controls lists control results.
func (s *Store) Controls(asmt string) ([]model.ControlResult, error) {
	rows, err := s.DB.Query(`SELECT id,domain,title,method,status,COALESCE(reason,''),COALESCE(adapter,''),evidence_json,refs_json FROM controls WHERE assessment_id=? ORDER BY id`, asmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ControlResult
	for rows.Next() {
		var c model.ControlResult
		var st string
		var ev, refs sql.NullString
		if err := rows.Scan(&c.ID, &c.Domain, &c.Title, &c.Method, &st, &c.Reason, &c.Adapter, &ev, &refs); err != nil {
			return nil, err
		}
		c.Status = model.Status(st)
		c.EvidenceIDs = unjs[[]string](ev)
		c.Refs = unjs[[]string](refs)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetControlStatus updates one control and records an event.
func (s *Store) SetControlStatus(projectID, asmt, id string, st model.Status, reason string) error {
	var old string
	_ = s.DB.QueryRow(`SELECT status FROM controls WHERE assessment_id=? AND id=?`, asmt, id).Scan(&old)
	if old == string(st) {
		return nil
	}
	if _, err := s.DB.Exec(`UPDATE controls SET status=?, reason=? WHERE assessment_id=? AND id=?`, string(st), reason, asmt, id); err != nil {
		return err
	}
	return s.Event(projectID, asmt+"/"+id, old, string(st), reason)
}

// PutEdges stores edges.
func (s *Store) PutEdges(asmt string, es []model.Edge) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	for _, e := range es {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO edges(assessment_id,id,domains,title,scenario,status,reason,provenance_json,tests_json) VALUES(?,?,?,?,?,?,?,?,?)`,
			asmt, e.ID, e.Domains, e.Title, e.Scenario, string(e.Status), e.Reason, js(e.Provenance), js(e.Tests)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Edges lists edges.
func (s *Store) Edges(asmt string) ([]model.Edge, error) {
	rows, err := s.DB.Query(`SELECT id,domains,title,COALESCE(scenario,''),status,COALESCE(reason,''),provenance_json,tests_json FROM edges WHERE assessment_id=? ORDER BY id`, asmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Edge
	for rows.Next() {
		var e model.Edge
		var st string
		var pv, ts sql.NullString
		if err := rows.Scan(&e.ID, &e.Domains, &e.Title, &e.Scenario, &st, &e.Reason, &pv, &ts); err != nil {
			return nil, err
		}
		e.Status = model.Status(st)
		e.Provenance = unjs[[]string](pv)
		e.Tests = unjs[[]string](ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PutRun stores an adapter run.
func (s *Store) PutRun(asmt string, r model.Run) error {
	_, err := s.DB.Exec(`INSERT OR REPLACE INTO runs(id,assessment_id,adapter,tool_version,started_at,ended_at,exit_class,detail,signals) VALUES(?,?,?,?,?,?,?,?,?)`,
		r.ID, asmt, r.Adapter, r.ToolVersion, r.StartedAt, r.EndedAt, r.ExitClass, r.Detail, r.SignalsCount)
	return err
}

// Runs lists adapter runs of an assessment.
func (s *Store) Runs(asmt string) ([]model.Run, error) {
	rows, err := s.DB.Query(`SELECT id,adapter,COALESCE(tool_version,''),COALESCE(started_at,''),COALESCE(ended_at,''),exit_class,COALESCE(detail,''),COALESCE(signals,0) FROM runs WHERE assessment_id=? ORDER BY adapter`, asmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Run
	for rows.Next() {
		var r model.Run
		if err := rows.Scan(&r.ID, &r.Adapter, &r.ToolVersion, &r.StartedAt, &r.EndedAt, &r.ExitClass, &r.Detail, &r.SignalsCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EvidenceRow is a row of the evidence table.
type EvidenceRow struct {
	ID             string `json:"id"`
	AssessmentID   string `json:"assessment_id"`
	Kind           string `json:"kind"`
	SHA256         string `json:"sha256"`
	Path           string `json:"path"`
	RedactionState string `json:"redaction_state"`
	CreatedAt      string `json:"created_at"`
	Collector      string `json:"collector"`
	SourceRef      string `json:"source_ref"`
}

// PutEvidence stores evidence metadata.
func (s *Store) PutEvidence(e EvidenceRow) error {
	_, err := s.DB.Exec(`INSERT OR IGNORE INTO evidence(id,assessment_id,kind,sha256,path,redaction_state,created_at,collector,source_ref) VALUES(?,?,?,?,?,?,?,?,?)`,
		e.ID, e.AssessmentID, e.Kind, e.SHA256, e.Path, e.RedactionState, e.CreatedAt, e.Collector, e.SourceRef)
	return err
}

// Evidence returns one evidence row.
func (s *Store) Evidence(id string) (*EvidenceRow, error) {
	e := &EvidenceRow{}
	err := s.DB.QueryRow(`SELECT id,assessment_id,kind,sha256,path,redaction_state,created_at,COALESCE(collector,''),COALESCE(source_ref,'') FROM evidence WHERE id=?`, id).
		Scan(&e.ID, &e.AssessmentID, &e.Kind, &e.SHA256, &e.Path, &e.RedactionState, &e.CreatedAt, &e.Collector, &e.SourceRef)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

// EvidenceFor lists evidence rows of an assessment.
func (s *Store) EvidenceFor(asmt string) ([]EvidenceRow, error) {
	rows, err := s.DB.Query(`SELECT id,assessment_id,kind,sha256,path,redaction_state,created_at,COALESCE(collector,''),COALESCE(source_ref,'') FROM evidence WHERE assessment_id=? ORDER BY id`, asmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceRow
	for rows.Next() {
		var e EvidenceRow
		if err := rows.Scan(&e.ID, &e.AssessmentID, &e.Kind, &e.SHA256, &e.Path, &e.RedactionState, &e.CreatedAt, &e.Collector, &e.SourceRef); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const findingCols = `id,fingerprint,COALESCE(rule_id,''),COALESCE(control_id,''),title,severity,confidence,status,COALESCE(cwe,''),COALESCE(file,''),COALESCE(start_line,0),COALESCE(end_line,0),
	COALESCE(message,''),COALESCE(fix,''),COALESCE(retest,''),COALESCE(collector,''),COALESCE(first_seen,''),COALESCE(last_seen,''),COALESCE(last_assessment,''),evidence_json,
	COALESCE(reviewer,''),COALESCE(note,''),COALESCE(expires_at,''),COALESCE(stale,0)`

func scanFinding(sc interface{ Scan(...any) error }) (model.Finding, error) {
	var f model.Finding
	var sev, conf, st string
	var ev sql.NullString
	err := sc.Scan(&f.ID, &f.Fingerprint, &f.RuleID, &f.ControlID, &f.Title, &sev, &conf, &st, &f.CWE, &f.File, &f.StartLine, &f.EndLine,
		&f.Message, &f.Fix, &f.Retest, &f.Collector, &f.FirstSeen, &f.LastSeen, &f.AssessmentID, &ev, &f.Reviewer, &f.Note, &f.ExpiresAt, &f.Stale)
	f.Severity = model.Severity(sev)
	f.Confidence = model.Confidence(conf)
	f.Status = model.FindingStatus(st)
	f.EvidenceIDs = unjs[[]string](ev)
	return f, err
}

// FindingByFingerprint returns a finding or nil.
func (s *Store) FindingByFingerprint(projectID, fp string) (*model.Finding, error) {
	f, err := scanFinding(s.DB.QueryRow(`SELECT `+findingCols+` FROM findings WHERE project_id=? AND fingerprint=?`, projectID, fp))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &f, err
}

// Finding returns a finding by display ID or nil.
func (s *Store) Finding(projectID, id string) (*model.Finding, error) {
	f, err := scanFinding(s.DB.QueryRow(`SELECT `+findingCols+` FROM findings WHERE project_id=? AND id=?`, projectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &f, err
}

// Findings lists all findings of a project.
func (s *Store) Findings(projectID string) ([]model.Finding, error) {
	rows, err := s.DB.Query(`SELECT `+findingCols+` FROM findings WHERE project_id=? ORDER BY id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// NextFindingID returns the next display ID (PW-0001, ...).
func (s *Store) NextFindingID(projectID string) (string, error) {
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM findings WHERE project_id=?`, projectID).Scan(&n); err != nil {
		return "", err
	}
	for {
		n++
		id := fmt.Sprintf("PW-%04d", n)
		var x int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM findings WHERE id=?`, id).Scan(&x); err != nil {
			return "", err
		}
		if x == 0 {
			return id, nil
		}
	}
}

// UpsertFinding inserts or updates a finding.
func (s *Store) UpsertFinding(projectID string, f model.Finding) error {
	return upsertFinding(s.DB, projectID, f)
}

func upsertFinding(x execer, projectID string, f model.Finding) error {
	_, err := x.Exec(`INSERT INTO findings(id,project_id,fingerprint,rule_id,control_id,title,severity,confidence,status,cwe,file,start_line,end_line,message,fix,retest,collector,
		first_seen,last_seen,last_assessment,evidence_json,reviewer,note,expires_at,stale) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(project_id,fingerprint) DO UPDATE SET rule_id=excluded.rule_id, control_id=excluded.control_id, title=excluded.title, severity=excluded.severity,
		confidence=excluded.confidence, status=excluded.status, cwe=excluded.cwe, file=excluded.file, start_line=excluded.start_line, end_line=excluded.end_line,
		message=excluded.message, fix=excluded.fix, retest=excluded.retest, collector=excluded.collector, last_seen=excluded.last_seen, last_assessment=excluded.last_assessment,
		evidence_json=excluded.evidence_json, reviewer=excluded.reviewer, note=excluded.note, expires_at=excluded.expires_at, stale=excluded.stale`,
		f.ID, projectID, f.Fingerprint, f.RuleID, f.ControlID, f.Title, string(f.Severity), string(f.Confidence), string(f.Status), f.CWE, f.File, f.StartLine, f.EndLine,
		f.Message, f.Fix, f.Retest, f.Collector, f.FirstSeen, f.LastSeen, f.AssessmentID, js(f.EvidenceIDs), f.Reviewer, f.Note, f.ExpiresAt, f.Stale)
	return err
}

// MarkStale records a changed file and flags findings in that file.
func (s *Store) MarkStale(projectID, path string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO stale_files(project_id,path,changed_at) VALUES(?,?,?) ON CONFLICT(project_id,path) DO UPDATE SET changed_at=excluded.changed_at`, projectID, path, Now()); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`UPDATE findings SET stale=1 WHERE project_id=? AND file=?`, projectID, path); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT INTO events(project_id,entity_id,old_state,new_state,ts,reason) VALUES(?,?,?,?,?,?)`, projectID, "file:"+path, "", "STALE", Now(), "file changed after assessment"); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// StaleFiles lists files changed since the last assessment.
func (s *Store) StaleFiles(projectID string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT path FROM stale_files WHERE project_id=? ORDER BY path`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ClearStale removes stale markers after a full re-assessment.
func (s *Store) ClearStale(projectID string) error {
	_, err := s.DB.Exec(`DELETE FROM stale_files WHERE project_id=?`, projectID)
	return err
}

// Approval is a human approval bound to a subject hash.
type Approval struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	SubjectHash string `json:"subject_hash"`
	ApprovedBy  string `json:"approved_by"`
	ApprovedAt  string `json:"approved_at"`
	ExpiresAt   string `json:"expires_at"`
}

// PutApproval stores an approval.
func (s *Store) PutApproval(projectID string, a Approval) error {
	_, err := s.DB.Exec(`INSERT INTO approvals(id,project_id,kind,subject_hash,approved_by,approved_at,expires_at) VALUES(?,?,?,?,?,?,?)`,
		a.ID, projectID, a.Kind, a.SubjectHash, a.ApprovedBy, a.ApprovedAt, a.ExpiresAt)
	if err == nil {
		err = s.Event(projectID, "approval:"+a.ID, "", "APPROVED", a.Kind+" by "+a.ApprovedBy)
	}
	return err
}

// ValidApproval returns a non-expired, non-revoked approval for a subject.
func (s *Store) ValidApproval(projectID, kind, subjectHash string, now time.Time) (*Approval, error) {
	rows, err := s.DB.Query(`SELECT id,kind,subject_hash,approved_by,approved_at,expires_at FROM approvals WHERE project_id=? AND kind=? AND subject_hash=? AND revoked=0 ORDER BY approved_at DESC`, projectID, kind, subjectHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.Kind, &a.SubjectHash, &a.ApprovedBy, &a.ApprovedAt, &a.ExpiresAt); err != nil {
			return nil, err
		}
		exp, err := time.Parse(time.RFC3339, a.ExpiresAt)
		if err == nil && now.Before(exp) {
			return &a, nil
		}
	}
	return nil, rows.Err()
}

// RevokeApprovals revokes all approvals of a kind.
func (s *Store) RevokeApprovals(projectID, kind string) (int64, error) {
	r, err := s.DB.Exec(`UPDATE approvals SET revoked=1 WHERE project_id=? AND kind=? AND revoked=0`, projectID, kind)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	if n > 0 {
		_ = s.Event(projectID, "approvals:"+kind, "APPROVED", "REVOKED", "revoked by operator")
	}
	return n, nil
}

// EventRow is an audit event.
type EventRow struct {
	Seq      int64  `json:"seq"`
	Entity   string `json:"entity"`
	OldState string `json:"old_state"`
	NewState string `json:"new_state"`
	TS       string `json:"ts"`
	Reason   string `json:"reason"`
}

// Events returns the last n events.
func (s *Store) Events(projectID string, n int) ([]EventRow, error) {
	rows, err := s.DB.Query(`SELECT seq,entity_id,COALESCE(old_state,''),COALESCE(new_state,''),ts,COALESCE(reason,'') FROM events WHERE project_id=? ORDER BY seq DESC LIMIT ?`, projectID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventRow
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(&e.Seq, &e.Entity, &e.OldState, &e.NewState, &e.TS, &e.Reason); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Assessment returns one assessment of a project, or nil.
func (s *Store) Assessment(projectID, id string) (*Assessment, error) {
	row := s.DB.QueryRow(`SELECT id,seq,COALESCE(git_commit,''),COALESCE(git_dirty,0),profile,COALESCE(config_hash,''),COALESCE(catalog_version,''),started_at,COALESCE(ended_at,''),status,COALESCE(manifest_json,'')
		FROM assessments WHERE project_id=? AND id=?`, projectID, id)
	a := &Assessment{}
	err := row.Scan(&a.ID, &a.Seq, &a.GitCommit, &a.GitDirty, &a.Profile, &a.ConfigHash, &a.CatalogVersion, &a.StartedAt, &a.EndedAt, &a.Status, &a.ManifestJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return a, err
}

// PreviousObserved returns the latest finished assessment before seq that
// recorded observations, or nil.
func (s *Store) PreviousObserved(projectID string, seq int) (*Assessment, error) {
	var id string
	err := s.DB.QueryRow(`SELECT id FROM assessments WHERE project_id=? AND seq<? AND observed=1 AND status IN ('COMPLETE','INCOMPLETE') ORDER BY seq DESC LIMIT 1`, projectID, seq).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.Assessment(projectID, id)
}

// Observation records that an assessment saw a finding, directly or carried
// over from the previous assessment by a targeted retest.
type Observation struct {
	Fingerprint string
	FindingID   string
	Carried     bool
}

// PutObservations stores the observations of an assessment and marks it as
// tracked, so an empty set means "nothing observed", not "unknown".
func (s *Store) PutObservations(asmt string, obs []Observation) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	for _, o := range obs {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO observations(assessment_id,fingerprint,finding_id,carried) VALUES(?,?,?,?)`, asmt, o.Fingerprint, o.FindingID, o.Carried); err != nil {
			tx.Rollback()
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE assessments SET observed=1 WHERE id=?`, asmt); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Observations returns fingerprint -> observation for an assessment and
// whether the assessment tracked observations at all.
func (s *Store) Observations(asmt string) (map[string]Observation, bool, error) {
	var tracked int
	if err := s.DB.QueryRow(`SELECT COALESCE(observed,0) FROM assessments WHERE id=?`, asmt).Scan(&tracked); err != nil {
		return nil, false, err
	}
	rows, err := s.DB.Query(`SELECT fingerprint,finding_id,carried FROM observations WHERE assessment_id=?`, asmt)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := map[string]Observation{}
	for rows.Next() {
		var o Observation
		if err := rows.Scan(&o.Fingerprint, &o.FindingID, &o.Carried); err != nil {
			return nil, false, err
		}
		out[o.Fingerprint] = o
	}
	return out, tracked == 1, rows.Err()
}

// ObservedBefore returns the fingerprints observed by any assessment of the
// project with a sequence number below seq.
func (s *Store) ObservedBefore(projectID string, seq int) (map[string]bool, error) {
	rows, err := s.DB.Query(`SELECT DISTINCT o.fingerprint FROM observations o JOIN assessments a ON a.id=o.assessment_id WHERE a.project_id=? AND a.seq<?`, projectID, seq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, err
		}
		out[fp] = true
	}
	return out, rows.Err()
}

// Waivers returns finding ID -> new state for findings marked false positive
// or risk accepted at a time in (from, to].
func (s *Store) Waivers(projectID, from, to string) (map[string]string, error) {
	rows, err := s.DB.Query(`SELECT entity_id,new_state FROM events WHERE project_id=? AND new_state IN ('FALSE_POSITIVE','RISK_ACCEPTED') AND ts>? AND ts<=? ORDER BY seq`, projectID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, st string
		if err := rows.Scan(&id, &st); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

// Migrations returns the ledger migrations in order. Published migrations
// are frozen; schema changes add a new one (see docs/SCHEMAS.md).
func Migrations() []string { return append([]string{}, migrations...) }
