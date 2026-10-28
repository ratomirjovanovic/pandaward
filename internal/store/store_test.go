package store

import (
	"slices"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.EnsureProject("p1", dir, "demo"); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestMigrationsAreIdempotent(t *testing.T) {
	s, dir := open(t)
	if err := s.MarkStale("p1", "src/a.js"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopening an existing ledger must not fail: %v", err)
	}
	defer s2.Close()
	if files, _ := s2.StaleFiles("p1"); !slices.Equal(files, []string{"src/a.js"}) {
		t.Fatalf("data must survive reopening: %v", files)
	}
}

func TestAssessmentLifecycle(t *testing.T) {
	s, _ := open(t)
	if a, _ := s.LatestAssessment("p1"); a != nil {
		t.Fatal("no assessment expected yet")
	}
	a1, err := s.NewAssessment("p1", Assessment{Profile: "local-passive"})
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := s.LatestAssessment("p1"); a != nil {
		t.Fatal("a RUNNING assessment must not count as latest")
	}
	if err := s.FinishAssessment("p1", a1.ID, "COMPLETE", "{}"); err != nil {
		t.Fatal(err)
	}
	a2, _ := s.NewAssessment("p1", Assessment{Profile: "local-passive"})
	if a2.Seq != a1.Seq+1 {
		t.Fatalf("sequence must increase: %d then %d", a1.Seq, a2.Seq)
	}
	if n, _ := s.MarkInterrupted("p1"); n != 1 {
		t.Fatalf("one running assessment must be marked interrupted, got %d", n)
	}
	if a, _ := s.LatestAssessment("p1"); a == nil || a.ID != a1.ID {
		t.Fatalf("interrupted assessments must not become latest: %+v", a)
	}
}

func TestStaleMarkersFlagFindings(t *testing.T) {
	s, _ := open(t)
	f := model.Finding{ID: "PW-0001", Fingerprint: "fp1", RuleID: "r", ControlID: "D-001", Title: "t", Severity: model.SevHigh,
		Confidence: model.Confirmed, Status: model.FindingOpen, File: "src/a.js", Collector: "builtin-code"}
	if err := s.UpsertFinding("p1", f); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkStale("p1", "src/a.js"); err != nil {
		t.Fatal(err)
	}
	s.MarkStale("p1", "src/a.js") // a second edit of the same file is one entry
	if files, _ := s.StaleFiles("p1"); !slices.Equal(files, []string{"src/a.js"}) {
		t.Fatalf("stale files = %v", files)
	}
	got, _ := s.Finding("p1", "PW-0001")
	if got == nil || !got.Stale {
		t.Fatalf("finding in a changed file must be flagged stale: %+v", got)
	}
	if err := s.ClearStale("p1"); err != nil {
		t.Fatal(err)
	}
	if files, _ := s.StaleFiles("p1"); len(files) != 0 {
		t.Fatalf("stale files must be cleared: %v", files)
	}
}

func TestFindingUpsertKeepsIdentityByFingerprint(t *testing.T) {
	s, _ := open(t)
	id, _ := s.NextFindingID("p1")
	if id != "PW-0001" {
		t.Fatalf("first ID = %s", id)
	}
	f := model.Finding{ID: id, Fingerprint: "fp1", RuleID: "r", ControlID: "D-001", Title: "first", Severity: model.SevHigh,
		Confidence: model.Hypothesis, Status: model.FindingOpen, EvidenceIDs: []string{"ev_1"}}
	s.UpsertFinding("p1", f)
	f.ID, f.Title, f.Status = "PW-9999", "second", model.FindingRemediated
	if err := s.UpsertFinding("p1", f); err != nil {
		t.Fatal(err)
	}
	got, _ := s.FindingByFingerprint("p1", "fp1")
	if got == nil || got.ID != "PW-0001" || got.Title != "second" || got.Status != model.FindingRemediated || !slices.Equal(got.EvidenceIDs, []string{"ev_1"}) {
		t.Fatalf("upsert must update in place and keep the original ID: %+v", got)
	}
	if next, _ := s.NextFindingID("p1"); next != "PW-0002" {
		t.Fatalf("next ID = %s", next)
	}
}

func TestFileHashesAndDomains(t *testing.T) {
	s, _ := open(t)
	a, _ := s.NewAssessment("p1", Assessment{})
	err := s.PutFileHashes(a.ID, map[string]string{"src/a.js": "h1", "README.md": "h2"}, map[string][]string{"src/a.js": {"B", "D"}})
	if err != nil {
		t.Fatal(err)
	}
	ds, known, _ := s.FileDomains(a.ID, "src/a.js")
	if !known || !slices.Equal(ds, []string{"B", "D"}) {
		t.Fatalf("domains = %v known=%v", ds, known)
	}
	if ds, known, _ := s.FileDomains(a.ID, "README.md"); !known || len(ds) != 0 {
		t.Fatalf("file without domains must be known with none: %v %v", ds, known)
	}
	if _, known, _ := s.FileDomains(a.ID, "new.js"); known {
		t.Fatal("unknown file must report known=false")
	}
}

func TestApprovalsExpireAndRevoke(t *testing.T) {
	s, _ := open(t)
	now := time.Now().UTC()
	ap := Approval{ID: "ap1", Kind: "scope", SubjectHash: "h", ApprovedBy: "alice", ApprovedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if err := s.PutApproval("p1", ap); err != nil {
		t.Fatal(err)
	}
	if a, _ := s.ValidApproval("p1", "scope", "h", now); a == nil {
		t.Fatal("approval must be valid before it expires")
	}
	if a, _ := s.ValidApproval("p1", "scope", "other", now); a != nil {
		t.Fatal("approval is bound to its subject hash")
	}
	if a, _ := s.ValidApproval("p1", "scope", "h", now.Add(2*time.Hour)); a != nil {
		t.Fatal("expired approval must not be valid")
	}
	if n, _ := s.RevokeApprovals("p1", "scope"); n != 1 {
		t.Fatalf("revoked %d", n)
	}
	if a, _ := s.ValidApproval("p1", "scope", "h", now); a != nil {
		t.Fatal("revoked approval must not be valid")
	}
}
