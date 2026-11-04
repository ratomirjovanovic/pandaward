package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/report"
)

var authzIDs = []string{"B-004", "C-001", "C-002"}

func latestControls(t *testing.T, e *engine.Engine) map[string]model.ControlResult {
	t.Helper()
	a, err := e.St.LatestAssessment(e.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := e.St.Controls(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]model.ControlResult{}
	for _, c := range cs {
		out[c.ID] = c
	}
	return out
}

func reportControls(t *testing.T, e *engine.Engine) map[string]model.ControlResult {
	t.Helper()
	r, err := report.Build(e)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]model.ControlResult{}
	for _, c := range r.Controls {
		out[c.ID] = c
	}
	return out
}

func runStaging(t *testing.T, e *engine.Engine, want model.Status) {
	t.Helper()
	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	for _, cid := range authzIDs {
		if res.Controls[cid] != string(want) {
			t.Fatalf("staging-active: %s = %s, want %s (%v)", cid, res.Controls[cid], want, res.Notes)
		}
	}
}

func wantStatus(t *testing.T, step string, cs map[string]model.ControlResult, want model.Status, reasonHas string) {
	t.Helper()
	for _, cid := range authzIDs {
		c := cs[cid]
		// decided_by is set only for decisive results; a STALE result in a
		// report is undecided, so it carries none.
		wantBy := model.DecidedRuntime
		if want == model.StatusStale && c.DecidedBy == "" {
			wantBy = ""
		}
		if c.Status != want || c.DecidedBy != wantBy || !strings.Contains(c.Reason, reasonHas) {
			t.Errorf("%s: %s = %s (decided_by %q, reason %q), want %s from runtime with %q", step, cid, c.Status, c.DecidedBy, c.Reason, want, reasonHas)
		}
	}
}

func scanOK(t *testing.T, e *engine.Engine) *engine.ScanResult {
	t.Helper()
	res, err := e.Scan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A passive scan cannot observe runtime controls. It keeps a runtime
// verdict while its approval and inputs hold (PASS and FAIL alike), shows
// it STALE once the approval is revoked, and a new runtime run replaces it.
func TestRuntimeVerdictCarriedAcrossPassiveScans(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	fixed.Store(true)
	var hits atomic.Int64
	app := invoiceApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	setCreds(t)
	e := authzProject(t, app.URL, "")
	approveScope(t, e)

	runStaging(t, e, model.StatusPass)
	before := scanOK(t, e)
	wantStatus(t, "scan after runtime PASS", latestControls(t, e), model.StatusPass, "runtime staging-active")
	wantStatus(t, "report after runtime PASS", reportControls(t, e), model.StatusPass, "denial(s) observed as expected")
	if _, res, err := e.RetestChanged(context.Background(), nil, true); err != nil {
		t.Fatal(err)
	} else if res.Coverage.Decisive != before.Coverage.Decisive {
		t.Errorf("retest decisive controls %d, scan had %d", res.Coverage.Decisive, before.Coverage.Decisive)
	}
	wantStatus(t, "targeted retest", latestControls(t, e), model.StatusPass, "runtime staging-active")

	// A runtime FAIL is carried too, and its findings stay open and current.
	fixed.Store(false)
	runStaging(t, e, model.StatusFail)
	scanOK(t, e)
	wantStatus(t, "scan after runtime FAIL", latestControls(t, e), model.StatusFail, "confirmed unauthorized")
	fs, _ := e.St.Findings(e.ProjectID)
	n := 0
	for _, f := range fs {
		if f.Collector != "authz" {
			continue
		}
		n++
		if !f.Status.Active() || f.Stale {
			t.Errorf("authz finding %s is %s (stale %v) after a passive scan; it must stay open and current", f.ID, f.Status, f.Stale)
		}
	}
	if n == 0 {
		t.Fatal("no authz findings recorded")
	}

	// Revoking the approval invalidates the verdict at once in reports and
	// in the next scan; nothing falls back to BLOCKED or PASS.
	if _, err := e.St.RevokeApprovals(e.ProjectID, engine.ApprovalKind); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "report after revoke", reportControls(t, e), model.StatusStale, "revoked")
	scanOK(t, e)
	wantStatus(t, "scan after revoke", latestControls(t, e), model.StatusStale, "was FAIL")
	wantStatus(t, "scan after revoke", latestControls(t, e), model.StatusStale, "revoked")
	fs, _ = e.St.Findings(e.ProjectID)
	for _, f := range fs {
		if f.Collector == "authz" && (!f.Status.Active() || !f.Stale) {
			t.Errorf("authz finding %s is %s (stale %v); with the verdict stale it must stay open and be marked stale", f.ID, f.Status, f.Stale)
		}
	}

	// A new approval and runtime run replace the stale verdict.
	fixed.Store(true)
	approveScope(t, e)
	runStaging(t, e, model.StatusPass)
	scanOK(t, e)
	wantStatus(t, "scan after new runtime run", latestControls(t, e), model.StatusPass, "runtime staging-active")
}

func TestRuntimeVerdictStaleOnFileChangeAndExpiry(t *testing.T) {
	t.Setenv("PANDAWARD_CONFIG_DIR", t.TempDir())
	var fixed atomic.Bool
	fixed.Store(true)
	var hits atomic.Int64
	app := invoiceApp(&fixed, &hits)
	defer app.Close()
	noZAP(t)
	setCreds(t)
	e := authzProject(t, app.URL, "")
	approveScope(t, e)
	runStaging(t, e, model.StatusPass)

	// The route file the checks depend on changes.
	p := filepath.Join(e.Root, "src", "server.js")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, []byte("\napp.get('/api/invoices/:id/pdf', (req, res) => res.send('x'));\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := reportControls(t, e)["C-001"]; c.Status != model.StatusStale || !strings.Contains(c.Reason, "src/server.js") {
		t.Fatalf("report C-001 after a route file change = %s %q, want STALE naming src/server.js", c.Status, c.Reason)
	}
	scanOK(t, e)
	c := latestControls(t, e)["C-001"]
	if c.Status != model.StatusStale || !strings.Contains(c.Reason, "src/server.js") || !strings.Contains(c.Reason, "was PASS") {
		t.Fatalf("C-001 after a route file change = %s %q, want STALE naming src/server.js", c.Status, c.Reason)
	}
	if c := reportControls(t, e)["C-001"]; c.Status != model.StatusStale {
		t.Fatalf("report C-001 after the scan = %s, want STALE", c.Status)
	}

	// A new runtime run replaces it; then the approval expires.
	runStaging(t, e, model.StatusPass)
	scanOK(t, e)
	wantStatus(t, "scan after re-run", latestControls(t, e), model.StatusPass, "runtime staging-active")
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if _, err := e.St.DB.Exec(`UPDATE approvals SET expires_at=?`, past); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "report after expiry", reportControls(t, e), model.StatusStale, "expired")
	scanOK(t, e)
	wantStatus(t, "scan after expiry", latestControls(t, e), model.StatusStale, "expired")
}
