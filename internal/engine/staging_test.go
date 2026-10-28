package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/scope"
	"github.com/ratomirjovanovic/pensec/internal/testfixture"
	"github.com/ratomirjovanovic/pensec/internal/zap"
)

// fakeZAP stands in for ZAP: it sends its requests through the guard like
// the real one does through the proxy, and returns the given alerts.
func fakeZAP(t *testing.T, paths []string, alerts []zap.Alert, err error) {
	t.Helper()
	oldL, oldR := ZAPLocator, ZAPRunner
	t.Cleanup(func() { ZAPLocator, ZAPRunner = oldL, oldR })
	ZAPLocator = func(string) (string, error) { return filepath.Join(t.TempDir(), "zap.sh"), nil }
	ZAPRunner = func(ctx context.Context, o zap.Options) (*zap.Result, error) {
		c := o.Guard.Client()
		for _, p := range paths {
			if resp, err := c.Get(p); err == nil {
				resp.Body.Close()
			}
		}
		if err != nil {
			return nil, err
		}
		return &zap.Result{Version: "2.17.0", Alerts: alerts}, nil
	}
}

func stagingSetup(t *testing.T, edit func(string) string) (*Engine, *httptest.Server, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	t.Cleanup(srv.Close)
	root := testfixture.VulnerableRepo(t)
	e, _ := scan(t, root)
	t.Cleanup(func() { e.Close() })
	m := writeScope(t, root, srv.URL, true)
	if edit != nil {
		b, _ := os.ReadFile(scope.Path(root))
		os.WriteFile(scope.Path(root), []byte(edit(string(b))), 0o644)
		m, _ = scope.Load(root)
	}
	approve(t, e, m)
	return e, srv, &hits
}

func controlStatus(t *testing.T, e *Engine, id string) model.ControlResult {
	t.Helper()
	a, _ := e.St.LatestAssessment(e.ProjectID)
	cs, _ := e.St.Controls(a.ID)
	for _, c := range cs {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %s missing", id)
	return model.ControlResult{}
}

func TestStagingRequiresApprovalAndNonProduction(t *testing.T) {
	root := testfixture.VulnerableRepo(t)
	e, _ := scan(t, root)
	defer e.Close()
	fakeZAP(t, nil, nil, nil)
	if _, err := e.StagingActive(context.Background(), func(string) {}); err == nil {
		t.Fatal("staging-active must fail without a scope manifest")
	}
	writeScope(t, root, "http://127.0.0.1:1", true)
	if _, err := e.StagingActive(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "approval") {
		t.Fatalf("staging-active must fail without approval, got %v", err)
	}
	e2, _, hits := stagingSetup(t, func(s string) string { return strings.Replace(s, "environment: staging", "environment: production", 1) })
	if _, err := e2.StagingActive(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "production") {
		t.Fatalf("staging-active must refuse production, got %v", err)
	}
	if *hits != 0 {
		t.Fatal("no request may be sent when the profile refuses")
	}
}

func TestStagingZAPMissingIsBlocked(t *testing.T) {
	e, _, hits := stagingSetup(t, nil)
	old := ZAPLocator
	defer func() { ZAPLocator = old }()
	ZAPLocator = func(string) (string, error) { return "", errors.New("ZAP is not installed") }
	if _, err := e.StagingActive(context.Background(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if c := controlStatus(t, e, "M-001"); c.Status != model.StatusBlocked {
		t.Fatalf("M-001 = %s, want BLOCKED", c.Status)
	}
	if *hits != 0 {
		t.Fatal("no request without ZAP")
	}
}

func TestStagingZAPFailureIsError(t *testing.T) {
	e, srv, _ := stagingSetup(t, nil)
	fakeZAP(t, []string{srv.URL + "/"}, nil, errors.New("ZAP exited 1: job spider failed"))
	if _, err := e.StagingActive(context.Background(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if c := controlStatus(t, e, "M-001"); c.Status != model.StatusError {
		t.Fatalf("a failed ZAP run must be ERROR, got %s", c.Status)
	}
}

func TestStagingZAPNoTrafficIsInconclusive(t *testing.T) {
	e, _, _ := stagingSetup(t, nil)
	fakeZAP(t, nil, nil, nil)
	if _, err := e.StagingActive(context.Background(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if c := controlStatus(t, e, "M-001"); c.Status != model.StatusInconclusive {
		t.Fatalf("a run that reached nothing must be INCONCLUSIVE, got %s", c.Status)
	}
}

func TestStagingZAPAlertsThenFixed(t *testing.T) {
	e, srv, hits := stagingSetup(t, nil)
	alert := zap.Alert{Site: srv.URL, PluginID: "10038", Name: "Content Security Policy (CSP) Header Not Set", Risk: 2, Confidence: 3, CWE: 693, Desc: "CSP is missing.", Solution: "Set a CSP.",
		Instances: []zap.Instance{{URI: srv.URL + "/?token=ghp_abcdefghijklmnopqrstuvwxyz0123456789", Method: "GET"}}}
	fp := zap.Alert{Site: srv.URL, PluginID: "10021", Name: "ignored", Risk: 1, Confidence: 0}
	fakeZAP(t, []string{srv.URL + "/", srv.URL + "/about"}, []zap.Alert{alert, fp}, nil)
	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Requests != 2 || *hits != 2 || res.Findings != 1 {
		t.Fatalf("requests %d hits %d findings %d", res.Requests, *hits, res.Findings)
	}
	if c := controlStatus(t, e, "M-001"); c.Status != model.StatusFail {
		t.Fatalf("M-001 = %s, want FAIL", c.Status)
	}
	if _, ok := res.Controls["D-005"]; ok {
		t.Fatal("D-005 must not be decided without zap.active_scan")
	}
	fs, _ := e.St.Findings(e.ProjectID)
	var f *model.Finding
	for i := range fs {
		if fs[i].RuleID == "zap.10038" {
			f = &fs[i]
		}
	}
	if f == nil || f.ControlID != "M-001" || f.Severity != model.SevMedium || f.File != srv.URL {
		t.Fatalf("finding: %+v", f)
	}
	ents, _ := os.ReadDir(filepath.Join(e.Private(), "evidence"))
	for _, en := range ents {
		raw, _ := os.ReadFile(filepath.Join(e.Private(), "evidence", en.Name()))
		if strings.Contains(string(raw), "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
			t.Fatal("token in a ZAP instance URL leaked into evidence")
		}
	}

	// Fixed: a complete run without the alert remediates the finding.
	fakeZAP(t, []string{srv.URL + "/"}, nil, nil)
	if _, err := e.StagingActive(context.Background(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if c := controlStatus(t, e, "M-001"); c.Status != model.StatusPass {
		t.Fatalf("M-001 after fix = %s, want PASS", c.Status)
	}
	g, _ := e.St.Finding(e.ProjectID, f.ID)
	if g.Status != model.FindingRemediated {
		t.Fatalf("finding after fix: %s", g.Status)
	}
}

func TestStagingActiveScanDecidesInjection(t *testing.T) {
	e, srv, _ := stagingSetup(t, func(s string) string { return strings.Replace(s, "active_scan: false", "active_scan: true", 1) })
	sqli := zap.Alert{Site: srv.URL, PluginID: "40018", Name: "SQL Injection", Risk: 3, Confidence: 2, CWE: 89, Instances: []zap.Instance{{URI: srv.URL + "/?id=1", Method: "GET", Param: "id"}}}
	fakeZAP(t, []string{srv.URL + "/"}, []zap.Alert{sqli}, nil)
	res, err := e.StagingActive(context.Background(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if res.Controls["D-005"] != string(model.StatusSuspected) || res.Controls["M-001"] != string(model.StatusPass) {
		t.Fatalf("controls: %v", res.Controls)
	}
}
