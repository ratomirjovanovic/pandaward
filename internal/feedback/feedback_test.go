package feedback

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func project(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "src", "billing"), 0o755)
	body := "const a = 1\nconst key = \"" + testfixture.FakeStripe + "\"\nrun(key)\n"
	if err := os.WriteFile(filepath.Join(root, "src", "billing", "charge.js"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

var finding = model.Finding{ID: "PW-0004", RuleID: "secret.stripe-live", ControlID: "E-001", Severity: model.SevHigh,
	Confidence: model.Confirmed, Collector: "builtin-secrets", File: "src/billing/charge.js", StartLine: 2, EndLine: 2,
	Title: "Hardcoded Stripe live secret key", Message: "m"}

// By default a report leaves out the path, the code and the finding text.
func TestDefaultReportCarriesNoProjectData(t *testing.T) {
	root := project(t)
	r := FromFinding(root, finding, []model.Run{{Adapter: "builtin-secrets", ToolVersion: "builtin"}}, Options{})
	if r.RuleID != "secret.stripe-live" || r.ControlID != "E-001" || r.FileType != ".js" || r.ToolVersion != "builtin" || r.Pandaward == "" || r.Catalog == "" {
		t.Fatalf("metadata missing: %+v", r)
	}
	all := r.Markdown() + r.IssueURL()
	for _, leak := range []string{"billing", "charge", testfixture.FakeStripe, "run(key)"} {
		if strings.Contains(all, leak) {
			t.Errorf("default report contains %q", leak)
		}
	}
}

// Opting in adds the path and the lines, redacted.
func TestOptInSnippetIsRedacted(t *testing.T) {
	root := project(t)
	r := FromFinding(root, finding, nil, Options{IncludePath: true, IncludeSnippet: true, Note: "key is a test value " + testfixture.FakeStripe})
	if r.Path != "src/billing/charge.js" || r.Line != 2 || !strings.Contains(r.Snippet, "const key") {
		t.Fatalf("opt-in data missing: %+v", r)
	}
	all := r.Markdown() + r.IssueURL()
	if strings.Contains(all, testfixture.FakeStripe) {
		t.Fatal("secret value in the report")
	}
}

func TestSnippetStaysInsideRoot(t *testing.T) {
	root := project(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("outside\n"), 0o644)
	rel, _ := filepath.Rel(root, outside)
	if s := snippet(root, filepath.ToSlash(rel), 1, 1); s != "" {
		t.Fatalf("read a file outside the root: %q", s)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(outside, link); err == nil {
		if s := snippet(root, "link.txt", 1, 1); s != "" {
			t.Fatalf("followed a symlink outside the root: %q", s)
		}
	}
}

func TestSnippetIsBounded(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.py"), []byte(strings.Repeat("x = 1\n", 100)), 0o644)
	if n := strings.Count(snippet(root, "a.py", 1, 100), "\n") + 1; n != MaxSnippetLines {
		t.Fatalf("snippet has %d lines, want %d", n, MaxSnippetLines)
	}
}

func TestIssueURLPrefillsTheForm(t *testing.T) {
	r := Missed(t.TempDir(), "d-003", "app/db.py", 10, Options{Note: "string formatting into execute"})
	if r.ControlID != "D-003" || r.RuleID != "" || r.Kind != FalseNegative {
		t.Fatalf("control not recognised: %+v", r)
	}
	u, err := url.Parse(r.IssueURL())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if !strings.HasPrefix(r.IssueURL(), Repo+"/issues/new?") || q.Get("template") != "false-negative.yml" || q.Get("rule") != "D-003" ||
		q.Get("title") != "[false-negative] D-003" || !strings.Contains(q.Get("details"), "string formatting") {
		t.Fatalf("bad prefill: %v", q)
	}
}

func TestFileType(t *testing.T) {
	for in, want := range map[string]string{
		"src/a/B.TS": ".ts", "Dockerfile": "Dockerfile", "deploy/.env.production": ".env",
		".github/workflows/ci.yml": "github-workflow.yml", "bin/run": "(no extension)", "": "",
	} {
		if got := FileType(in); got != want {
			t.Errorf("FileType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSummaryRanksRulesByFalsePositives(t *testing.T) {
	fs := []model.Finding{
		{RuleID: "a", Status: model.FindingFalsePositive}, {RuleID: "a", Status: model.FindingOpen},
		{RuleID: "b", Status: model.FindingFalsePositive}, {RuleID: "b", Status: model.FindingFalsePositive},
		{RuleID: "c", Status: model.FindingOpen},
	}
	got := Summary(fs)
	if len(got) != 2 || got[0].RuleID != "b" || got[0].FalsePositives != 2 || got[1].RuleID != "a" || got[1].Open != 1 {
		t.Fatalf("summary = %+v", got)
	}
}
