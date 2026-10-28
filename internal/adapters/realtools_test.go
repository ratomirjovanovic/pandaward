package adapters_test

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/engine"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

// TestRealTools scans the vulnerable fixture with the installed gitleaks,
// semgrep, osv-scanner and trivy and checks that every adapter completes
// and turns the real output into the expected findings. It needs the tools
// on PATH and network access for advisories and checks, so it runs only
// when PANDAWARD_REAL_TOOLS=1 (the real-tools CI job, which pins the versions).
// Rule IDs are those reported by the pinned versions; update them together.
func TestRealTools(t *testing.T) {
	if os.Getenv("PANDAWARD_REAL_TOOLS") != "1" {
		t.Skip("set PANDAWARD_REAL_TOOLS=1 to run against installed scanners")
	}
	root := testfixture.VulnerableRepo(t)
	e, _, err := engine.Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Cfg.Scan.AllowToolNetwork = true
	res, err := e.Scan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := []string{"gitleaks", "semgrep", "osv-scanner", "trivy"}
	for _, name := range tools {
		var run *model.Run
		for i := range res.Runs {
			if res.Runs[i].Adapter == name {
				run = &res.Runs[i]
			}
		}
		switch {
		case run == nil:
			t.Errorf("%s did not run", name)
		case run.ExitClass != model.ExitOK:
			t.Errorf("%s ended %s: %s", name, run.ExitClass, run.Detail)
		case run.ToolVersion == "":
			t.Errorf("%s version was not recorded", name)
		default:
			t.Logf("%s %s: %d signals, %s", name, run.ToolVersion, run.SignalsCount, run.Detail)
		}
	}

	fs, err := e.St.Findings(e.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{} // collector|rule|file|line
	for _, f := range fs {
		got[f.Collector+"|"+f.RuleID+"|"+f.File] = true
		if f.StartLine > 0 {
			got[f.Collector+"|"+f.RuleID+"|"+f.File+"|"+strconv.Itoa(f.StartLine)] = true
		}
		if f.File == "(outside-root)" {
			t.Errorf("%s %s: path not mapped into the project", f.Collector, f.RuleID)
		}
		b, _ := json.Marshal(f)
		if strings.Contains(string(b), testfixture.FakeStripe) || strings.Contains(string(b), testfixture.FakeGitHub) {
			t.Errorf("%s %s: finding contains an unredacted secret", f.Collector, f.RuleID)
		}
	}
	for _, want := range []string{
		"gitleaks|gitleaks.stripe-access-token|.env|1",
		"gitleaks|gitleaks.stripe-access-token|src/server.js|2",
		"semgrep|semgrep.pandaward-js-sql-string|src/server.js|6",
		"semgrep|semgrep.pandaward-js-shell-exec|src/server.js|8",
		"semgrep|semgrep.pandaward-js-eval|src/server.js|8",
		"semgrep|semgrep.pandaward-js-html-sink|src/server.js|9",
		"semgrep|semgrep.pandaward-py-unsafe-deserialization|app.py|4",
		"semgrep|semgrep.pandaward-py-tls-verify-off|app.py|5",
		"semgrep|semgrep.pandaward-py-shell|app.py|6",
		"semgrep|semgrep.pandaward-py-eval|app.py|7",
		"osv-scanner|osv.GHSA-p6mc-m468-83gw|legacy/package-lock.json",
		"osv-scanner|osv.GHSA-35jh-r3h4-6jhm|legacy/package-lock.json",
		"trivy|trivy.DS-0001|Dockerfile|1",
		"trivy|trivy.DS-0002|Dockerfile",
		"trivy|trivy.AWS-0099|infra/main.tf|2",
	} {
		if !got[want] {
			t.Errorf("missing finding %s", want)
		}
	}
	if t.Failed() {
		for _, f := range fs {
			if f.Collector != "" && !strings.HasPrefix(f.Collector, "builtin-") {
				t.Logf("found %s|%s|%s|%d", f.Collector, f.RuleID, f.File, f.StartLine)
			}
		}
	}
}
