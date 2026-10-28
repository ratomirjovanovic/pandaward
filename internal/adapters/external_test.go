package adapters

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

func TestSemgrepNormalizeMapsControlsAndStableIDs(t *testing.T) {
	raw := []byte(`{"results":[
	 {"check_id":"tmp.home.pandaward-semgrep-rules.pandaward-js-eval","path":"src/a.js","start":{"line":3},"end":{"line":3},
	  "extra":{"message":"eval","severity":"ERROR","lines":"eval(x)","metadata":{"cwe":"CWE-95: x","pandaward-control":"D-001"}}},
	 {"check_id":"custom.rule","path":"src/b.js","start":{"line":1},"end":{"line":1},
	  "extra":{"message":"m","severity":"WARNING","lines":"y","metadata":{"cwe":["CWE-918: SSRF"]}}},
	 {"check_id":"bad.mapping","path":"src/c.js","start":{"line":1},"end":{"line":1},
	  "extra":{"message":"m","severity":"INFO","lines":"z","metadata":{"pandaward-control":"R-001"}}}
	],"errors":[]}`)
	sigs, err := semgrep().(*externalTool).normalize(&Context{Root: "."}, raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ rule, control, cwe string }{
		{"semgrep.pandaward-js-eval", "D-001", "CWE-95"},
		{"semgrep.rule", "D-006", "CWE-918"},
		{"semgrep.mapping", "D-006", ""},
	}
	for i, w := range want {
		s := sigs[i]
		if s.RuleID != w.rule || s.ControlID != w.control || s.CWE != w.cwe || s.Confidence != model.Hypothesis {
			t.Errorf("signal %d: got %s %s %s %s", i, s.RuleID, s.ControlID, s.CWE, s.Confidence)
		}
	}
}

// The samples below are trimmed from real output of the versions pinned in
// the real-tools CI job (gitleaks 8.30.1, semgrep 1.182.0, osv-scanner
// 2.7.0, trivy 0.76.1); paths are shortened.

func TestSemgrepNormalizeDropsLoginPlaceholder(t *testing.T) {
	raw := []byte(`{"version":"1.182.0","results":[
	 {"check_id":"pandaward.private.tool-home.pandaward-semgrep-rules.pandaward-py-eval","path":"/w/fx/app.py",
	  "start":{"line":7,"col":5,"offset":180},"end":{"line":7,"col":49,"offset":224},
	  "extra":{"message":"Dynamic code evaluation.","metadata":{"pandaward-control":"D-001","cwe":"CWE-95: Eval Injection"},
	   "severity":"ERROR","fingerprint":"requires login","lines":"requires login","validation_state":"NO_VALIDATOR","engine_kind":"OSS"}}],
	 "errors":[],"paths":{"scanned":["/w/fx/app.py"]},"skipped_rules":[]}`)
	sigs, err := semgrep().(*externalTool).normalize(&Context{Root: "/w/fx"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 || sigs[0].RuleID != "semgrep.pandaward-py-eval" || sigs[0].ControlID != "D-001" || sigs[0].StartLine != 7 {
		t.Fatalf("unexpected signals %+v", sigs)
	}
	if sigs[0].Snippet != "" {
		t.Errorf("snippet = %q, want the login placeholder dropped", sigs[0].Snippet)
	}
}

func TestGitleaksNormalizeRealOutput(t *testing.T) {
	raw := []byte(`[{"RuleID":"stripe-access-token","Description":"Found a Stripe Access Token.","StartLine":1,"EndLine":1,
	 "StartColumn":23,"EndColumn":54,"Match":"REDACTED","Secret":"REDACTED","File":"/w/fx/.env","SymlinkFile":"","Commit":"",
	 "Entropy":2.248778,"Author":"","Email":"","Date":"","Message":"","Tags":[],"Fingerprint":"/w/fx/.env:stripe-access-token:1"}]`)
	sigs, err := gitleaks().(*externalTool).normalize(&Context{Root: "/w/fx"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 || sigs[0].RuleID != "gitleaks.stripe-access-token" || sigs[0].ControlID != "E-005" || sigs[0].StartLine != 1 || sigs[0].Snippet != "REDACTED" {
		t.Fatalf("unexpected signals %+v", sigs)
	}
}

func TestOSVNormalizeRealOutput(t *testing.T) {
	raw := []byte(`{"results":[{"source":{"path":"/w/fx/legacy/package-lock.json","type":"lockfile"},"packages":[{
	 "package":{"name":"lodash","version":"4.17.15","ecosystem":"npm","purl":"pkg:npm/lodash@4.17.15?source=PUBLIC_REGISTRY"},
	 "vulnerabilities":[
	  {"id":"GHSA-29mw-wpgm-hmr9","summary":"ReDoS in lodash","aliases":["CVE-2020-28500"],"schema_version":"1.7.3",
	   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],"database_specific":{"severity":"MODERATE"}},
	  {"id":"GHSA-35jh-r3h4-6jhm","summary":"Command Injection in lodash","aliases":["CVE-2021-23337"],
	   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],"database_specific":{"severity":"HIGH"}}],
	 "groups":[{"ids":["GHSA-29mw-wpgm-hmr9"],"aliases":["CVE-2020-28500","GHSA-29mw-wpgm-hmr9"],"max_severity":"5.3"},
	  {"ids":["GHSA-35jh-r3h4-6jhm"],"aliases":["CVE-2021-23337","GHSA-35jh-r3h4-6jhm"],"max_severity":"7.2"}]}]}],
	 "experimental_config":{"licenses":{"summary":false,"allowlist":null}}}`)
	sigs, err := osvScanner().(*externalTool).normalize(&Context{Root: "/w/fx"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("got %d signals, want 2", len(sigs))
	}
	if sigs[0].RuleID != "osv.GHSA-29mw-wpgm-hmr9" || sigs[0].Severity != model.SevMedium || sigs[1].Severity != model.SevHigh || sigs[1].Key != "lodash@4.17.15/GHSA-35jh-r3h4-6jhm" {
		t.Errorf("unexpected signals %+v", sigs)
	}
}

func TestTrivyNormalizeRealOutput(t *testing.T) {
	// trivy 0.76 no longer emits AVDID; whole-file checks carry no line, and
	// directory-level results without failures must not produce signals.
	raw := []byte(`{"SchemaVersion":2,"Trivy":{"Version":"0.76.1"},"ArtifactName":"/w/fx","ArtifactType":"repository","Results":[
	 {"Target":"Dockerfile","Class":"config","Type":"dockerfile","MisconfSummary":{"Successes":24,"Failures":2},"Misconfigurations":[
	  {"Type":"Dockerfile Security Check","ID":"DS-0001","Title":"':latest' tag used","Message":"Specify a tag in the 'FROM' statement for image 'node'",
	   "Namespace":"builtin.dockerfile.DS001","Resolution":"Add a tag to the image in the 'FROM' statement","Severity":"MEDIUM","Status":"FAIL",
	   "CauseMetadata":{"Provider":"Dockerfile","Service":"general","StartLine":1,"EndLine":1}},
	  {"Type":"Dockerfile Security Check","ID":"DS-0002","Title":"Image user should not be 'root'","Message":"Specify at least 1 USER command in Dockerfile with non-root user as argument",
	   "Resolution":"Add 'USER <non root user name>' line to the Dockerfile","Severity":"HIGH","Status":"FAIL","CauseMetadata":{"Provider":"Dockerfile","Service":"general"}}]},
	 {"Target":"infra","Class":"config","Type":"terraform","MisconfSummary":{"Successes":69,"Failures":0}}]}`)
	sigs, err := trivy().(*externalTool).normalize(&Context{Root: "/w/fx"}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 || sigs[0].RuleID != "trivy.DS-0001" || sigs[0].StartLine != 1 || sigs[0].File != "Dockerfile" ||
		sigs[1].RuleID != "trivy.DS-0002" || sigs[1].Severity != model.SevHigh || sigs[1].StartLine != 0 {
		t.Errorf("unexpected signals %+v", sigs)
	}
}

// TestFakeTool is a helper, not a test: TestOSVNoPackagesIsUnsupported runs
// the test binary as a stand-in tool that exits with the code after "--".
func TestFakeTool(t *testing.T) {
	if flag.NArg() != 1 {
		t.Skip("helper process only")
	}
	code, _ := strconv.Atoi(flag.Arg(0))
	fmt.Fprintln(os.Stderr, "Warning: --output has been deprecated in favor of --output-file")
	os.Exit(code)
}

func TestOSVNoPackagesIsUnsupported(t *testing.T) {
	tool := osvScanner().(*externalTool)
	tool.binary = os.Args[0]
	tool.verArgs = []string{"-test.run=^TestFakeTool$", "--", "0"}
	tool.args = func(*Context, string) ([]string, error) {
		return []string{"-test.run=^TestFakeTool$", "--", "128"}, nil
	}
	cfg := config.Default("x")
	cfg.Scan.AllowToolNetwork = true
	dir := t.TempDir()
	_, run := tool.Run(context.Background(), &Context{Root: dir, Cfg: cfg, RunDir: dir, ToolHome: filepath.Join(dir, "home"), Timeout: time.Minute})
	if run.ExitClass != model.ExitUnsupported || !strings.Contains(run.Detail, "no lockfile") {
		t.Errorf("exit 128 gave %s %q, want UNSUPPORTED with the reason", run.ExitClass, run.Detail)
	}
}
