package adapters

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
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

// Results in test code are skipped like in the built-in checks, and counted;
// scan.semgrep_include_tests keeps them for rules other than the bundled
// ones. The check uses the project-relative path, so a project that lives
// under a directory named fixture is still scanned.
func TestSemgrepSkipsTestPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixture", "app")
	abs := func(p string) string {
		b, _ := json.Marshal(filepath.Join(root, filepath.FromSlash(p)))
		return string(b)
	}
	raw := []byte(`{"results":[
	 {"check_id":"h.pandaward-semgrep-rules.pandaward-js-sql-string","path":` + abs("test/unit/a.test.ts") + `,"start":{"line":1},"end":{"line":1},"extra":{"severity":"ERROR","metadata":{"pandaward-control":"D-003"}}},
	 {"check_id":"h.pandaward-semgrep-rules.pandaward-js-sql-string","path":` + abs("src/db.ts") + `,"start":{"line":2},"end":{"line":2},"extra":{"severity":"ERROR","metadata":{"pandaward-control":"D-003"}}},
	 {"check_id":"local.no-raw-sql","path":` + abs("test/unit/a.test.ts") + `,"start":{"line":3},"end":{"line":3},"extra":{"severity":"WARNING","metadata":{}}}
	],"errors":[]}`)
	run := func(include bool) ([]string, string) {
		cfg := config.Default("fx")
		cfg.Scan.SemgrepIncludeTests = include
		tool := semgrep().(*externalTool)
		sigs, err := tool.normalize(&Context{Root: root, Cfg: cfg}, raw)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, s := range sigs {
			got = append(got, fmt.Sprintf("%s@%d", s.RuleID, s.StartLine))
		}
		return got, tool.note
	}
	got, note := run(false)
	if strings.Join(got, ",") != "semgrep.pandaward-js-sql-string@2" || note != "; 2 result(s) in test/fixture files skipped by policy" {
		t.Errorf("default: signals %v, note %q", got, note)
	}
	got, note = run(true)
	if strings.Join(got, ",") != "semgrep.pandaward-js-sql-string@2,semgrep.no-raw-sql@3" || note != "; 1 result(s) in test/fixture files skipped by policy" {
		t.Errorf("semgrep_include_tests: signals %v, note %q", got, note)
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

func TestGitleaksIgnoredLocalFile(t *testing.T) {
	root := t.TempDir()
	item := func(file string, line int) string {
		b, _ := json.Marshal(filepath.Join(root, filepath.FromSlash(file)))
		return fmt.Sprintf(`{"RuleID":"stripe-access-token","Description":"Found a Stripe Access Token.","StartLine":%d,"EndLine":%d,"Match":"REDACTED","File":%s}`, line, line, b)
	}
	raw := []byte("[" + item(".env.local", 1) + "," + item("src/config.ts", 2) + "," + item(".env.staged", 3) + "]")
	inv := &inventory.Inventory{Tracked: map[string]bool{"src/config.ts": true}, Ignored: []string{".env.local", "secrets/"}}
	sigs, err := gitleaks().(*externalTool).normalize(&Context{Root: root, Inv: inv}, raw)
	if err != nil {
		t.Fatal(err)
	}
	sev := map[int]model.Severity{}
	for _, s := range sigs {
		sev[s.StartLine] = s.Severity
	}
	// Ignored and untracked: listed only. Tracked, or untracked but not
	// ignored (it may be committed next): a real finding.
	if sev[1] != model.SevInfo || sev[2] != model.SevHigh || sev[3] != model.SevHigh {
		t.Fatalf("severities %v", sev)
	}
}

// Secret-shaped values in the tests below are assembled at run time, so the
// repository holds no literal that a secret scanner would flag.

func pseudoRandom(n int, seed uint32) string {
	const alpha = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, n)
	x := seed
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = alpha[(x>>16)%uint32(len(alpha))]
	}
	return string(b)
}

func fakeJWT(payload, sig string) string {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"HS256","typ":"JWT"}`) + "." + enc(payload) + "." + sig
}

func TestPlaceholderSecret(t *testing.T) {
	sk := "sk_" + "test_"
	fallback := pseudoRandom(30, 7)
	inExpr := "  KEY: ${{ secrets.ANON_KEY || '" + fallback + "' }}"
	cases := []struct {
		name, value, file, line string
		want                    bool
	}{
		{"sequential letters", sk + "51" + "abcdefghijklmnop", "a_test.go", "", true},
		{"sequential digits", "key" + "0123456789" + "Zq", "x.go", "", true},
		{"repeated", sk + strings.Repeat("x", 24), "x.go", "", true},
		{"placeholder word", "my" + "-placeholder-" + "value", "x.go", "", true},
		{"your prefix", "your" + "_api_key_here", "x.go", "", true},
		{"test_ prefix", "test" + "_api_secret_" + pseudoRandom(12, 1), "x_test.go", "", true},
		{"test- prefix", "test" + "-secrets-key-" + pseudoRandom(12, 8), "src/lib/ai/config.test.ts", "", true},
		{"test inside the value", "my" + "-test-" + pseudoRandom(16, 9), "src/config.ts", "", false},
		{"random 40", pseudoRandom(40, 2), "src/config.ts", "", false},
		{"random stripe test key", sk + "51" + pseudoRandom(24, 3), "x_test.go", "", false},
		{"jwt short signature", fakeJWT(`{"ref":"dummy","role":"anon"}`, "abcde"), "x.go", "", true},
		{"jwt dummy claim", fakeJWT(`{"iss":"dummy-issuer","role":"anon"}`, pseudoRandom(43, 4)), "x.go", "", true},
		{"jwt real", fakeJWT(`{"iss":"acme","role":"anon"}`, pseudoRandom(43, 5)), "x.go", "", false},
		{"service_role short sig", fakeJWT(`{"ref":"dummy","role":"service_role"}`, "abcde"), "x.go", "", false},
		{"service_role full sig", fakeJWT(`{"iss":"acme","role":"service_role"}`, pseudoRandom(43, 6)), "x.go", "", false},
		{"workflow fallback", fallback, ".github/workflows/ci.yml", inExpr, true},
		{"fallback outside workflows", fallback, "deploy/ci.yml", inExpr, false},
		{"workflow literal without secrets", fallback, ".github/workflows/ci.yml", "  KEY: '" + fallback + "'", false},
	}
	for _, tc := range cases {
		if got := placeholderSecret(tc.value, tc.file, tc.line); got != tc.want {
			t.Errorf("%s: placeholderSecret = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGitleaksPlaceholdersListedAsInfo(t *testing.T) {
	root := t.TempDir()
	sk := "sk_" + "test_"
	dummyJWT := fakeJWT(`{"iss":"supabase","ref":"dummy","role":"anon"}`, "abcde")
	serviceJWT := fakeJWT(`{"iss":"supabase","ref":"`+pseudoRandom(20, 8)+`","role":"service_role"}`, pseudoRandom(43, 9))
	random40 := pseudoRandom(40, 10)
	randomSK := sk + "51" + pseudoRandom(24, 11)
	seqSK := sk + "51" + "ABCDEFGHIJKLMNOPQRSTUVWX"
	generic := "test" + "_api_secret_" + pseudoRandom(16, 12)
	values := []string{dummyJWT, serviceJWT, random40, randomSK, seqSK, generic}

	files := map[string][]string{
		".github/workflows/ci.yml": {"env:", "  ANON: ${{ secrets.SUPABASE_ANON_KEY || '" + dummyJWT + "' }}"},
		"src/config.ts":            {"// config", `export const k = "` + random40 + `";`, `const s = "` + serviceJWT + `";`},
		"tests/pay_test.go":        {"package pay", `var real = "` + randomSK + `"`, `var seq = "` + seqSK + `"`, `api_secret := "` + generic + `"`},
	}
	for f, lines := range files {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var items []string
	// shift moves the columns one to the right, as gitleaks reports them on
	// some lines; the outcome must not change.
	add := func(rule, file string, line int, match string, shift int) {
		text := files[file][line-1]
		i := strings.Index(text, match)
		if i < 0 {
			t.Fatalf("match not in line %s:%d", file, line)
		}
		fb, _ := json.Marshal(filepath.Join(root, filepath.FromSlash(file)))
		items = append(items, fmt.Sprintf(`{"RuleID":%q,"Description":"d","StartLine":%d,"EndLine":%d,"StartColumn":%d,"EndColumn":%d,"Match":"REDACTED","Secret":"REDACTED","File":%s}`,
			rule, line, line, i+1+shift, i+len(match)+shift, fb))
	}
	add("jwt", ".github/workflows/ci.yml", 2, dummyJWT+"'", 0)
	add("generic-api-key", "src/config.ts", 2, `k = "`+random40+`"`, 0)
	add("jwt", "src/config.ts", 3, serviceJWT, 1)
	add("stripe-access-token", "tests/pay_test.go", 2, randomSK, 0)
	add("stripe-access-token", "tests/pay_test.go", 3, seqSK, 1)
	add("generic-api-key", "tests/pay_test.go", 4, `api_secret := "`+generic+`"`, 0)
	// A file that is gone and a path outside the root keep the signal as is.
	items = append(items, `{"RuleID":"jwt","Description":"d","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":10,"Match":"REDACTED","File":"gone.ts"}`)
	outside, _ := json.Marshal(filepath.Join(filepath.Dir(root), "elsewhere.ts"))
	items = append(items, `{"RuleID":"jwt","Description":"d","StartLine":1,"EndLine":1,"StartColumn":1,"EndColumn":10,"Match":"REDACTED","File":`+string(outside)+`}`)

	tool := gitleaks().(*externalTool)
	sigs, err := tool.normalize(&Context{Root: root}, []byte("["+strings.Join(items, ",")+"]"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 8 {
		t.Fatalf("got %d signals, want 8: nothing is dropped", len(sigs))
	}
	type key struct {
		file string
		line int
	}
	got := map[key]model.Signal{}
	for _, s := range sigs {
		got[key{relPath(root, s.File), s.StartLine}] = s
		for _, v := range values {
			for _, f := range []string{s.Title, s.Message, s.Fix, s.Snippet, s.Key, s.File} {
				if strings.Contains(f, v) {
					t.Fatal("a signal field holds the matched value")
				}
			}
		}
	}
	want := map[key]model.Severity{
		{".github/workflows/ci.yml", 2}: model.SevInfo,
		{"src/config.ts", 2}:            model.SevMedium,
		{"src/config.ts", 3}:            model.SevHigh,
		{"tests/pay_test.go", 2}:        model.SevLow,
		{"tests/pay_test.go", 3}:        model.SevInfo,
		{"tests/pay_test.go", 4}:        model.SevInfo,
		{"gone.ts", 1}:                  model.SevHigh,
		{"(outside-root)", 1}:           model.SevHigh,
	}
	for k, sev := range want {
		s, ok := got[k]
		if !ok {
			t.Errorf("%v: missing signal", k)
			continue
		}
		if s.Severity != sev {
			t.Errorf("%v: severity %s, want %s", k, s.Severity, sev)
		}
		if sev == model.SevInfo && (s.Confidence != model.Hypothesis || !strings.Contains(s.Title, "Placeholder-shaped")) {
			t.Errorf("%v: placeholder signal %+v", k, s)
		}
	}
	if tool.note != "; 3 placeholder-shaped value(s) listed as info" {
		t.Errorf("note = %q", tool.note)
	}
	for _, v := range values {
		if strings.Contains(tool.note, v) {
			t.Fatal("the note holds the matched value")
		}
	}
}

// Registry rules that rate themselves confidence LOW: audit hints are listed
// as info, vuln rules count as low at most. Nothing is dropped, and bundled
// rules and rules with higher confidence keep their severity.
func TestSemgrepLowConfidenceRegistryRules(t *testing.T) {
	root := t.TempDir()
	path, _ := json.Marshal(filepath.Join(root, "src", "a.ts"))
	res := func(id, sev, meta string, line int) string {
		return `{"check_id":"` + id + `","path":` + string(path) + `,"start":{"line":` + fmt.Sprint(line) + `},"end":{"line":` + fmt.Sprint(line) + `},"extra":{"severity":"` + sev + `","metadata":` + meta + `}}`
	}
	raw := []byte(`{"results":[` + strings.Join([]string{
		res("r.js.audit.spawn-shell-true", "ERROR", `{"confidence":"LOW","subcategory":["audit"]}`, 1),
		res("r.js.detect-non-literal-regexp", "WARNING", `{"confidence":"LOW","subcategory":["vuln"]}`, 2),
		res("r.js.gcm-no-tag-length", "ERROR", `{"confidence":"MEDIUM","subcategory":["vuln"]}`, 3),
		res("r.js.audit-string", "INFO", `{"confidence":"low","subcategory":"audit"}`, 4),
		res("h.pandaward-semgrep-rules.pandaward-js-sql-string", "ERROR", `{"pandaward-control":"D-003","confidence":"LOW","subcategory":["audit"]}`, 5),
	}, ",") + `],"errors":[]}`)
	tool := semgrep().(*externalTool)
	sigs, err := tool.normalize(&Context{Root: root, Cfg: config.Default("fx")}, raw)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range sigs {
		got = append(got, fmt.Sprintf("%s=%s", s.Title, s.Severity))
	}
	want := "spawn-shell-true=info,detect-non-literal-regexp=low,gcm-no-tag-length=high,audit-string=info,pandaward-js-sql-string=high"
	if strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
	if tool.note != "; 2 low-confidence audit result(s) listed as info" {
		t.Errorf("note %q", tool.note)
	}
}

// Gitleaks must not walk the directories inventory.exclude skips: a Rust
// target or node_modules directory could outlast the adapter timeout.
func TestGitleaksExcludeRegexes(t *testing.T) {
	res := excludePathRegexes([]string{"node_modules", ".next-*", "apps/web/out"})
	match := func(p string) bool {
		for _, r := range res {
			if regexp.MustCompile(r).MatchString(p) {
				return true
			}
		}
		return false
	}
	for _, p := range []string{`C:\w\repo\node_modules\a.js`, "/w/repo/src/node_modules/x/y.js", "node_modules/a.js", "/w/repo/.next-cache/a.js", `C:\w\repo\apps\web\out\a.js`} {
		if !match(p) {
			t.Errorf("%s should be excluded", p)
		}
	}
	for _, p := range []string{"/w/repo/src/node_modulesX/a.js", "/w/repo/src/node_modules.js", "/w/repo/.nextcache/a.js", "/w/repo/web/out/a.js"} {
		if match(p) {
			t.Errorf("%s should not be excluded", p)
		}
	}
}

func TestGitleaksConfigExtendsProjectConfig(t *testing.T) {
	root, run := t.TempDir(), t.TempDir()
	c := &Context{Root: root, RunDir: run, Cfg: config.Default("x")}
	p, err := gitleaksConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "useDefault = true") || !strings.Contains(string(b), "node_modules") {
		t.Fatalf("default config:\n%s", b)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitleaks.toml"), []byte("title = \"own\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _ = gitleaksConfig(c)
	b, _ = os.ReadFile(p)
	if strings.Contains(string(b), "useDefault") || !strings.Contains(string(b), filepath.Join(root, ".gitleaks.toml")) {
		t.Fatalf("project config not extended:\n%s", b)
	}
}

// With gitleaks installed, a secret in an excluded directory is never read.
func TestGitleaksSkipsExcludedDirs(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks not installed")
	}
	root := t.TempDir()
	token := "const k = 'gh" + "p_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'\n"
	for _, p := range []string{"src/a.js", "node_modules/pkg/b.js", "src-tauri/target/debug/c.js"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := &Context{Root: root, RunDir: t.TempDir(), ToolHome: t.TempDir(), Timeout: time.Minute, Cfg: config.Default("x"), Inv: &inventory.Inventory{Root: root}}
	res, run := gitleaks().Run(context.Background(), c)
	if run.ExitClass != model.ExitOK {
		t.Fatalf("gitleaks ended %s: %s", run.ExitClass, run.Detail)
	}
	var files []string
	for _, s := range res.Signals {
		files = append(files, filepath.ToSlash(relPath(root, s.File)))
	}
	if len(files) != 1 || files[0] != "src/a.js" {
		t.Fatalf("signals in %v, want only src/a.js", files)
	}
}
