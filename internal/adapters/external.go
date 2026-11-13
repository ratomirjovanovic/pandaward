package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/rules"
)

// externalTool wraps a user-installed scanner binary. PandaWard never installs
// or downloads tools itself. Tools run with an argument array (no shell), a
// scrubbed environment (no cloud/VCS tokens), a disposable HOME, a timeout,
// and their stdout/stderr kept apart from evidence.
type externalTool struct {
	name     string
	binary   string
	controls []string
	network  bool   // tool needs network (advisory DB / rule download)
	sends    string // what leaves the machine when network is allowed
	verArgs  []string
	args     func(c *Context, out string) ([]string, error)
	// okExit lists exit codes that mean "ran successfully".
	okExit map[int]bool
	// noInput maps exit codes that mean "nothing this tool can read" to
	// the reason reported; the run is UNSUPPORTED rather than an error.
	noInput   map[int]string
	normalize func(c *Context, raw []byte) ([]model.Signal, error)
	// note, set by normalize, is added to the run detail.
	note string
	// alts are other binaries that run the same rules and output format
	// (opengrep for semgrep), tried after binary.
	alts []string
	// choose returns the one binary the project configured, or "" for
	// binary and then alts. It is read at the start of a run.
	choose func(c *Context) string
	// prefer is the configured binary for this run; found is the binary
	// Lookup resolved last.
	prefer, found string
}

func (t *externalTool) Name() string       { return t.name }
func (t *externalTool) Controls() []string { return t.controls }
func (t *externalTool) Maturity() string   { return MaturityUnvalidated }
func (t *externalTool) Network() bool      { return t.network }

// Lookup returns the absolute path of the tool binary or an error. A tool
// with alternative engines resolves the configured one, or the first
// installed one.
func (t *externalTool) Lookup() (string, error) {
	names := append([]string{t.binary}, t.alts...)
	if t.prefer != "" {
		names = []string{t.prefer}
	}
	var first error
	for _, n := range names {
		p, err := exec.LookPath(n)
		if err == nil {
			t.found = n
			return p, nil
		}
		if first == nil {
			first = err
		}
	}
	t.found = ""
	return "", first
}

// engine names the binary that runs, for messages: the alternative engine
// when one was resolved, else the tool name.
func (t *externalTool) engine() string {
	if t.found != "" && t.found != t.binary {
		return t.found
	}
	return t.name
}

// binaries names what Lookup looks for, for messages.
func (t *externalTool) binaries() string {
	if t.prefer != "" {
		return t.prefer
	}
	return strings.Join(append([]string{t.binary}, t.alts...), " or ")
}

// Version returns the tool version string, or "" when unavailable.
func (t *externalTool) Version(ctx context.Context) string {
	bin, err := t.Lookup()
	if err != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, t.verArgs...)
	// Without quietEnv semgrep checks for updates over the network and
	// prints the notice, after a blank line, before its version.
	cmd.Env = append(inventory.MinimalEnv(), quietEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	v := firstLine(string(out))
	// An alternative engine has its own version numbers; name it so a
	// version is never read as the main tool's.
	if t.found != "" && t.found != t.binary && !strings.HasPrefix(v, t.found) {
		v = t.found + " " + v
	}
	return v
}

// quietEnv turns off update checks, telemetry, progress bars and colors.
var quietEnv = []string{"SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0", "TRIVY_NO_PROGRESS=true", "DO_NOT_TRACK=1", "NO_COLOR=1"}

// toolEnv builds the scrubbed tool environment. tmp is a short per-run temp
// directory: semgrep-core on Windows fails when TEMP is a long path, so the
// temp directory is kept apart from the (possibly deep) tool home.
func toolEnv(c *Context, tmp string) []string {
	env := inventory.MinimalEnv()
	var out []string
	for _, kv := range env {
		k := strings.SplitN(kv, "=", 2)[0]
		switch strings.ToUpper(k) {
		case "HOME", "USERPROFILE", "TEMP", "TMP", "TMPDIR":
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "HOME="+c.ToolHome, "USERPROFILE="+c.ToolHome, "TEMP="+tmp, "TMP="+tmp, "TMPDIR="+tmp)
	if runtime.GOOS == "windows" {
		// Opengrep unpacks itself into LOCALAPPDATA and exits with a fail-fast
		// crash (0xC0000409) when that directory does not exist. Both point
		// into the tool home, like HOME, and are created here.
		local, roaming := filepath.Join(c.ToolHome, "AppData", "Local"), filepath.Join(c.ToolHome, "AppData", "Roaming")
		_ = os.MkdirAll(local, 0o700)
		_ = os.MkdirAll(roaming, 0o700)
		out = append(out, "LOCALAPPDATA="+local, "APPDATA="+roaming)
	}
	return append(out, quietEnv...)
}

func (t *externalTool) Run(ctx context.Context, c *Context) (Result, model.Run) {
	res := Result{Decisions: map[string]Decision{}}
	if t.choose != nil {
		t.prefer = t.choose(c)
	}
	bin, err := t.Lookup()
	if err != nil {
		run := newRun(t.name, "")
		return res, finish(run, model.ExitBlocked, t.binaries()+" is not installed (optional; run `pandaward doctor`)", 0)
	}
	run := newRun(t.name, t.Version(ctx))
	if t.network && !c.Cfg.Scan.AllowToolNetwork {
		return res, finish(run, model.ExitBlocked, t.name+" needs network access: it "+t.sends+". Set scan.allow_tool_network: true in .pandaward/config.yaml to allow it; no project target is contacted", 0)
	}
	out := filepath.Join(c.RunDir, t.name+".json")
	args, err := t.args(c, out)
	if err != nil {
		return res, finish(run, model.ExitBlocked, err.Error(), 0)
	}
	if err := os.MkdirAll(c.ToolHome, 0o700); err != nil {
		return res, finish(run, model.ExitError, err.Error(), 0)
	}
	tmp, err := os.MkdirTemp("", "pandaward-")
	if err != nil {
		return res, finish(run, model.ExitError, err.Error(), 0)
	}
	defer os.RemoveAll(tmp)
	cctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Dir = c.Root
	cmd.Env = toolEnv(c, tmp)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedBuffer{b: &stdout, max: 64 << 20}
	cmd.Stderr = &limitedBuffer{b: &stderr, max: 1 << 20}
	err = cmd.Run()
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return res, finish(run, model.ExitTimeout, fmt.Sprintf("%s exceeded %s", t.engine(), c.Timeout), 0)
	}
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			return res, finish(run, model.ExitError, err.Error(), 0)
		}
	}
	_ = os.WriteFile(filepath.Join(c.RunDir, t.name+".stderr.txt"), []byte(redact.Text(stderr.String())), 0o600)
	if why, ok := t.noInput[code]; ok {
		return res, finish(run, model.ExitUnsupported, why, 0)
	}
	if !t.okExit[code] {
		why := firstLine(stderr.String())
		if why == "" {
			why = "no error output; run " + t.engine() + " manually in the project to see the cause"
		}
		return res, finish(run, model.ExitError, fmt.Sprintf("%s exited %d: %s", t.engine(), code, why), 0)
	}
	raw, rerr := os.ReadFile(out)
	if rerr != nil || len(bytes.TrimSpace(raw)) == 0 {
		raw = stdout.Bytes()
	}
	t.note = ""
	sigs, err := t.normalize(c, raw)
	if err != nil {
		return res, finish(run, model.ExitError, "could not parse "+t.name+" output: "+err.Error(), 0)
	}
	for i := range sigs {
		sigs[i].Collector = t.name
		sigs[i].Snippet = redact.Line(sigs[i].Snippet)
		sigs[i].Message = redact.Line(sigs[i].Message)
		sigs[i].Title = redact.Line(sigs[i].Title)
		sigs[i].File = relPath(c.Root, sigs[i].File)
	}
	res.Signals = sigs
	return res, finish(run, model.ExitOK, fmt.Sprintf("exit %d", code)+t.note, len(sigs))
}

type limitedBuffer struct {
	b   *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.b.Len()+len(p) > l.max {
		return 0, errors.New("tool output exceeded limit")
	}
	return l.b.Write(p)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return redact.Line(s)
}

// relPath makes tool-reported paths relative to the project root and
// rejects anything that points outside it.
func relPath(root, p string) string {
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	r, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(r, "..") {
		return "(outside-root)"
	}
	return filepath.ToSlash(r)
}

func sevFrom(s string) model.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return model.SevCritical
	case "high", "error":
		return model.SevHigh
	case "medium", "moderate", "warning":
		return model.SevMedium
	case "low", "info", "note":
		return model.SevLow
	}
	return model.SevMedium
}

func gitleaks() Adapter {
	// normalize records a note on t, so t exists before its fields.
	t := &externalTool{}
	*t = externalTool{
		name: "gitleaks", binary: "gitleaks", controls: []string{"E-005"}, verArgs: []string{"version"},
		okExit: map[int]bool{0: true},
		args: func(c *Context, out string) ([]string, error) {
			args := []string{"detect", "--no-git", "--source", c.Root, "--redact", "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", out}
			cfg, err := gitleaksConfig(c)
			if err != nil {
				return nil, err
			}
			return append(args, "--config", cfg), nil
		},
		normalize: func(c *Context, raw []byte) ([]model.Signal, error) {
			var items []struct {
				RuleID      string `json:"RuleID"`
				Description string `json:"Description"`
				File        string `json:"File"`
				StartLine   int    `json:"StartLine"`
				EndLine     int    `json:"EndLine"`
				StartColumn int    `json:"StartColumn"`
				EndColumn   int    `json:"EndColumn"`
				Match       string `json:"Match"`
				Fingerprint string `json:"Fingerprint"`
			}
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, err
			}
			var out []model.Signal
			placeholders := 0
			for _, it := range items {
				// Specific formats are strong signals. Generic rules match on
				// entropy, and test fixtures hold fake values in real formats,
				// so those are hypotheses; they are still reported.
				sev, conf := model.SevHigh, model.StronglySupported
				if strings.HasPrefix(it.RuleID, "generic") {
					sev, conf = model.SevMedium, model.Hypothesis
				}
				rel := relPath(c.Root, it.File)
				if IsTestPath(rel) {
					sev, conf = model.SevLow, model.Hypothesis
				}
				title, msg, fix := "Secret detected: "+it.Description, "Gitleaks rule "+it.RuleID+" matched (value redacted by gitleaks and PandaWard).", "Rotate the credential, remove it from code and history, load it at runtime from a secret manager."
				// A file git ignores and does not track is where local
				// secrets belong; it is listed, not counted against E-005.
				if c.Inv.IgnoredLocal(rel) {
					sev, conf = model.SevInfo, model.Hypothesis
					title = "Secret in an untracked, git-ignored local file: " + it.Description
					msg += " The file is ignored by git and not tracked, so it is not in the repository."
					fix = "Nothing to do while the file stays ignored and untracked. Rotate the credential if the file was ever committed or shared."
				} else if placeholderHit(c.Root, rel, it.RuleID, it.StartLine, it.EndLine, it.StartColumn, it.EndColumn) {
					// A placeholder in one project can be a live value in
					// another, so it is listed for review, never dropped.
					placeholders++
					sev, conf = model.SevInfo, model.Hypothesis
					title = "Placeholder-shaped value matched a secret rule: " + it.Description
					msg += " The value is shaped like a placeholder (sequential or repeated characters, a placeholder word, a dummy JWT or a workflow secrets fallback), so it is listed for review and not counted against E-005."
					fix = "Confirm the value is not a real credential. If it is real, rotate it and load it at runtime from a secret manager."
				}
				out = append(out, model.Signal{RuleID: "gitleaks." + it.RuleID, ControlID: "E-005", Title: title, Severity: sev, Confidence: conf, CWE: "CWE-798",
					File: it.File, StartLine: it.StartLine, EndLine: it.EndLine, Snippet: it.Match, Message: msg, Fix: fix, Key: it.RuleID})
			}
			if placeholders > 0 {
				t.note = fmt.Sprintf("; %d placeholder-shaped value(s) listed as info", placeholders)
			}
			return out, nil
		},
	}
	return t
}

// gitleaksConfig writes a gitleaks config into the run directory that
// extends the project's own .gitleaks.toml (or the default rules) and
// allowlists the directories inventory.exclude skips. Gitleaks then does not
// walk node_modules, target or .next at all: those signals were dropped
// anyway, and a Rust or Node build directory could take longer than the
// adapter timeout to read.
func gitleaksConfig(c *Context) (string, error) {
	var b strings.Builder
	b.WriteString("[extend]\n")
	if own := filepath.Join(c.Root, ".gitleaks.toml"); regularFile(own) {
		b.WriteString("path = '''" + own + "'''\n")
	} else {
		b.WriteString("useDefault = true\n")
	}
	b.WriteString("\n[allowlist]\ndescription = \"PandaWard inventory.exclude\"\npaths = [\n")
	var exclude []string
	if c.Cfg != nil {
		exclude = c.Cfg.Inventory.Exclude
	}
	for _, re := range excludePathRegexes(exclude) {
		b.WriteString("  '''" + re + "''',\n")
	}
	b.WriteString("]\n")
	p := filepath.Join(c.RunDir, "gitleaks.toml")
	return p, os.WriteFile(p, []byte(b.String()), 0o600)
}

// excludePathRegexes turns inventory.exclude entries into path regexes
// with the same meaning as the inventory walk: a plain name matches a
// directory of that name anywhere, an entry with a slash matches that
// directory path, and * or ? in an entry match within one name. Separators
// may be / or \, since gitleaks reports OS paths.
func excludePathRegexes(exclude []string) []string {
	const sep = `[\\/]`
	var out []string
	for _, e := range exclude {
		e = strings.Trim(filepath.ToSlash(e), "/")
		if e == "" || strings.Contains(e, "'''") {
			continue
		}
		var parts []string
		for _, seg := range strings.Split(e, "/") {
			var r strings.Builder
			for _, ch := range seg {
				switch ch {
				case '*':
					r.WriteString(`[^\\/]*`)
				case '?':
					r.WriteString(`[^\\/]`)
				default:
					r.WriteString(regexp.QuoteMeta(string(ch)))
				}
			}
			parts = append(parts, r.String())
		}
		out = append(out, `(^|`+sep+`)`+strings.Join(parts, sep)+sep)
	}
	return out
}

func regularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// placeholderHit re-reads a single-line gitleaks match and reports whether
// the value is placeholder-shaped. Private keys are not judged: their
// encoding legitimately holds long runs of repeated characters.
func placeholderHit(root, rel, rule string, startLine, endLine, startCol, endCol int) bool {
	if startLine != endLine || strings.Contains(rule, "private-key") {
		return false
	}
	value, line, ok := matchedValue(root, rel, startLine, startCol, endCol)
	return ok && placeholderSecret(value, rel, line)
}

func semgrep() Adapter {
	// normalize records a note on t, so t exists before its fields.
	t := &externalTool{}
	*t = externalTool{
		name: "semgrep", binary: "semgrep", alts: []string{"opengrep"}, controls: []string{"D-006"}, verArgs: []string{"--version"},
		okExit: map[int]bool{0: true, 1: true},
		choose: func(c *Context) string {
			if c.Cfg == nil {
				return ""
			}
			return c.Cfg.Scan.SemgrepEngine
		},
		args: func(c *Context, out string) ([]string, error) {
			// The bundled rules always run; they are local and need no network.
			bundled, err := rules.WriteSemgrep(filepath.Join(c.ToolHome, "pandaward-semgrep-rules"))
			if err != nil {
				return nil, err
			}
			args := []string{"scan", "--config", bundled}
			cfg := c.Cfg.Scan.SemgrepConfig
			if cfg == "" {
				local := filepath.Join(c.Root, ".pandaward", "semgrep")
				if st, err := os.Stat(local); err == nil && st.IsDir() {
					cfg = local
				}
			}
			if cfg != "" {
				remote := strings.HasPrefix(cfg, "p/") || strings.HasPrefix(cfg, "r/") || cfg == "auto" || strings.HasPrefix(cfg, "http")
				if remote && !c.Cfg.Scan.AllowToolNetwork {
					return nil, errors.New("semgrep config " + cfg + " is downloaded from the registry; set scan.allow_tool_network: true or use local rules")
				}
				if cfg == "auto" {
					return nil, errors.New("semgrep --config auto sends project metadata to the registry; choose an explicit pack")
				}
				args = append(args, "--config", cfg)
			}
			args = append(args, "--json", "--output", out, "--disable-version-check", "--quiet", "--timeout", "30")
			if t.found == "opengrep" {
				// Opengrep sends no metrics and has no --metrics flag; it
				// follows taint through functions in the same file.
				args = append(args, "--taint-intrafile")
			} else {
				args = append(args, "--metrics=off")
			}
			return append(args, c.Root), nil
		},
		normalize: func(c *Context, raw []byte) ([]model.Signal, error) {
			var doc struct {
				Results []struct {
					CheckID string             `json:"check_id"`
					Path    string             `json:"path"`
					Start   struct{ Line int } `json:"start"`
					End     struct{ Line int } `json:"end"`
					Extra   struct {
						Message  string `json:"message"`
						Severity string `json:"severity"`
						Lines    string `json:"lines"`
						Metadata struct {
							CWE         any    `json:"cwe"`
							Control     string `json:"pandaward-control"`
							Confidence  string `json:"confidence"`
							Subcategory any    `json:"subcategory"`
						} `json:"metadata"`
					} `json:"extra"`
				} `json:"results"`
				Errors []any `json:"errors"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, err
			}
			var out []model.Signal
			skipped, audit, proven := 0, 0, 0
			for _, r := range doc.Results {
				// Results in test and fixture code are skipped, as in the
				// built-in checks: registry rules match the fake keys and
				// patterns tests are full of. scan.semgrep_include_tests keeps
				// them for rules other than the bundled ones. The path is made
				// relative first, so a project that itself lives under a test
				// or fixture directory is not skipped whole.
				if IsTestPath(relPath(c.Root, r.Path)) {
					if bundled := strings.HasPrefix(lastSegment(r.CheckID), "pandaward-"); bundled || c.Cfg == nil || !c.Cfg.Scan.SemgrepIncludeTests {
						skipped++
						continue
					}
				}
				// The built-in check proves some raw HTML assignments safe
				// (escaped or constant markup); the bundled semgrep rule
				// cannot see that, so the same proof applies to its results.
				if lastSegment(r.CheckID) == "pandaward-js-html-sink" && semgrepHTMLSinkProven(c, filepath.ToSlash(relPath(c.Root, r.Path)), r.Start.Line) {
					proven++
					continue
				}
				// Registry rules rate their own precision. A low-confidence
				// audit rule only points at code worth a look: it is listed as
				// info and does not decide the control. A low-confidence vuln
				// rule still counts, as low at most. Nothing is dropped, since a
				// hint that is noise in one project can be real in another.
				sev := sevFrom(r.Extra.Severity)
				if !strings.HasPrefix(lastSegment(r.CheckID), "pandaward-") && strings.EqualFold(r.Extra.Metadata.Confidence, "low") {
					switch {
					case hasValue(r.Extra.Metadata.Subcategory, "audit"):
						sev = model.SevInfo
						audit++
					case model.SeverityRank(sev) > model.SeverityRank(model.SevLow):
						sev = model.SevLow
					}
				}
				cwe := ""
				switch v := r.Extra.Metadata.CWE.(type) {
				case string:
					cwe = cweRe.FindString(v)
				case []any:
					if len(v) > 0 {
						cwe = cweRe.FindString(fmt.Sprint(v[0]))
					}
				}
				// Bundled rules name a specific control; the engine raises that
				// control's status, never lowers it. Other rules count for D-006.
				cid := "D-006"
				if ctl := catalog.ControlByID(r.Extra.Metadata.Control); ctl != nil && ctl.Domain != "R" {
					cid = ctl.ID
				}
				// Semgrep without a login replaces the matched source with this
				// placeholder; it is not a snippet.
				snippet := r.Extra.Lines
				if strings.TrimSpace(snippet) == "requires login" {
					snippet = ""
				}
				// check_id is prefixed with the rule file's directory, which
				// differs per machine; keep only the rule id for stable fingerprints.
				out = append(out, model.Signal{RuleID: "semgrep." + lastSegment(r.CheckID), ControlID: cid, Title: lastSegment(r.CheckID), Severity: sev, Confidence: model.Hypothesis, CWE: cwe,
					File: r.Path, StartLine: r.Start.Line, EndLine: r.End.Line, Snippet: snippet, Message: r.Extra.Message, Fix: "See rule " + lastSegment(r.CheckID) + " guidance."})
			}
			t.note = ""
			if skipped > 0 {
				t.note = fmt.Sprintf("; %d result(s) in test/fixture files skipped by policy", skipped)
			}
			if audit > 0 {
				t.note += fmt.Sprintf("; %d low-confidence audit result(s) listed as info", audit)
			}
			if proven > 0 {
				t.note += fmt.Sprintf("; %d raw HTML result(s) proven to write only escaped or constant markup", proven)
			}
			return out, nil
		},
	}
	return t
}

var cweRe = regexp.MustCompile(`CWE-\d+`)

func lastSegment(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

func osvScanner() Adapter {
	// normalize records a note on t, so t exists before its fields.
	t := &externalTool{}
	*t = externalTool{
		name: "osv-scanner", binary: "osv-scanner", controls: []string{"I-003"}, network: true, sends: "sends the package names and versions from your lockfiles to api.osv.dev to look up advisories", verArgs: []string{"--version"},
		okExit:  map[int]bool{0: true, 1: true},
		noInput: map[int]string{128: "osv-scanner found no lockfile or SBOM it can read (exit 128); commit a lockfile to check dependencies against advisories"},
		args: func(c *Context, out string) ([]string, error) {
			return []string{"--format", "json", "--output", out, "-r", c.Root}, nil
		},
		normalize: func(c *Context, raw []byte) ([]model.Signal, error) {
			var doc struct {
				Results []struct {
					Source struct {
						Path string `json:"path"`
					} `json:"source"`
					Packages []struct {
						Package struct {
							Name      string `json:"name"`
							Version   string `json:"version"`
							Ecosystem string `json:"ecosystem"`
						} `json:"package"`
						Vulnerabilities []struct {
							ID       string   `json:"id"`
							Summary  string   `json:"summary"`
							Aliases  []string `json:"aliases"`
							Severity []struct {
								Type  string `json:"type"`
								Score string `json:"score"`
							} `json:"severity"`
							DatabaseSpecific struct {
								Severity string `json:"severity"`
							} `json:"database_specific"`
						} `json:"vulnerabilities"`
					} `json:"packages"`
				} `json:"results"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, err
			}
			var out []model.Signal
			var dropped, kept []string
			nDropped, nKept := 0, 0
			overrides := map[string][]override{}
			for _, r := range doc.Results {
				// Overrides live in the workspace root, next to the lockfile.
				lock := relPath(c.Root, r.Source.Path)
				lockDir := path.Dir(lock)
				ovs, ok := overrides[lockDir]
				if !ok && lock != "(outside-root)" && lock != "" {
					ovs = readOverrides(c.Root, lockDir)
					overrides[lockDir] = ovs
				}
				for _, p := range r.Packages {
					if len(p.Vulnerabilities) > 0 {
						drop, keep := overrideVerdict(c.Root, lockDir, p.Package.Name, p.Package.Version, ovs)
						if drop != nil {
							nDropped += len(p.Vulnerabilities)
							dropped = appendOnce(dropped, fmt.Sprintf("%s %s in %s", drop.key, drop.value, drop.file))
							continue
						}
						if keep != nil {
							nKept += len(p.Vulnerabilities)
							kept = appendOnce(kept, fmt.Sprintf("%s %s (override %s %s in %s)", p.Package.Name, p.Package.Version, keep.key, keep.value, keep.file))
						}
					}
					for _, v := range p.Vulnerabilities {
						sev := sevFrom(v.DatabaseSpecific.Severity)
						out = append(out, model.Signal{RuleID: "osv." + v.ID, ControlID: "I-003", Title: fmt.Sprintf("%s %s: %s", p.Package.Name, p.Package.Version, v.ID), Severity: sev, Confidence: model.StronglySupported, CWE: "CWE-1395",
							File: r.Source.Path, Message: v.Summary + " (advisory presence does not prove the vulnerable code path is reachable)",
							Fix: "Upgrade " + p.Package.Name + " to a fixed version listed in " + v.ID + "; check the advisory for workarounds.", Key: p.Package.Name + "@" + p.Package.Version + "/" + v.ID})
					}
				}
			}
			t.note = ""
			if nDropped > 0 {
				t.note = fmt.Sprintf("; %d result(s) dropped for packages an override replaces with a local package (%s)", nDropped, redact.Line(strings.Join(dropped, "; ")))
			}
			if nKept > 0 {
				t.note += fmt.Sprintf("; %d result(s) kept although an override names the package, because the lockfile lists a registry version or another local package, or the override is an npm: alias: %s", nKept, redact.Line(strings.Join(kept, "; ")))
			}
			return out, nil
		},
	}
	return t
}

func appendOnce(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

func trivy() Adapter {
	return &externalTool{
		name: "trivy", binary: "trivy", controls: []string{"J-005"}, network: true, sends: "downloads its vulnerability database and sends nothing about the project", verArgs: []string{"--version"},
		okExit: map[int]bool{0: true},
		args: func(c *Context, out string) ([]string, error) {
			return []string{"config", "--format", "json", "--output", out, "--exit-code", "0", "--quiet", c.Root}, nil
		},
		normalize: func(c *Context, raw []byte) ([]model.Signal, error) {
			var doc struct {
				Results []struct {
					Target            string `json:"Target"`
					Misconfigurations []struct {
						ID            string `json:"ID"`
						AVDID         string `json:"AVDID"`
						Title         string `json:"Title"`
						Message       string `json:"Message"`
						Resolution    string `json:"Resolution"`
						Severity      string `json:"Severity"`
						Status        string `json:"Status"`
						CauseMetadata struct {
							StartLine int `json:"StartLine"`
							EndLine   int `json:"EndLine"`
						} `json:"CauseMetadata"`
					} `json:"Misconfigurations"`
				} `json:"Results"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, err
			}
			var out []model.Signal
			for _, r := range doc.Results {
				for _, m := range r.Misconfigurations {
					if m.Status == "PASS" {
						continue
					}
					out = append(out, model.Signal{RuleID: "trivy." + m.ID, ControlID: "J-005", Title: m.Title, Severity: sevFrom(m.Severity), Confidence: model.StronglySupported,
						File: r.Target, StartLine: m.CauseMetadata.StartLine, EndLine: m.CauseMetadata.EndLine, Message: m.Message, Fix: m.Resolution})
				}
			}
			return out, nil
		},
	}
}

// ExternalTools returns the external adapters for doctor output.
func ExternalTools() []*externalTool {
	var out []*externalTool
	for _, a := range Registry() {
		if t, ok := a.(*externalTool); ok {
			out = append(out, t)
		}
	}
	return out
}

// ToolInfo is a doctor row.
type ToolInfo struct {
	Name    string `json:"name"`
	Binary  string `json:"binary"`
	Path    string `json:"path"`
	Version string `json:"version"`
	Network bool   `json:"needs_network"`
}

// Tools reports installed optional tools.
func Tools(ctx context.Context) []ToolInfo {
	var out []ToolInfo
	for _, t := range ExternalTools() {
		ti := ToolInfo{Name: t.name, Binary: t.binaries(), Network: t.network}
		if p, err := t.Lookup(); err == nil {
			ti.Path = p
			ti.Version = t.Version(ctx)
		}
		out = append(out, ti)
	}
	ti := ToolInfo{Name: "apktool", Binary: "apktool"}
	if p, err := (apktoolAdapter{}).lookup(); err == nil {
		ti.Path, ti.Version = p, (apktoolAdapter{}).version(ctx, p)
	}
	return append(out, ti)
}

// hasValue reports whether a metadata field, a string or a list of strings,
// holds v.
func hasValue(field any, v string) bool {
	switch x := field.(type) {
	case string:
		return strings.EqualFold(x, v)
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && strings.EqualFold(s, v) {
				return true
			}
		}
	}
	return false
}
