package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pensec/internal/catalog"
	"github.com/ratomirjovanovic/pensec/internal/inventory"
	"github.com/ratomirjovanovic/pensec/internal/model"
	"github.com/ratomirjovanovic/pensec/internal/redact"
	"github.com/ratomirjovanovic/pensec/rules"
)

// externalTool wraps a user-installed scanner binary. PenSec never installs
// or downloads tools itself. Tools run with an argument array (no shell), a
// scrubbed environment (no cloud/VCS tokens), a disposable HOME, a timeout,
// and their stdout/stderr kept apart from evidence.
type externalTool struct {
	name     string
	binary   string
	controls []string
	network  bool // tool needs network (advisory DB / rule download)
	verArgs  []string
	args     func(c *Context, out string) ([]string, error)
	// okExit lists exit codes that mean "ran successfully".
	okExit map[int]bool
	// noInput maps exit codes that mean "nothing this tool can read" to
	// the reason reported; the run is UNSUPPORTED rather than an error.
	noInput   map[int]string
	normalize func(c *Context, raw []byte) ([]model.Signal, error)
}

func (t *externalTool) Name() string       { return t.name }
func (t *externalTool) Controls() []string { return t.controls }
func (t *externalTool) Maturity() string   { return MaturityUnvalidated }
func (t *externalTool) Network() bool      { return t.network }

// Lookup returns the absolute path of the tool binary or an error.
func (t *externalTool) Lookup() (string, error) { return exec.LookPath(t.binary) }

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
	return firstLine(string(out))
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
	return append(out, quietEnv...)
}

func (t *externalTool) Run(ctx context.Context, c *Context) (Result, model.Run) {
	res := Result{Decisions: map[string]Decision{}}
	bin, err := t.Lookup()
	if err != nil {
		run := newRun(t.name, "")
		return res, finish(run, model.ExitBlocked, t.binary+" is not installed (optional; run `pensec doctor`)", 0)
	}
	run := newRun(t.name, t.Version(ctx))
	if t.network && !c.Cfg.Scan.AllowToolNetwork {
		return res, finish(run, model.ExitBlocked, t.name+" needs network access for its advisory database or rules; set scan.allow_tool_network: true to permit it (no target is contacted)", 0)
	}
	out := filepath.Join(c.RunDir, t.name+".json")
	args, err := t.args(c, out)
	if err != nil {
		return res, finish(run, model.ExitBlocked, err.Error(), 0)
	}
	if err := os.MkdirAll(c.ToolHome, 0o700); err != nil {
		return res, finish(run, model.ExitError, err.Error(), 0)
	}
	tmp, err := os.MkdirTemp("", "pensec-")
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
		return res, finish(run, model.ExitTimeout, fmt.Sprintf("%s exceeded %s", t.name, c.Timeout), 0)
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
			why = "no error output; run " + t.binary + " manually in the project to see the cause"
		}
		return res, finish(run, model.ExitError, fmt.Sprintf("%s exited %d: %s", t.name, code, why), 0)
	}
	raw, rerr := os.ReadFile(out)
	if rerr != nil || len(bytes.TrimSpace(raw)) == 0 {
		raw = stdout.Bytes()
	}
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
	return res, finish(run, model.ExitOK, fmt.Sprintf("exit %d", code), len(sigs))
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
	return &externalTool{
		name: "gitleaks", binary: "gitleaks", controls: []string{"E-005"}, verArgs: []string{"version"},
		okExit: map[int]bool{0: true},
		args: func(c *Context, out string) ([]string, error) {
			return []string{"detect", "--no-git", "--source", c.Root, "--redact", "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", out}, nil
		},
		normalize: func(c *Context, raw []byte) ([]model.Signal, error) {
			var items []struct {
				RuleID      string `json:"RuleID"`
				Description string `json:"Description"`
				File        string `json:"File"`
				StartLine   int    `json:"StartLine"`
				EndLine     int    `json:"EndLine"`
				Match       string `json:"Match"`
				Fingerprint string `json:"Fingerprint"`
			}
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, err
			}
			var out []model.Signal
			for _, it := range items {
				out = append(out, model.Signal{RuleID: "gitleaks." + it.RuleID, ControlID: "E-005", Title: "Secret detected: " + it.Description, Severity: model.SevHigh, Confidence: model.StronglySupported, CWE: "CWE-798",
					File: it.File, StartLine: it.StartLine, EndLine: it.EndLine, Snippet: it.Match, Message: "Gitleaks rule " + it.RuleID + " matched (value redacted by gitleaks and PenSec).",
					Fix: "Rotate the credential, remove it from code and history, load it at runtime from a secret manager.", Key: it.RuleID})
			}
			return out, nil
		},
	}
}

func semgrep() Adapter {
	t := &externalTool{
		name: "semgrep", binary: "semgrep", controls: []string{"D-006"}, verArgs: []string{"--version"},
		okExit: map[int]bool{0: true, 1: true},
		args: func(c *Context, out string) ([]string, error) {
			// The bundled rules always run; they are local and need no network.
			bundled, err := rules.WriteSemgrep(filepath.Join(c.ToolHome, "pensec-semgrep-rules"))
			if err != nil {
				return nil, err
			}
			args := []string{"scan", "--config", bundled}
			cfg := c.Cfg.Scan.SemgrepConfig
			if cfg == "" {
				local := filepath.Join(c.Root, ".pensec", "semgrep")
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
			return append(args, "--json", "--output", out, "--metrics=off", "--disable-version-check", "--quiet", "--timeout", "30", c.Root), nil
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
							CWE     any    `json:"cwe"`
							Control string `json:"pensec-control"`
						} `json:"metadata"`
					} `json:"extra"`
				} `json:"results"`
				Errors []any `json:"errors"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, err
			}
			var out []model.Signal
			for _, r := range doc.Results {
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
				out = append(out, model.Signal{RuleID: "semgrep." + lastSegment(r.CheckID), ControlID: cid, Title: lastSegment(r.CheckID), Severity: sevFrom(r.Extra.Severity), Confidence: model.Hypothesis, CWE: cwe,
					File: r.Path, StartLine: r.Start.Line, EndLine: r.End.Line, Snippet: snippet, Message: r.Extra.Message, Fix: "See rule " + lastSegment(r.CheckID) + " guidance."})
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
	return &externalTool{
		name: "osv-scanner", binary: "osv-scanner", controls: []string{"I-003"}, network: true, verArgs: []string{"--version"},
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
			for _, r := range doc.Results {
				for _, p := range r.Packages {
					for _, v := range p.Vulnerabilities {
						sev := sevFrom(v.DatabaseSpecific.Severity)
						out = append(out, model.Signal{RuleID: "osv." + v.ID, ControlID: "I-003", Title: fmt.Sprintf("%s %s: %s", p.Package.Name, p.Package.Version, v.ID), Severity: sev, Confidence: model.StronglySupported, CWE: "CWE-1395",
							File: r.Source.Path, Message: v.Summary + " (advisory presence does not prove the vulnerable code path is reachable)",
							Fix: "Upgrade " + p.Package.Name + " to a fixed version listed in " + v.ID + "; check the advisory for workarounds.", Key: p.Package.Name + "@" + p.Package.Version + "/" + v.ID})
					}
				}
			}
			return out, nil
		},
	}
}

func trivy() Adapter {
	return &externalTool{
		name: "trivy", binary: "trivy", controls: []string{"J-005"}, network: true, verArgs: []string{"--version"},
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
		ti := ToolInfo{Name: t.name, Binary: t.binary, Network: t.network}
		if p, err := t.Lookup(); err == nil {
			ti.Path = p
			ti.Version = t.Version(ctx)
		}
		out = append(out, ti)
	}
	return out
}
