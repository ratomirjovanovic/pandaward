// Package adapters contains the built-in static checks and the wrappers for
// optional third-party scanners. Built-in adapters only read the in-memory
// inventory; they never execute repository content or touch the network.
package adapters

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// Maturity labels from the PRD capability registry.
const (
	MaturityBenchmarked = "implemented_and_benchmarked"
	MaturityUnvalidated = "implemented_unvalidated"
)

// Context is handed to every adapter.
type Context struct {
	Root     string
	Inv      *inventory.Inventory
	Cfg      *config.Config
	RunDir   string // private scratch directory for raw tool output
	ToolHome string // disposable HOME for external tools
	Timeout  time.Duration
}

// Decision lets an adapter set a control status directly (for controls that
// are not simply "no signals = PASS").
type Decision struct {
	Status model.Status
	Reason string
}

// Result is the normalized adapter output.
type Result struct {
	Signals   []model.Signal
	Decisions map[string]Decision
}

// Adapter is the contract every scanner implements.
type Adapter interface {
	Name() string
	Controls() []string
	Maturity() string
	Network() bool // true if the adapter needs network access for its tool
	Run(ctx context.Context, c *Context) (Result, model.Run)
}

// Registry returns all adapters in execution order.
func Registry() []Adapter {
	return []Adapter{
		&inventoryAdapter{},
		&secretsAdapter{},
		&codeAdapter{},
		&cicdAdapter{},
		&infraAdapter{},
		&supplyAdapter{},
		&mobileAdapter{},
		apktoolAdapter{},
		gitleaks(),
		semgrep(),
		osvScanner(),
		trivy(),
		sarifAdapter{},
	}
}

// ByName returns an adapter or nil.
func ByName(name string) Adapter {
	for _, a := range Registry() {
		if a.Name() == name {
			return a
		}
	}
	return nil
}

func newRun(name, version string) model.Run {
	return model.Run{ID: name + "-" + time.Now().UTC().Format("20060102T150405.000Z"), Adapter: name, ToolVersion: version, StartedAt: time.Now().UTC().Format(time.RFC3339)}
}

func finish(r model.Run, class, detail string, n int) model.Run {
	r.EndedAt = time.Now().UTC().Format(time.RFC3339)
	r.ExitClass = class
	r.Detail = redact.Line(detail)
	r.SignalsCount = n
	return r
}

// lineRule is a single-line regular expression check.
type lineRule struct {
	ID         string
	Control    string
	Title      string
	Langs      map[string]bool // nil = all code languages
	Re         *regexp.Regexp
	Not        *regexp.Regexp // skip the line if it matches
	Severity   model.Severity
	Confidence model.Confidence
	CWE        string
	Message    string
	Fix        string
}

func langs(ls ...string) map[string]bool {
	m := map[string]bool{}
	for _, l := range ls {
		m[l] = true
	}
	return m
}

var commentRe = regexp.MustCompile(`^\s*(//|#|\*|/\*|<!--|--|;)`)

// IsTestPath reports whether a path looks like test or fixture code.
func IsTestPath(p string) bool {
	l := strings.ToLower(p)
	// Inside a main source set "example" is a package name (com.example is
	// the default for new Android projects), not a directory of samples.
	main := strings.Contains("/"+l, "/src/main/")
	for _, s := range []string{"/test/", "/tests/", "/__tests__/", "/spec/", "/fixtures/", "/testdata/", "/__mocks__/", "/e2e/", "/examples/", "/example/"} {
		if main && (s == "/examples/" || s == "/example/") {
			continue
		}
		if strings.Contains("/"+l, s) {
			return true
		}
	}
	for _, seg := range strings.Split(l, "/") {
		if strings.Contains(seg, "fixture") {
			return true
		}
	}
	return strings.Contains(l, ".test.") || strings.Contains(l, ".spec.") || strings.HasSuffix(l, "_test.go") || strings.HasPrefix(path_base(l), "test_")
}

func path_base(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func sig(r lineRule, f *inventory.File, line int, collector string) model.Signal {
	return model.Signal{
		RuleID: r.ID, ControlID: r.Control, Title: r.Title, Severity: r.Severity, Confidence: r.Confidence, CWE: r.CWE,
		File: f.Path, StartLine: line, EndLine: line, Snippet: redact.Line(strings.TrimSpace(f.Lines[line-1])),
		Message: r.Message, Fix: r.Fix, Collector: collector,
	}
}
