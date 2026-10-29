// Package feedback builds false positive and false negative reports that a
// user can send to the PandaWard project. Nothing is sent from here: a report
// is text and a prefilled issue link the user decides to open. By default a
// report carries only rule metadata and the file type; the path and the
// lines are added only on request, and then redacted.
package feedback

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/catalog"
	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
	"github.com/ratomirjovanovic/pandaward/internal/version"
)

// Kinds of report, also the issue template names.
const (
	FalsePositive = "false-positive"
	FalseNegative = "false-negative"
)

// Repo is where reports are filed.
const Repo = "https://github.com/ratomirjovanovic/pandaward"

// MaxSnippetLines bounds the code a report may carry.
const MaxSnippetLines = 12

// Report is one false positive or false negative.
type Report struct {
	Kind        string `json:"kind"`
	RuleID      string `json:"rule_id,omitempty"`
	ControlID   string `json:"control_id,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	Adapter     string `json:"adapter,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`
	PandaWard   string `json:"pandaward_version"`
	Catalog     string `json:"catalog_version"`
	FileType    string `json:"file_type,omitempty"`
	Path        string `json:"path,omitempty"`
	Line        int    `json:"line,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Options choose what leaves the machine beyond the rule metadata.
type Options struct {
	IncludePath    bool
	IncludeSnippet bool
	Note           string
}

// FromFinding builds a false positive report for a finding. runs are the
// adapter runs of the finding's assessment, used for the tool version.
func FromFinding(root string, f model.Finding, runs []model.Run, o Options) Report {
	r := Report{Kind: FalsePositive, RuleID: f.RuleID, ControlID: f.ControlID, Severity: string(f.Severity),
		Confidence: string(f.Confidence), Adapter: f.Collector, PandaWard: version.Version, Catalog: catalog.Version,
		FileType: FileType(f.File), Note: clean(o.Note)}
	for _, run := range runs {
		if run.Adapter == f.Collector {
			r.ToolVersion = redact.Line(run.ToolVersion)
		}
	}
	addLocation(&r, root, f.File, f.StartLine, f.EndLine, o)
	return r
}

// Missed builds a false negative report: a problem PandaWard did not flag.
// rule may be a rule ID or a control ID; either may be empty.
func Missed(root, rule, file string, line int, o Options) Report {
	r := Report{Kind: FalseNegative, PandaWard: version.Version, Catalog: catalog.Version, FileType: FileType(file), Note: clean(o.Note)}
	if catalog.ControlByID(strings.ToUpper(rule)) != nil {
		r.ControlID = strings.ToUpper(rule)
	} else {
		r.RuleID = clean(rule)
	}
	addLocation(&r, root, file, line, line, o)
	return r
}

func addLocation(r *Report, root, file string, start, end int, o Options) {
	if file == "" {
		return
	}
	if o.IncludePath {
		r.Path = redact.Line(filepath.ToSlash(file))
		r.Line = start
	}
	if o.IncludeSnippet && start > 0 {
		r.Snippet = snippet(root, file, start, end)
	}
}

// snippet reads lines around the location from the project, redacted. Files
// outside the root are never read.
func snippet(root, file string, start, end int) string {
	if end < start {
		end = start
	}
	if end-start >= MaxSnippetLines {
		end = start + MaxSnippetLines - 1
	}
	// Resolve links on both sides, so a symlink cannot lead outside.
	rootAbs, err := filepath.EvalSymlinks(root)
	if err != nil {
		return ""
	}
	abs, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil {
		return ""
	}
	if rel, err := filepath.Rel(rootAbs, abs); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return ""
	}
	fh, err := os.Open(abs)
	if err != nil {
		return ""
	}
	defer fh.Close()
	var lines []string
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for n := 1; sc.Scan() && n <= end; n++ {
		if n >= start {
			lines = append(lines, redact.Line(sc.Text()))
		}
	}
	return strings.Join(lines, "\n")
}

// FileType names the kind of file without revealing its path: the
// extension, or a well-known base name such as Dockerfile.
func FileType(file string) string {
	if file == "" {
		return ""
	}
	base := path.Base(filepath.ToSlash(file))
	switch strings.ToLower(base) {
	case "dockerfile", "makefile", "jenkinsfile", "gemfile", "procfile":
		return base
	}
	if strings.HasPrefix(strings.ToLower(base), ".env") {
		return ".env"
	}
	if ext := path.Ext(base); ext != "" {
		if strings.Contains(filepath.ToSlash(file), ".github/workflows/") {
			return "github-workflow" + ext
		}
		return strings.ToLower(ext)
	}
	return "(no extension)"
}

func clean(s string) string { return strings.TrimSpace(redact.Line(s)) }

// Title is the issue title.
func (r Report) Title() string {
	subject := r.RuleID
	if subject == "" {
		subject = r.ControlID
	}
	if subject == "" {
		subject = "unknown rule"
	}
	return fmt.Sprintf("[%s] %s", r.Kind, subject)
}

// Markdown renders the report for the issue body or the terminal.
func (r Report) Markdown() string {
	var b strings.Builder
	rows := [][2]string{
		{"Kind", r.Kind}, {"Rule", r.RuleID}, {"Control", r.ControlID}, {"Severity", r.Severity},
		{"Confidence", r.Confidence}, {"Adapter", r.Adapter}, {"Tool version", r.ToolVersion},
		{"PandaWard", r.PandaWard}, {"Catalog", r.Catalog}, {"File type", r.FileType},
	}
	if r.Path != "" {
		rows = append(rows, [2]string{"Location", fmt.Sprintf("%s:%d", r.Path, r.Line)})
	}
	b.WriteString("| | |\n|---|---|\n")
	for _, row := range rows {
		if row[1] != "" {
			fmt.Fprintf(&b, "| %s | %s |\n", row[0], strings.ReplaceAll(row[1], "|", "/"))
		}
	}
	if r.Snippet != "" {
		b.WriteString("\nRedacted lines:\n\n```\n" + strings.ReplaceAll(r.Snippet, "```", "'''") + "\n```\n")
	}
	if r.Note != "" {
		b.WriteString("\nNote: " + r.Note + "\n")
	}
	return b.String()
}

// IssueURL returns a link to the matching issue form, prefilled with the
// report. The user opens it, reviews the text and submits it.
func (r Report) IssueURL() string {
	q := url.Values{}
	q.Set("template", r.Kind+".yml")
	q.Set("title", r.Title())
	rule := r.RuleID
	if rule == "" {
		rule = r.ControlID
	}
	q.Set("rule", rule)
	q.Set("version", r.PandaWard)
	q.Set("details", r.Markdown())
	return Repo + "/issues/new?" + q.Encode()
}

// Subject is the rule, else the control the report is about.
func (r Report) Subject() string {
	if r.RuleID != "" {
		return r.RuleID
	}
	return r.ControlID
}

// ExistingURL links to open reports about the same rule, so a user can
// upvote one instead of filing a duplicate.
func (r Report) ExistingURL() string {
	q := "is:issue is:open label:" + r.Kind
	if s := r.Subject(); s != "" {
		q += " " + s
	}
	return Repo + "/issues?q=" + url.QueryEscape(q)
}

// RuleCount is how often a rule's findings were closed as false positives
// in this project, next to how many are still open.
type RuleCount struct {
	RuleID         string `json:"rule_id"`
	FalsePositives int    `json:"false_positives"`
	Open           int    `json:"open"`
}

// Summary groups the project's findings by rule, rules with the most false
// positives first.
func Summary(fs []model.Finding) []RuleCount {
	m := map[string]*RuleCount{}
	for _, f := range fs {
		c := m[f.RuleID]
		if c == nil {
			c = &RuleCount{RuleID: f.RuleID}
			m[f.RuleID] = c
		}
		switch {
		case f.Status == model.FindingFalsePositive:
			c.FalsePositives++
		case f.Status.Active():
			c.Open++
		}
	}
	var out []RuleCount
	for _, c := range m {
		if c.FalsePositives > 0 {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FalsePositives != out[j].FalsePositives {
			return out[i].FalsePositives > out[j].FalsePositives
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
