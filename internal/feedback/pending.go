package feedback

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/model"
	"github.com/ratomirjovanovic/pandaward/internal/redact"
)

// Modes say how the guided review handles feedback in a project.
const (
	// ModeAsk offers each report on its own; also the behavior before the
	// user has chosen.
	ModeAsk = "ask"
	// ModeBatch prepares every pending report after triage and files them
	// after one confirmation.
	ModeBatch = "batch"
	// ModeOff never offers reports. They can still be prepared by hand.
	ModeOff = "off"
)

// ValidMode reports whether m is a mode a user can choose.
func ValidMode(m string) bool { return m == ModeAsk || m == ModeBatch || m == ModeOff }

// State is the user's feedback choice for one project and the findings
// already reported from it. It lives in the private directory: consent is
// personal, so it is never committed for a whole team.
type State struct {
	Mode    string `json:"mode,omitempty"`
	ModeSet string `json:"mode_set_at,omitempty"`
	// Sent maps a finding fingerprint to the issue it was reported in, or
	// to "link" when a prefilled link was printed instead.
	Sent map[string]string `json:"sent,omitempty"`
}

// StatePath is where the state of a project is kept.
func StatePath(privateDir string) string { return filepath.Join(privateDir, "feedback.json") }

// LoadState reads the state; a missing file is an empty state.
func LoadState(privateDir string) (State, error) {
	var s State
	b, err := os.ReadFile(StatePath(privateDir))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}, fmt.Errorf("%s: %w", StatePath(privateDir), err)
	}
	return s, nil
}

// SaveState writes the state.
func SaveState(privateDir string, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(StatePath(privateDir), append(b, '\n'), 0o600)
}

// SetMode records the user's choice.
func (s *State) SetMode(m string, now time.Time) error {
	if !ValidMode(m) {
		return fmt.Errorf("feedback mode must be %s, %s or %s", ModeAsk, ModeBatch, ModeOff)
	}
	s.Mode, s.ModeSet = m, now.UTC().Format(time.RFC3339)
	return nil
}

// Group is one report about one rule or control, standing for every
// finding of the project it covers.
type Group struct {
	Report
	Findings     []string `json:"findings"`
	fingerprints []string
}

// reviewCollector marks findings recorded by a reviewer, not by a rule.
const reviewCollector = "manual-assisted"

// Pending builds the reports a project has not sent yet:
//
//   - false positives: rule findings a person closed as false positives,
//     one report per rule. Reviewer hypotheses closed as false positives are
//     not reports about a rule and are left out, and so are findings the
//     latest scan no longer observed: that rule no longer fires there.
//   - false negatives: reviewer findings a person confirmed (or fixed) where
//     no rule reported the same control in the same file, one report per
//     control. Those are problems the scanners missed.
//
// runs returns the adapter runs of an assessment, for tool versions and the
// adapters that ran. observed reports whether the latest scan saw a
// fingerprint; nil means it is not known and every finding counts. Reports
// hold rule metadata, counts and file types only.
func Pending(fs []model.Finding, runs func(assessmentID string) []model.Run, observed func(fingerprint string) bool, st State) []Group {
	covered := map[string]bool{}
	for _, f := range fs {
		if f.Collector != reviewCollector {
			covered[f.ControlID+"|"+f.File] = true
		}
	}
	by := map[string]*Group{}
	types := map[string]map[string]bool{}
	var order []string
	add := func(key string, f model.Finding, base func() Report) {
		g := by[key]
		if g == nil {
			g = &Group{Report: base()}
			by[key], types[key] = g, map[string]bool{}
			order = append(order, key)
		}
		g.Count++
		g.Findings = append(g.Findings, f.ID)
		g.fingerprints = append(g.fingerprints, f.Fingerprint)
		if t := FileType(f.File); t != "" {
			types[key][t] = true
		}
	}
	for _, f := range fs {
		if _, sent := st.Sent[f.Fingerprint]; sent || f.Fingerprint == "" {
			continue
		}
		switch {
		case f.Status == model.FindingFalsePositive && f.Collector != reviewCollector && (observed == nil || observed(f.Fingerprint)):
			add(FalsePositive+"|"+f.RuleID, f, func() Report {
				return FromFinding("", f, runs(f.AssessmentID), Options{})
			})
		case f.Collector == reviewCollector && f.Confidence != model.Hypothesis &&
			(f.Status.Active() || f.Status == model.FindingRemediated) && !covered[f.ControlID+"|"+f.File]:
			add(FalseNegative+"|"+f.ControlID, f, func() Report {
				r := Missed("", f.ControlID, "", 0, Options{Note: "A PandaWard reviewer found this and a person confirmed it; no rule reported this control in the same file."})
				r.Severity = string(f.Severity)
				r.Adapters = adaptersRun(runs(f.AssessmentID))
				return r
			})
		}
	}
	out := make([]Group, 0, len(order))
	for _, k := range order {
		g := by[k]
		var ts []string
		for t := range types[k] {
			ts = append(ts, t)
		}
		sort.Strings(ts)
		g.FileType = strings.Join(ts, ", ")
		if g.Kind == FalsePositive {
			// The severity and confidence of one finding do not describe
			// the others; the rule and the counts do.
			g.Confidence = ""
		}
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			// Missed issues first: they can hide real vulnerabilities.
			return out[i].Kind == FalseNegative
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Subject() < out[j].Subject()
	})
	return out
}

func adaptersRun(runs []model.Run) string {
	var names []string
	for _, r := range runs {
		if r.ExitClass == model.ExitOK {
			names = append(names, redact.Line(r.Adapter))
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// MarkSent records the findings of a group as reported in url.
func (s *State) MarkSent(g Group, url string) {
	if s.Sent == nil {
		s.Sent = map[string]string{}
	}
	for _, fp := range g.fingerprints {
		s.Sent[fp] = url
	}
}

// Runner runs gh with arguments and optional standard input and returns
// its standard output.
type Runner func(stdin string, args ...string) (string, error)

// Result is what happened to one report.
type Result struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Action  string `json:"action"` // created, commented or link
	URL     string `json:"url"`
}

// RepoSlug is Repo as OWNER/NAME.
func RepoSlug() string { return strings.TrimPrefix(Repo, "https://github.com/") }

// Submit files each group with gh: a comment and a thumbs up on an open
// report with the same title, which the rule quality dashboard counts, or a
// new issue. The rule-quality workflow labels new reports by their title.
func Submit(gh Runner, gs []Group) ([]Result, error) {
	var out []Result
	for _, g := range gs {
		res := Result{Kind: g.Kind, Subject: g.Subject()}
		n, url, err := findOpen(gh, g.Title())
		if err != nil {
			return out, err
		}
		if n > 0 {
			if _, err := gh(g.Markdown(), "issue", "comment", fmt.Sprint(n), "-R", RepoSlug(), "--body-file", "-"); err != nil {
				return out, err
			}
			_, _ = gh("", "api", "-X", "POST", fmt.Sprintf("repos/%s/issues/%d/reactions", RepoSlug(), n), "-f", "content=+1")
			res.Action, res.URL = "commented", url
		} else {
			u, err := gh(g.Markdown(), "issue", "create", "-R", RepoSlug(), "--title", g.Title(), "--body-file", "-")
			if err != nil {
				return out, err
			}
			res.Action, res.URL = "created", strings.TrimSpace(lastLine(u))
		}
		out = append(out, res)
	}
	return out, nil
}

// findOpen looks for an open report whose title is the report title, alone
// or followed by ":" or a space.
func findOpen(gh Runner, title string) (int, string, error) {
	q := fmt.Sprintf("%q in:title", title)
	b, err := gh("", "issue", "list", "-R", RepoSlug(), "--state", "open", "--search", q, "--json", "number,title,url", "--limit", "30")
	if err != nil {
		return 0, "", err
	}
	var is []struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal([]byte(b), &is); err != nil {
		return 0, "", fmt.Errorf("gh issue list: %w", err)
	}
	sort.Slice(is, func(i, j int) bool { return is[i].Number < is[j].Number })
	for _, i := range is {
		t := strings.ToLower(strings.TrimSpace(i.Title))
		want := strings.ToLower(title)
		if t == want || strings.HasPrefix(t, want+":") || strings.HasPrefix(t, want+" ") {
			return i.Number, i.URL, nil
		}
	}
	return 0, "", nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}
