// Command rulequality groups open false positive and false negative reports
// by rule and file type, scores them and plans labels and a dashboard. It
// reads issues from the GitHub REST API on stdin, as printed by
//
//	gh api --paginate "repos/OWNER/REPO/issues?state=open&labels=false-positive&per_page=100"
//
// for each of the two labels (concatenated arrays are accepted), and writes
// a plan as JSON. REST pagination has no result cap, so this keeps working
// with many thousands of reports. It never calls the API itself; the
// rule-quality workflow applies the plan. Issue text is untrusted: it is
// only parsed, and names are reduced to a safe label alphabet.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

type issue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
	Reactions struct {
		PlusOne int `json:"+1"`
	} `json:"reactions"`
	PullRequest json.RawMessage `json:"pull_request"`
}

// Group is the open reports about one rule.
type Group struct {
	Rule      string `json:"rule"`
	Priority  string `json:"priority"`
	Score     int    `json:"score"`
	FP        int    `json:"false_positives"`
	FN        int    `json:"false_negatives"`
	Reporters int    `json:"reporters"`
	Upvotes   int    `json:"upvotes"`
	Issues    []int  `json:"issues"`
	// FileTypes counts reports per file type, the second grouping level:
	// a rule that misfires on one language shows up as one cluster.
	FileTypes map[string]int `json:"file_types"`
}

// LabelChange sets the rule and priority labels of one issue.
type LabelChange struct {
	Issue  int      `json:"issue"`
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

// Plan is what the workflow applies.
type Plan struct {
	Groups    []Group       `json:"groups"`
	Labels    []LabelChange `json:"labels"`
	Dashboard string        `json:"dashboard"`
}

const (
	labelFP = "false-positive"
	labelFN = "false-negative"
	unknown = "unknown"
	// MaxDashboardRules keeps the dashboard within the issue body limit.
	MaxDashboardRules = 200
)

var priorities = []string{"priority:P1", "priority:P2", "priority:P3"}

func main() {
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 256<<20))
	check(err)
	issues, err := decode(b)
	check(err)
	out, err := json.MarshalIndent(Build(issues), "", "  ")
	check(err)
	fmt.Println(string(out))
}

// decode accepts one JSON array or several concatenated ones, which is what
// gh api --paginate prints across pages and the two label queries.
func decode(b []byte) ([]issue, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	var all []issue
	for dec.More() {
		var page []issue
		if err := dec.Decode(&page); err != nil {
			return nil, err
		}
		all = append(all, page...)
	}
	return all, nil
}

// Build groups, scores and renders. The result depends only on the input.
func Build(issues []issue) Plan {
	type acc struct {
		g       Group
		authors map[string]bool
	}
	by := map[string]*acc{}
	ruleOf := map[int]string{}
	var kept []issue
	for _, is := range issues {
		fp, fn := hasLabel(is, labelFP), hasLabel(is, labelFN)
		if (!fp && !fn) || len(is.PullRequest) > 0 {
			continue
		}
		if _, dup := ruleOf[is.Number]; dup {
			continue
		}
		rule := RuleFromBody(is.Body)
		ruleOf[is.Number] = rule
		kept = append(kept, is)
		a := by[rule]
		if a == nil {
			a = &acc{g: Group{Rule: rule, FileTypes: map[string]int{}}, authors: map[string]bool{}}
			by[rule] = a
		}
		if fn {
			a.g.FN++
		} else {
			a.g.FP++
		}
		a.authors[strings.ToLower(is.User.Login)] = true
		a.g.Upvotes += is.Reactions.PlusOne
		a.g.FileTypes[FileTypeFromBody(is.Body)]++
		a.g.Issues = append(a.g.Issues, is.Number)
	}
	p := Plan{Groups: []Group{}, Labels: []LabelChange{}}
	prio := map[string]string{}
	for _, a := range by {
		a.g.Reporters = len(a.authors)
		a.g.Score = Score(a.g)
		a.g.Priority = Priority(a.g.Score)
		sort.Ints(a.g.Issues)
		p.Groups = append(p.Groups, a.g)
		prio[a.g.Rule] = a.g.Priority
	}
	sort.Slice(p.Groups, func(i, j int) bool {
		if p.Groups[i].Score != p.Groups[j].Score {
			return p.Groups[i].Score > p.Groups[j].Score
		}
		return p.Groups[i].Rule < p.Groups[j].Rule
	})
	for _, is := range kept {
		rule := ruleOf[is.Number]
		want := []string{"rule:" + rule, prio[rule]}
		var add, remove []string
		for _, l := range want {
			if !hasLabel(is, l) {
				add = append(add, l)
			}
		}
		for _, l := range is.Labels {
			stale := strings.HasPrefix(l.Name, "rule:") && l.Name != want[0]
			stale = stale || (strings.HasPrefix(l.Name, "priority:") && l.Name != want[1])
			if stale {
				remove = append(remove, l.Name)
			}
		}
		if len(add)+len(remove) > 0 {
			p.Labels = append(p.Labels, LabelChange{Issue: is.Number, Add: add, Remove: remove})
		}
	}
	sort.Slice(p.Labels, func(i, j int) bool { return p.Labels[i].Issue < p.Labels[j].Issue })
	p.Dashboard = Dashboard(p.Groups)
	return p
}

// Score weighs a missed issue twice as much as a false alarm, because a
// miss can hide a real vulnerability, and counts every extra reporter and
// upvote as independent confirmation.
func Score(g Group) int {
	s := 2*g.FN + g.FP + g.Upvotes
	if g.Reporters > 1 {
		s += g.Reporters - 1
	}
	return s
}

// Priority maps a score to P1 (fix next), P2 (soon) or P3 (collect more).
func Priority(score int) string {
	switch {
	case score >= 6:
		return priorities[0]
	case score >= 3:
		return priorities[1]
	}
	return priorities[2]
}

var (
	heading  = regexp.MustCompile(`(?m)^###\s+(Rule ID|Rule or control)\s*$`)
	fileType = regexp.MustCompile(`(?m)^\|\s*File type\s*\|\s*([^|\n]{1,40}?)\s*\|`)
	safe     = regexp.MustCompile(`[^a-z0-9._-]+`)
	dashes   = regexp.MustCompile(`-{2,}`)
)

// label reduces untrusted text to [a-z0-9._-], at most 40 characters, and
// trims the given characters from both ends.
func label(s, trim string) string {
	r := strings.Trim(dashes.ReplaceAllString(safe.ReplaceAllString(strings.ToLower(s), "-"), "-"), trim)
	if len(r) > 40 {
		r = r[:40]
	}
	if r == "" {
		return unknown
	}
	return r
}

// RuleFromBody reads the rule field of an issue form. Missing or empty
// fields group under "unknown".
func RuleFromBody(body string) string {
	loc := heading.FindStringIndex(body)
	if loc == nil {
		return unknown
	}
	for _, line := range strings.Split(body[loc[1]:], "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "###") || line == "_No response_" {
			return unknown
		}
		return label(strings.Trim(line, "`"), "-.")
	}
	return unknown
}

// FileTypeFromBody reads the file type row that pensec feedback writes.
func FileTypeFromBody(body string) string {
	m := fileType.FindStringSubmatch(body)
	if m == nil {
		return unknown
	}
	return label(m[1], "-")
}

// Dashboard renders the ranked table for the tracking issue.
func Dashboard(gs []Group) string {
	var b strings.Builder
	b.WriteString("# Rule quality\n\n")
	b.WriteString("Open false positive and false negative reports, grouped by rule and file type. Updated automatically by the `rule-quality` workflow; edits to this issue are overwritten.\n\n")
	if len(gs) == 0 {
		b.WriteString("No open reports.\n")
	} else {
		b.WriteString("| # | Rule | Priority | Score | False positives | Missed | Reporters | Upvotes | File types | Issues |\n")
		b.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
		for i, g := range gs {
			if i == MaxDashboardRules {
				fmt.Fprintf(&b, "\n%d more rules with lower scores are not shown; filter issues by their `rule:` label.\n", len(gs)-i)
				break
			}
			var refs []string
			for j, n := range g.Issues {
				if j == 10 {
					refs = append(refs, fmt.Sprintf("and %d more", len(g.Issues)-j))
					break
				}
				refs = append(refs, fmt.Sprintf("#%d", n))
			}
			fmt.Fprintf(&b, "| %d | `%s` | %s | %d | %d | %d | %d | %d | %s | %s |\n", i+1, g.Rule, strings.TrimPrefix(g.Priority, "priority:"),
				g.Score, g.FP, g.FN, g.Reporters, g.Upvotes, topTypes(g.FileTypes), strings.Join(refs, " "))
		}
	}
	b.WriteString("\nScore = 2 x missed + false positives + upvotes + (reporters - 1). P1 from 6, P2 from 3, otherwise P3. Upvote a report with :+1: if you hit the same problem instead of opening a new one.\n\n")
	b.WriteString("Fixing a report: change the rule, add the example as a vulnerable or safe case to the benchmark corpus so it cannot regress, and close the issues from the pull request.\n")
	return b.String()
}

func topTypes(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var xs []kv
	for k, v := range m {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool {
		if xs[i].v != xs[j].v {
			return xs[i].v > xs[j].v
		}
		return xs[i].k < xs[j].k
	})
	var out []string
	for i, x := range xs {
		if i == 3 {
			out = append(out, "...")
			break
		}
		out = append(out, fmt.Sprintf("%s (%d)", x.k, x.v))
	}
	return strings.Join(out, ", ")
}

func hasLabel(is issue, name string) bool {
	for _, l := range is.Labels {
		if l.Name == name {
			return true
		}
	}
	return false
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "rulequality:", err)
		os.Exit(1)
	}
}
