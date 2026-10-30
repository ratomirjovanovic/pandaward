package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func form(heading, value string) string {
	return "### " + heading + "\n\n" + value + "\n\n### PandaWard version\n\n0.1.3\n"
}

func TestRuleFromBody(t *testing.T) {
	for body, want := range map[string]string{
		form("Rule ID", "code.sql-concat"):              "code.sql-concat",
		form("Rule ID", "`Code.SQL-Concat`"):            "code.sql-concat",
		form("Rule or control", "D-003"):                "d-003",
		form("Rule or control", "_No response_"):        "unknown",
		form("Rule ID", "x; rm -rf / $(id) <script>"):   "x-rm-rf-id-script",
		form("Rule ID", strings.Repeat("a", 80)):        strings.Repeat("a", 40),
		"no form at all":                                "unknown",
		"### Rule ID\n\n### PandaWard version\n\n0.1.3": "unknown",
		form("Rule ID", "../../etc/passwd"):             "etc-passwd",
	} {
		if got := RuleFromBody(body); got != want {
			t.Errorf("RuleFromBody(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestRuleOf(t *testing.T) {
	table := "| | |\n|---|---|\n| Kind | false-positive |\n| Rule | semgrep.pandaward-js-sql-string |\n| Control | D-003 |\n"
	for _, c := range []struct{ title, body, want string }{
		{"[false-positive] x", form("Rule ID", "code.sql-concat") + table, "code.sql-concat"},
		{"[false-positive] x", form("Rule ID", "_No response_") + table, "semgrep.pandaward-js-sql-string"},
		{"[false-positive] semgrep.pandaward-js-sql-string", table, "semgrep.pandaward-js-sql-string"},
		{"", "| Kind | false-negative |\n| Control | A-002 |\n", "a-002"},
		{"", "| Rule | `Code.Webhook` |\n", "code.webhook"},
		{"[false-negative] A-002: Next.js server actions are not listed", "free text", "a-002"},
		{"[false-positive] ", "free text", "unknown"},
		{"[false-positive] $(id)", "", "id"},
		{"Something else", "free text", "unknown"},
	} {
		if got := RuleOf(c.title, c.body); got != c.want {
			t.Errorf("RuleOf(%q, %q) = %q, want %q", c.title, c.body, got, c.want)
		}
	}
}

func TestFileTypeFromBody(t *testing.T) {
	for body, want := range map[string]string{
		"| | |\n|---|---|\n| Rule | x |\n| File type | .py |\n": ".py",
		"| File type | github-workflow.yml |":                   "github-workflow.yml",
		"| File type | <img src=x> |":                           "img-src-x",
		"no table":                                              "unknown",
	} {
		if got := FileTypeFromBody(body); got != want {
			t.Errorf("FileTypeFromBody(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestScoreAndPriority(t *testing.T) {
	if s := Score(Group{FN: 1, FP: 2, Reporters: 3, Upvotes: 1}); s != 2+2+1+2 {
		t.Fatalf("score = %d", s)
	}
	for score, want := range map[int]string{0: "priority:P3", 2: "priority:P3", 3: "priority:P2", 5: "priority:P2", 6: "priority:P1", 20: "priority:P1"} {
		if got := Priority(score); got != want {
			t.Errorf("Priority(%d) = %s, want %s", score, got, want)
		}
	}
}

// Two pages as gh api --paginate prints them, with a duplicate across the
// label queries and a pull request that must be ignored.
const pages = `[
 {"number": 12, "body": "### Rule ID\n\ncode.sql-concat\n\n### Details\n\n| File type | .py |\n", "labels": [{"name": "false-positive"}], "user": {"login": "ana"}, "reactions": {"+1": 2}},
 {"number": 10, "body": "### Rule ID\n\ncode.sql-concat\n\n### Details\n\n| File type | .js |\n", "labels": [{"name": "false-positive"}, {"name": "rule:old"}], "user": {"login": "bo"}}
][
 {"number": 11, "body": "### Rule or control\n\nD-003\n", "labels": [{"name": "false-negative"}, {"name": "rule:d-003"}, {"name": "priority:P3"}], "user": {"login": "ana"}},
 {"number": 12, "body": "### Rule ID\n\ncode.sql-concat\n\n### Details\n\n| File type | .py |\n", "labels": [{"name": "false-positive"}], "user": {"login": "ana"}, "reactions": {"+1": 2}},
 {"number": 13, "body": "### Rule ID\n\ncode.sql-concat\n", "labels": [{"name": "bug"}], "user": {"login": "cy"}},
 {"number": 14, "body": "### Rule ID\n\ncode.sql-concat\n", "labels": [{"name": "false-positive"}], "user": {"login": "dee"}, "pull_request": {"url": "x"}}
]`

func TestBuild(t *testing.T) {
	in, err := decode([]byte(pages))
	if err != nil {
		t.Fatal(err)
	}
	p := Build(in)
	want := []Group{
		{Rule: "code.sql-concat", Priority: "priority:P2", Score: 5, FP: 2, Reporters: 2, Upvotes: 2, Issues: []int{10, 12}, FileTypes: map[string]int{".py": 1, ".js": 1}},
		{Rule: "d-003", Priority: "priority:P3", Score: 2, FN: 1, Reporters: 1, Issues: []int{11}, FileTypes: map[string]int{"unknown": 1}},
	}
	if !reflect.DeepEqual(p.Groups, want) {
		t.Fatalf("groups = %+v", p.Groups)
	}
	wantLabels := []LabelChange{
		{Issue: 10, Add: []string{"rule:code.sql-concat", "priority:P2"}, Remove: []string{"rule:old"}},
		{Issue: 12, Add: []string{"rule:code.sql-concat", "priority:P2"}},
	}
	if !reflect.DeepEqual(p.Labels, wantLabels) {
		t.Fatalf("labels = %+v", p.Labels)
	}
	if !strings.Contains(p.Dashboard, "| 1 | `code.sql-concat` | P2 | 5 | 2 | 0 | 2 | 2 | .js (1), .py (1) | #10 #12 |") {
		t.Fatalf("dashboard:\n%s", p.Dashboard)
	}
	in[0], in[2] = in[2], in[0]
	if q := Build(in); !reflect.DeepEqual(p, q) {
		t.Fatal("plan depends on input order")
	}
}

// Thousands of reports stay one bounded dashboard.
func TestDashboardIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 5000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"number": %d, "body": "### Rule ID\n\nrule-%d\n", "labels": [{"name": "false-positive"}], "user": {"login": "u%d"}}`, i+1, i%400, i)
	}
	b.WriteString("]")
	in, err := decode([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	p := Build(in)
	if len(p.Groups) != 400 || len(p.Dashboard) > 60000 || !strings.Contains(p.Dashboard, "200 more rules") {
		t.Fatalf("groups %d, dashboard %d bytes", len(p.Groups), len(p.Dashboard))
	}
}
