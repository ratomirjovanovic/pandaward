package main

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Category is one OWASP Benchmark vulnerability category.
type Category struct {
	Name string
	CWE  int
}

// Categories are the eleven categories of OWASP Benchmark 1.2, in the order
// its scorecard lists them.
var Categories = []Category{
	{"cmdi", 78}, {"crypto", 327}, {"hash", 328}, {"ldapi", 90}, {"pathtraver", 22}, {"securecookie", 614},
	{"sqli", 89}, {"trustbound", 501}, {"weakrand", 330}, {"xpathi", 643}, {"xss", 79},
}

// ruleCategory maps built-in rules that apply to Java files to the category
// they are meant to detect. It takes precedence over the CWE mapping because
// a rule's CWE does not always match the Benchmark's choice (the weak
// password hash rule carries CWE-327, while the Benchmark files weak hashes
// under hash, CWE-328). A category with no rule here and no mapped finding
// is reported as not covered.
var ruleCategory = map[string]string{
	"code.java-shell":         "cmdi",
	"code.sql-concat":         "sqli",
	"code.sql-template":       "sqli",
	"code.sql-unsafe-raw":     "sqli",
	"code.html-sink":          "xss",
	"code.weak-hash-password": "hash",
	"code.insecure-random":    "weakrand",
	"code.cookie-flags-off":   "securecookie",
}

// cweCategory maps CWE numbers to categories for rules not listed in
// ruleCategory. CWE-338 is a child of CWE-330 and counts as weakrand.
var cweCategory = map[int]string{
	78: "cmdi", 327: "crypto", 328: "hash", 90: "ldapi", 22: "pathtraver", 614: "securecookie",
	89: "sqli", 501: "trustbound", 330: "weakrand", 338: "weakrand", 643: "xpathi", 79: "xss",
}

// CategoryOf returns the Benchmark category a finding counts for, or "".
func CategoryOf(rule, cwe string) string {
	if c, ok := ruleCategory[rule]; ok {
		return c
	}
	n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(cwe)), "CWE-"))
	if err != nil {
		return ""
	}
	return cweCategory[n]
}

// CoveredCategories returns the categories at least one of the given rules
// is mapped to.
func CoveredCategories(rules []string) map[string][]string {
	out := map[string][]string{}
	for _, r := range rules {
		if c := ruleCategory[r]; c != "" {
			out[c] = append(out[c], r)
		}
	}
	for c := range out {
		sort.Strings(out[c])
	}
	return out
}

// Expected is one labelled test case from expectedresults-*.csv.
type Expected struct {
	Name     string
	Category string
	Real     bool
	CWE      int
}

// ParseExpected reads the Benchmark's expected results file. Lines starting
// with '#' are comments.
func ParseExpected(r io.Reader) ([]Expected, error) {
	var out []Expected
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 4 {
			return nil, fmt.Errorf("line %d: want 4 fields, got %d", n, len(f))
		}
		isReal, err := strconv.ParseBool(strings.TrimSpace(f[2]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", n, err)
		}
		cwe, err := strconv.Atoi(strings.TrimSpace(f[3]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", n, err)
		}
		out = append(out, Expected{Name: strings.TrimSpace(f[0]), Category: strings.TrimSpace(f[1]), Real: isReal, CWE: cwe})
	}
	return out, sc.Err()
}

// Finding is the part of a Pandaward signal the scoring needs.
type Finding struct {
	Rule string
	CWE  string
	File string
	Line int
}

var testCaseRe = regexp.MustCompile(`^(BenchmarkTest\d{5})\.java$`)

// TestCaseOf returns the test case a file belongs to, or "".
func TestCaseOf(file string) string {
	m := testCaseRe.FindStringSubmatch(path.Base(strings.ReplaceAll(file, "\\", "/")))
	if m == nil {
		return ""
	}
	return m[1]
}

// CategoryResult is the confusion matrix for one category.
type CategoryResult struct {
	Category string   `json:"category"`
	CWE      int      `json:"cwe"`
	Covered  bool     `json:"covered"`
	Rules    []string `json:"rules,omitempty"`
	Real     int      `json:"real_vulnerabilities"`
	NotReal  int      `json:"false_positive_tests"`
	TP       int      `json:"tp"`
	FP       int      `json:"fp"`
	FN       int      `json:"fn"`
	TN       int      `json:"tn"`
	TPR      float64  `json:"tpr"`
	FPR      float64  `json:"fpr"`
	Score    float64  `json:"score"`
}

// Score is the outcome of scoring findings against the expected results.
type Score struct {
	Categories []CategoryResult `json:"categories"`
	// AverageCovered averages the score over covered categories only.
	AverageCovered float64 `json:"average_score_covered"`
	// AverageAll averages over all categories with not covered ones as 0,
	// which is how the OWASP scorecard averages a tool.
	AverageAll        float64 `json:"average_score_all"`
	TestCases         int     `json:"test_cases"`
	Findings          int     `json:"findings"`
	FindingsInTests   int     `json:"findings_in_test_cases"`
	OffCategory       int     `json:"findings_other_category"`
	UnknownTestCases  int     `json:"findings_unlabelled_test_cases"`
	FindingsElsewhere int     `json:"findings_outside_test_cases"`
}

// Compute scores findings against the expected results. A test case counts
// as flagged when at least one finding in its file maps to the test case's
// own category, as the OWASP scorecard does; findings of another category
// in the same file are counted separately and do not affect the matrix.
func Compute(expected []Expected, findings []Finding, covered map[string][]string) Score {
	byName := map[string]Expected{}
	for _, e := range expected {
		byName[e.Name] = e
	}
	s := Score{TestCases: len(expected), Findings: len(findings)}
	flagged := map[string]bool{}
	observed := map[string]bool{}
	for _, f := range findings {
		tc := TestCaseOf(f.File)
		if tc == "" {
			s.FindingsElsewhere++
			continue
		}
		e, ok := byName[tc]
		if !ok {
			s.UnknownTestCases++
			continue
		}
		s.FindingsInTests++
		cat := CategoryOf(f.Rule, f.CWE)
		if cat != "" {
			observed[cat] = true
		}
		if cat != e.Category {
			s.OffCategory++
			continue
		}
		flagged[tc] = true
	}
	results := map[string]*CategoryResult{}
	for _, c := range Categories {
		_, cov := covered[c.Name]
		results[c.Name] = &CategoryResult{Category: c.Name, CWE: c.CWE, Covered: cov || observed[c.Name], Rules: covered[c.Name]}
	}
	for _, e := range expected {
		r := results[e.Category]
		if r == nil {
			r = &CategoryResult{Category: e.Category, CWE: e.CWE, Covered: observed[e.Category]}
			results[e.Category] = r
		}
		hit := flagged[e.Name]
		switch {
		case e.Real && hit:
			r.TP++
		case e.Real:
			r.FN++
		case hit:
			r.FP++
		default:
			r.TN++
		}
		if e.Real {
			r.Real++
		} else {
			r.NotReal++
		}
	}
	names := make([]string, 0, len(results))
	for n := range results {
		names = append(names, n)
	}
	sort.Strings(names)
	nCovered := 0
	for _, n := range names {
		r := results[n]
		if r.TP+r.FN > 0 {
			r.TPR = float64(r.TP) / float64(r.TP+r.FN)
		}
		if r.FP+r.TN > 0 {
			r.FPR = float64(r.FP) / float64(r.FP+r.TN)
		}
		r.Score = r.TPR - r.FPR
		if r.Covered {
			nCovered++
			s.AverageCovered += r.Score
		}
		s.AverageAll += r.Score
		s.Categories = append(s.Categories, *r)
	}
	if nCovered > 0 {
		s.AverageCovered /= float64(nCovered)
	}
	if len(names) > 0 {
		s.AverageAll /= float64(len(names))
	}
	return s
}
