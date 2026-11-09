package main

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/rules"
)

// Category is one OWASP Benchmark vulnerability category.
type Category struct {
	Name string
	CWE  int
}

// Suite is one OWASP Benchmark: where to fetch it, how its test case files
// are named, its categories and which built-in rules are meant for them.
type Suite struct {
	Key          string
	Title        string
	URL          string
	PinnedCommit string
	Expected     string
	// TestCodeDir holds one file per test case, BenchmarkTest#####<Ext>.
	TestCodeDir string
	Ext         string
	// Language is the Semgrep language of the bundled rules that apply.
	Language string
	// Categories are the suite's categories, in the order its scorecard
	// lists them.
	Categories []Category
	// Rules maps built-in rules that apply to the suite's language to the
	// category they are meant to detect. It takes precedence over the CWE
	// mapping because a rule's CWE does not always match the Benchmark's
	// choice (the weak password hash rule carries CWE-327, while the
	// Benchmark files weak hashes under hash, CWE-328). A category with no
	// rule here and no mapped finding is reported as not covered.
	Rules map[string]string
}

// Java is OWASP BenchmarkJava 1.2.
var Java = &Suite{
	Key: "java", Title: "OWASP Benchmark for Java", URL: "https://github.com/OWASP-Benchmark/BenchmarkJava",
	PinnedCommit: "f40c618c5a709afce350ef06ed2899c85cf586e9", Expected: "expectedresults-1.2.csv",
	TestCodeDir: "src/main/java/org/owasp/benchmark/testcode", Ext: ".java", Language: "java",
	Categories: []Category{
		{"cmdi", 78}, {"crypto", 327}, {"hash", 328}, {"ldapi", 90}, {"pathtraver", 22}, {"securecookie", 614},
		{"sqli", 89}, {"trustbound", 501}, {"weakrand", 330}, {"xpathi", 643}, {"xss", 79},
	},
	Rules: map[string]string{
		"code.java-shell":         "cmdi",
		"code.sql-concat":         "sqli",
		"code.sql-template":       "sqli",
		"code.sql-unsafe-raw":     "sqli",
		"code.html-sink":          "xss",
		"code.weak-hash-password": "hash",
		"code.insecure-random":    "weakrand",
		"code.cookie-flags-off":   "securecookie",
	},
}

// Python is OWASP BenchmarkPython 0.1. It is GPL-3.0 and only fetched at run
// time, never vendored.
var Python = &Suite{
	Key: "python", Title: "OWASP Benchmark for Python", URL: "https://github.com/OWASP-Benchmark/BenchmarkPython",
	PinnedCommit: "f1291485808b66e20ddb6b01b10dc71b3df8c8ba", Expected: "expectedresults-0.1.csv",
	TestCodeDir: "testcode", Ext: ".py", Language: "python",
	Categories: []Category{
		{"cmdi", 78}, {"codeinj", 94}, {"deserialization", 502}, {"hash", 328}, {"ldapi", 90}, {"pathtraver", 22},
		{"redirect", 601}, {"securecookie", 614}, {"sqli", 89}, {"trustbound", 501}, {"weakrand", 330},
		{"xpathi", 643}, {"xss", 79}, {"xxe", 611},
	},
	Rules: map[string]string{
		"code.py-shell":           "cmdi",
		"code.py-eval":            "codeinj",
		"code.py-deserialize":     "deserialization",
		"code.sql-concat":         "sqli",
		"code.sql-template":       "sqli",
		"code.sql-unsafe-raw":     "sqli",
		"code.html-sink":          "xss",
		"code.weak-hash-password": "hash",
		"code.insecure-random":    "weakrand",
		"code.cookie-flags-off":   "securecookie",
	},
}

// Suites are the benchmarks the tool can measure, by key.
var Suites = map[string]*Suite{"java": Java, "python": Python}

// cweCategory maps CWE numbers to categories for rules not listed in a
// suite's Rules. CWE-338 is a child of CWE-330 and counts as weakrand;
// CWE-95 (eval injection) is a child of CWE-94.
var cweCategory = map[int]string{
	78: "cmdi", 327: "crypto", 328: "hash", 90: "ldapi", 22: "pathtraver", 614: "securecookie",
	89: "sqli", 501: "trustbound", 330: "weakrand", 338: "weakrand", 643: "xpathi", 79: "xss",
	94: "codeinj", 95: "codeinj", 502: "deserialization", 601: "redirect", 611: "xxe",
}

var cweNumRe = regexp.MustCompile(`^\s*(?i:CWE-)?(\d+)\b`)

// CategoryOf returns the Benchmark category a finding counts for, or "".
func (st *Suite) CategoryOf(rule, cwe string) string {
	if c, ok := st.Rules[rule]; ok {
		return c
	}
	// A CWE comes as "CWE-89", "89" or with its title ("CWE-89: Improper ...").
	m := cweNumRe.FindStringSubmatch(cwe)
	if m == nil {
		return ""
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return ""
	}
	// A CWE outside the suite's categories counts for none of them.
	c := cweCategory[n]
	for _, sc := range st.Categories {
		if sc.Name == c {
			return c
		}
	}
	return ""
}

// CoveredCategories returns the categories at least one of the given rules
// is mapped to.
func (st *Suite) CoveredCategories(rules []string) map[string][]string {
	out := map[string][]string{}
	for _, r := range rules {
		if c := st.Rules[r]; c != "" {
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

// Finding is the part of a PandaWard signal the scoring needs.
type Finding struct {
	Rule string
	CWE  string
	File string
	Line int
}

var testCaseRe = regexp.MustCompile(`^(BenchmarkTest\d{5})(\.\w+)$`)

// TestCaseOf returns the test case a file belongs to, or "". Only files with
// the suite's extension count: BenchmarkPython also has an HTML template
// per test case.
func (st *Suite) TestCaseOf(file string) string {
	m := testCaseRe.FindStringSubmatch(path.Base(strings.ReplaceAll(file, "\\", "/")))
	if m == nil || m[2] != st.Ext {
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
func (st *Suite) Compute(expected []Expected, findings []Finding, covered map[string][]string) Score {
	byName := map[string]Expected{}
	for _, e := range expected {
		byName[e.Name] = e
	}
	s := Score{TestCases: len(expected), Findings: len(findings)}
	flagged := map[string]bool{}
	observed := map[string]bool{}
	for _, f := range findings {
		tc := st.TestCaseOf(f.File)
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
		cat := st.CategoryOf(f.Rule, f.CWE)
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
	for _, c := range st.Categories {
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

// SemgrepCoverage maps the bundled Semgrep rules for the suite's language to
// the categories their CWE belongs to, under the rule id the semgrep adapter
// reports.
func (st *Suite) SemgrepCoverage() (map[string][]string, error) {
	rs, err := rules.SemgrepRules()
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, r := range rs {
		if !slices.Contains(r.Languages, st.Language) {
			continue
		}
		id := "semgrep." + r.ID
		if c := st.CategoryOf(id, r.Metadata.CWE); c != "" {
			out[c] = append(out[c], id)
		}
	}
	return out, nil
}
