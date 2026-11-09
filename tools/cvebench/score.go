package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/tools/internal/engines"
)

// CVE is one entry of the OpenSSF CVE Benchmark (CVEs/<id>.json).
type CVE struct {
	ID         string `json:"CVE"`
	State      string `json:"state"`
	Repository string `json:"repository"`
	PrePatch   struct {
		Commit     string     `json:"commit"`
		Weaknesses []Weakness `json:"weaknesses"`
	} `json:"prePatch"`
	PostPatch struct {
		Commit string `json:"commit"`
	} `json:"postPatch"`
	CWEs []string `json:"CWEs"`
}

// Weakness is a labelled vulnerable line in the pre-patch commit.
type Weakness struct {
	Location struct {
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"location"`
	Explanation string `json:"explanation"`
}

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// LoadCVEs reads every published CVE of a benchmark checkout, sorted by id.
// Entries without a 40-character commit on both sides, a repository or a
// weakness are skipped and counted, since they cannot be scored.
func LoadCVEs(bench string) ([]CVE, int, error) {
	files, err := filepath.Glob(filepath.Join(bench, "CVEs", "*.json"))
	if err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no CVEs/*.json in %s; is it an ossf-cve-benchmark checkout?", bench)
	}
	var out []CVE
	skipped := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, 0, err
		}
		var c CVE
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, 0, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		if c.State != "PUBLISHED" || c.Repository == "" || !commitRe.MatchString(c.PrePatch.Commit) || !commitRe.MatchString(c.PostPatch.Commit) || len(c.PrePatch.Weaknesses) == 0 {
			skipped++
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, skipped, nil
}

var cweNumRe = regexp.MustCompile(`(?i)^\s*(?:CWE-)?0*(\d+)\b`)

// CWENumber returns the number of a CWE in any of the usual spellings
// ("CWE-079", "CWE-79: title", "79"), or 0.
func CWENumber(s string) int {
	m := cweNumRe.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// cleanPath normalizes a repository-relative path for comparison.
func cleanPath(p string) string {
	return strings.TrimPrefix(path.Clean(strings.ReplaceAll(p, "\\", "/")), "./")
}

// Outcome is how one engine did on one CVE.
type Outcome struct {
	CVE    string `json:"cve"`
	CWE    int    `json:"cwe"`
	Engine string `json:"engine"`
	// Detected: a finding covers a labelled vulnerable line in the
	// pre-patch commit.
	Detected bool `json:"detected"`
	// CWEMatch: one of those findings carries one of the CVE's CWEs.
	CWEMatch bool `json:"cwe_match"`
	// Rules are the rules whose findings cover a vulnerable line.
	Rules []string `json:"rules,omitempty"`
	// FixRecognized: one of those rules reports fewer findings in the
	// vulnerable files after the patch. A detected CVE whose rules report as
	// many findings there after the patch is still flagged when fixed, the
	// fixed-commit false positive.
	FixRecognized bool `json:"fix_recognized"`
	// FindingsInVulnerableFiles counts the engine's pre-patch findings in the
	// files that hold a labelled weakness.
	FindingsInVulnerableFiles int `json:"findings_in_vulnerable_files"`
}

// Score decides one engine's outcome on one CVE from its findings on the
// pre-patch and the post-patch commit.
func Score(c CVE, engine string, pre, post []engines.Finding) Outcome {
	o := Outcome{CVE: c.ID, Engine: engine}
	if len(c.CWEs) > 0 {
		o.CWE = CWENumber(c.CWEs[0])
	}
	cwes := map[int]bool{}
	for _, s := range c.CWEs {
		if n := CWENumber(s); n > 0 {
			cwes[n] = true
		}
	}
	vulnFiles := map[string]bool{}
	for _, w := range c.PrePatch.Weaknesses {
		vulnFiles[cleanPath(w.Location.File)] = true
	}
	rules := map[string]bool{}
	for _, f := range pre {
		file := cleanPath(f.File)
		if !vulnFiles[file] {
			continue
		}
		o.FindingsInVulnerableFiles++
		end := f.EndLine
		if end < f.Line {
			end = f.Line
		}
		for _, w := range c.PrePatch.Weaknesses {
			if cleanPath(w.Location.File) == file && f.Line <= w.Location.Line && w.Location.Line <= end {
				rules[f.Rule] = true
				if cwes[CWENumber(f.CWE)] {
					o.CWEMatch = true
				}
			}
		}
	}
	for r := range rules {
		o.Rules = append(o.Rules, r)
	}
	sort.Strings(o.Rules)
	o.Detected = len(o.Rules) > 0
	if !o.Detected {
		return o
	}
	count := func(fs []engines.Finding, rule string) int {
		n := 0
		for _, f := range fs {
			if f.Rule == rule && vulnFiles[cleanPath(f.File)] {
				n++
			}
		}
		return n
	}
	for _, r := range o.Rules {
		if count(post, r) < count(pre, r) {
			o.FixRecognized = true
		}
	}
	return o
}

// Summary aggregates the outcomes of one engine.
type Summary struct {
	Engine  string `json:"engine"`
	Version string `json:"version,omitempty"`
	NotRun  string `json:"not_run,omitempty"`
	// Scored counts CVEs whose both commits were checked out and scanned.
	Scored        int `json:"scored"`
	Detected      int `json:"detected"`
	CWEMatch      int `json:"detected_with_cwe_match"`
	FixRecognized int `json:"fix_recognized"`
	StillFlagged  int `json:"still_flagged_after_fix"`
	// DetectionRate is Detected / Scored; FixRate is FixRecognized / Detected.
	DetectionRate float64        `json:"detection_rate"`
	FixRate       float64        `json:"fix_recognized_rate"`
	ByCWE         []CWESummary   `json:"by_cwe"`
	Rules         map[string]int `json:"detecting_rules"`
	Outcomes      []Outcome      `json:"outcomes"`
	byCWE         map[int]*CWESummary
}

// CWESummary is the detection for the CVEs whose first CWE is CWE.
type CWESummary struct {
	CWE           int `json:"cwe"`
	Scored        int `json:"scored"`
	Detected      int `json:"detected"`
	FixRecognized int `json:"fix_recognized"`
}

// Add counts one outcome.
func (s *Summary) Add(o Outcome) {
	if s.byCWE == nil {
		s.byCWE = map[int]*CWESummary{}
		s.Rules = map[string]int{}
	}
	s.Scored++
	c := s.byCWE[o.CWE]
	if c == nil {
		c = &CWESummary{CWE: o.CWE}
		s.byCWE[o.CWE] = c
	}
	c.Scored++
	if o.Detected {
		s.Detected++
		c.Detected++
		if o.CWEMatch {
			s.CWEMatch++
		}
		if o.FixRecognized {
			s.FixRecognized++
			c.FixRecognized++
		} else {
			s.StillFlagged++
		}
		for _, r := range o.Rules {
			s.Rules[r]++
		}
	}
	s.Outcomes = append(s.Outcomes, o)
}

// Finish computes rates and orders the per-CWE rows by size.
func (s *Summary) Finish() {
	if s.Scored > 0 {
		s.DetectionRate = float64(s.Detected) / float64(s.Scored)
	}
	if s.Detected > 0 {
		s.FixRate = float64(s.FixRecognized) / float64(s.Detected)
	}
	s.ByCWE = s.ByCWE[:0]
	for _, c := range s.byCWE {
		s.ByCWE = append(s.ByCWE, *c)
	}
	sort.Slice(s.ByCWE, func(i, j int) bool {
		if s.ByCWE[i].Scored != s.ByCWE[j].Scored {
			return s.ByCWE[i].Scored > s.ByCWE[j].Scored
		}
		return s.ByCWE[i].CWE < s.ByCWE[j].CWE
	})
}
