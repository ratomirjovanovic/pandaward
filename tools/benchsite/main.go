// Command benchsite renders the benchmark page of pandaward.dev from
// measurement snapshots. A snapshot is a directory with meta.json and the
// JSON output of tools/owaspbench (owasp-java.json, owasp-python.json) and
// tools/cvebench (cve.json); any of the three may be missing. Snapshots come
// from site/benchmarks/snapshots (committed measurements of main) and from
// release assets fetched by site/build.sh.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Meta describes where a snapshot comes from.
type Meta struct {
	// Label is what the page shows, such as "0.2.15" or "main, 2026-11-09".
	Label string `json:"label"`
	// Date is the measurement or release date, YYYY-MM-DD.
	Date string `json:"date"`
	// URL is the release page or the commit the numbers belong to.
	URL string `json:"url"`
	// Assets maps a file name (owasp-java.json, ...) to its download URL,
	// for release snapshots.
	Assets map[string]string `json:"assets,omitempty"`
}

// Snapshot is one set of measurements.
type Snapshot struct {
	Meta
	ID     string
	Suites []Suite
	CVE    *CVE
}

// Suite is one OWASP Benchmark measured on several engines.
type Suite struct {
	Key, Title, Commit, Asset string
	Categories                []string
	Engines                   []Engine
}

// Engine is one engine's result on a suite.
type Engine struct {
	Name, Version  string
	NotRun         string
	AverageCovered float64
	AverageAll     float64
	Covered        int
	Scores         map[string]*float64 // category -> score; nil when not covered
}

// CVE is the OpenSSF CVE Benchmark result.
type CVE struct {
	Commit, Asset string
	Scored        int
	Unavailable   int
	Engines       []CVEEngine
}

// CVEEngine is one engine's CVE result.
type CVEEngine struct {
	Name, Version, NotRun                         string
	Scored, Detected, CWEMatch, Fixed, StillFlagd int
	Rate                                          float64
}

type owaspJSON struct {
	Benchmark       string `json:"benchmark"`
	BenchmarkCommit string `json:"benchmark_commit"`
	Engines         []struct {
		Engine         string  `json:"engine"`
		Version        string  `json:"version"`
		NotRun         string  `json:"not_run"`
		AverageCovered float64 `json:"average_score_covered"`
		AverageAll     float64 `json:"average_score_all"`
		Categories     []struct {
			Category string  `json:"category"`
			Covered  bool    `json:"covered"`
			Score    float64 `json:"score"`
		} `json:"categories"`
	} `json:"engines"`
}

type cveJSON struct {
	BenchmarkCommit string   `json:"benchmark_commit"`
	Unavailable     []string `json:"unavailable"`
	Engines         []struct {
		Engine        string  `json:"engine"`
		Version       string  `json:"version"`
		NotRun        string  `json:"not_run"`
		Scored        int     `json:"scored"`
		Detected      int     `json:"detected"`
		CWEMatch      int     `json:"detected_with_cwe_match"`
		FixRecognized int     `json:"fix_recognized"`
		StillFlagged  int     `json:"still_flagged_after_fix"`
		Rate          float64 `json:"detection_rate"`
	} `json:"engines"`
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	var dirs multi
	flag.Var(&dirs, "snapshots", "directory holding snapshot directories (repeatable)")
	out := flag.String("out", "", "HTML file to write (required)")
	flag.Parse()
	if *out == "" || len(dirs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: benchsite --snapshots dir [--snapshots dir]... --out index.html")
		os.Exit(2)
	}
	snaps, err := Load(dirs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchsite:", err)
		os.Exit(1)
	}
	if len(snaps) == 0 {
		fmt.Fprintln(os.Stderr, "benchsite: no snapshots found")
		os.Exit(1)
	}
	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchsite:", err)
		os.Exit(1)
	}
	defer f.Close()
	if err := Render(f, snaps); err != nil {
		fmt.Fprintln(os.Stderr, "benchsite:", err)
		os.Exit(1)
	}
}

// Load reads every snapshot below the given directories, newest first. A
// snapshot without any result file is skipped.
func Load(dirs []string) ([]Snapshot, error) {
	var out []Snapshot
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			s, ok, err := loadOne(filepath.Join(d, e.Name()))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", e.Name(), err)
			}
			if ok {
				s.ID = e.Name()
				out = append(out, s)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Date != out[j].Date {
			return out[i].Date > out[j].Date
		}
		return out[i].Label > out[j].Label
	})
	return out, nil
}

func loadOne(dir string) (Snapshot, bool, error) {
	var s Snapshot
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return s, false, err
	}
	if err := json.Unmarshal(b, &s.Meta); err != nil {
		return s, false, fmt.Errorf("meta.json: %w", err)
	}
	if s.Label == "" || s.Date == "" || s.URL == "" {
		return s, false, fmt.Errorf("meta.json needs label, date and url")
	}
	for _, f := range []struct{ file, key, title string }{
		{"owasp-java.json", "java", "OWASP Benchmark for Java"},
		{"owasp-python.json", "python", "OWASP Benchmark for Python"},
	} {
		b, err := os.ReadFile(filepath.Join(dir, f.file))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return s, false, err
		}
		suite, err := parseOWASP(b, f.key, f.title)
		if err != nil {
			return s, false, fmt.Errorf("%s: %w", f.file, err)
		}
		suite.Asset = s.Assets[f.file]
		s.Suites = append(s.Suites, suite)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cve.json")); err == nil {
		c, err := parseCVE(b)
		if err != nil {
			return s, false, fmt.Errorf("cve.json: %w", err)
		}
		c.Asset = s.Assets["cve.json"]
		s.CVE = c
	} else if !errors.Is(err, os.ErrNotExist) {
		return s, false, err
	}
	return s, len(s.Suites) > 0 || s.CVE != nil, nil
}

func parseOWASP(b []byte, key, title string) (Suite, error) {
	var o owaspJSON
	if err := json.Unmarshal(b, &o); err != nil {
		return Suite{}, err
	}
	s := Suite{Key: key, Title: title, Commit: o.BenchmarkCommit}
	seen := map[string]bool{}
	for _, e := range o.Engines {
		if e.Engine == "all" {
			continue
		}
		eng := Engine{Name: e.Engine, Version: e.Version, NotRun: e.NotRun, AverageCovered: e.AverageCovered, AverageAll: e.AverageAll, Scores: map[string]*float64{}}
		for _, c := range e.Categories {
			if !seen[c.Category] {
				seen[c.Category] = true
				s.Categories = append(s.Categories, c.Category)
			}
			if c.Covered {
				v := c.Score
				eng.Scores[c.Category] = &v
				eng.Covered++
			}
		}
		s.Engines = append(s.Engines, eng)
	}
	if len(s.Engines) == 0 {
		return s, fmt.Errorf("no engine results")
	}
	return s, nil
}

func parseCVE(b []byte) (*CVE, error) {
	var o cveJSON
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, err
	}
	c := &CVE{Commit: o.BenchmarkCommit, Unavailable: len(o.Unavailable)}
	for _, e := range o.Engines {
		c.Engines = append(c.Engines, CVEEngine{Name: e.Engine, Version: e.Version, NotRun: e.NotRun, Scored: e.Scored, Detected: e.Detected, CWEMatch: e.CWEMatch, Fixed: e.FixRecognized, StillFlagd: e.StillFlagged, Rate: e.Rate})
		if e.Scored > c.Scored {
			c.Scored = e.Scored
		}
	}
	if len(c.Engines) == 0 {
		return nil, fmt.Errorf("no engine results")
	}
	return c, nil
}

var engineLabel = map[string]string{"builtin": "Built-in rules", "semgrep": "Semgrep", "opengrep": "Opengrep"}

var funcs = template.FuncMap{
	"engine": func(name string) string {
		if l, ok := engineLabel[name]; ok {
			return l
		}
		return name
	},
	"score": func(v float64) string {
		s := fmt.Sprintf("%+.3f", v)
		if s == "-0.000" || s == "+0.000" {
			return "0.000"
		}
		return s
	},
	"pct":   func(v float64) string { return fmt.Sprintf("%.1f%%", 100*v) },
	"ver":   EngineVersion,
	"short": func(s string) string { return shortCommit(s) },
	"cat": func(e Engine, c string) string {
		v := e.Scores[c]
		if v == nil {
			return "-"
		}
		s := fmt.Sprintf("%+.3f", *v)
		if s == "-0.000" || s == "+0.000" {
			return "0.000"
		}
		return s
	},
	"suite": func(s Snapshot, key string) *Suite {
		for i := range s.Suites {
			if s.Suites[i].Key == key {
				return &s.Suites[i]
			}
		}
		return nil
	},
	"eng": func(s *Suite, name string) *Engine {
		if s == nil {
			return nil
		}
		for i := range s.Engines {
			if s.Engines[i].Name == name && s.Engines[i].NotRun == "" {
				return &s.Engines[i]
			}
		}
		return nil
	},
	"cveeng": func(c *CVE, name string) *CVEEngine {
		if c == nil {
			return nil
		}
		for i := range c.Engines {
			if c.Engines[i].Name == name && c.Engines[i].NotRun == "" {
				return &c.Engines[i]
			}
		}
		return nil
	},
	"engines": func() []string { return []string{"builtin", "semgrep", "opengrep"} },
}

func shortCommit(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

// Render writes the page.
func Render(w interface{ Write([]byte) (int, error) }, snaps []Snapshot) error {
	t, err := template.New("page").Funcs(funcs).Parse(page)
	if err != nil {
		return err
	}
	return t.Execute(w, struct {
		Latest  Snapshot
		History []Snapshot
	}{snaps[0], snaps})
}

// EngineVersion is the version shown under an engine name: without a
// repeated engine name, and empty for a source build ("dev" or a Go
// pseudo-version), which the snapshot's source link identifies instead.
func EngineVersion(name, v string) string {
	v = strings.TrimSpace(strings.TrimPrefix(v, name))
	if v == "dev" || strings.Count(v, "-") >= 2 {
		return ""
	}
	return v
}
