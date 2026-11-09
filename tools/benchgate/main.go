// Command benchgate compares benchmark results with the committed baseline
// and fails when a score drops. It reads the JSON output of
// tools/owaspbench (one file per suite) and tools/cvebench.
//
// Scores never drop silently: raising the baseline is an explicit change to
// baseline.json in a pull request (run with --update and commit the file).
// Lowering it needs the same explicit change, with the reason in the pull
// request.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// tolerance absorbs floating point noise; the benchmarks are deterministic.
const tolerance = 0.0005

// Baseline holds the scores that must not drop, keyed by
// "owasp/<suite>/<engine>" and "cve/<engine>".
type Baseline struct {
	Note   string            `json:"note"`
	Scores map[string]Scores `json:"scores"`
}

// Scores are the gated numbers of one suite and engine.
type Scores struct {
	// AverageCovered is the OWASP average score over covered categories.
	AverageCovered *float64 `json:"average_score_covered,omitempty"`
	// Categories are OWASP per-category scores.
	Categories map[string]float64 `json:"categories,omitempty"`
	// Detected and FixRecognized are CVE benchmark counts.
	Detected      *int `json:"detected,omitempty"`
	FixRecognized *int `json:"fix_recognized,omitempty"`
}

type owaspOutput struct {
	Benchmark string `json:"benchmark"`
	Engines   []struct {
		Engine         string  `json:"engine"`
		NotRun         string  `json:"not_run"`
		AverageCovered float64 `json:"average_score_covered"`
		Categories     []struct {
			Category string  `json:"category"`
			Covered  bool    `json:"covered"`
			Score    float64 `json:"score"`
		} `json:"categories"`
	} `json:"engines"`
}

type cveOutput struct {
	Engines []struct {
		Engine        string `json:"engine"`
		NotRun        string `json:"not_run"`
		Detected      int    `json:"detected"`
		FixRecognized int    `json:"fix_recognized"`
	} `json:"engines"`
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	baselinePath := flag.String("baseline", "tools/benchgate/baseline.json", "baseline file")
	var owasp, cve multi
	flag.Var(&owasp, "owasp", "owaspbench --json output (repeatable)")
	flag.Var(&cve, "cve", "cvebench --json output (repeatable)")
	update := flag.Bool("update", false, "write the measured scores into the baseline instead of comparing")
	flag.Parse()
	if len(owasp)+len(cve) == 0 {
		fmt.Fprintln(os.Stderr, "usage: benchgate [--baseline file] [--owasp file]... [--cve file]... [--update]")
		os.Exit(2)
	}
	got, err := collect(owasp, cve)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchgate:", err)
		os.Exit(1)
	}
	var base Baseline
	if b, err := os.ReadFile(*baselinePath); err == nil {
		if err := json.Unmarshal(b, &base); err != nil {
			fmt.Fprintln(os.Stderr, "benchgate:", *baselinePath+":", err)
			os.Exit(1)
		}
	} else if !*update {
		fmt.Fprintln(os.Stderr, "benchgate:", err)
		os.Exit(1)
	}
	if *update {
		if base.Scores == nil {
			base.Scores = map[string]Scores{}
		}
		if base.Note == "" {
			base.Note = "Scores that must not drop. Raise them with `go run ./tools/benchgate --update` and commit; see docs/BENCHMARKS.md."
		}
		for k, v := range got {
			base.Scores[k] = v
		}
		b, _ := json.MarshalIndent(base, "", "  ")
		if err := os.WriteFile(*baselinePath, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "benchgate:", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %d entries to %s\n", len(got), *baselinePath)
		return
	}
	lines, failed := Compare(base, got)
	for _, l := range lines {
		fmt.Println(l)
	}
	if failed > 0 {
		fmt.Printf("\n%d score(s) dropped below the baseline\n", failed)
		os.Exit(1)
	}
	fmt.Println("\nno score below the baseline")
}

func collect(owasp, cve []string) (map[string]Scores, error) {
	out := map[string]Scores{}
	for _, p := range owasp {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var o owaspOutput
		if err := json.Unmarshal(b, &o); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		suite := ""
		switch {
		case strings.Contains(o.Benchmark, "Java"):
			suite = "java"
		case strings.Contains(o.Benchmark, "Python"):
			suite = "python"
		default:
			return nil, fmt.Errorf("%s: unknown benchmark %q", p, o.Benchmark)
		}
		for _, e := range o.Engines {
			if e.NotRun != "" {
				continue
			}
			avg := e.AverageCovered
			s := Scores{AverageCovered: &avg, Categories: map[string]float64{}}
			for _, c := range e.Categories {
				if c.Covered {
					s.Categories[c.Category] = c.Score
				}
			}
			out["owasp/"+suite+"/"+e.Engine] = s
		}
	}
	for _, p := range cve {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var o cveOutput
		if err := json.Unmarshal(b, &o); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, e := range o.Engines {
			if e.NotRun != "" {
				continue
			}
			d, f := e.Detected, e.FixRecognized
			out["cve/"+e.Engine] = Scores{Detected: &d, FixRecognized: &f}
		}
	}
	return out, nil
}

// Compare checks every measured entry that has a baseline. A baseline entry
// that was not measured fails too: an engine that silently stops running
// must not pass the gate. Entries measured without a baseline are listed.
func Compare(base Baseline, got map[string]Scores) ([]string, int) {
	var lines []string
	failed := 0
	keys := map[string]bool{}
	for k := range base.Scores {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	measured := map[string]bool{}
	for k := range got {
		measured[strings.SplitN(k, "/", 2)[0]] = true
	}
	for _, k := range sorted {
		b, hasBase := base.Scores[k]
		g, hasGot := got[k]
		switch {
		case !hasBase:
			lines = append(lines, fmt.Sprintf("NEW   %s (no baseline yet)", k))
			continue
		case !hasGot:
			// Only a benchmark that was run at all can miss an entry.
			if measured[strings.SplitN(k, "/", 2)[0]] && sameSuite(k, got) {
				lines = append(lines, fmt.Sprintf("FAIL  %s was not measured (engine missing or not run)", k))
				failed++
			}
			continue
		}
		check := func(name string, base, now float64) {
			status := "ok   "
			if now < base-tolerance {
				status = "FAIL "
				failed++
			}
			lines = append(lines, fmt.Sprintf("%s %s %s: %.4f (baseline %.4f)", status, k, name, now, base))
		}
		if b.AverageCovered != nil && g.AverageCovered != nil {
			check("average", *b.AverageCovered, *g.AverageCovered)
		}
		cats := make([]string, 0, len(b.Categories))
		for c := range b.Categories {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			now, ok := g.Categories[c]
			if !ok {
				lines = append(lines, fmt.Sprintf("FAIL  %s %s is no longer covered", k, c))
				failed++
				continue
			}
			check(c, b.Categories[c], now)
		}
		if b.Detected != nil && g.Detected != nil {
			check("detected", float64(*b.Detected), float64(*g.Detected))
		}
		if b.FixRecognized != nil && g.FixRecognized != nil {
			check("fix recognized", float64(*b.FixRecognized), float64(*g.FixRecognized))
		}
	}
	return lines, failed
}

// sameSuite reports whether got has any entry of k's suite, so a gate run
// for Java does not fail on missing Python entries.
func sameSuite(k string, got map[string]Scores) bool {
	i := strings.LastIndex(k, "/")
	prefix := k[:i+1]
	for g := range got {
		if strings.HasPrefix(g, prefix) {
			return true
		}
	}
	return false
}
