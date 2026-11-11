// Command cvebench measures PandaWard on the OpenSSF CVE Benchmark
// (https://github.com/ossf-cve-benchmark/ossf-cve-benchmark): real CVEs in
// JavaScript and TypeScript projects, each with the commit before and after
// the fix and the vulnerable lines. For every CVE it checks out both commits,
// runs the selected engines on each and scores:
//
//   - detected: a finding covers a labelled vulnerable line before the fix;
//   - fix recognized: a detecting rule reports fewer findings in the
//     vulnerable files after the fix; otherwise the CVE is still flagged
//     when fixed;
//   - missed: no finding on a vulnerable line.
//
// Project checkouts are only read: hooks, LFS, symlinks and global git
// configuration are off, and nothing from them is built, installed or run.
// Use tools/cvebench/run.sh to fetch the pinned benchmark and run it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/version"
	"github.com/ratomirjovanovic/pandaward/rules"
	"github.com/ratomirjovanovic/pandaward/tools/internal/engines"
)

// PinnedCommit is the ossf-cve-benchmark commit the published numbers
// refer to; run.sh checks out the same commit.
const PinnedCommit = "91c59fd54b2b768c0f310bb0027d2ac59cdf74d4"

// Output is the JSON document printed with --json.
type Output struct {
	Benchmark        string     `json:"benchmark"`
	BenchmarkCommit  string     `json:"benchmark_commit"`
	PandawardVersion string     `json:"pandaward_version"`
	SemgrepRulesHash string     `json:"semgrep_rules_sha256"`
	CVEs             int        `json:"cves"`
	SkippedEntries   int        `json:"skipped_entries"`
	Unavailable      []string   `json:"unavailable"`
	Engines          []*Summary `json:"engines"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "merge" {
		if err := runMerge(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "cvebench merge:", err)
			os.Exit(1)
		}
		return
	}
	bench := flag.String("bench", "", "path to an ossf-cve-benchmark checkout (required)")
	work := flag.String("work", "", "directory for project checkouts, reused between runs (required)")
	engineList := flag.String("engine", "builtin", "comma-separated engines to measure: "+strings.Join(engines.Names, ", "))
	only := flag.String("cve", "", "comma-separated CVE ids to measure (default: all)")
	limit := flag.Int("limit", 0, "measure only the first N CVEs (0: all)")
	jobs := flag.Int("jobs", 2, "CVEs measured in parallel")
	asJSON := flag.Bool("json", false, "print JSON instead of a table")
	shardFlag := flag.String("shard", "", "measure one shard i/n of the CVEs, such as 0/8, for parallel jobs; combine with `cvebench merge`")
	flag.Parse()
	shard, shards, err := parseShard(*shardFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cvebench:", err)
		os.Exit(2)
	}
	if *bench == "" || *work == "" {
		fmt.Fprintln(os.Stderr, "usage: cvebench --bench <ossf-cve-benchmark checkout> --work <dir> [--engine builtin,semgrep,opengrep] [--cve ids] [--limit n] [--json]")
		os.Exit(2)
	}
	sel, err := engines.Parse(*engineList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cvebench:", err)
		os.Exit(2)
	}
	out, err := measure(context.Background(), *bench, *work, sel, *only, *limit, *jobs, shard, shards)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cvebench:", err)
		os.Exit(1)
	}
	if out.BenchmarkCommit != PinnedCommit {
		fmt.Fprintf(os.Stderr, "warning: benchmark is at %q, published numbers refer to %s\n", out.BenchmarkCommit, PinnedCommit)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	printTable(out)
}

func measure(ctx context.Context, bench, work string, selected []string, only string, limit, jobs, shard, shards int) (*Output, error) {
	cves, skipped, err := LoadCVEs(bench)
	if err != nil {
		return nil, err
	}
	if only != "" {
		want := map[string]bool{}
		for _, id := range strings.Split(only, ",") {
			want[strings.TrimSpace(id)] = true
		}
		var keep []CVE
		for _, c := range cves {
			if want[c.ID] {
				keep = append(keep, c)
			}
		}
		cves = keep
	}
	if limit > 0 && len(cves) > limit {
		cves = cves[:limit]
	}
	cves = shardOf(cves, shard, shards)
	hash, err := rules.SemgrepHash()
	if err != nil {
		return nil, err
	}
	// Each CVE's result is appended to a journal in the work directory as
	// soon as it is measured, so an interrupted run continues where it
	// stopped. The journal is keyed by the engines, the rule set and the
	// PandaWard version: results of other rules are never mixed in.
	journal := filepath.Join(work, fmt.Sprintf("results-%s-%s-%s.jsonl", strings.Join(selected, "+"), hash[:12], safeName(version.Version)))
	done, err := readJournal(journal)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	jf, err := os.OpenFile(journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer jf.Close()
	out := &Output{Benchmark: "OpenSSF CVE Benchmark", BenchmarkCommit: gitHead(bench), PandawardVersion: version.Version, SemgrepRulesHash: hash, CVEs: len(cves), SkippedEntries: skipped}
	sums := map[string]*Summary{}
	if sg := combinedSemgrep(selected); sg != "" {
		sums[Combined] = &Summary{Engine: Combined, Version: "built-in + " + sg}
		out.Engines = append(out.Engines, sums[Combined])
	}
	for _, e := range selected {
		sums[e] = &Summary{Engine: e}
		out.Engines = append(out.Engines, sums[e])
	}
	if jobs < 1 {
		jobs = 1
	}
	var mu sync.Mutex
	var firstErr error
	prog := newProgress(len(cves))
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for _, c := range cves {
		wg.Add(1)
		sem <- struct{}{}
		go func(c CVE) {
			defer wg.Done()
			defer func() { <-sem }()
			rec, ok := done[c.ID]
			// A journal entry written before the combined score existed is
			// measured again rather than counted without it.
			if ok && !rec.Unavailable && combinedSemgrep(selected) != "" && !hasEngine(rec.Outcomes, Combined) && rec.NotRun[Combined] == "" {
				ok = false
			}
			var err error
			if !ok {
				rec = record{CVE: c.ID}
				rec.Outcomes, rec.NotRun, rec.Versions, err = measureCVE(ctx, c, work, selected)
				if errors.Is(err, errUnavailable) {
					rec.Unavailable, rec.Reason, err = true, err.Error(), nil
				}
			}
			mu.Lock()
			defer mu.Unlock()
			fmt.Fprintf(os.Stderr, "%s %s", prog.next(!ok), c.ID)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", c.ID, err)
				}
				fmt.Fprintf(os.Stderr, ": %v\n", err)
				return
			}
			if !ok {
				if werr := appendJournal(jf, rec); werr != nil && firstErr == nil {
					firstErr = werr
				}
			} else {
				fmt.Fprint(os.Stderr, " (from journal)")
			}
			if rec.Unavailable {
				out.Unavailable = append(out.Unavailable, c.ID)
				fmt.Fprintf(os.Stderr, ": unavailable (%s)\n", rec.Reason)
				return
			}
			fmt.Fprintln(os.Stderr)
			for e, why := range rec.NotRun {
				sums[e].NotRun = why
			}
			for e, v := range rec.Versions {
				if v != "" {
					sums[e].Version = v
				}
			}
			for _, o := range rec.Outcomes {
				sums[o.Engine].Add(o)
			}
		}(c)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	for _, s := range out.Engines {
		s.Finish()
	}
	sort.Strings(out.Unavailable)
	return out, nil
}

var errUnavailable = errors.New("commit not available")

// record is one CVE's result in the journal.
type record struct {
	CVE         string            `json:"cve"`
	Unavailable bool              `json:"unavailable,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Outcomes    []Outcome         `json:"outcomes,omitempty"`
	NotRun      map[string]string `json:"not_run,omitempty"`
	Versions    map[string]string `json:"versions,omitempty"`
}

// readJournal loads the results of an earlier run. A torn last line, from a
// run killed while writing, is ignored and measured again.
func readJournal(p string) (map[string]record, error) {
	out := map[string]record{}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r record
		if json.Unmarshal([]byte(line), &r) == nil && r.CVE != "" {
			out[r.CVE] = r
		}
	}
	return out, nil
}

func appendJournal(f *os.File, r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, s)
}

// measureCVE checks out both commits of one CVE and runs every engine on
// each. An engine that is not installed is reported in notRun.
func measureCVE(ctx context.Context, c CVE, work string, selected []string) ([]Outcome, map[string]string, map[string]string, error) {
	pre, err := checkout(ctx, c.Repository, c.PrePatch.Commit, filepath.Join(work, c.ID, "pre"))
	if err != nil {
		return nil, nil, nil, err
	}
	post, err := checkout(ctx, c.Repository, c.PostPatch.Commit, filepath.Join(work, c.ID, "post"))
	if err != nil {
		return nil, nil, nil, err
	}
	invPre, err := engines.Walk(pre)
	if err != nil {
		return nil, nil, nil, err
	}
	invPost, err := engines.Walk(post)
	if err != nil {
		return nil, nil, nil, err
	}
	var outcomes []Outcome
	notRun, versions := map[string]string{}, map[string]string{}
	pre1, post1 := map[string][]engines.Finding{}, map[string][]engines.Finding{}
	for _, e := range selected {
		rp, err := engines.Measure(ctx, invPre, e)
		if err != nil {
			return nil, nil, nil, err
		}
		versions[e] = rp.Version
		if rp.NotRun != "" {
			notRun[e] = rp.NotRun
			continue
		}
		ra, err := engines.Measure(ctx, invPost, e)
		if err != nil {
			return nil, nil, nil, err
		}
		pre1[e], post1[e] = rp.Findings, ra.Findings
		outcomes = append(outcomes, Score(c, e, rp.Findings, ra.Findings))
	}
	if sg := combinedSemgrep(selected); sg != "" {
		_, okB := pre1["builtin"]
		_, okS := pre1[sg]
		if okB && okS {
			outcomes = append(outcomes, Score(c, Combined, merge(pre1["builtin"], pre1[sg]), merge(post1["builtin"], post1[sg])))
		} else {
			notRun[Combined] = "needs the built-in engine and " + sg
		}
	}
	return outcomes, notRun, versions, nil
}

// Combined is the engine name of PandaWard as a whole: the built-in rules
// plus the Semgrep rules, as a scan runs them. JavaScript findings of the
// built-in rules are not superseded by Semgrep, so both count.
const Combined = "pandaward"

// merge returns the findings of two engines as one list. Rule ids of the
// built-in rules (code.*) and of Semgrep (semgrep.*) never collide, so a
// fix is still judged per rule.
func merge(a, b []engines.Finding) []engines.Finding {
	return append(append(make([]engines.Finding, 0, len(a)+len(b)), a...), b...)
}

func hasEngine(outs []Outcome, engine string) bool {
	for _, o := range outs {
		if o.Engine == engine {
			return true
		}
	}
	return false
}

// combinedSemgrep returns the Semgrep engine the combined score uses:
// semgrep, the scan's default, or opengrep when only that was selected; ""
// when the built-in engine or both Semgrep engines are missing.
func combinedSemgrep(selected []string) string {
	has := map[string]bool{}
	for _, e := range selected {
		has[e] = true
	}
	switch {
	case !has["builtin"]:
		return ""
	case has["semgrep"]:
		return "semgrep"
	case has["opengrep"]:
		return "opengrep"
	}
	return ""
}

// checkout fetches one commit of a repository into dir, or reuses dir when
// it already holds that commit. Only the commit itself is fetched, with
// hooks, LFS, symlinks and the user's git configuration off.
func checkout(ctx context.Context, repo, commit, dir string) (string, error) {
	if gitHead(dir) == commit {
		return dir, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	for _, args := range [][]string{
		{"init", "-q"},
		{"fetch", "-q", "--depth", "1", "--no-tags", repo, commit},
		{"checkout", "-q", "FETCH_HEAD"},
	} {
		if out, err := git(cctx, dir, args...); err != nil {
			if args[0] == "init" {
				return "", fmt.Errorf("git init: %v %s", err, firstLine(out))
			}
			// A commit that cannot be fetched or checked out on this
			// machine (gone, or a path the file system refuses) is
			// unavailable, not a failed measurement.
			return "", fmt.Errorf("%w: git %s: %s", errUnavailable, args[0], firstLine(out))
		}
	}
	if got := gitHead(dir); got != commit {
		return "", fmt.Errorf("checkout is at %q, want %s", got, commit)
	}
	return dir, nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	base := []string{"-C", dir, "-c", "core.hooksPath=" + os.DevNull, "-c", "core.autocrlf=false", "-c", "core.symlinks=false", "-c", "core.longpaths=true", "-c", "core.fsmonitor=false", "-c", "protocol.file.allow=never"}
	cmd := exec.CommandContext(ctx, "git", append(base, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_ASKPASS=", "SSH_ASKPASS=")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func gitHead(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return ""
	}
	out, err := git(context.Background(), dir, "rev-parse", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func printTable(o *Output) {
	fmt.Printf("%s at %s, PandaWard %s, bundled Semgrep rules sha256 %s\n", o.Benchmark, o.BenchmarkCommit, o.PandawardVersion, o.SemgrepRulesHash)
	fmt.Printf("%d CVEs selected, %d entries skipped (not published or incomplete), %d unavailable (commit could not be fetched)\n\n", o.CVEs, o.SkippedEntries, len(o.Unavailable))
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ENGINE\tSCORED\tDETECTED\tRATE\tCWE MATCH\tFIX RECOGNIZED\tSTILL FLAGGED\tFIX RATE")
	for _, s := range o.Engines {
		name := s.Engine
		if s.Version != "" && !strings.HasPrefix(s.Version, s.Engine) {
			name += " " + s.Version
		} else if s.Version != "" {
			name = s.Version
		}
		if s.NotRun != "" {
			fmt.Fprintf(tw, "%s\tnot run: %s\n", name, s.NotRun)
			continue
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%.3f\t%d\t%d\t%d\t%.3f\n", name, s.Scored, s.Detected, s.DetectionRate, s.CWEMatch, s.FixRecognized, s.StillFlagged, s.FixRate)
	}
	tw.Flush()
	for _, s := range o.Engines {
		if s.NotRun != "" || s.Scored == 0 {
			continue
		}
		fmt.Printf("\n== %s by first CWE\n", s.Engine)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "CWE\tSCORED\tDETECTED\tFIX RECOGNIZED")
		for _, c := range s.ByCWE {
			fmt.Fprintf(tw, "CWE-%d\t%d\t%d\t%d\n", c.CWE, c.Scored, c.Detected, c.FixRecognized)
		}
		tw.Flush()
	}
}
