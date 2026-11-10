package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// parseShard reads "i/n" (0 <= i < n); "" means no sharding, 0 of 1.
func parseShard(s string) (int, int, error) {
	if s == "" {
		return 0, 1, nil
	}
	a, b, ok := strings.Cut(s, "/")
	i, err1 := strconv.Atoi(strings.TrimSpace(a))
	n, err2 := strconv.Atoi(strings.TrimSpace(b))
	if !ok || err1 != nil || err2 != nil || n < 1 || i < 0 || i >= n {
		return 0, 0, fmt.Errorf("--shard %q: want i/n with 0 <= i < n", s)
	}
	return i, n, nil
}

// shardOf keeps the CVEs whose position in the sorted list is i modulo n,
// so the shards of one list are disjoint and cover it.
func shardOf(cves []CVE, i, n int) []CVE {
	if n <= 1 {
		return cves
	}
	var out []CVE
	for k, c := range cves {
		if k%n == i {
			out = append(out, c)
		}
	}
	return out
}

// runMerge reads cvebench --json outputs of the shards of one run and
// prints one output, with every summary recomputed from the per-CVE
// outcomes.
func runMerge(files []string) error {
	if len(files) == 0 {
		return fmt.Errorf("usage: cvebench merge shard.json...")
	}
	var parts []*Output
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var o Output
		if err := json.Unmarshal(b, &o); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		parts = append(parts, &o)
	}
	out, err := Merge(parts)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// Merge combines shard outputs. They must come from the same benchmark
// commit, PandaWard build and rule set.
func Merge(parts []*Output) (*Output, error) {
	first := parts[0]
	out := &Output{Benchmark: first.Benchmark, BenchmarkCommit: first.BenchmarkCommit, PandawardVersion: first.PandawardVersion,
		SemgrepRulesHash: first.SemgrepRulesHash, SkippedEntries: first.SkippedEntries, Unavailable: []string{}}
	sums := map[string]*Summary{}
	for _, p := range parts {
		if p.BenchmarkCommit != first.BenchmarkCommit || p.PandawardVersion != first.PandawardVersion || p.SemgrepRulesHash != first.SemgrepRulesHash {
			return nil, fmt.Errorf("shards come from different runs (benchmark %s/%s, version %s/%s, rules %s/%s)",
				first.BenchmarkCommit, p.BenchmarkCommit, first.PandawardVersion, p.PandawardVersion, first.SemgrepRulesHash, p.SemgrepRulesHash)
		}
		out.CVEs += p.CVEs
		out.Unavailable = append(out.Unavailable, p.Unavailable...)
		for _, e := range p.Engines {
			s := sums[e.Engine]
			if s == nil {
				s = &Summary{Engine: e.Engine}
				sums[e.Engine] = s
				out.Engines = append(out.Engines, s)
			}
			if s.Version == "" {
				s.Version = e.Version
			}
			if e.NotRun != "" && s.NotRun == "" {
				s.NotRun = e.NotRun
			}
			for _, o := range e.Outcomes {
				s.Add(o)
			}
		}
	}
	for _, s := range out.Engines {
		s.Finish()
	}
	sort.Strings(out.Unavailable)
	return out, nil
}
