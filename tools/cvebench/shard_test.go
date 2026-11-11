package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestShard(t *testing.T) {
	if _, _, err := parseShard("8/8"); err == nil {
		t.Error("8/8 accepted")
	}
	if i, n, err := parseShard(""); err != nil || i != 0 || n != 1 {
		t.Errorf("empty = %d/%d %v", i, n, err)
	}
	var cves []CVE
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		cves = append(cves, CVE{ID: id})
	}
	seen := map[string]int{}
	for i := 0; i < 3; i++ {
		for _, c := range shardOf(cves, i, 3) {
			seen[c.ID]++
		}
	}
	if len(seen) != 5 {
		t.Fatalf("shards cover %v", seen)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("%s in %d shards", id, n)
		}
	}
}

// Merging shard outputs gives the same summaries as one run over all CVEs.
func TestMergeEqualsWholeRun(t *testing.T) {
	outcomes := []Outcome{
		{CVE: "CVE-1", CWE: 79, Engine: "builtin", Detected: true, Rules: []string{"code.html-sink"}, FixRecognized: true},
		{CVE: "CVE-2", CWE: 78, Engine: "builtin", Detected: true, Rules: []string{"code.js-shell"}},
		{CVE: "CVE-3", CWE: 79, Engine: "builtin"},
	}
	whole := &Output{Benchmark: "b", BenchmarkCommit: "c", PandawardVersion: "v", SemgrepRulesHash: "h", CVEs: 4, Unavailable: []string{"CVE-4"}}
	ws := &Summary{Engine: "builtin", Version: "v"}
	for _, o := range outcomes {
		ws.Add(o)
	}
	ws.Finish()
	whole.Engines = []*Summary{ws}

	var parts []*Output
	for i, group := range [][]Outcome{{outcomes[2]}, {outcomes[0], outcomes[1]}} {
		p := &Output{Benchmark: "b", BenchmarkCommit: "c", PandawardVersion: "v", SemgrepRulesHash: "h", CVEs: len(group), Unavailable: []string{}}
		if i == 0 {
			p.CVEs++
			p.Unavailable = []string{"CVE-4"}
		}
		s := &Summary{Engine: "builtin", Version: "v"}
		for _, o := range group {
			s.Add(o)
		}
		s.Finish()
		p.Engines = []*Summary{s}
		// Round-trip through JSON, as the shard files are.
		b, _ := json.Marshal(p)
		var q Output
		if err := json.Unmarshal(b, &q); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, &q)
	}
	merged, err := Merge(parts)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(whole)
	b, _ := json.Marshal(merged)
	var x, y any
	json.Unmarshal(a, &x)
	json.Unmarshal(b, &y)
	if !reflect.DeepEqual(x, y) {
		t.Fatalf("merged\n%s\nwant\n%s", b, a)
	}
	parts[1].SemgrepRulesHash = "other"
	if _, err := Merge(parts); err == nil {
		t.Error("shards of different rule sets merged")
	}
}
