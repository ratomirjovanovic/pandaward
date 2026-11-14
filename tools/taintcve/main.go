// Command taintcve is a fast development check of the taint engine on the
// OpenSSF CVE Benchmark: it analyzes only the labelled files of each CVE,
// fetched beforehand at the pre- and post-patch commits, and scores them
// the way tools/cvebench does (a finding covers a labelled line; fewer
// findings of a detecting rule after the patch recognize the fix). It
// sees one file at a time, so cross-file flows are out of its reach; the
// full benchmark remains tools/cvebench.
//
//	go run ./tools/taintcve -bench <ossf-cve-benchmark> -files <dir> [-v] [-cve ids]
//
// <dir>/<CVE>/{pre,post}/<labelled file path> holds the files.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/adapters"
	"github.com/ratomirjovanovic/pandaward/internal/config"
	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
	"github.com/ratomirjovanovic/pandaward/internal/taint/jsflow"
)

type cve struct {
	ID       string   `json:"CVE"`
	State    string   `json:"state"`
	CWEs     []string `json:"CWEs"`
	PrePatch struct {
		Weaknesses []struct {
			Location struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"location"`
		} `json:"weaknesses"`
	} `json:"prePatch"`
}

func main() {
	bench := flag.String("bench", "", "ossf-cve-benchmark checkout")
	files := flag.String("files", "", "directory with the fetched files")
	verbose := flag.Bool("v", false, "print every CVE")
	only := flag.String("cve", "", "comma-separated CVE ids")
	scan := flag.Bool("scan", false, "instead: print the findings in application code under the directories given as arguments (no library mode)")
	cpu := flag.String("cpuprofile", "", "write a CPU profile to this file")
	flag.Parse()
	if *cpu != "" {
		f, err := os.Create(*cpu)
		if err == nil && pprof.StartCPUProfile(f) == nil {
			defer pprof.StopCPUProfile()
		}
	}
	if *scan {
		scanApps(flag.Args())
		return
	}
	spec, err := taint.Load("javascript")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	want := map[string]bool{}
	for _, id := range strings.Split(*only, ",") {
		if id != "" {
			want[id] = true
		}
	}
	paths, _ := filepath.Glob(filepath.Join(*bench, "CVEs", "*.json"))
	type row struct{ scored, detected, fixed int }
	byCWE := map[string]*row{}
	total := &row{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var c cve
		if json.Unmarshal(b, &c) != nil || c.State != "PUBLISHED" || len(c.PrePatch.Weaknesses) == 0 {
			continue
		}
		if len(want) > 0 && !want[c.ID] {
			continue
		}
		cwe := "?"
		if len(c.CWEs) > 0 {
			cwe = strings.TrimPrefix(strings.TrimLeft(strings.TrimPrefix(c.CWEs[0], "CWE-"), "0"), "")
		}
		pre, preOK := analyze(spec, filepath.Join(*files, c.ID, "pre"), c)
		if !preOK {
			continue
		}
		post, _ := analyze(spec, filepath.Join(*files, c.ID, "post"), c)
		r := byCWE[cwe]
		if r == nil {
			r = &row{}
			byCWE[cwe] = r
		}
		r.scored++
		total.scored++
		rules := map[string]bool{}
		for _, w := range c.PrePatch.Weaknesses {
			for _, f := range pre[w.Location.File] {
				end := f.EndLine
				if end < f.Line {
					end = f.Line
				}
				if f.Line <= w.Location.Line && w.Location.Line <= end {
					rules[f.Sink.ID] = true
				}
			}
		}
		detected, fixed := len(rules) > 0, false
		for rule := range rules {
			if count(post, rule) < count(pre, rule) {
				fixed = true
			}
		}
		if detected {
			r.detected++
			total.detected++
		}
		if fixed {
			r.fixed++
			total.fixed++
		}
		if *verbose {
			mark := "  "
			switch {
			case fixed:
				mark = "DF"
			case detected:
				mark = "D "
			}
			var lines []string
			for _, w := range c.PrePatch.Weaknesses {
				lines = append(lines, fmt.Sprintf("%s:%d", w.Location.File, w.Location.Line))
			}
			n := 0
			for _, fs := range pre {
				n += len(fs)
			}
			fmt.Printf("%s %-18s CWE-%-4s findings %-3d %s\n", mark, c.ID, cwe, n, strings.Join(lines, " "))
		}
	}
	keys := make([]string, 0, len(byCWE))
	for k := range byCWE {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return byCWE[keys[i]].scored > byCWE[keys[j]].scored || byCWE[keys[i]].scored == byCWE[keys[j]].scored && keys[i] < keys[j]
	})
	fmt.Printf("scored %d, detected %d, fix recognized %d\n", total.scored, total.detected, total.fixed)
	for _, k := range keys {
		r := byCWE[k]
		fmt.Printf("  CWE-%-4s %3d scored %3d detected %3d fixed\n", k, r.scored, r.detected, r.fixed)
	}
}

// analyze returns the findings per labelled file under dir, and false when
// none of the files is there.
func analyze(spec *taint.Spec, dir string, c cve) (map[string][]taint.Finding, bool) {
	out := map[string][]taint.Finding{}
	found := false
	seen := map[string]bool{}
	for _, w := range c.PrePatch.Weaknesses {
		f := w.Location.File
		if seen[f] {
			continue
		}
		seen[f] = true
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f)))
		if err != nil {
			continue
		}
		found = true
		file := js.Parse(f, string(b), js.OptionsFor(f))
		out[f] = jsflow.Analyze(file, spec, jsflow.Options{Library: true})
	}
	return out, found
}

func count(m map[string][]taint.Finding, rule string) int {
	n := 0
	for _, fs := range m {
		for _, f := range fs {
			if f.Sink.ID == rule {
				n++
			}
		}
	}
	return n
}

// scanApps prints every finding in the application code under dirs, for
// reviewing precision by hand. It runs the builtin-taint adapter on an
// inventory of each directory, as a scan does.
func scanApps(dirs []string) {
	files, total := 0, 0
	for _, root := range dirs {
		cfg := config.Default("scan")
		inv, err := inventory.Walk(root, inventory.Options{Exclude: cfg.Inventory.Exclude, MaxFileBytes: cfg.Inventory.MaxFileBytes, MaxFiles: cfg.Inventory.MaxFiles})
		if err != nil {
			fmt.Fprintln(os.Stderr, root, err)
			continue
		}
		res, run := adapters.ByName(adapters.TaintAdapter).Run(context.Background(), &adapters.Context{Root: root, Inv: inv, Cfg: cfg})
		fmt.Fprintln(os.Stderr, root+":", run.Detail)
		var k int
		if _, err := fmt.Sscanf(run.Detail, "%d", &k); err == nil {
			files += k
		}
		for _, sg := range res.Signals {
			total++
			fmt.Printf("%s:%d %s\n    %s\n", filepath.Join(root, filepath.FromSlash(sg.File)), sg.StartLine, sg.RuleID, sg.Message)
		}
	}
	fmt.Printf("%d files, %d findings\n", files, total)
}
