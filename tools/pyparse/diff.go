package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint/py"
)

// diff compares the positions of selected nodes with CPython's ast, read
// from the output of astnodes.py, and prints the differences per node
// type. Names inside case patterns are left out: CPython has no Name node
// for a capture pattern.
func diff(tsv string, show int) error {
	f, err := os.Open(tsv)
	if err != nil {
		return err
	}
	defer f.Close()
	missing, extra := map[string]int{}, map[string]int{}
	examples := map[string]string{}
	total, files, clean := 0, 0, 0
	// astnodes.py writes the nodes of one file together, so each file is
	// compared as soon as the next one starts.
	compare := func(path string, want map[string]int) {
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		files++
		got := nodes(py.Parse(path, string(b)))
		ok := true
		for k, n := range want {
			total += n
			if d := n - got[k]; d > 0 {
				t := strings.Fields(k)[0]
				missing[t] += d
				ok = false
				if _, seen := examples["-"+t]; !seen {
					examples["-"+t] = path + " " + k
				}
			}
		}
		for k, n := range got {
			if d := n - want[k]; d > 0 {
				t := strings.Fields(k)[0]
				extra[t] += d
				ok = false
				if _, seen := examples["+"+t]; !seen {
					examples["+"+t] = path + " " + k
				}
			}
		}
		if ok {
			clean++
		}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	cur := ""
	want := map[string]int{}
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "	")
		if len(parts) != 4 {
			continue
		}
		if parts[0] != cur {
			if cur != "" {
				compare(cur, want)
			}
			cur, want = parts[0], map[string]int{}
		}
		want[parts[1]+" "+parts[2]+" "+parts[3]]++
	}
	if cur != "" {
		compare(cur, want)
	}
	fmt.Printf("%d files, %d with every node at CPython's position; %d nodes compared\n", files, clean, total)
	var types []string
	for t := range missing {
		types = append(types, t)
	}
	for t := range extra {
		if missing[t] == 0 {
			types = append(types, t)
		}
	}
	sort.Strings(types)
	for _, t := range types {
		fmt.Printf("  %-11s missing %6d  extra %6d\n", t, missing[t], extra[t])
		if show > 0 {
			if e := examples["-"+t]; e != "" {
				fmt.Printf("      missing: %s\n", e)
			}
			if e := examples["+"+t]; e != "" {
				fmt.Printf("      extra:   %s\n", e)
			}
		}
	}
	return nil
}

func nodes(f *py.File) map[string]int {
	out := map[string]int{}
	add := func(t string, p py.Pos) { out[t+" "+strconv.Itoa(p.Line)+" "+strconv.Itoa(p.Col-1)]++ }
	var visit func(py.Node) bool
	visit = func(n py.Node) bool {
		switch n := n.(type) {
		case *py.Match:
			add("Match", n.Pos)
			py.Inspect(n.Subject, visit)
			for _, c := range n.Cases {
				// Patterns: only calls (class patterns) and attributes
				// (value patterns) have the same node in CPython.
				// In patterns, CPython has nodes for the class of a class
				// pattern and for dotted value patterns, not for captures.
				var pat func(py.Node) bool
				pat = func(m py.Node) bool {
					switch m := m.(type) {
					case *py.Attribute:
						py.Inspect(m, visit)
						return false
					case *py.Call:
						py.Inspect(m.Func, visit)
						for _, a := range m.Args {
							py.Inspect(a.Value, pat)
						}
						return false
					}
					return true
				}
				py.Inspect(c.Pattern, pat)
				py.Inspect(c.Guard, visit)
				for _, s := range c.Body {
					py.Inspect(s, visit)
				}
			}
			return false
		case *py.Call:
			add("Call", n.Pos)
		case *py.Attribute:
			add("Attribute", n.Pos)
		case *py.Subscript:
			add("Subscript", n.Pos)
		case *py.Name:
			add("Name", n.Pos)
		case *py.FString:
			add("FString", n.Pos)
		case *py.FuncDef:
			add("FuncDef", n.Pos)
		case *py.ClassDef:
			add("ClassDef", n.Pos)
		case *py.Return:
			add("Return", n.Pos)
		case *py.If:
			add("If", n.Pos)
		case *py.For:
			add("For", n.Pos)
		case *py.While:
			add("While", n.Pos)
		case *py.With:
			add("With", n.Pos)
		case *py.Try:
			add("Try", n.Pos)
		case *py.Assign:
			add("Assign", n.Pos)
		case *py.AugAssign:
			add("AugAssign", n.Pos)
		case *py.AnnAssign:
			add("AnnAssign", n.Pos)
		case *py.Lambda:
			add("Lambda", n.Pos)
		case *py.Comp:
			add("Comp", n.Pos)
		case *py.Import:
			add("Import", n.Pos)
		case *py.ImportFrom:
			add("ImportFrom", n.Pos)
		case *py.Raise:
			add("Raise", n.Pos)
		case *py.NamedExpr:
			add("NamedExpr", n.Pos)
		case *py.Await:
			add("Await", n.Pos)
		case *py.Yield:
			add("Yield", n.Pos)
		}
		return true
	}
	for _, s := range f.Body {
		py.Inspect(s, visit)
	}
	return out
}
