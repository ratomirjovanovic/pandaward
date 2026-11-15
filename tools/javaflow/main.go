// Command javaflow runs the built-in taint engine on the Java files under
// each directory, as one project, and prints each flow, or with -ir the IR
// of each file, for developing the engine.
//
//	go run ./tools/javaflow [-v] [-slow 1s] <dir>...
//	go run ./tools/javaflow -ir <dir>
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/flow"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
	"github.com/ratomirjovanovic/pandaward/internal/taint/java"
)

func main() {
	showIR := flag.Bool("ir", false, "print the IR of each file instead")
	verbose := flag.Bool("v", false, "print the steps of each flow")
	slow := flag.Duration("slow", 0, "report files whose analysis takes longer than this")
	flag.Parse()
	spec, err := taint.Load("java")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	eng := flow.New(spec)
	for _, root := range flag.Args() {
		var paths []string
		props := map[string]string{}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", "target", "build":
					return filepath.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			switch filepath.Ext(p) {
			case ".java":
				paths = append(paths, rel)
			case ".properties":
				readProps(p, props)
			}
			return nil
		})
		files := java.NewFiles(paths)
		lines := map[string][]string{}
		mods := map[string][]*ir.Module{}
		parse := func(rel string) []*ir.Module {
			if m, ok := mods[rel]; ok {
				return m
			}
			b, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				return nil
			}
			text := strings.ReplaceAll(string(b), "\r\n", "\n")
			lines[rel] = strings.Split(text, "\n")
			mods[rel] = java.Lower(java.Parse(rel, text))
			return mods[rel]
		}
		if *showIR {
			for _, rel := range paths {
				for _, m := range parse(rel) {
					for _, fn := range m.Funcs {
						fmt.Println(fn)
					}
				}
			}
			continue
		}
		proj := eng.NewProject(func(name string) (*ir.Module, []string) {
			p := files.Lookup(name)
			if p == "" {
				return nil, nil
			}
			for _, m := range parse(p) {
				if m.Name == name {
					return m, lines[p]
				}
			}
			return nil, nil
		})
		proj.SetProperties(props)
		for _, rel := range paths {
			start := time.Now()
			for _, m := range parse(rel) {
				for _, fd := range proj.Module(m.Name) {
					fmt.Printf("%s\t%d\t%s\n", filepath.Join(root, fd.File), fd.Line, fd.Sink.ID)
					if *verbose {
						for _, s := range fd.Steps {
							at := ""
							if s.File != "" {
								at = s.File + " "
							}
							fmt.Printf("\t\t%s%d: %s\n", at, s.Line, s.What)
						}
					}
				}
			}
			if d := time.Since(start); *slow > 0 && d > *slow {
				fmt.Fprintf(os.Stderr, "slow\t%s\t%s\n", d.Round(time.Millisecond), rel)
			}
		}
	}
}

func readProps(path string, out map[string]string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if old, dup := out[k]; dup && old != v {
			out[k] = "" // the same key with two values: unknown
			continue
		}
		out[k] = v
	}
}
