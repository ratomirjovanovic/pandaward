// Command pyflow runs the built-in taint engine on the Python files under
// each directory, as one project, and prints each flow, or with -ir the IR
// of each file, for developing the engine.
//
//	go run ./tools/pyflow [-v] [-slow 1s] <dir>...
//	go run ./tools/pyflow -ir <dir or file>
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
	"github.com/ratomirjovanovic/pandaward/internal/taint/py"
)

func main() {
	showIR := flag.Bool("ir", false, "print the IR of each file instead")
	verbose := flag.Bool("v", false, "print the steps of each flow")
	slow := flag.Duration("slow", 0, "report modules whose analysis takes longer than this")
	flag.Parse()
	spec, err := taint.Load("python")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	eng := flow.New(spec)
	for _, root := range flag.Args() {
		var paths []string
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", "__pycache__":
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, ".py") {
				rel, _ := filepath.Rel(root, p)
				paths = append(paths, filepath.ToSlash(rel))
			}
			return nil
		})
		if len(paths) == 0 && strings.HasSuffix(root, ".py") {
			paths = []string{filepath.Base(root)}
			root = filepath.Dir(root)
		}
		files := py.NewFiles(paths)
		src := map[string][]string{}
		mods := map[string]*ir.Module{}
		parse := func(rel string) (*ir.Module, []string) {
			if m, ok := mods[rel]; ok {
				return m, src[rel]
			}
			b, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				return nil, nil
			}
			text := strings.ReplaceAll(string(b), "\r\n", "\n")
			src[rel] = strings.Split(text, "\n")
			name, pkg := files.Name(rel)
			mods[rel] = py.Lower(py.Parse(rel, text), name, pkg)
			return mods[rel], src[rel]
		}
		if *showIR {
			for _, rel := range paths {
				m, _ := parse(rel)
				for _, fn := range m.Funcs {
					fmt.Println(fn)
				}
			}
			continue
		}
		proj := eng.NewProject(func(name string) (*ir.Module, []string) {
			if p := files.Lookup(name); p != "" {
				return parse(p)
			}
			return nil, nil
		})
		for _, rel := range paths {
			name, _ := files.Name(rel)
			start := time.Now()
			found := proj.Module(name)
			if d := time.Since(start); *slow > 0 && d > *slow {
				fmt.Fprintf(os.Stderr, "slow\t%s\t%s\n", d.Round(time.Millisecond), rel)
			}
			for _, fd := range found {
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
	}
}
