// Command pyflow runs the built-in taint engine on Python files and prints
// each flow, or with -ir the IR of one file, for developing the engine.
//
//	go run ./tools/pyflow [-v] <file or dir>...
//	go run ./tools/pyflow -ir <file.py>
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
	"github.com/ratomirjovanovic/pandaward/internal/taint/py"
)

func main() {
	showIR := flag.Bool("ir", false, "print the IR of each file instead")
	verbose := flag.Bool("v", false, "print the steps of each flow")
	slow := flag.Duration("slow", 0, "report files whose analysis takes longer than this")
	flag.Parse()
	spec, err := taint.Load("python")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	eng := flow.New(spec)
	for _, root := range flag.Args() {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".py") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			src := strings.ReplaceAll(string(b), "\r\n", "\n")
			f := py.Parse(p, src)
			m := py.Lower(f, "", false)
			if *showIR {
				for _, fn := range m.Funcs {
					fmt.Println(fn)
				}
				return nil
			}
			start := time.Now()
			fds := eng.Analyze(m, strings.Split(src, "\n"))
			if d := time.Since(start); *slow > 0 && d > *slow {
				fmt.Fprintf(os.Stderr, "slow\t%s\t%s\n", d.Round(time.Millisecond), p)
			}
			for _, fd := range fds {
				fmt.Printf("%s\t%d\t%s\n", p, fd.Line, fd.Sink.ID)
				if *verbose {
					for _, s := range fd.Steps {
						fmt.Printf("\t\t%d: %s\n", s.Line, s.What)
					}
				}
			}
			return nil
		})
	}
}
