// Command pyparse measures the taint engine's Python parser on real code:
// it parses every .py file under the given directories and reports how many
// parse without error, the most common error messages and the throughput.
//
//	go run ./tools/pyparse [-v] [-top 20] <dir>...
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/taint/py"
)

const maxBytes = 1 << 20

// Python 2 files are not what the engine analyzes: print statements, exec
// statements and old except syntax mark them.
var py2 = regexp.MustCompile(`(?m)^\s*print\s+[^(=\s]|^\s*exec\s+["'a-z]|except\s+\w+\s*,\s*\w+\s*:|^\s*raise\s+\w+\s*,`)

func main() {
	verbose := flag.Bool("v", false, "list every file with errors and its first error")
	top := flag.Int("top", 20, "number of distinct error messages to show")
	diffTSV := flag.String("diff", "", "compare node positions with the output of astnodes.py instead")
	flag.Parse()
	if *diffTSV != "" {
		if err := diff(*diffTSV, *top); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: pyparse [-v] [-top n] <dir>...")
		os.Exit(2)
	}
	var files, failed, skipped2, bytes, stmts, bad int
	msgs := map[string]int{}
	examples := map[string]string{}
	norm := regexp.MustCompile(`'[^']*'|number \S+`)
	start := time.Now()
	for _, root := range flag.Args() {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", "__pycache__", ".tox", ".mypy_cache":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".py") && !strings.HasSuffix(p, ".pyi") {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > maxBytes {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			src := string(b)
			f := py.Parse(p, src)
			if len(f.Errors) > 0 && py2.MatchString(src) {
				skipped2++
				return nil
			}
			files++
			bytes += len(b)
			stmts += len(f.Body)
			for _, s := range f.Body {
				if _, ok := s.(*py.BadStmt); ok {
					bad++
				}
			}
			if len(f.Errors) > 0 {
				failed++
				e := f.Errors[0]
				key := norm.ReplaceAllString(e.Msg, "'X'")
				msgs[key]++
				if _, ok := examples[key]; !ok {
					examples[key] = fmt.Sprintf("%s:%d:%d", p, e.Line, e.Col)
				}
				if *verbose {
					fmt.Printf("%s:%d:%d: %s\n", p, e.Line, e.Col, e.Msg)
				}
			}
			return nil
		})
	}
	el := time.Since(start)
	ok := files - failed
	pct := 0.0
	if files > 0 {
		pct = 100 * float64(ok) / float64(files)
	}
	fmt.Printf("%d files (%d Python 2 files skipped), %d parse without error (%.2f%%), %d top-level statements, %d lost\n", files, skipped2, ok, pct, stmts, bad)
	fmt.Printf("%.1f MB in %s (%.1f MB/s)\n", float64(bytes)/1e6, el.Round(time.Millisecond), float64(bytes)/1e6/el.Seconds())
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range msgs {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v || list[i].v == list[j].v && list[i].k < list[j].k })
	for i, e := range list {
		if i >= *top {
			break
		}
		fmt.Printf("%6d  %s  (%s)\n", e.v, e.k, examples[e.k])
	}
}
