// Command javaparse measures the taint engine's Java parser on real code:
// it parses every .java file under the given directories and reports how
// many parse without error, the most common error messages and the
// throughput.
//
//	go run ./tools/javaparse [-v] [-top 20] <dir>...
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/ratomirjovanovic/pandaward/internal/taint/java"
)

const maxBytes = 2 << 20

func main() {
	verbose := flag.Bool("v", false, "list every file with errors and its first error")
	top := flag.Int("top", 20, "number of distinct error messages to show")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: javaparse [-v] [-top n] <dir>...")
		os.Exit(2)
	}
	var files, failed, bytes, types int
	msgs := map[string]int{}
	examples := map[string]string{}
	norm := regexp.MustCompile(`'[^']*'|identifier '[^']*'`)
	start := time.Now()
	for _, root := range flag.Args() {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", "build", "target":
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(p) != ".java" {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil || len(b) > maxBytes {
				return nil
			}
			files++
			bytes += len(b)
			f := java.Parse(p, string(b))
			types += len(f.Types)
			if len(f.Errors) > 0 {
				failed++
				e := f.Errors[0]
				key := norm.ReplaceAllString(e.Msg, "X")
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
	dur := time.Since(start)
	ok := files - failed
	pct := 0.0
	if files > 0 {
		pct = 100 * float64(ok) / float64(files)
	}
	fmt.Printf("%d files, %d parse without error (%.2f%%), %d type declarations\n", files, ok, pct, types)
	fmt.Printf("%.1f MB in %s (%.1f MB/s)\n", float64(bytes)/1e6, dur.Round(time.Millisecond), float64(bytes)/1e6/dur.Seconds())
	type kv struct {
		k string
		n int
	}
	var list []kv
	for k, n := range msgs {
		list = append(list, kv{k, n})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
	for i, e := range list {
		if i >= *top {
			break
		}
		fmt.Printf("%6d  %s  (%s)\n", e.n, e.k, examples[e.k])
	}
}
