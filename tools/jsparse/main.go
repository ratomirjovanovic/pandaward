// Command jsparse measures the taint engine's JavaScript and TypeScript
// parser on real code: it parses every source file under the given
// directories and reports how many parse without error, the most common
// error messages and the throughput.
//
//	go run ./tools/jsparse [-v] [-app] [-top 20] <dir>...
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

	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

var exts = map[string]bool{".js": true, ".jsx": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".mts": true, ".cts": true}

// Generated and bundled files are not what the engine analyzes.
var skipName = regexp.MustCompile(`\.min\.|\.d\.[cm]?ts$|\.bundle\.|-bundle\.`)

const maxBytes = 1 << 20

func main() {
	verbose := flag.Bool("v", false, "list every file with errors and its first error")
	top := flag.Int("top", 20, "number of distinct error messages to show")
	appOnly := flag.Bool("app", false, "skip node_modules and build output, to measure application code")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: jsparse [-v] [-top n] <dir>...")
		os.Exit(2)
	}
	var files, failed, bytes, stmts, bad int
	msgs := map[string]int{}
	examples := map[string]string{}
	start := time.Now()
	for _, root := range flag.Args() {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git":
					return filepath.SkipDir
				case "node_modules", ".next", "dist", "build", "out", "coverage", "target", ".claude", ".pandaward":
					if *appOnly {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !exts[strings.ToLower(filepath.Ext(p))] || skipName.MatchString(d.Name()) {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > maxBytes {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			files++
			bytes += len(src)
			f := js.Parse(p, string(src), js.OptionsFor(p))
			stmts += len(f.Stmts)
			for _, s := range f.Stmts {
				if _, ok := s.(*js.BadStmt); ok {
					bad++
				}
			}
			if len(f.Errors) == 0 {
				return nil
			}
			failed++
			m := normalize(f.Errors[0].Msg)
			msgs[m]++
			if _, ok := examples[m]; !ok {
				examples[m] = fmt.Sprintf("%s:%d", p, f.Errors[0].Line)
			}
			if *verbose {
				fmt.Printf("%s:%d: %s\n", p, f.Errors[0].Line, f.Errors[0].Msg)
			}
			return nil
		})
	}
	el := time.Since(start)
	ok := files - failed
	fmt.Printf("files %d, without errors %d (%.2f%%), with errors %d\n", files, ok, pct(ok, files), failed)
	fmt.Printf("top-level statements %d, lost to errors %d\n", stmts, bad)
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
		fmt.Printf("%6d  %s  (e.g. %s)\n", e.v, e.k, examples[e.k])
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

var quoted = regexp.MustCompile(`"[^"]*"`)

func normalize(m string) string { return quoted.ReplaceAllString(m, `"…"`) }
