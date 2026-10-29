// Command demofixture writes PandaWard's deliberately vulnerable fixture into a
// directory. It is used to produce the website demo; all secret-shaped
// values are synthetic.
package main

import (
	"fmt"
	"os"

	"github.com/ratomirjovanovic/pandaward/internal/testfixture"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: demofixture <empty-directory>")
		os.Exit(2)
	}
	if entries, err := os.ReadDir(os.Args[1]); err == nil && len(entries) > 0 {
		fmt.Fprintln(os.Stderr, "refusing to write into a non-empty directory")
		os.Exit(1)
	}
	if err := testfixture.Build(os.Args[1], func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
