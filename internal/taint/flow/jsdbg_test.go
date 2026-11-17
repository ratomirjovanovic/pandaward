package flow

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
	"github.com/ratomirjovanovic/pandaward/internal/taint/jsflow"
)

// TestJSDbg is a development harness: JSDBG=file runs the IR engine on
// it (JSDBG_IR=1 prints the IR, JSDBG_JSFLOW=1 also runs jsflow).
func TestJSDbg(t *testing.T) {
	path := os.Getenv("JSDBG")
	if path == "" {
		t.Skip()
	}
	b, _ := os.ReadFile(path)
	src := string(b)
	f := js.Parse(path, src, js.OptionsFor(path))
	m := js.Lower(f, path, nil)
	if os.Getenv("JSDBG_IR") != "" {
		for _, fn := range m.Funcs {
			fmt.Println(fn.String())
		}
	}
	spec, err := taint.Load("jsir")
	if err != nil {
		t.Fatal(err)
	}
	p := New(spec).NewProject(func(string) (*ir.Module, []string) { return nil, nil })
	p.Library = true
	for _, x := range p.AnalyzeOne(m, strings.Split(src, "\n")) {
		what := ""
		if len(x.Steps) > 0 {
			what = x.Steps[0].What
		}
		fmt.Println(x.Line, x.Sink.ID, "<-", what)
		if os.Getenv("JSDBG_STEPS") != "" {
			for _, st := range x.Steps {
				fmt.Println("     ", st.Line, st.What)
			}
		}
	}
	if os.Getenv("JSDBG_JSFLOW") != "" {
		js2, _ := taint.Load("javascript")
		fmt.Println("-- jsflow")
		for _, x := range jsflow.Analyze(f, js2, jsflow.Options{Library: true}) {
			what := ""
			if len(x.Steps) > 0 {
				what = x.Steps[0].What
			}
			fmt.Println(x.Line, x.Sink.ID, "<-", what)
		}
	}
}
