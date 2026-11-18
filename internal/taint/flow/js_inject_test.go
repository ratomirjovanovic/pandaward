package flow

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

// TestJSConstructorInjection checks that a method analyzed on its own reaches the
// class of a field set by constructor injection or an initializer, in the
// same file and in another.
func TestJSConstructorInjection(t *testing.T) {
	files := map[string]string{
		"a.controller": "import { Svc } from './svc';\nclass AController {\n  constructor(private readonly svc: Svc) {}\n  run(@Query('cmd') cmd: string) {\n    return this.svc.go(cmd);\n  }\n}\n",
		"svc":          "import { exec } from 'child_process';\nexport class Svc {\n  go(c: string) {\n    exec('echo ' + c);\n  }\n}\n",
		"one":          "import { exec } from 'child_process';\nclass Svc {\n  go(c: string) {\n    exec('echo ' + c);\n  }\n}\nclass A {\n  constructor(private readonly svc: Svc) {}\n  run(@Query('cmd') cmd: string) {\n    return this.svc.go(cmd);\n  }\n}\n",
		"two":          "import { exec } from 'child_process';\nclass Svc {\n  go(c: string) {\n    exec('echo ' + c);\n  }\n}\nclass A {\n  svc = new Svc();\n  run(@Query('cmd') cmd: string) {\n    return this.svc.go(cmd);\n  }\n}\n",
	}
	spec, _ := taint.Load("jsir")
	p := New(spec).NewProject(func(n string) (*ir.Module, []string) {
		src, ok := files[n]
		if !ok {
			return nil, nil
		}
		name := n + ".ts"
		m := js.Lower(js.Parse(name, src, js.OptionsFor(name)), n, func(s string) string {
			return strings.TrimPrefix(s, "./")
		})
		m.Name = n
		return m, strings.Split(src, "\n")
	})
	want := map[string]string{"a.controller": "svc.ts:4", "one": "one.ts:4", "two": "two.ts:4"}
	for _, n := range []string{"a.controller", "one", "two"} {
		var got []string
		m, lines := p.load(n)
		for _, f := range p.AnalyzeOne(m, lines) {
			got = append(got, fmt.Sprintf("%s:%d", f.File, f.Line))
		}
		if strings.Join(got, " ") != want[n] {
			t.Errorf("%s: got %v, want %s", n, got, want[n])
		}
	}
}
