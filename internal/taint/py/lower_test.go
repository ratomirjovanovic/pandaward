package py

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

func lowerFn(t *testing.T, src, name string) *ir.Function {
	t.Helper()
	f := Parse("m.py", src)
	if len(f.Errors) > 0 {
		t.Fatal(f.Errors)
	}
	m := Lower(f, "pkg.mod", false)
	for _, fn := range m.Funcs {
		if fn.Name == name {
			return fn
		}
	}
	t.Fatalf("no function %s", name)
	return nil
}

func TestLowerScopes(t *testing.T) {
	fn := lowerFn(t, `import os
from . import util
from ..base import thing as base_thing
def f(a):
    b = [x for x in a if x]
    return os.path.join(a, b, util, base_thing)
`, "f")
	got := fn.String()
	for _, want := range []string{
		"$c1.x = $",       // the comprehension variable is renamed
		"free os",         // a module name read from a function
		"func f(a)",       // parameters
		"listcomp{$c1.x}", // the element
		"return $",        // the return value
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	init := lowerFn(t, "from . import util\nfrom ..base import thing as base_thing\n", "<module>").String()
	for _, want := range []string{"util = import pkg.util", "base_thing = import base.thing"} {
		if !strings.Contains(init, want) {
			t.Errorf("missing %q in\n%s", want, init)
		}
	}
}

// and, or and not become branches, so each test is a guard of its own.
func TestLowerConditions(t *testing.T) {
	fn := lowerFn(t, `def f(x):
    if not x.startswith("a") or "b" in x:
        return 1
    return 2
`, "f")
	branches := 0
	for _, b := range fn.Blocks {
		if b.Term.Kind == ir.Branch {
			branches++
		}
	}
	if branches != 2 {
		t.Errorf("want 2 branches, got %d:\n%s", branches, fn)
	}
}

// Every block of a try body may raise into the handler.
func TestLowerTry(t *testing.T) {
	fn := lowerFn(t, `def f(x):
    try:
        y = g(x)
        if y:
            h(y)
    except ValueError as e:
        y = None
    return y
`, "f")
	protected := 0
	for _, b := range fn.Blocks {
		if len(b.Handlers) > 0 {
			protected++
		}
	}
	if protected < 3 {
		t.Errorf("want the try body's blocks protected:\n%s", fn)
	}
	if !strings.Contains(fn.String(), `e = exception`) {
		t.Errorf("handler name not bound:\n%s", fn)
	}
}

// Every statement of a real file lowers without a panic, and decorators
// keep their name and constant arguments.
func TestLowerDecorators(t *testing.T) {
	fn := lowerFn(t, `@app.route("/u/<int:id>", methods=["GET"])
@login_required
async def view(id, *args, **kw):
    async with lock:
        await go()
    match id:
        case 1 | 2:
            pass
        case {"k": v}:
            pass
    del kw["x"]
    global counter
    counter += 1
    lambda q: q
    yield id
`, "view")
	if len(fn.Decorators) != 2 || fn.Decorators[0].Name != "app.route" || !fn.Decorators[0].Call || fn.Decorators[0].Args[0] != "/u/<int:id>" {
		t.Errorf("decorators %+v", fn.Decorators)
	}
	if len(fn.Params) != 3 || fn.Params[1].Kind != "*" {
		t.Errorf("params %+v", fn.Params)
	}
}
