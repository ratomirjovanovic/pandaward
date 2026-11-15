package jsflow

import (
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

// TestRegexpsReDoS checks that exponential patterns are reported where
// they are written, whether as a literal or a RegExp of a string, and that
// quadratic ones are reported in a library only.
func TestRegexpsReDoS(t *testing.T) {
	spec, err := taint.Load("jsir")
	if err != nil {
		t.Fatal(err)
	}
	src := `var a = /^(a+)+$/;
var b = new RegExp("^(\w+\s?)*$");
var c = /^[a-z]+$/;
var d = /^(a+)+/;
var e = / *, */;`
	f := js.Parse("x.js", src, js.OptionsFor("x.js"))
	lines := func(lib bool) []int {
		var out []int
		for _, fd := range Structural(f, spec, Options{Library: lib}) {
			if fd.Sink.ID == "taint.js-redos" {
				out = append(out, fd.Line)
			}
		}
		return out
	}
	if got := lines(false); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("application: got %v, want [1 2]", got)
	}
	if got := lines(true); len(got) != 3 || got[2] != 5 {
		t.Errorf("library: got %v, want [1 2 5]", got)
	}
}
