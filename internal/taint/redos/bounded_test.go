package redos

import "testing"

// A fix that bounds the loops is a fix; an unbounded or very large bound is not.
func TestBoundedRepetitionIsNotReDoS(t *testing.T) {
	cases := []struct {
		name, pat, flags string
		poly, exp        bool
	}{
		// moment, CVE-2017-18214: before (unbounded loops) and after (bounded to 256).
		{"moment before", `[0-9]*['a-z -׿܀-퟿豈-﷏ﷰ-￯]+|[؀-ۿ\/]+(\s*?[؀-ۿ]+){1,2}`, "i", true, false},
		{"moment after", `[0-9]{0,256}['a-z -׿܀-퟿豈-﷏ﷰ-￯]{1,256}|[؀-ۿ\/]{1,256}(\s*?[؀-ۿ]{1,256}){1,2}`, "i", false, false},
		// the same quadratic shape with bounds
		{"quadratic unbounded", `\s*,\s*x`, "", true, false},
		{"quadratic bounded 256", `\s{0,256},\s{0,256}x`, "", false, false},
		{"quadratic bound over the limit", `\s{0,1000},\s{0,1000}x`, "", true, false},
		// one bounded and one unbounded loop is still linear work per start
		{"one bounded one unbounded", `\s{0,100},\s*x`, "", false, false},
		// exponential ambiguity is not hidden by a bound on a different part
		{"exponential stays", `^(a+)+$`, "", false, true},
		{"exponential with bounded tail", `^(a+)+b{1,200}$`, "", false, true},
	}
	for _, c := range cases {
		r := Analyze(c.pat, c.flags)
		if r.Polynomial != c.poly || r.Exponential != c.exp {
			t.Errorf("%s: poly=%v exp=%v, want poly=%v exp=%v", c.name, r.Polynomial, r.Exponential, c.poly, c.exp)
		}
	}
}
