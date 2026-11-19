package prefilter

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

func TestWords(t *testing.T) {
	cases := []struct {
		pat  string
		want []string
	}{
		{`(?i)(\bstripe\b|paypal|braintree)`, []string{"stripe", "paypal", "braintree"}},
		{`(?i)eval\s*\(`, []string{"eval"}},
		{`\bexec\(.*\$_(GET|POST)`, []string{"exec("}},
		{`a|bcd`, nil},             // a branch with no usable word: cannot filter
		{`(?i)[a-z]+@[a-z]+`, nil}, // nothing literal
		{`(?i)(foo)?barbaz`, []string{"barbaz"}},
	}
	for _, c := range cases {
		f := New(regexp.MustCompile(c.pat))
		if strings.Join(f.words, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: words %v, want %v", c.pat, f.words, c.want)
		}
	}
}

// The filter must never rule out a text the pattern matches.
func TestNeverHidesAMatch(t *testing.T) {
	pats := []string{
		`(?i)(\bstripe\b|paypal|braintree|adyen|checkout\.sessions)`,
		`(?i)eval\s*\(`, `\bexec\(.*\$_(GET|POST)`, `(?i)(foo)?barbaz`, `(?i)credentials\s*:\s*true`,
		`unserialize\(\s*\$_`, `(?i)select .* from`,
	}
	alphabet := []string{"stripe", "STRIPE", "paypal", "eval", "EVAL (", "exec(", "$_GET", "$_POST", "barbaz", "BarBaz", "credentials:true", "Credentials : true",
		"unserialize($_", "SELECT x FROM", " ", "\n", "x", "é", "K", "ſ", "checkout.sessions"}
	rng := rand.New(rand.NewSource(1))
	for _, p := range pats {
		re := regexp.MustCompile(p)
		f := New(re)
		for i := 0; i < 3000; i++ {
			var b strings.Builder
			for n := rng.Intn(6); n >= 0; n-- {
				b.WriteString(alphabet[rng.Intn(len(alphabet))])
			}
			s := b.String()
			if re.MatchString(s) && !f.MayMatch(Fold(s)) {
				t.Fatalf("%s hides a match in %q", p, s)
			}
		}
	}
}

func TestKelvinSign(t *testing.T) {
	re := regexp.MustCompile(`(?i)token`)
	s := "TOKEN"
	if !re.MatchString(s) {
		t.Skip("regexp does not fold the Kelvin sign here")
	}
	if !New(re).MayMatch(Fold(s)) {
		t.Fatal("hid a Kelvin sign match")
	}
}
