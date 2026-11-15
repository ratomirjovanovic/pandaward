package redos

import "testing"

func TestAnalyze(t *testing.T) {
	const (
		none = iota
		poly
		exp
	)
	cases := []struct {
		re, flags string
		want      int
	}{
		{`^(a+)+$`, "", exp},
		{`(a+)+b`, "", exp},
		{`^(a|a)*$`, "", exp},
		{`^(a|aa)+$`, "", exp},
		{`^(\w+\s?)*$`, "", exp},
		{`^(.*,)+(.+)?$`, "", exp},
		{`^(?:\.?[a-zA-Z_][a-zA-Z_0-9]*)+$`, "", exp},
		{`^([a-z]+)*\d$`, "i", exp},
		{` *, *`, "", poly},
		{`^\s+|\s+$`, "g", poly},
		{`\s*\n\s*`, "g", poly},
		{`^[a-z]+$`, "", none},
		{`^(a+)+`, "", none}, // succeeds at the first a
		{`^[\w.-]+@[\w-]+\.[a-z]{2,}$`, "", none},
		{`^(\d{3})-(\d{4})$`, "", none},
		{`^\d+(\.\d+)?$`, "", none},
		{`(a)\1`, "", none},
		{`^(?:ab|cd)+$`, "", none},
		{`^[^=;]+=[^;]*$`, "", none},
	}
	for _, c := range cases {
		r := Analyze(c.re, c.flags)
		got := none
		if r.Exponential {
			got = exp
		} else if r.Polynomial {
			got = poly
		}
		if got != c.want {
			t.Errorf("/%s/%s: got %d, want %d", c.re, c.flags, got, c.want)
		}
	}
}
