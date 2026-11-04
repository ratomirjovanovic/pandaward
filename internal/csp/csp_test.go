package csp

import "testing"

func TestCheck(t *testing.T) {
	cases := []struct {
		policy  string
		keyword string // "" means not weak
		dir     string
	}{
		{"script-src 'self' 'unsafe-inline'", "'unsafe-inline'", "script-src"},
		{"default-src 'self' 'unsafe-eval'", "'unsafe-eval'", "default-src"},
		{"default-src 'self' 'unsafe-inline'; object-src 'none'", "'unsafe-inline'", "default-src"},
		{"default-src 'self'; script-src 'self' 'UNSAFE-EVAL' 'nonce-abc'", "'unsafe-eval'", "script-src"},
		{"script-src 'self' 'nonce-abc' 'unsafe-inline' 'strict-dynamic'", "", ""},
		{"script-src 'self' 'sha256-xyz' 'unsafe-inline'", "", ""},
		{"script-src 'self' 'sha384-xyz' 'unsafe-inline'", "", ""},
		{"script-src 'self' 'sha512-xyz' 'unsafe-inline'", "", ""},
		{"script-src 'strict-dynamic' 'unsafe-inline' https:", "", ""},
		{"default-src 'self'; style-src 'self' 'unsafe-inline'", "", ""},
		{"script-src 'self'; style-src 'unsafe-inline'", "", ""},
		// script-src overrides default-src.
		{"default-src 'unsafe-inline' 'unsafe-eval'; script-src 'self'", "", ""},
		// Only the exact keyword counts.
		{"script-src 'self' 'wasm-unsafe-eval'", "", ""},
		{"script-src 'self' unsafe-inline", "", ""},
		// The first directive wins.
		{"script-src 'self'; script-src 'unsafe-inline'", "", ""},
		// No script restriction is a missing CSP, not a weak one.
		{"frame-ancestors 'none'", "", ""},
		{"", "", ""},
		// Every policy is enforced: a strict one protects.
		{"script-src 'unsafe-inline', script-src 'self'", "", ""},
		{"frame-ancestors 'none', script-src 'self' 'unsafe-inline'", "'unsafe-inline'", "script-src"},
		// Inline elements follow script-src-elem first.
		{"script-src 'self' 'unsafe-inline'; script-src-elem 'self'", "", ""},
		{"script-src 'self'; script-src-elem 'self' 'unsafe-inline'", "'unsafe-inline'", "script-src-elem"},
	}
	for _, c := range cases {
		w, ok := Check(c.policy)
		if ok != (c.keyword != "") || w.Keyword != c.keyword || w.Directive != c.dir {
			t.Errorf("Check(%q) = %+v, %v; want %q in %q", c.policy, w, ok, c.keyword, c.dir)
		}
	}
}

func TestParseFirstOccurrenceAndCase(t *testing.T) {
	p := Parse(" Script-Src 'self' ;script-src 'none'; ;bad/name x")
	if got := p["script-src"]; len(got) != 1 || got[0] != "'self'" {
		t.Errorf("script-src = %v", got)
	}
	if len(p) != 1 {
		t.Errorf("unexpected directives %v", p)
	}
}
