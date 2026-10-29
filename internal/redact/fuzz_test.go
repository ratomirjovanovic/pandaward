package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// fuzzSecret is a synthetic GitHub token: it has the format, not a value
// that was ever valid.
const fuzzSecret = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

// FuzzLine checks the redaction of untrusted text: no panic, valid UTF-8,
// bounded length, no control characters, and a token surrounded by spaces
// never survives, whatever text is around it.
func FuzzLine(f *testing.F) {
	for _, s := range []string{"", "plain text", "token=" + fuzzSecret, "\x1b[31mred\x1b[0m", "Authorization: Bearer abc.def", strings.Repeat("é", 300), "-----BEGIN PRIVATE KEY-----"} {
		f.Add(s, "")
	}
	f.Fuzz(func(t *testing.T, before, after string) {
		for _, in := range []string{before, before + " " + fuzzSecret + " " + after} {
			out := Line(in)
			if !utf8.ValidString(out) {
				t.Fatalf("invalid UTF-8 for %q", in)
			}
			if n := utf8.RuneCountInString(out); n > MaxSnippet+1 {
				t.Fatalf("%d runes for %q", n, in)
			}
			for _, r := range out {
				if r != ' ' && r < 0x20 || r == 0x7f {
					t.Fatalf("control character %U in output for %q", r, in)
				}
			}
			if strings.Contains(out, fuzzSecret) {
				t.Fatalf("secret survived in %q", out)
			}
			if Line(out) != Line(Line(out)) {
				t.Fatalf("not stable when applied again: %q", out)
			}
		}
	})
}
