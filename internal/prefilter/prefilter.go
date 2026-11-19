// Package prefilter makes large scans cheap. Most patterns of the built-in
// rules cannot match a file that lacks one of a few words, and checking for a
// word with strings.Contains is orders of magnitude faster than running a
// case-insensitive regular expression over every line. A Filter derives those
// words from the pattern itself, so a pattern and its filter cannot drift
// apart, and only ever says "this file cannot match"; it never changes what a
// pattern matches.
package prefilter

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// minLen is the shortest word worth testing for; shorter ones occur in nearly
// every file.
const minLen = 3

// Filter holds lower-case words of which at least one occurs in any text the
// pattern matches. A Filter with no words never rules anything out.
type Filter struct {
	words []string
}

// New derives the filter of a compiled pattern.
func New(re *regexp.Regexp) *Filter {
	p, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return &Filter{}
	}
	w, ok := required(p.Simplify())
	if !ok {
		return &Filter{}
	}
	return &Filter{words: w}
}

// Folded is a text prepared for filtering.
type Folded struct {
	lower string
	ok    bool
}

// Fold lower-cases text once for any number of filters. Two characters fold to
// an ASCII letter under the case-insensitive matching of regexp but not under
// strings.ToLower (the Kelvin sign and the long s); a text that has one is
// not filtered at all, so the answer stays exact.
func Fold(text string) Folded {
	if strings.ContainsRune(text, 'K') || strings.ContainsRune(text, 'ſ') {
		return Folded{}
	}
	return Folded{lower: strings.ToLower(text), ok: true}
}

// MayMatch reports whether the pattern can match somewhere in the text. It
// is true whenever it cannot tell.
func (f *Filter) MayMatch(t Folded) bool {
	if f == nil || len(f.words) == 0 || !t.ok {
		return true
	}
	for _, w := range f.words {
		if strings.Contains(t.lower, w) {
			return true
		}
	}
	return false
}

// required returns words of which at least one must occur in every match.
func required(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		s := strings.ToLower(string(re.Rune))
		for _, r := range s {
			if r < 0x20 || r > 0x7e {
				return nil, false
			}
		}
		if len(s) < minLen {
			return nil, false
		}
		return []string{s}, true
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil, false
	case syntax.OpConcat:
		var best []string
		bestLen := 0
		for _, s := range re.Sub {
			w, ok := required(s)
			if !ok {
				continue
			}
			// Prefer the set whose shortest word is longest: it is the most selective.
			l := len(w[0])
			for _, x := range w {
				if len(x) < l {
					l = len(x)
				}
			}
			if l > bestLen {
				best, bestLen = w, l
			}
		}
		return best, best != nil
	case syntax.OpAlternate:
		var all []string
		for _, s := range re.Sub {
			w, ok := required(s)
			if !ok {
				return nil, false
			}
			all = append(all, w...)
		}
		return all, true
	}
	return nil, false
}
