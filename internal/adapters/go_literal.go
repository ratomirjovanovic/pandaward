package adapters

import (
	"go/scanner"
	"go/token"
	"sort"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// goLiterals holds the byte ranges of the string literals in a Go file, and
// which of them are a pattern passed to the regexp package.
type goLiterals struct {
	src     string
	spans   [][2]int // sorted, end exclusive
	pattern map[int]bool
}

// scanGoLiterals tokenizes Go source. It needs no valid syntax: the scanner
// reports errors and keeps going, so a broken file still yields its strings.
func scanGoLiterals(src string) *goLiterals {
	g := &goLiterals{src: src, pattern: map[int]bool{}}
	fs := token.NewFileSet()
	f := fs.AddFile("", fs.Base(), len(src))
	var s scanner.Scanner
	s.Init(f, []byte(src), func(token.Position, string) {}, 0)
	// The last four tokens, to recognize regexp.Name( "pattern".
	var prev [4]token.Token
	var prevLit [4]string
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.STRING {
			off := f.Offset(pos)
			g.spans = append(g.spans, [2]int{off, off + len(lit)})
			if prev[3] == token.LPAREN && prev[2] == token.IDENT && prev[1] == token.PERIOD && prev[0] == token.IDENT && prevLit[0] == "regexp" {
				g.pattern[len(g.spans)-1] = true
			}
		}
		copy(prev[:], prev[1:])
		copy(prevLit[:], prevLit[1:])
		prev[3], prevLit[3] = tok, lit
	}
	return g
}

// within returns the index of the literal that holds [start, end) whole,
// or -1.
func (g *goLiterals) within(start, end int) int {
	i := sort.Search(len(g.spans), func(i int) bool { return g.spans[i][1] > start })
	if i < len(g.spans) && g.spans[i][0] <= start && end <= g.spans[i][1] {
		return i
	}
	return -1
}

// acrossLiterals reports whether [start, end) runs over string literals
// joined only by commas, plus signs and white space, as in a list of
// arguments that are all strings.
func (g *goLiterals) acrossLiterals(start, end int) bool {
	i := sort.Search(len(g.spans), func(i int) bool { return g.spans[i][1] > start })
	if i >= len(g.spans) || g.spans[i][0] > start {
		return false
	}
	for ; i < len(g.spans); i++ {
		if end <= g.spans[i][1] {
			return true
		}
		if i+1 >= len(g.spans) || strings.Trim(g.src[g.spans[i][1]:g.spans[i+1][0]], " \t\r\n,+") != "" {
			return false
		}
	}
	return false
}

// verdict classifies a match at [start, end) of a Go file: "" when it is
// code, "pattern" when it lies inside a regular expression handed to the
// regexp package (text that is never run or rendered), "string" when it
// lies inside other string literals (data, which is code only if the
// program later serves or evaluates it).
func (g *goLiterals) verdict(start, end int) string {
	if i := g.within(start, end); i >= 0 {
		if g.pattern[i] {
			return "pattern"
		}
		return "string"
	}
	if g.acrossLiterals(start, end) {
		return "string"
	}
	return ""
}

// goStringDemote lists a signal whose match lies inside a Go string
// literal as info, keeping the rule's title so it can still be found.
func goStringDemote(s *model.Signal) {
	s.Severity, s.Confidence = model.SevInfo, model.Hypothesis
	s.Title = "Inside a Go string literal: " + s.Title
	s.Message = "The matched text is inside a Go string literal, so it is data in this file, not code. It matters only if the program serves or evaluates the string, for example as a page, a script or a query."
	s.Fix = "Review where the string goes; nothing to change if it is never served or evaluated."
}
