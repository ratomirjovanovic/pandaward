// Package redos finds regular expressions whose matching time grows
// exponentially or polynomially with the input on a backtracking engine
// (JavaScript's). It builds the automaton of the pattern and looks for
// ambiguity in it: a state that two different paths leave and return to on
// the same text (exponential), or two states on cycles where one text
// loops on the first and leads to the second (polynomial). Patterns with
// back references are not analyzed.
package redos

import (
	"sort"
	"strconv"
	"strings"
)

// Result is what the analysis finds in a pattern.
type Result struct {
	// Exponential: matching can take time exponential in the input.
	Exponential bool
	// Polynomial: matching can take time at least quadratic in the input
	// (and not exponential).
	Polynomial bool
	// Attack is a text that repeats and a character that makes the match
	// fail, for a message.
	Pump string
}

// Analyze checks a pattern (the text between the slashes) with its flags.
func Analyze(pattern, flags string) Result {
	p := &parser{src: []rune(pattern), icase: strings.Contains(flags, "i"), dotAll: strings.Contains(flags, "s"), multi: strings.Contains(flags, "m")}
	n := p.alt()
	if p.bad || p.pos < len(p.src) || p.backref {
		return Result{}
	}
	b := &builder{}
	start := b.new()
	acc := b.new()
	if !b.build(n, start, acc) || b.over {
		return Result{}
	}
	nfa := b.finish(start, acc, p.anchored && !p.multi, p.endAnchored && !p.multi)
	if nfa == nil {
		return Result{}
	}
	return nfa.analyze()
}

// ---- character sets

// set is a sorted list of disjoint, inclusive rune ranges.
type set [][2]rune

const maxRune = 0x10FFFF

// endSym is the symbol that stands for the end of the input, consumed only
// by $.
const endSym = maxRune + 1

func (s set) has(r rune) bool {
	for _, x := range s {
		if r >= x[0] && r <= x[1] {
			return true
		}
	}
	return false
}

func norm(s set) set {
	sort.Slice(s, func(i, j int) bool { return s[i][0] < s[j][0] })
	var out set
	for _, x := range s {
		if n := len(out); n > 0 && x[0] <= out[n-1][1]+1 {
			if x[1] > out[n-1][1] {
				out[n-1][1] = x[1]
			}
			continue
		}
		out = append(out, x)
	}
	return out
}

func negate(s set) set {
	s = norm(append(set{}, s...))
	var out set
	next := rune(0)
	for _, x := range s {
		if x[0] > next {
			out = append(out, [2]rune{next, x[0] - 1})
		}
		next = x[1] + 1
	}
	if next <= maxRune {
		out = append(out, [2]rune{next, maxRune})
	}
	return out
}

func intersects(a, b set) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i][1] < b[j][0] {
			i++
		} else if b[j][1] < a[i][0] {
			j++
		} else {
			return true
		}
	}
	return false
}

func union(a, b set) set { return norm(append(append(set{}, a...), b...)) }

var (
	digit = set{{'0', '9'}}
	word  = set{{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}}
	space = set{{9, 13}, {' ', ' '}, {0xA0, 0xA0}, {0x1680, 0x1680}, {0x2000, 0x200A}, {0x2028, 0x2029}, {0x202F, 0x202F}, {0x205F, 0x205F}, {0x3000, 0x3000}, {0xFEFF, 0xFEFF}}
	dot   = set{{0, 9}, {11, 12}, {14, 0x2027}, {0x202A, maxRune}}
	all   = set{{0, maxRune}}
)

func fold(s set) set {
	out := append(set{}, s...)
	for _, x := range s {
		lo, hi := x[0], x[1]
		if lo < 'A' {
			lo = 'A'
		}
		if hi > 'z' {
			hi = 'z'
		}
		for c := lo; c <= hi; c++ {
			switch {
			case c >= 'A' && c <= 'Z':
				out = append(out, [2]rune{c + 32, c + 32})
			case c >= 'a' && c <= 'z':
				out = append(out, [2]rune{c - 32, c - 32})
			}
		}
	}
	return norm(out)
}

// ---- syntax tree

type kind int

const (
	kSet kind = iota
	kSeq
	kAlt
	kRep
	kEmpty
	kEnd // $
)

type node struct {
	k        kind
	set      set
	kids     []*node
	min, max int // kRep; max -1 is unbounded
}

type parser struct {
	src                   []rune
	pos                   int
	icase, dotAll, multi  bool
	bad, backref          bool
	anchored, endAnchored bool
	depth                 int
	last                  rune
}

func (p *parser) more() bool { return p.pos < len(p.src) }
func (p *parser) peek() rune {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

func (p *parser) alt() *node {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 40 {
		p.bad = true
		return &node{k: kEmpty}
	}
	top := p.depth == 1
	first := p.seq(top)
	if !p.more() || p.peek() != '|' {
		return first
	}
	alts := []*node{first}
	// Anchors at the start of a pattern of alternatives bind to one
	// alternative only.
	if top {
		p.anchored, p.endAnchored = false, false
	}
	for p.more() && p.peek() == '|' {
		p.pos++
		alts = append(alts, p.seq(false))
	}
	return &node{k: kAlt, kids: alts}
}

func (p *parser) seq(top bool) *node {
	var items []*node
	for p.more() && p.peek() != '|' && p.peek() != ')' {
		if top && len(items) == 0 && p.peek() == '^' {
			p.anchored = true
		}
		a := p.atom()
		if p.bad {
			return &node{k: kEmpty}
		}
		if a == nil {
			continue
		}
		a = p.quant(a)
		items = append(items, a)
	}
	if top && len(items) > 0 && items[len(items)-1].k == kEnd {
		p.endAnchored = true
	}
	return &node{k: kSeq, kids: items}
}

func (p *parser) quant(a *node) *node {
	for p.more() {
		min, max := -2, -2
		switch p.peek() {
		case '*':
			min, max = 0, -1
			p.pos++
		case '+':
			min, max = 1, -1
			p.pos++
		case '?':
			min, max = 0, 1
			p.pos++
		case '{':
			save := p.pos
			p.pos++
			lo, ok := p.number()
			if !ok {
				p.pos = save
				return a
			}
			min, max = lo, lo
			if p.peek() == ',' {
				p.pos++
				if p.peek() == '}' {
					max = -1
				} else if hi, ok := p.number(); ok {
					max = hi
				} else {
					p.pos = save
					return a
				}
			}
			if p.peek() != '}' {
				p.pos = save
				return a
			}
			p.pos++
		default:
			return a
		}
		if p.more() && p.peek() == '?' {
			p.pos++ // lazy: same language
		}
		a = &node{k: kRep, kids: []*node{a}, min: min, max: max}
	}
	return a
}

func (p *parser) number() (int, bool) {
	start := p.pos
	for p.more() && p.peek() >= '0' && p.peek() <= '9' {
		p.pos++
	}
	if start == p.pos {
		return 0, false
	}
	n, err := strconv.Atoi(string(p.src[start:p.pos]))
	if err != nil || n > 1000 {
		return 1000, true
	}
	return n, true
}

func (p *parser) leaf(s set) *node {
	if p.icase {
		s = fold(s)
	}
	return &node{k: kSet, set: s}
}

func (p *parser) atom() *node {
	c := p.peek()
	switch c {
	case '^':
		p.pos++
		if p.multi {
			return nil
		}
		return nil // handled by the anchored flag
	case '$':
		p.pos++
		if p.multi {
			return nil
		}
		return &node{k: kEnd}
	case '.':
		p.pos++
		if p.dotAll {
			return p.leaf(all)
		}
		return p.leaf(dot)
	case '(':
		p.pos++
		look := false
		if p.peek() == '?' {
			p.pos++
			switch p.peek() {
			case ':':
				p.pos++
			case '=', '!':
				look = true
				p.pos++
			case '<':
				p.pos++
				if p.peek() == '=' || p.peek() == '!' {
					look = true
					p.pos++
				} else {
					for p.more() && p.peek() != '>' {
						p.pos++
					}
					p.pos++
				}
			default:
				p.bad = true
				return nil
			}
		}
		inner := p.alt()
		if p.peek() != ')' {
			p.bad = true
			return nil
		}
		p.pos++
		if look {
			return &node{k: kEmpty} // not followed into
		}
		return inner
	case '[':
		return p.class()
	case '\\':
		return p.escape()
	case '*', '+', '?':
		p.bad = true
		return nil
	}
	p.pos++
	return p.leaf(set{{c, c}})
}

func (p *parser) escape() *node {
	p.pos++ // backslash
	if !p.more() {
		p.bad = true
		return nil
	}
	c := p.src[p.pos]
	p.pos++
	switch c {
	case 'b', 'B':
		return &node{k: kEmpty}
	case '1', '2', '3', '4', '5', '6', '7', '8', '9', 'k':
		p.backref = true
		return nil
	}
	if s, ok := p.classEscape(c); ok {
		return p.leaf(s)
	}
	r := p.escapedChar(c)
	return p.leaf(set{{r, r}})
}

func (p *parser) classEscape(c rune) (set, bool) {
	switch c {
	case 'd':
		return digit, true
	case 'D':
		return negate(digit), true
	case 'w':
		return word, true
	case 'W':
		return negate(word), true
	case 's':
		return space, true
	case 'S':
		return negate(space), true
	}
	return nil, false
}

// escapedChar decodes the escape whose letter c was read and stores the
// code point in p.last; it returns it too.
func (p *parser) escapedChar(c rune) rune {
	r := c
	switch c {
	case 'n':
		r = '\n'
	case 'r':
		r = '\r'
	case 't':
		r = '\t'
	case 'f':
		r = '\f'
	case 'v':
		r = '\v'
	case '0':
		r = 0
	case 'x':
		r = p.hex(2, c)
	case 'u':
		if p.peek() == '{' {
			p.pos++
			start := p.pos
			for p.more() && p.peek() != '}' {
				p.pos++
			}
			v, err := strconv.ParseUint(string(p.src[start:p.pos]), 16, 32)
			p.pos++
			if err != nil {
				return c
			}
			r = rune(v)
		} else {
			r = p.hex(4, c)
		}
	case 'c':
		if p.more() {
			r = p.src[p.pos] % 32
			p.pos++
		}
	}
	p.last = r
	return r
}

func (p *parser) hex(n int, fallback rune) rune {
	if p.pos+n > len(p.src) {
		return fallback
	}
	v, err := strconv.ParseUint(string(p.src[p.pos:p.pos+n]), 16, 32)
	if err != nil {
		return fallback
	}
	p.pos += n
	return rune(v)
}

func (p *parser) class() *node {
	p.pos++ // [
	neg := false
	if p.peek() == '^' {
		neg = true
		p.pos++
	}
	var s set
	for {
		if !p.more() {
			p.bad = true
			return nil
		}
		c := p.src[p.pos]
		if c == ']' {
			p.pos++
			break
		}
		lo, isSet, cs := p.classAtom()
		if isSet {
			s = append(s, cs...)
			continue
		}
		hi := lo
		if p.peek() == '-' && p.pos+1 < len(p.src) && p.src[p.pos+1] != ']' {
			save := p.pos
			p.pos++
			h, hset, hs := p.classAtom()
			if hset {
				s = append(s, [2]rune{lo, lo}, [2]rune{'-', '-'})
				s = append(s, hs...)
				continue
			}
			if h < lo {
				p.pos = save
				p.bad = true
				return nil
			}
			hi = h
		}
		s = append(s, [2]rune{lo, hi})
	}
	s = norm(s)
	if p.icase {
		s = fold(s)
	}
	if neg {
		s = negate(s)
	}
	return &node{k: kSet, set: s}
}

// classAtom reads one member of a class: a character, or a set.
func (p *parser) classAtom() (rune, bool, set) {
	c := p.src[p.pos]
	p.pos++
	if c != '\\' {
		return c, false, nil
	}
	if !p.more() {
		p.bad = true
		return 0, false, nil
	}
	e := p.src[p.pos]
	p.pos++
	if e == 'b' {
		return 8, false, nil
	}
	if s, ok := p.classEscape(e); ok {
		return 0, true, s
	}
	return p.escapedChar(e), false, nil
}
