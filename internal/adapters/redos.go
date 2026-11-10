package adapters

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/ratomirjovanovic/pandaward/internal/inventory"
	"github.com/ratomirjovanovic/pandaward/internal/model"
)

// ReDoS analysis of JavaScript regular expressions (CWE-1333).
//
// A backtracking matcher such as V8's tries every way a pattern can match a
// prefix of the input before it gives up. Two shapes make that slow:
//
//   - exponential: a loop whose body can match the same text in two ways,
//     as in (a+)+$ or (.*,)+$, doubles the work with every repetition;
//   - polynomial: two loops in sequence that accept the same text, as in
//     \s*\s*$, or one loop the search can start at any input position, as in
//     an unanchored \s+$, make the work grow with the square of the input.
//
// The pattern is turned into its position automaton (Glushkov), where every
// state is one character class of the pattern and an edge counts the
// distinct ways the pattern can step from one to the next. For each
// character the automaton is reduced to the edges that accept it. A loop
// part (strongly connected component) with more edges than states can match
// a run of that character in two ways: exponential. Two looping parts where
// the second is reachable from the first, or reachable from the start of an
// unanchored search, split a run of that character in many ways: polynomial.
// Either matters only when the match can still fail after the run, so the
// later loop must not be able to end the match. Assertions, lookarounds
// and backreferences are treated as states no character passes, so they
// only ever hide a finding. Repetition counts above maxRepeat are cut to
// maxRepeat, which also only hides findings.

const maxRepeat = 20

type redosKind int

const (
	redosNone redosKind = iota
	redosPolynomial
	redosExponential
)

// redosResult describes the worst shape found and a character that pumps it.
type redosResult struct {
	Kind redosKind
	Pump rune
}

type runeRange struct{ lo, hi rune }

type charSet []runeRange

func (s charSet) has(r rune) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i].hi >= r })
	return i < len(s) && s[i].lo <= r
}

func normSet(rs []runeRange) charSet {
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	var out charSet
	for _, r := range rs {
		if r.lo > r.hi {
			continue
		}
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			if r.hi > out[n-1].hi {
				out[n-1].hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func negateSet(s charSet) charSet {
	var out charSet
	next := rune(0)
	for _, r := range s {
		if r.lo > next {
			out = append(out, runeRange{next, r.lo - 1})
		}
		next = r.hi + 1
	}
	if next <= unicode.MaxRune {
		out = append(out, runeRange{next, unicode.MaxRune})
	}
	return out
}

func foldSet(s charSet) charSet {
	rs := append([]runeRange(nil), s...)
	for _, r := range s {
		for c := r.lo; c <= r.hi && c <= 0x7f; c++ {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
				o := c ^ 0x20
				rs = append(rs, runeRange{o, o})
			}
		}
	}
	return normSet(rs)
}

var (
	digitSet = charSet{{'0', '9'}}
	wordSet  = normSet([]runeRange{{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}})
	spaceSet = normSet([]runeRange{{'\t', '\r'}, {' ', ' '}, {0xa0, 0xa0}, {0x1680, 0x1680}, {0x2000, 0x200a},
		{0x2028, 0x2029}, {0x202f, 0x202f}, {0x205f, 0x205f}, {0x3000, 0x3000}, {0xfeff, 0xfeff}})
	lineEnds = normSet([]runeRange{{'\n', '\n'}, {'\r', '\r'}, {0x2028, 0x2029}})
	anySet   = charSet{{0, unicode.MaxRune}}
)

// Regex syntax tree.
type rxNode struct {
	op       byte // 'c' class, 'a' assertion, '.' concat, '|' alternation, '*' repeat
	set      charSet
	subs     []*rxNode
	min, max int // repeat bounds; max < 0 is unbounded
}

type rxParser struct {
	src    []rune
	i      int
	fold   bool
	dotAll bool
	groups int
}

type rxError struct{}

func (p *rxParser) peek() rune {
	if p.i < len(p.src) {
		return p.src[p.i]
	}
	return -1
}

func (p *rxParser) next() rune {
	c := p.peek()
	if c < 0 {
		panic(rxError{})
	}
	p.i++
	return c
}

// parseJSRegex parses a JavaScript pattern with its flags. ok is false for
// syntax the parser does not understand.
func parseJSRegex(pattern, flags string) (n *rxNode, ok bool) {
	p := &rxParser{src: []rune(pattern), fold: strings.Contains(flags, "i"), dotAll: strings.Contains(flags, "s")}
	defer func() {
		if r := recover(); r != nil {
			if _, is := r.(rxError); !is {
				panic(r)
			}
			n, ok = nil, false
		}
	}()
	n = p.alt()
	if p.i != len(p.src) {
		return nil, false
	}
	return n, true
}

func (p *rxParser) alt() *rxNode {
	subs := []*rxNode{p.seq()}
	for p.peek() == '|' {
		p.i++
		subs = append(subs, p.seq())
	}
	if len(subs) == 1 {
		return subs[0]
	}
	return &rxNode{op: '|', subs: subs}
}

func (p *rxParser) seq() *rxNode {
	n := &rxNode{op: '.'}
	for c := p.peek(); c >= 0 && c != '|' && c != ')'; c = p.peek() {
		a := p.atom()
		n.subs = append(n.subs, p.quant(a))
	}
	return n
}

func (p *rxParser) quant(a *rxNode) *rxNode {
	lo, hi := 0, 0
	switch p.peek() {
	case '*':
		p.i++
		lo, hi = 0, -1
	case '+':
		p.i++
		lo, hi = 1, -1
	case '?':
		p.i++
		lo, hi = 0, 1
	case '{':
		save := p.i
		p.i++
		m, okm := p.num()
		if !okm {
			p.i = save
			return a
		}
		lo, hi = m, m
		if p.peek() == ',' {
			p.i++
			hi = -1
			if n, okn := p.num(); okn {
				hi = n
			}
		}
		if p.peek() != '}' {
			p.i = save
			return a
		}
		p.i++
	default:
		return a
	}
	if p.peek() == '?' {
		p.i++ // lazy: same automaton
	}
	if a.op == 'a' {
		return a
	}
	return &rxNode{op: '*', subs: []*rxNode{a}, min: lo, max: hi}
}

func (p *rxParser) num() (int, bool) {
	start := p.i
	for c := p.peek(); c >= '0' && c <= '9'; c = p.peek() {
		p.i++
	}
	if p.i == start {
		return 0, false
	}
	n, err := strconv.Atoi(string(p.src[start:p.i]))
	if err != nil || n > 1000 {
		n = 1000
	}
	return n, true
}

func (p *rxParser) class(s charSet) *rxNode {
	if p.fold {
		s = foldSet(s)
	}
	return &rxNode{op: 'c', set: s}
}

func (p *rxParser) atom() *rxNode {
	c := p.next()
	switch c {
	case '^', '$':
		return &rxNode{op: 'a'}
	case '.':
		if p.dotAll {
			return p.class(anySet)
		}
		return p.class(negateSet(lineEnds))
	case '(':
		look := false
		if p.peek() == '?' {
			p.i++
			switch p.next() {
			case ':':
			case '=', '!':
				look = true
			case '<':
				if q := p.peek(); q == '=' || q == '!' {
					p.i++
					look = true
				} else {
					for p.next() != '>' {
					}
					p.groups++
				}
			default:
				panic(rxError{})
			}
		} else {
			p.groups++
		}
		n := p.alt()
		if p.next() != ')' {
			panic(rxError{})
		}
		if look {
			return &rxNode{op: 'a'}
		}
		return n
	case '[':
		return p.class(p.bracket())
	case '\\':
		return p.escape()
	case '*', '+', '?', ')':
		panic(rxError{})
	}
	return p.class(charSet{{c, c}})
}

func (p *rxParser) bracket() charSet {
	neg := false
	if p.peek() == '^' {
		p.i++
		neg = true
	}
	var rs []runeRange
	first := true
	for {
		c := p.next()
		if c == ']' && !first {
			break
		}
		if c == ']' {
			break // [] matches nothing, [^] anything
		}
		first = false
		var lo charSet
		single := rune(-1)
		if c == '\\' {
			lo, single = p.classEscape()
		} else {
			single = c
		}
		if single >= 0 && p.peek() == '-' && p.i+1 < len(p.src) && p.src[p.i+1] != ']' {
			p.i++
			d := p.next()
			hi := d
			if d == '\\' {
				var hs charSet
				hs, hi = p.classEscape()
				if hi < 0 {
					rs = append(rs, runeRange{single, single}, runeRange{'-', '-'})
					rs = append(rs, hs...)
					continue
				}
			}
			if hi < single {
				panic(rxError{})
			}
			rs = append(rs, runeRange{single, hi})
			continue
		}
		if single >= 0 {
			rs = append(rs, runeRange{single, single})
		} else {
			rs = append(rs, lo...)
		}
	}
	s := normSet(rs)
	if neg {
		return negateSet(s)
	}
	return s
}

// classEscape reads an escape inside a bracket: either a set (\d) or a single
// rune.
func (p *rxParser) classEscape() (charSet, rune) {
	c := p.next()
	switch c {
	case 'd':
		return digitSet, -1
	case 'D':
		return negateSet(digitSet), -1
	case 'w':
		return wordSet, -1
	case 'W':
		return negateSet(wordSet), -1
	case 's':
		return spaceSet, -1
	case 'S':
		return negateSet(spaceSet), -1
	case 'b':
		return nil, '\b'
	}
	return nil, p.escapedRune(c)
}

func (p *rxParser) escapedRune(c rune) rune {
	switch c {
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'v':
		return '\v'
	case 'f':
		return '\f'
	case '0':
		return 0
	case 'c':
		return p.next() % 32
	case 'x':
		return p.hex(2)
	case 'u':
		if p.peek() == '{' {
			p.i++
			start := p.i
			for p.next() != '}' {
			}
			v, err := strconv.ParseUint(string(p.src[start:p.i-1]), 16, 32)
			if err != nil || v > unicode.MaxRune {
				panic(rxError{})
			}
			return rune(v)
		}
		return p.hex(4)
	}
	return c
}

func (p *rxParser) hex(n int) rune {
	if p.i+n > len(p.src) {
		panic(rxError{})
	}
	v, err := strconv.ParseUint(string(p.src[p.i:p.i+n]), 16, 32)
	if err != nil || v > unicode.MaxRune {
		panic(rxError{})
	}
	p.i += n
	return rune(v)
}

func (p *rxParser) escape() *rxNode {
	c := p.peek()
	switch {
	case c == 'b' || c == 'B':
		p.i++
		return &rxNode{op: 'a'}
	case c >= '1' && c <= '9', c == 'k':
		// Backreference: no character passes it in this model.
		p.i++
		if c == 'k' && p.peek() == '<' {
			for p.next() != '>' {
			}
		}
		for d := p.peek(); d >= '0' && d <= '9'; d = p.peek() {
			p.i++
		}
		return &rxNode{op: 'a'}
	case c == 'p' || c == 'P':
		// Unicode property: any character, an over-approximation that keeps
		// loops over it comparable.
		p.i++
		if p.peek() == '{' {
			for p.next() != '}' {
			}
		}
		return p.class(anySet)
	}
	s, r := p.classEscape()
	if r >= 0 {
		return p.class(charSet{{r, r}})
	}
	return p.class(s)
}

// Glushkov automaton with edge multiplicities capped at 2.

type gpos struct {
	set    charSet
	assert bool
}

type gInfo struct {
	nullable    bool
	first, last map[int]int
}

type glushkov struct {
	pos    []gpos
	follow []map[int]int
	tooBig bool
}

const maxPositions = 400

func addMult(dst map[int]int, k, v int) {
	if dst[k]+v > 2 {
		dst[k] = 2
	} else {
		dst[k] += v
	}
}

func (g *glushkov) link(from, to map[int]int) {
	for x, mx := range from {
		for y, my := range to {
			addMult(g.follow[x], y, mx*my)
		}
	}
}

func union(a, b map[int]int) map[int]int {
	out := map[int]int{}
	for k, v := range a {
		addMult(out, k, v)
	}
	for k, v := range b {
		addMult(out, k, v)
	}
	return out
}

func (g *glushkov) build(n *rxNode) gInfo {
	if len(g.pos) > maxPositions {
		g.tooBig = true
		return gInfo{nullable: true, first: map[int]int{}, last: map[int]int{}}
	}
	switch n.op {
	case 'c', 'a':
		id := len(g.pos)
		g.pos = append(g.pos, gpos{set: n.set, assert: n.op == 'a'})
		g.follow = append(g.follow, map[int]int{})
		one := map[int]int{id: 1}
		return gInfo{first: one, last: map[int]int{id: 1}}
	case '|':
		out := gInfo{first: map[int]int{}, last: map[int]int{}}
		for _, s := range n.subs {
			i := g.build(s)
			out.nullable = out.nullable || i.nullable
			out.first, out.last = union(out.first, i.first), union(out.last, i.last)
		}
		return out
	case '.':
		out := gInfo{nullable: true, first: map[int]int{}, last: map[int]int{}}
		for _, s := range n.subs {
			i := g.build(s)
			g.link(out.last, i.first)
			if out.nullable {
				out.first = union(out.first, i.first)
			}
			if i.nullable {
				out.last = union(out.last, i.last)
			} else {
				out.last = i.last
			}
			out.nullable = out.nullable && i.nullable
		}
		return out
	case '*':
		lo, hi := n.min, n.max
		if lo > maxRepeat {
			lo = maxRepeat
		}
		if hi > maxRepeat {
			hi = maxRepeat
		}
		// E{lo,hi} = E...E (lo times) then (hi-lo) optional copies, or a
		// star when unbounded.
		seq := &rxNode{op: '.'}
		for k := 0; k < lo; k++ {
			seq.subs = append(seq.subs, n.subs[0])
		}
		var tail *rxNode
		if hi < 0 {
			tail = &rxNode{op: 'S', subs: n.subs}
		} else {
			for k := lo; k < hi; k++ {
				seq.subs = append(seq.subs, &rxNode{op: '?', subs: n.subs})
			}
		}
		if tail != nil {
			seq.subs = append(seq.subs, tail)
		}
		return g.build(seq)
	case 'S', '?':
		i := g.build(n.subs[0])
		if n.op == 'S' {
			g.link(i.last, i.first)
		}
		i.nullable = true
		return i
	}
	return gInfo{nullable: true, first: map[int]int{}, last: map[int]int{}}
}

// analyzeRegex finds the worst backtracking shape of a JavaScript pattern.
func analyzeRegex(pattern, flags string) redosResult {
	n, ok := parseJSRegex(pattern, flags)
	if !ok {
		return redosResult{}
	}
	g := &glushkov{}
	info := g.build(n)
	if g.tooBig || len(g.pos) == 0 {
		return redosResult{}
	}
	// State len(g.pos) is the search start: it loops on any character and
	// steps to the pattern's first positions, unless the regex is sticky.
	start := len(g.pos)
	sticky := strings.Contains(flags, "y")
	accepting := map[int]bool{}
	for x := range info.last {
		if !g.pos[x].assert {
			accepting[x] = true
		}
	}
	best := redosResult{}
	for _, a := range representatives(g.pos) {
		r := analyzeChar(g, info, start, sticky, accepting, a)
		if r > best.Kind {
			best = redosResult{Kind: r, Pump: a}
			if r == redosExponential {
				break
			}
		}
	}
	return best
}

// representatives returns one rune for each region of the alphabet that all
// positions treat alike.
func representatives(pos []gpos) []rune {
	cuts := map[rune]bool{0: true}
	for _, p := range pos {
		for _, r := range p.set {
			cuts[r.lo] = true
			if r.hi < unicode.MaxRune {
				cuts[r.hi+1] = true
			}
		}
	}
	out := make([]rune, 0, len(cuts))
	for r := range cuts {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func analyzeChar(g *glushkov, info gInfo, start int, sticky bool, accepting map[int]bool, a rune) redosKind {
	n := len(g.pos) + 1
	type edge struct{ to, mult int }
	adj := make([][]edge, n)
	for x, f := range g.follow {
		for y, m := range f {
			if !g.pos[y].assert && g.pos[y].set.has(a) {
				adj[x] = append(adj[x], edge{y, m})
			}
		}
	}
	if !sticky {
		adj[start] = append(adj[start], edge{start, 1})
		for y := range info.first {
			if !g.pos[y].assert && g.pos[y].set.has(a) {
				adj[start] = append(adj[start], edge{y, 1})
			}
		}
	}
	// Tarjan's strongly connected components.
	comp := make([]int, n)
	for i := range comp {
		comp[i] = -1
	}
	index := make([]int, n)
	low := make([]int, n)
	onStack := make([]bool, n)
	var stack []int
	counter, ncomp := 0, 0
	var strong func(v int)
	strong = func(v int) {
		counter++
		index[v], low[v] = counter, counter
		stack = append(stack, v)
		onStack[v] = true
		for _, e := range adj[v] {
			if index[e.to] == 0 {
				strong(e.to)
				low[v] = min(low[v], low[e.to])
			} else if onStack[e.to] {
				low[v] = min(low[v], index[e.to])
			}
		}
		if low[v] == index[v] {
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				comp[w] = ncomp
				if w == v {
					break
				}
			}
			ncomp++
		}
	}
	for v := 0; v < n; v++ {
		if index[v] == 0 {
			strong(v)
		}
	}
	nodes := make([]int, ncomp)
	edges := make([]int, ncomp)
	canEnd := make([]bool, ncomp)
	for v := 0; v < n; v++ {
		nodes[comp[v]]++
		if accepting[v] {
			canEnd[comp[v]] = true
		}
		for _, e := range adj[v] {
			if comp[e.to] == comp[v] {
				edges[comp[v]] += e.mult
			}
		}
	}
	cyclic := func(c int) bool { return edges[c] > 0 }
	for c := 0; c < ncomp; c++ {
		if c != comp[start] && edges[c] > nodes[c] && !canEnd[c] {
			return redosExponential
		}
	}
	// Polynomial: a cyclic component reachable on this character from
	// another cyclic component, and unable to end the match.
	for v := 0; v < n; v++ {
		if !cyclic(comp[v]) {
			continue
		}
		seen := make([]bool, n)
		todo := []int{v}
		seen[v] = true
		for len(todo) > 0 {
			x := todo[len(todo)-1]
			todo = todo[:len(todo)-1]
			for _, e := range adj[x] {
				if seen[e.to] {
					continue
				}
				seen[e.to] = true
				c := comp[e.to]
				if c != comp[v] && cyclic(c) && !canEnd[c] {
					return redosPolynomial
				}
				todo = append(todo, e.to)
			}
		}
	}
	return redosNone
}

// jsRegexLiteral is a regular expression written in JavaScript source.
type jsRegexLiteral struct {
	Pattern, Flags string
	Offset         int
}

var regExpCallRe = regexp.MustCompile(`\bRegExp\s*\(\s*$`)

// jsRegexLiterals lists the regex literals of src and the string literals
// passed directly to RegExp(...).
func jsRegexLiterals(src string) []jsRegexLiteral {
	var out []jsRegexLiteral
	var prev byte
	word := ""
	for i := 0; i < len(src); {
		j := jsSkip(src, i, prev, word)
		if j == i {
			c := src[i]
			switch {
			case isIdent(c):
				if i == 0 || !isIdent(src[i-1]) {
					word = ""
				}
				word += string(c)
				prev = c
			case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			default:
				prev, word = c, ""
			}
			i++
			continue
		}
		lit := src[i:j]
		switch c := src[i]; {
		case c == '/' && len(lit) > 1 && lit[1] != '/' && lit[1] != '*':
			end := strings.LastIndexByte(lit, '/')
			out = append(out, jsRegexLiteral{Pattern: lit[1:end], Flags: lit[end+1:], Offset: i})
		case (c == '\'' || c == '"') && regExpCallRe.MatchString(src[max(0, i-40):i]):
			if s, ok := unquoteJS(lit); ok {
				flags := ""
				rest := strings.TrimLeft(src[j:], " \t")
				if strings.HasPrefix(rest, ",") {
					rest = strings.TrimLeft(rest[1:], " \t")
					if len(rest) > 0 && (rest[0] == '\'' || rest[0] == '"') {
						if k := strings.IndexByte(rest[1:], rest[0]); k >= 0 {
							flags = rest[1 : k+1]
						}
					}
				}
				out = append(out, jsRegexLiteral{Pattern: s, Flags: flags, Offset: i})
			}
		}
		if comment := src[i] == '/' && i+1 < len(src) && (src[i+1] == '/' || src[i+1] == '*'); !comment {
			prev, word = '"', ""
		}
		i = j
	}
	return out
}

// unquoteJS decodes a single or double quoted JavaScript string literal.
func unquoteJS(lit string) (string, bool) {
	if len(lit) < 2 {
		return "", false
	}
	body := lit[1 : len(lit)-1]
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(body) {
			return "", false
		}
		switch e := body[i]; e {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case 'f':
			b.WriteByte('\f')
		case 'b':
			b.WriteByte('\b')
		case '0':
			b.WriteByte(0)
		case 'x', 'u':
			n := 2
			if e == 'u' {
				n = 4
			}
			if e == 'u' && i+1 < len(body) && body[i+1] == '{' {
				k := strings.IndexByte(body[i:], '}')
				if k < 0 {
					return "", false
				}
				v, err := strconv.ParseUint(body[i+2:i+k], 16, 32)
				if err != nil || v > unicode.MaxRune {
					return "", false
				}
				b.WriteRune(rune(v))
				i += k
				continue
			}
			if i+n >= len(body) {
				return "", false
			}
			v, err := strconv.ParseUint(body[i+1:i+1+n], 16, 32)
			if err != nil || v > unicode.MaxRune {
				return "", false
			}
			b.WriteRune(rune(v))
			i += n
		case '\n':
		default:
			b.WriteByte(e)
		}
	}
	return b.String(), true
}

var (
	redosExpRule = lineRule{ID: "code.js-redos", Control: "D-007", Title: "Regular expression with exponential backtracking",
		Severity: model.SevMedium, Confidence: model.Hypothesis, CWE: "CWE-1333",
		Fix: "Rewrite the pattern so each part of the input can be matched in only one way (for example (a+)+ as a+, or make alternatives exclusive), or bound the input length before matching."}
	redosPolyRule = lineRule{ID: "code.js-redos-polynomial", Control: "D-007", Title: "Regular expression with polynomial backtracking",
		Severity: model.SevInfo, Confidence: model.Hypothesis, CWE: "CWE-1333",
		Fix: "Anchor the pattern, make neighbouring repetitions accept different characters, or limit the input length before matching. Nothing to change when the input is always short or trusted."}
)

// redosSignals reports the regular expressions of a JavaScript or
// TypeScript file that backtrack catastrophically. Exponential cases are
// suspected findings. Polynomial ones are listed for review only: they
// matter when long input from outside reaches the pattern, which this check
// does not follow.
func redosSignals(f *inventory.File, text, collector string) []model.Signal {
	var out []model.Signal
	line, at := 1, 0
	for _, l := range jsRegexLiterals(text) {
		line += strings.Count(text[at:l.Offset], "\n")
		at = l.Offset
		r := analyzeRegex(l.Pattern, l.Flags)
		if r.Kind == redosNone || line > len(f.Lines) {
			continue
		}
		rule := redosPolyRule
		rule.Message = fmt.Sprintf("Input with a long run of %s followed by a character that makes the match fail takes time that grows with the square of its length or worse, because the pattern can split the run between repetitions in many ways.", pumpName(r.Pump))
		if r.Kind == redosExponential {
			rule = redosExpRule
			rule.Message = fmt.Sprintf("Input with a run of %s followed by a character that makes the match fail takes time that doubles with every character, because a repetition in the pattern can match the same text in more than one way. A short request can block the event loop.", pumpName(r.Pump))
		}
		out = append(out, sig(rule, f, line, collector))
	}
	return out
}

func pumpName(r rune) string {
	switch {
	case r == ' ':
		return "spaces"
	case r == '\t':
		return "whitespace"
	case r == '\n':
		return "line breaks"
	case r < 0x20 || r == 0x7f:
		return fmt.Sprintf("the control character U+%04X", r)
	case r >= '0' && r <= '9':
		return "digits"
	case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
		return "letters"
	}
	return fmt.Sprintf("%q characters", string(r))
}
