package php

import (
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

const (
	maxIncludeDepth = 3
	maxSplices      = 12
	maxCandidates   = 8
)

// splice lowers the files an include expression (tokens start to end) can
// name, in place. Several candidates are alternatives: one of them runs.
func (p *parser) splice(start, end int) {
	if p.env == nil || p.env.Include == nil || len(p.stack) > maxIncludeDepth || end <= start {
		return
	}
	seg, dynamic := includeSegment(p.toks[start:end])
	seg = strings.TrimLeft(strings.ReplaceAll(seg, "\\", "/"), "./")
	if len(seg) < 3 {
		return
	}
	var cands []Source
	for _, c := range p.env.Include(seg, dynamic) {
		if len(c.Src) > 0 && strings.Count(c.Src, "\n") < Slot-1 && !p.including(c.Path) {
			cands = append(cands, c)
		}
	}
	if len(cands) == 0 || len(cands) > maxCandidates || len(p.slots)+len(cands) > maxSplices {
		return
	}
	join := p.newBlock()
	for i, c := range cands {
		next := join
		if i < len(cands)-1 {
			next = p.newBlock()
		}
		if len(cands) > 1 {
			// one of the alternatives runs
			body := p.newBlock()
			p.branch(ir.C(ir.Other, "include"), p.pos(), body, next)
			p.cur = body
		}
		p.slots = append(p.slots, c.Path)
		toks, at := p.toks, p.p
		p.toks, p.p = lex(c.Src, len(p.slots)*Slot+1, false), 0
		p.stack = append(p.stack, c.Path)
		for p.peek().k != tEOF {
			p.stmt()
		}
		p.stack = p.stack[:len(p.stack)-1]
		p.toks, p.p = toks, at
		p.jump(join)
		p.cur = next
		if next == join {
			p.cur = join
		}
	}
	if p.cur == nil {
		p.cur = join
	}
}

func (p *parser) including(path string) bool {
	for _, s := range p.stack {
		if s == path {
			return true
		}
	}
	return false
}

// includeSegment returns the literal piece of an include path that names
// the file: the text after the last part that is not known, or, when the
// path ends in one, the text before it (dynamic).
func includeSegment(toks []token) (string, bool) {
	var segs []string
	cur := ""
	for _, t := range toks {
		switch t.k {
		case tStr:
			cur += t.s
		case tTpl:
			for _, part := range t.parts {
				if part.code == "" {
					cur += part.lit
					continue
				}
				segs = append(segs, cur)
				cur = ""
			}
		case tVar:
			segs = append(segs, cur)
			cur = ""
		}
	}
	if cur != "" || len(segs) == 0 {
		return cur, false
	}
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] != "" {
			return segs[i], true
		}
	}
	return "", true
}
