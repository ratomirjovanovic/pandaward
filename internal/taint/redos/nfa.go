package redos

// maxStates bounds the automaton: larger patterns are not analyzed.
const maxStates = 160

type edge struct {
	on set
	to int
}

type builder struct {
	eps   [][]int
	trans [][]edge
	over  bool
}

func (b *builder) new() int {
	if len(b.eps) >= maxStates*3 {
		b.over = true
		return 0
	}
	b.eps = append(b.eps, nil)
	b.trans = append(b.trans, nil)
	return len(b.eps) - 1
}

func (b *builder) epsilon(from, to int) { b.eps[from] = append(b.eps[from], to) }

// build adds the automaton of n between from and to.
func (b *builder) build(n *node, from, to int) bool {
	if b.over {
		return false
	}
	switch n.k {
	case kSet:
		b.trans[from] = append(b.trans[from], edge{n.set, to})
	case kEmpty:
		b.epsilon(from, to)
	case kEnd:
		b.trans[from] = append(b.trans[from], edge{set{{endSym, endSym}}, to})
	case kSeq:
		cur := from
		for i, k := range n.kids {
			next := to
			if i < len(n.kids)-1 {
				next = b.new()
			}
			if !b.build(k, cur, next) {
				return false
			}
			cur = next
		}
		if len(n.kids) == 0 {
			b.epsilon(from, to)
		}
	case kAlt:
		for _, k := range n.kids {
			if !b.build(k, from, to) {
				return false
			}
		}
	case kRep:
		kid := n.kids[0]
		min, max := n.min, n.max
		if min > 8 {
			min = 8
		}
		if max >= 0 && max-min > 12 {
			max = -1
		}
		cur := from
		for i := 0; i < min; i++ {
			next := b.new()
			if !b.build(kid, cur, next) {
				return false
			}
			cur = next
		}
		if max < 0 {
			loop, out := b.new(), b.new()
			b.epsilon(cur, loop)
			body := b.new()
			b.epsilon(loop, body)
			if !b.build(kid, body, loop) {
				return false
			}
			b.epsilon(loop, out)
			b.epsilon(out, to)
		} else {
			for i := min; i < max; i++ {
				b.epsilon(cur, to)
				next := b.new()
				if !b.build(kid, cur, next) {
					return false
				}
				cur = next
			}
			b.epsilon(cur, to)
		}
	}
	return !b.over
}

// nfa is an automaton without empty transitions.
type nfa struct {
	out    [][]edge
	accept []bool // the state's closure holds the accepting state
	start  int
}

// finish removes empty transitions and, for a pattern not anchored at the
// start, adds the loop that lets a match begin anywhere.
func (b *builder) finish(start, acc int, anchored, endAnchored bool) *nfa {
	if b.over {
		return nil
	}
	n := len(b.eps)
	if !anchored {
		s := b.new()
		if b.over {
			return nil
		}
		b.trans[s] = append(b.trans[s], edge{all, s})
		b.epsilon(s, start)
		start = s
		n = len(b.eps)
	}
	closure := make([][]int, n)
	for s := 0; s < n; s++ {
		seen := map[int]bool{s: true}
		stack := []int{s}
		for len(stack) > 0 {
			x := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, y := range b.eps[x] {
				if !seen[y] {
					seen[y] = true
					stack = append(stack, y)
				}
			}
		}
		for x := range seen {
			closure[s] = append(closure[s], x)
		}
	}
	m := &nfa{out: make([][]edge, n), accept: make([]bool, n), start: start}
	for s := 0; s < n; s++ {
		for _, x := range closure[s] {
			if x == acc {
				m.accept[s] = true
			}
			m.out[s] = append(m.out[s], b.trans[x]...)
		}
	}
	// A state is only worth keeping when it can be reached from the start.
	reach := make([]bool, n)
	stack := []int{start}
	reach[start] = true
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, e := range m.out[x] {
			if !reach[e.to] {
				reach[e.to] = true
				stack = append(stack, e.to)
			}
		}
	}
	// Renumber the reachable states.
	id := make([]int, n)
	cnt := 0
	for s := 0; s < n; s++ {
		id[s] = -1
		if reach[s] {
			id[s] = cnt
			cnt++
		}
	}
	if cnt > maxStates {
		return nil
	}
	r := &nfa{out: make([][]edge, cnt), accept: make([]bool, cnt), start: id[start]}
	for s := 0; s < n; s++ {
		if id[s] < 0 {
			continue
		}
		r.accept[id[s]] = m.accept[s]
		for _, e := range m.out[s] {
			if id[e.to] >= 0 {
				r.out[id[s]] = append(r.out[id[s]], edge{e.on, id[e.to]})
			}
		}
	}
	return r
}

func inter(a, b set) set {
	var out set
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		lo, hi := a[i][0], a[i][1]
		if b[j][0] > lo {
			lo = b[j][0]
		}
		if b[j][1] < hi {
			hi = b[j][1]
		}
		if lo <= hi {
			out = append(out, [2]rune{lo, hi})
		}
		if a[i][1] < b[j][1] {
			i++
		} else {
			j++
		}
	}
	return out
}

// sccs returns the strongly connected components of the automaton that
// hold a cycle.
func (m *nfa) sccs() [][]int {
	n := len(m.out)
	index := make([]int, n)
	low := make([]int, n)
	on := make([]bool, n)
	for i := range index {
		index[i] = -1
	}
	var stack []int
	var out [][]int
	counter := 0
	var strong func(v int)
	strong = func(v int) {
		index[v], low[v] = counter, counter
		counter++
		stack = append(stack, v)
		on[v] = true
		for _, e := range m.out[v] {
			w := e.to
			if index[w] < 0 {
				strong(w)
				if low[w] < low[v] {
					low[v] = low[w]
				}
			} else if on[w] && index[w] < low[v] {
				low[v] = index[w]
			}
		}
		if low[v] == index[v] {
			var comp []int
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				on[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			cyclic := len(comp) > 1
			for _, e := range m.out[v] {
				if e.to == v {
					cyclic = true
				}
			}
			if cyclic {
				out = append(out, comp)
			}
		}
	}
	for v := 0; v < n; v++ {
		if index[v] < 0 {
			strong(v)
		}
	}
	return out
}

// attackable reports that some character is read by none of the states,
// so a text that ends with it fails after the loop, and that no state
// accepts, which would end the search at once.
func (m *nfa) attackable(states []int) bool {
	var u set
	for _, s := range states {
		if m.accept[s] {
			return false
		}
		for _, e := range m.out[s] {
			u = union(u, e.on)
		}
	}
	return len(negate(u)) > 0
}

func (m *nfa) analyze() Result {
	// Exponential: two paths of one text lead from a state back to it,
	// which the product of the automaton with itself shows as a component
	// holding (q,q) and a pair of different states.
	for _, comp := range m.sccs() {
		if len(comp) > 70 {
			continue
		}
		if m.ambiguousCycle(comp) {
			return Result{Exponential: true}
		}
	}
	if m.polynomial() {
		return Result{Polynomial: true}
	}
	return Result{}
}

// ambiguousCycle looks for a pair of different paths of one text from a
// state of comp back to it, inside comp.
func (m *nfa) ambiguousCycle(comp []int) bool {
	k := len(comp)
	pos := map[int]int{}
	for i, s := range comp {
		pos[s] = i
	}
	// Two edges that leave a state for the same state of the component on
	// a common character are two paths of one text.
	for _, s := range comp {
		for i, e1 := range m.out[s] {
			if _, ok := pos[e1.to]; !ok {
				continue
			}
			for _, e2 := range m.out[s][i+1:] {
				if e1.to == e2.to && intersects(e1.on, e2.on) && m.attackable(comp) {
					return true
				}
			}
		}
	}
	// Nodes are pairs (i,j); edges follow a common character.
	next := func(a, b int) [][2]int {
		var out [][2]int
		for _, e1 := range m.out[comp[a]] {
			i, ok := pos[e1.to]
			if !ok {
				continue
			}
			for _, e2 := range m.out[comp[b]] {
				j, ok := pos[e2.to]
				if !ok {
					continue
				}
				if intersects(e1.on, e2.on) {
					out = append(out, [2]int{i, j})
				}
			}
		}
		return out
	}
	idx := make([]int, k*k)
	low := make([]int, k*k)
	on := make([]bool, k*k)
	for i := range idx {
		idx[i] = -1
	}
	var stack []int
	counter := 0
	found := false
	var strong func(v int)
	strong = func(v int) {
		if found {
			return
		}
		idx[v], low[v] = counter, counter
		counter++
		stack = append(stack, v)
		on[v] = true
		for _, t := range next(v/k, v%k) {
			w := t[0]*k + t[1]
			if idx[w] < 0 {
				strong(w)
				if low[w] < low[v] {
					low[v] = low[w]
				}
			} else if on[w] && idx[w] < low[v] {
				low[v] = idx[w]
			}
		}
		if low[v] == idx[v] {
			var members []int
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				on[w] = false
				members = append(members, w)
				if w == v {
					break
				}
			}
			diag, off := false, false
			var states []int
			seen := map[int]bool{}
			for _, w := range members {
				a, b := w/k, w%k
				if a == b {
					diag = true
				} else {
					off = true
				}
				for _, x := range []int{comp[a], comp[b]} {
					if !seen[x] {
						seen[x] = true
						states = append(states, x)
					}
				}
			}
			if diag && off && m.attackable(states) {
				found = true
			}
		}
	}
	for a := 0; a < k && !found; a++ {
		if v := a*k + a; idx[v] < 0 {
			strong(v)
		}
	}
	return found
}

// polynomial looks for two different states p and q, each on a cycle, such
// that one text loops on p, leads from p to q and loops on q.
func (m *nfa) polynomial() bool {
	n := len(m.out)
	cyc := make([]bool, n)
	var comps [][]int
	for _, c := range m.sccs() {
		comps = append(comps, c)
		for _, s := range c {
			cyc[s] = true
		}
	}
	var cand []int
	for s := 0; s < n; s++ {
		if cyc[s] {
			cand = append(cand, s)
		}
	}
	if len(cand) > 60 {
		return false
	}
	// reach[p][q]: q reachable from p.
	reach := make([][]bool, n)
	for _, p := range cand {
		r := make([]bool, n)
		stack := []int{p}
		r[p] = true
		for len(stack) > 0 {
			x := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, e := range m.out[x] {
				if !r[e.to] {
					r[e.to] = true
					stack = append(stack, e.to)
				}
			}
		}
		reach[p] = r
	}
	budget := 400000
	for _, p := range cand {
		for _, q := range cand {
			if p == q || !reach[p][q] || m.accept[p] || m.accept[q] {
				continue
			}
			if !m.attackable([]int{q}) || m.accept[p] {
				continue
			}
			if m.triple(p, q, &budget) {
				return true
			}
			if budget <= 0 {
				return false
			}
		}
	}
	return false
}

// triple searches the product of three copies of the automaton for the
// path (p,p,q) to (p,q,q): one text that loops on p, goes from p to q and
// loops on q.
func (m *nfa) triple(p, q int, budget *int) bool {
	type key [3]int
	start, goal := key{p, p, q}, key{p, q, q}
	seen := map[key]bool{start: true}
	queue := []key{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e1 := range m.out[cur[0]] {
			for _, e2 := range m.out[cur[1]] {
				i12 := inter(e1.on, e2.on)
				if len(i12) == 0 {
					continue
				}
				for _, e3 := range m.out[cur[2]] {
					if !intersects(i12, e3.on) {
						continue
					}
					nk := key{e1.to, e2.to, e3.to}
					if nk == goal {
						return true
					}
					if !seen[nk] {
						seen[nk] = true
						queue = append(queue, nk)
						*budget--
						if *budget <= 0 {
							return false
						}
					}
				}
			}
		}
	}
	return false
}
