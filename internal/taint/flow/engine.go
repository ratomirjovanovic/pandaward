// Package flow is the language-independent taint engine over the IR: a
// worklist fixpoint per function over its control flow graph, with
// constants, container keys and list elements, qualified names of imported
// modules, guards on branch edges, and sources, sinks and sanitizers read
// from a taint specification.
package flow

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// maxVisits bounds the visits of a block before joins widen.
const maxVisits = 8

type sinkTarget struct {
	sink  *taint.Sink
	t     taint.Target
	shell bool
}

// Engine analyzes modules against one specification.
type Engine struct {
	spec         *taint.Spec
	calls        map[string][]sinkTarget
	methods      map[string][]sinkTarget
	stores       map[string]*taint.Sink
	handlerSink  *taint.Sink
	srcAttrs     map[string]bool
	srcCalls     map[string]bool
	params       map[string]bool
	routes       map[string]bool
	normalizers  map[string]bool
	responses    map[string]bool
	setters      map[string]bool
	urlParsers   map[string]bool
	textCalls    map[string]bool
	lookups      map[string]bool
	paramAnns    map[string]bool
	weakAlgs     map[string][]weakAlg
	props        map[string]string
	secretStores []secretStore
	weak         weak
	chains       [][]string
	pureCalls    map[string]bool
	decoders     map[string]bool
	pureMethods  map[string]bool
}

// New prepares an engine for a specification.
func New(spec *taint.Spec) *Engine {
	e := &Engine{spec: spec, calls: map[string][]sinkTarget{}, methods: map[string][]sinkTarget{}, stores: map[string]*taint.Sink{},
		srcAttrs: set(spec.Sources.Attributes), srcCalls: set(spec.Sources.Calls), params: set(spec.Sources.Params),
		routes: set(spec.Sources.RouteDecorators), normalizers: set(spec.Normalizers), responses: set(spec.Responses.Calls), setters: map[string]bool{}, urlParsers: set(spec.URLParsers), textCalls: set(spec.TextCalls), lookups: set(spec.Lookups)}
	e.weak = newWeak(spec)
	e.paramAnns = set(spec.Sources.ParamAnnotations)
	e.weakAlgs = map[string][]weakAlg{}
	for _, s := range spec.Sinks {
		if s.WeakAlgorithms == nil {
			continue
		}
		for _, c := range s.WeakAlgorithms.Calls {
			name, arg, _ := strings.Cut(c, "#")
			n, _ := strconv.Atoi(arg)
			e.weakAlgs[name] = append(e.weakAlgs[name], weakAlg{s, n})
		}
	}
	for _, st := range spec.Weak.SecretStores {
		parts := strings.Split(st, "#")
		if len(parts) == 3 {
			k, _ := strconv.Atoi(parts[1])
			v, _ := strconv.Atoi(parts[2])
			e.secretStores = append(e.secretStores, secretStore{parts[0], k, v})
		}
	}
	e.pureCalls, e.pureMethods = set(spec.Pure.Calls), set(spec.Pure.Methods)
	e.decoders = set(spec.Decoders)
	for _, c := range spec.Sources.Chains {
		e.chains = append(e.chains, strings.Split(c, "."))
	}
	for _, s := range spec.Sinks {
		for n, t := range s.Calls {
			e.calls[n] = append(e.calls[n], sinkTarget{s, t, false})
		}
		for n, t := range s.CallsWithShell {
			e.calls[n] = append(e.calls[n], sinkTarget{s, t, true})
		}
		for n, t := range s.Methods {
			e.methods[n] = append(e.methods[n], sinkTarget{s, t, false})
		}
		for _, st := range s.Stores {
			e.stores[st] = s
		}
		if s.HandlerReturn {
			e.handlerSink = s
		}
		if s.RequiresFlag != nil {
			for _, m := range s.RequiresFlag.Setter {
				e.setters[m] = true
			}
		}
	}
	return e
}

func set(list []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range list {
		m[s] = true
	}
	return m
}

// run is the analysis of one module.
type run struct {
	e     *Engine
	p     *Project
	mod   *ir.Module
	lines []string
	envs  map[*ir.Function]State
	// exit is the module body's state at its end.
	exit State
	html bool
	// done are the functions analyzed as roots.
	done map[*ir.Function]bool
}

// Analyze returns the flows from sources to sinks in one module on its
// own; lines are the source lines, for the steps of each flow.
func (e *Engine) Analyze(m *ir.Module, lines []string) []taint.Finding {
	p := e.NewProject(func(string) (*ir.Module, []string) { return nil, nil })
	return p.analyze(p.add(m, lines))
}

// imports reports a module body that imports mod or one of its members.
func imports(fn *ir.Function, mod string) bool {
	for _, b := range fn.Blocks {
		for _, in := range b.Instrs {
			if in.Op == ir.Import && (in.Name == mod || strings.HasPrefix(in.Name, mod+".")) {
				return true
			}
		}
	}
	return false
}

func (r *run) text(line int) string {
	if line < 1 || line > len(r.lines) {
		return ""
	}
	s := strings.TrimSpace(r.lines[line-1])
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

// fnRun is the analysis of one function.
type fnRun struct {
	*run
	fn     *ir.Function
	route  bool
	report bool
	// path is the route of a handler without path parameters: what
	// request.path holds while it runs.
	path string
	// ret and self are the returned value and self at the returns, joined
	// in the report pass.
	ret, self *Value
	// raises and returns record, in the report pass, a raise no handler of
	// the function catches and a return of something other than None.
	raises, returns bool
	// shared are the temporaries read outside the block that sets them;
	// the others are dropped at the end of their block.
	shared map[string]bool
}

// sharedTemps returns the temporaries a function reads in another block
// than the one that sets them (the value of a or b, x if c else y).
func sharedTemps(fn *ir.Function) map[string]bool {
	home := map[string]*ir.Block{}
	for _, b := range fn.Blocks {
		for _, in := range b.Instrs {
			if ir.IsTemp(in.Dst) {
				if h, ok := home[in.Dst]; ok && h != b {
					home[in.Dst] = nil // set in several blocks
				} else {
					home[in.Dst] = b
				}
			}
		}
	}
	out := map[string]bool{}
	use := func(b *ir.Block, o ir.Operand) {
		if ir.IsTemp(o.Var) && home[o.Var] != b {
			out[o.Var] = true
		}
	}
	for _, b := range fn.Blocks {
		for _, in := range b.Instrs {
			use(b, in.A)
			use(b, in.B)
			use(b, in.C)
			for _, a := range in.Args {
				use(b, a)
			}
			for _, a := range in.Keys2 {
				use(b, a)
			}
		}
		use(b, b.Term.Cond)
		use(b, b.Term.Value)
	}
	return out
}

func (r *run) isRoute(fn *ir.Function) bool {
	for _, d := range fn.Decorators {
		if !d.Call {
			continue
		}
		name := d.Name
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		if r.e.routes[name] {
			return true
		}
	}
	return false
}

// root analyzes a function on its own: its parameters hold whatever a
// caller passes, except route parameters, which are sources.
func (r *run) root(fn *ir.Function) {
	if r.done[fn] {
		return
	}
	r.done[fn] = true
	route := r.isRoute(fn)
	typed := typedParams(fn)
	entry := State{}
	for _, p := range fn.Params {
		v := &Value{Inst: p.Ann}
		if numericType[p.Ann] || javaScalar[p.Ann] {
			v.Inst = ""
		}
		if r.e.params[p.Name] {
			v.Q = p.Name
		}
		if route && p.Name != "self" && p.Name != "cls" && p.Name != "this" && !typed[p.Name] && !numericType[p.Ann] && !javaScalar[p.Ann] {
			v.T = r.newSource(p.Pos.Line, "route parameter "+p.Name)
		}
		for _, d := range p.Decorators {
			if r.e.paramAnns[d.Name] && !javaScalar[p.Ann] {
				v.T = r.newSource(p.Pos.Line, "@"+d.Name+" "+p.Name)
			}
		}
		entry[p.Name] = v
	}
	r.function(fn, entry, route)
}

func (r *run) newSource(line int, what string) *taint.Trace {
	t := taint.NewSource(line, what, false)
	t.File = r.mod.Path
	return t
}

// function analyzes fn from an entry state and returns the value it
// returns and the value of self when it returns.
func (r *run) function(fn *ir.Function, entry State, route bool) (ret, self *Value) {
	ret, self, _ = r.analyzeFn(fn, entry, route)
	return ret, self
}

// analyzeFn is function, and also reports a validator: a function that
// returns nothing and raises on some path, so that its caller continues
// only with arguments it accepted.
func (r *run) analyzeFn(fn *ir.Function, entry State, route bool) (ret, self *Value, validates bool) {
	f := &fnRun{run: r, fn: fn, route: route, shared: sharedTemps(fn)}
	if route {
		f.path = fixedRoute(fn)
	}
	in := map[*ir.Block]State{fn.Entry(): entry}
	visits := map[*ir.Block]int{}
	work := []*ir.Block{fn.Entry()}
	queued := map[*ir.Block]bool{fn.Entry(): true}
	push := func(b *ir.Block, s State) {
		old, ok := in[b]
		if !ok {
			in[b] = s.copy()
		} else if !joinInto(old, s, visits[b] > maxVisits) {
			return
		}
		if !queued[b] {
			queued[b] = true
			work = append(work, b)
		}
	}
	for steps := 0; len(work) > 0 && steps < 20000; steps++ {
		b := work[0]
		work = work[1:]
		queued[b] = false
		visits[b]++
		f.block(b, in[b], push)
	}
	// Report from the fixpoint's states only, so a sink is judged once.
	f.report = true
	for _, b := range fn.Blocks {
		if s, ok := in[b]; ok {
			f.block(b, s, func(*ir.Block, State) {})
		}
	}
	if fn == r.mod.Init {
		r.exit = State{}
		for _, b := range fn.Blocks {
			if s, ok := in[b]; ok && b.Term.Kind == ir.Return {
				out := s.copy()
				f.instrs(b, out)
				joinInto(r.exit, out, false)
			}
		}
	}
	return f.ret, f.self, f.raises && !f.returns
}

// fixedRoute returns the path of a route decorator without parameters
// (@app.route('/about')), or "".
func fixedRoute(fn *ir.Function) string {
	for _, d := range fn.Decorators {
		if d.Call && len(d.Args) > 0 && strings.HasPrefix(d.Args[0], "/") {
			if strings.ContainsAny(d.Args[0], "<{") {
				return ""
			}
			return d.Args[0]
		}
	}
	return ""
}

// textTypes are declared types whose values are text.
var textTypes = map[string]bool{"String": true, "java.lang.String": true, "CharSequence": true, "char[]": true, "byte[]": true,
	"String[]": true, "StringBuilder": true, "StringBuffer": true}

// javaScalar are Java types whose values cannot carry text.
var javaScalar = map[string]bool{"int": true, "long": true, "short": true, "byte": true, "boolean": true, "double": true, "float": true, "char": true,
	"Integer": true, "Long": true, "Short": true, "Byte": true, "Boolean": true, "Double": true, "Float": true, "java.util.UUID": true}

// routeParam matches a typed path parameter such as <int:id>.
var routeParam = regexp.MustCompile(`<(\w+):(\w+)>`)

// numericType are converters and annotations whose values cannot carry
// text.
var numericType = map[string]bool{"int": true, "float": true, "bool": true, "uuid": true, "uuid.UUID": true, "UUID": true}

// typedParams returns the parameters a route declares as numbers or UUIDs.
func typedParams(fn *ir.Function) map[string]bool {
	out := map[string]bool{}
	for _, d := range fn.Decorators {
		for _, a := range d.Args {
			for _, m := range routeParam.FindAllStringSubmatch(a, -1) {
				if numericType[m[1]] {
					out[m[2]] = true
				}
			}
		}
	}
	return out
}

// block runs the instructions of b from state s and passes the result to
// its successors, refined by the branch condition, and to its handlers.
func (f *fnRun) block(b *ir.Block, s State, push func(*ir.Block, State)) {
	st := s.copy()
	f.instrs(b, st)
	// Temporaries no other block reads are dropped once the branch
	// condition has been refined, which keeps the states small.
	prune := func(x State) State {
		if f.report {
			return x
		}
		for k := range x {
			if ir.IsTemp(k) && !f.shared[k] {
				delete(x, k)
			}
		}
		return x
	}
	if t := b.Term; t.Kind == ir.Branch && !t.Cond.IsZero() {
		if truth, ok := known(f.val(st, t.Cond)); !ok {
			yes, no := f.refine(st, t.Cond, true), f.refine(st, t.Cond, false)
			for _, h := range b.Handlers {
				push(h, prune(s.copy()))
				push(h, prune(st.copy()))
			}
			push(t.Succs[0], prune(yes))
			push(t.Succs[1], prune(no))
			return
		} else if truth {
			push(t.Succs[0], prune(st))
			return
		} else {
			push(t.Succs[1], prune(st))
			return
		}
	}
	st = prune(st)
	for _, h := range b.Handlers {
		push(h, s)
		push(h, st)
	}
	t := b.Term
	switch t.Kind {
	case ir.Jump:
		push(t.Succs[0], st)
	case ir.Branch:
		cond := f.val(st, t.Cond)
		if truth, ok := known(cond); ok && !t.Cond.IsZero() {
			if truth {
				push(t.Succs[0], st)
			} else {
				push(t.Succs[1], st)
			}
			return
		}
		push(t.Succs[0], f.refine(st, t.Cond, true))
		push(t.Succs[1], f.refine(st, t.Cond, false))
	case ir.Raise:
		if f.report && len(b.Handlers) == 0 {
			f.raises = true
		}
	case ir.Return:
		if f.report {
			v := f.val(st, t.Value)
			f.ret = joinFirst(f.ret, v)
			if !t.Value.IsZero() && !(v.C != nil && v.C.Kind == ir.None) {
				f.returns = true
			}
			if v, ok := st["self"]; ok {
				f.self = joinFirst(f.self, v)
			}
		}
		if f.report && f.route && f.html && f.e.handlerSink != nil {
			body := f.val(st, t.Value)
			if body.Known && len(body.Elems) > 0 {
				body = body.Elems[0] // (body, status, headers)
			}
			// An object a helper built (a JSON response, a model) is not the
			// input as HTML text.
			if body.tainted(f.e.handlerSink.Kind) && !body.Opaque {
				f.found(f.e.handlerSink, t.Pos.Line, body)
			}
		}
	}
}

// chained reports an attribute read at the end of a source chain, such
// as completion.choices[0].message.content.
func (f *fnRun) chained(in *ir.Instr) bool {
	if len(f.e.chains) == 0 {
		return false
	}
	path := []string{in.Name}
	o := in.A
	for len(path) < 8 {
		d := f.fn.Defs[o.Var]
		if d == nil {
			break
		}
		if d.Op == ir.Load {
			path = append(path, d.Name)
		} else if d.Op == ir.Index {
			path = append(path, "[]")
		} else {
			break
		}
		o = d.A
	}
	for _, c := range f.e.chains {
		if len(c) > len(path) {
			continue
		}
		ok := true
		for i := range c {
			if c[len(c)-1-i] != path[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// joinFirst joins v into acc, taking v as it is when acc is unset.
func joinFirst(acc, v *Value) *Value {
	if acc == nil {
		return v
	}
	return join(acc, v, false)
}

// known returns the truth of a value when it is known.
func known(v *Value) (bool, bool) {
	if v.C != nil {
		return v.C.Truth()
	}
	if v.Known {
		return len(v.Elems) > 0, true
	}
	return false, false
}

func (f *fnRun) instrs(b *ir.Block, st State) {
	for _, in := range b.Instrs {
		f.instr(in, st)
	}
}

// val returns the value of an operand.
func (f *fnRun) val(st State, o ir.Operand) *Value {
	if o.Const != nil {
		return constVal(o.Const)
	}
	if o.Var == "" {
		return empty
	}
	if v, ok := st[o.Var]; ok {
		return v
	}
	return empty
}

// lookup finds a variable of an enclosing scope or the module, or names a
// builtin.
func (f *fnRun) lookup(name string) *Value {
	for fn := f.fn; fn != nil; fn = fn.Parent {
		if env, ok := f.envs[fn]; ok {
			if v, ok := env[name]; ok {
				return v
			}
		}
	}
	if v, ok := f.exit[name]; ok {
		return v
	}
	return &Value{Q: name}
}

func (f *fnRun) set(st State, dst string, v *Value, line int) {
	if dst == "" {
		return
	}
	if !ir.IsTemp(dst) && v.T != nil {
		v = v.copy()
		v.T = v.T.AddStep(taint.Step{Line: line, What: f.text(line), File: f.mod.Path})
	}
	st[dst] = v
}

func (f *fnRun) source(line int, q string) *Value {
	return &Value{T: f.newSource(line, f.text(line)), Q: q}
}

func (f *fnRun) instr(in *ir.Instr, st State) {
	line := in.Pos.Line
	switch in.Op {
	case ir.Copy:
		f.set(st, in.Dst, f.val(st, in.A), line)
	case ir.Free:
		st[in.Dst] = f.lookup(in.Name)
	case ir.Import:
		st[in.Dst] = &Value{Q: in.Name}
	case ir.Func:
		st[in.Dst] = &Value{Fn: in.Fn}
		// The enclosing scope a nested function sees, recorded in every
		// pass: it may be called before the fixpoint ends.
		if old, ok := f.envs[in.Fn]; ok {
			joinInto(old, st, false)
		} else {
			f.envs[in.Fn] = st.copy()
		}
	case ir.Bin:
		a, b := f.val(st, in.A), f.val(st, in.B)
		r := purified(binary(in.Name, a, b), a, b)
		if in.Name == "+" {
			r = hinted(r, a, b)
		}
		f.set(st, in.Dst, r, line)
	case ir.Unary:
		a := f.val(st, in.A)
		f.set(st, in.Dst, purified(unary(in.Name, a), a), line)
	case ir.Load:
		v := f.load(f.val(st, in.A), in.Name, line)
		if v.T == nil && f.chained(in) {
			v = f.source(line, "")
		}
		f.set(st, in.Dst, v, line)
	case ir.Store:
		if in.A.Var != "" {
			base := f.val(st, in.A).copy()
			if base.Fields == nil {
				base.Fields = map[string]*Value{}
			}
			v := f.val(st, in.B)
			if f.report {
				f.weakStore(in.Name, v, line)
			}
			base.Fields["."+in.Name] = v
			st[in.A.Var] = mix(base, v)
		}
	case ir.Index:
		r := f.index(in, st)
		if in.Name == "slice" {
			r = purified(r, f.val(st, in.A), f.val(st, in.B), f.val(st, in.C))
		} else {
			r = purified(r, f.val(st, in.A), f.val(st, in.B))
		}
		f.set(st, in.Dst, r, line)
	case ir.SetIndex:
		f.setIndex(in, st)
	case ir.Build:
		f.set(st, in.Dst, f.build(in, st), line)
	case ir.Iter:
		f.set(st, in.Dst, iterate(f.val(st, in.A)), line)
	case ir.Cast:
		v := f.val(st, in.A)
		// The declared type names the class, unless the value is an
		// instance of a class of the project, whose methods are analyzed.
		if in.Name != "" && in.Name != "Object" && v.Inst != in.Name && f.p.classes[v.Inst] == nil && !javaScalar[in.Name] {
			v = v.copy()
			v.Inst = in.Name
		}
		// A value declared as text is text, whatever call returned it.
		if v.Opaque && textTypes[in.Name] {
			v = v.copy()
			v.Opaque = false
		}
		st[in.Dst] = v
	case ir.Call:
		f.set(st, in.Dst, f.call(in, st), line)
	}
}

func (f *fnRun) load(base *Value, name string, line int) *Value {
	if name == "path" && f.path != "" && strings.HasSuffix(base.Q, "request") {
		return strVal(f.path)
	}
	if fv, ok := base.Fields["."+name]; ok {
		return fv
	}
	if base.Q != "" {
		// a static field of a class of the project
		if r := f.p.module(base.Q); r != nil {
			if v, ok := r.exit[name]; ok {
				return v
			}
		}
		q := base.Q + "." + name
		if f.e.srcAttrs[q] {
			return f.source(line, q)
		}
		r := taintOf(base).copy()
		r.Q = q
		return r
	}
	return taintOf(base)
}

func key(c *ir.Const) string {
	if c.Kind == ir.Int {
		return "#" + c.Val
	}
	return c.Val
}

func (f *fnRun) index(in *ir.Instr, st State) *Value {
	base := f.val(st, in.A)
	k := f.val(st, in.B)
	if in.Name == "slice" {
		hi := f.val(st, in.C)
		if base.C != nil && base.C.Kind == ir.Str {
			lo, ok1 := sliceBound(in.B, k, 0)
			h, ok2 := sliceBound(in.C, hi, len(base.C.Val))
			if ok1 && ok2 {
				return strVal(pySlice(base.C.Val, lo, h))
			}
		}
		if base.Known {
			lo, ok1 := sliceBound(in.B, k, 0)
			h, ok2 := sliceBound(in.C, hi, len(base.Elems))
			if ok1 && ok2 {
				n := len(base.Elems)
				lo, h = clamp(lo, n), clamp(h, n)
				r := &Value{Known: true}
				if lo < h {
					r.Elems = append([]*Value(nil), base.Elems[lo:h]...)
				}
				for _, e := range r.Elems {
					r = mix(r, e)
				}
				return r
			}
		}
		return taintOf(base)
	}
	if k.C != nil {
		if fv, ok := base.Fields[key(k.C)]; ok {
			return fv
		}
		if base.C != nil && base.C.Kind == ir.Str && k.C.Kind == ir.Int {
			if i, err := strconv.Atoi(k.C.Val); err == nil {
				s := []rune(base.C.Val)
				if i < 0 {
					i += len(s)
				}
				if i >= 0 && i < len(s) {
					return strVal(string(s[i]))
				}
			}
		}
		if base.Known && k.C.Kind == ir.Int {
			if i, err := strconv.Atoi(k.C.Val); err == nil {
				if i < 0 {
					i += len(base.Elems)
				}
				if i >= 0 && i < len(base.Elems) {
					return base.Elems[i]
				}
			}
		}
	}
	if base.Known {
		var r *Value = empty
		for _, e := range base.Elems {
			r = join(r, e, true)
		}
		return taintOf(r)
	}
	r := taintOf(base)
	if base.Q != "" && k.C != nil {
		r = r.copy()
		r.Q = base.Q + "[" + k.C.Val + "]"
	}
	return r
}

func sliceBound(o ir.Operand, v *Value, def int) (int, bool) {
	if o.IsZero() {
		return def, true
	}
	if v.C != nil && v.C.Kind == ir.Int {
		n, err := strconv.Atoi(v.C.Val)
		return n, err == nil
	}
	return 0, false
}

func clamp(i, n int) int {
	if i < 0 {
		i += n
	}
	if i < 0 {
		return 0
	}
	if i > n {
		return n
	}
	return i
}

func pySlice(s string, lo, hi int) string {
	r := []rune(s)
	lo, hi = clamp(lo, len(r)), clamp(hi, len(r))
	if lo >= hi {
		return ""
	}
	return string(r[lo:hi])
}

func (f *fnRun) setIndex(in *ir.Instr, st State) {
	base := f.val(st, in.A)
	k := f.val(st, in.B)
	v := f.val(st, in.C)
	if f.report {
		if name := keyName(k); name != "" {
			f.weakStore(name, v, in.Pos.Line)
		}
		if _, ok := f.e.stores[base.Q]; ok {
			f.weakSession(v, in.Pos.Line)
		}
	}
	if s, ok := f.e.stores[base.Q]; ok && f.report {
		if k.tainted(s.Kind) && !(s.TextOnly && k.Opaque) {
			f.found(s, in.Pos.Line, k)
		} else if v.tainted(s.Kind) && !(s.TextOnly && v.Opaque) {
			f.found(s, in.Pos.Line, v)
		}
	}
	if in.A.Var == "" {
		return
	}
	nb := base.copy()
	switch {
	case in.B.IsZero():
		// a slice assignment
		nb.Known, nb.Elems = false, nil
	case k.C != nil && base.Known && k.C.Kind == ir.Int:
		i, err := strconv.Atoi(k.C.Val)
		if i < 0 {
			i += len(nb.Elems)
		}
		if err == nil && i >= 0 && i < len(nb.Elems) {
			nb.Elems[i] = v
		} else {
			nb.Known, nb.Elems = false, nil
		}
	case k.C != nil:
		if nb.Fields == nil {
			nb.Fields = map[string]*Value{}
		}
		nb.Fields[key(k.C)] = v
	default:
		nb.Known, nb.Elems = false, nil
	}
	st[in.A.Var] = mix(nb, v)
}

func (f *fnRun) build(in *ir.Instr, st State) *Value {
	switch in.Name {
	case "str":
		r := &Value{}
		var sb strings.Builder
		allConst, allPure := true, true
		for _, a := range in.Args {
			v := f.val(st, a)
			allPure = allPure && isPure(v)
			r = mix(r, v)
			if v.C != nil && v.C.Kind == ir.Str {
				sb.WriteString(v.C.Val)
			} else if v.C != nil && (v.C.Kind == ir.Int || v.C.Kind == ir.Float) {
				sb.WriteString(v.C.Val)
			} else {
				allConst = false
			}
		}
		if allConst && r.T == nil {
			return strVal(sb.String())
		}
		if r.Opaque || allPure {
			r = r.copy()
			r.Opaque = false // text built here
			r.Pure = allPure
		}
		return r
	case "list", "tuple":
		r := &Value{Known: true, Elems: []*Value{}, Inst: in.Name}
		for _, a := range in.Args {
			v := f.val(st, a)
			r.Elems = append(r.Elems, v)
			r = mix(r, v)
		}
		return r
	case "dict":
		r := &Value{Fields: map[string]*Value{}, Inst: "dict"}
		for i, a := range in.Args {
			v := f.val(st, a)
			if k := in.Keys2[i]; k.Const != nil {
				r.Fields[key(k.Const)] = v
			} else if k.IsZero() {
				for fk, fv := range v.Fields {
					r.Fields[fk] = fv
				}
			}
			r = mix(r, v)
		}
		return r
	}
	r := &Value{}
	for _, a := range in.Args {
		r = mix(r, iterateOrSelf(f.val(st, a)))
	}
	return r
}

func iterateOrSelf(v *Value) *Value { return taintOf(v) }

// iterate returns an element of an iterable.
func iterate(v *Value) *Value {
	if v.Known && len(v.Elems) > 0 {
		r := v.Elems[0]
		for _, e := range v.Elems[1:] {
			r = join(r, e, true)
		}
		return r
	}
	return taintOf(v)
}

// binary computes an operator, folding constants.
func binary(op string, a, b *Value) *Value {
	switch op {
	case "==", "!=", "<", ">", "<=", ">=", "in", "not in", "is", "is not", "and", "or":
		if r := foldCompare(op, a, b); r != nil {
			return r
		}
		return &Value{}
	}
	if a.C != nil && b.C != nil {
		if r := foldArith(op, a.C, b.C); r != nil {
			return r
		}
	}
	r := mix(mix(&Value{}, a), b)
	if r.Opaque && (op == "+" || op == "%") && (a.C != nil && a.C.Kind == ir.Str || b.C != nil && b.C.Kind == ir.Str || !a.Opaque || !b.Opaque) {
		r = r.copy()
		r.Opaque = false // text built here
	}
	if op == "/" && a.Inst == "pathlib.Path" {
		r = r.copy()
		r.Inst = "pathlib.Path"
	}
	if op == "+" && a.Known && b.Known {
		r = r.copy()
		r.Known = true
		r.Elems = append(append([]*Value(nil), a.Elems...), b.Elems...)
	}
	return r
}

func foldArith(op string, a, b *ir.Const) *Value {
	if a.Kind == ir.Int && b.Kind == ir.Int {
		x, err1 := strconv.ParseInt(a.Val, 10, 64)
		y, err2 := strconv.ParseInt(b.Val, 10, 64)
		if err1 != nil || err2 != nil {
			return nil
		}
		switch op {
		case "+":
			return intVal(x + y)
		case "-":
			return intVal(x - y)
		case "*":
			return intVal(x * y)
		case "//":
			if y != 0 {
				q := x / y
				if (x%y != 0) && ((x < 0) != (y < 0)) {
					q--
				}
				return intVal(q)
			}
		case "%":
			if y != 0 {
				m := x % y
				if m != 0 && (m < 0) != (y < 0) {
					m += y
				}
				return intVal(m)
			}
		}
		return nil
	}
	if a.Kind == ir.Str && b.Kind == ir.Str && op == "+" {
		return strVal(a.Val + b.Val)
	}
	if a.Kind == ir.Str && b.Kind == ir.Int && op == "*" {
		if n, err := strconv.Atoi(b.Val); err == nil && n >= 0 && n*len(a.Val) < 1<<16 {
			return strVal(strings.Repeat(a.Val, n))
		}
	}
	return nil
}

func foldCompare(op string, a, b *Value) *Value {
	if op == "and" || op == "or" {
		x, ok1 := known(a)
		y, ok2 := known(b)
		if ok1 && ok2 {
			if op == "and" {
				return boolVal(x && y)
			}
			return boolVal(x || y)
		}
		return nil
	}
	if a.C == nil || b.C == nil {
		return nil
	}
	x, y := a.C, b.C
	switch op {
	case "in", "not in":
		if x.Kind == ir.Str && y.Kind == ir.Str {
			r := strings.Contains(y.Val, x.Val)
			return boolVal(r == (op == "in"))
		}
		return nil
	case "is", "is not":
		if x.Kind == ir.None || y.Kind == ir.None {
			r := x.Kind == y.Kind
			return boolVal(r == (op == "is"))
		}
		return nil
	}
	if x.Kind == ir.Int && y.Kind == ir.Int {
		p, err1 := strconv.ParseInt(x.Val, 10, 64)
		q, err2 := strconv.ParseInt(y.Val, 10, 64)
		if err1 != nil || err2 != nil {
			return nil
		}
		switch op {
		case "==":
			return boolVal(p == q)
		case "!=":
			return boolVal(p != q)
		case "<":
			return boolVal(p < q)
		case ">":
			return boolVal(p > q)
		case "<=":
			return boolVal(p <= q)
		case ">=":
			return boolVal(p >= q)
		}
	}
	if x.Kind == y.Kind && (x.Kind == ir.Str || x.Kind == ir.Bool || x.Kind == ir.None) {
		switch op {
		case "==":
			return boolVal(x.Val == y.Val)
		case "!=":
			return boolVal(x.Val != y.Val)
		}
	}
	if (op == "==" || op == "!=") && x.Kind != y.Kind && x.Kind != ir.Other && y.Kind != ir.Other &&
		!(x.Kind == ir.Int && y.Kind == ir.Float || x.Kind == ir.Float && y.Kind == ir.Int) &&
		!(x.Kind == ir.Bool || y.Kind == ir.Bool) {
		return boolVal(op == "!=")
	}
	return nil
}

func unary(op string, a *Value) *Value {
	switch op {
	case "not":
		if t, ok := known(a); ok {
			return boolVal(!t)
		}
		return &Value{}
	case "-":
		if a.C != nil && a.C.Kind == ir.Int {
			if n, err := strconv.ParseInt(a.C.Val, 10, 64); err == nil {
				return intVal(-n)
			}
		}
	case "+":
		if a.C != nil && a.C.Kind == ir.Int {
			return a
		}
	}
	return taintOf(a)
}
