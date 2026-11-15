package flow

import (
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// call is a resolved call: its qualified names, receiver and arguments.
type call struct {
	in     *ir.Instr
	names  []string // qualified callee names, most specific first
	method string   // method name for a method call on an object
	recv   *Value
	args   []*Value // positional
	kw     map[string]*Value
	all    []*Value // every argument, *x and **x included
}

func (f *fnRun) resolve(in *ir.Instr, st State) *call {
	c := &call{in: in, kw: map[string]*Value{}}
	if in.Name != "" {
		c.recv = f.val(st, in.A)
		if c.recv.Q != "" {
			c.names = append(c.names, c.recv.Q+"."+in.Name)
		} else {
			c.method = in.Name
		}
		if c.recv.Inst != "" {
			c.names = append(c.names, c.recv.Inst+"."+in.Name)
		}
		// A name nothing is known of (db in db.query(...), declared
		// elsewhere) is a receiver like any other.
		if c.method == "" && f.javascript() && c.recv.Fn == nil && !f.e.namedCall(c.names) {
			c.method = in.Name
		}
	} else {
		c.recv = empty
		if q := f.val(st, in.A).Q; q != "" {
			c.names = append(c.names, q)
		}
	}
	for i, a := range in.Args {
		v := f.val(st, a)
		c.all = append(c.all, v)
		switch k := in.Keys[i]; k {
		case "":
			c.args = append(c.args, v)
		case "*", "**":
		default:
			c.kw[k] = v
		}
	}
	return c
}

// receiverName is the source name of a method call's receiver.
func (f *fnRun) receiverName(in *ir.Instr) string {
	if in.Name == "" {
		return ""
	}
	if !ir.IsTemp(in.A.Var) {
		return in.A.Var
	}
	if d := f.fn.Defs[in.A.Var]; d != nil && d.Op == ir.Free {
		return d.Name
	}
	return ""
}

func (f *fnRun) call(in *ir.Instr, st State) *Value {
	c := f.resolve(in, st)
	if f.report {
		f.weakSinks(c)
		f.routeCall(c)
		f.eventCall(c)
		f.jsxSinks(c)
	}
	r := f.weakSource(c, f.callResolved(c, st))
	// new URL("/login", request.url): the address is the base's host with
	// a path the code chose, which is not a redirect to another site.
	if contains(c.names, "URL") && len(c.args) == 2 && c.args[0].T == nil && r.T != nil {
		r = r.copy()
		r.Safe |= taint.Redirect
	}
	// new RegExp("^[a-z]+$") is the pattern, as a /literal/ is.
	if contains(c.names, "RegExp") && len(c.args) >= 1 && c.args[0].C != nil && c.args[0].C.Kind == ir.Str {
		flags := ""
		if len(c.args) > 1 && c.args[1].C != nil {
			flags = c.args[1].C.Val
		}
		return constVal(&ir.Const{Kind: ir.Other, Val: "/" + c.args[0].C.Val + "/" + flags})
	}
	for _, n := range c.names {
		if contains(f.e.spec.Weak.RandomFill, n) && len(in.Args) > 0 {
			if name := f.root(in.Args[0]); name != "" {
				v := st[name].copy()
				v.W = f.newSource(in.Pos.Line, f.text(in.Pos.Line))
				v.WK |= taint.WeakRandom
				st[name] = v
			}
		}
	}
	{
		for _, n := range c.names {
			if t, ok := f.e.spec.Returns[n]; ok {
				r = r.copy()
				r.Inst = t
				break
			}
		}
	}
	// $(sel).find(x).closest(y): a jQuery method returns the selection,
	// except the ones that read a value from it.
	if c.recv.Inst == "jQuery" && in.Name != "" && !jqueryValues[in.Name] && !(in.Name == "html" && len(c.args) == 0) && r.Inst == "" {
		r = r.copy()
		r.Inst = "jQuery"
	}
	// Properties.getProperty(key, default) reads the project's files.
	if in.Name == "getProperty" && len(c.args) >= 1 && c.args[0].C != nil && r.T == nil {
		if v, ok := f.e.props[c.args[0].C.Val]; ok {
			return strVal(v)
		}
		if len(c.args) == 2 && c.args[1].C != nil {
			return c.args[1]
		}
	}
	if f.pureCall(c) {
		inputs := append([]*Value{}, c.all...)
		if c.in.Name != "" && c.method != "" {
			inputs = append(inputs, c.recv)
		}
		r = purified(r, inputs...)
	}
	return r
}

// pureCall reports a call that only transforms its input, so its result
// comes from constants when its input does.
func (f *fnRun) pureCall(c *call) bool {
	if c.method != "" {
		return f.e.pureMethods[c.method]
	}
	for _, n := range c.names {
		if f.e.pureCalls[n] {
			return true
		}
	}
	return false
}

func (f *fnRun) callResolved(c *call, st State) *Value {
	in := c.in
	if f.report {
		f.sinks(c, st)
	}
	f.flags(c, st)
	line := in.Pos.Line

	for _, n := range c.names {
		if f.e.srcCalls[n] {
			return f.source(line, "")
		}
	}
	for _, n := range c.names {
		if f.e.responses[n] {
			return f.response(c)
		}
	}
	var kinds taint.Kind
	for _, n := range c.names {
		kinds |= f.e.spec.Sanitizes(n)
	}
	if c.method != "" {
		kinds |= f.e.spec.SanitizesMethod(c.method)
	}
	if kinds == taint.All {
		// A number or an escaped text is safe to use anywhere, but it is
		// still the client's data: storing it in the session crosses the
		// trust boundary.
		r := &Value{}
		for _, a := range append([]*Value{c.recv}, c.all...) {
			if a.T != nil && r.T == nil {
				r.T, r.Safe = a.T, taint.All&^taint.Trust
			}
		}
		if len(c.names) > 0 {
			r.Inst = c.names[0]
		}
		return r
	}
	if kinds == 0 {
		if r, ok := f.project(c, st); ok {
			return r
		}
	}
	f.callbacks(c)
	if r := f.container(c, st); r != nil {
		return r
	}
	if in.Name != "" && f.e.lookups[in.Name] && c.recv.T == nil {
		// A lookup in a store the request does not fill.
		return &Value{}
	}
	r := &Value{}
	r = mix(r, c.recv)
	for _, a := range c.all {
		r = mix(r, a)
	}
	// A method of the input itself (a string or the request's dicts)
	// returns text; any other call returns an object built from it.
	if r.T != nil {
		r = r.copy()
		// "".join(parts), "{}".format(x), escapers and normalizers
		text := c.recv.C != nil || kinds != 0
		for _, n := range c.names {
			text = text || f.e.textCalls[n] || f.e.normalizers[n]
		}
		if c.recv.T != nil {
			r.Opaque = c.recv.Opaque
		} else {
			r.Opaque = !text
		}
		if text && c.recv.T == nil {
			r.Opaque = false
		}
	}
	if in.Name == "replace" && len(c.args) >= 2 && c.args[0].C != nil && c.args[1].C != nil {
		for _, x := range f.e.spec.Escapes {
			if c.args[0].C.Val == x.Old && !strings.Contains(c.args[1].C.Val, x.Old) {
				kinds |= x.Kinds
			}
		}
	}
	if in.Name == "replace" && len(c.args) >= 2 && stripsDotDot(c.args[0].C, c.args[1].C) {
		kinds |= taint.Path
	}
	if kinds != 0 && r.T != nil {
		r = r.copy()
		r.Safe |= kinds
	}
	for _, n := range c.names {
		if f.e.decoders[n] && r.T != nil && r.Safe != 0 {
			// decoded bytes can be anything again
			r = r.copy()
			r.Safe = 0
		}
		if f.e.urlParsers[n] && len(in.Args) > 0 {
			r = r.copy()
			r.From = f.root(in.Args[0])
		}
	}
	for _, n := range c.names {
		if f.e.normalizers[n] {
			r = r.copy()
			r.Norm = true
		}
	}
	if fv := f.fold(c); fv != nil && r.T == nil {
		return fv
	}
	switch {
	case c.recv.Inst == "pathlib.Path" && pathMethod[in.Name]:
		r = r.copy()
		r.Inst = "pathlib.Path"
	case c.method == "" && c.recv.Inst == "" && len(c.names) > 0:
		// A call of a class or factory: the instance is known by it.
		r = r.copy()
		r.Inst = c.names[0]
		if c.names[0] == "str" && len(c.args) == 1 {
			r.Norm = c.args[0].Norm
		}
	}
	return r
}

var pathMethod = map[string]bool{"resolve": true, "absolute": true, "joinpath": true, "with_name": true, "with_suffix": true, "expanduser": true}

// response returns the body of a response built by a framework call: the
// first argument or the first element of a (body, status, headers) tuple,
// safe for HTML when its content type is not HTML.
func (f *fnRun) response(c *call) *Value {
	var body *Value = empty
	if len(c.args) > 0 {
		body = c.args[0]
	} else if v, ok := c.kw["response"]; ok {
		body = v
	}
	if body.Known && len(body.Elems) > 0 {
		body = body.Elems[0]
	}
	r := taintOf(body)
	for _, k := range f.e.spec.Responses.ContentType {
		v, ok := c.kw[k]
		if !ok || v.C == nil || r.T == nil {
			continue
		}
		html := false
		for _, t := range f.e.spec.Responses.HTMLTypes {
			html = html || strings.HasPrefix(strings.ToLower(v.C.Val), t)
		}
		if !html {
			r = r.copy()
			r.Safe |= taint.XSS
		}
	}
	return r
}

// container models the methods of lists, dicts and config parsers called
// on a variable, so constant keys and list positions keep their values.
func (f *fnRun) container(c *call, st State) *Value {
	in := c.in
	if in.Name == "" || c.recv.Q != "" || in.A.Var == "" {
		return nil
	}
	recv := c.recv
	update := func(v *Value) { st[in.A.Var] = v }
	cfg := strings.HasPrefix(recv.Inst, "configparser.")
	switch in.Name {
	case "append", "add":
		if len(c.args) != 1 {
			return nil
		}
		n := recv.copy()
		if n.Known && in.Name == "append" {
			n.Elems = append(n.Elems, c.args[0])
		} else {
			n.Known, n.Elems = false, nil
		}
		update(mix(n, c.args[0]))
		return &Value{}
	case "insert":
		if len(c.args) != 2 {
			return nil
		}
		n := recv.copy()
		if i, ok := intConst(c.args[0]); ok && n.Known {
			i = clampInsert(i, len(n.Elems))
			n.Elems = append(n.Elems[:i], append([]*Value{c.args[1]}, n.Elems[i:]...)...)
		} else {
			n.Known, n.Elems = false, nil
		}
		update(mix(n, c.args[1]))
		return &Value{}
	case "write":
		if recv.Inst != "io.StringIO" && recv.Inst != "io.BytesIO" || len(c.args) != 1 {
			return nil
		}
		update(mix(recv, c.args[0]))
		return &Value{}
	case "extend", "update":
		n := recv.copy()
		n.Known, n.Elems = false, nil
		for _, a := range c.all {
			if in.Name == "update" {
				for k, v := range a.Fields {
					if n.Fields == nil {
						n.Fields = map[string]*Value{}
					}
					n.Fields[k] = v
				}
			}
			n = mix(n, iterate(a))
			n = mix(n, a)
		}
		update(n)
		return &Value{}
	case "pop":
		if recv.Known {
			i := -1
			if len(c.args) == 1 {
				var ok bool
				if i, ok = intConst(c.args[0]); !ok {
					return taintOf(recv)
				}
			}
			n := recv.copy()
			if i < 0 {
				i += len(n.Elems)
			}
			if i < 0 || i >= len(n.Elems) {
				return taintOf(recv)
			}
			v := n.Elems[i]
			n.Elems = append(n.Elems[:i], n.Elems[i+1:]...)
			update(n)
			return v
		}
		if len(c.args) >= 1 && c.args[0].C != nil {
			if v, ok := recv.Fields[key(c.args[0].C)]; ok {
				n := recv.copy()
				delete(n.Fields, key(c.args[0].C))
				update(n)
				return v
			}
		}
		return taintOf(recv)
	case "remove":
		if recv.Known && len(c.args) == 1 && c.args[0].C != nil {
			n := recv.copy()
			for i, e := range n.Elems {
				if e.C != nil && *e.C == *c.args[0].C {
					n.Elems = append(n.Elems[:i], n.Elems[i+1:]...)
					update(n)
					return &Value{}
				}
			}
		}
		n := recv.copy()
		n.Known, n.Elems = false, nil
		update(n)
		return &Value{}
	case "clear":
		update(&Value{Inst: recv.Inst, Known: recv.Known, Elems: func() []*Value {
			if recv.Known {
				return []*Value{}
			}
			return nil
		}()})
		return &Value{}
	case "get":
		if cfg && len(c.args) >= 2 && c.args[0].C != nil && c.args[1].C != nil {
			if v, ok := recv.Fields[c.args[0].C.Val+"\x00"+c.args[1].C.Val]; ok {
				return v
			}
			return taintOf(recv)
		}
		if !cfg && len(c.args) >= 1 && c.args[0].C != nil && recv.Fields != nil {
			if v, ok := recv.Fields[key(c.args[0].C)]; ok {
				return v
			}
			r := taintOf(recv)
			if len(c.args) > 1 {
				r = mix(r, c.args[1])
			}
			return r
		}
	case "set":
		if cfg && len(c.args) == 3 && c.args[0].C != nil && c.args[1].C != nil {
			n := recv.copy()
			if n.Fields == nil {
				n.Fields = map[string]*Value{}
			}
			n.Fields[c.args[0].C.Val+"\x00"+c.args[1].C.Val] = c.args[2]
			update(mix(n, c.args[2]))
			return &Value{}
		}
	case "setdefault":
		if len(c.args) == 2 && c.args[0].C != nil {
			k := key(c.args[0].C)
			if v, ok := recv.Fields[k]; ok {
				return v
			}
			n := recv.copy()
			if n.Fields == nil {
				n.Fields = map[string]*Value{}
			}
			n.Fields[k] = c.args[1]
			update(mix(n, c.args[1]))
			return c.args[1]
		}
	case "copy":
		return recv
	}
	return nil
}

func intConst(v *Value) (int, bool) {
	if v.C == nil || v.C.Kind != ir.Int {
		return 0, false
	}
	n, err := strconv.Atoi(v.C.Val)
	return n, err == nil
}

func clampInsert(i, n int) int {
	if i < 0 {
		i += n
		if i < 0 {
			i = 0
		}
	}
	if i > n {
		i = n
	}
	return i
}

// fold computes string methods on constants.
func (f *fnRun) fold(c *call) *Value {
	if c.recv.C == nil || c.recv.C.Kind != ir.Str {
		return nil
	}
	s := c.recv.C.Val
	strs := make([]string, 0, len(c.args))
	for _, a := range c.args {
		if a.C == nil {
			return nil
		}
		strs = append(strs, a.C.Val)
	}
	ints := make([]int, 0, len(c.args))
	for _, a := range c.args {
		if n, ok := intConst(a); ok {
			ints = append(ints, n)
		}
	}
	r := []rune(s)
	switch c.in.Name {
	case "charAt":
		if len(ints) == 1 && ints[0] >= 0 && ints[0] < len(r) {
			return strVal(string(r[ints[0]]))
		}
	case "substring":
		if len(ints) == len(c.args) && len(ints) >= 1 {
			lo, hi := ints[0], len(r)
			if len(ints) == 2 {
				hi = ints[1]
			}
			if lo >= 0 && lo <= hi && hi <= len(r) {
				return strVal(string(r[lo:hi]))
			}
		}
	case "length":
		if len(c.args) == 0 {
			return intVal(int64(len(r)))
		}
	case "toUpperCase":
		return strVal(strings.ToUpper(s))
	case "toLowerCase":
		return strVal(strings.ToLower(s))
	case "trim":
		return strVal(strings.TrimSpace(s))
	}
	switch c.in.Name {
	case "upper":
		return strVal(strings.ToUpper(s))
	case "lower":
		return strVal(strings.ToLower(s))
	case "strip":
		if len(strs) == 0 {
			return strVal(strings.TrimSpace(s))
		}
	case "replace":
		if len(strs) == 2 {
			return strVal(strings.ReplaceAll(s, strs[0], strs[1]))
		}
	}
	return nil
}

// flags records flags set on a variable by a setter, such as
// parser.setFeature(feature_external_ges, True).
func (f *fnRun) flags(c *call, st State) {
	if !f.e.setters[c.in.Name] || c.in.A.Var == "" || len(c.args) != 2 || c.args[0].Q == "" {
		return
	}
	n := c.recv.copy()
	if n.Fields == nil {
		n.Fields = map[string]*Value{}
	}
	n.Fields["!"+c.args[0].Q] = c.args[1]
	st[c.in.A.Var] = n
}

// sinks reports untrusted arguments of a dangerous call.
func (f *fnRun) sinks(c *call, st State) {
	var targets []sinkTarget
	for _, n := range c.names {
		targets = append(targets, f.e.calls[n]...)
	}
	if c.method != "" {
		recvName := f.receiverName(c.in)
		for _, t := range f.e.methods[c.method] {
			if rs := t.sink.MethodReceivers[c.method]; len(rs) > 0 && !contains(rs, recvName) && !(c.recv.Inst == "jQuery" && contains(rs, "$")) {
				continue
			}
			if contains(t.sink.ReceiversNot, recvName) {
				continue
			}
			targets = append(targets, t)
		}
	}
	for _, t := range targets {
		s := t.sink
		if t.shell {
			sh, ok := c.kw["shell"]
			if !ok && len(c.args) > 0 {
				// JavaScript: spawn(cmd, args, { shell: true })
				sh, ok = c.args[len(c.args)-1].Fields["shell"]
			}
			if truth, known := knownTruth(sh); !ok || !known || !truth {
				// [shell, "-c", command, ...] runs command in a shell too.
				if cmd := f.shellList(c, t.t.Arg); cmd != nil && cmd.tainted(s.Kind) {
					f.foundSpan(s, c.in.Pos, cmd.T)
				}
				continue
			}
		}
		if f.safeKwargs(s, c) || !f.flagged(s, c) {
			continue
		}
		var vals []*Value
		switch {
		case t.t.Arg == taint.ArgReceiver:
			vals = []*Value{c.recv}
		case t.t.Arg < 0:
			vals = c.all
		case t.t.Arg < len(c.args):
			vals = []*Value{c.args[t.t.Arg]}
		}
		for _, v := range vals {
			if v.tainted(s.Kind) && !(s.TextOnly && v.Opaque) {
				f.foundSpan(s, c.in.Pos, v.T)
				break
			}
			if s.UnlessConstant && v.T == nil && !isPure(v) {
				// Not from the request, but not from constants either: a
				// hypothesis, as a pattern rule would report it.
				f.foundUnknown(s, c.in.Pos.Line)
				break
			}
		}
	}
}

// shellList returns the command of an argument list that starts with a
// shell and its command flag, such as ["sh", "-c", cmd].
func (f *fnRun) shellList(c *call, arg int) *Value {
	if arg < 0 || arg >= len(c.args) {
		return nil
	}
	l := c.args[arg]
	if !l.Known || len(l.Elems) < 3 || l.Elems[1].C == nil || !contains(f.e.spec.ShellFlags, l.Elems[1].C.Val) {
		return nil
	}
	r := &Value{}
	for _, e := range l.Elems[2:] {
		r = mix(r, e)
	}
	return r
}

func knownTruth(v *Value) (bool, bool) {
	if v == nil {
		return false, false
	}
	return known(v)
}

func (f *fnRun) safeKwargs(s *taint.Sink, c *call) bool {
	for k, safe := range s.SafeKwargs {
		v, ok := c.kw[k]
		if !ok {
			continue
		}
		for _, x := range safe {
			if v.Q == x || v.C != nil && v.C.Val == x {
				return true
			}
		}
	}
	return false
}

func (f *fnRun) flagged(s *taint.Sink, c *call) bool {
	if s.RequiresFlag == nil {
		return true
	}
	if s.RequiresFlag.Arg >= len(c.args) {
		return false
	}
	v, ok := c.args[s.RequiresFlag.Arg].Fields["!"+s.RequiresFlag.Flag]
	if !ok {
		return false
	}
	truth, known := known(v)
	return known && truth
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (f *fnRun) found(s *taint.Sink, line int, v *Value) {
	f.foundAt(s, line, v.T)
}

// foundUnknown records a finding at a sink whose input has no known
// origin.
func (f *fnRun) foundUnknown(s *taint.Sink, line int) {
	f.foundAt(s, line, nil)
	k := f.mod.Path + "|" + s.ID + ":" + strconv.Itoa(line)
	fd := f.p.findings[k]
	if fd.Steps != nil && len(fd.Steps) == 1 {
		fd.Library = true
		f.p.findings[k] = fd
	}
}

// foundAt records a finding at a sink with the trace that reached it, or
// with the sink alone when nil.
// propSinks reports a store into a property that is a sink, such as
// el.innerHTML = x or location.href = x: the property alone, or with the
// receiver's name or qualified name.
func (f *fnRun) propSinks(in *ir.Instr, base, v *Value) {
	if !v.dangerous() {
		return
	}
	recv := f.receiverName(&ir.Instr{Name: in.Name, A: in.A})
	for _, s := range f.e.spec.Sinks {
		for _, p := range s.Props {
			if p == in.Name || recv != "" && p == recv+"."+in.Name || base.Q != "" && p == base.Q+"."+in.Name {
				if v.tainted(s.Kind) {
					f.found(s, in.Pos.Line, v)
				}
			}
		}
	}
}

// jsxSinks reports an attribute path of a JSX element (jsx(tag, attrs))
// that is a sink, such as dangerouslySetInnerHTML.__html.
func (f *fnRun) jsxSinks(c *call) {
	if len(c.names) == 0 || c.names[0] != "jsx" || len(c.args) < 2 {
		return
	}
	for _, s := range f.e.spec.Sinks {
		for _, path := range s.JSX {
			v := c.args[1]
			for _, part := range strings.Split(path, ".") {
				next, ok := v.Fields[part]
				if !ok {
					// Not written as an attribute: only a spread
					// ({...props}) can still carry it.
					if sp, ok := v.Fields["..."]; ok {
						if n, ok := sp.Fields[part]; ok {
							v = n
							continue
						}
						v = taintOf(sp)
					} else {
						v = empty
					}
					break
				}
				v = next
			}
			if v.tainted(s.Kind) {
				f.found(s, c.in.Pos.Line, v)
			}
		}
	}
}

// elementCallbacks are methods whose callback gets an element of the
// receiver as its first argument.
var elementCallbacks = map[string]bool{"forEach": true, "map": true, "filter": true, "some": true, "every": true, "find": true,
	"findIndex": true, "flatMap": true, "each": true, "then": true, "replace": false}

// callbacks analyzes the functions a call of code the engine does not see
// receives (new Promise(function (resolve) {...}), list.forEach(fn),
// p.then(fn)): they run with the caller's scope, and their sinks count.
//
// A function written in place (its parent is this function) does not
// count toward the call depth: it is nesting in the source, as in
// new Promise(() => process.nextTick(() => exec(cmd))), which bounds it.
func (f *fnRun) callbacks(c *call) {
	if !f.report {
		return
	}
	for _, a := range callbackFns(c.all) {
		if a.Fn == nil || isClass(a.Fn) || f.p.owner[a.Fn] == nil || f.p.active[a.Fn] {
			continue
		}
		inPlace := a.Fn.Parent == f.fn
		if !inPlace && f.p.depth >= maxCallDepth {
			continue
		}
		args := &call{in: &ir.Instr{}, kw: map[string]*Value{}}
		if elementCallbacks[c.in.Name] {
			args.args = []*Value{iterate(c.recv)}
		}
		if inPlace {
			f.p.depth--
		}
		f.invoke(a.Fn, nil, args)
		if inPlace {
			f.p.depth++
		}
	}
}

// callbackFns returns the arguments of a call that are functions, and the
// functions in arguments that are lists or object literals, as in
// async.series([fn, fn], done) or run({ task: fn }).
func callbackFns(args []*Value) []*Value {
	var out []*Value
	for _, a := range args {
		switch {
		case a.Fn != nil:
			out = append(out, a)
		case a.Inst == "dict":
			for _, k := range sortedKeys(a.Fields) {
				if a.Fields[k].Fn != nil {
					out = append(out, a.Fields[k])
				}
			}
		default:
			for _, e := range a.Elems {
				if e.Fn != nil {
					out = append(out, e)
				}
			}
		}
	}
	return out
}

// stripsDotDot reports a replace() whose pattern is a JavaScript regular
// expression matching parent directory segments (/\.\.\//g) and whose
// replacement is empty: it removes them from a path.
func stripsDotDot(re, repl *ir.Const) bool {
	return re != nil && repl != nil && re.Kind == ir.Other && strings.HasPrefix(re.Val, "/") &&
		strings.Contains(re.Val, `\.\.`) && repl.Kind == ir.Str && repl.Val == ""
}

// jqueryValues are jQuery methods that return a value read from the
// selection rather than the selection.
var jqueryValues = map[string]bool{"text": true, "val": true, "attr": true, "prop": true, "data": true, "css": true, "is": true,
	"hasClass": true, "index": true, "get": true, "toArray": true, "serialize": true, "serializeArray": true, "width": true,
	"height": true, "offset": true, "position": true, "scrollTop": true, "scrollLeft": true, "outerWidth": true, "outerHeight": true}

// socketLifecycle events carry no message from a peer.
var socketLifecycle = map[string]bool{"connect": true, "connection": true, "disconnect": true, "close": true, "open": true,
	"error": true, "end": true, "reconnect": true, "ready": true, "listening": true}

// eventCall analyzes the listeners of events whose data another party
// chooses: socket.on('chat', msg => ...) on a socket, and events such as
// an archive's entry on any emitter.
func (f *fnRun) eventCall(c *call) {
	if c.in.Name != "on" && c.in.Name != "once" && c.in.Name != "addListener" || len(c.args) < 2 {
		return
	}
	ev := c.args[0].C
	if ev == nil || ev.Kind != ir.Str {
		return
	}
	recv := f.receiverName(c.in)
	if recv == "" {
		recv = c.recv.Q
	}
	if i := strings.LastIndexByte(recv, '.'); i >= 0 {
		recv = recv[i+1:]
	}
	if !contains(f.e.spec.Sources.Events, ev.Val) && !(contains(f.e.spec.Sources.Sockets, recv) && !socketLifecycle[ev.Val]) {
		return
	}
	for _, a := range c.args[1:] {
		if a.Fn != nil && !isClass(a.Fn) {
			f.p.listener(a.Fn, f.newSource(c.in.Pos.Line, "'"+ev.Val+"' event data"))
		}
	}
}

// routeCall analyzes the handlers a call registers.
func (f *fnRun) routeCall(c *call) {
	for _, rc := range f.e.spec.Sources.RouteCalls {
		match := false
		for _, n := range c.names {
			match = match || contains(rc.Calls, n)
		}
		if !match && contains(rc.Methods, c.in.Name) {
			match = contains(rc.Receivers, f.receiverName(c.in)) || contains(rc.Receivers, c.recv.Inst)
		}
		if !match {
			continue
		}
		for _, a := range c.all {
			if a.Fn != nil && !isClass(a.Fn) {
				f.p.handler(a.Fn, rc)
			}
		}
	}
}

func (f *fnRun) foundAt(s *taint.Sink, line int, t *taint.Trace) {
	f.foundSpan(s, ir.Pos{Line: line}, t)
}

// foundSpan is foundAt for a call whose arguments may span lines up to
// pos.End, which the finding covers.
func (f *fnRun) foundSpan(s *taint.Sink, pos ir.Pos, t *taint.Trace) {
	line := pos.Line
	if s.RequestOnly && t != nil && t.Root().Library {
		return // a library that opens the path it is given does its job
	}
	k := f.mod.Path + "|" + s.ID + ":" + strconv.Itoa(line)
	if _, ok := f.p.findings[k]; ok {
		return
	}
	step := taint.Step{Line: line, What: f.text(line), File: f.mod.Path}
	tr := t.AddStep(step)
	if t == nil {
		tr = taint.FromSteps([]taint.Step{step}, false)
	}
	steps := tr.Steps()
	for i := range steps {
		if steps[i].File == f.mod.Path {
			steps[i].File = ""
		}
	}
	f.p.findings[k] = taint.Finding{Sink: s, File: f.mod.Path, Line: line, EndLine: max(line, pos.End), Steps: steps, Library: t != nil && t.Root().Library}
	f.p.order = append(f.p.order, k)
}

// uncalled analyzes the functions fn writes in place that nothing called
// while it was analyzed, such as funcs[k] = function (cb) {...} that a
// library runs later, with the scope fn gave them, when that scope holds
// untrusted data. Like callbacks written in place, they do not use up the
// call depth.
func (f *fnRun) uncalled() {
	for _, b := range f.fn.Blocks {
		for _, in := range b.Instrs {
			if in.Op != ir.Func || in.Fn.Parent != f.fn || isClass(in.Fn) || f.p.invoked[in.Fn] || f.p.active[in.Fn] || f.p.handlers[in.Fn] {
				continue
			}
			if !taintedScope(f.envs[in.Fn]) {
				continue
			}
			f.p.depth--
			f.invoke(in.Fn, nil, &call{in: &ir.Instr{}, kw: map[string]*Value{}})
			f.p.depth++
		}
	}
}

// taintedScope reports a scope that holds untrusted data.
func taintedScope(env State) bool {
	for _, v := range env {
		if v.T != nil || taintOf(v).T != nil {
			return true
		}
	}
	return false
}
