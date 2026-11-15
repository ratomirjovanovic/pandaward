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
	}
	r := f.weakSource(c, f.callResolved(c, st))
	if r.Inst == "" || r.Inst == r.Q {
		for _, n := range c.names {
			if t, ok := f.e.spec.Returns[n]; ok {
				r = r.copy()
				r.Inst = t
				break
			}
		}
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
		if a.C == nil || a.C.Kind != ir.Str {
			return nil
		}
		strs = append(strs, a.C.Val)
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
			if rs := t.sink.MethodReceivers[c.method]; len(rs) > 0 && !contains(rs, recvName) {
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
			if truth, known := knownTruth(sh); !ok || !known || !truth {
				// [shell, "-c", command, ...] runs command in a shell too.
				if cmd := f.shellList(c, t.t.Arg); cmd != nil && cmd.tainted(s.Kind) {
					f.found(s, c.in.Pos.Line, cmd)
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
				f.found(s, c.in.Pos.Line, v)
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
func (f *fnRun) foundAt(s *taint.Sink, line int, t *taint.Trace) {
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
	f.p.findings[k] = taint.Finding{Sink: s, File: f.mod.Path, Line: line, EndLine: line, Steps: steps}
	f.p.order = append(f.p.order, k)
}
