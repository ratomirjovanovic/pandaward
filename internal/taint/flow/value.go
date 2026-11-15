package flow

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// Value is what the engine knows about a variable at a point: whether
// untrusted data reaches it (T, with the kinds it was made safe for), its
// constant value, the qualified name of the module, function or attribute
// it refers to, the class it is an instance of, and the values of its
// fields, keys and list elements where those are known. Values are never
// changed once built.
type Value struct {
	T    *taint.Trace
	Safe taint.Kind
	C    *ir.Const
	Q    string
	Inst string
	// Fields holds attributes (".name"), constant keys and flags ("!flag").
	Fields map[string]*Value
	// Elems are the elements of a list or tuple whose length is known.
	Elems []*Value
	Known bool
	// Norm marks a normalized path (resolved, real or absolute).
	Norm bool
	Fn   *ir.Function
	// From is the variable a parsed URL was parsed from.
	From string
	// Opaque marks tainted data returned by a function the engine does not
	// model: an object built from the input rather than the input as text.
	Opaque bool
	// W is where a weak digest or predictable number in the value comes
	// from, and WK which of the two (taint.WeakHash, taint.WeakRandom).
	W  *taint.Trace
	WK taint.Kind
	// Hint is the constant text of a string built from constant and
	// unknown parts ("rememberMe" of "rememberMe" + n), for naming checks.
	Hint string
	// Pure marks a value computed from constants only, through operators,
	// containers and functions that only transform their input (base64,
	// encode, format), even when the engine does not compute it.
	Pure bool
}

// text returns the constant text of a value: a string constant or the
// hint of one partly built from constants.
func text(v *Value) string {
	if v.C != nil && v.C.Kind == ir.Str {
		return v.C.Val
	}
	return v.Hint
}

// hinted marks r with the constant text of the parts it was built from.
func hinted(r *Value, parts ...*Value) *Value {
	if r.C != nil {
		return r
	}
	var sb strings.Builder
	for _, p := range parts {
		sb.WriteString(text(p))
	}
	if sb.Len() == 0 || r.Hint == sb.String() {
		return r
	}
	r = r.copy()
	r.Hint = sb.String()
	return r
}

// isPure reports a value known to come from constants only.
func isPure(v *Value) bool {
	if v == nil {
		return false
	}
	if v.C != nil || v.Pure {
		return true
	}
	if !v.Known || v.T != nil {
		return false
	}
	for _, e := range v.Elems {
		if !isPure(e) {
			return false
		}
	}
	return true
}

// purified marks r pure when every input it was computed from is.
func purified(r *Value, inputs ...*Value) *Value {
	if isPure(r) {
		return r
	}
	for _, in := range inputs {
		if !isPure(in) {
			return r
		}
	}
	r = r.copy()
	r.Pure = true
	return r
}

var empty = &Value{}

// tainted reports untrusted data that is still dangerous for kind k.
func (v *Value) tainted(k taint.Kind) bool {
	return v != nil && v.T != nil && v.Safe&k != k
}

// dangerous reports untrusted data dangerous for some kind.
func (v *Value) dangerous() bool { return v != nil && v.T != nil && v.Safe != taint.All }

func constVal(c *ir.Const) *Value { return &Value{C: c} }

func strVal(s string) *Value { return &Value{C: &ir.Const{Kind: ir.Str, Val: s}} }

func intVal(n int64) *Value {
	return &Value{C: &ir.Const{Kind: ir.Int, Val: strconv.FormatInt(n, 10)}}
}

func boolVal(b bool) *Value {
	if b {
		return &Value{C: &ir.Const{Kind: ir.Bool, Val: "true"}}
	}
	return &Value{C: &ir.Const{Kind: ir.Bool, Val: "false"}}
}

// with returns a copy of v that the caller may change.
func (v *Value) copy() *Value {
	if v == nil {
		return &Value{}
	}
	c := *v
	if v.Fields != nil {
		c.Fields = make(map[string]*Value, len(v.Fields))
		for k, f := range v.Fields {
			c.Fields[k] = f
		}
	}
	if v.Elems != nil {
		c.Elems = append([]*Value(nil), v.Elems...)
	}
	return &c
}

// taintOf keeps only the taint of v: data derived from it that is neither
// constant nor a known object.
func taintOf(v *Value) *Value {
	if v == nil || v.T == nil && v.W == nil {
		return empty
	}
	return &Value{T: v.T, Safe: v.Safe, Opaque: v.Opaque, W: v.W, WK: v.WK}
}

// mix adds the taint of x to v (a value being built from both).
func mix(v, x *Value) *Value {
	if x != nil && x.W != nil && v.WK&x.WK != x.WK {
		v = v.copy()
		if v.W == nil {
			v.W = x.W
		}
		v.WK |= x.WK
	}
	if x == nil || x.T == nil {
		return v
	}
	if v.T == nil {
		r := v.copy()
		r.T, r.Safe, r.Opaque = x.T, x.Safe, x.Opaque
		return r
	}
	if v.Safe&x.Safe == v.Safe && (x.Opaque || !v.Opaque) {
		return v
	}
	r := v.copy()
	if v.Safe&^x.Safe != 0 {
		r.T = x.T // the trace of the part that is not safe
	}
	r.Safe &= x.Safe
	r.Opaque = v.Opaque && x.Opaque
	return r
}

const maxDepth = 4

// join merges the values a variable has on two incoming paths.
func join(a, b *Value, widen bool) *Value {
	return joinDepth(a, b, widen, 0)
}

func joinDepth(a, b *Value, widen bool, depth int) *Value {
	if a == nil {
		a = empty
	}
	if b == nil {
		b = empty
	}
	if a == b && !widen {
		return a
	}
	r := &Value{}
	switch {
	case a.T != nil && b.T != nil:
		r.T, r.Safe, r.Opaque = a.T, a.Safe&b.Safe, a.Opaque && b.Opaque
		if a.Safe&^b.Safe != 0 {
			// the trace of the side the join is not safe for
			r.T = b.T
		}
	case a.T != nil:
		r.T, r.Safe, r.Opaque = a.T, a.Safe, a.Opaque
	case b.T != nil:
		r.T, r.Safe, r.Opaque = b.T, b.Safe, b.Opaque
	}
	if !widen && a.C != nil && b.C != nil && *a.C == *b.C {
		r.C = a.C
	}
	if a.Q == b.Q {
		r.Q = a.Q
	}
	r.W, r.WK = a.W, a.WK|b.WK
	if r.W == nil {
		r.W = b.W
	}
	if a.Inst == b.Inst {
		r.Inst = a.Inst
	}
	if a.Fn == b.Fn {
		r.Fn = a.Fn
	}
	r.Norm = a.Norm && b.Norm
	r.Pure = isPure(a) && isPure(b)
	if a.Hint == b.Hint {
		r.Hint = a.Hint
	}
	if a.From == b.From {
		r.From = a.From
	}
	if depth < maxDepth && (a.Fields != nil || b.Fields != nil) {
		// A key known on one path only is unknown after the join: it holds
		// whatever the container holds as a whole on the other path.
		r.Fields = map[string]*Value{}
		for k, x := range a.Fields {
			y, ok := b.Fields[k]
			if !ok {
				y = taintOf(b)
			}
			r.Fields[k] = joinDepth(x, y, widen, depth+1)
		}
		for k, y := range b.Fields {
			if _, ok := a.Fields[k]; !ok {
				r.Fields[k] = joinDepth(taintOf(a), y, widen, depth+1)
			}
		}
	}
	if !widen && a.Known && b.Known && len(a.Elems) == len(b.Elems) && depth < maxDepth {
		r.Known = true
		r.Elems = make([]*Value, len(a.Elems))
		for i := range a.Elems {
			r.Elems[i] = joinDepth(a.Elems[i], b.Elems[i], widen, depth+1)
		}
	}
	return r
}

// covers reports, without allocating, that joining v into old would leave
// old unchanged; false means the join has to be computed.
func covers(old, v *Value) bool {
	if v.T != nil && (old.T == nil || old.Safe&v.Safe != old.Safe || old.Opaque && !v.Opaque) {
		return false
	}
	if old.C != nil && (v.C == nil || *old.C != *v.C) {
		return false
	}
	if old.Q != "" && old.Q != v.Q || old.Inst != "" && old.Inst != v.Inst || old.Fn != nil && old.Fn != v.Fn || old.From != "" && old.From != v.From {
		return false
	}
	if old.Norm && !v.Norm || old.WK&v.WK != v.WK || old.Pure && !isPure(v) {
		return false
	}
	return old.Fields == nil && v.Fields == nil && !old.Known
}

// equal compares values as the fixpoint needs: taint presence and safety,
// constants, names and known parts; traces may differ.
func equal(a, b *Value) bool {
	if a == b {
		return true
	}
	if a == nil {
		a = empty
	}
	if b == nil {
		b = empty
	}
	if (a.T != nil) != (b.T != nil) || a.Safe != b.Safe || a.Q != b.Q || a.Inst != b.Inst || a.Norm != b.Norm || a.Fn != b.Fn || a.Known != b.Known || a.From != b.From || a.Opaque != b.Opaque || a.WK != b.WK || isPure(a) != isPure(b) || a.Hint != b.Hint {
		return false
	}
	if (a.C == nil) != (b.C == nil) || a.C != nil && *a.C != *b.C {
		return false
	}
	if len(a.Fields) != len(b.Fields) || len(a.Elems) != len(b.Elems) {
		return false
	}
	for k, x := range a.Fields {
		if !equal(x, b.Fields[k]) {
			return false
		}
	}
	for i := range a.Elems {
		if !equal(a.Elems[i], b.Elems[i]) {
			return false
		}
	}
	return true
}

// State maps variables to values. A missing variable has no value yet.
type State map[string]*Value

func (s State) copy() State {
	c := make(State, len(s))
	for k, v := range s {
		c[k] = v
	}
	return c
}

// joinInto merges s into dst and reports a change.
func joinInto(dst State, s State, widen bool) bool {
	changed := false
	for k, v := range s {
		old, ok := dst[k]
		if !ok {
			dst[k] = v
			changed = true
			continue
		}
		if old == v || !widen && covers(old, v) {
			continue
		}
		j := join(old, v, widen)
		if !equal(j, old) {
			dst[k] = j
			changed = true
		}
	}
	return changed
}

func sortedKeys(m map[string]*Value) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
