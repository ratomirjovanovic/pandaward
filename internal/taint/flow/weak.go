package flow

import (
	"strings"
	"unicode"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
)

// weak holds what the engine needs to find weak digests stored as
// passwords, predictable numbers used as secrets and cookies set without
// their security flags.
type weak struct {
	hashCalls, hashNew, hashNames, randCalls map[string]bool
	secret, password                         map[string]bool
	cookieSetters                            map[string]bool
	cookieFlags                              []string
	hashSink, randSink, cookieSink           *taint.Sink
}

func newWeak(spec *taint.Spec) weak {
	w := spec.Weak
	out := weak{hashCalls: set(w.HashCalls), hashNew: set(w.HashNew), hashNames: set(w.HashNames), randCalls: set(w.RandomCalls),
		secret: set(w.SecretNames), password: set(w.PasswordNames), cookieSetters: set(w.CookieSetters), cookieFlags: w.CookieFlags}
	for _, s := range spec.Sinks {
		switch s.Kind {
		case taint.WeakHash:
			out.hashSink = s
		case taint.WeakRandom:
			out.randSink = s
		case taint.Cookie:
			out.cookieSink = s
		}
	}
	return out
}

// words splits a name into lower-case words at separators and case
// changes: rememberMe_token -> remember, me, token.
func words(name string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	prev := rune(0)
	for _, r := range name {
		switch {
		case !unicode.IsLetter(r):
			flush()
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return out
}

// named reports a name with one of the words, alone or as two words
// written together (api_key for apikey).
func named(name string, list map[string]bool) bool {
	ws := words(name)
	for i, w := range ws {
		if list[w] || i+1 < len(ws) && list[w+ws[i+1]] {
			return true
		}
	}
	return false
}

// weakSource marks the result of a call that makes a weak digest or a
// predictable number, and remembers the path of a file a call opens.
func (f *fnRun) weakSource(c *call, r *Value) *Value {
	w := &f.e.weak
	var kind taint.Kind
	for _, n := range c.names {
		switch {
		case w.hashCalls[n]:
			kind = taint.WeakHash
		case w.hashNew[n] && len(c.args) > 0 && c.args[0].C != nil && w.hashNames[c.args[0].C.Val]:
			kind = taint.WeakHash
		case w.randCalls[n]:
			kind = taint.WeakRandom
		}
		if (n == "open" || n == "io.open" || n == "codecs.open") && len(c.in.Args) > 0 {
			if name := f.constText(c.in.Args[0]); name != "" {
				r = r.copy()
				if r.Fields == nil {
					r.Fields = map[string]*Value{}
				}
				r.Fields["?path"] = strVal(name)
			}
		}
	}
	if kind == 0 {
		return r
	}
	r = r.copy()
	line := c.in.Pos.Line
	r.W = taint.NewSource(line, f.text(line), false)
	r.W.File = f.mod.Path
	r.WK |= kind
	return r
}

// weakSinks reports, at a call, a cookie set without its flags or with a
// predictable value, and a weak digest or predictable number written to a
// file named for a password or secret.
func (f *fnRun) weakSinks(c *call) {
	w := &f.e.weak
	line := c.in.Pos.Line
	if w.cookieSetters[c.in.Name] {
		for _, flag := range w.cookieFlags {
			if v, ok := c.kw[flag]; ok && v.C != nil {
				if t, known := v.C.Truth(); known && !t && w.cookieSink != nil {
					f.foundAt(w.cookieSink, line, nil)
					break
				}
			}
		}
		value := c.kw["value"]
		if value == nil && len(c.args) > 1 {
			value = c.args[1]
		}
		if value != nil && value.WK&taint.WeakRandom != 0 && w.randSink != nil {
			f.foundAt(w.randSink, line, value.W)
		}
	}
	if c.in.Name == "write" || c.in.Name == "writelines" {
		if p, ok := c.recv.Fields["?path"]; ok && p.C != nil {
			for _, a := range c.args {
				f.weakStore(p.C.Val, a, line)
			}
		}
	}
}

// weakStore reports a weak value stored under a name: a key, an attribute
// or a file.
func (f *fnRun) weakStore(name string, v *Value, line int) {
	w := &f.e.weak
	if v == nil || v.W == nil {
		return
	}
	switch {
	case v.WK&taint.WeakHash != 0 && w.hashSink != nil && named(name, w.password):
		f.foundAt(w.hashSink, line, v.W)
	case v.WK&taint.WeakRandom != 0 && w.randSink != nil && named(name, w.secret):
		f.foundAt(w.randSink, line, v.W)
	}
}

// weakSession reports a predictable number stored in the session.
func (f *fnRun) weakSession(v *Value, line int) {
	if v != nil && v.WK&taint.WeakRandom != 0 && f.e.weak.randSink != nil {
		f.foundAt(f.e.weak.randSink, line, v.W)
	}
}

// constText returns the constant text of an operand: a string constant,
// or the constant parts of an f-string or concatenation, such as
// "/passwordFile.txt" of f'{base}/passwordFile.txt'.
func (f *fnRun) constText(o ir.Operand) string {
	if o.Const != nil {
		if o.Const.Kind == ir.Str {
			return o.Const.Val
		}
		return ""
	}
	d := f.fn.Defs[o.Var]
	if d == nil {
		return ""
	}
	switch {
	case d.Op == ir.Build && d.Name == "str":
		var sb strings.Builder
		for _, a := range d.Args {
			sb.WriteString(f.constText(a))
		}
		return sb.String()
	case d.Op == ir.Bin && d.Name == "+":
		return f.constText(d.A) + f.constText(d.B)
	case d.Op == ir.Copy:
		return f.constText(d.A)
	}
	return ""
}

// keyName returns the constant name a store uses.
func keyName(k *Value) string {
	if k.C != nil && k.C.Kind == ir.Str {
		return k.C.Val
	}
	return ""
}
