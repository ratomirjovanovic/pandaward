// Package csp parses Content-Security-Policy values and decides whether the
// script policy they enforce still lets injected script run.
//
// The check is deliberately narrow so that it rarely fires on a policy that
// actually protects: it looks only at the script directives, follows the
// browser fallback from script-src to default-src, and treats
// 'unsafe-inline' as harmless when a nonce, a hash or 'strict-dynamic' makes
// browsers ignore it. Report-only policies are not enforced and must not be
// passed in.
package csp

import "strings"

// Policy maps a directive name to its source expressions. Directive names
// are lower case; the first occurrence of a directive wins, as in browsers.
type Policy map[string][]string

// Parse reads one serialized policy (directives separated by ";").
func Parse(policy string) Policy {
	p := Policy{}
	for _, d := range strings.Split(policy, ";") {
		f := strings.Fields(d)
		if len(f) == 0 || !validName(f[0]) {
			continue
		}
		name := strings.ToLower(f[0])
		if _, dup := p[name]; dup {
			continue
		}
		p[name] = f[1:]
	}
	return p
}

func validName(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return s != ""
}

// sources returns the first of the named directives that the policy sets.
func (p Policy) sources(names ...string) (string, []string, bool) {
	for _, n := range names {
		if s, ok := p[n]; ok {
			return n, s, true
		}
	}
	return "", nil, false
}

// Weakness describes why an enforced policy does not restrict scripts.
type Weakness struct {
	// Keyword is 'unsafe-eval' or 'unsafe-inline'.
	Keyword string
	// Directive is the directive that carries the keyword.
	Directive string
}

// Check evaluates a header value, which may hold several policies separated
// by commas (repeated headers joined with ","). Every policy is enforced, so
// the result is weak only when each policy that restricts scripts allows the
// same unsafe keyword. A value with no script restriction at all is not
// reported here; a missing CSP is a different finding.
func Check(value string) (Weakness, bool) {
	var policies []Policy
	for _, s := range strings.Split(value, ",") {
		if p := Parse(s); len(p) > 0 {
			policies = append(policies, p)
		}
	}
	if w, ok := allWeak(policies, evalWeak); ok {
		return w, true
	}
	return allWeak(policies, inlineWeak)
}

func allWeak(policies []Policy, weak func(Policy) (Weakness, bool, bool)) (Weakness, bool) {
	var first Weakness
	found := false
	for _, p := range policies {
		w, restricts, isWeak := weak(p)
		if !restricts {
			continue
		}
		if !isWeak {
			return Weakness{}, false
		}
		if !found {
			first, found = w, true
		}
	}
	return first, found
}

// evalWeak: string evaluation is governed by script-src, else default-src.
func evalWeak(p Policy) (Weakness, bool, bool) {
	name, src, ok := p.sources("script-src", "default-src")
	if !ok {
		return Weakness{}, false, false
	}
	if has(src, "'unsafe-eval'") {
		return Weakness{Keyword: "'unsafe-eval'", Directive: name}, true, true
	}
	return Weakness{}, true, false
}

// inlineWeak: inline script elements are governed by script-src-elem, else
// script-src, else default-src. 'unsafe-inline' is ignored by browsers when
// the same list has a nonce, a hash or 'strict-dynamic'.
func inlineWeak(p Policy) (Weakness, bool, bool) {
	name, src, ok := p.sources("script-src-elem", "script-src", "default-src")
	if !ok {
		return Weakness{}, false, false
	}
	if !has(src, "'unsafe-inline'") {
		return Weakness{}, true, false
	}
	for _, s := range src {
		l := strings.ToLower(s)
		if l == "'strict-dynamic'" || strings.HasPrefix(l, "'nonce-") || strings.HasPrefix(l, "'sha256-") || strings.HasPrefix(l, "'sha384-") || strings.HasPrefix(l, "'sha512-") {
			return Weakness{}, true, false
		}
	}
	return Weakness{Keyword: "'unsafe-inline'", Directive: name}, true, true
}

func has(src []string, kw string) bool {
	for _, s := range src {
		if strings.EqualFold(s, kw) {
			return true
		}
	}
	return false
}

// Message explains a weakness in one sentence.
func (w Weakness) Message() string {
	if w.Keyword == "'unsafe-eval'" {
		return "The enforced CSP allows 'unsafe-eval' in " + w.Directive + ", so strings can run as code (eval, new Function) and an injection has more reach."
	}
	return "The enforced CSP allows 'unsafe-inline' in " + w.Directive + " without a nonce, hash or 'strict-dynamic', so injected inline scripts run and the CSP does not mitigate XSS."
}

// Fix is the remediation advice for a weakness.
func (w Weakness) Fix() string {
	if w.Keyword == "'unsafe-eval'" {
		return "Remove 'unsafe-eval' from " + w.Directive + "; replace eval-based code or libraries, or allow WebAssembly only with 'wasm-unsafe-eval'."
	}
	return "Remove 'unsafe-inline' from " + w.Directive + ", or use per-response nonces or hashes (with 'strict-dynamic') so browsers ignore it."
}
