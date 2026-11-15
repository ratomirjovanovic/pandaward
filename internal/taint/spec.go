// Package taint holds what the built-in taint engine shares across
// languages: the specification of sources, sinks and sanitizers, the kinds
// of weakness, and traces from a source to a sink.
package taint

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ratomirjovanovic/pandaward/rules"
)

// Kind is a set of weakness kinds; a sanitizer makes a value safe for some
// kinds only.
type Kind uint32

const (
	Cmd Kind = 1 << iota
	Code
	Path
	SQL
	XSS
	SSRF
	Redirect
	Proto
	Deser
	LDAP
	XPath
	// Trust is untrusted data stored where the application trusts it, such
	// as the session.
	Trust
	XXE
	// WeakHash, WeakRandom and Cookie are not untrusted input: a weak
	// digest stored as a password, a predictable value used as a secret,
	// and a cookie set without its security flags (Python).
	WeakHash
	WeakRandom
	Cookie
	// WeakCrypto is a broken cipher or mode (Java).
	WeakCrypto
	// Shape marks checks found by the shape of the code alone.
	Shape
	All Kind = 1<<iota - 1
)

var kindByName = map[string]Kind{"cmd": Cmd, "code": Code, "path": Path, "sql": SQL, "xss": XSS, "ssrf": SSRF, "redirect": Redirect, "proto": Proto, "deser": Deser, "ldap": LDAP, "xpath": XPath, "trust": Trust, "xxe": XXE, "weakhash": WeakHash, "weakrandom": WeakRandom, "cookie": Cookie, "weakcrypto": WeakCrypto, "shape": Shape, "all": All}

// Spec is a parsed taint specification.
type Spec struct {
	Sources    Sources
	Sinks      []*Sink
	Sanitizers []Sanitizer
	// Guards are checks that make a value safe on one branch (Python).
	Guards []*Guard
	// Normalizers return a canonical path, which a prefix check can then
	// confine (Python).
	Normalizers []string
	// Responses build an HTTP response from a body (Python).
	Responses Responses
	// Escapes are replace() calls that remove a character (Python).
	Escapes []*Escape
	// URLParsers parse a URL whose netloc a guard can check (Python).
	URLParsers []string
	// ShellFlags make a list [shell, flag, command] run a shell command.
	ShellFlags []string
	// TextCalls return text derived from their arguments (unquote,
	// b64decode, os.path.join); any other call the engine does not model
	// returns an opaque object built from them (Python).
	TextCalls []string
	// Weak describes weak hashes and random numbers and the names of
	// values that must not be predictable or stored as a weak digest
	// (Python).
	Weak Weak
	// Supersedes lists bundled Semgrep rules the engine replaces in the
	// files it analyzes (Python).
	Supersedes []string
	// Pure are calls and methods that only transform their input.
	Pure Pure
	// Returns maps a qualified method to the class it returns (Java).
	Returns map[string]string
	// Decoders turn text into bytes that can hold anything, undoing what
	// a check of the text allowed (Python).
	Decoders []string
	// Lookups are methods that return what their receiver holds, not their
	// arguments: a row found by a key from the request is the database's
	// data (Python).
	Lookups []string
	// sanitizer kinds by callee name and by method name
	sanitizeCall   map[string]Kind
	sanitizeMethod map[string]Kind
}

// Sources lists where untrusted data comes from.
type Sources struct {
	Request struct {
		Names   []string `yaml:"names"`
		Weak    []string `yaml:"weak_names"`
		Props   []string `yaml:"props"`
		Methods []string `yaml:"methods"`
	} `yaml:"request"`
	Handlers struct {
		Receivers []string `yaml:"receivers"`
		Methods   []string `yaml:"methods"`
		Calls     []string `yaml:"calls"`
	} `yaml:"handlers"`
	HelperParams      []string `yaml:"helper_params"`
	Events            []string `yaml:"events"`
	Sockets           []string `yaml:"sockets"`
	PluginOptions     []string `yaml:"plugin_options"`
	Globals           []string `yaml:"globals"`
	LibraryParameters bool     `yaml:"library_parameters"`

	// The IR engine (Python): qualified attributes and calls that return
	// untrusted data, parameter names that hold a request object (their
	// attributes are then qualified by that name), and decorators that
	// register a route handler, whose parameters are path values.
	Attributes []string `yaml:"attributes"`
	// Chains are attribute paths whose end is untrusted wherever it is
	// read, such as a language model's reply (choices.[].message.content).
	Chains          []string `yaml:"chains"`
	Calls           []string `yaml:"calls"`
	Params          []string `yaml:"params"`
	RouteDecorators []string `yaml:"route_decorators"`
	// RouteCalls register a handler function: its first parameter is the
	// request (Q Request) and its second the response (class Response)
	// (JavaScript: app.get(path, handler), http.createServer(handler)).
	RouteCalls []RouteCall `yaml:"route_calls"`
	// ParamAnnotations mark a parameter as request data (Java:
	// RequestParam, PathVariable, QueryParam, ...).
	ParamAnnotations []string `yaml:"param_annotations"`
	// HTMLReturnFrameworks are modules whose import makes a route
	// handler's return value an HTML response.
	HTMLReturnFrameworks []string `yaml:"html_return_frameworks"`
}

// RouteCall is a call that registers a request handler: a method in
// Methods called on a receiver named or of a class in Receivers, or a
// call of one of Calls.
type RouteCall struct {
	Receivers []string `yaml:"receivers"`
	Methods   []string `yaml:"methods"`
	Calls     []string `yaml:"calls"`
	Request   string   `yaml:"request"`
	Response  string   `yaml:"response"`
}

// Guard is a test that makes a value safe for Kinds on one branch: the
// value does not contain one of Contains (the branch where `c in x` is
// false), or a normalized path passed Method (startswith) on the branch
// where it is true.
type Guard struct {
	KindsRaw   []string `yaml:"kinds"`
	Kinds      Kind     `yaml:"-"`
	Contains   []string `yaml:"contains"`
	Method     string   `yaml:"method"`
	Normalized bool     `yaml:"normalized"`
	// QuotedLiteral: startswith and endswith a quote and no quote between.
	QuotedLiteral bool `yaml:"quoted_literal"`
	// Netloc: the host of a parsed URL is in a constant allowlist.
	Netloc bool `yaml:"netloc"`
	// Methods are checks such as isalnum: true only when the whole value
	// has no character that could matter.
	Methods []string `yaml:"methods"`
	// Allowlist: `x in <constants>` is true, so x is one of them.
	Allowlist bool `yaml:"allowlist"`
	// Calls are library checks that return true only for a safe first
	// argument.
	Calls []string `yaml:"calls"`
}

// Escape is x.replace(Old, new) with a new that does not contain Old.
type Escape struct {
	Old      string   `yaml:"old"`
	KindsRaw []string `yaml:"kinds"`
	Kinds    Kind     `yaml:"-"`
}

// Responses are calls that build a response from a body (the first
// argument, or the first element of a tuple); a keyword in ContentType
// with a value outside HTMLTypes makes the body safe for HTML.
type Responses struct {
	Calls       []string `yaml:"calls"`
	ContentType []string `yaml:"content_type_kwargs"`
	HTMLTypes   []string `yaml:"html_types"`
}

// ArgReceiver is the Arg of a target that watches the receiver of a
// method call (`pathlib.Path.read_text#self`).
const ArgReceiver = -2

// Target is a callee or method name and the argument it watches; Arg is -1
// for any argument.
type Target struct {
	Name string
	Arg  int
}

// Sink is one kind of dangerous operation.
type Sink struct {
	ID      string `yaml:"id"`
	KindStr string `yaml:"kind"`
	Kind    Kind   `yaml:"-"`
	Control string `yaml:"control"`
	CWE     string `yaml:"cwe"`
	Title   string `yaml:"title"`
	Message string `yaml:"message"`
	Fix     string `yaml:"fix"`
	// Calls are resolved callees; CallsWithShell only count with a
	// { shell: true } option; Methods match a method name on any receiver
	// unless MethodReceivers restricts it; Props are assignment targets;
	// JSX are attribute paths.
	CallsRaw        []string            `yaml:"calls"`
	ShellRaw        []string            `yaml:"calls_with_shell_option"`
	MethodsRaw      []string            `yaml:"methods"`
	MethodReceivers map[string][]string `yaml:"method_receivers"`
	ReceiversNot    []string            `yaml:"receivers_not"`
	Props           []string            `yaml:"props"`
	JSX             []string            `yaml:"jsx"`
	// The IR engine (Python): Stores are containers (qualified names)
	// where storing an untrusted key or value is the sink; SafeKwargs maps
	// a keyword to the qualified names or constants that make the call
	// safe; RequiresFlag needs a flag set on an argument (a parser with
	// external entities turned on); HandlerReturn makes the return value
	// of a route handler the sink.
	Stores        []string            `yaml:"stores"`
	SafeKwargs    map[string][]string `yaml:"safe_kwargs"`
	RequiresFlag  *Flag               `yaml:"requires_flag"`
	HandlerReturn bool                `yaml:"handler_return"`
	// TextOnly sinks need the input as text, not an object a helper
	// built from it: a redirect to url_for(..., next=x) or a session
	// entry holding a form object is not the flaw.
	TextOnly bool `yaml:"text_only"`
	// WeakAlgorithms report a call whose argument names a broken
	// algorithm, constant or read from a properties file (Java).
	WeakAlgorithms *WeakAlgorithms `yaml:"weak_algorithms"`
	// UnlessConstant sinks are reported for any input that is not shown
	// to come from constants, not only for untrusted input (Python
	// deserialization).
	UnlessConstant bool `yaml:"unless_constant"`
	// RequestOnly sinks are reported only for request sources, not for
	// library parameters: a library that fetches the URL it is given is
	// doing its job.
	RequestOnly bool `yaml:"request_only"`

	Calls          map[string]Target `yaml:"-"`
	CallsWithShell map[string]Target `yaml:"-"`
	Methods        map[string]Target `yaml:"-"`
}

// WeakAlgorithms are calls (name#arg) whose argument names an algorithm:
// the first part of a transformation such as DES/CBC/PKCS5Padding is in
// Names, a mode part is ecb, or the algorithm is in Bare with no mode.
type WeakAlgorithms struct {
	Calls []string `yaml:"calls"`
	Names []string `yaml:"names"`
	Bare  []string `yaml:"bare"`
}

// Flag is a flag set on argument Arg by a call such as
// parser.setFeature(Flag, True).
type Flag struct {
	Arg    int      `yaml:"arg"`
	Flag   string   `yaml:"flag"`
	Setter []string `yaml:"setters"`
}

// Sanitizer makes values safe for some kinds. Methods are method names
// called on the value (Python: x.isdigit() returns no part of x).
type Sanitizer struct {
	KindsRaw []string `yaml:"kinds"`
	Calls    []string `yaml:"calls"`
	Methods  []string `yaml:"methods"`
}

type specFile struct {
	Sources     Sources           `yaml:"sources"`
	Sinks       []*Sink           `yaml:"sinks"`
	Sanitizers  []Sanitizer       `yaml:"sanitizers"`
	Guards      []*Guard          `yaml:"guards"`
	Normalizers []string          `yaml:"normalizers"`
	Responses   Responses         `yaml:"responses"`
	Escapes     []*Escape         `yaml:"escapes"`
	URLParsers  []string          `yaml:"url_parsers"`
	ShellFlags  []string          `yaml:"shell_flags"`
	TextCalls   []string          `yaml:"text_calls"`
	Lookups     []string          `yaml:"lookups"`
	Weak        Weak              `yaml:"weak"`
	Supersedes  []string          `yaml:"supersedes"`
	Pure        Pure              `yaml:"pure"`
	Returns     map[string]string `yaml:"returns"`
	Decoders    []string          `yaml:"decoders"`
}

// Pure lists the calls and methods whose result comes from constants when
// their input does (Python).
type Pure struct {
	Calls   []string `yaml:"calls"`
	Methods []string `yaml:"methods"`
}

// Weak lists the calls that make a weak digest or a predictable number,
// and the names (of keys, attributes, files) that mark a secret or a
// stored password.
type Weak struct {
	HashCalls     []string `yaml:"hash_calls"`
	HashNew       []string `yaml:"hash_new"`
	HashNames     []string `yaml:"hash_algorithms"`
	RandomCalls   []string `yaml:"random_calls"`
	SecretNames   []string `yaml:"secret_names"`
	PasswordNames []string `yaml:"password_names"`
	CookieSetters []string `yaml:"cookie_setters"`
	CookieFlags   []string `yaml:"cookie_flags"`
	// RandomFill are calls that fill their first argument with predictable
	// bytes (Java: Random.nextBytes).
	RandomFill []string `yaml:"random_fill"`
	// SecretStores are callee#nameArg#valueArg: a call that stores a
	// value under a name (Java: new Cookie(name, value)).
	SecretStores []string `yaml:"secret_stores"`
	// CookieFlagSetters are methods that set a cookie's security flag
	// (Java: Cookie.setSecure); false is the finding.
	CookieFlagSetters []string `yaml:"cookie_flag_setters"`
}

func parseTarget(s string) (Target, error) {
	name, arg, ok := strings.Cut(s, "#")
	t := Target{Name: name}
	if !ok {
		return t, nil
	}
	switch arg {
	case "*":
		t.Arg = -1
		return t, nil
	case "self":
		t.Arg = ArgReceiver
		return t, nil
	}
	n, err := strconv.Atoi(arg)
	if err != nil {
		return t, fmt.Errorf("bad argument index in %q", s)
	}
	t.Arg = n
	return t, nil
}

func targets(list []string) (map[string]Target, error) {
	m := map[string]Target{}
	for _, s := range list {
		t, err := parseTarget(s)
		if err != nil {
			return nil, err
		}
		m[t.Name] = t
	}
	return m, nil
}

// Parse reads a specification.
func Parse(data []byte) (*Spec, error) {
	var f specFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	s := &Spec{Sources: f.Sources, Sinks: f.Sinks, Sanitizers: f.Sanitizers, Guards: f.Guards, Normalizers: f.Normalizers, Responses: f.Responses, Escapes: f.Escapes, URLParsers: f.URLParsers, ShellFlags: f.ShellFlags, TextCalls: f.TextCalls, Lookups: f.Lookups, Weak: f.Weak, Supersedes: f.Supersedes, Pure: f.Pure, Returns: f.Returns, Decoders: f.Decoders, sanitizeCall: map[string]Kind{}, sanitizeMethod: map[string]Kind{}}
	for _, g := range s.Guards {
		for _, n := range g.KindsRaw {
			k, ok := kindByName[n]
			if !ok {
				return nil, fmt.Errorf("guard: unknown kind %q", n)
			}
			g.Kinds |= k
		}
	}
	for _, x := range s.Escapes {
		for _, n := range x.KindsRaw {
			k, ok := kindByName[n]
			if !ok {
				return nil, fmt.Errorf("escape: unknown kind %q", n)
			}
			x.Kinds |= k
		}
	}
	for _, k := range s.Sinks {
		var ok bool
		if k.Kind, ok = kindByName[k.KindStr]; !ok || k.Kind == All {
			return nil, fmt.Errorf("sink %s: unknown kind %q", k.ID, k.KindStr)
		}
		var err error
		if k.Calls, err = targets(k.CallsRaw); err != nil {
			return nil, err
		}
		if k.CallsWithShell, err = targets(k.ShellRaw); err != nil {
			return nil, err
		}
		if k.Methods, err = targets(k.MethodsRaw); err != nil {
			return nil, err
		}
	}
	for _, z := range s.Sanitizers {
		var kinds Kind
		for _, n := range z.KindsRaw {
			k, ok := kindByName[n]
			if !ok {
				return nil, fmt.Errorf("sanitizer: unknown kind %q", n)
			}
			kinds |= k
		}
		for _, c := range z.Calls {
			s.sanitizeCall[c] |= kinds
		}
		for _, m := range z.Methods {
			s.sanitizeMethod[m] |= kinds
		}
	}
	return s, nil
}

// Load returns the bundled specification for a language.
func Load(lang string) (*Spec, error) {
	b, err := rules.TaintSpec(lang)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Classes returns the qualified class names the specification mentions
// (the part of a qualified name before a lower-case method, and the
// classes methods return), for resolving the names of star imports.
func (s *Spec) Classes() map[string]bool {
	out := map[string]bool{}
	add := func(name string) {
		name, _, _ = strings.Cut(name, "#")
		parts := strings.Split(name, ".")
		for i := len(parts); i >= 2; i-- {
			last := parts[i-1]
			if last != "" && last[0] >= 'A' && last[0] <= 'Z' {
				out[strings.Join(parts[:i], ".")] = true
				return
			}
		}
	}
	for _, k := range s.Sinks {
		for _, list := range [][]string{k.CallsRaw, k.ShellRaw, k.MethodsRaw} {
			for _, n := range list {
				add(n)
			}
		}
		if k.WeakAlgorithms != nil {
			for _, n := range k.WeakAlgorithms.Calls {
				add(n)
			}
		}
	}
	for _, n := range s.Sources.Calls {
		add(n)
	}
	for _, z := range s.Sanitizers {
		for _, n := range z.Calls {
			add(n)
		}
	}
	for k, v := range s.Returns {
		add(k)
		add(v + ".x")
	}
	for _, n := range append(append(append([]string{}, s.Weak.RandomCalls...), s.Weak.CookieFlagSetters...), s.TextCalls...) {
		add(n)
	}
	for _, st := range s.Weak.SecretStores {
		add(st)
	}
	return out
}

// Sanitizes returns the kinds a call to the resolved callee name makes safe.
func (s *Spec) Sanitizes(name string) Kind { return s.sanitizeCall[name] }

// SanitizesMethod returns the kinds a method of that name makes safe.
func (s *Spec) SanitizesMethod(name string) Kind { return s.sanitizeMethod[name] }

// Step is one point on the way from a source to a sink.
type Step struct {
	Line int    `json:"line"`
	What string `json:"what"`
	// File is set on a step in another file than the finding's.
	File string `json:"file,omitempty"`
}

// Trace is a source and the steps that carried its data, newest first. A
// trace is immutable and shared between values.
type Trace struct {
	Step
	Prev *Trace
	// Library is set when the source is a parameter of an exported
	// function rather than client input.
	Library bool
	// Param marks a placeholder source, parameter Param-1 of a function
	// being summarized; it never reaches a finding.
	Param int
	n     int
}

// NewMarker starts the placeholder trace of parameter i of a function
// being summarized.
func NewMarker(line, i int) *Trace {
	return &Trace{Step: Step{Line: line, What: "parameter"}, Param: i + 1, n: 1}
}

// Root returns the source of the trace.
func (t *Trace) Root() *Trace {
	for t != nil && t.Prev != nil {
		t = t.Prev
	}
	return t
}

// maxTrace bounds the steps kept per trace.
const maxTrace = 16

// NewSource starts a trace.
func NewSource(line int, what string, library bool) *Trace {
	return &Trace{Step: Step{Line: line, What: what}, Library: library, n: 1}
}

// Add returns t extended by a step; t itself is unchanged. Steps on the line
// of the previous one replace nothing but are skipped when identical.
func (t *Trace) Add(line int, what string) *Trace {
	return t.AddStep(Step{Line: line, What: what})
}

// AddStep is Add for a step that may be in another file.
func (t *Trace) AddStep(s Step) *Trace {
	if t == nil {
		return nil
	}
	if t.Step == s || t.n >= maxTrace {
		return t
	}
	return &Trace{Step: s, Prev: t, Library: t.Library, Param: t.Param, n: t.n + 1}
}

// FromSteps builds a trace from its steps, source first.
func FromSteps(steps []Step, library bool) *Trace {
	var t *Trace
	for _, s := range steps {
		if t == nil {
			t = &Trace{Step: s, Library: library, n: 1}
			continue
		}
		t = t.AddStep(s)
	}
	return t
}

// Steps returns the trace from source to the newest step.
func (t *Trace) Steps() []Step {
	var out []Step
	for c := t; c != nil; c = c.Prev {
		out = append(out, c.Step)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Finding is a source-to-sink flow.
type Finding struct {
	Sink    *Sink
	File    string
	Line    int // the sink
	EndLine int
	Steps   []Step
	Library bool
}
