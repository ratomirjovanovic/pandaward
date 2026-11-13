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
type Kind uint16

const (
	Cmd Kind = 1 << iota
	Code
	Path
	SQL
	XSS
	SSRF
	Redirect
	All Kind = 1<<iota - 1
)

var kindByName = map[string]Kind{"cmd": Cmd, "code": Code, "path": Path, "sql": SQL, "xss": XSS, "ssrf": SSRF, "redirect": Redirect, "all": All}

// Spec is a parsed taint specification.
type Spec struct {
	Sources    Sources
	Sinks      []*Sink
	Sanitizers []Sanitizer
	// sanitizer kinds by callee name
	sanitizeCall map[string]Kind
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
	} `yaml:"handlers"`
	Globals           []string `yaml:"globals"`
	LibraryParameters bool     `yaml:"library_parameters"`
}

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
	// RequestOnly sinks are reported only for request sources, not for
	// library parameters: a library that fetches the URL it is given is
	// doing its job.
	RequestOnly bool `yaml:"request_only"`

	Calls          map[string]Target `yaml:"-"`
	CallsWithShell map[string]Target `yaml:"-"`
	Methods        map[string]Target `yaml:"-"`
}

// Sanitizer makes values safe for some kinds.
type Sanitizer struct {
	KindsRaw []string `yaml:"kinds"`
	Calls    []string `yaml:"calls"`
}

type specFile struct {
	Sources    Sources     `yaml:"sources"`
	Sinks      []*Sink     `yaml:"sinks"`
	Sanitizers []Sanitizer `yaml:"sanitizers"`
}

func parseTarget(s string) (Target, error) {
	name, arg, ok := strings.Cut(s, "#")
	t := Target{Name: name}
	if !ok {
		return t, nil
	}
	if arg == "*" {
		t.Arg = -1
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
	s := &Spec{Sources: f.Sources, Sinks: f.Sinks, Sanitizers: f.Sanitizers, sanitizeCall: map[string]Kind{}}
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

// Sanitizes returns the kinds a call to the resolved callee name makes safe.
func (s *Spec) Sanitizes(name string) Kind { return s.sanitizeCall[name] }

// Step is one point on the way from a source to a sink.
type Step struct {
	Line int    `json:"line"`
	What string `json:"what"`
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
	return &Trace{Step: Step{line, "parameter"}, Param: i + 1, n: 1}
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
	return &Trace{Step: Step{line, what}, Library: library, n: 1}
}

// Add returns t extended by a step; t itself is unchanged. Steps on the line
// of the previous one replace nothing but are skipped when identical.
func (t *Trace) Add(line int, what string) *Trace {
	if t == nil {
		return nil
	}
	if t.Line == line && t.What == what || t.n >= maxTrace {
		return t
	}
	return &Trace{Step: Step{line, what}, Prev: t, Library: t.Library, Param: t.Param, n: t.n + 1}
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
