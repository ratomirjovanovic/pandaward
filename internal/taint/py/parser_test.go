package py

import (
	"strings"
	"testing"
)

func parse(t *testing.T, src string) *File {
	t.Helper()
	f := Parse("t.py", src)
	if len(f.Errors) > 0 {
		t.Fatalf("errors parsing %q: %v", src, f.Errors)
	}
	return f
}

func TestExpressions(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"a + b * c ** -d", "(+ a (* b (** c (- d))))"},
		{"a or b and not c", "(or a (and b (not c)))"},
		{"a < b <= c is not d not in e", "(cmp a < b <= c is not d not in e)"},
		{"x if c else y if d else z", "(if c x (if d y z))"},
		{"lambda x, *a, k=1, **kw: x + k", "(lambda (x *a k=1 **kw) (+ x k))"},
		{"f(a, *b, k=c, **d)(e)[1:2, ::3, x]", "f(a *b k=c **d)(e)[(tuple 1:2 _:_:3 x)]"},
		{"obj.attr.call()", "obj.attr.call()"},
		{"(a % b).encode('u')", "(% a b).encode(\"u\")"},
		{"[x * 2 for x in xs if x if y]", "(listcomp (* x 2) for x in xs if x if y)"},
		{"{k: v for k, v in d.items()}", "(dictcomp k:v for (tuple k v) in d.items())"},
		{"{*a, b}", "(set *a b)"},
		{"{**a, 'k': 1}", "{**a \"k\":1}"},
		{"sum(x for x in y)", "sum((gencomp x for x in y))"},
		{"(y := f(x)) and y", "(and (:= y f(x)) y)"},
		{"await a.b()", "(await a.b())"},
		{"a[b][c].d(e)", "a[b][c].d(e)"},
		{"-x ** 2", "(- (** x 2))"},
		{"a | b ^ c & d << e", "(| a (^ b (& c (<< d e))))"},
		{"'a' 'b' \"c\"", "\"abc\""},
		{"b'\\x00' b'z'", "b\"\\x00z\""},
		{"r'\\d+' '\\n'", "\"\\\\d+\\n\""},
		{"...", "..."},
		{"x[1:]", "x[1:_]"},
	} {
		f := parse(t, c.src+"\n")
		got := Dump(f.Body[0])
		if got != c.want {
			t.Errorf("%s\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

func TestFStrings(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`f"a{b}c"`, `(f "a" {b} "c")`},
		{`f"{x!r:>{width}}"`, `(f {x!r:(f ">" {width})})`},
		{`f"{x=}"`, `(f {x})`},
		{`f"{d['key']}"`, `(f {d["key"]})`},
		{`f"{'nested' + f"{y}"}"`, `(f {(+ "nested" (f {y}))})`},
		{`f"{{literal}}"`, `(f "{literal}")`},
		{`f"{a:#x} {b:%Y-%m}"`, `(f {a:(f "#x")} " " {b:(f "%Y-%m")})`},
		{`rf"\d{n}\{{"`, `(f "\\d" {n} "\\{")`},
		{`"pre " f"{x}"`, `(f "pre " {x})`},
		{"f'''multi\n{x}\nline'''", `(f "multi\n" {x} "\nline")`},
	} {
		f := parse(t, c.src+"\n")
		got := Dump(f.Body[0])
		if got != c.want {
			t.Errorf("%s\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

func TestStatements(t *testing.T) {
	src := `import os.path as p, sys
from ..pkg import (a as b,
    c)
from . import *
x: int = 1
y = z = f()
y += 1
a, *b = c
del a[0], b.c
assert x, "msg"
global g
@dec(1)
@other
async def fn[T: int](a, /, b: str = "s", *args, c, d=2, **kw) -> list[T]:
    return a
class C[T](Base, metaclass=M):
    def m(self): pass
for i, (j, k) in enumerate(xs):
    continue
else:
    pass
while x:
    break
if a:
    pass
elif b:
    pass
else:
    pass
try:
    pass
except (A, B) as e:
    raise X from e
except* C:
    pass
else:
    pass
finally:
    pass
with open(f) as fh, lock:
    pass
with (open(a) as x, open(b) as y):
    pass
async with s as t:
    pass
type Alias[T] = list[T]
`
	f := parse(t, src)
	want := strings.Join([]string{
		`import os.path as p sys`,
		`from ..pkg import a as b c`,
		`from . import *`,
		`x: int = 1`,
		`y = z = f()`,
		`y += 1`,
		`(tuple a *b) = c`,
		`del a[0] b.c`,
		`assert x, "msg"`,
		`global g`,
		`@dec(1) @other async def fn(a / b:str="s" *args c d=2 **kw) -> list[T] {return a}`,
		`class C(Base metaclass=M) {def m(self) {pass}}`,
		`for (tuple i (tuple j k)) in enumerate(xs) {continue} else {pass}`,
		`while x {break}`,
		`if a {pass} else {if b {pass} else {pass}}`,
		`try {pass} except (tuple A B) as e {raise X from e} except* C {pass} else {pass} finally {pass}`,
		`with open(f) as fh, lock {pass}`,
		`with open(a) as x, open(b) as y {pass}`,
		`async with s as t {pass}`,
		`type Alias = list[T]`,
	}, "\n")
	if got := DumpBody(f.Body); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestMatch(t *testing.T) {
	src := `match command.split():
    case [action]:
        pass
    case ["go", direction] | ["move", direction]:
        pass
    case Point(x=0, y=0) as origin if origin:
        pass
    case {"type": "a" | "b" as kind, **rest}:
        pass
    case Color.RED | -1 | 1.5j:
        pass
    case [first, *others]:
        pass
    case Doc(value=str() as text) if (
        text
    ):
        pass
    case _:
        pass
match = {"soft": "keyword"}
match(x)
match[x] = 1
`
	f := parse(t, src)
	want := strings.Join([]string{
		`match command.split() case [action] {pass} case (| ["go" direction] ["move" direction]) {pass} case (as Point(x=0 y=0) origin) if origin {pass} case {"type":(as (| "a" "b") kind) **rest} {pass} case (| (| Color.RED (- 1)) 1.5j) {pass} case [first *others] {pass} case Doc(value=(as str() text)) if text {pass} case _ {pass}`,
		`match = {"soft":"keyword"}`,
		`match(x)`,
		`match[x] = 1`,
	}, "\n")
	if got := DumpBody(f.Body); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestLexicalDetails(t *testing.T) {
	src := "x = (1 +\n     2)  # comment\ny = [\n  1,\n]\nz = 1 + \\\n    2\n\n\nif x:\n\n    # only a comment\n    pass\n\tpass_tab = 1\n"
	f := Parse("t.py", src)
	if len(f.Body) < 4 {
		t.Fatalf("statements: %s", DumpBody(f.Body))
	}
	if got := Dump(f.Body[0]); got != "x = (+ 1 2)" {
		t.Errorf("implicit line join: %s", got)
	}
	if got := Dump(f.Body[2]); got != "z = (+ 1 2)" {
		t.Errorf("backslash continuation: %s", got)
	}
	// A BOM and CRLF line ends.
	g := parse(t, bom+"a = 1\r\nb = 'x'\r\n")
	if got := DumpBody(g.Body); got != "a = 1\nb = \"x\"" {
		t.Errorf("bom and crlf: %s", got)
	}
}

func TestPositions(t *testing.T) {
	f := parse(t, "def f():\n    return obj.method(arg)\n")
	ret := f.Body[0].(*FuncDef).Body[0].(*Return)
	call := ret.X.(*Call)
	if call.Pos != (Pos{2, 12}) || call.Args[0].Value.At() != (Pos{2, 23}) {
		t.Errorf("positions: call %v, arg %v", call.Pos, call.Args[0].Value.At())
	}
	g := parse(t, "s = f'abc {name} def'\n")
	fv := g.Body[0].(*Assign).Value.(*FString).Parts[1].(*FormattedValue)
	if fv.Value.At() != (Pos{1, 12}) {
		t.Errorf("f-string field position: %v", fv.Value.At())
	}
}

// A syntax error loses only the broken statement; the rest of the file,
// including the block after it, still parses.
func TestRecovery(t *testing.T) {
	src := `import os
x = = 1
def ok():
    return 1
def broken(:
    y = 2
z = os.system(cmd)
print "py2"
w = 3
`
	f := Parse("t.py", src)
	if len(f.Errors) == 0 {
		t.Fatal("no errors reported")
	}
	got := DumpBody(f.Body)
	for _, want := range []string{"import os", "def ok() {return 1}", "z = os.system(cmd)", "w = 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("lost %q after recovery:\n%s", want, got)
		}
	}
	if strings.Count(got, "BAD") != 3 {
		t.Errorf("want 3 bad statements:\n%s", got)
	}
}

// A bracket left open ends at the next statement, but a keyword argument
// at the indentation of the call's line does not close it.
func TestUnclosedBracket(t *testing.T) {
	f := Parse("t.py", "x = foo(1,\ny = 2\n")
	if len(f.Errors) == 0 || !strings.Contains(f.Errors[0].Msg, "never closed") {
		t.Errorf("want a never closed error first, got %v", f.Errors)
	}
	if got := DumpBody(f.Body); !strings.Contains(got, "y = 2") {
		t.Errorf("lost the next statement:\n%s", got)
	}
	for _, src := range []string{
		"def f():\n    write(\n        '''\nx''',\n    a=1)\n",
		"def f():\n    g(\n    a=1,\n    b=2,\n    )\n",
	} {
		if f := Parse("t.py", src); len(f.Errors) != 0 {
			t.Errorf("%q: %v", src, f.Errors)
		}
	}
}

// Nothing a file holds makes the parser loop or panic.
func TestNoPanics(t *testing.T) {
	for _, src := range []string{
		"", "\n\n", "(", ")", "[[[", "}}}", "f'{", "f'{x", "'''", "if", "if x", "if x:", "def", "class C(", "match x:", "case 1:",
		"\tx = 1", "  \n\t\n", "x = (\n", "@", "@x", "async", "lambda", "a[", "a.", "1 +", "f(**)", "from", "from . import",
		"with (a as b", "try:\n pass", "x = f'{a!}'", "x = f'{:}'", "\\", "a = 1 \\", "u'\\N{DASH'",
	} {
		_ = Parse("t.py", src)
	}
}

// FuzzParse checks that no input makes the parser panic or loop.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"x = f'{a!r:>{w}}' + b'\x00'\n",
		"match p:\n case {'k': [1, *r]} | C(a=b) as z if z:\n  pass\n",
		"@d\nasync def f[T](a, /, *b, c=1, **d) -> T:\n    return (yield from g)\n",
		"with (a as b, c):\n    try:\n        pass\n    except* E as e:\n        raise\n",
		"x = [i async for i in y if i]\ntype A[T] = dict[str, T]\n",
		"def f(:\n    y = 2\nz = (\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		file := Parse("fuzz.py", src)
		for _, s := range file.Body {
			Inspect(s, func(Node) bool { return true })
			_ = Dump(s)
		}
	})
}
