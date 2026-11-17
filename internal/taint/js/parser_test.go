package js

import (
	"strings"
	"testing"
)

var jsOpt = Options{JSX: true}
var tsOpt = Options{TS: true}
var tsxOpt = Options{TS: true, JSX: true}

func check(t *testing.T, opt Options, src, want string) {
	t.Helper()
	f := Parse("t", src, opt)
	if len(f.Errors) > 0 {
		t.Errorf("%q: errors %v", src, f.Errors)
	}
	if got := Dump(f.Stmts); got != want {
		t.Errorf("%q\n got: %s\nwant: %s", src, got, want)
	}
}

func TestExpressions(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"a + b * c", "(+ a (* b c));"},
		{"a ** b ** c", "(** a (** b c));"},
		{"a = b = c", "(= a (= b c));"},
		{"a ?? b ?? c", "(?? (?? a b) c);"},
		{"x = a ? b : c ? d : e", "(= x (? a b (? c d e)));"},
		{"a.b[c].d(e, ...f)", "(call (. (.[] (. a b) c) d) e ...f);"},
		{"a?.b?.[c]?.(d)", "(call? (?.[] (?. a b) c) d);"},
		{"new Foo(1).bar", "(. (new Foo 1) bar);"},
		{"new Foo", "(new Foo);"},
		{"new a.b.C()", "(new (. (. a b) C));"},
		{"new.target", "new.target;"},
		{"x++ + ++y", "(+ (post++ x) (++ y));"},
		{"typeof x === 'string'", "(=== (typeof x) \"string\");"},
		{"delete o[k], void 0", "(, (delete (.[] o k)) (void 0));"},
		{"`a${b}c${d + 1}`", "(tpl \"a\" b \"c\" (+ d 1) \"\");"},
		{"tag`x${y}`", "(tpl tag=tag \"x\" y \"\");"},
		{"`outer ${`inner ${x}`}`", "(tpl \"outer \" (tpl \"inner \" x \"\") \"\");"},
		{"x = /ab+c/gi.test(s)", "(= x (call (. /ab+c/gi test) s));"},
		{"a / b / c", "(/ (/ a b) c);"},
		{"x = y / 2 / z", "(= x (/ (/ y 2) z));"},
		{"[1, , ...a]", "[1 _ ...a];"},
		{"({a, b: c, [k]: v, ...s, m() {}, get g() { return 1 }, 'q': 2})", "{a, b:c, [k]:v, ...s, method m:(fn m () {}), get g:(fn g () {(return 1)}), q:2};"},
		{"x => x + 1", "(=> (x) (+ x 1));"},
		{"(a, b) => { return a }", "(=> (a b) {(return a)});"},
		{"async (a) => await a", "(=> async (a) (await a));"},
		{"async x => x", "(=> async (x) x);"},
		{"({a = 1, b: {c}}) => c", "(=> ({(= a 1), b:{c}}) c);"},
		{"([a, b = 2], ...rest) => a", "(=> ([a (= b 2)] ...rest) a);"},
		{"(a)", "a;"},
		{"(a, b)", "(, a b);"},
		{"f(function () {}, function* g() { yield 1 })", "(call f (fn () {}) (fn * g () {(yield 1);}));"},
		{"async function f() { await g(); for await (const x of y) {} }", "(fn async f () {(await (call g)); (for (const x) of y {})})"},
		{"class A extends B { constructor(x) { super(x) } static s = 1; #p = 2; get v() { return this.#p } static { init() } }",
			"(class A extends B (constructor constructor (fn constructor (x) {(call super x);})) (static field s 1) (field #p 2) (get v (fn v () {(return (. this #p))})) (static block {(call init);}))"},
		{"x = class {}", "(= x (class));"},
		{"a in b", "(in a b);"},
		{"a instanceof B", "(instanceof a B);"},
		{"import('x').then(m => m)", "(call (. (call import \"x\") then) (=> (m) m));"},
		{"import.meta.url", "(. (. import meta) url);"},
		{"a?.5:1", "(? a .5 1);"},
		{"x = y\n(z)", "(= x (call y z));"},
		{"let x = 1\nlet y = 2", "(let x=1) (let y=2)"},
		{"a\n++b", "a; (++ b);"},
		{"o = {if: 1, class: 2}; o.if; o.class", "(= o {if:1, class:2}); (. o if); (. o class);"},
		{"x = a < b > c", "(= x (> (< a b) c));"},
		{"label: for (;;) { break label; continue label }", "(label label (for _ _ _ {(break label) (continue label)}))"},
		{"yield = 1; await = 2", "(= yield 1); (= await 2);"},
	} {
		check(t, jsOpt, c.src, c.want)
	}
}

func TestStatements(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"var a = 1, b; let [c] = d; const {e, f: g} = h", "(var a=1 b) (let [c]=d) (const {e, f:g}=h)"},
		{"if (a) b(); else if (c) d(); else { e() }", "(if a (call b); else (if c (call d); else {(call e);}))"},
		{"for (let i = 0; i < n; i++) s += i", "(for (let i=0) (< i n) (post++ i) (+= s i);)"},
		{"for (const k in o) {}", "(for (const k) in o {})"},
		{"for (x of xs) f(x)", "(for x; of xs (call f x);)"},
		{"for (var i = 0, n = a.length; i < n; ++i);", "(for (var i=0 n=(. a length)) (< i n) (++ i) ;)"},
		{"for (('x' in o) ? a : b;;) break", "(for (? (in \"x\" o) a b); _ _ (break))"},
		{"while (x) x--; do { y() } while (z)", "(while x (post-- x);) (do {(call y);} z)"},
		{"try { a() } catch (e) { b(e) } finally { c() }", "(try {(call a);} catch e {(call b e);} finally {(call c);})"},
		{"try {} catch { }", "(try {} catch _ {})"},
		{"switch (x) { case 1: a(); break; default: b() }", "(switch x (case 1 (call a); (break)) (case _ (call b);))"},
		{"throw new Error(m)", "(throw (new Error m))"},
		{"function f(a, b = 1, ...c) { return }", "(fn f (a (= b 1) ...c) {(return)})"},
		{"return\nx", "(return) x;"},
		{"import a, {b as c, d} from 'm'; import * as ns from 'n'; import 'side'", "(import \"m\" default:a b:c d:d) (import \"n\" *:ns) (import \"side\" )"},
		{"export default function () {}; export const x = 1; export { a as b, c }; export * from 'm'; export * as ns from 'n'; export { d } from 'o'",
			"(export default (fn () {})) ; (export (const x=1)) (export a:b c:c) (export * from \"m\") (export * *:ns from \"n\") (export d:d from \"o\")"},
		{"export default class A {}", "(export default (class A))"},
		{"export default async function f() {}", "(export default (fn async f () {}))"},
		{"export default {a: 1}", "(export default {a:1})"},
		{"module.exports = function (req, res) { res.send(req.query.q) }", "(= (. module exports) (fn (req res) {(call (. res send) (. (. req query) q));}));"},
		{"#!/usr/bin/env node\nrun()", "(call run);"},
		{"debugger;", ";"},
		{"let\nx = 1", "(let x=1)"},
		{"let = 1", "(= let 1);"},
	} {
		check(t, jsOpt, c.src, c.want)
	}
}

func TestTypeScript(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"let x: number = 1", "(let x=1)"},
		{"const m: Map<string, Array<number>> = new Map()", "(const m=(new Map))"},
		{"function f<T extends object>(a: T, b?: string): Promise<T[]> { return g<T>(a) }", "(fn f (a b) {(return (call g a))})"},
		{"const f = async <T,>(x: T): Promise<void> => {}", "(const f=(=> async (x) {}))"},
		{"const g = (x: number): x is 1 => x === 1", "(const g=(=> (x) (=== x 1)))"},
		{"interface A extends B<C> { a: string; b(): void }", ";"},
		{"type U = A | B & { c: D[] } | ((x: E) => F) | `p${string}`", ";"},
		{"type C<T> = T extends string ? 'a' : T extends infer U ? U[] : never", ";"},
		{"enum E { A = 1, B }", ";"},
		{"declare const x: number;", ";"},
		{"declare module 'm' { export const y: string }", ";"},
		{"namespace N { export const z = 1 }", "{(export (const z=1))}"},
		{"x as unknown as string", "x;"},
		{"(x satisfies Y).z", "(. x z);"},
		{"a!.b!", "(. a b);"},
		{"<string>x", "x;"},
		{"class A<T> implements I, J<T> { private x: number = 1; constructor(private readonly svc: Svc, public y?: string) { super() } abstract m(): void; [k: string]: any; static override z?: T }",
			"(class A (field x 1) (constructor constructor (fn constructor (svc y) {(call super);}) props=svc,y) (method m (fn m () nobody)) (static field z _))"},
		{"abstract class B { protected abstract f(): void }", "(class B (method f (fn f () nobody)))"},
		{"function over(a: string): void;\nfunction over(a: any) {}", "(fn over (a) nobody) (fn over (a) {})"},
		{"import type { A } from 'a'; import { type B, C } from 'b'; export type { D }", "(import \"a\" A:A) (import \"b\" B:B C:C) (export D:D)"},
		{"import fs = require('fs')", "(const fs=(call require \"fs\"))"},
		{"export = foo", "(export default foo)"},
		{"let v = obj as const", "(let v=obj)"},
		{"const t: [a: string, b?: number] = x", "(const t=x)"},
		{"let fn: (a: number) => void, y = 2", "(let fn y=2)"},
		{"let k: keyof typeof obj", "(let k)"},
		{"f<string>(x); a < b; c<d>e", "(call f x); (< a b); (> (< c d) e);"},
		{"let x!: string", "(let x)"},
		{"c = (e.target as Element)?.closest?.<HTMLElement>('[x]')", "(= c (call? (?. (. e target) closest) \"[x]\"));"},
		{"for (const [k, v] of Object.entries(o) as [string, number][]) {}", "(for (const [k v]) of (call (. Object entries) o) {})"},
		{"@Injectable() class S { @Input() name: string; m(@Inject(T) t: T) {} }", "(class S (field name _) (method m (fn m (t) {})))"},
		{"const x = <T,>(a: T) => a", "(const x=(=> (a) a))"},
		{"function assertIsString(val: any): asserts val is string {}", "(fn assertIsString (val) {})"},
		{"let a: Array<Array<number>>= []", "(let a=[])"},
	} {
		opt := tsOpt
		if strings.Contains(c.src, "<T,>") {
			opt = tsxOpt
		}
		check(t, opt, c.src, c.want)
	}
}

func TestJSX(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"x = <div className=\"a\" id={b}>hi {name}!</div>", "(= x <div className=\"a\" id=b>hiname!</>);"},
		{"x = <A.B {...props} on-click={() => f()} disabled />", "(= x <A.B {...props} on-click=(=> () (call f)) disabled></>);"},
		{"x = <><Item key={1} /><Item /></>", "(= x <><Item key=1></><Item></></>);"},
		{"x = <div dangerouslySetInnerHTML={{__html: html}} />", "(= x <div dangerouslySetInnerHTML={__html:html}></>);"},
		{"x = <p>{a ? <b>{c}</b> : null}{/* note */}</p>", "(= x <p>(? a <b>c</> null)</>);"},
		{"const C = () => <div>it's {`t${x}`}</div>", "(const C=(=> () <div>it's(tpl \"t\" x \"\")</>))"},
		{"x = <a href='b\\c'>d</a>", "(= x <a href=\"b\\\\c\">d</>);"},
	} {
		check(t, jsOpt, c.src, c.want)
	}
	check(t, tsxOpt, "const el = <Foo<string> value={v as string} />", "(const el=<Foo value=v></>)")
	// > ends a JSX tag even when text starts with = or >.
	check(t, tsxOpt, `x = <B v="o">= {n}</B>`, `(= x <B v="o">=n</>);`)
	check(t, jsOpt, `x = <i>>> {n}</i>`, `(= x <i>>>n</>);`)
}

// Errors cost the broken statement, not the file.
func TestRecovery(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"a();\nb(;\nc();", "(call a); BAD; (call c);"},
		{"function f() {\n  x = ;\n  y();\n}\nz();", "(fn f () {BAD; (call y);}) (call z);"},
		{"(function () {\n  var a = %;\n  exports.f = function (q) { run(q) };\n})();", "(call (fn () {BAD; (= (. exports f) (fn (q) {(call run q);}));}));"},
		{"x = `a${ ) }b`; y()", "BAD; (call y);"},
		{"if (a) { b(}\nc()", "(if a {BAD; (call c);})"},
		{"class A { m() { @@ } n() {} }", "(class A (method m (fn m () {BAD;})) (method n (fn n () {})))"},
		{"x = {a: 1,, b: 2}\ny()", "BAD; (call y);"},
	} {
		f := Parse("t", c.src, jsOpt)
		if len(f.Errors) == 0 {
			t.Errorf("%q: no error reported", c.src)
		}
		if got := Dump(f.Stmts); got != c.want {
			t.Errorf("%q\n got: %s\nwant: %s", c.src, got, c.want)
		}
	}
}

func TestLines(t *testing.T) {
	f := Parse("t", "a()\n\n/* c\n c */ b()\n`x\ny`; z()", jsOpt)
	var lines []int
	for _, s := range f.Stmts {
		lines = append(lines, s.Ln())
	}
	if len(lines) != 3 || lines[0] != 1 || lines[1] != 4 || lines[2] != 6 {
		t.Fatalf("lines %v", lines)
	}
}

func TestStrings(t *testing.T) {
	check(t, jsOpt, `x = "a\nb\x41B\u{43}\'"`, `(= x "a\nbABC'");`)
	check(t, jsOpt, "x = 'unterminated\ny()", "(= x \"unterminated\"); (call y);")
	check(t, jsOpt, "x = 0x1F + 1_000n + 1e-3 + .5", "(= x (+ (+ (+ 0x1F 1_000n) 1e-3) .5));")
	check(t, jsOpt, "été = 1", "(= été 1);")
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"a(b)", "x = `${y}`", "<div>{a}</div>", "let x: T<U> = 1", "/re/.test(s)", "class A { #x; static {} }", "for (;;) {}", "({a, ...b} = c)"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		for _, opt := range []Options{jsOpt, tsOpt, tsxOpt} {
			Parse("f", src, opt)
		}
	})
}

// Deeply nested input is cut off, not a stack overflow.
func TestDeepNesting(t *testing.T) {
	src := strings.Repeat("(", 100000) + "x" + strings.Repeat(")", 100000) + ";\ny()"
	f := Parse("t", src, jsOpt)
	if len(f.Errors) == 0 {
		t.Fatal("no error for deep nesting")
	}
	if d := Dump(f.Stmts); !strings.HasSuffix(d, "(call y);") {
		t.Fatalf("statement after the deep one lost: %.80s", d)
	}
}

func BenchmarkParse(b *testing.B) {
	src := strings.Repeat("function f(a, b) {\n  const x = a.b.c(d, `t${e}`) + /re/g.test(s) ? [1, 2] : {k: v, ...w};\n  if (x) { return y => y * 2 } else for (let i = 0; i < n; i++) s += i;\n}\n", 2000)
	b.SetBytes(int64(len(src)))
	for i := 0; i < b.N; i++ {
		Parse("b.js", src, jsOpt)
	}
}
