package java

import (
	"strings"
	"testing"
)

func parse(t *testing.T, src string) *File {
	t.Helper()
	f := Parse("T.java", src)
	if len(f.Errors) > 0 {
		t.Fatalf("errors: %v", f.Errors)
	}
	return f
}

// Modern Java syntax parses: generics with >>, lambdas, method references,
// switch expressions and patterns, records, text blocks, annotations,
// anonymous and local classes, varargs and arrays.
func TestParseSyntax(t *testing.T) {
	src := `package a.b;
import java.util.*;
import static java.lang.Math.max;
@SuppressWarnings({"x", "y"})
public sealed class T<K extends Comparable<K>> extends Base implements I, J permits U {
    private final Map<String, List<Map<String, Integer>>> m = new HashMap<>();
    static int[] xs = {1, 2, 3}, ys[];
    @Override public <R> R f(@RequestParam("q") String q, int... rest) throws Exception {
        var r = switch (q) {
            case "a", "b" -> 1;
            case String s when s.isEmpty() -> { yield 2; }
            default -> 3;
        };
        Object o = q;
        if (o instanceof String str && !str.isBlank()) { r += str.length(); }
        Runnable run = () -> System.out.println(q);
        java.util.function.Function<String, Integer> len = String::length;
        int[][] grid = new int[3][];
        String block = """
            hello
              world
            """;
        List<String> l = new ArrayList<String>() {{ add("x"); }};
        label: for (int i = 0, j = 0; i < 10; i++, j--) { if (i > 2) break label; else continue; }
        for (String s : l) { try (var in = open(s); var out = open(s)) { out.write(in.read()); } catch (IOException | RuntimeException e) { throw e; } finally { } }
        record Point(int x, int y) {}
        int a = (int) (long) r >>> 2;
        boolean b = a < 2 && a > 1 ? true : false;
        return (R) (Object) q.<String>chars();
    }
    enum E { A(1), B(2) { void f() {} }; E(int v) {} }
    @interface Ann { String value() default ""; }
}
`
	f := parse(t, src)
	if f.Package != "a.b" || len(f.Imports) != 2 || len(f.Types) != 1 {
		t.Fatalf("unit %+v", f)
	}
	c := f.Types[0]
	if c.Name != "T" || len(c.Extends) != 1 || len(c.Implements) != 2 {
		t.Errorf("class %+v", c)
	}
	var m *Method
	for _, mm := range c.Members {
		if x, ok := mm.(*Method); ok && x.Name == "f" {
			m = x
		}
	}
	if m == nil || len(m.Params) != 2 || m.Params[0].Annotations[0].Name != "RequestParam" || !m.Params[1].Varargs {
		t.Fatalf("method %+v", m)
	}
}

// A broken statement or member is dropped; the rest of the file parses.
func TestRecovery(t *testing.T) {
	f := Parse("T.java", `class T {
    void a() { int x = ; y(); }
    void b( { }
    void c() { z(); }
}`)
	if len(f.Errors) == 0 {
		t.Fatal("no errors")
	}
	names := []string{}
	for _, m := range f.Types[0].Members {
		if x, ok := m.(*Method); ok {
			names = append(names, x.Name)
		}
	}
	if !strings.Contains(strings.Join(names, ","), "c") {
		t.Errorf("lost method c: %v", names)
	}
}

func TestNoPanics(t *testing.T) {
	for _, src := range []string{"", "class", "class T {", "class T { void f() {", "@", "x ->", "a<b<c>>", `"`, `"""`, "'", "/*", "class T { int x = (a)", "switch", "enum E { A(", "record R("} {
		_ = Parse("T.java", src)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"class T { void f() { int x = a < b ? c : d; } }", "record R(int a) { R { } }", "class T { List<List<String>> l; }"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		_ = Parse("T.java", src)
	})
}
