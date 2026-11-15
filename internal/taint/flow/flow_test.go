package flow

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/py"
)

func analyze(t *testing.T, src string) []taint.Finding {
	t.Helper()
	spec, err := taint.Load("python")
	if err != nil {
		t.Fatal(err)
	}
	src = strings.ReplaceAll(src, "\t", "    ")
	f := py.Parse("app.py", src)
	if len(f.Errors) > 0 {
		t.Fatalf("parse: %v", f.Errors)
	}
	return New(spec).Analyze(py.Lower(f, "app", false), strings.Split(src, "\n"))
}

// sinks returns "id:line" for each finding.
func sinks(fs []taint.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, strings.TrimPrefix(f.Sink.ID, "taint.py-")+":"+itoa(f.Line))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

const header = `from flask import Flask, request, redirect, session, make_response
import os, subprocess, pickle, yaml, pathlib, configparser, urllib.parse
app = Flask(__name__)
`

// Each case is a handler body after the header and a route decorator
// (line 6 is the first line of the body) and the findings it must give.
func TestFlows(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
	}{
		{"direct", `	x = request.args.get("x")
	os.system("echo " + x)`, []string{"command-injection:7"}},
		{"constant", `	os.system("echo hi")`, nil},
		{"shell only with shell=True", `	x = request.args.get("x")
	subprocess.run(["echo", x])
	subprocess.run(x, shell=True)`, []string{"command-injection:8"}},
		{"sh -c list", `	x = request.form["x"]
	subprocess.run(["sh", "-c", "echo " + x])`, []string{"command-injection:7"}},
		{"branch folded", `	x = request.args.get("x")
	num = 106
	bar = "safe" if 7 * 18 + num > 200 else x
	os.system(bar)`, nil},
		{"branch not folded", `	x = request.args.get("x")
	bar = "safe" if len(x) > 2 else x
	os.system(bar)`, []string{"command-injection:8"}},
		{"match on constant", `	x = request.args.get("x")
	guess = "ABC"[1]
	match guess:
		case "A":
			bar = x
		case "B":
			bar = "bob"
		case _:
			bar = x
	eval(bar)`, nil},
		{"dict keys", `	x = request.args.get("x")
	m = {}
	m["a"] = "safe"
	m["b"] = x
	eval(m["a"])
	eval(m["b"])`, []string{"code-injection:11"}},
		{"list pop", `	x = request.args.get("x")
	lst = []
	lst.append("safe")
	lst.append(x)
	lst.append("more")
	lst.pop(0)
	eval(lst[1])
	eval(lst[0])`, []string{"code-injection:13"}},
		{"configparser keys", `	x = request.args.get("x")
	conf = configparser.ConfigParser()
	conf.add_section("s")
	conf.set("s", "a", "safe")
	conf.set("s", "b", x)
	eval(conf.get("s", "a"))
	eval(conf.get("s", "b"))`, []string{"code-injection:12"}},
		{"loop fixpoint", `	x = request.args.get("x")
	acc = ""
	for i in range(3):
		acc = acc + x
	os.system(acc)`, []string{"command-injection:10"}},
		{"dotdot guard", `	x = request.args.get("x")
	if '..' in x:
		return "no"
	open(x)`, nil},
		{"guard on the wrong branch", `	x = request.args.get("x")
	if '..' not in x:
		return "no"
	open(x)`, []string{"path-traversal:9"}},
		{"resolve and startswith", `	x = request.args.get("x")
	base = pathlib.Path("/srv")
	p = (base / x).resolve()
	if not str(p).startswith(str(base)):
		return "no"
	p.read_text()`, nil},
		{"startswith without resolve", `	x = request.args.get("x")
	base = pathlib.Path("/srv")
	p = base / x
	if not str(p).startswith(str(base)):
		return "no"
	p.read_text()`, []string{"path-traversal:11"}},
		{"quoted literal guard", `	x = request.args.get("x")
	if not x.startswith("'") or not x.endswith("'") or "'" in x[1:-1]:
		return "no"
	eval(x)`, nil},
		{"half a literal guard", `	x = request.args.get("x")
	if not x.startswith("'") or not x.endswith("'"):
		return "no"
	eval(x)`, []string{"code-injection:9"}},
		{"netloc allowlist", `	x = request.args.get("x")
	url = urllib.parse.urlparse(x)
	if url.netloc not in ["example.com"]:
		return "no"
	return redirect(x)`, nil},
		{"open redirect", `	x = request.args.get("next")
	return redirect(x)`, []string{"open-redirect:7"}},
		{"yaml safe loader", `	x = request.data
	yaml.load(x, Loader=yaml.SafeLoader)
	yaml.load(x, Loader=yaml.Loader)
	pickle.loads(x)`, []string{"deserialization:8", "deserialization:9"}},
		{"session store", `	x = request.args.get("x")
	session["user"] = x
	session["n"] = len(x)`, []string{"trust-boundary:7"}},
		{"html return", `	x = request.args.get("x")
	return f"<p>{x}</p>"`, []string{"xss:7"}},
		{"escaped return", `	import html
	x = request.args.get("x")
	return f"<p>{html.escape(x)}</p>"`, nil},
		{"header is not the body", `	x = request.args.get("x")
	return make_response(("ok", {"X-Value": x}))`, nil},
		{"plain text response", `	x = request.args.get("x")
	return make_response(x, mimetype="text/plain")`, nil},
		{"object from a helper", `	x = request.args.get("x")
	user = load_user(x)
	return jsonify_user(user)`, nil},
		{"sql text", `	import sqlite3
	x = request.args.get("x")
	cur = sqlite3.connect("db").cursor()
	cur.execute("SELECT * FROM t WHERE a = ?", (x,))
	cur.execute("SELECT * FROM t WHERE a = '" + x + "'")`, []string{"sql-injection:10"}},
		{"quote replaced", `	import lxml.etree
	x = request.args.get("x")
	root = lxml.etree.parse("f.xml")
	root.xpath("//u[@id='" + x.replace("'", "&apos;") + "']")
	root.xpath("//u[@id='" + x + "']")`, []string{"xpath-injection:10"}},
		{"int conversion", `	x = int(request.args.get("x"))
	os.system("kill " + str(x))`, nil},
	}
	for _, c := range cases {
		src := header + "@app.route('/x', methods=['POST'])\ndef handler():\n" + c.body + "\n"
		got := sinks(analyze(t, src))
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Path parameters of a route are sources unless their converter or
// annotation makes them numbers; a nested handler sees the module's
// imports.
func TestRouteParameters(t *testing.T) {
	src := `from flask import Flask
import os
def init(app):
    @app.route('/a/<name>/<int:n>')
    def a(name, n):
        os.system("echo " + str(n))
        os.system("echo " + name)
    return a
`
	got := sinks(analyze(t, src))
	if strings.Join(got, " ") != "command-injection:7" {
		t.Errorf("got %v", got)
	}
}

// XML parsed with external entities turned on is a sink only then.
func TestXXEFlag(t *testing.T) {
	src := header + `@app.route('/x', methods=['POST'])
def handler():
    import xml.dom.minidom, xml.sax, xml.sax.handler
    x = request.data
    safe = xml.sax.make_parser()
    xml.dom.minidom.parseString(x, safe)
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    xml.dom.minidom.parseString(x, parser)
`
	got := sinks(analyze(t, src))
	if strings.Join(got, " ") != "xxe:12" {
		t.Errorf("got %v", got)
	}
}

// A flow keeps its steps from source to sink.
func TestSteps(t *testing.T) {
	src := header + `@app.route('/x')
def handler():
    a = request.args.get("x")
    b = "echo " + a
    os.system(b)
`
	fs := analyze(t, src)
	if len(fs) != 1 {
		t.Fatalf("got %v", sinks(fs))
	}
	var lines []int
	for _, s := range fs[0].Steps {
		lines = append(lines, s.Line)
	}
	if len(lines) != 3 || lines[0] != 6 || lines[2] != 8 {
		t.Errorf("steps %v", fs[0].Steps)
	}
}
