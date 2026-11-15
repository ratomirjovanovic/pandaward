package flow

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/ir"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

// jsFlows analyzes one JavaScript file in library mode and returns
// "sink:line" for each flow.
func jsFlows(t *testing.T, src string) []string {
	t.Helper()
	spec, err := taint.Load("jsir")
	if err != nil {
		t.Fatal(err)
	}
	f := js.Parse("app.js", src, js.OptionsFor("app.js"))
	p := New(spec).NewProject(func(string) (*ir.Module, []string) { return nil, nil })
	p.Library = true
	var out []string
	for _, x := range p.AnalyzeOne(js.Lower(f, "app.js", nil), strings.Split(src, "\n")) {
		at := fmt.Sprintf("%s:%d", x.Sink.ID, x.Line)
		if x.EndLine > x.Line {
			at += fmt.Sprintf("-%d", x.EndLine)
		}
		out = append(out, at)
	}
	return out
}

// TestJSNestedExports checks that a function a module exports from inside
// the function it wraps itself in is analyzed as exported.
func TestJSNestedExports(t *testing.T) {
	src := `(function () {
  var exec = require('child_process').exec, findLoad;
  findLoad = exports.findLoad = function findLoad(arg, cb) {
    exec('wmic path ' + arg, cb);
  };
}());`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-command-injection:4" {
		t.Errorf("got %q", got)
	}
}

// TestJSMultiLineCall checks that a finding at a call covers the lines of
// its arguments.
func TestJSMultiLineCall(t *testing.T) {
	src := `const sh = require('execa').shell
module.exports = function (port) {
  return sh(
    'lsof -i tcp:' + port
  )
}`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-command-injection:3-4" {
		t.Errorf("got %q", got)
	}
}

// TestJSExportedObjectAndCallbackLists checks the functions of an object
// a module exports by name, and functions in a list passed to a call the
// engine does not see.
func TestJSExportedObjectAndCallbackLists(t *testing.T) {
	src := `var exec = require('child_process').exec
var series = require('contra').series
var stats = {
  ps: function (pid) { exec('ps -p ' + pid) },
  commit: function (msg) {
    series([function (done) { exec('git commit -m ' + msg, done) }])
  }
}
module.exports = stats`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-command-injection:4 taint.js-command-injection:6" {
		t.Errorf("got %q", got)
	}
}

// TestJSRequestByName checks parameters that hold the request by name, the
// path parameter of a helper that takes the request and the response, and
// the default import of a package.
func TestJSRequestByName(t *testing.T) {
	src := `import send from 'send'
var fs = require('fs')
module.exports = function (options) {
  return function (req, res, next) { fs.stat(req.url, next) }
}
export function serveStatic (req, res, path) {
  send(req, path).pipe(res)
}
function fetchIt (request) { fs.readFile(request.url) }`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-path-traversal:4 taint.js-path-traversal:7" {
		t.Errorf("got %q", got)
	}
}

// TestJSPathGuards checks the JavaScript checks that a path has no parent
// segments, and replace() calls that remove them.
func TestJSPathGuards(t *testing.T) {
	head := "var fs = require('fs')\nfunction serve (req, res, p) {\n"
	for _, c := range []struct{ body, want string }{
		{"  fs.readFile(p)\n", "taint.js-path-traversal:3"},
		{"  if (p.indexOf('..') !== -1) return\n  fs.readFile(p)\n", ""},
		{"  if (p.indexOf('..') === -1) fs.readFile(p)\n", ""},
		{"  if (-1 < p.indexOf('..')) return\n  fs.readFile(p)\n", ""},
		{"  if (p.indexOf('..') === -1) return\n  fs.readFile(p)\n", "taint.js-path-traversal:4"},
		{"  if (!p.includes('..')) fs.readFile(p)\n", ""},
		{`  if (/\.\./.test(p)) return` + "\n  fs.readFile(p)\n", ""},
		{`  fs.readFile(p.replace(/\.\.\//g, ''))` + "\n", ""},
	} {
		src := head + c.body + "}"
		if got := strings.Join(jsFlows(t, src), " "); got != c.want {
			t.Errorf("got %q, want %q\n%s", got, c.want, src)
		}
	}
}

// TestJSExportForms checks which functions count as exported: only the
// exports of a module, the ones a chain of assignments or a wrapper
// exports, the methods of an exported instance, and every function of a
// script that exports nothing.
func TestJSExportForms(t *testing.T) {
	head := "var exec = require('child_process').exec\n"
	for _, c := range []struct{ body, want string }{
		{"function run (a) { exec(a) }\nexports.ok = function () { run('ls') }", ""},
		{"function run (a) { exec(a) }\nexports = module.exports = run", "taint.js-command-injection:2"},
		{"function View (a) { exec(a) }\nexport default memo(View)", "taint.js-command-injection:2"},
		{"function run (a) { exec(a) }\nclass C { go (b) { run(b) } }\nmodule.exports = new C()", "taint.js-command-injection:2"},
		{"function run (a) { exec(a) }\nclass C { go () { run('ls') } }\nmodule.exports = new C()", ""},
	} {
		src := head + c.body
		if got := strings.Join(jsFlows(t, src), " "); got != c.want {
			t.Errorf("got %q, want %q\n%s", got, c.want, src)
		}
	}
	script := "function run (a) { document.write(a) }"
	if got := strings.Join(jsFlows(t, script), " "); got != "taint.js-xss:1" {
		t.Errorf("script: got %q", got)
	}
}

// TestJSInPlaceCallbacks checks that functions written in place as
// callbacks do not use up the call depth.
func TestJSInPlaceCallbacks(t *testing.T) {
	src := `var exec = require('child_process').exec
function one (x) { return new Promise(() => { process.nextTick(() => { two(x) }) }) }
function two (y) { return new Promise(() => { process.nextTick(() => { exec('ls ' + y) }) }) }
exports.one = one`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-command-injection:3" {
		t.Errorf("got %q", got)
	}
}

// TestJSRouteHandlers checks that the flows in a handler the module body
// registers are reported: loading the module analyzes its body, and the
// handler with it.
func TestJSRouteHandlers(t *testing.T) {
	cases := []struct{ src, want string }{
		{`var http = require('http');
var fs = require('fs');
http.createServer(function (req, res) {
  fs.readFile(req.url, function (e, d) { res.end(d); });
}).listen(80);`, "taint.js-path-traversal:4"},
		{`var express = require('express');
var app = express();
app.get('/', function (req, res) {
  eval(req.query.code);
});`, "taint.js-code-injection:4"},
	}
	for _, c := range cases {
		got := strings.Join(jsFlows(t, c.src), " ")
		if got != c.want {
			t.Errorf("got %q, want %q\n%s", got, c.want, c.src)
		}
	}
}
