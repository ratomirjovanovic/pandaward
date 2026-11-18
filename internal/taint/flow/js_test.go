package flow

import (
	"fmt"
	"sort"
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
	return jsFlowsIn(t, "app.js", src)
}

// jsFlowsIn is jsFlows for a file of the given name.
func jsFlowsIn(t *testing.T, name, src string) []string {
	t.Helper()
	spec, err := taint.Load("jsir")
	if err != nil {
		t.Fatal(err)
	}
	f := js.Parse(name, src, js.OptionsFor(name))
	p := New(spec).NewProject(func(string) (*ir.Module, []string) { return nil, nil })
	p.Library = true
	var out []string
	for _, x := range p.AnalyzeOne(js.Lower(f, name, nil), strings.Split(src, "\n")) {
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
	head := "var fs = require('fs'), path = require('path'), base = '/srv'\nfunction serve (req, res, p) {\n"
	for _, c := range []struct{ body, want string }{
		{"  fs.readFile(p)\n", "taint.js-path-traversal:3"},
		{"  if (p.search(/(\\/|^)\\.\\.(\\/|$)/) != -1) return\n  fs.readFile(p)\n", ""},
		{"  var f = path.resolve(path.join(base, p))\n  if (f.indexOf(base) != 0) return\n  fs.readFile(f)\n", ""},
		{"  var f = path.join(base, p)\n  if (f.indexOf(base) != 0) return\n  fs.readFile(f)\n", "taint.js-path-traversal:5"},
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
		// a program that imports and exports nothing has no API
		{"function run (a) { exec(a) }", ""},
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

// TestJSValueChecks checks the JavaScript checks that leave only safe
// values: anchored patterns of listed characters, lists of constants, and
// functions of the project that return such a check.
func TestJSValueChecks(t *testing.T) {
	head := "var exec = require('child_process').execSync\nvar Re = new RegExp('^[a-z0-9.-]+$')\nvar Loose = new RegExp('^([a-z]\\.)*[a-z]$')\nvar Types = ['A', 'MX']\nfunction ok (h) { return Re.test(h) }\nfunction loose (h) { return Loose.test(h) }\nexports.f = function (h) {\n"
	for _, c := range []struct{ check, want string }{
		{"", "taint.js-command-injection:9"},
		{"  if (!/^[a-z]+$/.test(h)) return\n", ""},
		{"  if (!ok(h)) return\n", ""},
		{"  if (Types.indexOf(h) === -1) return\n", ""},
		{"  if (!Types.includes(h)) return\n", ""},
		{"  if (!h.match(/^\\w+$/)) return\n", ""},
		// a dot in a string pattern is any character: a;ls x passes
		{"  if (!loose(h)) return\n", "taint.js-command-injection:9"},
		{"  if (!/^[a-z]+/.test(h)) return\n", "taint.js-command-injection:9"},
		{"  if (!/^[^;]+$/.test(h)) return\n", "taint.js-command-injection:9"},
		{"  if (!/^a|b$/.test(h)) return\n", "taint.js-command-injection:9"},
	} {
		body := c.check
		if body == "" {
			body = "  ;\n"
		}
		src := head + body + "  exec('host ' + h)\n}"
		if got := strings.Join(jsFlows(t, src), " "); got != c.want {
			t.Errorf("got %q, want %q\n%s", got, c.want, src)
		}
	}
}

// TestJSModuleGlobals checks that names the module body reads but never
// sets are globals, such as document in a browser script.
func TestJSModuleGlobals(t *testing.T) {
	src := "document.write(location.hash)\n"
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-xss:1" {
		t.Errorf("got %q", got)
	}
}

// TestJSClosures checks closures a library runs later (stored, not
// called), methods reached through this, and names of an enclosing scope
// a closure assigns on some paths only.
func TestJSClosures(t *testing.T) {
	src := `const proc = require('child_process').exec
class Tools {
  funcs (opts) {
    const scope = this
    const funcs = {}
    let cmd = false
    let list = opts.hosts
    Object.keys(opts.range).forEach(function blocks (block) {
      const range = opts.range[block]
      funcs[range] = function block (callback) {
        cmd = scope.command(opts, range)
        proc(cmd, callback)
      }
      if (block === '*') { list = [] }
      proc('ping ' + list.join(' '))
    })
    return funcs
  }
  command (opts, block) { return opts.nmap + ' ' + block }
}
module.exports = new Tools()`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-command-injection:12 taint.js-command-injection:15" {
		t.Errorf("got %q", got)
	}
}

// TestJSEvents checks listeners of socket messages and of events whose
// data another party chooses, and not of connection events.
func TestJSEvents(t *testing.T) {
	src := `var fs = require('fs')
socket.on('topic', function (data) { $('#t').html(data.topic) })
socket.on('connect', function (s) { $('#t').html(s) })
zip.on('entry', function (entry) { fs.createWriteStream(entry.path) })
emitter.on('done', function (x) { $('#t').html(x) })`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-path-traversal:4 taint.js-xss:2" {
		t.Errorf("got %q", got)
	}
}

// TestJSPrototypeMethods checks prototype methods of constructors
// assigned to a name and of classes inside a wrapper function, which a
// library's callers reach through its instances.
func TestJSPrototypeMethods(t *testing.T) {
	script := `Panel = function (ui) { this.ui = ui }
Panel.prototype.color = function (c) {
  var apply = function () { this.el.innerHTML = '<b>' + c + '</b>' }
  apply()
}`
	if got := strings.Join(jsFlows(t, script), " "); got != "taint.js-xss:3" {
		t.Errorf("script: got %q", got)
	}
	module := `module.exports = (function () {
  function Editor () {}
  Editor.prototype.setValue = function (val) { this.body.innerHTML = val }
  return Editor
})()`
	if got := strings.Join(jsFlows(t, module), " "); got != "taint.js-xss:3" {
		t.Errorf("module: got %q", got)
	}
}

// TestJSHypotheses checks that command line arguments are hypotheses:
// reported at a command, ignored by a path sink, and not hiding the
// request when a path is built from both.
func TestJSHypotheses(t *testing.T) {
	src := `var fs = require('fs'), path = require('path'), exec = require('child_process').exec
var dir = process.argv[2]
exec('ls ' + dir)
fs.readFile(dir)
require('http').createServer(function (req, res) {
  fs.readFile(path.join(dir, req.url))
})`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-command-injection:3 taint.js-path-traversal:6" {
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

// TestJSNextRoutes checks the route handlers of Next.js: a parameter typed
// Request is the request, a redirect to it is reported, and a page whose
// markup holds the request elsewhere is not an XSS.
func TestJSNextRoutes(t *testing.T) {
	src := `import { NextResponse } from "next/server"
export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url)
  const next = searchParams.get("next") ?? "/"
  return NextResponse.redirect(` + "`${origin}${next}`" + `)
}
export function POST(request: Request) {
  return NextResponse.redirect("/done")
}`
	if got := strings.Join(jsFlowsIn(t, "route.ts", src), " "); got != "taint.js-open-redirect:5" {
		t.Errorf("got %q", got)
	}
	// The host of the request's own URL and a path the code chose are not
	// a redirect to another site.
	safe := `import { NextResponse } from "next/server"
export function GET(request: Request) {
  const { origin } = new URL(request.url)
  if (origin) return NextResponse.redirect(new URL("/login", request.url))
  return NextResponse.redirect(origin + "/home")
}`
	if got := jsFlowsIn(t, "route.ts", safe); len(got) != 0 {
		t.Errorf("safe: got %v", got)
	}
	page := `export default function Page() {
  const shop = new URLSearchParams(window.location.search).get('shop') ?? ''
  return (
    <div>
      <p>{shop}</p>
      <a href={'/x/' + shop}>x</a>
    </div>
  )
}`
	if got := jsFlowsIn(t, "page.tsx", page); len(got) != 0 {
		t.Errorf("page: got %v", got)
	}
}

// TestJSReactProps checks that in a library of components this.props and
// the props of createElement reach dangerouslySetInnerHTML, and that the
// bind operator does not hide the render method that holds it.
func TestJSReactProps(t *testing.T) {
	src := `import React from 'react';
export default class Box extends React.Component {
  render() {
    const { html } = this.props;
    return <div onClick={::this.click}><span dangerouslySetInnerHTML={{ __html: html }} /></div>;
  }
  click() {}
}
export function Raw(props) {
  return React.createElement('span', { dangerouslySetInnerHTML: { __html: props.html } });
}`
	flows := jsFlowsIn(t, "box.jsx", src)
	sort.Strings(flows)
	got := strings.Join(flows, " ")
	if got != "taint.js-xss:10 taint.js-xss:5" {
		t.Errorf("got %q", got)
	}
}

// TestJSFixes checks the forms a fix takes: JSON.stringify of a value put
// in code, a field checked with an anchored pattern before the program
// exits, a $name variable, util.promisify, prototype methods assigned in a
// constructor and the lines of a multi-line value written to a property.
func TestJSFixes(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"stringify", `exports.compile = function (format) {
  return new Function('return ' + JSON.stringify(format));
};
exports.bad = function (format) {
  return new Function('return ' + format);
};`, "taint.js-code-injection:5"},
		{"exit after check", `var exec = require('child_process').exec;
module.exports = function (file) {
  var $c = JSON.parse(require('fs').readFileSync(file));
  if (!/^[a-z]+$/.test($c.name)) {
    process.exit(-1);
  }
  exec('zip ' + $c.name);
};`, ""},
		{"no check", `var exec = require('child_process').exec;
module.exports = function (file) {
  var $c = JSON.parse(require('fs').readFileSync(file));
  exec('zip ' + $c.name);
};`, "taint.js-command-injection:4"},
		{"promisify", `const { promisify } = require('util');
const { exec } = require('child_process');
const run = promisify(exec);
module.exports = async function (cmd) { return await run(cmd); };`, "taint.js-command-injection:4"},
		{"prototype in constructor", `const { execSync } = require('child_process');
function Info(name) {
  this.name = name;
  Info.prototype.get = function () {
    return execSync('info ' + this.name);
  };
}
module.exports = Info;`, "taint.js-command-injection:5"},
		{"multi-line value", `module.exports = function (el) {
  el.innerHTML = '<a>' +
    location.hash +
    '</a>';
};`, "taint.js-xss:2-4"},
	}
	for _, c := range cases {
		if got := strings.Join(jsFlows(t, c.src), " "); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestJSRouteChain checks that handlers registered on app.route(path) are
// routes, so the request reaches the helpers they call.
func TestJSRouteChain(t *testing.T) {
	src := `import { Request, Response } from 'express';
function show(name: any, response: Response) {
  return response.send('Dashboard ' + name);
}
export function setup(app: any) {
  app.route('/:d').get((request: Request, response: Response) => {
    show(request.params.d, response);
  });
}`
	if got := strings.Join(jsFlowsIn(t, "routes.ts", src), " "); got != "taint.js-xss:3" {
		t.Errorf("got %q", got)
	}
}

// TestJSNestDecorators checks that a NestJS parameter bound by a decorator
// is a source and an undecorated one is not.
func TestJSNestDecorators(t *testing.T) {
	src := `import { exec } from 'child_process';
class C {
  constructor(private readonly n: number) {}
  run(@Query('c') c: string) {
    exec('echo ' + c);
  }
  safe(c: string) {
    exec('echo ' + c);
  }
  both(@Body() b: string, @Req() r, other: string) {
    exec(other);
  }
}`
	if got := strings.Join(jsFlowsIn(t, "c.controller.ts", src), " "); got != "taint.js-command-injection:5" {
		t.Errorf("got %q", got)
	}
}

// TestJSSpawnShell checks that a command string passed to a shell with its
// command flag is a command injection, and a fixed one is not.
func TestJSSpawnShell(t *testing.T) {
	src := `const { spawn } = require('child_process');
function run(c) {
  spawn('sh', ['-c', 'echo ' + c]);
  spawn('ls', ['-l', c]);
  spawn('sh', ['-c', 'echo fixed']);
}
module.exports = run;`
	if got := strings.Join(jsFlows(t, src), " "); got != "taint.js-command-injection:3" {
		t.Errorf("got %q", got)
	}
}

// TestJSPrototypeTwoKeys checks the store of an object selected by a key
// from the input with a key from the input (preferences[section][key]).
func TestJSPrototypeTwoKeys(t *testing.T) {
	src := `export function g() {
  const params = new URLSearchParams(window.location.search);
  const section = params.get('section') || 'd';
  const key = params.get('key') || 'l';
  const value = params.get('value') || '';
  const preferences = { d: {}, c: {} };
  const sp = preferences[section] || (preferences[section] = {});
  sp[key] = value;
  return { preferences };
}
export function fixed() {
  const params = new URLSearchParams(window.location.search);
  const section = params.get('section') || 'd';
  const key = params.get('key') || 'l';
  const preferences = { d: {}, c: {} };
  const sp = preferences[section];
  sp['x'] = key;
  sp[section] = 'y';
}
export function named() {
  const params = new URLSearchParams(window.location.search);
  const section = params.get('section') || 'd';
  const value = params.get('value') || '';
  const preferences = { d: {}, c: {} };
  const sec = preferences[section] || (preferences[section] = {});
  sec.display = value;
}`
	got := jsFlowsIn(t, "p.js", src)
	if strings.Join(got, " ") != "taint.js-prototype-pollution:26 taint.js-prototype-pollution:8" {
		t.Errorf("got %q", got)
	}
}
