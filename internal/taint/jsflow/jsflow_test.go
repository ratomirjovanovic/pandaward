package jsflow

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
	"github.com/ratomirjovanovic/pandaward/internal/taint/js"
)

func run(t *testing.T, src string, library bool) []string {
	t.Helper()
	spec, err := taint.Load("javascript")
	if err != nil {
		t.Fatal(err)
	}
	f := js.Parse("a.js", src, js.Options{JSX: true, TS: true})
	if len(f.Errors) > 0 {
		t.Fatalf("parse errors %v in\n%s", f.Errors, src)
	}
	var out []string
	for _, fd := range Analyze(f, spec, Options{Library: library}) {
		out = append(out, fmt.Sprintf("%s:%d", strings.TrimPrefix(fd.Sink.ID, "taint.js-"), fd.Line))
	}
	return out
}

func expect(t *testing.T, name, src string, library bool, want ...string) {
	t.Helper()
	got := run(t, src, library)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("%s:\n got %v\nwant %v", name, got, want)
	}
}

func TestRequestFlows(t *testing.T) {
	expect(t, "express exec", `
const { exec } = require('child_process');
app.get('/run', (req, res) => {
  const cmd = 'ls ' + req.query.dir;
  exec(cmd);
});`, false, "command-injection:5")

	expect(t, "handler with other names", `
const cp = require('node:child_process');
router.post('/x', function (q, s) {
  cp.execSync(`+"`git log ${q.body.ref}`"+`);
  s.send(q.params.id);
});`, false, "command-injection:4", "xss:5")

	expect(t, "destructured request", `
import fs from 'fs';
export default function handler(req, res) {
  const { file } = req.query;
  fs.readFileSync('/data/' + file);
}`, false, "path-traversal:5")

	expect(t, "eval and Function", `
app.post('/calc', (req, res) => {
  eval(req.body.expr);
  new Function('a', req.body.code);
});`, false, "code-injection:3", "code-injection:4")

	expect(t, "sql", `
app.get('/u', async (req, res) => {
  await db.query("SELECT * FROM u WHERE id = '" + req.params.id + "'");
  await db.query('SELECT * FROM u WHERE id = $1', [req.params.id]);
});`, false, "sql-injection:3")

	expect(t, "innerHTML from location", `
const q = location.hash.slice(1);
document.getElementById('out').innerHTML = q;
`, false, "xss:3")

	expect(t, "jsx dangerouslySetInnerHTML", `
export function Page({ searchParams }) {
  const html = window.location.search;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}`, false, "xss:4")

	expect(t, "spawn with shell", `
const { spawn } = require('child_process');
app.get('/a', (req, res) => {
  spawn(req.query.c, [], { shell: true });
  spawn(req.query.c, ['x']);
});`, false, "command-injection:4")

	expect(t, "promisified exec", `
const util = require('util');
const run = util.promisify(require('child_process').exec);
app.get('/a', async (req, res) => { await run('ping ' + req.query.h); });
`, false, "command-injection:4")

	expect(t, "redirect and ssrf", `
app.get('/go', (req, res) => {
  res.redirect(req.query.next);
  fetch(req.query.url);
});`, false, "open-redirect:3", "ssrf:4")
}

func TestSanitizersAndGuards(t *testing.T) {
	expect(t, "number conversion", `
app.get('/a', (req, res) => {
  exec('kill ' + parseInt(req.query.pid, 10));
});`, false)

	expect(t, "early return on failed check", `
app.get('/a', (req, res) => {
  const name = req.query.name;
  if (!/^[\w-]+$/.test(name)) return res.status(400).end();
  exec('git checkout ' + name);
});`, false)

	expect(t, "allowlist branch", `
const { exec } = require('child_process');
app.get('/a', (req, res) => {
  const t = req.query.tool;
  if (ALLOWED.includes(t)) { exec(t); }
  exec(t);
});`, false, "command-injection:6")

	expect(t, "path.basename", `
const path = require('path');
app.get('/f', (req, res) => {
  fs.readFile(path.join(DIR, path.basename(req.params.f)));
  fs.readFile(path.join(DIR, req.params.f));
});`, false, "path-traversal:5")

	expect(t, "escape for html only", `
const escapeHtml = require('escape-html');
const { exec } = require('child_process');
app.get('/a', (req, res) => {
  res.send(escapeHtml(req.query.q));
  exec(escapeHtml(req.query.q));
});`, false, "command-injection:6")

	expect(t, "strip to allowed characters", `
app.get('/a', (req, res) => {
  exec('ping ' + req.query.h.replace(/[^a-z0-9.]/gi, ''));
});`, false)

	expect(t, "constant command", `
const { exec } = require('child_process');
exec('ls -la');
app.get('/a', (req, res) => { res.send('ok'); });`, false)

	expect(t, "length is not the value", `
app.get('/a', (req, res) => { res.send('n=' + req.query.q.length); });`, false)

	expect(t, "a variable named request holding something else", `
export async function send(config) {
  const request = buildRequest(config);
  const response = await fetch(request.url, request.init);
  response.send(request.body);
}`, false)

	expect(t, "dom append inserts text", `
document.body.append(location.hash);
$('#x').append(location.hash);
`, false, "xss:3")
}

func TestLibraryMode(t *testing.T) {
	src := `
var exec = require('child_process').exec;
module.exports = function (iface, callback) {
  exec("cat /sys/class/net/" + iface + "/address", function (err, out) {});
};
function internal(x) { exec(x); }
`
	expect(t, "exported function parameter", src, true, "command-injection:4")
	expect(t, "library mode off", src, false)

	expect(t, "exports.f chain and object export", `
const shell = require('shelljs');
findLoad = exports.findLoad = function findLoad(arg, cb) {
  var cmd = "wmic process | findstr " + arg;
  require('child_process').exec(cmd, cb);
};
module.exports.resolve = { resolve: function resolve(hostname) {
  shell.exec(require('util').format('"%s" %s', 'node', hostname), {silent: true});
} };`, true, "command-injection:5", "command-injection:8")

	expect(t, "exported class method", `
import * as cp from 'child_process';
export class Git {
  run(args: string) { cp.exec('git ' + args); }
  _private(x: string) { cp.exec(x); }
}`, true, "command-injection:4")

	expect(t, "closure in exported function", `
const { exec } = require('child_process');
exports.ps = function (pid, done) {
  var cmd = 'ps -o pcpu -p ';
  if (os.platform() == 'aix') cmd = 'ps -o pcpu,rssize -p ';
  return new Promise(function (resolve) { exec(cmd + pid, resolve); });
};`, true, "command-injection:6")

	expect(t, "library fetch is not ssrf", `
export async function get(url) { return fetch(url); }
`, true)

	expect(t, "array join of parameters", `
var exec = require('child_process').exec;
module.exports = function (args, fn) {
  args = ['growl'].concat(args);
  exec(args.join(' '), fn);
};`, true, "command-injection:5")
}

func TestTrace(t *testing.T) {
	spec, _ := taint.Load("javascript")
	f := js.Parse("a.js", `
app.get('/a', (req, res) => {
  const dir = req.query.dir;
  const cmd = 'ls ' + dir;
  require('child_process').exec(cmd);
});`, js.Options{JSX: true})
	fs := Analyze(f, spec, Options{})
	if len(fs) != 1 {
		t.Fatalf("%d findings", len(fs))
	}
	var lines []int
	for _, s := range fs[0].Steps {
		lines = append(lines, s.Line)
	}
	if fmt.Sprint(lines) != "[3 3 4 4 5]" || fs[0].Steps[0].What != "req.query" {
		t.Fatalf("steps %+v", fs[0].Steps)
	}
}
