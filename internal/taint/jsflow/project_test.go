package jsflow

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/taint"
)

// project analyzes files (path to source) together and returns the flows
// as file:kind:line, with the steps of each when steps is set.
func project(t *testing.T, files map[string]string, library bool, resolve func(from, spec string) string) []string {
	t.Helper()
	spec, err := taint.Load("javascript")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	p := NewProject(spec, Options{Library: library}, paths, func(f string) (string, bool) {
		s, ok := files[f]
		return s, ok
	}, resolve)
	var out []string
	for _, f := range paths {
		for _, fd := range p.Analyze(f) {
			out = append(out, fmt.Sprintf("%s:%s:%d", fd.File, strings.TrimPrefix(fd.Sink.ID, "taint.js-"), fd.Line))
		}
	}
	if p.ParseErrors > 0 {
		t.Fatalf("%d files did not parse", p.ParseErrors)
	}
	sort.Strings(out)
	return out
}

func expectProject(t *testing.T, name string, files map[string]string, want ...string) {
	t.Helper()
	got := project(t, files, false, nil)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("%s:\n got %v\nwant %v", name, got, want)
	}
}

func TestCrossFile(t *testing.T) {
	expectProject(t, "commonjs helper", map[string]string{
		"routes/run.js": `
const { list } = require('../lib/shell');
app.get('/run', (req, res) => {
  list(req.query.dir);
});`,
		"lib/shell.js": `
const { exec } = require('child_process');
function list(dir) {
  exec('ls ' + dir);
}
module.exports = { list };`,
	}, "lib/shell.js:command-injection:4")

	expectProject(t, "module object and exports.name", map[string]string{
		"app.js": `
const db = require('./db');
app.get('/u', async (req, res) => {
  await db.find(req.params.id);
});`,
		"db.js": `
exports.find = function (id) {
  return pool.query("SELECT * FROM users WHERE id = '" + id + "'");
};`,
	}, "db.js:sql-injection:3")

	expectProject(t, "es module default export, TypeScript, index file", map[string]string{
		"src/pages/api/file.ts": `
import read from '../../util';
export default function handler(req, res) {
  res.send(read(req.query.name));
}`,
		"src/util/index.ts": `
import fs from 'fs';
export default function read(name: string) {
  fs.readFileSync('/srv/' + name, 'utf8');
  return 'ok';
}`,
	}, "src/util/index.ts:path-traversal:4")

	expectProject(t, "return value comes back tainted", map[string]string{
		"a.js": `
import { wrap } from './fmt.js';
app.get('/', (req, res) => {
  res.send(wrap(req.query.q));
});`,
		"fmt.ts": `
export const wrap = (s) => '<b>' + s + '</b>';`,
	}, "a.js:xss:4")

	expectProject(t, "sanitizer in the helper", map[string]string{
		"a.js": `
import { wrap } from './fmt';
app.get('/', (req, res) => {
  res.send(wrap(req.query.q));
});`,
		"fmt.js": `
import escape from 'escape-html';
export function wrap(s) { return '<b>' + escape(s) + '</b>'; }`,
	})

	expectProject(t, "re-export through a barrel", map[string]string{
		"a.js": `
import { run } from './lib';
app.post('/', (req, res) => { run(req.body.cmd); });`,
		"lib/index.js": `
export * from './exec';
export { other as renamed } from './other';`,
		"lib/exec.js": `
import { execSync } from 'child_process';
export function run(c) { execSync(c); }`,
		"lib/other.js": `export function other() {}`,
	}, "lib/exec.js:command-injection:3")

	expectProject(t, "two callers, one sink", map[string]string{
		"a.js": `
const { run } = require('./x');
app.get('/a', (req, res) => run(req.query.c));`,
		"b.js": `
const { run } = require('./x');
app.get('/b', (req, res) => run(req.query.c));`,
		"x.js": `
module.exports.run = (c) => require('child_process').exec(c);`,
	}, "x.js:command-injection:2")

	expectProject(t, "constant argument", map[string]string{
		"a.js": `
const { run } = require('./x');
app.get('/a', (req, res) => run('uptime'));`,
		"x.js": `
module.exports.run = (c) => require('child_process').exec(c);`,
	})

	expectProject(t, "import cycle", map[string]string{
		"a.js": `
import { b } from './b';
export function a(x) { return b(x); }
app.get('/', (req, res) => { a(req.query.x); });`,
		"b.js": `
import { a } from './a';
import { exec } from 'child_process';
export function b(x) { exec(x); return a; }`,
	}, "b.js:command-injection:4")

	expectProject(t, "package imports are not files", map[string]string{
		"a.js": `
import { run } from 'x';
app.get('/', (req, res) => { run(req.query.x); });`,
		"x.js": `
export function run(c) { require('child_process').exec(c); }`,
	})
}

func TestCrossFileAliases(t *testing.T) {
	files := map[string]string{
		"web/app/api/route.ts": `
import { redirectTo } from '@/lib/nav';
export async function GET(request: Request) {
  const next = new URL(request.url).searchParams.get('next');
  return redirectTo(next);
}`,
		"web/src/lib/nav.ts": `
import { NextResponse } from 'next/server';
export function redirectTo(to: string) {
  return NextResponse.redirect(to);
}`,
	}
	alias := func(from, spec string) string {
		if rest, ok := strings.CutPrefix(spec, "@/"); ok {
			return "web/src/" + rest + ".ts"
		}
		return ""
	}
	got := project(t, files, false, alias)
	if want := "web/src/lib/nav.ts:open-redirect:4"; strings.Join(got, " ") != want {
		t.Errorf("alias: got %v, want %v", got, want)
	}
	if got := project(t, files, false, nil); len(got) != 0 {
		t.Errorf("without the alias the import is a package: got %v", got)
	}
}

func TestCrossFileSteps(t *testing.T) {
	spec, err := taint.Load("javascript")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"app.js": `
const { list } = require('./shell');
app.get('/run', (req, res) => {
  const dir = req.query.dir;
  list(dir);
});`,
		"shell.js": `
const { exec } = require('child_process');
function list(d) {
  const cmd = 'ls ' + d;
  exec(cmd);
}
module.exports = { list };`,
	}
	p := NewProject(spec, Options{}, []string{"app.js", "shell.js"}, func(f string) (string, bool) { s, ok := files[f]; return s, ok }, nil)
	var fds []taint.Finding
	for _, f := range []string{"app.js", "shell.js"} {
		fds = append(fds, p.Analyze(f)...)
	}
	if len(fds) != 1 {
		t.Fatalf("got %d findings", len(fds))
	}
	var steps []string
	for _, st := range fds[0].Steps {
		steps = append(steps, fmt.Sprintf("%s@%s%d", st.What, st.File, st.Line))
	}
	// Steps in the caller name its file; those in the finding's file do not.
	got := strings.Join(steps, " -> ")
	want := "req.query@app.js4 -> dir@app.js4 -> list()@app.js5 -> d@3 -> concatenation@4 -> cmd@4 -> Shell command built from untrusted input@5"
	if got != want || fds[0].File != "shell.js" {
		t.Errorf("steps in %s:\n got %s\nwant %s", fds[0].File, got, want)
	}
}

func TestProjectFreesAnalyses(t *testing.T) {
	spec, err := taint.Load("javascript")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"a.js":         "import { b } from './lib';\napp.get('/', (req, res) => { b(req.query.x); });",
		"lib/index.js": "export * from './b';",
		"lib/b.js":     "import { c } from '../c';\nexport function b(x) { c(x); }",
		"c.js":         "export function c(x) { require('child_process').exec(x); }",
		"d.js":         "export const unused = 1;",
	}
	paths := []string{"a.js", "c.js", "d.js", "lib/b.js", "lib/index.js"}
	p := NewProject(spec, Options{}, paths, func(f string) (string, bool) { s, ok := files[f]; return s, ok }, nil)
	var got []string
	for _, f := range paths {
		for _, fd := range p.Analyze(f) {
			got = append(got, fmt.Sprintf("%s:%d", fd.File, fd.Line))
		}
		if f == "a.js" && len(p.mods) != 3 {
			// a.js is done; what it imports is still to be reported.
			t.Errorf("after a.js: %d analyses kept, want 3", len(p.mods))
		}
	}
	if strings.Join(got, " ") != "c.js:1" {
		t.Errorf("got %v", got)
	}
	if len(p.mods) != 0 {
		t.Errorf("%d analyses kept at the end", len(p.mods))
	}
}

func TestCrossFileDatabaseRows(t *testing.T) {
	expectProject(t, "a row found by a key from the request", map[string]string{
		"route.ts": `
import { providerBySlug } from './db';
export async function GET(request: Request) {
  const slug = new URL(request.url).searchParams.get('slug');
  const provider = await providerBySlug(slug);
  return fetch(provider.issuer + '/.well-known/openid-configuration');
}`,
		"db.ts": `
export async function providerBySlug(slug: string) {
  const [row] = await sql()` + "`SELECT * FROM providers WHERE slug = ${slug}`" + `;
  return row;
}`,
	})
}

func TestCrossFileDatabaseRowsControl(t *testing.T) {
	expectProject(t, "the helper returns the input itself", map[string]string{
		"route.ts": `
import { providerBySlug } from './db';
export async function GET(request: Request) {
  const slug = new URL(request.url).searchParams.get('slug');
  const provider = await providerBySlug(slug);
  return fetch(provider + '/.well-known/openid-configuration');
}`,
		"db.ts": `
export async function providerBySlug(slug: string) {
  await sql()` + "`SELECT * FROM providers WHERE slug = ${slug}`" + `;
  return slug;
}`,
	}, "route.ts:ssrf:6")
}
