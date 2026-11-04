package adapters

import (
	"strings"
	"testing"

	"github.com/ratomirjovanovic/pandaward/internal/model"
)

const (
	escHelper   = "export function jsonLd(data: unknown): string {\n  return JSON.stringify(data)\n    .replace(/</g, '\\\\u003c')\n    .replace(/>/g, '\\\\u003e')\n}\n"
	ldSinkStart = "export default function Page() {\n  return (\n    <script\n      type=\"application/ld+json\"\n      dangerouslySetInnerHTML={{ __html: "
	ldSinkEnd   = " }}\n    />\n  )\n}\n"
)

func ldPage(imports, value string) string { return imports + ldSinkStart + value + ldSinkEnd }

// Each case is a set of files; code.html-sink must fire on src/app/page.tsx
// or stay silent.
func TestHTMLSinkProvenSafe(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"whole string literal over several lines", map[string]string{
			"src/app/page.tsx": "export const A = () => (\n  <script\n    type=\"text/plain\"\n    dangerouslySetInnerHTML={{\n      __html:\n        \"window.dataLayer=window.dataLayer||[];\",\n    }}\n  />\n)\n"}, false},
		{"text/plain script with a dynamic value", map[string]string{
			"src/app/page.tsx": "export const A = ({ code }) => <script type=\"text/plain\" dangerouslySetInnerHTML={{ __html: code }} />\n"}, true},
		{"template with interpolation", map[string]string{
			"src/app/page.tsx": "export const A = ({ name }) => <div dangerouslySetInnerHTML={{ __html: `<b>${name}</b>` }} />\n"}, true},
		{"helper in the same file escapes <", map[string]string{
			"src/app/page.tsx": strings.Replace(escHelper, "export ", "", 1) + ldPage("", "jsonLd(data)")}, false},
		{"arrow helper in the same file escapes <", map[string]string{
			"src/app/page.tsx": ldPage("const ld = (d: unknown): string => JSON.stringify(d).replace(/</g, \"\\\\u003c\");\n", "ld(data)")}, false},
		{"helper without the escape", map[string]string{
			"src/app/page.tsx": ldPage("function jsonLd(d) {\n  return JSON.stringify(d)\n}\n", "jsonLd(data)")}, true},
		{"helper escapes > but not <", map[string]string{
			"src/app/page.tsx": ldPage("function jsonLd(d) {\n  return JSON.stringify(d).replace(/>/g, '\\\\u003e')\n}\n", "jsonLd(data)")}, true},
		{"helper puts the match back", map[string]string{
			"src/app/page.tsx": ldPage("function jsonLd(d) {\n  return JSON.stringify(d).replace(/</g, '$&')\n}\n", "jsonLd(data)")}, true},
		{"helper with an early return", map[string]string{
			"src/app/page.tsx": ldPage("function jsonLd(d) {\n  if (typeof d === 'string') { return d }\n  return JSON.stringify(d).replace(/</g, '\\\\u003c')\n}\n", "jsonLd(data)")}, true},
		{"helper defined twice", map[string]string{
			"src/app/page.tsx": ldPage("function jsonLd(d) {\n  return JSON.stringify(d).replace(/</g, '\\\\u003c')\n}\nconst x = { f() { const jsonLd = (d) => d } }\n", "jsonLd(data)")}, true},
		{"helper imported by relative path", map[string]string{
			"src/lib/json-ld.ts": escHelper,
			"src/app/page.tsx":   ldPage("import { jsonLd } from '../lib/json-ld'\n", "jsonLd(data)")}, false},
		{"helper imported through a tsconfig path alias, renamed", map[string]string{
			"tsconfig.json":      "{\n  // paths for the app\n  \"compilerOptions\": { \"paths\": { \"@/*\": [\"./src/*\"], }, },\n}\n",
			"src/lib/json-ld.ts": escHelper,
			"src/app/page.tsx":   ldPage("import { jsonLd as serialize } from '@/lib/json-ld'\n", "serialize(data)")}, false},
		{"helper imported from a package", map[string]string{
			"node_modules/json-ld/index.js": escHelper,
			"src/app/page.tsx":              ldPage("import { jsonLd } from 'json-ld'\n", "jsonLd(data)")}, true},
		{"local helper that does not escape", map[string]string{
			"src/lib/json-ld.ts": "export function jsonLd(data: unknown): string {\n  return JSON.stringify(data)\n}\n",
			"src/app/page.tsx":   ldPage("import { jsonLd } from '../lib/json-ld'\n", "jsonLd(data)")}, true},
		{"alias that no tsconfig declares", map[string]string{
			"src/lib/json-ld.ts": escHelper,
			"src/app/page.tsx":   ldPage("import { jsonLd } from '@/lib/json-ld'\n", "jsonLd(data)")}, true},
		{"const from a local sanitize-html helper", map[string]string{
			"src/lib/md.ts":    "import sanitize from 'sanitize-html'\n\nexport function markdownToHtml(md: string): string {\n  const raw = md.replace(/\\[([^\\]]+)\\]\\(([^)]+)\\)/g, (_, text, href) => {\n    if (href.startsWith('/')) return `<a href=\"${href}\">${text}</a>`\n    return text\n  })\n  return sanitize(raw, { allowedTags: ['p', 'a'] })\n}\n",
			"src/app/page.tsx": "import { markdownToHtml } from '../lib/md'\n\nexport default function Page({ doc }) {\n  const html = markdownToHtml(doc.body)\n  return (\n    <div\n      className=\"prose\"\n      dangerouslySetInnerHTML={{ __html: html }}\n    />\n  )\n}\n"}, false},
		{"sanitizer options that allow script", map[string]string{
			"src/lib/md.ts":    "import sanitize from 'sanitize-html'\nexport function render(md: string): string {\n  return sanitize(md, { allowedTags: ['b', 'script'] })\n}\n",
			"src/app/page.tsx": "import { render } from '../lib/md'\nexport const P = ({ md }) => <div dangerouslySetInnerHTML={{ __html: render(md) }} />\n"}, true},
		{"const shadowed by a parameter", map[string]string{
			"src/app/page.tsx": "const html = '<b>static</b>'\nexport const L = ({ items }) => items.map((html) => <div dangerouslySetInnerHTML={{ __html: html }} />)\n"}, true},
		{"const from a database row", map[string]string{
			"src/app/page.tsx": "export default async function Page() {\n  const page = await load()\n  return <div dangerouslySetInnerHTML={{ __html: page.intro_html }} />\n}\n"}, true},
	}
	for _, c := range cases {
		sigs := runOn(t, codeAdapter{}, c.files)
		got := false
		for _, s := range sigs {
			if s.RuleID == "code.html-sink" && s.File == "src/app/page.tsx" {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("%s: fired=%v, want %v", c.name, got, c.want)
		}
	}
}

const sqlScript = "import { writeFileSync } from 'node:fs'\nimport { CATALOGUE } from './catalogue.mjs'\n\n" +
	"const rows = CATALOGUE.map((c) => 'insert into prices (id, plan) values (' + [lit(c.id), lit(c.plan)].join(', ') + ');')\n" +
	"writeFileSync(`migrations/${Date.now()}_prices.sql`, rows.join('\\n'))\n"

// A concatenated SQL string in a file that cannot run it is listed as info;
// anything that could run it keeps the high finding.
func TestSQLConcatForFileOnly(t *testing.T) {
	cases := []struct {
		name, src string
		want      model.Severity
	}{
		{"script that only writes a .sql file", sqlScript, model.SevInfo},
		{"script that prints the SQL", "const ids = process.argv.slice(2)\nconsole.log('delete from sessions where id = ' + ids[0] + ';')\n", model.SevInfo},
		{"literal program run as a child process", "import { execFileSync } from 'node:child_process'\n" + sqlScript + "execFileSync('stripe', ['prices', 'list'])\n", model.SevInfo},
		{"db.query in a file that also writes files", sqlScript + "await db.query('delete from prices where id = ' + id)\n", model.SevHigh},
		{"imports a database client", "import pg from 'pg'\n" + sqlScript, model.SevHigh},
		{"requires a database client", "const { Pool } = require('pg')\n" + sqlScript, model.SevHigh},
		{"exports the builder", sqlScript + "export function del(id) { return 'delete from prices where id = ' + id }\n", model.SevHigh},
		{"pipes the SQL to psql", "import { execFileSync } from 'node:child_process'\n" + sqlScript + "execFileSync('psql', ['-c', rows.join(';')])\n", model.SevHigh},
		{"runs a command it computes", "import { execFileSync } from 'node:child_process'\n" + sqlScript + "execFileSync(tool, ['-c', rows.join(';')])\n", model.SevHigh},
		{"calls an imported local function", "import { apply } from './db.mjs'\n" + sqlScript + "await apply(rows)\n", model.SevHigh},
		{"sends the SQL over the network", sqlScript + "await fetch(url, { method: 'POST', body: rows.join(';') })\n", model.SevHigh},
		{"writes nothing", "const q = 'select * from prices where id = ' + id\n", model.SevHigh},
	}
	for _, c := range cases {
		sigs := runOn(t, codeAdapter{}, map[string]string{"scripts/gen.mjs": c.src})
		var got model.Severity
		for _, s := range sigs {
			if s.RuleID == "code.sql-concat" {
				got = s.Severity
			}
		}
		if got != c.want {
			t.Errorf("%s: severity %q, want %q", c.name, got, c.want)
		}
	}
}

func TestMaskLiterals(t *testing.T) {
	src := "const f = `${dir}/x.sql` // db.query(\nconst r = /a.query(/g; db.run(x)\n"
	got := maskLiterals(src)
	if strings.Contains(got, ".sql") || strings.Contains(got, "a.query(") || !strings.Contains(got, "dir") || !strings.Contains(got, "db.run(x)") {
		t.Fatalf("maskLiterals(%q) = %q", src, got)
	}
	if len(got) != len(src) || strings.Count(got, "\n") != strings.Count(src, "\n") {
		t.Fatalf("maskLiterals must keep offsets and line breaks")
	}
}
