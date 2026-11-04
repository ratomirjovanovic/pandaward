package adapters

import (
	"regexp"
	"strings"
)

// Structural checks that narrow the line rules in builtin_code.go. Each one
// only drops a match when the code itself shows the value cannot carry
// attacker input; anything it cannot prove keeps firing.

// ---- code.js-shell ----

var jsShellExecRe = regexp.MustCompile(`\b(exec|execSync)\s*\(\s*(\x60[^\x60]*\$\{|['"][^'"]*['"]\s*\+|[a-zA-Z_]\w*\s*[,)])`)

var (
	interpRe      = regexp.MustCompile(`\$\{([^}]*)\}`)
	constInterpRe = regexp.MustCompile(`^([A-Z][A-Z0-9_]*|[A-Za-z_$][\w$]*\.pid)$`)
)

// jsShellDynamic reports whether some exec call on the line builds its
// command from something other than a template literal whose every
// interpolation is an UPPER_CASE constant or a process id.
func jsShellDynamic(l, _ string) bool {
	for _, m := range jsShellExecRe.FindAllStringSubmatchIndex(l, -1) {
		start := m[4]
		if l[start] != '`' {
			return true
		}
		tpl := l[start+1:]
		if end := strings.IndexByte(tpl, '`'); end >= 0 {
			tpl = tpl[:end]
		}
		ins := interpRe.FindAllStringSubmatch(tpl, -1)
		if len(ins) == 0 || len(ins) != strings.Count(tpl, "${") {
			return true
		}
		for _, in := range ins {
			if !constInterpRe.MatchString(strings.TrimSpace(in[1])) {
				return true
			}
		}
	}
	return false
}

var (
	ownExecRe   = regexp.MustCompile(`(?m)(^|[^.\w$])(function\s*\*?\s*exec\s*[<(]|(const|let|var)\s+exec\s*(:[^=]+)?=\s*(async\s+)?(function\b|\([^)]*\)\s*(:[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>))`)
	childProcRe = regexp.MustCompile(`child_process|shelljs`)
)

// definesOwnExec reports whether the file declares its own exec function
// and never references child_process or shelljs, so a bare exec(...) call
// in it cannot be the shell API. An imported exec does not count.
func definesOwnExec(text string) bool {
	return ownExecRe.MatchString(text) && !childProcRe.MatchString(text)
}

// ---- code.html-sink ----

var (
	htmlSinkRe   = regexp.MustCompile(`dangerouslySetInnerHTML|\.(inner|outer)HTML\s*=[^=]|document\.write(ln)?\s*\(|\bv-html\s*=|\bmark_safe\s*\(|\bhtml_safe\b|bypassSecurityTrust\w+\(`)
	htmlSinkNot  = regexp.MustCompile(`(?i)DOMPurify|sanitize|escape|innerHTML\s*=\s*['"\x60]{2}|innerHTML\s*=\s*['"]\s*['"]|JSON\.stringify\(.*\)\s*\.replace\(\s*/</g\s*,`)
	htmlAssignRe = regexp.MustCompile(`\.(inner|outer)HTML\s*=([^=].*)$`)
	constRHSRe   = regexp.MustCompile(`^\s*([A-Z][A-Z0-9_]*|'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\x60[^\x60$]*\x60)\s*;?\s*(//.*)?$`)
	literalRe    = regexp.MustCompile(`^('(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|\x60[^\x60]*\x60)\s*(as\s+const\s*)?(;|\r?\n|$)`)
)

// htmlSinkDynamic drops an innerHTML/outerHTML assignment whose right-hand
// side is a string literal, a template without interpolation, or an
// UPPER_CASE constant the same file declares with such a literal.
func htmlSinkDynamic(l, text string) bool {
	m := htmlAssignRe.FindStringSubmatchIndex(l)
	if m == nil {
		return true
	}
	rhs := constRHSRe.FindStringSubmatch(l[m[4]:m[5]])
	if rhs == nil {
		return true
	}
	if c := rhs[1]; c[0] >= 'A' && c[0] <= 'Z' && !constLiteralDefined(c, text) {
		return true
	}
	return htmlSinkRe.MatchString(l[:m[0]])
}

// constLiteralDefined reports whether text declares `const name = <literal>`
// with a plain string or an interpolation-free template.
func constLiteralDefined(name, text string) bool {
	re := regexp.MustCompile(`(?:^|[^.\w$])const\s+` + regexp.QuoteMeta(name) + `(?:\s*:\s*string)?\s*=\s*`)
	loc := re.FindStringIndex(text)
	if loc == nil {
		return false
	}
	lit := literalRe.FindStringSubmatch(text[loc[1]:])
	return lit != nil && !strings.Contains(lit[1], "${")
}

var (
	reactSinkRe = regexp.MustCompile(`dangerouslySetInnerHTML`)
	htmlPropRe  = regexp.MustCompile(`^dangerouslySetInnerHTML\s*(?:=\s*\{|:)\s*\{\s*__html\s*:\s*`)
)

// htmlSinkProvenSafe reports whether every dangerouslySetInnerHTML on the
// line, and no other sink, receives a value the code proves cannot carry
// markup from outside: a whole string literal; JSON.stringify(...) whose
// "<" is replaced; a call to a helper defined in the file or imported from a
// module in the repository whose only return is such an escape or a call
// to a known sanitizer (sanitize-html, DOMPurify, xss); or a const of the
// same file initialized with one of those. A script element's type is no
// proof: a consent manager re-types text/plain scripts and runs them.
func htmlSinkProvenSafe(c lineCtx) bool {
	l := c.File.Lines[c.Index]
	if htmlSinkRe.MatchString(reactSinkRe.ReplaceAllString(l, "")) {
		return false
	}
	locs := reactSinkRe.FindAllStringIndex(l, -1)
	if len(locs) == 0 {
		return false
	}
	off := c.offset()
	for _, loc := range locs {
		at := off + loc[0]
		m := htmlPropRe.FindStringIndex(c.Text[at:])
		if m == nil {
			return false
		}
		start := at + m[1]
		end := exprEnd(c.Text, start, ",", false)
		if !safeHTMLValue(c, strings.TrimSpace(c.Text[start:end]), start, true) {
			return false
		}
	}
	return true
}

// safeHTMLValue applies the proofs of htmlSinkProvenSafe to one expression
// of the sink's file; at is where it appears, and trace allows following
// one identifier to its const declaration.
func safeHTMLValue(c lineCtx, expr string, at int, trace bool) bool {
	if isWholeLiteral(expr) || isLtEscapedJSON(expr) {
		return true
	}
	if callee, args, ok := wholeCall(expr); ok {
		return sanitizerCall(callee, args, jsImports(c.Text)) || safeHelper(c, callee)
	}
	if trace && identRe.MatchString(expr) {
		init, ok := constInit(c.Text, expr, at)
		return ok && safeHTMLValue(c, init, at, false)
	}
	return false
}

var sanitizerModules = map[string]bool{"sanitize-html": true, "dompurify": true, "isomorphic-dompurify": true, "xss": true}

// sanitizerCall reports whether callee(args) is a known HTML sanitizer
// imported in the file, called without options that let scripts through.
func sanitizerCall(callee, args string, imports map[string]jsBinding) bool {
	if unsafeOptsRe.MatchString(args) {
		return false
	}
	name, method, _ := strings.Cut(callee, ".")
	b, ok := imports[name]
	if !ok || !sanitizerModules[b.module] {
		return false
	}
	switch b.module {
	case "sanitize-html":
		return method == "" && b.imported == "default"
	case "xss":
		return method == "" && (b.imported == "default" || b.imported == "filterXSS")
	}
	// dompurify, isomorphic-dompurify
	return method == "sanitize" && (b.imported == "default" || b.imported == "*") || method == "" && b.imported == "sanitize"
}

// safeHelper reports whether name, called at the sink, is a function whose
// only return is a proven-safe expression: defined in the sink's file, or a
// named import from a module of the repository (never a package).
func safeHelper(c lineCtx, name string) bool {
	if strings.Contains(name, ".") {
		return false
	}
	imports := jsImports(c.Text)
	text, fn, exported := c.Text, name, false
	if b, ok := imports[name]; ok {
		if b.imported == "default" || b.imported == "*" {
			return false
		}
		f := resolveLocal(c.Inv, c.File.Path, b.module)
		if f == nil {
			return false
		}
		text, fn, exported = strings.Join(f.Lines, "\n"), b.imported, true
		imports = jsImports(text)
	}
	ret, ok := funcReturn(text, fn, exported)
	if !ok {
		return false
	}
	if isLtEscapedJSON(ret) {
		return true
	}
	callee, args, ok := wholeCall(ret)
	return ok && sanitizerCall(callee, args, imports)
}

// constInit returns the initializer of the one const declaration of name in
// text, when it comes before at in a block that is still open there and the
// name is not used in between (so no parameter or later binding shadows it).
func constInit(text, name string, at int) (string, bool) {
	q := regexp.QuoteMeta(name)
	all := regexp.MustCompile(`(?:^|[^.\w$])(?:const|let|var|function|class)\s+`+q+`\b`).FindAllStringIndex(text, -1)
	decl := regexp.MustCompile(`(?:^|[^.\w$])const\s+`+q+`\s*(?::[^=]+)?=\s*`).FindAllStringIndex(text, -1)
	if len(all) != 1 || len(decl) != 1 || decl[0][1] >= at {
		return "", false
	}
	start := decl[0][1]
	end := exprEnd(text, start, ";,", true)
	if end >= at || regexp.MustCompile(`(?:^|[^.\w$])`+q+`\b`).MatchString(text[end:at]) {
		return "", false
	}
	depth := 0
	walkJS(text[:at], end, func(i int) bool {
		switch text[i] {
		case '{', '(', '[':
			depth++
		case '}', ')', ']':
			depth--
		}
		return depth < 0
	})
	if depth < 0 {
		return "", false
	}
	return strings.TrimSpace(text[start:end]), true
}

// ---- code.secret-logged ----

var (
	labelRe       = regexp.MustCompile(`(?i)\b(password|passwd|secret|api_?key|access_?token|refresh_?token|authorization|private_?key)\b\s*[:=]\s*(%[-+#0-9.]*[a-zA-Z]|\{\d*\})?\s*$`)
	proseInterpRe = regexp.MustCompile(`\$?\{[^}]*\}|#\{[^}]*\}|\$[A-Za-z_]\w*`)
)

// blankProse empties the prose inside string literals so words in a log
// message do not count as logged values. Interpolations are kept, and so is
// a literal (or the text right before an interpolation) that ends in a
// label such as "password:" or "secret=%s", because a value follows it.
func blankProse(l string) string {
	var b strings.Builder
	for i := 0; i < len(l); {
		q := l[i]
		if q != '"' && q != '\'' && q != '`' {
			b.WriteByte(q)
			i++
			continue
		}
		j := i + 1
		for j < len(l) && l[j] != q {
			if l[j] == '\\' {
				j++
			}
			j++
		}
		end := min(j, len(l))
		body := l[i+1 : end]
		next := strings.TrimLeft(l[min(end+1, len(l)):], " \t")
		b.WriteByte(q)
		if labelRe.MatchString(body) && next != "" && strings.ContainsRune(",+%.", rune(next[0])) {
			b.WriteString(body)
		} else {
			b.WriteString(keepInterpolations(body))
		}
		if j < len(l) {
			b.WriteByte(q)
		}
		i = j + 1
	}
	return b.String()
}

func keepInterpolations(body string) string {
	var parts []string
	prev := 0
	for _, m := range proseInterpRe.FindAllStringIndex(body, -1) {
		if labelRe.MatchString(body[prev:m[0]]) {
			parts = append(parts, body[prev:m[0]])
		}
		parts = append(parts, body[m[0]:m[1]])
		prev = m[1]
	}
	return strings.Join(parts, " ")
}

// ---- code.llm-output-exec ----

var (
	llmSinkRe = regexp.MustCompile(`(?i)(\beval|\bexec|\bexecSync|\bsubprocess\.\w+|\bos\.system|\bnew\s+Function)\s*\(`)
	llmWordRe = regexp.MustCompile(`(?i)\b(completion|response|output|message|content|choices|generated|llm|model|answer|result\.text)\b`)
)

// llmOutputExec reports whether model output appears inside the argument
// list of an execution sink on the line. A method call such as re.exec(...)
// counts only in files that use child_process or shelljs, since elsewhere
// .exec is a RegExp or library method rather than a shell.
func llmOutputExec(l, text string) bool {
	for _, m := range llmSinkRe.FindAllStringSubmatchIndex(l, -1) {
		name := strings.ToLower(l[m[2]:m[3]])
		if m[2] > 0 && l[m[2]-1] == '.' {
			if name == "eval" || !childProcRe.MatchString(text) {
				continue
			}
		}
		if llmWordRe.MatchString(callArgs(l[m[1]:])) {
			return true
		}
	}
	return false
}

// callArgs returns the text up to the parenthesis that closes a call whose
// opening parenthesis was just consumed, or the rest of the line.
func callArgs(s string) string {
	depth := 1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[:i]
			}
		}
	}
	return s
}

// ---- code.sql-concat ----

// sqlConcatRe pairs each opening quote with the same closing quote.
var sqlConcatRe = regexp.MustCompile(`(?i)("\s*` + sqlIn(`[^"]`) + `[^"]*"|'\s*` + sqlIn(`[^']`) + `[^']*'|\x60\s*` + sqlIn(`[^\x60]`) + `[^\x60]*\x60)\s*(\+|\.\s*\$|%\s*[\w(]|\.format\()`)

// sqlIn is the statement start; class keeps "select ... from" inside one
// literal.
func sqlIn(class string) string {
	return `(select\s` + class + `+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b`
}

var (
	dbClientRe = regexp.MustCompile(`['"\x60](pg|pg-promise|pg-pool|postgres|@neondatabase/serverless|mysql|mysql2|mariadb|sqlite|sqlite3|better-sqlite3|sql\.js|bun:sqlite|node:sqlite|@libsql/client|@planetscale/database|@vercel/postgres|@supabase/supabase-js|@supabase/postgrest-js|knex|drizzle-orm|@prisma/client|prisma|kysely|sequelize|typeorm|mongodb|mongoose|@mikro-orm/core|objection|slonik|tedious|mssql|oracledb|duckdb|@duckdb/node-api|@clickhouse/client|cassandra-driver|redis|ioredis|@cloudflare/d1|@electric-sql/pglite)(/[^'"\x60]*)?['"\x60]`)
	dbCLIRe    = regexp.MustCompile(`^(?:.*[/\\])?(psql|pg_restore|mysql|mariadb|sqlite3?|sqlcmd|duckdb|clickhouse(-client)?|cockroach|supabase|wrangler|turso|bq|snowsql|mongosh|mongo|prisma|knex|drizzle-kit|sequelize|npx|pnpm|pnpx|yarn|npm|bunx|bun|node|deno|tsx|ts-node|sh|bash|zsh|dash|cmd|cmd\.exe|powershell|pwsh|env|docker|podman|kubectl|ssh|sudo)(\.exe)?(\s|$)`)
	queryRunRe = regexp.MustCompile(`\.\s*\$?(query|queryRaw\w*|executeRaw\w*|execute|exec|unsafe|raw|prepare|run|all|batch|sql|transaction)\s*[(\x60]|\bsql\s*[(\x60]|\bimport\s*\(`)
	netRe      = regexp.MustCompile(`\bfetch\s*\(|\baxios\b|\bgot\s*\(|\bky\s*\(|XMLHttpRequest|WebSocket|\bundici\b|\bnew\s+Worker\b|process\.send\b|postMessage\b`)
	netModRe   = regexp.MustCompile(`['"\x60](node:)?(https?|http2|net|tls|dgram|worker_threads|cluster|axios|undici|got|ky|node-fetch|ws)['"\x60]`)
	exportRe   = regexp.MustCompile(`(?m)^\s*export\b|\bmodule\.exports\b|\bexports\.\w+\s*=`)
	writeOutRe = regexp.MustCompile(`\b(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(|process\.stdout\.write\s*\(|console\.(log|info)\s*\(`)
	childRunRe = regexp.MustCompile(`\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|execa|execaSync)\s*\(\s*(?:'([^'\n]*)'|"([^"\n]*)"|())`)
	pureMethod = map[string]bool{"map": true, "filter": true, "find": true, "findIndex": true, "some": true, "every": true, "forEach": true, "reduce": true,
		"join": true, "includes": true, "indexOf": true, "slice": true, "concat": true, "flat": true, "flatMap": true, "keys": true, "values": true,
		"entries": true, "at": true, "toString": true, "has": true, "get": true}
)

// nodeBuiltins are modules whose bindings may be used freely: none of them
// can run a query. child_process is checked separately.
var nodeBuiltins = map[string]bool{"fs": true, "fs/promises": true, "path": true, "url": true, "os": true, "util": true, "crypto": true, "process": true,
	"readline": true, "events": true, "stream": true, "zlib": true, "assert": true, "buffer": true, "string_decoder": true, "timers": true, "child_process": true}

// sqlForFileOnly demotes a concatenated SQL string to an info listing when
// the JavaScript file that builds it cannot run it: the file imports no
// database client, calls no query method, uses no network, exports
// nothing, starts no database command line tool, calls no imported
// function from outside the Node standard library, and writes files or
// console output. The SQL may still be executed later from the generated
// file, so it stays listed.
func sqlForFileOnly(c lineCtx) *demotion {
	t := c.Text
	if !jsLike[c.File.Lang] || dbClientRe.MatchString(t) || netModRe.MatchString(t) {
		return nil
	}
	// The remaining checks look at code only, so a file name such as
	// "x.sql" in a string is not taken for a query call.
	code := maskLiterals(t)
	if !writeOutRe.MatchString(code) || queryRunRe.MatchString(code) || netRe.MatchString(code) || exportRe.MatchString(code) {
		return nil
	}
	// A child process must be a literal program that is neither a
	// database tool nor a shell or runner that could start one.
	for _, m := range childRunRe.FindAllStringSubmatchIndex(t, -1) {
		cmd := ""
		switch {
		case m[2] >= 0:
			cmd = t[m[2]:m[3]]
		case m[4] >= 0:
			cmd = t[m[4]:m[5]]
		default:
			return nil
		}
		if cmd == "" || dbCLIRe.MatchString(cmd) {
			return nil
		}
	}
	for name, b := range jsImports(t) {
		if nodeBuiltins[strings.TrimPrefix(b.module, "node:")] {
			continue
		}
		q := regexp.QuoteMeta(name)
		if regexp.MustCompile(`(?:^|[^.\w$])(new\s+)?` + q + `\s*[(\x60]`).MatchString(code) {
			return nil
		}
		for _, m := range regexp.MustCompile(`(?:^|[^.\w$])`+q+`\s*\??\.\s*([A-Za-z_$][\w$]*)\s*\(`).FindAllStringSubmatch(code, -1) {
			if !pureMethod[m[1]] {
				return nil
			}
		}
	}
	return &demotion{
		Title:   "SQL text built for a file, not executed here",
		Message: "Query text is concatenated with values, but this file imports no database client, runs no query, exports nothing and only writes its output to files or the console. It is listed because the generated SQL may be executed later.",
		Fix:     "Check that every value placed in the generated SQL is validated against the shape it may have, or quoted with the database's own literal quoting, before the file is applied.",
	}
}

// ---- code.weak-hash-password ----

// weakHashCall matches an MD5 or SHA-1 hashing call in common languages,
// including the md5sum/sha1sum command line tools.
const weakHashCall = `(\b(md5|sha1)(hex|_hex|digest)?\s*\(|\b(md5|sha1)sum\b` +
	`|\b(md5|sha1)\.(sum|new)\w*\s*\(` +
	`|\bhashlib\.(md5|sha1)\b` +
	`|(createHash|\bhash|hashlib\.new|\bdigest|getInstance|Digest\.new)\s*\(\s*['"\x60](md5|sha-?1)['"\x60]` +
	`|DigestUtils\.(md5|sha1|sha)\w*\s*\(` +
	`|Digest::(md5|sha1)\b` +
	`|\b(md5|sha1)(\.create\s*\(|managed\b|cryptoserviceprovider\b)` +
	`|:crypto\.hash\(\s*:(md5|sha)\b)`

var weakHashPasswordRe = regexp.MustCompile(`(?i)(` + weakHashCall + `.*\b(password|passwd|pwd)\b|\b(password|passwd|pwd)\b.*` + weakHashCall + `)`)
