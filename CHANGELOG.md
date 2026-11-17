# Changelog

All notable changes to PandaWard. Versions follow the release tags; each release page has binaries, checksums, the SBOM and build provenance. PandaWard was called PenSec before 0.2.0.

## [Unreleased]

### Changed
- `code.secret-logged` lists a log line as info when every credential word on it is inside a hashing call, such as a CLI that prints `hashPassword(password)` for an environment variable; a credential outside the call keeps the finding (#363).

## [0.2.16] - 2026-11-17

### Added
- The built-in taint engine analyzes JavaScript and TypeScript with the same IR engine as Python and Java (#406): files are one project, calls follow imports across files, Next.js route handlers (`request: Request`, `NextResponse.redirect`) and JSX are understood, and a redirect to the request's own host is not reported. The AST engine stays available with `PANDAWARD_JS_ENGINE=jsflow`.
- Regular expressions that backtrack catastrophically (ReDoS, CWE-1333) are found by the ambiguity of their automaton, not by patterns (#406): nested quantifiers and overlapping alternatives (`^(a+)+$`, `^(\w+\s?)*$`) are reported in any JavaScript or TypeScript file, and quadratic ones (`/ *, */`) in libraries, where the caller chooses the text. A pattern that succeeds at its first match, such as `^(a+)+`, is not reported. On the labelled files of the OpenSSF CVE benchmark the engine now detects 97 of 220 weaknesses and recognizes 56 fixes, from 72 and 46 with the AST engine; 20 of the 29 ReDoS cases are detected. On 48 local projects it reports nothing in their own code and 7 patterns in bundled WordPress scripts, each a real one.
- A Sponsor button (`.github/FUNDING.yml`) and a Sponsoring section in the README (#424).
- PandaWard's own data flow engine for Java (#406, milestones J1 to J3). A Java parser in pure Go (`internal/taint/java`) reads Java 21: generics, lambdas, method references, switch expressions and patterns, records, text blocks and annotations, and keeps going after a syntax error. `tools/javaparse` measures it: all 2,767 files of the OWASP Benchmark for Java and all 2,569 of the Adyen Java SDK parse without error. Java is lowered to the same IR as Python: each class is a module named after it, instance methods get `this`, declared types become the classes of values (resolved through imports, star imports of classes the specification knows and the file's package), lists, maps and `StringBuilder` become the container operations the engine models, and a `switch` falls through as Java does. `rules/taint/java.yaml` has the sources of servlets (request parameters, headers, cookies, query string) and of Spring MVC and JAX-RS (`@RequestParam`, `@PathVariable`, `@QueryParam`, ...), sinks for SQL (JDBC, Spring `JdbcTemplate`, JPA, Hibernate), OS commands, file paths, LDAP, XPath, the session and the HTTP response writer, weak hash and cipher algorithms (also read from the project's `.properties` files), predictable `java.util.Random` values in cookies and the session, and `setSecure(false)`. In Java files the engine replaces the bundled Semgrep rules for those weaknesses; the SSRF and deserialization rules stay. On the OWASP Benchmark for Java the engine alone and PandaWard as a scan runs it score +1.000 in all 11 categories (Opengrep with the bundled rules +0.818, the built-in rules alone 0.000). On real code: Spring PetClinic gives no finding, the Adyen Java SDK none, and WebGoat 19, all in its intentionally vulnerable SQL injection, path traversal and hashing lessons and in WebWolf's upload of a file named by the client. `tools/javaflow` prints flows or the IR. The engine gained what Java needed: declared return types (`returns`), a value's text hint ("rememberMe" + n), methods without a body skipped in favour of passing taint through, a value declared as text is not an opaque object, and `this` after a constructor.
- GitHub Discussions for questions, ideas and show and tell, with forms that ask for the version, how PandaWard runs and the rule or control; the issue chooser, README, CONTRIBUTING, the new SUPPORT.md and the site link to them (#412).
- Request wrapper classes are followed by the Java rules: a class of the project that keeps the servlet request in a field and returns its data from `String` methods (`wrapper.getTheParameter("x")`) adds those methods to the request sources; methods that do not use the request stay clean. On the OWASP Benchmark for Java with Opengrep, with #398, the average moves from 0.723 to 0.818 and every injection category finds all its vulnerable cases. With Semgrep CE, which cannot follow the wrapper's value within the calling method's helpers, cmdi, ldapi and xpathi lose up to 0.08 to false positives (#400).
- Weak hash and cipher algorithms named in a `.properties` file are found: when the Semgrep rules run, PandaWard writes an extra rule for each key whose value is a weak hash (MD5, SHA-1, ...) or cipher (DES, RC4, ECB, ...) that follows `getProperty("<key>")` to `MessageDigest.getInstance` or `Cipher.getInstance`. On the OWASP Benchmark for Java the hash and crypto categories reach 1.000 and the average with Opengrep moves from 0.723 to 0.774 (#398).
- The Python taint engine reports `pickle`, `yaml.load` and the other unsafe deserializers for any input it cannot show to come from constants (#406): request data with its flow, anything else as a hypothesis, as the pattern rule did. It tracks which values come from constants only, through operators, containers and functions that only transform their input (`base64`, `encode`, `format`, `unquote`), and replaces the deserialization pattern rule too. Decoders (`base64.b64decode`, `bytes.fromhex`, `zlib.decompress`, ...) undo what a check of the text allowed, since letters and digits decode to any payload. In a route without path parameters, `request.path` is the route's own path. A number, an escaped text or a value checked with `isalnum()` stays the client's data for the trust boundary: only a check that the whole value is one of a list of constants makes it trusted. On the OWASP Benchmark for Python, the taint engine alone and PandaWard as a scan runs it both score +1.000. On pgAdmin 4 the 32 `pickle.loads` of data the server stored itself are still reported, as hypotheses.
- In Python files the taint engine replaces the bundled Semgrep rules for the weaknesses it decides (#406), listed under `supersedes` in `rules/taint/python.yaml`. Rules for TLS verification and template injection stay, and so does the deserialization rule, since `pickle` and `yaml.load` run code from any input that is not a constant. The built-in heuristics stay for scans without Semgrep or Opengrep. On pgAdmin 4 the replaced rules reported 85 findings the engine does not; reviewed one by one, each was a false positive: XSS on JSON responses, redirects to `login_url(...)`, "path traversal" on string escaping, the session holding the application's own objects and shell calls with an argument list. The engine adds a language model's reply (`completion.choices[0].message.content`, `message.content[0].text`, `output_text`) as a source, as the bundled rules have it, and server-side request sinks (`requests`, `urllib.request.urlopen`, `httpx`), counts a helper of the project that returns nothing and raises on what it rejects (`check_access_permission(path)`) as a check of its arguments, accepts Django's `url_has_allowed_host_and_scheme` and werkzeug's `safe_join`, binds constant parameter defaults, and analyzes a nested function with its enclosing scope at the call (it saw an empty scope when called before the end of the analysis, and the result was reused). On the OWASP Benchmark for Python, PandaWard as a scan runs it moves from +0.893 to +0.972 (the taint engine alone scores +0.992; the difference is the deserialization rule's false positives on constant input). The OWASP benchmark's combined row applies the same replacement.
- The Python taint engine finds weak cryptography by data flow, not by one line (#406): a predictable number from the `random` module (not `secrets`) that reaches the session, a cookie value or a key, attribute or file named for a secret (`token`, `nonce`, `salt`, `csrf`, `remember`, ...); an MD5 or SHA-1 digest (`hashlib.md5`, `hashlib.sha1`, `hashlib.new('md5')`) stored under a password name or written to a file named for one; and `set_cookie` with `secure=False` or `httponly=False`. Names are compared word by word, so `author` is not `auth`. Taint kinds are now 32 bits wide. On the OWASP Benchmark for Python the taint engine alone moves from +0.778 to +0.992, with weak random, hash and insecure cookie at +1.000. On the local corpus it adds two findings: an OIDC nonce built with `random.sample` in a bundled library, and an MD5 password digest in pgAdmin 4.
- The Python taint engine follows calls across the modules of a project (#406, milestone P3). A call of a function, class or method the project defines is analyzed with the actual arguments, once per distinct arguments, up to four calls deep. Recursion ends, and the analysis of one module adds at most 2,000 distinct calls. Data a helper returns, a request a wrapper class keeps in `self` and reads in its methods, and a sink a helper reaches with what its caller passes are now followed. A flow into another file names the steps in each file. Imports resolve from the outermost package directory or, for a source root such as `src/` or `web/`, from the end of the file's path. Methods resolve through base classes. Values checked with `isalnum()` and similar checks, or with `x in [constants]`, are safe, so an escaping helper that keeps only allowed characters counts as one. A lookup such as `Model.query.filter_by(id=x).first()` or `d.get(x)` on data the request does not fill returns that data, not the key. On the OWASP Benchmark for Python the taint engine alone moves from +0.642 to +0.778, with every injection category between +0.944 and +1.000 and no false positive, and PandaWard as a scan runs it from +0.761 to +0.893. On pgAdmin 4 it reports 17 flows, among them paths from request JSON to `open` through the file manager's helpers.
- PandaWard's own data flow engine for Python (#406, milestone P2), with no other analyzer installed. Python files are lowered to a language-independent IR (`internal/taint/ir`): functions become control flow graphs, and `and`, `or` and `not` become branches. The analysis (`internal/taint/flow`) runs to a fixpoint over each function and tracks constants (`7 * 18 + num > 200`, `"ABC"[1]`, `match` on a constant), dict keys, list positions through `append` and `pop`, `ConfigParser` keys and module imports. Guards on branch edges make values safe: `'..' in x`, a resolved path checked with `startswith`, a quoted string literal checked before `eval`, `urlparse(x).netloc` in an allowlist and `replace("'", ...)`. Sources, sinks, sanitizers and guards for Flask, Django and FastAPI are data in `rules/taint/python.yaml`. It covers command, code, SQL, LDAP and XPath injection, deserialization, path traversal, XXE with external entities turned on, open redirects, session stores and HTML returned by a Flask view. Path parameters typed `<int:id>` or annotated `int` are not sources. A redirect, a session entry or a returned page counts only when the input reaches it as text, not as an object a helper built from it. It runs in the `builtin-taint` adapter next to the JavaScript engine. On the OWASP Benchmark for Python it scores +0.642 alone (built-in rules alone +0.015), with one false positive in the eleven injection categories; with the built-in rules and Opengrep, as a scan runs them, PandaWard moves from +0.637 to +0.761 and no category drops. On pgAdmin 4 it reports 11 flows, among them the `eval` of a request value fixed as CVE-2025-2945. `tools/pyflow` prints the flows or the IR of Python files. The OWASP benchmark counts the taint engine in the combined `pandaward` row when it is measured, and CI measures it for Python.
- A Python parser in pure Go (`internal/taint/py`), the first part of PandaWard's own data flow engine for Python (#406): Python 3.12 and 3.13 syntax including f-strings with nested format specs, `match`, type parameters, decorators, comprehensions, walrus and async. It keeps parsing after a syntax error, losing only the broken statement, and closes a bracket left open at the next statement. `tools/pyparse` measures it on real code: all 17,059 files of the Python 3.13 standard library, two `site-packages` trees and local projects parse without error, and on 14,901 of them every one of 8.47 million compared nodes sits where CPython's `ast` puts it. It produces no findings yet.
- A JavaScript, TypeScript and JSX parser in pure Go (`internal/taint/js`), the first part of the built-in taint engine (#347). It keeps parsing after a syntax error, losing only the broken statement, and skips type annotations, including Flow. `tools/jsparse` measures it on real code: 61,624 of 61,626 files in four `node_modules` trees and 99.8% of 31,555 application files parse without error. It produces no findings yet.
- The built-in taint engine follows data from a source to a dangerous call within a JavaScript or TypeScript file (#347): request objects and route handler parameters, browser URL globals and, in a published npm package, the parameters of exported functions, to shell commands, eval, file paths, SQL text, HTML output, server-side requests and redirects. Sources, sinks and sanitizers are data in `rules/taint/javascript.yaml`; a check that leaves the function on bad input counts as validation. Each finding shows the path from source to sink. It runs as the adapter `builtin-taint`, and the CVE benchmark measures it as the engine `taint`.
- The taint engine follows calls between the functions of a file: each function gets a summary of which parameters reach which sinks and its return value, applied where it is called, including methods called on `this`, fields set by constructors (also TypeScript parameter properties), prototype classes and hoisted function declarations. Redirect findings need a value that can choose the host: a parsed request URL, its `origin`, and text after a literal path such as `/api/?` do not count (#347).
- The taint engine covers more of what only the Semgrep rules found: path traversal through `http.createServer` handlers, helpers such as `serveStatic(req, res, path)`, `send(req, path)`, `fs.exists`/`stat`/`lstat`/`link` and archive entries (zip slip), with `..` checks and stripping as fixes; prototype pollution by shape (recursive merges and key-path walks without a `__proto__` check, not merges into a fresh copy); and cross-site scripting from socket messages, `res.status(...).send(...)`, jQuery selectors and plugin options, `execCommand('inserthtml')` and, in libraries, page text read back as HTML. Functions of the file named like sanitizers are judged by their code, not their name (#347).
- The taint engine reports incomplete escaping (a string `replace("'", ...)` or a regex without the `g` flag changes only the first match; removing `../`, `<script` or `<!--` in one pass can rebuild them) and URL checks that reject `javascript:` but not `data:`. In a library every such call counts; in an application only one applied to input from a source (#347).
- Prototype pollution shapes the taint engine now recognizes: a merge split over a function that walks the keys and a helper that descends and writes (`mixinDeep` and `mixin`, or a callback given to `forIn`), where checking only `__proto__` is not enough because `constructor.prototype` also leads to `Object.prototype`; index loops over `Object.keys`; and a write after a loop that only descends along a key path, reported from the descent to the write. A call named like a validator counts as a key check only when it is given the key, not `isObject(o[k])` (#390).
- The taint engine runs by default (#381). It runs with `builtin-code`, so configs written before it was a default get it too; `scan.taint_engine: false` turns it off. A retest re-runs it only when JavaScript, TypeScript or `package.json` files change. On the 9,736 files of the medusa repository it takes under 10 seconds. A taint finding replaces the `builtin-code` heuristic and the bundled Semgrep rule for the same control on the same line, so one flow is one finding with its path; Semgrep rules a project adds itself are kept.
- `.wrangler` (Cloudflare Wrangler build output) is excluded from the inventory by default (#381).
- The taint engine follows flows across files (#347): a call of a function another file of the project exports (`import`, `require`, `export ... from` re-exports, `module.exports` and `exports.name`, path aliases from `tsconfig.json` or `jsconfig.json`) uses that function's summary, so request data that a route handler passes to a helper module is found at the sink in the helper, with the steps in the caller's file named in the flow. A sink reached from several files is one finding. The analysis of a file is kept only while a file importing it still needs it. `list.push(x)` and `list.unshift(x)` carry `x` into the array, so markup built in a list and joined is followed, as a helper that renders a directory listing does. What a `sql` tagged template returns is no longer tainted by its parameters: a row looked up by a key from the request is the database's data, not the request's.
- The CVE benchmark counts the taint engine in the combined `pandaward` score when it is selected, since a scan runs it by default.
- Node.js scripts without an extension in a `bin` directory (`#!/usr/bin/env node`) are inventoried as JavaScript, so the code rules and the taint engine read package commands such as `bin/serve`. A package with a name and version but no `main` counts as a library when it has a root `index.js`, which npm then loads.

### Changed
- `pandaward doctor` lists the built-in taint engine and recommends Opengrep when it is not installed, and the `start` and `init` skills install or mention Opengrep rather than Semgrep for the bundled rules, matching the engine a scan prefers since #387 (#407).
- With both installed, Opengrep now runs the bundled Semgrep rules instead of Semgrep, because it follows taint through functions in the same file: on the OWASP Benchmark the bundled rules score 0.723 with Opengrep and 0.467 with Semgrep in Java, 0.530 and 0.433 in Python. `scan.semgrep_engine: semgrep` keeps Semgrep. Findings keep their identity, as the adapter is still `semgrep`. The OWASP benchmark tool reports the engine `pandaward` (built-in rules and the engine a scan picks) instead of `all`, which merged both Semgrep engines as no scan does (#387).

### Fixed
- The benchmark page could show an older measurement of main as the latest when two were taken on the same day, and listed a commit twice when it was both a committed snapshot and the site build's latest run. Snapshots now carry the time of the run and the commit in their label, and each commit is shown once (#402).
- The taint engine kept treating text decoded or parsed by `decodeURIComponent`, `querystring.parse`, `qs.parse`, `query-string` or `url.parse` as a value of the code's choosing, as it does for other functions from another module, and missed open redirects such as CVE-2019-18350, where the query string reaches `window.location.href` through a helper in another file (#388).
- Python rules: `pandaward-py-open-redirect` skips a redirect after a check that returns unless `urlparse(x).netloc` is in an allowlist; `pandaward-py-path-traversal` reports where a `pathlib` path is used rather than built, adds `os.path.exists` and the other `os.path` and `os` file system functions, and skips code after a check that returns on `'../'` in the name or a resolved path outside its base; a `ConfigParser` carries a value only to a read of the same key. Measured with Semgrep 1.182.1 on the OWASP Benchmark for Python: redirect +0.026 to +0.502, pathtraver +0.153 to +0.344, trustbound -0.029 to +0.129, average +0.433 to +0.514, no category lower (#394).
- `pandaward-py-eval` no longer reports `eval` after a check that returns unless the value is one quoted string literal (quote at both ends, none between), which can only evaluate to that string. On the OWASP Benchmark for Python this removes 12 of the 19 codeinj false positives with Semgrep (#392).
- The reason of a control that went stale or was raised by another collector no longer reads `was PASS: ...`, which the secret redaction took for a password assignment: reports showed `[REDACTED]` in it and a bundle export was refused. It now reads `was PASS, because ...`. The flow text of taint findings is redacted like other finding text (#381); each step is redacted on its own, so a long flow is no longer cut off at 240 characters.
- The taint engine no longer reports a loop that rewrites the keys an object already owns (`for (k of Object.keys(a)) a[k] = f(a[k])`) or a key path walk over a constant list of string paths as prototype pollution, nor `location.href = x || location.href` as an open redirect; a value taken out of the page URL, such as `location.href.split("next=")[1]`, is still reported (#381).
- Gitleaks no longer walks the directories `inventory.exclude` skips: PandaWard runs it with a config that extends the project's `.gitleaks.toml` or the default rules and allowlists those directories. A large `target` or `node_modules` directory made gitleaks outlast the adapter timeout and every assessment end incomplete; on this repository gitleaks went from 35 s to 2 s with the same findings (#374).
- The default `inventory.exclude` skips `bin`, the build output of .NET and Go, which also hid the commands of a Node.js package (`bin/www`, `bin/cli.js`, `bin/serve`). The files directly in a `bin` directory next to a `package.json` are now read; its subdirectories, where .NET writes `Debug` and `Release`, stay skipped, and findings of other tools in such a file are kept (#384).
- The taint engine lost a flow when one path of an `if`, loop or `switch` inside a callback assigned a variable of the enclosing function: the assignment replaced the value on every path. A test such as `if (x === '/') { x = '/index.html' }` no longer counts as a check of `x` on the other path (#384).
- A finding whose file was deleted, excluded or moved into a git-ignored directory is closed on the next scan even when its collector is skipped for lack of input files; infra and mobile findings stayed open as STALE before. The note says the file is no longer scanned (#372).

## [0.2.15] - 2026-11-11

### Added
- `code.json-in-script-unescaped` reports `JSON.stringify` output written into a script element without escaping `<`, which lets a value containing `</script>` end the element; it was a generic raw HTML finding before, now with its own message and one-line fix. The raw HTML rule follows ternaries, consts read around the sink, `await`, SVG from the `qrcode` library and imported constant scripts built only from constants (#352).
- Control D-007 finds regular expressions with catastrophic backtracking (ReDoS) in JavaScript and TypeScript: regex literals and `RegExp(...)` strings are analysed as automata. Exponential patterns are suspected findings; polynomial ones are listed as info, since they matter only for long input from outside. On the OpenSSF CVE Benchmark the built-in rules now detect 21 of 24 ReDoS CVEs, up from none, and recognize 17 fixes (#332).
- Opengrep can run the Semgrep rules: `scan.semgrep_engine` picks `semgrep` or `opengrep`; without it Semgrep is used and Opengrep is the fallback. Opengrep runs with intra-file taint. On Windows the tool home gets its own `LOCALAPPDATA`, without which Opengrep crashes (#314).
- `tools/owaspbench --engine builtin,semgrep,opengrep` measures the bundled Semgrep rules on both engines next to the built-in rules, with engine versions and the rule set hash; `docs/BENCHMARKS.md` has the new baseline (#314).
- `tools/owaspbench --suite python` measures PandaWard on OWASP BenchmarkPython (1,230 test cases, 14 categories), fetched at a pinned commit at run time; `docs/BENCHMARKS.md` has the first Python baseline (#315).
- `tools/cvebench` measures PandaWard on the OpenSSF CVE Benchmark: real CVEs in JavaScript and TypeScript projects, scored on the commit before and after each fix (detected, fix recognized, still flagged after the fix); `docs/BENCHMARKS.md` has the first JavaScript baseline (#316).
- Benchmark quality gates: the `benchmarks` workflow measures the OWASP Java and Python suites on every engine for pull requests that touch rules or engines, and the CVE benchmark weekly, and fails when a score drops below `tools/benchgate/baseline.json`. Rule fixtures run on Opengrep as well as Semgrep (#317).
- A benchmark page on pandaward.dev shows the latest results and the history per release, with links to the raw results and the commands to reproduce them. Each release gets `owasp-java.json`, `owasp-python.json` and `cve.json` attached (#318).
- pandaward.dev/benchmarks also shows the latest successful weekly or manual benchmark run of main, and is rebuilt when such a run finishes, so rule improvements appear before the next release (#335).
- `tools/cvebench` scores PandaWard as a whole, `pandaward`: the built-in rules plus Semgrep, as a scan runs them. pandaward.dev shows it first in the CVE table and the history (#341).

### Changed
- New JavaScript rule `pandaward-js-prototype-pollution-path` reports a loop that walks into an object along a path of keys (`o = o[k]`) and writes a key without checking for `__proto__` or `constructor`, the shape of path setters such as `set(obj, 'a.b', v)` and nested form field parsers (#365).
- JavaScript path traversal follows the path parameter of a helper that also takes the request and response, such as `serveStatic(req, res, path)`, and the router fields `req.pathname`, `req.urlBase`, `req.baseUrl`, `req.filename` and `req.filePath`; a containment check that leaves a loop with `break` or `continue` counts as a guard (#364).
- Fewer false positives on real code (#352): agent worktrees such as `.claude/worktrees/*` are skipped, which had doubled findings; `pandaward-js-sql-string` is replaced by the taint rule `pandaward-js-sql-injection`, which follows request data into query text and Supabase `.or()` filter strings and replaces the built-in SQL heuristics for JavaScript and TypeScript when Semgrep or Opengrep ran; the SSRF rule takes only the incoming request as a source; CORS needs credentials next to the wildcard; a disabled flag on a preference cookie and an OAuth callback that reads `code` and `state` through a local variable are no longer reported. On seven real application repositories the distinct findings at low severity or above went from 117, 3 of them real, to 29, 8 of them real: every reviewed real one is kept, and the SQL rule now finds a Supabase filter injection the old rules missed.
- The CVE benchmark runs in eight parallel shards, `tools/cvebench --shard i/n`, joined by `tools/cvebench merge` into the same `cve.json`, so a full run takes a fraction of the time (#355).
- JavaScript rules recognize fixes: path traversal is not reported after a check that compares the path with its root, tests it for `..` or calls `isPathInside` and stops the request, nor through `path.join('/', ...)` or a regular expression that removes `..`; a shell command is not reported after a regular expression test that stops on bad input; `innerHTML` is not reported for values passed through `DOMPurify.sanitize` or an escape function. On the OpenSSF CVE Benchmark Semgrep and Opengrep recognize 39 fixes instead of 27 and are still flagged after the fix in 18 CVEs instead of 33; three CVEs whose vulnerable commit already had a bypassable check (CVE-2018-3712, CVE-2018-3713, CVE-2018-3718) are no longer detected, and the baseline is lowered by those three (#345).
- JavaScript rules know more call shapes: `Function(...)` without `new`, `exec` wrapped by `util.promisify`, `execa.shell` and `execa.command`, and the new `pandaward-js-error-to-html` reports an error sent as the response body, which Express sends as HTML. On the OpenSSF CVE Benchmark this adds 6 detected CVEs and 1 recognized fix for Semgrep and Opengrep, with no CVE lost (#346).
- JavaScript rules for incomplete escaping and redirects: `pandaward-js-incomplete-sanitization` reports `replace()` calls that escape only the first match or remove a markup or traversal sequence in one pass, `pandaward-js-incomplete-url-scheme-check` reports `javascript:` checks that let `data:` through, and `pandaward-js-open-redirect` follows request data to redirects and `Location` headers. On the OpenSSF CVE Benchmark this adds 9 detected CVEs and 5 recognized fixes for Semgrep and Opengrep, with no CVE lost (#344).
- JavaScript rules for client-side XSS through jQuery: `pandaward-js-jquery-html` reports non-constant HTML passed to `.html()`, markup built by concatenation passed to `$()`, `.append()` and similar, `execCommand('insertHTML')` and `createElement` with concatenation; `pandaward-js-jquery-plugin-option` reports plugin options passed to `$()` or to a jQuery insertion method, as in the Bootstrap tooltip, collapse and affix CVEs. On the OpenSSF CVE Benchmark the Semgrep and Opengrep rules detect 69 CVEs instead of 60 and recognize 32 fixes instead of 27, with no CVE lost (#334).
- The CVE benchmark baseline is raised to the measurement of main after #330 and #332: built-in rules 45 CVEs detected and 28 fixes recognized, Semgrep and Opengrep 60 and 27, up from 23 and 10, and 13 and 6 (#339).
- `tools/cvebench` progress lines show how many CVEs are done, the elapsed time and an estimate of the time left, so a CI run can be followed in its live log (#337).
- JavaScript rules: `pandaward-js-prototype-pollution` reports recursive merges that write `target[key]` without a `__proto__` or own-property check; path traversal follows `req.url`, `req.path`, headers and cookies of Node, Express and Koa requests and archive entry names to `fs`, `send` and `fstream` sinks; the shell rule finds `child_process` exec under every import form and `shelljs`; `pandaward-js-reflected-xss` follows request data to `res.send`, `res.write` and `res.end`. On the OpenSSF CVE Benchmark the bundled rules detect several times more CVEs, with no CVE lost (#330).
- With Semgrep or Opengrep installed, Java and Python files no longer get findings from the built-in SQL, shell, eval, deserialization, weak hash and weak random heuristics: a bundled rule that decides the same weakness lists them in `pandaward-supersedes`, and its result counts instead. Controls say how many signals were replaced, and an open finding only a replaced heuristic raised is closed with a note. Without a completed Semgrep or Opengrep run nothing changes. On the OWASP Benchmark the merged Java SQL score goes from 0.027 to 0.282 and the Python command injection score from -0.154 to +0.626 (#328).
- Python rules follow Flask and Django request data, and the text a language model returns, to its sink: eval, OS command, SQL, file path, LDAP, XPath, XSS, open redirect, session and XXE are taint rules, with propagators through list, dict and config objects, and new rules for weak hashes, the `random` module and insecure cookies. `pandaward-py-sql-string` is now `pandaward-py-sql-injection`. On the OWASP Benchmark for Python the bundled rules score 0.530 on Opengrep and 0.433 on Semgrep, up from 0.059 and 0.039 (#326).
- Java rules follow request data to its sink: SQL, OS command, file path, LDAP, XPath, HTML response and session sinks are taint rules, with new rules for weak hashes, `java.util.Random`, insecure cookies and DES or Blowfish in any mode. Types are matched fully qualified as well as imported. `pandaward-java-sql-string` is now `pandaward-java-sql-injection`. On the OWASP Benchmark for Java the bundled rules score 0.723 on Opengrep and 0.467 on Semgrep, up from 0.000 (#324).
- In a git repository, directories git ignores and does not track are no longer scanned: the inventory line names them, results external scanners report there are dropped, and secrets gitleaks finds there stay listed as info. `inventory.include_ignored: true` scans them again (#312).

### Fixed
- Built with Go 1.27.4, which fixes GO-2026-6859 in `net/http` (#358).
- pandaward.dev/benchmarks published an older run of main right after a new one succeeded: the rebuild now takes the run that triggered it, and otherwise the newest successful run from the unfiltered listing (#353).
- The bundled JavaScript SQL rule no longer reports constants and numbers in template literals on Opengrep, which binds an interpolation with its `${...}` (#317).
- In Go files, a rule match inside a string literal is data: inside a `regexp` pattern it is dropped, inside other strings it is listed as info. Go SQL built only from literals and constants is no longer reported (#306).
- A-003 no longer compares routes from test and fixture files with the OpenAPI contract, so test servers do not raise `inventory.undeclared-route` findings or keep A-003 from passing (#310).

## [0.2.14] - 2026-11-08

### Added
- Runtime checks for the last undecided runtime controls in `pandaward test --profile staging-active` (#296):
  - G-002: `contract: {check: true}` sends every secured GET or HEAD operation of the OpenAPI contract without credentials and expects a denial (#297).
  - B-003: `flow_checks` replay login, reset and MFA flows with negative steps the server must refuse (#298).
  - F-002 and Q-002: `effect_checks` repeat an action in sequence or at once and check with a read-only probe that it took effect once (#299).
  - P-003: `llm_checks` send five built-in prompt-injection payloads in a data field and look for a canary only a model that obeyed them would produce (#300).
- State-changing requests (POST, PUT, PATCH, DELETE) as a separate opt-in: allowed only with `environment: staging` or `local`, sent only for flow, effect and LLM checks, and listed by `pandaward scope approve` (#298).
- Identity provisioning output can carry `inputs` for request bodies and headers, kept in memory only (#298).

### Fixed
- `innerHTML` and `outerHTML` assignments built from literals, constants and escape helpers, and Prisma `$queryRaw` tagged templates, are proven safe instead of reported (#295).

### Changed
- Built with Go 1.27.3; `go install` and source builds need Go 1.27 or later.
- modernc.org/sqlite 1.62.0.

## [0.2.13] - 2026-11-05

- Bump modernc.org/sqlite from 1.61.0 to 1.61.1 in the go-modules group (#237) by @dependabot[bot]
- Add attested verdicts for manual controls (#276)
- Draft scope manifests, provision test identities, name the ZAP install (#278)

## [0.2.12] - 2026-11-04

- Detect the wrong plugin variant before scanning (#266)
- Prove html-sink values safe and list file-only SQL builders as info (#267)
- Show how coverage was decided and a path to 100% (#268)
- Decide A-002 for Next.js apps from the file-system route table (#269)
- Drop osv results for packages an override replaces with local code (#270)
- Keep runtime verdicts across passive scans while they stay valid (#271)
- Explain scope approval input and test profiles in the CLI (#272)

## [0.2.11] - 2026-11-04

- Detect hidden and injected instructions in agent files and MCP tool descriptions (#254)
- Decide controls without signals a person dismissed as false positive (#251)
- Say what network scanners send, and offer the switch once (#250)
- Strip invisible tag and zero-width characters in Sanitize (#256)

## [0.2.10] - 2026-11-04

- Fix A-002 false negative on Next.js server actions (#169)
- Mask GitHub tokens glued to surrounding text (#236)
- Weight down low-confidence Semgrep registry rules (#238)
- Skip constant markup and fixed SQL choices in JavaScript rules (#239)
- Fix false positives in DB URL, PEM stub, workspace lockfile and OAuth callback checks (#241)
- Fix false positives in built-in code rules (#242)
- List placeholder-shaped gitleaks matches as info (#240)
- Flag floating tool installs and tag-only images in CI workflows (#243)
- Report CSPs that allow unsafe inline or eval scripts (#244)
- Flag RLS policies on privileged columns and tracked tool-local settings (#245)

## [0.2.9] - 2026-10-31

- Show scan progress with a percentage and the time left (#180)
- Offer false-positive reports only while the rule still fires (#185)
- Skip semgrep results in test and fixture code by default (#186)
- List gitleaks hits in untracked, git-ignored files as info (#187)
- Ask for the feedback mode wherever triage is recorded (#188)

## [0.2.8] - 2026-10-30

- Read the rule of a report from its table or title (#173)
- Check every documented pandaward command against the CLI (#174)
- Ask for feedback once and file grouped reports, including missed issues (#175)
- Let a human mark a fixed finding as remediated (#176)

## [0.2.7] - 2026-10-29

- Do not treat sign-in callbacks as webhooks (#162)
- Do not flag SQL built from constants in pandaward-js-sql-string (#165)
- Do not flag fetches to a fixed origin in pandaward-js-ssrf (#166)
- Apply inventory.exclude to every adapter's signals (#161)

## [0.2.6] - 2026-10-29

- Show live reviewer progress during the guided assessment (#154)

## [0.2.5] - 2026-10-29

- Keep finding identity stable across fixes and moved files (#150)

## [0.2.4] - 2026-10-29

- Mark releases latest, and build the hostile fixture's JSON with json.Marshal (#141)
- Remove the MobSF key after sanitizing, not only before (#145)
- Point links at pandaward.dev (#143)
- Say on the site that telemetry is opt-in, and name Go 1.26 (#147)

## [0.2.3] - 2026-10-29

- Bump pre-commit from 4.0.1 to 4.7.0 in /.github/requirements (#133) by @dependabot[bot]
- Bump modernc.org/sqlite from 1.34.5 to 1.61.0 in the go-modules group (#132) by @dependabot[bot]
- Bump the actions group with 10 updates (#134) by @dependabot[bot]
- Send opt-in telemetry to telemetry.pandaward.dev, off the command's path (#137)

## [0.2.2] - 2026-10-29

- Always skip the .pandaward and .pensec state directories (#120)
- Fix bundled Semgrep false positives and run the rule fixtures in CI (#122)
- Add an optional MobSF adapter for APK and IPA files (#118)
- Build with Go 1.26.10 and gate CI and releases on govulncheck (#126)
- Pin pre-commit by hash, add Dependabot, CodeQL and fuzz tests (#128)
- Add opt-in usage telemetry, off by default (#124)
- Stop overclaiming confidence on secrets and SQL templates (#131)

## [0.2.1] - 2026-10-28

- Stop the file walk once its deadline has passed (#113)
- Ship an MCPB bundle and server.json for the MCP Registry (#111)
- Publish a plugin-directory branch without binaries (#115)

## [0.2.0] - 2026-10-28

- Rename the project to Pandaward and release 0.2.0 (#108)

## [0.1.6] - 2026-10-28

### Upgrade notes
- Update the `pensec` CLI together with the plugin. 0.1.6 adds `runtime.android_package` and `runtime.ios_bundle_id` to `.pensec/config.yaml`; older binaries reject unknown keys. Existing files keep working.
- New configs list `apktool` in `scan.adapters`. To use it in an existing project, add `apktool` to that list.
- The catalog is now `2026.10-m4` with four new controls (K-004, K-005, L-003, L-004), so the first scan after the update does not carry results over from older assessments.

### Highlights
- Mobile source checks: credentials in plain SharedPreferences and world-readable storage (K-004), `get-task-allow` outside debug entitlements (L-003), `kSecAttrAccessibleAlways` and credentials in UserDefaults (L-004) (#14).
- Optional apktool adapter: `.apk` files in the project are decoded (resources only, the app's code is never run) and their manifest goes through the Android checks (K-005) (#14).
- `pensec test --profile local-runtime`: reads the configured test build's storage on an Android emulator (K-003) or in an iOS simulator on macOS (L-002) and reports credential-like keys by name, never their values. Real devices are refused; anything missing is `BLOCKED` with the reason (#14).
- The hostile-repository self-test runs in CI on every OS and before every release, and a new case checks that scanner output claiming confirmation stays a hypothesis (#15).
- Android sources under `com/example` in `src/main/` are no longer skipped as sample code (#101).

## [0.1.5] - 2026-10-28

### Upgrade notes
- Update the `pensec` CLI together with the plugin. 0.1.5 adds `runtime.zap_path` to `.pensec/config.yaml` and `zap`, `identities` and `authorization_checks` to `.pensec/scope.yaml`; older binaries reject unknown keys. Existing files keep working.
- Claude Code does not update third-party marketplaces unless auto-update is on: `/plugin`, Marketplaces, `pensec`, Enable auto-update. Or run `claude plugin marketplace update pensec` and `claude plugin update pensec-windows@pensec` (`pensec@pensec` on macOS and Linux), then restart.
- On Windows keep only `pensec-windows@pensec`. If `pensec@pensec` is also installed, the MCP server does not connect; see [Troubleshooting](https://github.com/ratomirjovanovic/pensec/wiki/Troubleshooting).

### Highlights
- `pensec test --profile staging-active` runs your installed ZAP (Java 17+) against approved staging or local targets: spider and passive scan for M-001, and the active scan for D-005 when the manifest sets `zap.active_scan: true`. Every ZAP request, including HTTPS, goes through the PenSec scope guard: origins, excluded paths, methods, request budget, rate limit and address checks, and a stop after three consecutive 429 or 5xx answers. A failed run is `ERROR`, a cut-short run `INCONCLUSIVE` (#13).
- Authorization checks with test identities: list identities (credentials come from environment variables and are never stored) and read-only checks in the scope manifest. Each check is sent as every identity and anonymously; object checks decide C-001 (BOLA), function checks C-002 and revoked identities B-004 (#12).
- `pensec doctor` shows whether ZAP is installed.
- Documentation for updating and uninstalling, with every file PenSec creates (#92).

## [0.1.4] - 2026-10-28

### Upgrade notes
- Update the `pensec` CLI (Homebrew, Scoop, release binary or `go install`) together with the plugin. `pensec init` from 0.1.4 writes a new `hooks` section to `.pensec/config.yaml`, and older binaries reject unknown config keys. Existing configs without the section keep working and get the default `hooks.auto_retest: true`.
- The Claude Code plugin now retests automatically after Claude edits code. Set `hooks.auto_retest: false` in `.pensec/config.yaml` to turn that off.

### Highlights
- Hands-free plugin: ask Claude to check the project's security or run `/pensec:start`. Claude runs the whole assessment, asks one question at the end and carries out what you choose, with a retest after every fix (#80).
- Automatic retest: a Stop hook retests the files edited in a turn, within 40 seconds, and hands new or reopened findings back to Claude. A clean retest stays silent (#82).
- `pensec findings apply --file decisions.json --by <name>` records many triage decisions in one transaction, and the plugin shows the whole list in one confirmation prompt (#83).
- The website shows the install commands for the visitor's platform (#87).

## [0.1.3] - 2026-10-28

- Clone plugin sources over HTTPS (#46)
- Report the module version for go install builds (#49)
- Update install instructions in README, website and VERIFYING.md (#50)
- Run OpenSSF Scorecard and show its badge (#63)
- Add pre-commit hooks (#60)
- Add Homebrew, Scoop and winget packages (#62)
- Add a GitHub Action (#59)
- Validate optional scanner adapters against real tool output (#67)
- Measure built-in rules on the OWASP Benchmark (#64)
- Add an animated terminal demo generated from a real session (#65)
- Collect false positive and false negative reports and prioritize rule fixes (#68)
- Import findings from SARIF files (#61)
- Add a guided assessment: pensec assess and /pensec:start (#70)

## [0.1.2] - 2026-10-28

- Freeze schemas and pin them with a golden test (#41)
- Declare the plugin MCP server inline and keep plugin branches byte-exact (#44)

## [0.1.1] - 2026-10-27

- Deterministic SBOM serial number for the release attestation (#39)


[Unreleased]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.15...HEAD
[0.2.15]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.14...v0.2.15
[0.2.14]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.13...v0.2.14
[0.2.13]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.12...v0.2.13
[0.2.12]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.11...v0.2.12
[0.2.11]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/ratomirjovanovic/pandaward/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ratomirjovanovic/pandaward/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ratomirjovanovic/pandaward/releases/tag/v0.1.1
