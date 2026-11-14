# Benchmarks

Current and past results are on [pandaward.dev/benchmarks](https://pandaward.dev/benchmarks/), with links to the raw JSON of each measurement: the results attached to each release, and the latest successful weekly or manual `benchmarks` run on main, which rebuilds the page when it finishes. This page explains the method.

PandaWard has two kinds of measurement:

- `pandaward benchmark` runs every built-in rule against PandaWard's own small corpus of vulnerable and safe cases (see the README). It checks that each rule does what it was written to do.
- The OWASP Benchmark measurements below run PandaWard against public, labelled evaluation projects that PandaWard's authors did not write, for Java and for Python: the built-in rules, and the bundled Semgrep rules on Semgrep and on Opengrep. They show how much of a known test suite each engine finds.
- The OpenSSF CVE Benchmark measurement runs the same engines on real JavaScript and TypeScript projects at the commit before and after a published CVE was fixed.

## Quality gates

The numbers below are guarded so they cannot drop unnoticed:

| Gate | Runs on | Fails when |
|---|---|---|
| Own corpus (`pandaward benchmark --strict`) | every pull request | any built-in rule misses a vulnerable case or fires on a safe one |
| Rule fixtures (`ruleid:` and `ok:` per bundled Semgrep rule) | every pull request | a rule lacks either kind of fixture |
| Fixtures on Semgrep and Opengrep (`real-tools` job) | every pull request | either engine disagrees with a fixture annotation |
| OWASP Java and Python on all engines (`benchmarks` workflow) | pull requests that touch rules, adapters, inventory or the benchmark tools; weekly | any average or per-category score drops below `tools/benchgate/baseline.json` |
| OpenSSF CVE Benchmark on all engines (`benchmarks` workflow) | weekly and on demand (about 20 minutes on GitHub Actions, in eight parallel shards merged by `tools/cvebench merge`) | fewer CVEs detected or fewer fixes recognized than the baseline |

The baseline is committed. A change that improves a score raises it in the same pull request with `go run ./tools/benchgate --update --owasp owasp-java.json --owasp owasp-python.json` (and `--cve cve.json`), using the JSON from the workflow's artifacts. A score may only go down through the same explicit change, with the reason in the pull request.

## Built-in heuristics and bundled rules

A scan with Semgrep or Opengrep installed runs both the built-in rules and the bundled Semgrep rules. For Java and Python, a bundled rule lists in its `pandaward-supersedes` metadata the built-in heuristics it replaces in files of its languages, for example `pandaward-java-sql-injection` replaces `code.sql-concat`. When the semgrep adapter completes, signals of those heuristics in those files are dropped: they do not decide a control, the control's reason says how many were replaced, and a finding only they raised is closed with a note naming the rule that replaced it. When Semgrep and Opengrep are missing or fail, the built-in rules report as before. In JavaScript and TypeScript only the SQL heuristics are replaced, by the taint rule `pandaward-js-sql-injection`: on real application code they reported dynamic SQL built from constants and identifier helpers (#352). The other JavaScript built-in rules stay, since they find more real CVEs than the bundled ones (see the CVE benchmark below).

## OWASP Benchmark for Java

The [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) is a Java web application with 2,740 test cases in 11 categories. Each test case is one file, `BenchmarkTest#####.java`, and `expectedresults-1.2.csv` labels it as a real vulnerability or not, with its category and CWE. About half of the test cases in each category are deliberately not exploitable, so a tool that flags everything scores no better than one that flags nothing.

### How it is measured

```sh
sh tools/owaspbench/run.sh                                     # Java, built-in rules, table
sh tools/owaspbench/run.sh --engine builtin,semgrep,opengrep   # every engine, plus all of them merged
sh tools/owaspbench/run.sh --suite python --engine semgrep     # Python
sh tools/owaspbench/run.sh --engine semgrep --json              # JSON
```

`run.sh` fetches BenchmarkJava at a pinned commit into a temporary directory outside the repository and runs `go run ./tools/owaspbench --repo <checkout>`. The checkout is only read: no build script, Maven goal or other code from it is run. The tool:

1. walks the checkout with the same inventory settings as `pandaward scan` (default excludes and size limits);
2. runs each selected engine in process: `builtin` runs the built-in adapters; `semgrep` and `opengrep` run PandaWard's bundled Semgrep rules (`rules/semgrep`) through the same adapter a scan uses, offline, with no project or registry rules. Opengrep runs with `--taint-intrafile`. An engine that is not installed is reported as not run, never as a score of zero;
3. maps each finding to a test case by its file name, and to a Benchmark category by rule (explicit table for built-in rules) or by the rule's CWE;
4. counts a test case as flagged when a finding of the test case's own category is in its file, as the OWASP scorecard does. Findings of another category in the same file are reported separately and do not change the matrix. In the merged `all` result a test case counts once, however many engines flag it;
5. prints TP, FP, FN, TN, the true positive rate (TPR), the false positive rate (FPR) and the Benchmark score, TPR - FPR (Youden's index), per category and engine, with each engine's version and the SHA-256 of the bundled Semgrep rule set.

A category with no rule for an engine is shown as "not covered" rather than as a score of zero. The test case directory, `src/main/java/org/owasp/benchmark/testcode/`, is not treated as a test or fixture path, so every test case file is analyzed (the tool checks and reports this).

| | |
|---|---|
| Benchmark | OWASP BenchmarkJava, commit `f40c618c5a709afce350ef06ed2899c85cf586e9`, expected results 1.2 |
| PandaWard | source build of the branch of #324 |
| Engines | built-in rules; Semgrep 1.182.1 and Opengrep 1.33.1 with the bundled rule set `0a90a20b7a589dd1...` |
| Date | 2026-11-09 |
| Tool | `tools/owaspbench` |

### Results

Average score over covered categories, and over all 11 categories with not covered categories counted as 0 (how the OWASP scorecard averages a tool):

| Engine | Covered categories | Average, covered | Average, all 11 |
|---|---|---|---|
| Built-in rules | 6 | -0.000 | -0.000 |
| Semgrep 1.182.1, bundled rules | 11 | 0.467 | 0.467 |
| Opengrep 1.33.1, bundled rules | 11 | 0.723 | 0.723 |
| All merged | 11 | 0.486 | 0.486 |

Per category (TPR / FPR / score):

| Category | CWE | Real | Not real | Built-in | Semgrep | Opengrep | Bundled rule |
|---|---|---|---|---|---|---|---|
| cmdi | 78 | 126 | 125 | 0.000 / 0.000 / 0.000 | 0.690 / 0.488 / 0.202 | 0.913 / 0.240 / 0.673 | `pandaward-java-command-exec` |
| crypto | 327 | 130 | 116 | not covered | 0.746 / 0.000 / 0.746 | 0.746 / 0.000 / 0.746 | `pandaward-java-weak-cipher` |
| hash | 328 | 129 | 107 | 0.000 / 0.000 / 0.000 | 0.690 / 0.000 / 0.690 | 0.690 / 0.000 / 0.690 | `pandaward-java-weak-hash` |
| ldapi | 90 | 27 | 32 | not covered | 0.852 / 0.562 / 0.289 | 0.889 / 0.219 / 0.670 | `pandaward-java-ldap-injection` |
| pathtraver | 22 | 133 | 135 | not covered | 0.835 / 0.681 / 0.153 | 0.887 / 0.326 / 0.561 | `pandaward-java-path-traversal` |
| securecookie | 614 | 36 | 31 | 0.000 / 0.000 / 0.000 | 1.000 / 0.000 / 1.000 | 1.000 / 0.000 / 1.000 | `pandaward-java-insecure-cookie` |
| sqli | 89 | 272 | 232 | 0.886 / 0.888 / -0.002 | 0.860 / 0.616 / 0.244 | 0.938 / 0.259 / 0.679 | `pandaward-java-sql-injection` |
| trustbound | 501 | 83 | 43 | not covered | 0.831 / 0.605 / 0.227 | 0.867 / 0.465 / 0.402 | `pandaward-java-trust-boundary` |
| weakrand | 330 | 218 | 275 | 0.000 / 0.000 / 0.000 | 1.000 / 0.000 / 1.000 | 1.000 / 0.000 / 1.000 | `pandaward-java-weak-random` |
| xpathi | 643 | 15 | 20 | not covered | 0.933 / 0.650 / 0.283 | 0.933 / 0.150 / 0.783 | `pandaward-java-xpath-injection` |
| xss | 79 | 246 | 209 | 0.000 / 0.000 / 0.000 | 0.821 / 0.517 / 0.304 | 0.894 / 0.144 / 0.751 | `pandaward-java-xss` |

"All merged" counts a test case as flagged when any engine flags it, after dropping the built-in heuristics a bundled rule replaces (as a scan does when Semgrep or Opengrep completes, #328). Semgrep's extra findings still pull it below Opengrep alone; a scan runs one of the two, so this row is a lower bound, not a configuration anyone runs.

### Interpretation

With the bundled rules on Opengrep, PandaWard is above the 0.50 target of the PandaWard 1.0 plan on this suite, and in every category except trust boundary (0.402). The first measurement (0.000 on every engine, before #324) failed for two reasons: no rule followed data from the request to the sink, and the patterns used short type names (`new File`, `Cipher.getInstance`) while the Benchmark writes them fully qualified.

- **Taint rules** (#324) follow request parameters, headers, cookies, the query string and the body to SQL, OS command, file path, LDAP, XPath, HTML response and session sinks, with the usual encoders as sanitizers. The Benchmark's safe variants that pass a constant, overwrite the input or take a branch decided by constant arithmetic are not reported.
- **Opengrep is ahead of Semgrep** on the injection categories because it follows taint through methods of the same file (`--taint-intrafile`); many test cases pass the input through a helper method or an inner class. Weak cipher, hash, random and cookie rules are patterns and score the same on both.
- **Every remaining false positive** on Opengrep comes from two Benchmark constructions: a value taken from a list by index after the tainted element was removed, and a `switch` on a character of a constant string. Telling those apart needs value tracking, not rules.
- **The remaining misses** are mostly test cases that read the request through a helper class in another file (`SeparateClassRequest`), which needs cross-file taint, and weak algorithms named in a properties file (`hashAlg1`, `cryptoAlg1`) rather than in the code.
- **The built-in rules** still score 0. They are single-line regular expressions; for Java injection, crypto and randomness findings, install Opengrep (see [Configuration](https://github.com/ratomirjovanovic/pandaward/wiki)).

Every rule has `ruleid` and `ok` fixtures in `rules/semgrep/java.java` that run on both engines, and the benchmark gate keeps these scores from dropping. The Benchmark is a synthetic suite; tuning to it alone overstates real-world accuracy, which is why the CVE benchmark below measures real projects.

## OWASP Benchmark for Python

The [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) is a Flask application with 1,230 test cases in 14 categories, one file per test case in `testcode/`, labelled in `expectedresults-0.1.csv`. It has four categories the Java suite lacks: code injection (CWE-94), deserialization (CWE-502), open redirect (CWE-601) and XXE (CWE-611). The suite is GPL-3.0; `run.sh --suite python` fetches it at a pinned commit at run time and it is never copied into this repository. The method is the same as for Java; only the `.py` file of a test case counts, not its HTML template.

| | |
|---|---|
| Benchmark | OWASP BenchmarkPython, commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, expected results 0.1 |
| PandaWard | source build of the branch of #326 |
| Engines | built-in rules; Semgrep 1.182.1 and Opengrep 1.33.1 with the bundled rule set `80c6c9438d2ad9f8...` |
| Date | 2026-11-10 |

### Results

| Engine | Covered categories | Average, covered | Average, all 14 |
|---|---|---|---|
| Built-in rules | 8 | +0.026 | +0.015 |
| Semgrep 1.182.1, bundled rules | 14 | +0.433 | +0.433 |
| Opengrep 1.33.1, bundled rules | 14 | +0.530 | +0.530 |
| All merged | 14 | +0.494 | +0.494 |

Per category (TPR / FPR / score):

| Category | CWE | Real | Not real | Built-in | Semgrep | Opengrep | Bundled rule |
|---|---|---|---|---|---|---|---|
| cmdi | 78 | 13 | 7 | 0.538 / 1.000 / -0.462 | 0.615 / 0.143 / +0.473 | 0.769 / 0.143 / +0.626 | `pandaward-py-shell` |
| codeinj | 94 | 20 | 33 | 1.000 / 1.000 / +0.000 | 0.600 / 0.576 / +0.024 | 0.600 / 0.515 / +0.085 | `pandaward-py-eval` |
| deserialization | 502 | 18 | 36 | 1.000 / 0.333 / +0.667 | 1.000 / 0.333 / +0.667 | 1.000 / 0.333 / +0.667 | `pandaward-py-unsafe-deserialization` |
| hash | 328 | 71 | 80 | 0.000 / 0.000 / +0.000 | 1.000 / 0.000 / +1.000 | 1.000 / 0.000 / +1.000 | `pandaward-py-weak-hash` |
| ldapi | 90 | 16 | 13 | not covered | 0.688 / 0.154 / +0.534 | 0.750 / 0.077 / +0.673 | `pandaward-py-ldap-injection` |
| pathtraver | 22 | 65 | 103 | not covered | 0.415 / 0.262 / +0.153 | 0.508 / 0.204 / +0.304 | `pandaward-py-path-traversal` |
| redirect | 601 | 13 | 21 | not covered | 0.692 / 0.667 / +0.026 | 0.769 / 0.571 / +0.198 | `pandaward-py-open-redirect` |
| securecookie | 614 | 24 | 15 | 0.000 / 0.000 / +0.000 | 1.000 / 0.000 / +1.000 | 1.000 / 0.000 / +1.000 | `pandaward-py-insecure-cookie` |
| sqli | 89 | 5 | 11 | 0.000 / 0.000 / +0.000 | 0.400 / 0.000 / +0.400 | 0.600 / 0.000 / +0.600 | `pandaward-py-sql-injection` |
| trustbound | 501 | 18 | 19 | not covered | 0.444 / 0.474 / -0.029 | 0.556 / 0.421 / +0.135 | `pandaward-py-trust-boundary` |
| weakrand | 330 | 99 | 227 | 0.000 / 0.000 / +0.000 | 1.000 / 0.000 / +1.000 | 1.000 / 0.000 / +1.000 | `pandaward-py-weak-random` |
| xpathi | 643 | 51 | 135 | not covered | 0.412 / 0.200 / +0.212 | 0.431 / 0.163 / +0.268 | `pandaward-py-xpath-injection` |
| xss | 79 | 31 | 58 | 0.000 / 0.000 / +0.000 | 0.419 / 0.241 / +0.178 | 0.613 / 0.172 / +0.440 | `pandaward-py-xss` |
| xxe | 611 | 8 | 20 | not covered | 0.625 / 0.200 / +0.425 | 0.625 / 0.200 / +0.425 | `pandaward-py-xxe` |

The first measurement (#315) was +0.059 on Opengrep and +0.039 on Semgrep, with five covered categories.

### Interpretation

With the bundled rules on Opengrep, PandaWard reaches the 0.50 target of the PandaWard 1.0 plan on this suite on average, from +0.059 before #326. It is well short of it in several categories.

- **Taint rules** (#326) follow Flask and Django request data (arguments, form, cookies, headers, query string, body) to eval and exec, OS commands, SQL, file paths, LDAP, XPath, the HTML a view returns, redirects, the session and XML parsing with external entities enabled. Propagators carry taint through `list.append`, `dict.update` and `ConfigParser.set`, which the Benchmark uses to hide input. The cmdi score moved from -0.462 to +0.626 because the rule no longer reports commands built from constants.
- **Hash, weak random and insecure cookie** are pattern rules and score 1.000.
- **Deserialization stays a pattern rule**: `pickle` and `yaml.load` run code from their input whatever its source, so every call is reported. A taint version scored lower (+0.528), because it missed cases where the input passes through a step the engines do not follow, and the gate rejected it.
- **The remaining misses** come mostly from three constructions: input read through a request wrapper class in another module (`helpers.separate_request`), which needs cross-file taint; string slices (`s[4:-17]`), through which neither engine propagates taint; and values passed through a configuration object.
- **The remaining false positives** come from the same value-dependent constructions as in Java: a `match` on a character of a constant string, a list element taken by index after a removal, and a dictionary read with a constant key. Code injection (+0.085) is low for another reason: two thirds of its safe cases check that the input is a plain string literal before calling `exec`, and a rule cannot model that check.
- **Opengrep leads Semgrep** (+0.530 against +0.433) for the same reason as in Java: it follows taint through functions in the same file.

## OpenSSF CVE Benchmark (JavaScript and TypeScript)

The [OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark) (MIT) lists 223 real CVEs in JavaScript and TypeScript projects. Each entry names the project, the commit before the fix, the commit with the fix, the vulnerable lines and the CWEs. OWASP has no labelled suite for Node.js; this one is real code, not written to test tools.

### How it is measured

```sh
sh tools/cvebench/run.sh --engine builtin,semgrep,opengrep          # table
sh tools/cvebench/run.sh --engine opengrep --cve CVE-2018-3721       # one CVE
sh tools/cvebench/run.sh --engine builtin --json                     # JSON
```

`run.sh` fetches the benchmark at a pinned commit and runs `go run ./tools/cvebench`. For every CVE the tool fetches the project at both commits (one commit each, depth 1) into a reusable work directory, with git hooks, LFS, symlinks and the user's git configuration off; nothing from a project is built, installed or run. It walks each checkout with the same inventory settings as `pandaward scan`, runs each engine and scores, following the benchmark's own reports:

- **detected**: a finding covers a labelled vulnerable line in the commit before the fix;
- **CWE match**: one of those findings carries one of the CVE's CWEs;
- **fix recognized**: a detecting rule reports fewer findings in the vulnerable files after the fix. Otherwise the CVE is **still flagged after the fix**, the fixed-commit false positive;
- **unavailable**: a commit could not be fetched or checked out (repository gone). Such CVEs are not scored.
- **PandaWard**: when the built-in engine and Semgrep or Opengrep are measured together, the built-in findings and the Semgrep findings (Opengrep's when Semgrep was not measured) are scored as one engine, `pandaward`, as a scan runs both. A CVE counts once when either finds it; the fix is recognized when one of the detecting rules reports fewer findings after it.

Each CVE's result is written to a journal in the work directory as soon as it is measured, so an interrupted run continues where it stopped.

| | |
|---|---|
| Benchmark | ossf-cve-benchmark, commit `91c59fd54b2b768c0f310bb0027d2ac59cdf74d4` |
| PandaWard | `main` at `597264a` (after #330 and #332), manual `benchmarks` run [42848766043](https://github.com/ratomirjovanovic/pandaward/actions/runs/42848766043) on GitHub Actions |
| Engines | built-in rules; Semgrep 1.182.0 and Opengrep 1.33.1 with the bundled rule set |
| CVEs | 223 entries, 2 not scorable (not published or incomplete), 2 unavailable, 219 scored |
| Date | 2026-11-10 |

### Results

| Engine | Detected | Detection rate | With CWE match | Fix recognized | Still flagged after fix |
|---|---|---|---|---|---|
| Built-in rules | 45 of 219 | 20.5% | 19 | 28 | 17 |
| Semgrep 1.182.0, bundled rules | 60 of 219 | 27.4% | 48 | 27 | 33 |
| Opengrep 1.33.1, bundled rules | 60 of 219 | 27.4% | 48 | 27 | 33 |

The first measurement (2026-11-09, before #330 and #332) was 23 detected and 10 fixes recognized for the built-in rules, and 13 and 6 for both Semgrep engines.

By the CVE's first CWE, for the classes with four or more CVEs (detected by built-in / Semgrep / Opengrep):

| CWE | CVEs | Built-in | Semgrep | Opengrep |
|---|---|---|---|---|
| CWE-78, OS command injection | 48 | 10 | 30 | 30 |
| CWE-79, cross-site scripting | 48 | 9 | 11 | 11 |
| CWE-22, path traversal | 29 | 0 | 16 | 16 |
| CWE-730, regular expression denial of service | 29 | 21 | 0 | 0 |
| CWE-94, code injection | 12 | 4 | 3 | 3 |
| CWE-116, improper encoding or escaping | 9 | 0 | 0 | 0 |
| CWE-20, improper input validation | 6 | 0 | 0 | 0 |
| CWE-89, SQL injection | 4 | 0 | 0 | 0 |
| CWE-601, open redirect | 4 | 0 | 0 | 0 |
| CWE-770, allocation without limits | 4 | 0 | 0 | 0 |

The detecting rules were `code.js-redos-polynomial` (18), `code.js-shell` (10), `code.html-sink` (9), `code.js-eval` (4) and `code.js-redos` (4) for the built-in rules, and `pandaward-js-shell-exec` (21), `pandaward-js-path-traversal` (16), `pandaward-js-prototype-pollution` (9), `pandaward-js-html-sink` (7), `pandaward-js-reflected-xss` (4) and `pandaward-js-eval` (3) for both Semgrep engines.

### Interpretation

PandaWard finds about one real JavaScript CVE in five with its built-in rules, and a bit more than one in four with its bundled Semgrep rules. The two sets overlap little: ReDoS is found only by the built-in check, path traversal and prototype pollution only by Semgrep rules.

- **Most of the gain is command injection, path traversal, prototype pollution and ReDoS.** The shell rule follows `child_process` under every import form, path traversal follows request URLs and archive entry names, and the ReDoS check analyses each regular expression as an automaton.
- **The fix is recognized in less than half of the Semgrep detections.** In 33 of 60, the rule still fires as often after the fix, and for path traversal no fix is recognized at all: the fixes normalize the path and check its prefix, or escape the value, and the rules do not yet treat those checks as sanitizers.
- **Opengrep and Semgrep give identical results** on this suite.
- **Classes still missed**: encoding and escaping (9), input validation (6), SQL injection, open redirect and unbounded allocation (4 each), and most cross-site scripting in browser code.

Next: count a CVE once for PandaWard as a whole (built-in rules plus Semgrep, as a scan runs them), sanitizers for the path, shell and HTML rules so fixes are recognized, and rules for incomplete escaping, URL scheme checks and open redirects.

### jQuery cross-site scripting rules

`pandaward-js-jquery-html` reports a non-constant value passed to jQuery's `.html()`, markup built by concatenation and passed to `$()`, `.append()` and the other insertion methods, `document.execCommand('insertHTML', ...)` and `document.createElement` with concatenation. An element built from a bare tag name (`$('<' + tag + '/>')`) holds no text and is not reported. `pandaward-js-jquery-plugin-option` reports a plugin option (`this.options.x`, `this._config.x`) passed to `$()` or to an insertion method, where jQuery parses a string that starts with `<` as HTML; the `template` option is markup by design and is not reported.

Measured with a full `benchmarks` run on the branch ([run 42848842483](https://github.com/ratomirjovanovic/pandaward/actions/runs/42848842483)) against main at `597264a` ([run 42848766043](https://github.com/ratomirjovanovic/pandaward/actions/runs/42848766043)):

| Engine | Detected | Fix recognized | Still flagged after fix |
|---|---|---|---|
| Semgrep and Opengrep, before | 60 | 27 | 33 |
| Semgrep and Opengrep, with these rules | 69 | 32 | 37 |

The nine new detections are CVE-2017-16043, CVE-2018-14040, CVE-2018-14042, CVE-2018-20676, CVE-2018-20677, CVE-2019-14862, CVE-2019-15482, CVE-2020-4051 and CVE-2020-7656; no CVE detected before was lost and the OWASP scores did not change. Four of the nine are still flagged after their fix: the fix escapes the value (`escapedName`) or guards the call (`options.target === DEFAULTS.target`), which a pattern rule cannot tell apart. On seven real application repositories the rules report nothing; they do not use jQuery, so this says little about precision on jQuery code.

### More call shapes

The eval rule also reports `Function(..., body)` without `new`; the shell rule reports `exec` wrapped by `util.promisify` and execa's `shell` and `command` helpers; `pandaward-js-error-to-html` reports an error parameter or caught error (or its `message`) sent as the response body, which Express sends as HTML.

Measured with a full `benchmarks` run on the branch ([run 42870636199](https://github.com/ratomirjovanovic/pandaward/actions/runs/42870636199)) against main at `597264a`: Semgrep and Opengrep detect 66 CVEs instead of 60 (CVE-2017-16226, CVE-2019-10759, CVE-2019-10776, CVE-2019-15478, CVE-2019-15479, CVE-2019-5414) and recognize 28 fixes instead of 27, with no CVE lost and the OWASP scores unchanged. Five of the six are still flagged after the fix. On seven real application repositories the rules report two `Function()` calls, both in one test file.

### Escaping, URL scheme and redirect rules

`pandaward-js-incomplete-sanitization` reports a `replace()` that escapes only the first match (a string pattern of one escape character, or a regular expression of escape characters without the g flag) or removes `<!--`, `<script` or `../` in a single pass. `pandaward-js-incomplete-url-scheme-check` reports a `javascript:` check with no `data:` check in the same condition. `pandaward-js-open-redirect` follows request data to `res.redirect`, `ctx.redirect`, `res.location` and a `Location` header.

Measured with a full `benchmarks` run on the branch ([run 42866055034](https://github.com/ratomirjovanovic/pandaward/actions/runs/42866055034)) against main at `597264a`, before the jQuery rules:

| Engine | Detected | Fix recognized | Still flagged after fix |
|---|---|---|---|
| Semgrep and Opengrep, before | 60 | 27 | 33 |
| Semgrep and Opengrep, with these rules | 69 | 32 | 37 |

The nine new detections are CVE-2017-1000427, CVE-2017-16082, CVE-2018-11615, CVE-2018-3743, CVE-2019-10775, CVE-2019-10785, CVE-2019-16763, CVE-2019-5423 and CVE-2019-9844; no CVE detected before was lost and the OWASP scores did not change. On seven real application repositories the rules report two lines, both real instances of the pattern: a single-character `replace("<", "&lt;")` in a test and a one-pass `<script>` removal.

### Recognizing fixes

Most fixes add a check rather than remove the sink, so a sink-only rule fires as often after the fix. The path traversal rule no longer reports a sink after a check that stops the request (`return` in the `if`): the path compared with its root (`indexOf`, `startsWith`), tested for `..` (`search`, a regular expression test), or passed to `isPathInside`; nor in the branch after an `allowPath`-style check. `path.join('/', name)`, `path.resolve('/', name)`, a regular expression that removes `..` and removing `..` in a `while` loop are sanitizers. The shell rule no longer reports a command after a regular expression test that stops on bad input, and `innerHTML` is not reported for values passed through `DOMPurify.sanitize` or an escape function.

Measured with a full `benchmarks` run on the branch ([run 42869647146](https://github.com/ratomirjovanovic/pandaward/actions/runs/42869647146)) against main at `597264a`:

| Engine | Detected | Fix recognized | Still flagged after fix |
|---|---|---|---|
| Semgrep and Opengrep, before | 60 | 27 | 33 |
| Semgrep and Opengrep, with these checks | 57 | 39 | 18 |

Twelve fixes are now recognized (CVE-2017-16029, CVE-2017-16107, CVE-2018-1002203, CVE-2018-11798, CVE-2018-16478, CVE-2018-16485, CVE-2018-19048, CVE-2018-20835, CVE-2018-3725, CVE-2018-3731, CVE-2019-10765, CVE-2019-10777). Three CVEs are no longer detected: CVE-2018-3712, CVE-2018-3713 and CVE-2018-3718 already had a containment check or a `..` removal in the vulnerable commit, bypassed through URL encoding or a path the check did not cover. A pattern rule cannot tell such a check from a correct one, so the trade is fewer findings on guarded code for those three; the CVE baseline is lowered by three detections for it. The OWASP scores did not change.

### Built-in ReDoS check

Control D-007 analyses every regex literal and every string passed to `RegExp(...)` in JavaScript and TypeScript files. The pattern becomes its position automaton; for each character the check looks for a repetition that can match a run of it in two ways (exponential, as in `^(a+)+$`) or for two repetitions over it in sequence, counting the implicit leading loop of an unanchored search (polynomial, as in `\s+$`), followed by a way for the match to fail. Exponential cases are suspected findings (`code.js-redos`). Polynomial cases are listed as info (`code.js-redos-polynomial`) and do not fail the control: they matter only when long input from outside reaches the pattern, which the check does not follow.

On the 24 CVEs of the benchmark whose first weakness is a regular expression, measured with `--engine builtin --cve <those ids>`:

| | CVEs |
|---|---|
| Scored | 24 |
| Detected | 21 (4 exponential, 17 polynomial) |
| Fix recognized | 17 |
| Still flagged after the fix | 4 |

The three misses report the regex where it is used, not where it is written (`CHARSET_RE.exec(...)`, `regexps[i].toString()`), or are in a YAML file. The CVEs list CWE-730, so the CWE match column stays 0; the check reports CWE-1333.

On seven real application repositories (about 5,000 JavaScript and TypeScript files) the check lists about 110 polynomial patterns, such as `/\/+$/` and the common `^[^\s@]+@[^\s@]+\.[^\s@]+$` email check, and one exponential pattern, in a test file that the built-in rules skip.

### Built-in taint engine

The built-in taint engine (#347, adapter `builtin-taint`, enabled by default since #381; `scan.taint_engine: false` turns it off) follows data from a source to a sink, across the files of the project since M2 of #347: request objects and route handler parameters, browser URL globals and, in a published npm package, the parameters of exported functions. The CVE benchmark measures it as the engine `taint` (`--engine taint`).

`tools/taintcve` is the development check: it analyzes only the labelled files of each CVE, fetched beforehand at both commits, and scores them the same way. The engine follows calls between the functions of a file through per-function summaries (which parameters reach which sinks and the return value), including methods called on `this` and fields a constructor sets. Beyond flows from a source it checks the shape of prototype pollution (a recursive merge or a walk along a key path that writes a key without skipping `__proto__`).

| | CVEs detected | fixes recognized |
|---|---|---|
| intraprocedural only | 32 | 20 |
| with function summaries | 38 | 23 |
| with path, prototype pollution and browser XSS patterns | 56 | 37 |
| with incomplete escaping and URL scheme checks | 64 | 43 |

Compared with the full benchmark of `main` (run 43019314306) it adds 4 CVEs to the 116 the built-in rules and Semgrep find together, and recognizes 6 fixes they do not. Most of what Semgrep still finds alone is ReDoS (found by the built-in check, not by taint), jQuery plugin options and HTML written from values the engine cannot trace to a source.

On 10,220 application files of 46 local repositories it reports 12 findings: 8 open redirects, all real (`${origin}${next}` with `next` from the query string in Supabase auth callbacks, where `?next=@evil.example` leaves the site), and 4 prototype pollution shapes, two of them in a generated `.wrangler` directory and two in a message lookup whose keys come from the code. Each false positive seen while building it became a rule and a test. Since #381 `.wrangler` is excluded by default and walks over constant key paths are not reported, which leaves the 8 open redirects.

On third-party code checked out next to them (medusa, ollama, stripe-node and others) the first run reported 65 findings; 14 were loops rewriting an object's own keys in generated converters and 2 were redirects to the page's own URL, both fixed in #381. Those left are mostly real shapes (recursive merges and key path walks into shared objects, `res.send` of route parameters), some in internal utilities whose input the code controls.
