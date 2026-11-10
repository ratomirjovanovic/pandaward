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
| OpenSSF CVE Benchmark on all engines (`benchmarks` workflow) | weekly and on demand (it takes hours) | fewer CVEs detected or fewer fixes recognized than the baseline |

The baseline is committed. A change that improves a score raises it in the same pull request with `go run ./tools/benchgate --update --owasp owasp-java.json --owasp owasp-python.json` (and `--cve cve.json`), using the JSON from the workflow's artifacts. A score may only go down through the same explicit change, with the reason in the pull request.

## Built-in heuristics and bundled rules

A scan with Semgrep or Opengrep installed runs both the built-in rules and the bundled Semgrep rules. For Java and Python, a bundled rule lists in its `pandaward-supersedes` metadata the built-in heuristics it replaces in files of its languages, for example `pandaward-java-sql-injection` replaces `code.sql-concat`. When the semgrep adapter completes, signals of those heuristics in those files are dropped: they do not decide a control, the control's reason says how many were replaced, and a finding only they raised is closed with a note naming the rule that replaced it. When Semgrep and Opengrep are missing or fail, the built-in rules report as before. JavaScript keeps its built-in rules, which find more real CVEs than the bundled ones (see the CVE benchmark below).

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

Each CVE's result is written to a journal in the work directory as soon as it is measured, so an interrupted run continues where it stopped.

| | |
|---|---|
| Benchmark | ossf-cve-benchmark, commit `91c59fd54b2b768c0f310bb0027d2ac59cdf74d4` |
| PandaWard | source build of `main` at `84ebd1d` plus #316 |
| Engines | built-in rules; Semgrep 1.182.1 and Opengrep 1.33.1 with the bundled rule set `b24cf8d85498e933...` |
| CVEs | 223 entries, 2 not scorable (not published or incomplete), 2 unavailable, 219 scored |
| Date | 2026-11-09 |

### Results

| Engine | Detected | Detection rate | With CWE match | Fix recognized | Still flagged after fix |
|---|---|---|---|---|---|
| Built-in rules | 23 of 219 | 10.5% | 19 | 10 | 13 |
| Semgrep 1.182.1, bundled rules | 13 of 219 | 5.9% | 10 | 6 | 7 |
| Opengrep 1.33.1, bundled rules | 13 of 219 | 5.9% | 10 | 6 | 7 |

By the CVE's first CWE, for the classes with four or more CVEs (detected by built-in / Semgrep / Opengrep):

| CWE | CVEs | Built-in | Semgrep | Opengrep |
|---|---|---|---|---|
| CWE-78, OS command injection | 48 | 10 | 3 | 3 |
| CWE-79, cross-site scripting | 48 | 9 | 7 | 7 |
| CWE-22, path traversal | 29 | 0 | 0 | 0 |
| CWE-730, regular expression denial of service | 29 | 0 | 0 | 0 |
| CWE-94, code injection | 12 | 4 | 3 | 3 |
| CWE-116, improper encoding or escaping | 9 | 0 | 0 | 0 |
| CWE-20, improper input validation | 6 | 0 | 0 | 0 |
| CWE-89, SQL injection | 4 | 0 | 0 | 0 |
| CWE-601, open redirect | 4 | 0 | 0 | 0 |
| CWE-770, allocation without limits | 4 | 0 | 0 | 0 |

The detecting rules were `code.js-shell` (10), `code.html-sink` (9) and `code.js-eval` (4) for the built-in rules, and `pandaward-js-html-sink` (7), `pandaward-js-shell-exec` (3) and `pandaward-js-eval` (3) for both Semgrep engines.

### Interpretation

PandaWard finds about one real JavaScript CVE in ten with its built-in rules, and one in seventeen with its bundled Semgrep rules. Every detection is a sink rule (shell, HTML, eval) firing on the vulnerable line.

- **The fix is recognized in less than half of the detections.** In 13 of 23 built-in detections and 7 of 13 Semgrep detections, the rule still fires as often after the fix: the fix sanitizes or validates the input, and a sink-only rule cannot see that. Taint rules with sanitizers are the remedy.
- **Opengrep and Semgrep give identical results** on this suite. The JavaScript rules that detect anything are patterns, so `--taint-intrafile` has nothing to follow; unlike Python, no JavaScript taint rule fires on a vulnerable line.
- **Whole classes are missed**: path traversal (29 CVEs) and regular expression denial of service (29) have no detection at all, nor do encoding, validation, SQL injection and open redirect. Path traversal in library code needs taint from function parameters, not only from HTTP requests; ReDoS needs a regular expression analysis no engine here does.
- The built-in rules detect more than the bundled Semgrep rules (10 against 3 command injections) because the line rule `code.js-shell` accepts more call shapes than the structural Semgrep rule.

Next, for Phase 2: JavaScript taint rules with library sources (exported function parameters) and sanitizers for command, HTML and path sinks, and a ReDoS check. The CVE benchmark is the measure for them, since it is real code and also counts the fixed commit.

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
