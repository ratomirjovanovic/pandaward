# Benchmarks

PandaWard has two kinds of measurement:

- `pandaward benchmark` runs every built-in rule against PandaWard's own small corpus of vulnerable and safe cases (see the README). It checks that each rule does what it was written to do.
- The OWASP Benchmark measurements below run PandaWard against public, labelled evaluation projects that PandaWard's authors did not write, for Java and for Python: the built-in rules, and the bundled Semgrep rules on Semgrep and on Opengrep. They show how much of a known test suite each engine finds.

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
| PandaWard | source build of `main` at `3c896ba` plus the benchmark changes of #314 |
| Engines | built-in rules; Semgrep 1.182.1 and Opengrep 1.33.1 with the bundled rule set `b24cf8d85498e933...` |
| Date | 2026-11-09 |
| Tool | `tools/owaspbench` |

### Results

Average score over covered categories, and over all 11 categories with not covered categories counted as 0 (how the OWASP scorecard averages a tool):

| Engine | Covered categories | Average, covered | Average, all 11 |
|---|---|---|---|
| Built-in rules | 6 | -0.000 | -0.000 |
| Semgrep 1.182.1, bundled rules | 4 | 0.000 | 0.000 |
| Opengrep 1.33.1, bundled rules | 4 | 0.000 | 0.000 |
| All merged | 8 | -0.000 | -0.000 |

Per category, for the covered categories (TPR / FPR / score):

| Category | CWE | Real | Not real | Built-in | Semgrep and Opengrep (identical) |
|---|---|---|---|---|---|
| cmdi | 78 | 126 | 125 | 0.00 / 0.00 / 0.00 (`code.java-shell`) | 0.00 / 0.00 / 0.00 (`pandaward-java-command-exec`) |
| crypto | 327 | 130 | 116 | not covered | 0.00 / 0.00 / 0.00 (`pandaward-java-weak-cipher`) |
| hash | 328 | 129 | 107 | 0.00 / 0.00 / 0.00 (`code.weak-hash-password`) | not covered |
| pathtraver | 22 | 133 | 135 | not covered | 0.00 / 0.00 / 0.00 (`pandaward-java-path-traversal`) |
| securecookie | 614 | 36 | 31 | 0.00 / 0.00 / 0.00 (`code.cookie-flags-off`) | not covered |
| sqli | 89 | 272 | 232 | 0.886 / 0.888 / -0.002 (`code.sql-concat` and two more) | 0.00 / 0.00 / 0.00 (`pandaward-java-sql-string`) |
| weakrand | 330 | 218 | 275 | 0.00 / 0.00 / 0.00 (`code.insecure-random`) | not covered |
| xss | 79 | 246 | 209 | 0.00 / 0.00 / 0.00 (`code.html-sink`) | not covered |

ldapi, trustbound and xpathi have no rule in any engine.

The built-in rules reported 461 findings on the checkout: 447 `code.sql-concat` in test case files (241 in real and 206 in not real SQL injection cases), and 14 about the project's own CI workflows, Dockerfile, routes and a tracked key store. The bundled Semgrep rules reported one finding on either engine, a `pandaward-js-html-sink` in a JavaScript helper of the web UI, none in a test case.

### Interpretation

On this suite none of PandaWard's engines is better than not running them. That is the baseline the PandaWard 1.0 plan starts from; the target for 1.0 is a score of 0.50 or more in covered categories.

The reason is the same for every engine: no rule follows data from the request to the sink. The Benchmark moves input through variables, helper classes, collections and conditionals before it reaches the sink, and the safe variants differ from the vulnerable ones only in that data flow.

- Built-in rules are single-line regular expressions. `code.sql-concat` now matches the Benchmark's SQL concatenation (`"... PASSWORD='" + param + "'"`), so it flags 89% of the real cases and 89% of the safe ones alike: it sees the concatenation, not whether the concatenated value is attacker controlled. The other Java rules need the risky call and its argument on one line (`Runtime.getRuntime().exec(`, MD5 next to a password word, a weak random call next to a token name), which the test cases never write.
- The bundled Semgrep rules are mostly structural patterns. `pandaward-java-sql-string` requires the concatenation inside the call (`executeQuery("..." + x)`); the test cases build the SQL in a variable first. The two Java taint rules (path traversal and SSRF) model sources the Benchmark does not use. Opengrep's intra-file taint does not change this, because the rules themselves are patterns, and the two taint rules find no matching source.
- securecookie, xss and hash are matched by built-in rules written for other languages' idioms (configuration files, browser sinks, password hashing on one line), not for Java servlet code.

What this means for users: on Java server code, PandaWard's current rules should not be relied on for injection, crypto or randomness findings. The built-in rules remain useful for what the own corpus covers, such as CI, infrastructure, supply chain, secrets and the idioms they match in other languages.

Next: Java taint rules with servlet and Spring sources (PandaWard 1.0, Phase 2). Every change that targets the Benchmark reports its score next to the own-corpus results; tuning to a single suite overstates real-world accuracy.

## OWASP Benchmark for Python

The [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) is a Flask application with 1,230 test cases in 14 categories, one file per test case in `testcode/`, labelled in `expectedresults-0.1.csv`. It has four categories the Java suite lacks: code injection (CWE-94), deserialization (CWE-502), open redirect (CWE-601) and XXE (CWE-611). The suite is GPL-3.0; `run.sh --suite python` fetches it at a pinned commit at run time and it is never copied into this repository. The method is the same as for Java; only the `.py` file of a test case counts, not its HTML template.

| | |
|---|---|
| Benchmark | OWASP BenchmarkPython, commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, expected results 0.1 |
| PandaWard | source build of `main` at `3c896ba` plus #314 and #315 |
| Engines | built-in rules; Semgrep 1.182.1 and Opengrep 1.33.1 with the bundled rule set `b24cf8d85498e933...` |
| Date | 2026-11-09 |

### Results

| Engine | Covered categories | Average, covered | Average, all 14 |
|---|---|---|---|
| Built-in rules | 8 | +0.026 | +0.015 |
| Semgrep 1.182.1, bundled rules | 5 | +0.039 | +0.014 |
| Opengrep 1.33.1, bundled rules | 5 | +0.059 | +0.021 |
| All merged | 9 | +0.029 | +0.018 |

Per category, for the categories at least one engine covers (TPR / FPR / score):

| Category | CWE | Real | Not real | Built-in | Semgrep | Opengrep |
|---|---|---|---|---|---|---|
| cmdi | 78 | 13 | 7 | 0.54 / 1.00 / -0.462 | 0.54 / 1.00 / -0.462 | 0.54 / 1.00 / -0.462 |
| codeinj | 94 | 20 | 33 | 1.00 / 1.00 / 0.000 | 1.00 / 1.00 / 0.000 | 1.00 / 1.00 / 0.000 |
| deserialization | 502 | 18 | 36 | 1.00 / 0.33 / +0.667 | 1.00 / 0.33 / +0.667 | 1.00 / 0.33 / +0.667 |
| hash | 328 | 71 | 80 | 0.00 / 0.00 / 0.000 | not covered | not covered |
| pathtraver | 22 | 65 | 103 | not covered | 0.11 / 0.12 / -0.009 | 0.17 / 0.08 / +0.092 |
| securecookie | 614 | 24 | 15 | 0.00 / 0.00 / 0.000 | not covered | not covered |
| sqli | 89 | 5 | 11 | 0.00 / 0.00 / 0.000 | 0.00 / 0.00 / 0.000 | 0.00 / 0.00 / 0.000 |
| weakrand | 330 | 99 | 227 | 0.00 / 0.00 / 0.000 | not covered | not covered |
| xss | 79 | 31 | 58 | 0.00 / 0.00 / 0.000 | not covered | not covered |

ldapi, redirect, trustbound, xpathi and xxe have no rule in any engine.

### Interpretation

Python is the first suite where an engine is measurably better than not running it, but only in a few categories and far from the 1.0 target of 0.50.

- **Deserialization (+0.667)** is the one strong category: every real case calls `pickle` or `yaml.load`, and a third of the safe cases do too, with data that never comes from the request.
- **Code injection and command injection** show what a sink-only rule cannot do. The eval rules flag every `eval` and `exec`, real or safe (FPR 1.00). The shell rules flag every `shell=True` and `os.system`, which in this suite is all 7 safe cases and 7 of the 13 real ones, giving -0.462: the safe cases use the risky API with constant input.
- **Path traversal** is where data flow pays off: the bundled taint rule scores -0.009 on Semgrep, which follows taint within one function, and +0.092 on Opengrep with `--taint-intrafile`, which also follows it across functions in the same file. Same rule, same files, different engine.
- Hash, weak random, secure cookie, XSS and SQL injection need the risky call and its argument on one line or a framework source the rules do not model; they find nothing.

Next, for Phase 2: taint rules with Flask sources (`request.args`, `request.form`, `request.cookies`, `request.headers`) for eval, exec, subprocess, SQL and file paths, so the sink rules stop firing on constant input; and Opengrep as the reference engine, since it is the one that improves the same rules.
