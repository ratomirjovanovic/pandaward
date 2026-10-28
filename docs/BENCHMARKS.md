# Benchmarks

Pandaward has two measurements of its built-in rules:

- `pandaward benchmark` runs every rule against Pandaward's own small corpus of vulnerable and safe cases (see the README). It checks that each rule does what it was written to do.
- The OWASP Benchmark measurement below runs the built-in rules against a public, labelled evaluation project that Pandaward's authors did not write. It shows how much of a known test suite the line heuristics find.

## OWASP Benchmark for Java

The [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava) is a Java web application with 2,740 test cases in 11 categories. Each test case is one file, `BenchmarkTest#####.java`, and `expectedresults-1.2.csv` labels it as a real vulnerability or not, with its category and CWE. About half of the test cases in each category are deliberately not exploitable, so a tool that flags everything scores no better than one that flags nothing.

### How it is measured

```sh
sh tools/owaspbench/run.sh          # table
sh tools/owaspbench/run.sh --json   # JSON
```

`run.sh` fetches BenchmarkJava at a pinned commit into a temporary directory outside the repository and runs `go run ./tools/owaspbench --repo <checkout>`. The checkout is only read: no build script, Maven goal or other code from it is run. The tool:

1. walks the checkout with the same inventory settings as `pandaward scan` (default excludes and size limits);
2. runs the built-in adapters in process; optional third-party scanners (Semgrep, gitleaks, OSV-Scanner, Trivy) are not part of the measurement;
3. maps each finding to a test case by its file name, and to a Benchmark category by rule (explicit table) or, for rules not in the table, by CWE;
4. counts a test case as flagged when a finding of the test case's own category is in its file, as the OWASP scorecard does. Findings of another category in the same file are reported separately and do not change the matrix;
5. prints TP, FP, FN, TN, the true positive rate (TPR), the false positive rate (FPR) and the Benchmark score, TPR - FPR (Youden's index), per category.

A category with no mapped rule is shown as "not covered" rather than as a score of zero. The test case directory, `src/main/java/org/owasp/benchmark/testcode/`, is not treated as a test or fixture path, so the code heuristics do analyze every test case file (the tool checks and reports this).

| | |
|---|---|
| Benchmark | OWASP BenchmarkJava, commit `f40c618c5a709afce350ef06ed2899c85cf586e9`, expected results 1.2 |
| Pandaward | source build of commit `745a096` (main after release 0.1.2, same rules), built-in rules only |
| Date | 2026-10-28 |
| Tool | `tools/owaspbench` |

### Results

| Category | CWE | Real | Not real | TP | FP | FN | TN | TPR | FPR | Score | Pandaward rules |
|---|---|---|---|---|---|---|---|---|---|---|---|
| cmdi | 78 | 126 | 125 | 0 | 0 | 126 | 125 | 0.00 | 0.00 | 0.00 | `code.java-shell` |
| crypto | 327 | 130 | 116 | - | - | - | - | - | - | not covered | - |
| hash | 328 | 129 | 107 | 0 | 0 | 129 | 107 | 0.00 | 0.00 | 0.00 | `code.weak-hash-password` |
| ldapi | 90 | 27 | 32 | - | - | - | - | - | - | not covered | - |
| pathtraver | 22 | 133 | 135 | - | - | - | - | - | - | not covered | - |
| securecookie | 614 | 36 | 31 | 0 | 0 | 36 | 31 | 0.00 | 0.00 | 0.00 | `code.cookie-flags-off` |
| sqli | 89 | 272 | 232 | 0 | 0 | 272 | 232 | 0.00 | 0.00 | 0.00 | `code.sql-concat`, `code.sql-template`, `code.sql-unsafe-raw` |
| trustbound | 501 | 83 | 43 | - | - | - | - | - | - | not covered | - |
| weakrand | 330 | 218 | 275 | 0 | 0 | 218 | 275 | 0.00 | 0.00 | 0.00 | `code.insecure-random` |
| xpathi | 643 | 15 | 20 | - | - | - | - | - | - | not covered | - |
| xss | 79 | 246 | 209 | 0 | 0 | 246 | 209 | 0.00 | 0.00 | 0.00 | `code.html-sink` |

Average score: 0.00 over the 6 covered categories, and 0.00 over all 11 categories when not covered categories count as 0, which is how the OWASP scorecard averages a tool.

The built-in rules produced 14 findings on the whole checkout, none of them in a test case file. They are about the project's own CI workflows, Dockerfile, routes and a tracked key store, plus one `code.html-sink` in a JavaScript helper of the web UI.

### Interpretation

Pandaward's built-in code rules find nothing in the OWASP Benchmark. They also raise no false alarms on it, but a score of zero is a score of zero: on this suite the rules are no better than not running them.

The reason is the design of the rules, not a bug in the measurement. The built-in code checks are single-line regular expressions that look for well-known risky idioms, mostly in JavaScript, Python, PHP, Ruby and Go. The Benchmark is written to defeat exactly that kind of check: every test case moves the input through variables, helper classes, collections and conditionals before it reaches the sink, and the safe variants differ from the vulnerable ones only in that data flow. Telling them apart needs inter-procedural taint tracking, which Pandaward does not do. Concretely:

- cmdi: the rule looks for `Runtime.getRuntime().exec(` on one line. The test cases store the runtime in a variable and call `r.exec(...)` later, or use `ProcessBuilder`.
- sqli: the rules look for a quoted SQL statement followed by concatenation. The Benchmark's statements end in a quote inside the literal (`... PASSWORD='" + param + "'"`), which the rule's pattern does not cross, and many cases go through prepared statements, stored procedures or Spring's `JdbcTemplate`.
- hash: the rule needs MD5 or SHA-1 and a password-like word on the same line. The test cases call `MessageDigest.getInstance(...)` with the algorithm from a variable or a properties file.
- weakrand: the rule needs a weak random call and a security-like name (token, secret, session, ...) on the same line. The test cases call `java.util.Random` or `Math.random()` and use the value on later lines.
- securecookie: the rule matches configuration such as `secure: false` or `SESSION_COOKIE_SECURE = False`, not Java's `cookie.setSecure(false)`.
- xss: the rule matches browser and template sinks (`innerHTML`, `v-html`, `|safe`, ...), not servlet output through `response.getWriter()`.
- crypto (weak ciphers), ldapi, pathtraver, trustbound and xpathi have no built-in rule at all.

What this means for users: on Java server code, Pandaward's built-in rules should not be relied on for injection, crypto or randomness findings. Run Semgrep or another data flow aware analyzer through Pandaward's optional adapters for that. The built-in rules remain useful for what the own corpus covers, such as CI, infrastructure, supply chain, secrets and the idioms they match in other languages.

These numbers are a baseline. The rules were not changed for this measurement; any future change that targets the Benchmark should report its score next to the own-corpus results, and keep in mind that tuning to a single suite overstates real-world accuracy.
