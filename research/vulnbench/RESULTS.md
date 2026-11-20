# Results on Snyk VulnBench 2.0 (issue #467)

Protocol: [PROTOCOL.md](PROTOCOL.md), merged before the run. PandaWard at the frozen commit `734bfa7fb33ad407ceb17098418f927ad61a0afa` (tag `vulnbench2-freeze`), suite 2.0.0 at `385a3751046b62f30b61f9dfadb26d6d7dfc52aa`, run on 18 November 2026, 108 references in 20 applications. Per-reference results are in `builtin-refs.csv` and `default-refs.csv`, high and critical code findings that match no reference in `*-unmatched.csv`, and the scorer is `score.py`.

PandaWard was not tuned on these applications. The OWASP Benchmark rows elsewhere in the documentation are development benchmarks, where the engines were built against the tests; this is the first number on code they never saw.

## Headline

Built-in only (`builtin-code` and `builtin-taint`): **55 of 108 references located (51%, 95% interval 42% to 60%)**, 51 of them with a rule of the right weakness class (47%, 38% to 57%). With Semgrep 1.182.1 installed beside it (the default configuration): 54 of 108 located and 50 with the right class. Semgrep adds nothing here; see below.

These are lower than the 1.000 on the OWASP Benchmarks, which is the reason for this measurement. Read the 51% as the honest figure for a built-in scan of real applications written by someone else, on a suite whose reference set comes from a commercial engine plus manual tracing.

## Built-in only

| group | references | located | same weakness | located at high or critical |
|---|---|---|---|---|
| all | 108 | 55/108 (42% to 60%) | 51/108 (38% to 57%) | 51/108 (38% to 57%) |
| Go | 32 | 9/32 (16% to 45%) | 7/32 (11% to 39%) | 7/32 (11% to 39%) |
| Java | 12 | 8/12 (39% to 86%) | 7/12 (32% to 81%) | 7/12 (32% to 81%) |
| JavaScript/TypeScript | 30 | 11/30 (22% to 54%) | 10/30 (19% to 51%) | 10/30 (19% to 51%) |
| Python | 34 | 27/34 (63% to 90%) | 27/34 (63% to 90%) | 27/34 (63% to 90%) |
| code-injection | 4 | 4/4 (51% to 100%) | 4/4 (51% to 100%) | 4/4 (51% to 100%) |
| command-injection | 13 | 12/13 (67% to 99%) | 12/13 (67% to 99%) | 12/13 (67% to 99%) |
| idor | 1 | 0/1 (0% to 79%) | 0/1 (0% to 79%) | 0/1 (0% to 79%) |
| improper-type-validation | 2 | 0/2 (0% to 66%) | 0/2 (0% to 66%) | 0/2 (0% to 66%) |
| insecure-deserialization | 5 | 5/5 (57% to 100%) | 5/5 (57% to 100%) | 5/5 (57% to 100%) |
| mass-assignment | 2 | 0/2 (0% to 66%) | 0/2 (0% to 66%) | 0/2 (0% to 66%) |
| open-redirect | 11 | 6/11 (28% to 79%) | 6/11 (28% to 79%) | 6/11 (28% to 79%) |
| path-traversal | 16 | 10/16 (39% to 82%) | 10/16 (39% to 82%) | 10/16 (39% to 82%) |
| prototype-pollution | 6 | 0/6 (0% to 39%) | 0/6 (0% to 39%) | 0/6 (0% to 39%) |
| redos | 3 | 0/3 (0% to 56%) | 0/3 (0% to 56%) | 0/3 (0% to 56%) |
| sql-injection | 13 | 6/13 (23% to 71%) | 6/13 (23% to 71%) | 6/13 (23% to 71%) |
| ssrf | 9 | 2/9 (6% to 55%) | 2/9 (6% to 55%) | 2/9 (6% to 55%) |
| template-injection | 4 | 0/4 (0% to 49%) | 0/4 (0% to 49%) | 0/4 (0% to 49%) |
| xss | 19 | 10/19 (32% to 73%) | 6/19 (15% to 54%) | 6/19 (15% to 54%) |
unmatched high or critical code findings: 25

## Default configuration with Semgrep

| group | references | located | same weakness | located at high or critical |
|---|---|---|---|---|
| all | 108 | 54/108 (41% to 59%) | 50/108 (37% to 56%) | 49/108 (36% to 55%) |
| Go | 32 | 9/32 (16% to 45%) | 7/32 (11% to 39%) | 7/32 (11% to 39%) |
| Java | 12 | 7/12 (32% to 81%) | 6/12 (25% to 75%) | 6/12 (25% to 75%) |
| JavaScript/TypeScript | 30 | 11/30 (22% to 54%) | 10/30 (19% to 51%) | 10/30 (19% to 51%) |
| Python | 34 | 27/34 (63% to 90%) | 27/34 (63% to 90%) | 26/34 (60% to 88%) |

The two configurations differ on three references. Semgrep's rule `pandaward-js-reflected-xss` locates one that the built-in rules do not (`app1-xss-bank-profile-template-1`). Two that the built-in line rules locate are not located in the default configuration (`coffeeshop-sql-injection-1`, by `code.sql-concat`, and `app-project-saas-starter-lite-sql-injection-export-search`, by `code.sql-template`): in the default configuration a bundled Semgrep taint rule replaces the built-in line rule for the same weakness (supersession), and on these two it reports nothing near the sink. That is a defect of the supersession to look at; it is not changed here. On one Go application (`lastsaas`) Semgrep itself failed with exit code 7 and no output, which the scan reports as an adapter error, so the default figure has no Semgrep result for it.

## What is missed, and why

- **Go (9 of 32 located)**: PandaWard has no Go taint front end. The nine located references come from line rules and from the JavaScript front end on the JavaScript part of mixed projects: `code.go-shell` 5, `code.html-sink` 2, `code.sql-concat` 1 and `taint.js-open-redirect` 1. A line rule finds a sink without proving a flow. Go is the largest gap and the next language to build after PHP.
- **Prototype pollution (0 of 6), ReDoS (0 of 3), template injection (0 of 4), mass assignment (0 of 2), improper type validation (0 of 2), IDOR (0 of 1)**: PandaWard has rules for prototype pollution in a few merge and path-setter shapes and for ReDoS in JavaScript and TypeScript, and none for the other four classes. The 15 references in them are outside what the product claims to cover.
- **SQL injection, XSS and path traversal in Python, JavaScript and Java**: the remaining misses are flows the engine does not follow (through a framework helper, a template, a method it does not resolve) and sinks missing from the specification. They are listed per reference in the CSV; the causes are not yet classified one by one, and no cause is claimed for a miss that was not read.

## What was found beside the references

`builtin-unmatched.csv` has 25 high or critical code findings (secrets, containers and the supply chain left out) that match no reference. The reference list is not exhaustive and the suite does not say these are false positives, and none has been read yet, so none is counted as one here. The most frequent rules are `code.py-shell` (5), `taint.js-open-redirect` (4) and `code.sql-concat` (4).

## Limits of this measurement

- The match is looser than the suite's own rule: the sink must be within 2 lines of the reference's sink line, the source is not compared, and for the first figure any rule counts, so a line rule that happens to flag the same line counts. The second figure (right weakness class, decided by words in the rule id) is the one to quote.
- One run each, on 20 applications of which 7 are JavaScript or TypeScript projects and 6 are Go; the intervals are Wilson intervals on references that are not independent (several references share a file).
- The reference set was built with a commercial engine and manual tracing, so a finding that is real and not in it is not rewarded.
- A first attempt of the run stopped after two applications because the background job of my own harness was killed; it was discarded and the run was repeated from the start with the same binary and no change to the engine or the rules. Nothing else was repeated.

## Default configuration again, after the supersession fix (#533)

A development number, not held out: the suite has been used since the frozen run. Main at `a1fe9e9` (includes #555 supersession only where the replacing rule fired nearby, #563 and #565), built from source; Semgrep 1.182.1 on the PATH, no other change, one run on 20 applications, the same match rule. Files: `default-after-533-refs.csv`, `default-after-533-unmatched.csv`.

**91 of 108 references located (84%), 86 with a rule of the right weakness class, 85 at high or critical.** By language: Go 32/32, Python 30/34, JavaScript and TypeScript 21/30, Java 8/12.

The two references this issue named are located again in the default configuration: `coffeeshop-sql-injection-1` by `code.sql-concat` and `app-project-saas-starter-lite-sql-injection-export-search` by the taint rule `taint.js-sql-injection`. The default configuration now locates at least what the built-in only configuration does (89 on the same suite with an earlier main build; the two differ on `conduit-v2-sql-injection-search`, found by the Python taint engine, and `app1-xss-bank-profile-template-1`, found by the bundled Semgrep XSS rule). The frozen figures above (55 and 54) are unchanged.

The first attempt of this run reported zero for the first application because the report step failed; that application was repeated alone with the same binary and no other change.
