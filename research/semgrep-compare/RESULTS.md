# PandaWard against Semgrep OSS on VulnBench 2.0 (issue #544)

Protocol: [PROTOCOL.md](PROTOCOL.md), merged before the run. PandaWard at tag `semgrep-compare-freeze` (`bcc8b62`), built from source, built-in adapters only. Semgrep OSS 1.182.1 with `p/default`, `p/security-audit` and the pack of each project's language, rule packs fetched on 18 November 2026. VulnBench 2.0.0 at `385a3751046b62f30b61f9dfadb26d6d7dfc52aa`, 108 references in 20 applications. Per-reference results: `vulnbench-pandaward-refs.csv`, `vulnbench-semgrep-refs.csv`; references only one tool locates: `vulnbench-only.csv`. Scripts: `run_semgrep.py`, `compare.py`, and `../vulnbench/score.py`. The PHP part is a separate file, after its own run.

**Read this first.** VulnBench is no longer held out for PandaWard: the Go front end, NestJS and constructor-injection support and other changes were made after its first run with the misses in view (55 of 108 at the first run, 78 now). So the PandaWard column is a development number, not an independent one. Semgrep was not tuned on the suite.

## Result (located within 2 lines of a sink, any severity)

located
| group | refs | PandaWard (A) | Semgrep (B) | both (C) |
|---|---|---|---|---|
| all | 108 | 78/108 (63% to 80%) | 41/108 (29% to 47%) | 81/108 (66% to 82%) |
| Go | 32 | 31/32 (84% to 99%) | 12/32 (23% to 55%) | 31/32 (84% to 99%) |
| command-injection | 13 | 13/13 (77% to 100%) | 13/13 (77% to 100%) | 13/13 (77% to 100%) |
| sql-injection | 13 | 10/13 (50% to 92%) | 8/13 (36% to 82%) | 11/13 (58% to 96%) |
| ssrf | 9 | 7/9 (45% to 94%) | 0/9 (0% to 30%) | 7/9 (45% to 94%) |
| open-redirect | 11 | 10/11 (62% to 98%) | 4/11 (15% to 65%) | 11/11 (74% to 100%) |
| path-traversal | 16 | 15/16 (72% to 99%) | 2/16 (3% to 36%) | 15/16 (72% to 99%) |
| JavaScript/TypeScript | 30 | 12/30 (25% to 58%) | 6/30 (10% to 37%) | 14/30 (30% to 64%) |
| xss | 19 | 12/19 (41% to 81%) | 5/19 (12% to 49%) | 13/19 (46% to 85%) |
| prototype-pollution | 6 | 0/6 (0% to 39%) | 0/6 (0% to 39%) | 0/6 (0% to 39%) |
| redos | 3 | 0/3 (0% to 56%) | 0/3 (0% to 56%) | 0/3 (0% to 56%) |
| Java | 12 | 8/12 (39% to 86%) | 3/12 (9% to 53%) | 8/12 (39% to 86%) |
| template-injection | 4 | 2/4 (15% to 85%) | 0/4 (0% to 49%) | 2/4 (15% to 85%) |
| Python | 34 | 27/34 (63% to 90%) | 20/34 (42% to 74%) | 28/34 (66% to 92%) |
| insecure-deserialization | 5 | 5/5 (57% to 100%) | 5/5 (57% to 100%) | 5/5 (57% to 100%) |
| code-injection | 4 | 4/4 (51% to 100%) | 4/4 (51% to 100%) | 4/4 (51% to 100%) |
| mass-assignment | 2 | 0/2 (0% to 66%) | 0/2 (0% to 66%) | 0/2 (0% to 66%) |
| idor | 1 | 0/1 (0% to 79%) | 0/1 (0% to 79%) | 0/1 (0% to 79%) |
| improper-type-validation | 2 | 0/2 (0% to 66%) | 0/2 (0% to 66%) | 0/2 (0% to 66%) |

Totals: PandaWard alone 78 of 108, Semgrep alone 41 of 108, both together 81 of 108. At the same weakness class the two numbers are 74 and 41. At high or critical (Semgrep ERROR) PandaWard locates 74 and Semgrep 21.

## Where each tool wins

- Only PandaWard locates 40 references: 19 in Go (path traversal 5, SSRF 5, open redirect 4, SQL injection 2, template injection 2, XSS 1), 8 in Python (path traversal 5, SSRF 2, open redirect 1), 8 in JavaScript/TypeScript (XSS 4, open redirect 2, path traversal 1, SQL injection 1) and 5 in Java (XSS 3, path traversal 2). The list is in `vulnbench-only.csv`.
- Only Semgrep locates 3: `conduit-v2-sql-injection-search` (Python, `formatted-sql-query`), `app-project-saas-starter-lite-open-redirect-continue` (NestJS, `nestjs-open-redirect`) and `app-project-saas-starter-lite-xss-angular-render` (Angular `bypassSecurityTrust`). These are pattern rules that match a call without a data flow.
- Neither locates: prototype pollution (6), ReDoS (3), mass assignment (2), improper type validation (2), IDOR (1), and the remaining JavaScript/TypeScript and Java references. Closing these is the open work.
- Semgrep locates every command injection reference too (13 of 13), as PandaWard does.

## Noise

High or critical findings that match no reference, not judged because the applications have unlabelled vulnerabilities: PandaWard 31, Semgrep 36 (all ERROR findings).

## Tool failures and deviations

- Semgrep exited 0 on all 20 applications but reported parse errors in 10 of them, almost all in files that are not source code of the references (Dockerfiles, HTML templates, a workflow YAML). One is a TypeScript syntax it could not parse in `lastsaas` (`frontend/src/api/client.ts` line 125), which also had a Semgrep exit failure in the earlier default-configuration run.
- Deviation from the protocol: the resolved rule files were not saved, only the pack names. The registry changes, so this run cannot be reproduced exactly. Semgrep scanned with its default ignore rules (test directories are skipped), as PandaWard also skips tests.
- For Semgrep the class of a finding is taken from the CWE in the rule metadata (appended to the rule id by `run_semgrep.py`), so "same weakness" and "located" are almost the same number for it.
- One run per configuration; nothing was discarded.

## What this supports and what it does not

On this suite, PandaWard's engine locates about twice as many references as Semgrep OSS's public rule sets, and the references only PandaWard locates are mostly in classes that need a data flow from a request to a sink (path traversal, SSRF, open redirect, XSS). It does not support saying PandaWard is better than Semgrep in general: the suite is partly tuned for, the sets favor taint flows, and Semgrep Pro (with its interfile taint) was not run.
