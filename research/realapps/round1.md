# Round 1: applications that are vulnerable by design

Targets and commits: [targets.md](targets.md), published before the scan. Scan: `pandaward scan` with default settings on the pinned commits, built from `main`. Every high and critical finding (112) has a verdict and a reason in [round1-findings.csv](round1-findings.csv).

## How the verdicts were made

An agent read each finding with the cited source and proposed a verdict. Every reason was then read, and 6 findings were opened in the source. The review changed 8 verdicts: one finding whose title does not match its line, one build-time task, and six fake or lesson-only values that are now "unclear". This is not a hand triage of every finding, so the numbers below are a first measurement, not the final one for #470.

## Results (high and critical findings)

| Application | Findings | True | False positive | Unclear |
|---|---|---|---|---|
| Juice Shop | 37 | 23 | 14 | 0 |
| WebGoat | 23 | 3 | 18 | 2 |
| DVWA | 15 | 10 | 5 | 0 |
| Vulnerable-Flask-App | 13 | 5 | 8 | 0 |
| pygoat | 11 | 4 | 3 | 4 |
| NodeGoat | 9 | 8 | 1 | 0 |
| dvpwa | 2 | 0 | 2 | 0 |
| DVGA | 2 | 1 | 0 | 1 |
| **All** | **112** | **54 (48%)** | **51 (46%)** | **7 (6%)** |

95 distinct locations carry the 112 findings: some lines are reported by two rules.

## What it says

- **Dynamic code evaluation is the problem.** 31 of the 37 findings of this kind are false positives (84%), and they are 31 of the 51 false positives overall. Almost all are `eval` in vendored or static browser code (Closure loader, Materialize, an old menu script, a packed DVWA challenge) where the string is a constant or built from numbers and page-defined ids. A high-severity finding needs a data flow from an untrusted source, not just the presence of `eval`.
- Real ones that were found: shell and SQL built from request data in DVWA and NodeGoat, `eval` of request fields in NodeGoat, hardcoded private keys and SQL injection in Juice Shop, `pickle.loads` and `yaml.load` on uploads, JWT verification switched off, the Docker socket mounted in pygoat's compose file.
- **One rule misfire:** in Vulnerable-Flask-App a TLS certificate finding sits on a JWT verification line.
- Juice Shop's code-fix snippet files hold vulnerable variants next to fixed ones, so findings in them are true for the snippet but not for the running route.

## What this does not show

- Recall: the authors' own lists of vulnerabilities were not compared with the findings, so misses are not counted yet.
- General accuracy: these applications are vulnerable on purpose, so a high finding is often real. Ordinary projects come in a second round with its own published list and the projects' disclosure policies.
- The sample of opened findings is small (6), so the verdicts of the agent that were not changed are still unverified in the source.

## Module-level recall on DVWA (#513)

DVWA has one directory per vulnerability. Before the PHP line rules, PandaWard reported findings in 7 of the 19 vulnerability directories and most of those were secret or HTML sink noise. The PHP rules (SQL built by variable interpolation, request input in HTML, include and redirect from request input, uploads) bring that to findings in 16 of 19, with 35 new findings, all in the low, medium and high levels and none in the `impossible` level, which is the safe version. The three directories without a finding are file inclusion (the request variable is set in one file and included in another), cryptography and weak session ids. Findings are hypotheses at high or medium; they were checked by reading a few of them, not all 35. Stored XSS, CSRF, brute force and access control are not decided by a line rule; they need a PHP data flow front end.

## NodeGoat and dvpwa recall check (#515)

NodeGoat documents injection and XSS; PandaWard reported neither. Two rules were added: a MongoDB `$where` built from a string with variables (silent when every variable is set from a numeric conversion in the same file) and a template engine configured with autoescape off. Rescanned: NodeGoat reports the `$where` at `app/data/allocations-dao.js` line 78 (line 73 is silent because both values are parsed as integers) and `autoescape: false` at `server.js` line 137; Juice Shop reports two known NoSQL injection routes; dvpwa reports its `autoescape=False`. The new rules gave no other finding on the five applications rescanned (NodeGoat, Juice Shop, WebGoat, pygoat, dvpwa).

## pygoat and WebGoat recall check (#470)

The authors' own lists are the lab directories of pygoat (`dockerized_labs/`, 21 labs) and the lesson classes of the WebGoat checkout (78 files under `lessons/`, of which about 70 are real lessons). A lab or lesson counts as found when PandaWard reports a code-level finding in its source (a taint flow, a code rule or a Semgrep rule; secrets, container, lockfile and HTML-sink findings do not count).

| Application | Labs or lessons | With a code-level finding |
|---|---|---|
| pygoat | 21 | 8 |
| WebGoat | about 70 | 5 |

- **pygoat, a bug found by this check.** Python files that share a module name (the `app.py` of every lab, no package around them) were analyzed once, so the taint engine reported 2 flows on 116 files. Analyzing each file separately (#517) gives 10 flows: SQL injection, command and code injection, SSRF, path traversal and insecure deserialization labs now have a finding. The XXE lab was missed because its parser is passed by keyword to `xml.dom.pulldom`; that is fixed in #519 (11 flows, the XXE lab has a finding).
- **pygoat, still missed:** broken authentication and access control, cryptographic failure, insufficient logging, template injection (the lab is patched in this version), security misconfiguration and several dependency labs. These are design or configuration lessons that no line rule or data flow decides.
- **WebGoat, still missed:** the SQL, command, XPath and XML injection lessons and the XSS lessons. The checkout is the old Servlet and ECS version: input arrives through `s.getParser().getRawParameter(...)`, is kept in a field and used in another method. That accessor is not a known source, and the Java taint engine does not follow a field across methods. The line rule for SQL built by concatenation does fire on these lines, but it is dropped on purpose: when Semgrep completes, the bundled taint rule `pandaward-java-sql-injection` replaces it (to keep precision on the OWASP Java suite), and that rule only knows standard servlet sources. Adding the accessor as a source for this one application would raise the number without making PandaWard better on other code, so it was not done.
- These counts are of labs and lessons with at least one finding, not of vulnerabilities, and the findings were not each read in the source.

## Dynamic code evaluation after #509

Rescanning the eight applications with the rules from #512 and #524 and comparing against the round 1 verdicts: of the high findings for dynamic code evaluation that round 1 judged false, 2 remain (both on one line, `eval(ma)` in WebGoat `menu_system.js`, a value kept in a variable assigned from other strings), down from 31 in the published scan; the true ones are unchanged (10 findings in the same rescan). Shapes that are now lowered: constant text, text built from numbers and Math or Date, a property only ever set to a safe value, a call written as text with variables spliced in (low, not high), packed files, and a timer call that is only text. A value that comes from a parameter, client input or a response body stays high. These are the same eight applications the rules were tuned on, so this is not a measurement on unseen code.

## PHP taint front end on DVWA (#513)

PandaWard now has its own PHP parser and data flow in front of the shared engine (a first version). On DVWA (pinned commit, 168 PHP files, none skipped by the parser) it reports 40 flows: 12 path (file functions), 11 SQL, 8 command, 4 HTML, 3 redirect and 2 code. They add the flow from request input to the sink to findings the line rules already listed (SQL in sqli, sqli_blind, brute and bac, open redirect) and find the command injection of the exec module, which no line rule covered. Counted per module with at least one code-level finding (secret, container, lockfile and HTML-sink findings left out), 14 of the 19 vulnerability modules have one; this count is not the one of the PHP line rules above, which also counted lower-severity findings.

What it does not find, and why:
- reflected and stored XSS, file inclusion and CSRF: the DVWA source files only build `$html` or set `$file`, and the page that prints or includes it is `index.php`. Each file is analyzed alone, so these flows cross a file boundary the engine does not follow yet.
- cryptography, weak session ids, DOM XSS and the JavaScript module: no sink the engine knows.

False positives on the safe (`impossible`) level, two files: `exec/impossible.php` checks each array element with `is_numeric` before joining them, and the engine does not relate the check on `$octet[0]` to the later read of it; `upload/impossible.php` compares the file extension with constants and builds a random name, and the comparison is not understood as a guard. Both are findings that should not be there.
