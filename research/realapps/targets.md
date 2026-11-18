# Real-application scan: targets and pinned commits

Published before any scan, as #470 requires. The first round uses applications that are vulnerable by design, so the vulnerabilities are public, documented by their authors, and nothing here discloses anyone's unfixed bug. A second round on ordinary open-source projects will have its own list, published before its scan, and will follow each project's disclosure policy.

| Application | Language | Commit |
|---|---|---|
| juice-shop/juice-shop | TypeScript, JavaScript | 266448aba68cd8ba5915f526a128da4fa7bc3f9f |
| OWASP/WebGoat | Java | 5900119921433ecacbb02acde5ef0f2186d2626f |
| digininja/DVWA | PHP | 502ac150ce37c20ca6e04cab7c5ca959f315f2d0 |
| OWASP/NodeGoat | JavaScript | c5cb68a7084e4ae7dcc60e6a98768720a81841e8 |
| anxolerd/dvpwa | Python | 4a8f4a43fafcc1b304f1b97d0f0a8dea755a7756 |
| adeyosemanputra/pygoat | Python | 2aa4cc14f251e4a780e94e200aed6b36a5b15c21 |
| dolevf/Damn-Vulnerable-GraphQL-Application | Python | a961308c02d1fb462b192681c336b0739e432da7 |
| we45/Vulnerable-Flask-App | Python | b6a4f97afd466e83e1f60781494252dec1c37039 |

## Method

- Each application is checked out at its pinned commit outside this repository and scanned with `pandaward scan` (passive, default settings, optional scanners as installed). Nothing is run from the checkout.
- Every high and critical finding gets a verdict (true, false positive, or unclear) and a one-sentence reason. Verdicts are made by reading the cited code; an agent may propose a verdict, and only a human-checked verdict counts. A sample of the agent's verdicts is rechecked and its disagreements are reported.
- Published totals per application: findings, confirmed, false positives, unclear, and what the authors list as vulnerable that PandaWard did not report (misses), where the authors document it.
- These applications contain deliberate vulnerabilities, so a high finding is usually real. The numbers therefore show recall on known issues and the false positive rate on the remaining code, not general accuracy on ordinary software.
