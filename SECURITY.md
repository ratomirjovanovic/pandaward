# Security policy

Pandaward is a security tool, so weaknesses in Pandaward itself are taken seriously. Examples in scope:

- a way for repository content (comments, files, tool output, MCP metadata) to make Pandaward run commands, widen scope, or confirm a finding
- a network request to a host outside the approved scope manifest, including through redirects or DNS changes
- a secret value reaching the ledger, evidence, reports, terminal output or MCP responses unredacted
- a crashed or missing adapter producing a PASS
- evidence that can be modified without failing integrity verification

## Supported versions

Only the latest release gets security fixes. Upgrade with `brew upgrade pandaward`, `scoop update pandaward` or a new binary from the [releases page](https://github.com/ratomirjovanovic/pandaward/releases).

## Reporting

Please report privately through [GitHub's private vulnerability reporting](https://github.com/ratomirjovanovic/pandaward/security/advisories/new). Do not open a public issue for a vulnerability. Include the Pandaward version (`pandaward version`), operating system and a minimal reproduction using synthetic data only.

You get a first answer within 7 days. A confirmed vulnerability is fixed in a new release and published as a [security advisory](https://github.com/ratomirjovanovic/pandaward/security/advisories) with credit to the reporter, unless they ask not to be named.

## Not independently audited

Pandaward has not had an external security review yet. Its threat model is described in the product requirements and enforced by the tests in `internal/`.

`pandaward selftest` (and the release-blocking test in `internal/adversarial`) runs a hostile fixture repository through the full pipeline. It checks that nothing in the repository is executed, that a shipped scope manifest or forged ledger approval never authorizes traffic, that repository text cannot confirm, waive or approve anything, and that terminal escapes and HTML are neutralized in every output. Passing shows those attempts failed; it is not a proof.
