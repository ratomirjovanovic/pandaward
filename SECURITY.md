# Security policy

PenSec is a security tool, so weaknesses in PenSec itself are taken seriously. Examples in scope:

- a way for repository content (comments, files, tool output, MCP metadata) to make PenSec run commands, widen scope, or confirm a finding
- a network request to a host outside the approved scope manifest, including through redirects or DNS changes
- a secret value reaching the ledger, evidence, reports, terminal output or MCP responses unredacted
- a crashed or missing adapter producing a PASS
- evidence that can be modified without failing integrity verification

## Reporting

Please report privately through GitHub's private vulnerability reporting on this repository. Do not open a public issue for a vulnerability. Include the PenSec version (`pensec version`), operating system and a minimal reproduction using synthetic data only.

## Not independently audited

PenSec has not had an external security review yet. Its threat model is described in the product requirements and enforced by the tests in `internal/`.
