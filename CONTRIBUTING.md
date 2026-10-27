# Contributing

Thanks for helping make PenSec better.

## Before you start

- Open or find an issue first and describe the problem, the proposal and how it will be verified.
- One branch per issue, named `<type>/<issue>-<short-description>` (for example `fix/12-redact-basic-auth`).
- Security problems in PenSec itself go through private reporting, see [SECURITY.md](SECURITY.md).

## Changes

- Run `gofmt -l .`, `go vet ./...`, `go test ./...` and `claude plugin validate .` before opening a pull request.
- Every new check needs a vulnerable fixture that triggers it and, where possible, a safe analog that does not.
- Security fixes include a failing regression test.
- Test data must be synthetic. Build secret-shaped values at runtime (see `internal/testfixture`), never commit real-looking credentials.
- A check may only report PASS when it actually decided the control. When in doubt, use BLOCKED, INCONCLUSIVE or SUSPECTED.

## License of contributions

PenSec is licensed under AGPL-3.0-only. By submitting a contribution you agree that it is licensed under AGPL-3.0-only, that you have the right to submit it, and that the copyright holder may also offer your contribution under a separate commercial license together with the rest of PenSec. If you cannot agree to the last point, say so in the pull request before it is merged.
