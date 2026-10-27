# PenSec

Local, evidence-based application security assessment for your own projects. PenSec runs as a standalone Go CLI and as a Claude Code plugin (skills, read-only review agents, lifecycle hooks and a local MCP server).

PenSec is not a certified penetration test, attestation or guarantee that no vulnerabilities exist. It reports what was checked, how, with which evidence, and, just as important, what was not checked.

## Principles

- **Passive by default.** The `local-passive` profile reads the repository and sends no traffic to any target. Nothing in the repository is executed: no install scripts, Makefiles or build steps.
- **Network tests are human-authorized.** Anything that sends traffic needs `.pensec/scope.yaml` filled in by a person and approved with `pensec scope approve` from an interactive terminal. The approval is bound to the manifest's SHA-256 and expires. Redirects are never followed, and private, loopback and cloud metadata addresses are blocked at connection time.
- **Honest coverage.** Only PASS and FAIL are decisive. BLOCKED, UNSUPPORTED, SUSPECTED, INCONCLUSIVE, ERROR and STALE never count as secure. A crashed or missing scanner is reported as ERROR or BLOCKED, never as a clean result.
- **No AI-confirmed findings.** Model-proposed issues are stored as HYPOTHESIS. PenSec reads and redacts the cited lines itself; the model cannot supply evidence text.
- **Secrets stay secret.** Every snippet is redacted before it is stored, printed, reported or returned over MCP. `.env` and key files are recorded by name only, never read.
- **The ledger is the source of truth.** State lives in a local SQLite ledger (`.pensec/private/state.db`, gitignored). It survives context compaction and session restarts.
- **No telemetry, no account, no cloud backend.**

## What it checks today

| Domain | Automated (static, offline) | Needs review or runtime |
|---|---|---|
| A Inventory | file walk, route extraction (Express, Flask/FastAPI, Django, Go, Spring, Laravel, Rails, ASP.NET, Next.js), OpenAPI drift | threat model |
| B/C Identity, authorization | JWT `none`/unverified decode, cookie flags | BOLA/BFLA, session lifecycle (manual-assisted) |
| D Injection | eval, shell, SQL concatenation, unsafe deserialization | runtime probes (not implemented) |
| E Secrets, crypto | 16 high-specificity secret formats, tracked `.env`/key files, disabled TLS verification, weak hash/random | |
| G/H API, web | webhook signature presence, HTML sinks, CORS wildcard with credentials | security headers via `production-observe` |
| I Supply chain | missing lockfiles, npm install scripts, unpinned Python requirements, MCP config pinning | advisory DB via osv-scanner |
| J Infrastructure | Dockerfile root/unpinned base, privileged compose/Kubernetes, public Terraform storage and admin ports | trivy (optional) |
| K/L Mobile | Android manifest flags and exported components, iOS ATS | device runtime (not implemented) |
| N CI/CD | unpinned actions, script injection, `pull_request_target` checkout, missing token permissions | |
| P AI/MCP | model output reaching exec sinks, MCP config | prompt-injection tests (manual-assisted) |

Cross-domain edges (AB1, AD1, CG1, DG1, FG1, IN1, ...) are created only when both sides share concrete assets, and their status comes from the linked controls. Run `pensec capabilities` for the full catalog with adapter maturity. All adapters are currently `implemented_unvalidated`: they pass the fixture suite in this repository but have no published benchmark yet.

Optional scanners are used only when you installed them yourself: gitleaks, semgrep (local rules, or a registry pack with network allowed), osv-scanner and trivy (both need `scan.allow_tool_network: true` to download advisory data). They run with an argument array, a scrubbed environment without cloud or VCS tokens, a disposable HOME and a timeout.

## Install

Requires Go 1.23 or later.

```sh
go build -o bin/pensec ./cmd/pensec          # Linux/macOS
go build -o bin/pensec.exe ./cmd/pensec      # Windows
```

As a Claude Code plugin, from this directory:

```sh
claude --plugin-dir /path/to/pensec
```

or add it as a local marketplace with `/plugin marketplace add /path/to/pensec` and install `pensec`. The plugin expects the binary in `bin/`; Claude Code puts that directory on the Bash tool's PATH.

## Use

```sh
pensec init          # create .pensec/ and show the inventory
pensec plan          # applicable controls, gates, candidate edges
pensec scan          # passive scan; --fail-on high for CI gates (exit 4)
pensec findings      # open findings; findings show PSEC-0001
pensec fix-plan      # ordered remediation, nothing applied automatically
pensec retest        # changed files, re-scan, delta
pensec report        # HTML, Markdown, JSON, SARIF 2.1.0, CSV into .pensec/reports/
pensec graph --format mermaid
```

In Claude Code: `/pensec:init`, `/pensec:scan`, `/pensec:review` (read-only specialist agents record hypotheses), `/pensec:fix-plan`, `/pensec:report`. `/pensec:test` can only be started by you, not by the model.

Human decisions:

```sh
pensec findings false-positive PSEC-0007 --by "Jane" --note "constant input"
pensec findings accept-risk PSEC-0003 --by "Jane" --note "internal only" --expires 2027-03-01
pensec scope init      # then fill in .pensec/scope.yaml yourself
pensec scope approve --by "Jane"   # interactive terminal only
pensec test --profile production-observe
```

In Claude Code a PreToolUse hook asks you to confirm these commands, blocks edits to `.pensec/private/`, and asks before edits to the scope or config manifest.

## Layout

```
.claude-plugin/   plugin and marketplace manifests
skills/           /pensec:* commands
agents/           read-only review agents
hooks/            SessionStart, PreToolUse guard, PostToolUse invalidation, PreCompact
.mcp.json         local stdio MCP server (pensec mcp)
cmd/pensec/       CLI
internal/         engine, adapters, store, scope, redact, evidence, report, mcp, hooks
```

## Status

Early development (M0/M1 of the product requirements). Runtime profiles other than `production-observe` (staging-active, local-runtime, ZAP, emulator tests) are not implemented and are reported as UNSUPPORTED. Not independently audited.

## License

PenSec is free and open source software under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

You may use, study, modify and share it, including inside companies. If you distribute PenSec or a modified version, or let others use a modified version over a network (for example as a hosted scanning service), you must publish the complete corresponding source code under the same license. Commercial licensing for uses that cannot meet these terms is available from the copyright holder.

Third-party scanners that PenSec can call (gitleaks, semgrep, osv-scanner, trivy and others) keep their own licenses. The license does not apply to the projects you assess or to the reports PenSec produces about them.
