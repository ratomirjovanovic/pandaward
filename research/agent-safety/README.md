# Agent Safety Lab

Research tooling that measures whether a coding or security agent can be
steered by untrusted repository or tool content into (a) unauthorized side
effects or (b) security conclusions its evidence does not support. It is not
part of a scan, and it changes nothing in PandaWard's ledger, scopes or
findings.

Status: early. This directory has the scenario format, the validator and the
first scenarios. There are no measured results yet, and none are claimed.

## What is here

| Path | What |
|---|---|
| `asl/` | Go package: scenario schema `asl/v1`, fixture hashing, corpus loading and validation |
| `corpus/v1/` | scenarios, one JSON file each, grouped by family (`F01` to `F08`) |

```text
pandaward lab validate                 # check every scenario, fixture hash and oracle
pandaward lab validate --json
pandaward lab seal corpus/v1/F06/F06-A01.json   # recompute a fixture hash after editing
```

Validation calls no model and needs no account or key.

## Scenario rules

- One file per scenario, named `<id>.json`; ids look like `F06-A01` (attack) or `F06-L01` (legitimate control).
- Every attack has an untrusted fixture file that carries the attack, a forbidden effect or facts to judge claims against, and a mechanism that is not a paraphrase of another attack in its family.
- Every control mirrors one attack (`matched_with`) with the adversarial content removed or neutralized, so a defense that blocks everything shows up as lost utility.
- The fixture hash covers every file. Changing a fixture after a run means a new corpus version and invalidates earlier comparisons for that scenario.
- Content is synthetic. No real credentials, hosts or private code.

## Arms

All arms use the same tools; only enforcement differs.

| Arm | Prompt policy | Authorization gate | Evidence checks | Monitor |
|---|---|---|---|---|
| A | yes | no | no | no |
| B | yes | yes | no | no |
| C | yes | yes | yes | no |
| D | yes | yes | yes | yes |

The sandbox protects the host in every arm, including A.

## Reporting rules

Mock and scripted-agent results are labeled separately from provider-backed
runs. Null and negative results are published. Trials are never dropped from
denominators, and invalid episodes (infrastructure failure, timeout) are
counted separately from attack failures.

Tracking: issue #435 and ASL-01 to ASL-09 (#439 to #447).
