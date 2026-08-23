# `secureflow-run-v1` contract

## Purpose

`secureflow-run-v1` is the local manifest for a SecureFlow run. It joins the
authorized scope, analysis provenance, produced artifacts, deterministic
candidates, prioritization, and human decision.

The contract does not contain complete source code. Exported locations are
repository-relative and artifacts are referenced by hash.

The normative schema is
[`schemas/secureflow-run-v1.schema.json`](../../schemas/secureflow-run-v1.schema.json).

## Normative principles

1. Every run has an explicit `target` and `authorization`.
2. Deterministic analysis occurs before any model call.
3. AI may only enrich or prioritize an existing candidate.
4. AI can never write `human_review.decision`.
5. Only `human_review.decision = validated` permits treating a candidate as a
   validated vulnerability.
6. The human researcher retains superior contextual judgment and final
   authority. SecureFlow cannot replace that authority and must abstain when
   evidence is insufficient.
7. `rejected` and `abstained` are valid outcomes, not errors.
8. Every material claim points to a location, artifact, or hash.
9. Exported paths are relative, POSIX, and contain no `..`.
10. A scanner failure, timeout, or invalid report never becomes "clean."
11. Secure Bench evaluation remains separate from production decisions and
    cannot inject expectations into analysis.

The CLI requires an authorization reviewer. Written consent, organization
policy, and other documented bases require a reference. Expired authorization
fails before the engine runs. These fields are auditable operator declarations,
not cryptographic signatures or automatic legal proof of permission.

## States

### Run

`created`, `running`, `completed`, `partial`, `failed`, `cancelled`.

### Human review

`pending`, `validated`, `rejected`, `abstained`.

`abstained` means that evidence is insufficient for a decision. It must count
as neither a vulnerability nor a clean control.

Local review creates a derived manifest. The review input is never implicitly
overwritten, and `review-run` cannot change an existing terminal decision.

### AI validation

`not_requested`, `queued`, `completed`, `failed`, `skipped`.

Its state is auxiliary and never replaces human review.

## Identity and reproducibility

- `run_id` identifies the run.
- `target.root_sha256` identifies analyzed tree bytes through
  `secureflow-target-sha256-v2`. The canonical stream separates type, count,
  and total bytes, and length-prefixes paths and content so distinct trees do
  not share the same pre-hash serialization. `.git` is excluded and every
  symlink fails closed.
- `target.revision` identifies the commit or snapshot when available.
- `engine.binary_sha256` identifies the exact binary.
- `engine.report_sha256` identifies the received report.
- `configuration_sha256` identifies the effective configuration.
- In the current adapter, that hash binds arguments, timeout, output limit,
  memory, CPU, and descriptor limits. It does not prove filesystem isolation.
- The CLI checks target and binary hashes before and after the process. If
  either changes, it fails without writing the report or manifest. This is
  fail-closed detection, not a transactional snapshot; a change reverted
  between measurements may remain undetected.
- Derived outputs cannot alias their inputs. Unix also compares device and
  inode to reject hardlinks. `scan` rejects outputs inside the analyzed tree.
  Check and write are not a single atomic operation against a concurrent local
  actor.
- The fingerprint is capped at 250,000 files, 500,000 entries, 16 GiB total,
  2 GiB per file, and 256 levels. Non-UTF-8 paths are rejected. These bounds
  prevent unbounded input, but hashing occurs before the engine timeout.
- Timestamps support auditing but not semantic identity.
- Terminal states (`completed`, `partial`, `failed`, `cancelled`) require
  `completed_at`; `created` and `running` cannot include it.
- A human decision other than `pending` requires a reviewer, timestamp, and
  rationale. A pending finding cannot mimic a partial review with those fields.

In the first vertical, `findings` are ordered deterministically by severity,
confidence, rule, source location, sink location, and identifier. Ordering only
supports review; it is neither a risk score nor a human decision. Exact
duplicates within a run are removed after ordering, and
`summary.duplicate_count` records how many were dropped. No equivalence across
different engines is asserted.

## Privacy policy

The manifest may live locally next to the report, but external export must
exclude:

- absolute machine paths;
- secrets, tokens, and complete environment variables;
- source content not required as evidence;
- complete provider prompts or responses containing unapproved data.

The AI payload retains a redacted view and its hash, plus model, prompt version,
budget, and usage.

`ai_validation` is an advisory assessment separate from `human_review`.
Inactive states cannot carry metadata. `queued` requires a request identifier,
provider, model, prompt, and payload hash. `completed` additionally requires a
response hash, tokens, and assessment. Summary counters must match per-finding
states and usage. No AI state changes a human decision.

The local ledger writes `secureflow-knowledge-record-v2` and imports only
findings with a human decision. It stores hashes of the rationale, evidence
reference, and license evidence rather than complete text or source code. The
reader maintains strict v1 compatibility without silent migration.

## Minimal example

```json
{
  "contract_version": "secureflow-run-v1",
  "run_id": "sf_run_01JEXAMPLE0000000000000000",
  "status": "completed",
  "created_at": "2026-08-23T03:00:00Z",
  "completed_at": "2026-08-23T03:00:01Z",
  "target": {
    "label": "cms-nova-secure-engine-test",
    "root_sha256": "<sha256>",
    "revision": { "kind": "git", "value": "4c3de58000000000000000000000000000000000" },
    "authorization": {
      "status": "authorized",
      "basis": "repository-owner",
      "reviewer": "human"
    }
  },
  "engine": {
    "name": "secure-engine",
    "version": "0.1.10-rc2",
    "binary_sha256": "<sha256>",
    "report_schema": "secure-json-v1",
    "report_sha256": "<sha256>"
  },
  "phases": {
    "deterministic": "completed",
    "prioritization": "completed",
    "validation": "skipped",
    "evaluation": "skipped"
  },
  "findings": []
}
```
