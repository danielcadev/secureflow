# Initial architecture

## Objective

SecureFlow coordinates specialized tools without turning them into one black
box. Every stage preserves its inputs, outputs, hashes, limitations, and
decisions.

## Layers

```text
secureflow-cli
    ├── scope and authorization
    ├── local configuration
    ├── JSON/text queries for findings, ledger, and catalog
    └── review-run writes a derived manifest

secureflow-orchestrator
    ├── seven-phase state machine
    ├── hash links and a fail-closed next action
    └── optional AI, evaluation-only benchmark, and explicit abstention

secureflow-engine-adapter
    ├── Secure Engine as an external process
    ├── secure-json-v1
    ├── boundary projection for report fingerprint, graph accounting, and evidence state
    ├── timeout, process group, and bounded output
    ├── Linux memory/CPU/descriptor/core resource limits
    ├── Bubblewrap required by default: read-only root and private network
    └── binary and report provenance

secureflow-model
    ├── canonical findings
    ├── source/sink/evidence
    ├── deterministic ordering and exact per-run deduplication
    ├── human states
    └── export contracts

secureflow-secure-adapter
    ├── strict review-contract 1.1 import
    ├── Skill, contract, license, and payload hashes
    ├── link to an authorized run and target
    └── contextual candidates under human authority

secureflow-knowledge
    ├── v1-compatible JSONL v2 ledger
    ├── human decisions and repeated exact observations
    ├── separate SQLite v3 catalog for external security records
    ├── OSV snapshots, chained deltas, licensing, and quarantine
    ├── raw revisions, sources, licenses, and hashed provenance
    ├── conservative exact-alias joins; never text/AI joins
    ├── compact package ranges and query indexes
    ├── conservative finding-package-version-advisory correlation
    ├── FTS5, canonicalization, and reconstructible backups
    └── verified Zstandard distribution profiles kept outside app releases

secureflow-ai
    ├── local preparation with Luna as the logical family
    ├── minimized, redacted payloads
    ├── one call, budgets, and accounting
    ├── escalation only for ambiguity with human approval
    └── no network transport in the current MVP

secureflow-bench-adapter
    ├── Secure Bench separated from the production path
    ├── result-v2 and fingerprint validation
    ├── TP/FN by expectation and FP/TN by safe control
    ├── sealed prospective protocol with human cohort and blinding
    └── no ranking, global superiority, or production claims

secureflow-web
    ├── authorized, hashed, expiring repository scope
    ├── offline Next.js inventory without target-code execution
    ├── inference from client code, OpenAPI, manifests, tRPC, and GraphQL
    ├── control matrix with candidate and hardening observations
    ├── JSON/SARIF lab and 24-case synthetic development corpus
    └── no network, no automatic validation, and private outputs

secureflow-recon-network (proposed; not implemented)
    ├── verifiable allowlist and additional authorization before each request
    ├── DNS, redirect, and shared-asset revalidation
    ├── bounded passive acquisition and loopback-first safe checks
    └── rate limits, redaction, stop rules, and human review
```

## Repository structure

```text
secureflow/
├── Cargo.toml
├── README.md
├── docs/
│   ├── architecture.md
│   ├── mvp.md
│   ├── adr/
│   └── contracts/
├── schemas/
├── crates/
│   ├── secureflow-model/
│   ├── secureflow-engine-adapter/
│   ├── secureflow-secure-adapter/
│   ├── secureflow-bench-adapter/
│   ├── secureflow-ai/
│   ├── secureflow-knowledge/
│   ├── secureflow-orchestrator/
│   ├── secureflow-web/
│   └── secureflow-cli/
├── tests/
│   ├── contracts/
│   └── fixtures/
└── tools/
```

Additional crates should not be created until a responsibility boundary and a
test justify each one.

## Integration boundaries

- Secure Engine remains the owner of `secure-json-v1`.
- SecureFlow preserves selected Engine provenance and evidence metadata but
  does not reinterpret an Engine evidence state as human validation.
- SecureFlow alone owns the authorization scope and human-review decision in
  `secureflow-run-v2`; similarly named Engine report fields cannot override it.
- Secure Skill remains installable and usable without SecureFlow.
- Secure Skill output remains a separate contextual envelope; upstream
  `verified` is not SecureFlow human validation.
- Secure Bench does not participate in production decisions.
- The benchmark adapter only imports retained evidence; it runs no scanners and
  does not recompute historical results.
- Original projects are not copied into the monorepo.
- Initial integration uses external processes and versioned contracts.
- A future direct Rust dependency requires a separate compatibility, licensing,
  and release-cycle decision.

## Security invariants

- A target is authorized before any phase executes.
- Static analysis never executes target scripts.
- Network access is disabled by default.
- No exported path escapes the target's logical root.
- Secrets never enter an AI payload without redaction and consent.
- Human contextual judgment remains authoritative; only a human decision can
  validate a finding.
- Every retry is idempotent and preserves the previous attempt.
- An operational failure never equals a clean result.

The recon diagnosis and boundaries are documented in
[`diagnosis-recon-api-exposure.md`](./diagnosis-recon-api-exposure.md). The
offline phase already exists as `secureflow-web`. Remote traffic remains
disabled until an additional ADR, loopback tests, limits, and an independent
benchmark are approved.

SecureFlow's own assets, trust boundaries, controls, and residual risks are
maintained in [`threat-model.md`](./threat-model.md). Any new execution or
network boundary requires that document and the relevant ADR to be reviewed
before implementation.
