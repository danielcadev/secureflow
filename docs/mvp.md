# SecureFlow MVP

## Scope

The MVP answers one question:

> Can a researcher analyze an authorized repository, receive prioritized
> deterministic candidates, and validate each one with reproducible evidence
> without depending on AI?

## Deliverables

1. Local Rust CLI. **Implemented in the first vertical.**
2. External-process Secure Engine adapter. **Implemented with time and output
   limits.**
3. `secure-json-v1` validation. **Implemented.**
4. `secureflow-run-v1` manifest. **Implemented; it preserves hashes and leaves
   the human decision `pending`.**
5. Deterministic prioritization and deduplication. Exact ordering and
   within-engine deduplication are implemented; cross-engine equivalence remains
   pending.
6. `pending`, `validated`, `rejected`, and `abstained` states. The model and
   `review-run` support them with reviewer, timestamp, and rationale.
7. JSON and Markdown reports. **Implemented:** they preserve provenance,
   accounting, evidence, and limitations, do not call candidates
   "vulnerabilities," and omit human rationale by default.
8. Local storage with separate authorities. A **JSONL v2 ledger** stores human
   decisions and a separate **SQLite/FTS5 catalog** stores external records.
   Capacity was measured with 100k, 500k, and 1M synthetic records and 229,644
   accepted real source records from crates.io, GitHub Actions, and npm
   snapshots. These counts are not human-validated vulnerabilities.
9. Positive fixtures and safe controls. A minimal integration test uses a
   vulnerable Secure Engine fixture. The Secure Bench adapter imports
   `result-v2` with hashes and separate metrics, while a separate script runs
   seven vulnerable and seven safe-control cases as a local diagnostic. A new
   holdout must be defined and frozen before any publishable efficacy run.
10. Optional, redacted, budgeted AI path. **Local preparation and response
    accounting are implemented, disabled by default, with no network client.
    Real transport remains pending.**
11. Contextual Secure Skill adapter. **Implemented for provenance-bound import
    and validation of review-contract 1.1; it neither executes the Skill nor
    grants validation authority.**
12. Secure Bench adapter. **Implemented for retained v2 result import,
    fingerprint checks, and separate metrics; it runs no scanners and permits
    no ranking or superiority claims.**
13. Offline Recon/API Exposure. **Implemented as `secureflow-web`: authorized
    scope, Next.js inventory, inference from local artifacts, JSON/SARIF
    evaluation, and 24 synthetic development assertions. There is no DNS/CT
    acquisition, crawling, or HTTP traffic.**

## Implementation order

### Phase 1 — Contract and adapter

- [x] load an explicit binary;
- [x] record version and SHA-256;
- [x] execute without a shell;
- [x] capture stdout and stderr separately;
- [x] reject invalid schemas, paths, or reports;
- [x] preserve raw output unchanged;
- [x] isolate the process group and kill all descendants on timeout;
- [x] apply Linux memory, CPU, descriptor, and core-dump limits;
- [x] require Bubblewrap by default on Linux with read-only root and private
  network;
- [ ] evaluate Landlock, a VM, or a container for profiles requiring stronger
  isolation or non-Linux portability.

### Phase 2 — Model and review

- [x] project candidates into canonical findings;
- [x] order candidates deterministically without turning order into validity;
- [x] deduplicate exact candidates by fingerprint, rule, and locations;
- [x] show source, sink, flow, limitations, and rule;
- [x] require a human decision before marking `validated`.

### Phase 3 — Knowledge base

- [x] start with tens of records, not hundreds of thousands;
- [x] store source, declared license, hash, version, and finding relationship;
- [x] separate exact observation from human decision;
- [x] separate the human ledger from the external advisory catalog;
- [x] import local OSV, retain revisions, and query aliases, FTS, and packages;
- [x] measure synthetic capacity at 100k, 500k, and 1M records;
- [x] validate adapters, licenses, and rejections with real snapshots;
- [x] implement per-ecosystem `modified_id.csv` with chaining, replay, explicit
  `withdrawn`, and recovery; absence never means deactivation;
- [ ] measure 5–20 million relationships and concurrency before promising them;
- [ ] reconcile claims or rules across engines only after a labeled corpus can
  measure incorrect merges.

### Phase 4 — Measured AI

- [x] prepare only selected findings without transmitting them;
- [x] use Luna as the default logical family;
- [x] represent escalation only for ambiguous cases under human approval;
- [x] record budgets, tokens, model, and versioned prompt;
- [x] verify that AI cannot change the human decision;
- [ ] measure real cost and quality only after provider transport and a data
  policy are approved.

## Acceptance criteria

- Equivalent runs produce the same semantic result.
- A run without a binary fails clearly and never simulates a clean scan.
- An invalid report remains an operational error.
- A candidate without enough evidence can remain `abstained`.
- No finding is validated automatically.
- Source code does not leave the machine by default.
- Token usage is measured per finding and phase.
- Original repositories remain unchanged.

## Out of scope

- active scanning or automatic exploitation;
- autonomous patches;
- deployment or actions against third parties;
- a complete web dashboard;
- indiscriminate CVE/NVD/OSV acquisition or ingestion;
- competitive benchmarks or leaderboards;
- universal language support.

The offline Recon/API Exposure phase is part of the executable MVP. Its
diagnosis and future network boundary are documented in
[`diagnosis-recon-api-exposure.md`](./diagnosis-recon-api-exposure.md). No
network scanner has been created.
