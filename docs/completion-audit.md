# MVP completion audit

Observed state: August 29, 2026.

This matrix separates demonstrable functionality, evidence, and later work. A
technical check is not a claim that SecureFlow finds every vulnerability or
outperforms a human researcher.

## Extended goal: requirements against evidence

| Requirement | Current evidence | Status and limitation |
| --- | --- | --- |
| Independent Rust workspace | Nine packages under `crates/`; source repositories are consumed through processes or contracts | Complete for the MVP; the original projects were not physically copied |
| Authorized deterministic analysis | `secureflow scan` requires `--authorized`, runs an explicit binary without a shell, and validates `secure-json-v1` | Complete for local targets; identity and authorization are operator declarations, not verifiable signatures |
| Stable provenance | SHA-256 of target, binary, configuration, and report; domain- and length-prefixed tree fingerprint; target and binary checked before and after execution | Complete with fail-closed limits; not a transactional snapshot, so a change reverted between measurements might escape observation |
| Process boundary | Clean environment, null stdin, separately captured stdout/stderr under one aggregate budget, 1–3,600 s timeout capped by authorization expiry, 1 GiB binary maximum, process group, Linux rlimits, and Bubblewrap required by default | Complete for the Linux MVP; Bubblewrap provides a read-only host root and private network namespace, but does not replace a VM or protect against a compromised kernel |
| Strict canonical contract | frozen `secureflow-run-v1`, current `secureflow-run-v2`, schemas, structs that reject unknown fields, and semantic validation | Complete; v1 remains readable and rejects v2-only fields under its label; calibration and deterministic Engine abstentions are structural, while Secure Engine retains ownership of its external contract |
| Prioritization and deduplication | Deterministic ordering and exact deduplication by fingerprint, rule, and locations | Complete for one execution/engine; no semantic reconciliation across engines |
| Human workflow | `list-findings`, `show-finding`, `review-run`, an `abstained` decision, and a Markdown report | Complete; only a human decision can mark a finding `validated` |
| Input immutability | Derived commands reject output identical to an input, including Unix hardlinks; `scan` rejects outputs inside the target; new artifacts use `0600` and ledger directories use `0700` | Complete with tests; a local TOCTOU window remains between checking and writing |
| Local knowledge base | JSONL v2 for human decisions and a separate SQLite v3 catalog for advisories, revisions, aliases, packages, snapshots/deltas, and FTS5 | Complete as local infrastructure; the traceable pilot accepted 229,644 real records and quarantined 347 without converting them into human validations |
| Evidence-based JSONL/SQLite choice | JSONL measured through 10k; SQLite measured on NVMe/Btrfs with 100k, 500k, and 1M synthetic records | JSONL remains for the small ledger; SQLite demonstrated 1M source records/900k entities in 104.736 s and 2.07 GB, without extrapolating to real records |
| Secure Skill | Strict `review-contract` 1.1 import with commit/hashes/license and a separate envelope; when `.git` exists, the commit must match `HEAD` | Complete as an adapter; a snapshot without `.git` retains hashes but its revision is operator-declared; upstream `verified` is not SecureFlow validation |
| Secure Bench | `result-v2` import, suite/run fingerprints, optional `HEAD` verification, separated TP/FN and FP/TN, blocked claims, prospective protocol, and artifact preflight | Complete as evaluation infrastructure; the Phase 1 corpus is synthetic and known, and no real holdout/cohort/study exists yet |
| Conservative correlation | Exact finding-package-version-advisory link with run, catalog, snapshot/delta, and canonicalization hashes | V2 evaluates exact lists and `SEMVER`, preserves unknowns, and asserts no causality; package context is operator-declared |
| Incremental updates | Per-ecosystem `modified_id.csv`, hashed index/payloads/licenses, linear chain, replay, recovery, and explicit `withdrawn` | Complete with fixtures and a real overlapping replay of 7 RUSTSEC records; absence never deletes, and there were no new post-snapshot changes |
| Recon/API Exposure | `secureflow-web`: expiring scope, Next.js inventory, local OpenAPI/manifest/GraphQL/tRPC inference, control matrix, JSON/SARIF, 24 route assertions, and 400 paired API risk scenarios | Complete for the offline vertical and corpus-generation slice; the Mitiquete plan remains blocked because no production HTTP transport, independently bound ownership evidence, or staging run exists |
| Fail-closed orchestration | Seven-phase state machine, artifacts retained by hash, abstention, and derived next action | Complete as a local plan; it does not automatically execute network activity, AI, or human review |
| Operational backups | SQLite Online Backup API, hashed manifest, `quick_check`, foreign keys, no-overwrite creation, and restore to a new destination | Complete with round-trip and concurrency tests; external retention, encryption, and disaster-recovery policies are missing |
| Modular catalog distribution | Database-derived `core`, `malicious`, and `full` profiles; bounded Zstandard; strict manifest; deep verify/install; manifest-hash pin required for installation by default | Implemented locally; stored source declarations do not authenticate publishers, projected profiles are standalone current-record catalogs, publisher signatures and incremental bundle updates are not implemented, and no advisory data ships in the app release |
| Local-first AI | Redacted preparation disabled by default, consent, budget, Luna default, model/prompt/token accounting, and advisory response | Complete as an offline contract; no network client or real provider quality/cost measurement exists |
| CV/paper evidence | Demo, separate evaluation, schemas, ADRs, threat model, and a matrix of allowed/prohibited claims | Complete for describing an engineering prototype; does not support superiority, production readiness, or general effectiveness |
| Preservation of originals | Demo and evaluation write under `/tmp`; subsequent Git verification | Complete in this work: source repositories remained outside SecureFlow, and pre-existing changes in other worktrees were not modified |
| Reproducible publication | Public `danielcadev/secureflow` repository, pinned Rust 1.92, commit-pinned CI actions, fmt/clippy/test/audit/build, deterministic CycloneDX SBOM, and a hashed bundle from clean Git | Remote CI passed; release `v0.1.0` uses an annotated tag and checksums, but the initial tag has no cryptographic signature |

## Executed evidence

- `cargo fmt --all -- --check`: passed with the pinned Rust 1.92.0 toolchain.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed in
  the pinned Rust 1.92.0 toolchain.
- `cargo test --workspace --locked`: 178 tests passed, 0 failed in the pinned
  Rust 1.92.0 toolchain.
- `cargo audit`: 173 dependencies checked against 1,226 advisories with no
  reported vulnerabilities.
- The public Secure Engine `0.1.10-rc2` qualification binary with SHA-256
  `1094f6640d690586da00a5e169e5b5d172580f90b25ff471811ad1c1fbf6fb91`
  completed both a default and a full-graph-required compatibility run on the
  tracked local fixture. Both manifests validated as `secureflow-run-v2` and
  reported an empty full graph. The compatibility run explicitly disabled
  Bubblewrap, so it supports contract compatibility only; zero candidates is
  not security evidence.
- Corrected Secure Engine commit `c5c67cd` (binary SHA-256
  `74caae8462bf80f8be45787262d7addf685c7711db4b6c70353487be9723b96f`)
  completed compact and negotiated-full runs through SecureFlow on the neutral
  calibration fixture. Both retained 14 pending candidates and 7 deterministic
  Engine abstentions; full mode retained 688 nodes and 1,247 edges.
- The same binary analyzed the authorized, clean npm CLI checkout at
  `b888cc9a9ff34a8b023ff47b784692396635397b`. SecureFlow retained 0 candidates
  and 3 explicit Engine abstentions, not a clean verdict. The compact Engine
  report represented 208,157 internal nodes and 368,627 edges in 2,507,778
  bytes. End-to-end execution took 25.33 seconds and peaked at 987,332 KiB on
  this host. No target code or network request was executed.
- `scripts/demo-local.sh`: 6 deterministic candidates, all `pending`; a Luna
  request with an 899-byte payload and `transmitted=false`; valid Secure Skill
  and historical benchmark imports. The synthetic catalog imported 2 source
  records as 1 canonical entity, passed `quick_check`, and had no foreign-key
  violations. Artifacts from this execution remained in a private temporary
  directory and are not published.
- `scripts/eval-local.sh`: 14 synthetic cases, 0 TP, 7 FN, 2 FP, 5 TN, 0
  operational failures, and 70 ms aggregate duration. Its artifacts remained
  in a private temporary directory and are not published.
- The raw demo report's SHA-256 matches the hash in the manifest; creation and
  completion timestamps bound the execution.
- Two consecutive demos retained exactly the same target hash, ordering, and
  content for the six canonical findings. The raw report changed only in
  engine timestamps and durations, so byte-for-byte identity is not claimed
  for volatile telemetry.
- The dependency audit must be repeated after any lockfile change.
- Scripts set `umask 077`; new demo/evaluation artifacts must not grant group
  or other local-user permissions.
- `catalog_bench` on NVMe/Btrfs: 100k/500k/1M synthetic source records; 1M
  produced 900k canonical entities, 2,072,891,392 bytes, 104,736.081 ms total
  load time, 66.451 μs exact lookup, 843.406 ms worst-case FTS, and 450.295 μs
  exact package lookup. The CSV is retained at
  `docs/evidence/catalog-benchmark-2026-08-23.csv`.
- The real pilot accepted 2,730 crates.io, 55 GitHub Actions, and 226,859 npm
  records; 347 entries were quarantined. The resulting catalog has 229,644
  active source records, 228,674 components through exact aliases,
  `quick_check=ok`, and zero foreign-key violations. Hashed evidence is in
  `docs/evidence/real-advisory-pilot-2026-08-23.json`.
- A verified-copy expansion accepted 8,893 Go and 24,985 PyPI records and
  quarantined 34. The copy reached 263,522 active source records and 251,657
  exact-alias components; 231,319 active records are OpenSSF malicious-package
  reports. The portable database grew from 1,202,384,896 to 1,491,918,848
  bytes and retained `quick_check=ok`, zero foreign-key violations, and ready
  FTS. Evidence is in
  `docs/evidence/real-advisory-expansion-2026-08-25.json`.
- Policy-v2 bundles from that copy passed deep verification with externally
  pinned manifest hashes: `core` 66,142,849 bytes, `malicious` 147,507,376
  bytes, and `full` 234,613,073 bytes compressed. They remain local evidence,
  not authenticated or published catalog releases.
- Two SBOM generator executions produced the same SHA-256. This measures
  inventory determinism for one `Cargo.lock`, not cross-host binary
  reproducibility.
- The online backup of the real 1.20 GB catalog completed in 45.96 seconds,
  used mode `0600`, and revalidated its hash, `quick_check`, and foreign keys.
  That 2026-08-23 run did not execute a full-scale restore. The later Go/PyPI
  expansion verified and restored a fresh 1,202,384,896-byte backup before
  importing, while preserving the original catalog.
- The same retained catalog produced locally deep-verified Zstandard bundles:
  `core` 20,242,641 bytes, `malicious` 138,085,256 bytes, and frozen-snapshot
  `full` 178,149,536 bytes. Creation peaked at 230,748 KiB or less after removing a
  redundant compaction pass; deep verification took 0.44–6.15 seconds. These
  are single warm-cache observations, retained with exact hashes in
  `docs/evidence/catalog-bundle-benchmark-2026-08-23.json`.
- A copy of the real catalog migrated from v2 to v3 in 1.10 seconds, retained
  every count, and passed integrity checks. The original v2 backup continued
  to verify read-only. A 1.20 GB v3 backup took 49.96 seconds, and its
  verification took 31.12 seconds.
- The official crates.io index contained no post-snapshot changes. An
  overlapping window of 7 RUSTSEC records was prepared without quarantine and
  applied to the real copy as 7 unchanged/0 inserted/0 updated; initial
  application took 3.99 seconds and replay 0.99 seconds, with FTS ready and
  integrity checks passing.
- SecureFlow Web inventoried 6/6 routes in the synthetic fixture and passed
  24/24 development assertions without network or target execution. Retained
  artifacts expressly block holdout, superiority, and production-safety
  claims: `docs/evidence/web-route-lab-2026-08-23.json` and
  `docs/evidence/web-development-corpus-2026-08-23.json`.
- The paired API risk corpus contains 200 risky synthetic scenarios and 200
  safe controls across 20 families and 10 runtime profiles. The generator
  reproduced the retained corpus and generated 5,200 and 20,000 variant
  descriptors without retaining them as canonical records. The Mitiquete
  pilot remained blocked, and no production network request was executed.
  Evidence: `docs/evidence/web-api-risk-corpus-and-pilot-2026-08-24.json`.

Paths under `/tmp` and ignored pilots under `target/` are retained local session
evidence, not permanent publishable artifacts. A release must produce a
versioned, hashed bundle from a clean commit.

## Work after MVP publication

1. Add cryptographic signatures and stronger verifiable provenance to future
   releases. `v0.1.0` retains checksums and an SBOM, but its initial tag is
   unsigned.
2. Freeze a prospective corpus with controls, anti-leakage measures,
   adjudication protocol, and comparators under equivalent capabilities.
3. Run a human cohort and blind evaluation before claiming to outperform
   people on a narrow task.
4. If real AI is enabled, add audited transport, provider policy, data
   residency/retention, and measured cost and quality per finding.

## What is deliberately not being built yet

- Indiscriminate CVE/NVD/OSV download or ingestion. Current snapshots require
  separate acquisition, immutable revision, policy, license, and quarantine.
- Presenting synthetic capacity as a global database of real vulnerabilities.
- Embeddings for every advisory or AI deduplication without labels.
- Exploitation, active scanning, or autonomous patching.
- Remote recon, crawling, or HTTP checks outside loopback fixtures before the
  authorization/allowlist contract is approved.
- A web dashboard or distributed system.
- Semantic deduplication without a labeled corpus.
- Commercial rankings or superiority claims.
- Presenting a partial sandbox as complete isolation.
