# Changelog

All notable changes to SecureFlow are documented here.

## 0.3.0 — Unreleased

- prepare a deterministic source-only archive alongside the explicitly host-specific Linux bundle, with adjacent checksums and documented verification boundaries;
- split release construction and attestation from publication, use commit-pinned GitHub Actions with least-privilege job permissions, and attest the exact retained archives before publication;
- require every release-note paragraph and list item to occupy one physical Markdown source line so GitHub renders the full content area consistently;
- stage the workspace crates at version `0.3.0` while deliberately retaining the published `0.2.0` citation metadata until a separately approved release finalization;
- record a fresh, hash-bound npm CLI scan with zero findings and three explicit abstentions, while keeping Mitiquete evidence offline-only, the human-comparator study not started, and 50,000/100,000-record knowledge measurements classified as synthetic capacity and quality gates rather than validated-vulnerability counts.

## 0.2.0 — 2026-08-30

- freeze `secureflow-run-v1`, add `secureflow-run-v2` for Engine graph,
  fingerprint, byte-location, and evidence-state provenance, and retain a
  strict v1 reader;
- make `--full-engine-graph` preserve public RC2 compatibility while retrying
  once, within the original bounds, when a newer Engine explicitly declares a
  compact graph and supports the full-graph capability;
- preserve versioned Engine evidence calibration and deterministic abstentions
  without promoting them to findings or human review decisions;
- make local releases fail closed unless rustup executes the pinned Rust 1.92.0
  toolchain and records that exact toolchain in provenance;
- bind Cargo license declarations to checksum-verified local `.crate` archives,
  emit them in the deterministic CycloneDX SBOM, and include a human-readable
  declaration inventory without claiming legal completeness;
- add fail-closed label-free dataset, protocol-v2, and per-case submission
  contracts for a future blinded SecureFlow-assisted-human versus
  human-comparator study, while keeping all comparison claims unestablished;
- add verified-copy Go and PyPI advisory ingestion evidence without presenting
  security records or malicious-package reports as validated vulnerabilities;
- add a 400-scenario paired synthetic API-risk corpus and guarded authorized
  pilot plan without implementing remote production transport;
- exclude root and nested `node_modules` trees explicitly from Engine scans and
  from the matching target fingerprint without excluding project-owned tests;
- add a repository threat model covering assets, actors, trust boundaries,
  abuse cases, validation evidence, and explicit residual risks;
- preserve Secure Engine report fingerprints, compact/full graph accounting,
  finding/evidence states, locations, and limitations through a strict local
  `secure-json-v1` adapter boundary;
- keep compact Engine reports as the default and require an explicit
  `--full-engine-graph` choice for complete graph retention;
- add standalone `core`, `malicious` and `full` catalog distribution profiles;
- add bounded single-frame Zstandard bundles with strict, hash-bound manifests;
- add database-derived profile composition, fresh canonicalization for
  projections, deep verification and atomic no-overwrite installation;
- keep bundle integrity separate from publisher authenticity, require a
  manifest SHA-256 pin for installation by default, and reject pre-existing
  SQLite sidecars.

## 0.1.0 — 2026-08-23

Initial public MVP:

- local-first Rust CLI and versioned run contracts;
- authorized Secure Engine process adapter with Linux Bubblewrap-by-default;
- human-only finding review and append-only local knowledge ledger;
- SQLite/FTS5 advisory catalog with snapshots, deltas, provenance, quarantine,
  exact-alias canonicalization, integrity checks, backup and restore;
- Secure Skill and Secure Bench adapters with separate authority and claims;
- redacted, budgeted offline AI request/response contracts with no provider
  transport;
- deterministic fail-closed orchestration plan;
- offline SecureFlow Web scope, Next.js inventory, local API inference,
  conservative assessment, JSON/SARIF lab, and 24-case development corpus;
- pinned Rust 1.92 CI, dependency audit, deterministic SBOM, checksummed release
  bundle, security policy and contribution guidance.

Known limits:

- no remote recon, DNS/CT acquisition, crawling, or HTTP checks;
- no AI provider client and no automatic vulnerability validation;
- the 24 Web cases are development fixtures, not an independent holdout;
- no human comparison study or superiority claim;
- the one-million-record result is synthetic storage capacity, not one million
  validated vulnerabilities;
- release checksums and SBOM are provided, but the initial release is not
  cryptographically signed unless the published tag explicitly shows a valid
  signature.
