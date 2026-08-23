# Changelog

All notable changes to SecureFlow are documented here.

## Unreleased

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
