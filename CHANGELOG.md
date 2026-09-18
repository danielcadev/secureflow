# Changelog

All notable changes to SecureFlow are documented here.

## Unreleased

## 1.0.0-rc.1 — 2026-09-18

- add the local-first `secureflow-security-case-v1` evidence and decision boundary with strict Core and Review Room semantic validation, exact source-to-candidate authority, bounded strict UTF-8 browser loading, and human-only final decisions;
- import validated Secure Skill reviews as contextual candidates and SARIF 2.1.0 results as external-tool candidates without promoting either to a vulnerability verdict;
- add a provider-neutral local stdio MCP bridge limited to reading cases, investigating retained candidates, and staging non-authoritative agent recommendations;
- add the Review Room local case workflow with untrusted artifact annotations, loaded revision context, local audit drafts, and no agent-accessible decision route;
- add offline TUF publisher enrollment, public signing requests, consecutive root rotation and root-only revocation;
- bind unchanged v1 manifests and bounded payload verification to explicit scope, expiry, role history and per-profile release floors;
- add locked durable installation journals, conservative recovery, separate current-status and historical inspection, closed schemas and structured errors;
- retain synthetic lifecycle, independent OpenSSL vectors, crash/quota tests and release-binary demo evidence; independent human security review and real custody rehearsal remain pending before production qualification.

## 0.4.0-rc.3 — 2026-09-11

- provision Bubblewrap in both hosted CI and release builds, grant only the packaged executable the AppArmor user-namespace permission required on Ubuntu 24.04, and fail early if the adapter sandbox cannot execute;
- bind the runner setup helper into publication-control equality checks and retain mandatory CodeSupply integration coverage;
- supersede the unpublished `v0.4.0-rc.2` candidate after its hosted sandbox gates failed; preserve both earlier candidate tags unchanged and retain the cumulative v0.3.0/Review Room history.

## 0.4.0-rc.2 — 2026-09-11

- integrate the self-contained, offline CodeSupply demo, synthetic fixtures, strict artifact-link verification, tests, documentation, and CI retention on top of `71791c1`, preserving the v0.3.0 release controls and Review Room;
- align workspace, lockfile, and citation metadata at `0.4.0-rc.2` and support explicitly marked release candidates in the verified publication workflow;
- retain local-first operation, explicit target authorization, and human-only vulnerability validation; the demo leaves its synthetic candidate pending and makes no production-security or comparative-performance claim.

The immutable `v0.4.0-rc.1` tag identifies the earlier divergent CodeSupply candidate (`cb888ec`), which did not include the newer v0.3.0 and Review Room history. This cumulative candidate reconciles its changes onto the newer main branch; it does not replace or move that tag.

## 0.3.0 — 2026-08-30

- prepare a deterministic source-only archive alongside the explicitly host-specific Linux bundle, with adjacent checksums and documented verification boundaries;
- split tag-triggered release construction and attestation from manually approved publication, use commit-pinned GitHub Actions with least-privilege job permissions, and verify the retained archives, attestations, and draft uploads before publication;
- require every release-note paragraph and list item to occupy one physical Markdown source line so GitHub renders the full content area consistently;
- release the workspace crates and citation metadata as `0.3.0`; research users should cite the exact tag or commit;
- record fresh, hash-bound npm CLI observations with zero findings, three explicit abstentions, and one disclosed one-pass protocol deviation, while keeping Mitiquete evidence offline-only, the human-comparator study not started, and 50,000/100,000-record knowledge measurements classified as synthetic capacity and quality gates rather than validated-vulnerability counts; zero findings is not a clean verdict, and only a human review decision may validate a vulnerability.

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
