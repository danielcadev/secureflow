# Honest evidence for a CV or paper

## Claims supported today

| Scoped claim | Reproducible evidence | Required limitation |
| --- | --- | --- |
| Built a local-first Rust prototype | Nine-package workspace, pinned Rust 1.92 toolchain, public repository, and local/CI gates | Publication does not demonstrate general effectiveness, and the initial release is unsigned |
| Integrates an analyzer through an external process | `scan`, SHA-256 of the binary/target/report, resource limits, and `secure-json-v1` | Validated with local fixtures; does not demonstrate general coverage |
| Isolates Linux execution by default | Process group, rlimits, and Bubblewrap with a read-only host root and private network namespace | Not equivalent to a VM and cannot protect against a compromised kernel; disabled mode requires an explicit choice |
| Keeps human validation authoritative | Human-review states, derived manifests, and tests showing that AI cannot change the decision | Relies on an identity declared through the CLI; human signatures are not implemented yet |
| Exports readable evidence without promoting candidates | Markdown report with provenance, accounting, evidence, and limitations | Not a security certificate and not a substitute for human review |
| Integrates contextual review without mixing verdicts | `secureflow-secure-review-v1` plus Skill, contract, and license hashes | Imports outputs; does not yet orchestrate Secure Skill execution |
| Imports neutral benchmarks | Upstream schema, suite/run fingerprints, and separated metrics | The adapter only imports; execution lives in a separate script and never enables rankings |
| Runs a separate synthetic diagnostic | 14 local cases, raw bundle, and `local-development-diagnostic` import | Known corpus, one execution, no preregistration, and no comparative claim |
| Minimizes data before AI | An 899-byte demonstration request without source or evidence descriptions and with redaction | The secret detector is conservative, not a formal guarantee |
| Measures storage before scaling | JSONL v2: 10k records, 91.508 ms median on the documented host | One machine, synthetic workload, no concurrency, and no real p95 |
| Demonstrates local catalog capacity | SQLite/FTS5 at 100k, 500k, and 1M source records with retained CSV and separated queries | Synthetic data; 1M source records is not 1M real vulnerabilities |
| Conservatively deduplicates external IDs | Exact CVE/GHSA/OSV/RUSTSEC union through `aliases`; `upstream` and `related` do not merge | Removing an upstream alias requires rebuilding from a snapshot; no semantic deduplication |
| Retains license evidence and exact repeats | Knowledge v2 with declared license status, evidence hash, and `duplicate_of_record_id` | Does not legally validate SPDX data or semantically deduplicate across engines |
| Processes real snapshots with quarantine | 229,644 active source records from crates.io, GitHub Actions, and npm; hashes, revisions, licenses, and 347 retained rejections | These are advisories/security reports—including 219,658 malicious-package reports—not human-validated vulnerabilities |
| Expands source coverage without changing the retained baseline | A verified copy accepted 33,878 Go/PyPI records, quarantined 34, reached 263,522 active source records / 251,657 exact-alias entities, and produced deeply verified 66.14 MB core / 234.61 MB full bundles | 231,319 active records are malicious-package reports; this is not a 263k-vulnerability claim, an efficacy result, or an authenticated catalog release |
| Separates catalog distribution from the application | Verified `core` (20.24 MB), `malicious` (138.09 MB), and logically complete frozen `full` (178.15 MB) Zstandard profiles from the 1.20 GB retained pilot, with stored-declaration composition and no-overwrite installation | One warm-cache host; source declarations do not authenticate upstream origin, internal hashes do not authenticate an unsigned manifest, the profiles are not globally complete, and no catalog data is bundled in the normal app release |
| Updates the catalog without inferring removals | Chained per-ecosystem deltas, exact payloads, replay/recovery, and `withdrawn`; official overlapping pilot of 7 RUSTSEC records on the real copy | There were no post-snapshot changes; the pilot demonstrates idempotence, not seven new advisories |
| Correlates without promoting signals | Exact lookup evaluates lists and OSV `SEMVER` ranges while retaining unknowns, run/catalog hashes, and `causality=false` | Package context is operator-declared and requires human review; `affected` does not prove exploitability |
| Freezes and seals prospective study inputs | Label-free dataset, exact case/artifact hashes, equivalent SecureFlow-assisted-human and human-comparator lanes, pseudonymous per-case submissions, time/cost/token/RSS accounting, negative outcomes, and tamper rejection | The fixture is synthetic and known; no independent holdout, cohort, execution, label opening, adjudication, or result exists, so there is no basis for comparison with humans |
| Inventories Next.js APIs without network access | Sealed scope, 6/6 fixture routes, 11 local candidates, JSON/SARIF, and 24/24 assertions | Known synthetic fixture, not a holdout; does not measure real repositories or authorize superiority claims |
| Produces release evidence | Remote CI per commit, deterministic CycloneDX SBOM, and a hashed bundle from a clean commit published as `v0.1.0` | Annotated but unsigned tag, without cross-host binary reproducibility verification |

## Suggested CV wording

> Built a local-first Rust security orchestration prototype that integrates a
> deterministic analyzer, contextual review contracts, human-only adjudication,
> provenance-bound benchmark imports, and budgeted redacted AI request
> preparation. Added versioned JSON contracts, SHA-256 traceability, a
> versioned reviewed-finding ledger, and a measured local SQLite advisory
> catalog; no source is sent to a model by default.

Short version:

> Built a local-first Rust prototype for orchestrating static analysis,
> contextual review, human decisions, reproducible evidence, and redacted,
> budgeted AI preparation with hash-based traceability.

Do not use yet:

- "outperforms human researchers";
- "finds more vulnerabilities than Semgrep/OpenGrep";
- "production-ready";
- "global database of 300,000 real vulnerabilities";
- "autonomous AI that validates vulnerabilities";
- "zero false positives."

The vision may aim to outperform human baselines on narrow, measurable tasks,
but that claim is publishable only after a preregistered study with experts,
blind adjudication, time, coverage, precision, recall, uncertainty, and
disagreement analysis.

## Evidence unit for a paper

Every publishable result should fix the following before execution:

- research question and success criterion;
- corpus, license, provenance, deduplication, and public/holdout status;
- scanner versions/hashes, configuration, adapters, and schemas;
- TP/FN and FP/TN units;
- policy for crashes, timeouts, unsupported cases, and abstentions;
- repetition count and retry protocol;
- hardware, OS, isolation, and limits;
- raw reports, matcher decisions, and hashes;
- blind human evaluation and disagreement resolution;
- limitations, uncertainty intervals, and threats to validity.

## Results that can be shown

- The local Phase 3 fixture produced six candidates in the retained SecureFlow
  execution. They are candidates, not six validated vulnerabilities.
- A human marked one candidate `abstained` in the local trial. This proves the
  abstention state, not that the finding is false or valid.
- The imported historical Phase 1 baseline retains 0 TP, 7 FN, 3 FP, and 4 TN
  with its units and limitations. It is evidence of importer neutrality, not a
  measure of the current Engine.
- The real AI request was prepared locally with 899 bytes and zero
  transmissions. It is not a measurement of Luna's quality.
- Automated tests verify prototype contracts and flows; they are not
  vulnerability cases and do not replace a detection benchmark.
- The catalog processed 1M synthetic source records in 104.736 seconds on
  NVMe/Btrfs and produced 900k canonical entities. This measures
  infrastructure, not vulnerability coverage.
- The real pilot produced 228,674 canonical components through exact aliases
  from 229,644 accepted records. The difference is ID deduplication, not exploit
  confirmation or a precision metric.
- The Web vertical passed 24/24 development assertions and 6/6 labeled routes.
  This verifies contracts and the known fixture; `independent_holdout=false`
  prevents presenting it as general effectiveness or a human comparison.

## Blockers before comparative claims

1. A public release, CI, and checksums do not replace an effectiveness study;
   the initial tag also provides no cryptographic signature.
2. A proprietary corpus with controls must be frozen through the prospective
   protocol before results are observed.
3. Comparators must be run under equivalent capabilities and conditions.
4. A human cohort and independent adjudication are still required.
5. Audited real AI transport is missing; responses applied in tests are
   synthetic.
6. Cost, latency, and quality per finding must be measured, and time savings
   must be demonstrated.

Until these blockers are resolved, the evidence supports presenting the
architecture and engineering rigor of a prototype, not superior effectiveness.
