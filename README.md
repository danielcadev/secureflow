# SecureFlow

[![CI](https://github.com/danielcadev/secureflow/actions/workflows/ci.yml/badge.svg)](https://github.com/danielcadev/secureflow/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](./LICENSE-MIT)
[![Rust 1.92](https://img.shields.io/badge/Rust-1.92-orange.svg)](./rust-toolchain.toml)

SecureFlow is a local-first platform for analyzing authorized code, prioritizing
security signals, and helping a human researcher validate vulnerabilities with
reproducible evidence.

The project combines separate, versioned contracts and processes for:

- Secure Engine deterministic source-to-sink analysis;
- Secure Skill contextual review of security invariants;
- Secure Bench reproducible evaluation with separated metrics;
- a local knowledge base with provenance, deduplication, and versioning;
- optional AI agents for prioritization and investigation of ambiguous cases.

Human judgment is always authoritative. A candidate does not become a
vulnerability merely because a scanner or model suggests it.

The research goal is to outperform human baselines on narrow, measurable tasks
in coverage, speed, pattern memory, and reproducibility. That must be
demonstrated through a blind study and does not transfer final authority.
Contextual judgment and vulnerability validation remain human responsibilities,
and SecureFlow must abstain when evidence is insufficient.

## SecureFlow Web: offline API inventory

The implemented Web vertical seals a local scope with authorization and expiry,
inventories Next.js routes, correlates client calls, OpenAPI, manifests,
GraphQL, and tRPC, and retains everything as candidates. It neither executes
target code nor sends requests:

```bash
cargo run -p secureflow -- web-scope-create \
  --root /path/to/target \
  --repository-label my-app \
  --authorization-reference "repository owned by operator" \
  --authorization-reviewer "Daniel" \
  --authorization-expires-at 2027-01-01T00:00:00Z \
  --output /tmp/web-scope.json

cargo run -p secureflow -- web-inventory-nextjs \
  --root /path/to/target \
  --scope /tmp/web-scope.json \
  --source-name my-app \
  --source-revision <commit-or-snapshot> \
  --source-license-spdx MIT \
  --output /tmp/web-inventory.json

cargo run -p secureflow -- web-infer \
  --root /path/to/target \
  --scope /tmp/web-scope.json \
  --inventory /tmp/web-inventory.json \
  --output /tmp/web-inference.json

# An operator-reviewed coverage matrix produces candidates, hardening notes,
# and abstentions only; it never validates a vulnerability automatically.
cargo run -p secureflow -- web-assess \
  --scope /tmp/web-scope.json \
  --inventory /tmp/web-inventory.json \
  --coverage /path/to/coverage-routes.json \
  --output /tmp/web-assessment.json

# Only a person with retained local evidence can promote a candidate.
cargo run -p secureflow -- web-review-assessment \
  --assessment /tmp/web-assessment.json \
  --observation-id sf_web_observation_<hash> \
  --reviewer "Daniel" \
  --rationale "authorized reproduction verified locally" \
  --evidence /path/to/redacted-reproduction.json \
  --evidence-reference reproductions/WEB-001.json \
  --evidence-description "retained local reproduction" \
  --output /tmp/web-assessment-reviewed.json
```

The public fixture contains 24 development assertions. The retained execution
passed 24/24, and the six-route inventory achieved 6/6. Both result contracts,
however, explicitly set `independent_holdout=false` or
`superiority_claim_allowed=false`: these results test the pipeline and do not
show generalization. Results:
[`web-development-corpus-2026-08-23.json`](./docs/evidence/web-development-corpus-2026-08-23.json)
and [`web-route-lab-2026-08-23.json`](./docs/evidence/web-route-lab-2026-08-23.json).

```bash
cargo run -p secureflow -- web-lab \
  --inventory /tmp/web-inventory.json \
  --expected tests/fixtures/web-nextjs/expected.json \
  --output /tmp/web-lab.json \
  --sarif-output /tmp/web-lab.sarif

cargo run -p secureflow -- web-corpus-evaluate \
  --inventory /tmp/web-inventory.json \
  --inference /tmp/web-inference.json \
  --corpus tests/fixtures/web-nextjs/corpus.json \
  --output /tmp/web-corpus-result.json
```

The broader API risk corpus retains 200 risky synthetic scenarios paired with
200 safe controls across 20 security families and 10 runtime profiles. It can
generate 5,200–20,000 deterministic lineage-preserving variant descriptors
without storing them as new canonical records:

```bash
cargo run -p secureflow-web --bin secureflow-web-risk-corpus -- \
  tests/fixtures/web-api-risk-corpus/LICENSE \
  /tmp/secureflow-web-api-risk-corpus.json
```

The prepared Mitiquete pilot is intentionally blocked. It records the owner's
assertion, exact apex-host scope, read-only methods, request budgets, redaction,
authorization validity window, and remaining gates. It contains no HTTP
transport and has not contacted the production site:

```bash
cargo run -p secureflow-web --bin secureflow-web-pilot-plan -- \
  <authorization-reference> \
  <issued-at-rfc3339> \
  <expires-at-rfc3339> \
  /tmp/mitiquete-pilot.json
```

See [`secureflow-web-api-risk-corpus-v1`](./docs/contracts/secureflow-web-api-risk-corpus-v1.md)
and the [blocked pilot plan](./docs/pilots/mitiquete-web-pilot.md). Neither
artifact is a holdout, a production-safety result, or evidence that SecureFlow
outperforms a human researcher.

## First reproducible run

The current CLI runs an explicitly selected Secure Engine binary, retains its
`secure-json-v1` output without reserializing it, and generates a
`secureflow-run-v2` manifest. The manifest preserves the Engine version, report
fingerprint, compact/full graph accounting, finding and evidence states,
evidence calibration, deterministic Engine abstentions, source/sink locations,
and limitations. Engine abstentions remain separate from candidates and human
abstentions. SecureFlow—not the Engine report—owns the authorization scope and
human decision. Authorization acknowledgement is mandatory:

```bash
cargo run -p secureflow -- scan \
  --binary /path/to/secure \
  --authorized \
  --authorization-reviewer "Daniel" \
  --authorization-reference "local repository owned by operator" \
  --output /tmp/secureflow-report.json \
  --manifest-output /tmp/secureflow-run.json \
  /path/to/target
```

The Engine's default graph projection is retained unchanged. The explicit
`--full-engine-graph` option requires the selected Engine to return a complete
graph. SecureFlow first uses the public RC2-compatible invocation; if a newer
Engine explicitly returns a compact graph, it retries once with the bounded
full-graph capability. That mode raises the aggregate stdout+stderr allowance
to 256 MiB and can materially increase storage:

```bash
cargo run -p secureflow -- scan \
  --binary /path/to/secure \
  --authorized \
  --authorization-reviewer "Daniel" \
  --full-engine-graph \
  --output /tmp/secureflow-full-report.json \
  --manifest-output /tmp/secureflow-full-run.json \
  /path/to/target
```

See [`docs/secure-engine-adapter.md`](./docs/secure-engine-adapter.md) for the
exact contract boundary, compatibility policy, failure semantics, and retained
evidence.

On Linux, the CLI requires Bubblewrap by default, with a private network and a
read-only host filesystem. The run retains the hash of `/usr/bin/bwrap`. Only
an explicit operational choice may select `--sandbox disabled`; there is no
silent fallback when the required sandbox is unavailable.

`--authorization-reviewer` is required. The `written-consent`,
`organization-policy`, and `other-documented` bases also require
`--authorization-reference`; an expired RFC3339 timestamp fails before the
engine runs. `--target-revision-kind` and `--target-revision` bind the run to an
explicit commit or snapshot. A Git revision must be a complete lowercase
object ID.

The manifest can then be validated without running a scanner:

```bash
cargo run -p secureflow -- validate-run /tmp/secureflow-run.json
```

Candidates can be queried without manually opening the JSON:

```bash
cargo run -p secureflow -- list-findings \
  /tmp/secureflow-run.json --decision pending --format text

cargo run -p secureflow -- show-finding \
  /tmp/secureflow-run.json sf_finding_<id>
```

A local Markdown report can also be generated. By default, it records a human
decision but omits the human rationale text:

```bash
cargo run -p secureflow -- export-report \
  --manifest /tmp/secureflow-run.json \
  --output /tmp/secureflow-report.md
```

The report explicitly states that findings are candidates and that zero
candidates is not a security guarantee. Use `--include-human-rationale` only
when the report destination is authorized to receive that context.

A human review is written to a separate manifest, leaving the original intact:

```bash
cargo run -p secureflow -- review-run \
  --manifest /tmp/secureflow-run.json \
  --finding-id sf_finding_<id> \
  --decision validated \
  --reviewer "Daniel" \
  --rationale "The source-to-sink path was verified locally" \
  --output /tmp/secureflow-run-reviewed.json
```

Reviewed findings can enter a local append-only ledger:

```bash
cargo run -p secureflow -- knowledge-import \
  --manifest /tmp/secureflow-run-reviewed.json \
  --ledger .secureflow/knowledge.jsonl \
  --source-license-status spdx-declared \
  --source-license-expression MIT \
  --source-license-evidence /path/to/target/LICENSE

cargo run -p secureflow -- knowledge-list \
  .secureflow/knowledge.jsonl --decision validated --format json
```

The v2 ledger stores provenance, the target revision, a declared license with
hashed evidence, relative locations, and hashes of the rationale/reference. It
does not store source text or the full rationale. Exact repeated observations
are retained and linked to the first record without inferring equivalence
across engines. A source can instead be declared `private-or-undisclosed` or
`unknown`; a license is never invented. Normative schemas are printed with
`secureflow schema` and `secureflow knowledge-schema`; v1 remains available
through `secureflow knowledge-schema --version v1`.

Public advisories live in a separate SQLite catalog so external knowledge is
not confused with human decisions. The reproducible path prepares an
externally acquired OSV ZIP and retains every accepted and rejected record,
license evidence, and exact accounting:

```bash
cargo run -p secureflow -- snapshot-prepare-osv \
  --archive /path/to/npm-all.zip \
  --output .secureflow/npm-snapshot \
  --artifact-locator https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip \
  --artifact-revision gcs-generation:<id> \
  --expected-ecosystem npm \
  --acquired-at 2026-08-23T17:47:25Z \
  --github-license-evidence /path/to/GHAD-LICENSE.md \
  --openssf-malicious-packages-license-evidence /path/to/OPENSSF-LICENSE

cargo run -p secureflow -- catalog-import-snapshot \
  --database .secureflow/advisories.sqlite3 \
  --manifest .secureflow/npm-snapshot/manifest.json \
  --archive /path/to/npm-all.zip
```

PyPI snapshots additionally require `--pypa-license-evidence`; Go snapshots
require `--go-vulnerability-database-license-evidence`. Supply the GitHub and
OpenSSF evidence flags as well when their identifier families occur in the
same ecosystem archive. Missing source-specific evidence fails closed.

After a complete snapshot, changes from a per-ecosystem `modified_id.csv` are
prepared offline and chained to the previous snapshot or delta:

```bash
cargo run -p secureflow -- delta-prepare-osv \
  --modified-index /path/to/modified_id.csv \
  --records /path/to/payloads-json \
  --output .secureflow/crates-delta \
  --index-locator https://storage.googleapis.com/osv-vulnerabilities/crates.io/modified_id.csv \
  --index-revision gcs-generation:<id> \
  --expected-ecosystem crates.io \
  --acquired-at 2026-08-23T19:07:52Z \
  --after-modified 2026-08-21T01:00:00Z \
  --base-snapshot-id sf_snapshot_<hash> \
  --rustsec-license-evidence /path/to/RUSTSEC-README.md

cargo run -p secureflow -- catalog-import-delta \
  --database .secureflow/advisories.sqlite3 \
  --manifest .secureflow/crates-delta/manifest.json
```

The same source-specific evidence flags apply to deltas.

A missing or quarantined payload blocks cursor advancement. Absence never
deactivates a record. Explicit `withdrawn` data is retained as withdrawn, and
only a later full snapshot may mark absent records inactive.

Manual OSV JSON import remains available for explicit sources:

```bash
cargo run -p secureflow -- catalog-import-osv \
  --database .secureflow/advisories.sqlite3 \
  --input /path/to/osv-snapshot \
  --source-name github-advisory-database \
  --source-license-expression CC-BY-4.0 \
  --source-license-evidence /path/to/osv-snapshot/LICENSE \
  --source-locator https://github.com/github/advisory-database

cargo run -p secureflow -- catalog-lookup \
  --database .secureflow/advisories.sqlite3 CVE-2026-0001 --format json

cargo run -p secureflow -- catalog-search \
  --database .secureflow/advisories.sqlite3 "command injection" --format json

cargo run -p secureflow -- catalog-package \
  --database .secureflow/advisories.sqlite3 crates.io crate-name --format json

cargo run -p secureflow -- catalog-stats .secureflow/advisories.sqlite3
cargo run -p secureflow -- catalog-check .secureflow/advisories.sqlite3
```

The v3 database retains raw revisions, snapshots/deltas, exact aliases, and
compact ranges; `upstream` and `related` do not merge vulnerabilities. During
bulk imports, FTS is rebuilt at the end and remains `dirty` after an interrupted
process; `catalog-rebuild-index` recovers it. Small deltas update FTS per row in
each batch transaction and block advisory queries while they remain
`preparing`. Exact alias components can be rebuilt with
`catalog-rebuild-canonicalization`, including splits when a revision removes an
alias. Every structured query retains `validation_authority=human-only`.

The real crates.io, GitHub Actions, and npm pilot processed 229,644 active
source records into 228,674 canonical entities in a 1.20 GB database. It
includes 219,658 OpenSSF malicious-package reports, so these figures describe
security records, not human-validated vulnerabilities. The pipeline quarantined
347 records in total: 19 crates.io records and 328 npm records, of which 326
failed malicious-package provenance checks and 2 used unsupported primary IDs.
Exact evidence:
[`real-advisory-pilot-2026-08-23.json`](./docs/evidence/real-advisory-pilot-2026-08-23.json).

A later source-expansion pilot added official Go and PyPI ecosystem snapshots
to a verified copy, not to the retained baseline. It accepted 33,878 of 33,912
entries and quarantined 34, producing 263,522 active source records and
251,657 exact-alias canonical entities. The portable SQLite file grew by
289,533,952 bytes to 1,491,918,848 bytes. Of all active records, 231,319 are
OpenSSF malicious-package reports and 32,203 are advisory records, so the
combined total is not presented as a vulnerability count. Exact evidence:
[`real-advisory-expansion-2026-08-25.json`](./docs/evidence/real-advisory-expansion-2026-08-25.json).
From that copy, deeply verified policy-v2 bundles measured 66,142,849 bytes for
`core`, 147,507,376 bytes for `malicious`, and 234,613,073 bytes for `full`.
Catalogs therefore remain optional artifacts outside the application binary;
`core` is the planned practical default if catalog downloads are published.

A finding is conservatively linked to advisories for a package. V2 evaluates
exact lists and OSV `SEMVER` ranges; invalid data and `GIT`/`ECOSYSTEM` ranges
remain `unknown`. Even `affected` asserts neither causality nor validation:

```bash
cargo run -p secureflow -- correlate-package \
  --manifest /tmp/secureflow-run.json \
  --finding-id sf_finding_<id> \
  --database .secureflow/advisories.sqlite3 \
  --ecosystem crates.io --package tokio --version 1.0.0 \
  --output /tmp/secureflow-correlation.json

cargo run -p secureflow -- orchestrate-plan \
  --manifest /tmp/secureflow-run.json \
  --correlation /tmp/secureflow-correlation.json \
  --output /tmp/secureflow-plan.json
```

Backups and restores create new, hashed, verified destinations:

```bash
cargo run -p secureflow -- catalog-backup \
  --database .secureflow/advisories.sqlite3 \
  --output /backups/advisories.sqlite3 \
  --manifest-output /backups/advisories.backup.json

cargo run -p secureflow -- catalog-backup-verify \
  --backup /backups/advisories.sqlite3 \
  --manifest /backups/advisories.backup.json
```

Catalog data stays separate from the application release. A database can be
distributed as a Zstandard bundle in three verified profiles: `core` contains
current records classified from stored declarations as GitHub Advisory
Database, RustSec, PyPA Advisory Database, or Go Vulnerability Database;
`malicious` contains records classified as OpenSSF malicious-package reports;
and `full` is a logically complete SQLite online-backup snapshot.
Projected profiles are rebuilt and canonicalized afresh; an unknown active
source fails closed. Classification proves internal composition consistency,
not that an upstream publisher supplied the stored declarations.

```bash
cargo run -p secureflow -- catalog-bundle-create \
  --database .secureflow/advisories.sqlite3 \
  --profile core \
  --output /catalogs/secureflow-core.sqlite3.zst \
  --manifest-output /catalogs/secureflow-core.manifest.json

cargo run -p secureflow -- catalog-bundle-verify \
  --bundle /catalogs/secureflow-core.sqlite3.zst \
  --manifest /catalogs/secureflow-core.manifest.json \
  --required-profile core \
  --expected-manifest-sha256 <sha256>

cargo run -p secureflow -- catalog-bundle-install \
  --bundle /catalogs/secureflow-core.sqlite3.zst \
  --manifest /catalogs/secureflow-core.manifest.json \
  --required-profile core \
  --expected-manifest-sha256 <sha256> \
  --output .secureflow/advisories.core.sqlite3
```

Hashes inside an unsigned manifest prove internal consistency, not publisher
identity. Pin the manifest SHA-256 from an authenticated release channel. The
normal application bundle remains independent of all advisory data. Contract:
[`secureflow-catalog-bundle-v1`](./docs/contracts/secureflow-catalog-bundle-v1.md).

On the retained 229,644-record pilot, the measured artifacts were 20.24 MB for
`core`, 138.09 MB for `malicious`, and 178.15 MB for `full`; the uncompressed
origin was 1.20 GB. These are single local observations, not universal size or
speed guarantees. Exact hashes, timing, memory and limitations:
[`catalog-bundle-benchmark-2026-08-23.json`](./docs/evidence/catalog-bundle-benchmark-2026-08-23.json).

The documented host was measured with 100k, 500k, and 1M synthetic records. At
1M, it produced 900k canonical entities, occupied 2.07 GB, and took 104.7
seconds on NVMe/Btrfs. This demonstrates storage capacity, not the existence of
one million real vulnerabilities. Method and limits:
[`docs/knowledge-benchmark.md`](./docs/knowledge-benchmark.md).

A structured Secure Skill `review-contract` 1.1 output can be imported as
contextual candidates linked to an authorized run:

```bash
cargo run -p secureflow -- secure-review-import \
  --review /path/to/review.json \
  --manifest /tmp/secureflow-run.json \
  --secure-skill-root /path/to/secure-skill \
  --secure-skill-revision <full-commit> \
  --output /tmp/secureflow-contextual-review.json

cargo run -p secureflow -- secure-review-list \
  /tmp/secureflow-contextual-review.json --format text
```

The importer records hashes, version, commit, and license and checks the commit
against `HEAD` when the source root retains `.git`; it does not run the Skill.
Its findings remain `contextual-candidates`, validation authority is
`human-only`, and zero findings never means that the target is secure. Print
the third schema with `secureflow secure-review-schema`.

A retained Secure Bench result is imported through a separate evaluation path
that verifies the upstream schema and suite/run fingerprints:

```bash
cargo run -p secureflow -- benchmark-import \
  --result /path/to/result.json \
  --run-manifest /path/to/run.json \
  --suite /path/to/suite.toml \
  --secure-bench-root /path/to/secure-bench \
  --secure-bench-revision <full-commit> \
  --study-kind historical-public-diagnostic \
  --output /tmp/secureflow-benchmark.json

cargo run -p secureflow -- benchmark-summary \
  /tmp/secureflow-benchmark.json --format text
```

The output keeps TP/FN per vulnerable expectation, FP/TN per safe control,
ratios with denominators, failures, and performance separate. It never enables
rankings, superiority claims, or production-readiness claims. Print its schema
with `secureflow benchmark-schema`.

The complete, separated evaluation path can run the 14 local synthetic fixtures
without modifying Secure Bench:

```bash
bash scripts/eval-local.sh
```

The protocol, observed result, and limitations are in
[`docs/evaluation.md`](./docs/evaluation.md).

Before a new study, SecureFlow can freeze a label-free dataset and seal a v2
protocol for equivalent SecureFlow-assisted-human and human-comparator lanes.
The contracts bind blinding, artifacts, costs, outcomes, and claim limits:

```bash
cargo run -p secureflow -- benchmark-dataset-freeze --help
cargo run -p secureflow -- benchmark-protocol-preflight --version v2 --help
cargo run -p secureflow -- benchmark-submission-seal --help
```

A real study must check the exact dataset, case, provenance, license,
anti-leakage, environment, capability, randomization, lane, and raw-submission
hashes without receiving or opening labels. The repository fixture tests only
the contract; it is not a real preregistration, adjudication, or result. Runbook:
[`docs/prospective-study-runbook.md`](./docs/prospective-study-runbook.md).

Optional AI begins with an offline contract. The CLI prepares one redacted,
budgeted finding but makes no network call:

```bash
cargo run -p secureflow -- ai-prepare \
  --manifest /tmp/secureflow-run.json \
  --finding-id sf_finding_<id> \
  --enable-ai \
  --consent-redacted-export \
  --output /tmp/secureflow-ai-request.json
```

The default logical model family is Luna. The payload excludes code, evidence
descriptions, human metadata, and absolute paths; a conservative filter redacts
potential secrets. Preparation records `transmitted=false`. A structured
response can later be recorded with `ai-apply-response`, retaining hashes and
token counts without changing the human decision. No provider client is
implemented yet.

`scan` computes and records SHA-256 hashes of the target, binary, and report. It
checks the target and binary before and after execution and fails if either
changes. It projects candidates into a canonical model and leaves every human
review `pending`. Only exit codes `0` (no findings) and `1` (findings) count as
completed execution; `2+`, a signal, timeout, or invalid report is an
operational failure even if stdout contains JSON. Commands that create derived
artifacts reject an output that is the same as an input, and `scan` does not
allow results to be written inside the analyzed target.

The process runs without a shell or stdin and with a clean environment. On
Linux, it receives its own process group, disabled core dumps, a 2 GiB virtual
memory limit, 256 file descriptors, and CPU time tied to the timeout; the
manifest includes a hash of this configuration. In required mode, Bubblewrap
adds a private network namespace, a read-only host root, and isolated `/proc`
and `/dev`. This is not VM-grade isolation and cannot protect against a
compromised kernel.

The accepted timeout is 1 to 3,600 seconds and is shortened to finish before a
recorded authorization expiry. Binaries larger than 1 GiB are rejected. On
Unix, derived artifacts are created with mode `0600`, and new ledger directories
use `0700`.

The target uses the `secureflow-target-sha256-v3` fingerprint: it distinguishes
files from directories, prefixes lengths to prevent ambiguous serialization,
excludes `.git` and root or nested `node_modules` trees, and rejects other
symlinks. Hashing fails closed above 250,000 files, 500,000 entries, 16 GiB
total, 2 GiB per file, or 256 directory levels. Non-UTF-8 paths are also
rejected to prevent ambiguous fingerprints.

## Current architecture

This workspace integrates the original projects through processes and
contracts, not physical copies. Secure Engine, Secure Skill, Secure Bench, CMS
Nova, and Mitiquete remain in their own directories with their histories intact.

The first contract is
[`secureflow-run-v2`](./docs/contracts/secureflow-run-v2.md), while the frozen
[`secureflow-run-v1`](./docs/contracts/secureflow-run-v1.md) remains readable.

## Target flow

```text
authorized scope
  -> deterministic analysis and local API inventory
  -> normalization and deduplication
  -> deterministic prioritization
  -> optional AI validation support
  -> human decision
  -> report and local knowledge base
  -> separate benchmarks/evaluations
```

## Limits

- Third parties are never scanned without explicit authorization.
- An analyzed repository's code is not executed during static analysis.
- AI is disabled by default and cannot approve a finding.
- Source code is never uploaded automatically.
- External feeds are neither downloaded nor merged automatically; every
  snapshot must pass license, provenance, adapter, and rejection-accounting
  review.
- Synthetic capacity at 1M records is not a real global database or a coverage
  claim.

The architecture and MVP are documented under [`docs/`](./docs/). The
provisional JSONL-versus-SQLite decision, repeated for knowledge v2, is
supported by
[`docs/knowledge-benchmark.md`](./docs/knowledge-benchmark.md). The demo is in
[`docs/demo.md`](./docs/demo.md), and the allowed CV/paper claim matrix is in
[`docs/evidence-and-claims.md`](./docs/evidence-and-claims.md). The
requirement-to-evidence matrix and completion audit are in
[`docs/completion-audit.md`](./docs/completion-audit.md). SecureFlow's own
assets, trust boundaries, abuse cases, and residual risks are documented in the
[`threat model`](./docs/threat-model.md).

## Implementation status

The local MVP is operational: Rust workspace, contracts and schemas, external
process adapter, projection, ordering, within-engine deduplication, Markdown
report, explicit human-review recording, and local JSONL ledger. Secure Skill
contextual integration is also implemented through a separate contract and
verifiable provenance. Secure Bench can import retained v2 results through an
evaluation-only path. The SQLite/FTS5 catalog implements source revisions,
exact aliases, packages, queries, and local integrity checks. The AI path has
offline redacted preparation and accounting; provider transport remains
disabled and is not presented as a completed feature.

The `secureflow-web` vertical is also operational for strictly offline
analysis: authorized scope, Next.js inventory, local inference, route
assessment, a 400-scenario paired API risk corpus, and a blocked-by-construction
production pilot plan. Remote recon, DNS/CT, and HTTP transport remain
unimplemented.

## Release evidence

The local release bundle includes a deterministic CycloneDX 1.5 inventory and
a human-readable Cargo dependency license-declaration inventory. Registry
metadata is extracted offline from local `.crate` archives only after their
SHA-256 matches `Cargo.lock`; missing or ambiguous evidence stops the release.
This records package-manager declarations and does not establish legal
completeness, license compatibility, compliance, or cross-host binary
reproducibility. See
[`docs/dependency-license-evidence.md`](./docs/dependency-license-evidence.md).

## Security and contributions

See [`SECURITY.md`](./SECURITY.md) for private vulnerability reporting and
[`CONTRIBUTING.md`](./CONTRIBUTING.md) for reproducing the gates. Use this
software only on code and systems that you own, that are open source, or for
which you have explicit authorization.

## License

SecureFlow is distributed under either the MIT License or Apache License 2.0,
at the user's choice. See [`LICENSE-MIT`](./LICENSE-MIT) and
[`LICENSE-APACHE`](./LICENSE-APACHE).
