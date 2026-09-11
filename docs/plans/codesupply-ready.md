# CodeSupply-ready execution plan

## Milestone decision

`CodeSupply-ready` is a public, reproducible proof that an authorized
maintainer can combine a locally acquired advisory catalog with evidence from a
local analysis, then obtain conservative package context and an explicit human
review handoff. It is not a claim that SecureFlow discovers, validates, or
patches vulnerabilities automatically.

The implementation should compose the existing local interfaces first. A
production-code change is justified only when the documented demo cannot meet
an acceptance criterion using those interfaces.

## Existing capability, verified in the repository

| Capability | Evidence | Status for this milestone |
| --- | --- | --- |
| Explicit authorized local analysis, target hashing, provenance, and fail-closed target-change checks | `crates/secureflow-cli/src/main.rs` (`scan`); `crates/secureflow-cli/tests/cli.rs` (`scan_records_explicit_authorization_and_target_revision`, `scan_fails_closed_when_the_target_changes_during_execution`); `crates/secureflow-engine-adapter/src/lib.rs` | Implemented. |
| Local advisory ingestion with source/license provenance, alias reconciliation, SQLite checks, and human-only authority | `crates/secureflow-knowledge/`; `crates/secureflow-cli/src/main.rs` (`catalog-import-osv`, catalog queries); `crates/secureflow-cli/tests/cli.rs` (`imports_and_queries_a_deduplicated_local_osv_catalog`) | Implemented. |
| Offline prepared snapshots and chained deltas | `README.md` (snapshot and delta commands); `docs/contracts/secureflow-advisory-snapshot-v1.md`; `docs/contracts/secureflow-advisory-delta-v1.md`; `schemas/secureflow-advisory-*.schema.json` | Implemented. Acquisition remains intentionally outside SecureFlow. |
| Portable catalog distribution with profile binding, deep integrity checks, and caller-supplied manifest hash | `crates/secureflow-cli/src/main.rs` (`catalog-bundle-create`, `catalog-bundle-verify`, `catalog-bundle-install`); `docs/contracts/secureflow-catalog-bundle-v1.md`; bundle assertions in `crates/secureflow-cli/tests/cli.rs` | Implemented. It has no publisher signature, freshness, or rollback protection. |
| Conservative finding-to-package correlation | `crates/secureflow-cli/src/main.rs` (`correlate-package`, `correlation-validate`); `docs/contracts/secureflow-correlation-v2.md`; `schemas/secureflow-correlation-v2.schema.json` | Implemented. `affected` is an advisory version assessment, never causality, reachability, exploitability, or validation. |
| Fail-closed plan assembled from retained evidence | `crates/secureflow-cli/src/main.rs` (`orchestrate-plan`); `docs/contracts/secureflow-orchestration-v1.md`; `schemas/secureflow-orchestration-v1.schema.json` | Implemented. |
| Human review remains the sole decision authority | `crates/secureflow-cli/src/main.rs` (`review-run`); `docs/architecture.md`; `docs/demo.md` | Implemented and must remain unchanged. |
| Local build, test, audit, SBOM, provenance, checksum, and source-archive release lane | `.github/workflows/ci.yml`; `scripts/release-local.sh`; `Cargo.toml` | Implemented as a release lane; it must be run from a clean checkout. |

## Primary user and minimum demonstrable flow

The primary user is an OSS maintainer or product-security engineer who is
authorized to inspect a specific local checkout and wants advisory context
without sending source, fetching a feed, or allowing a tool to decide that a
candidate is a vulnerability.

The smallest credible demonstration is:

1. Build SecureFlow locally and create a temporary workspace with mode `0700`.
2. Run a deterministic, repository-contained synthetic engine fixture against
   a repository-contained authorized target using `scan --authorized`, a
   reviewer, an authorization reference, and a fixed target revision. Preserve
   the engine report and run manifest.
3. Prepare/import the committed synthetic OSV fixture with license evidence,
   build a `core` bundle, verify it, then install it only with its exact
   manifest SHA-256 supplied separately by the demo itself.
4. Correlate one candidate from that run to the installed catalog's exact
   package/version context; validate the correlation and assemble an
   orchestration plan.
5. Print the retained artifact paths and SHA-256 values. The last message must
   say that no network request, active scan, exploit, AI transmission, or
   human decision was created.
6. A real person may optionally invoke `review-run` after inspecting the
   candidate. The scripted demo must never manufacture that decision.

This must work in a fresh checkout with Rust plus the repository's documented
local prerequisites; it must not require sibling `secure-engine`,
`secure-skill`, or `secure-bench` checkouts. The current
`scripts/demo-local.sh` is valuable integration evidence but deliberately
requires those sibling repositories and does not cover bundle installation or
correlation, so it is not the CodeSupply public demo.

## Gaps that actually block an external-facing CodeSupply demonstration

1. There is no self-contained end-to-end path joining scan evidence, bundle
   verification/installation, correlation, and orchestration. The individual
   commands exist, but the current demo stops before the final two stages.
2. The committed fixtures do not yet form one linked scenario: the catalog
   names `secureflow-fixture`, while the run with a finding and the executable
   scan fixture need to be deliberately aligned for a public demonstration.
3. The public demo documentation does not state one concise artifact map,
   reproducible commands, expected outputs, and the exact non-claims for this
   combined flow.
4. No release receipt proves that this combined path remains executable from a
   clean checkout. Existing unit/CLI coverage validates substantial parts of
   it, but not their single public narrative.

Publisher signatures, global catalog freshness, online downloading, and an
automated human-review substitute are not gaps for this milestone; they are
explicit non-goals.

## Ordered vertical slices

### 1. Freeze one hermetic CodeSupply fixture

**Goal and visible result:** add a small, committed fixture set that represents
one authorized local target, one deterministic `secure-json-v1` engine output
with a candidate, and one matching package/version in the existing synthetic
OSV source. A reader can see exactly which inputs are synthetic and how they
link.

**Likely files/crates:** `tests/fixtures/codesupply-ready/` (new),
`tests/fixtures/osv-source/`, `crates/secureflow-cli/tests/cli.rs`; only if an
existing fixture cannot express a valid report, add a test-only helper rather
than a new runtime capability.

**Acceptance criteria:**

- All fixture inputs are committed, small, offline, and labeled synthetic.
- The engine output imports as `secure-json-v1`; the run contains a stable
  finding ID usable by `correlate-package`.
- The catalog contains a matching exact ecosystem/package/version and retains
  source/license provenance.
- Re-running the fixture leaves every input byte-identical.

**Tests/commands:** targeted CLI integration test; `cargo test -p secureflow --test cli --locked`; schema validation through the existing CLI test helpers.

**Risks:** accidentally making fixture content look like a real unreviewed
advisory or binding a candidate to an advisory semantically. Mitigate with
synthetic names and contract assertions that human authority remains unchanged.

### 2. Add the hermetic public demo harness

**Goal and visible result:** create a single `scripts/demo-codesupply-local.sh`
that performs the six-step flow above and retains a complete artifact directory
under a new temporary path.

**Likely files/crates:** `scripts/demo-codesupply-local.sh` (new),
`tests/fixtures/codesupply-ready/`, `crates/secureflow-cli/tests/cli.rs`.
No production crate should change unless the script proves a real composition
gap.

**Acceptance criteria:**

- Requires no sibling repository and makes no HTTP request.
- Uses `umask 077`, refuses missing prerequisites, and never overwrites an
  existing output.
- Supplies authorization metadata and fixed revision to `scan`.
- Creates, verifies, and installs a `core` bundle with
  `--expected-manifest-sha256`; the unverified-install path is not used.
- Validates the run and correlation, generates an orchestration envelope, and
  prints its artifact directory and hashes.
- Fails if a bundle/profile/hash/artifact link is substituted or if the target
  changes during execution.

**Tests/commands:** `bash scripts/demo-codesupply-local.sh`; a CLI integration
test executes the harness or its exact command sequence; negative tests for
missing authorization, wrong manifest SHA-256, profile substitution, and
cross-run correlation.

**Risks:** shell portability and accidental dependency on developer state.
Keep the script Bash-only, derive paths from its own location, and use committed
fixtures exclusively.

### 3. Make the evidence boundary machine-checkable

**Goal and visible result:** make the demo's final artifacts easy to inspect:
the run, installed-catalog verification, correlation, and orchestration plan
all validate and point only to the intended inputs.

**Likely files/crates:** primarily `crates/secureflow-cli/tests/cli.rs` and
fixture expectations; possibly `crates/secureflow-cli/src/main.rs` only if a
necessary stable machine-readable field is missing from an existing command.

**Acceptance criteria:**

- The test asserts SHA/link consistency from run manifest through correlation
  and orchestration.
- The correlation retains `causal_relationship_asserted=false` and
  `validation_authority=human-only`.
- The orchestration output contains evidence references but no synthetic human
  verdict.
- No input artifact is modified by the flow.

**Tests/commands:** `cargo test -p secureflow --test cli --locked`; run
`secureflow correlation-validate` and `secureflow orchestration-validate` on
the generated artifacts if the CLI exposes those validators.

**Risks:** adding a convenience output that overstates security meaning. Treat
the contracts in `docs/contracts/secureflow-correlation-v2.md` and
`docs/contracts/secureflow-orchestration-v1.md` as the authority.

### 4. Publish the maintainer walkthrough and claim boundary

**Goal and visible result:** an external maintainer can run the demo, inspect
its artifacts, and understand both what is demonstrated and what is not.

**Likely files/crates:** `docs/demo-codesupply.md` (new), `README.md`,
`docs/demo.md`, and possibly `docs/architecture.md`; no crate changes.

**Acceptance criteria:**

- Documents prerequisites, one command, expected artifact list, reproducibility
  procedure, and clean-up behavior.
- Separates synthetic demonstration data from any real pilot evidence.
- States the source of each SHA-256 and that a manifest hash alone is not a
  publisher signature.
- States explicit authorization, local-first behavior, and the optional manual
  review step.
- Links the normative catalog-bundle and correlation contracts.

**Tests/commands:** execute every documented command in a fresh checkout;
`rg -n "validates vulnerability|automatic.*decision|publisher signature" README.md docs/demo-codesupply.md` should find no unsupported claim.

**Risks:** documentation drift. Keep the walkthrough derived directly from the
script and make the script the executable source of truth.

### 5. Capture a release-grade reproducibility receipt

**Goal and visible result:** a tagged release candidate has a retained,
independently rerunnable receipt that the CodeSupply demo and existing quality
gates passed.

**Likely files/crates:** `.github/workflows/ci.yml` only if the new demo needs a
CI job; `scripts/release-local.sh`; release notes or
`docs/evidence/codesupply-ready-<version>.md` (new). Do not add telemetry or
remote services.

**Acceptance criteria:**

- The demo runs in CI or an equivalent documented clean-checkout gate.
- Rust formatting, Clippy, full workspace tests, dependency audit, and the demo
  pass on the pinned toolchain.
- Release artifacts include source archive, checksums, SBOM, and provenance as
  already produced by `scripts/release-local.sh`.
- The receipt records commit/tag, toolchain, commands, artifact SHA-256 values,
  and results without copying private targets or user data.

**Tests/commands:** `bash scripts/release-local.sh` in a clean checkout;
`cargo +1.92.0 fmt --all -- --check`; `cargo +1.92.0 clippy --workspace --all-targets --locked -- -D warnings`; `cargo +1.92.0 test --workspace --locked`; `cargo audit`.

**Risks:** `release-local.sh` intentionally rejects a dirty checkout. Create the
receipt only after intended changes are committed in a clean release worktree;
do not touch unrelated untracked files in the present workspace.

## Release checklist

### Documentation and demo

- [ ] `docs/demo-codesupply.md` has been executed verbatim from a fresh clone.
- [ ] The script uses only local committed fixtures and produces a new private
  temporary artifact directory.
- [ ] The README points to the public demo and its non-claims.
- [ ] The artifact map identifies run manifest, engine report, bundle, manifest,
  installed SQLite catalog, correlation envelope, and orchestration envelope.

### Tests and reproducibility

- [ ] Targeted demo integration and existing workspace tests pass.
- [ ] Format, Clippy, audit, and release script pass on Rust 1.92.0.
- [ ] The demo passes twice with byte-stable fixture inputs; differences are
  limited to explicitly documented run timestamps/temporary paths where
  applicable.
- [ ] Bundle verification uses the exact expected manifest SHA-256 and rejects
  wrong profile/hash inputs.

### Permitted and prohibited claims

- [ ] Permitted: local, provenance-retaining advisory ingestion; reproducible
  bundle integrity verification; conservative package/version context; and
  human-only validation.
- [ ] Prohibited: a correlation proves a vulnerability, causality,
  reachability, exploitability, remediation, publisher authenticity, catalog
  freshness, or complete ecosystem coverage.
- [ ] Prohibited: SecureFlow downloads feeds, crawls third parties, performs an
  active scan or exploit, transmits to an AI service, or patches code in this
  flow.

### Project security and artifacts

- [ ] No fixture contains credentials, a real private target, or unredacted
  personal review data.
- [ ] Inputs are immutable during execution; outputs are new files with
  restrictive permissions.
- [ ] Release receipt, checksums, SBOM, and provenance are published beside the
  exact source version.

## Explicit postponements

- Publisher signing, Sigstore integration, key rotation, freshness proofs, and
  rollback protection for catalog bundles.
- Any HTTP downloader, crawler, third-party API call, feed synchronization, or
  hosted catalog service.
- Automatic dependency discovery, reachability analysis, exploit validation,
  severity re-ranking, patch generation, or autonomous remediation.
- Real AI transport, agent orchestration, or an AI-derived validation decision.
- A dashboard, multi-user workflow, benchmark expansion, or a new web-scanning
surface.
- A real-world vulnerability case study unless the maintainer's written scope,
data-handling permission, and human review are available separately.
