# CodeSupply: local evidence to human review

An authorized maintainer can join retained local analysis evidence with an
attributed advisory catalog and hand the result to a person. This demonstration
uses only [synthetic fixtures](../tests/fixtures/codesupply-ready/README.md).
It does not demonstrate detection accuracy or a real vulnerability.

## Prerequisites and execution

Use Linux with Bash, Python 3 (standard library), GNU coreutils, a C linker,
Rust/Cargo 1.92.0, and `/usr/bin/bwrap` with working unprivileged user namespaces.
The demo keeps the CLI's required Bubblewrap sandbox; it fails if isolation is
unavailable. No sibling Secure Engine, Secure Skill, or Secure Bench checkout is
needed. On Ubuntu, the OS packages are `build-essential python3 coreutils
bubblewrap`. Install the toolchain and cache locked dependencies as a separate
setup step (these setup commands may access the network):

```bash
rustup toolchain install 1.92.0 --profile minimal --component clippy,rustfmt
cargo +1.92.0 fetch --locked
```

From the SecureFlow checkout, run:

```bash
bash scripts/demo-codesupply-local.sh
```

The script builds with `--offline --locked`, derives repository paths from its
own location, and creates a new `/tmp/secureflow-codesupply.XXXXXX` directory with
mode `0700` and `umask 077`. It accepts only an optional `--binary /path/to/secureflow`
for an already-built CLI (used by CI and integration tests). It has no target,
engine, authorization, or sandbox override. The scope acknowledgement applies
only to the repository's synthetic fixture; it is not authorization for another
target or a vulnerability validation decision.

The synthetic engine emits one fixed candidate. The archive contains two local
OSV records: preparation accepts one attributed GHSA record and quarantines the
standalone CVE record with unsupported source attribution. The CVE alias remains
in the GHSA record. Expected results are one candidate, one advisory version
assessment of `affected` for `crates.io/secureflow-fixture@1.0.0`, zero validated
findings, zero AI calls, and next action `human-review-or-abstain`.

The last line is:

> No network request, active scan, exploit, AI transmission, or human decision was created.

## Retained artifacts and hashes

| Artifact | Meaning and hash source |
| --- | --- |
| `fixture-inputs.json` | SHA-256 of every file in the two fixture trees, checked again at completion. |
| `engine-report.json` | Byte-exact synthetic `secure-json-v1` report; `run.json` contains its SHA-256 and the engine script hash. |
| `run.json` | Authorized run, target-tree hash, fixed snapshot revision, sandbox provenance, and one pending finding. The adapter checks the target hash before and after execution. |
| `synthetic-osv.zip` | Locally generated archive with fixed entry metadata; the snapshot records its SHA-256. |
| `snapshot/` | Validated snapshot manifest, accepted/quarantined records, and synthetic source/license evidence. No URL in these records is fetched. |
| `catalog.sqlite3` | Original snapshot import with complete snapshot provenance. |
| `catalog.core.sqlite3.zst`, `catalog.core.manifest.json` | Core projection and separate manifest: compressed hash, decompressed database hash, source/license hashes, origin and payload provenance. |
| `expected-manifest-sha256.txt`, `bundle-verification.json` | The separately hashed manifest bytes supplied to both verify and install, required profile `core`, and deep verification result. |
| `installed.core.sqlite3` | Byte-exact verified installation; its SHA-256 must equal the manifest's payload database hash. |
| `installed.sqlite3`, `installed-check.json` | Working copy with the retained snapshot reimported and SQLite integrity checked; used for correlation. |
| `*.sqlite3-shm`, `*.sqlite3-wal` | SQLite sidecars, when present; retained and checksummed beside their databases. Opening a catalog later may update these files, so inspect a copy if preserving the original checksum set. |
| `correlation.json` | Exact operator-supplied package/version context, finding ID, run hash, restored snapshot IDs, and conservative advisory assessment. |
| `orchestration.json` | Run ID/hash, target hash and correlation-file hash; human review remains pending. |
| `SHA256SUMS` | SHA-256 of every retained file except this checksum list itself, including all snapshot files. |

A `core` bundle is a current-record projection: it deliberately omits complete
snapshot/delta history. Correlation requires complete snapshot provenance. The
script preserves `installed.core.sqlite3`, makes a separate working copy, and
reimports the exact validated snapshot with the existing CLI. This fixture's
snapshot contains only the core advisory source, so its origin provenance is
restored without adding records from another profile. Reimporting an arbitrary
mixed-profile snapshot would not preserve a core-only working catalog. The
working copy has its own checksum; it is not claimed to remain byte-identical to
the bundle payload. An installed projection alone is not correlation-ready.

`manifest-sha256-pinned` means the bytes matched the caller's expected hash. The
demo computes that hash locally from a separate manifest file; it is not a
publisher signature, authenticated publisher channel, freshness proof, or
rollback protection. The snapshot's source label and license evidence are
synthetic contract data, not assertions about a real feed publisher.

## Inspect and repeat

Replace the value below with the actual retained directory printed by the run:

```bash
DEMO=/tmp/secureflow-codesupply.XXXXXX
(cd "$DEMO" && sha256sum --check SHA256SUMS)
python3 scripts/verify-codesupply-demo.py "$PWD" "$DEMO"
target/debug/secureflow validate-run "$DEMO/run.json"
target/debug/secureflow correlation-validate "$DEMO/correlation.json"
target/debug/secureflow orchestration-validate "$DEMO/orchestration.json"
```

Run the demo again and compare `fixture-inputs.json`, `engine-report.json`, and
`synthetic-osv.zip`: these are byte-stable. The target-tree hash, synthetic
finding ID, package/version, and authority semantics are stable too. Run IDs,
run/envelope/catalog timestamps, sandbox/binary/configuration hashes across
builds or machines, database bytes, bundle IDs and downstream artifact hashes
may differ. A second run is not expected to reproduce every output byte. Each
run's hash links must reconcile within that run. The integration test executes
the harness twice and checks these boundaries plus rejection of substituted
hashes, profiles, bundle bytes, cross-run and altered-manifest correlation.

The script retains artifacts on success and failure and never reuses an output
directory. Inspect the printed path before deleting that one demo directory;
there is no automatic cleanup and no repository input is modified. A failed
run's directory is incomplete and must not be treated as a receipt.

## Human authority and non-claims

The [`correlation-v2` contract](contracts/secureflow-correlation-v2.md) retains
`causal_relationship_asserted=false`, `changes_human_decision=false`,
`version_result_validates_vulnerability=false`, and
`validation_authority=human-only`. An `affected` range assessment does not prove
a defect in this target, causality, reachability, exploitability, remediation,
complete ecosystem coverage, or discovery quality.

The [bundle contract](contracts/secureflow-catalog-bundle-v1.md) defines integrity
and profile binding; the [orchestration contract](contracts/secureflow-orchestration-v1.md)
defines the fail-closed handoff. This flow performs no crawling, third-party
HTTP, active scanning, exploitation, dependency discovery, AI transmission,
patch generation, or autonomous remediation. It does not run target code.

A real person may inspect the run and then invoke `review-run --help` to record
their own decision in a new manifest, supplying the actual finding ID, reviewer,
rationale and evidence. The demo and its integration test never call `review-run`,
invent a review identity, or assign a human verdict. Keep any later reviewed manifest
separate from the original checksum set and regenerate its downstream context.

## Clean release receipt

CI runs the public script with the built CLI on Rust 1.92.0, alongside formatting,
Clippy, workspace tests, and the dependency audit, and retains its artifacts.
That CI result is evidence only for its exact revision. The v0.4.0-rc.2 GitHub
prerelease includes a separate versioned validation receipt and checksum; the
walkthrough itself is not evidence that any gate passed.

After the maintainer commits the intended changes, including the accepted plan,
and selects a matching version/tag, use a separate clean checkout with the
pinned rustup toolchain. Do not delete unrelated untracked files to clean the
current workspace. From the clean release checkout, run:

```bash
cargo +1.92.0 fmt --all -- --check
cargo +1.92.0 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.92.0 test --workspace --locked
cargo +1.92.0 audit
bash scripts/demo-codesupply-local.sh
bash scripts/release-local.sh /tmp/secureflow-codesupply-release
```

The release output path must not already exist. `release-local.sh` enforces a
clean checkout and rechecks its release gates; it produces a source-containing
archive, checksums, CycloneDX SBOM and build provenance. Retain command logs,
`git rev-parse HEAD`, `git describe --tags --exact-match`, `rustup run 1.92.0
rustc --version --verbose`, the demo directory and its `SHA256SUMS`, and the
release archive/checksum beside the exact source version. Record the audit's
advisory database revision/time and actual outcomes. Publish a receipt only
after these gates pass; never infer a pass from this walkthrough.
