# Secure Engine adapter boundary

## Purpose and authority

`secureflow-engine-adapter` invokes an explicitly selected local Secure Engine
binary and imports the stable subset of `secure-json-v1` needed by
`secureflow-run-v2`. It does not link the Engine crate, copy Engine extraction
logic, or reproduce the complete Engine schema.

Secure Engine owns deterministic analysis, its report fingerprint, evidence
graph, finding identifiers, evidence state, locations, and scanner
limitations. SecureFlow owns target authorization, revision/scope metadata,
process provenance, prioritization, and human review. Fields named
`authorization` or `scope` in an Engine report are ignored and cannot replace
the operator-supplied SecureFlow scope. No Engine or AI state can set
`human_review.decision`.

## Imported contract

| Engine `secure-json-v1` field | SecureFlow field |
| --- | --- |
| `engine_version` | `engine.version` |
| `report_fingerprint` | `engine.report_fingerprint` |
| Raw report bytes | retained unchanged and bound by `engine.report_sha256` |
| `graph.scope` | `engine.graph.scope` |
| Serialized `graph.nodes` / `graph.edges` lengths | `engine.graph.nodes` / `engine.graph.edges` |
| `graph.total_nodes` / `graph.total_edges` | same names under `engine.graph` |
| Finding `finding_id` / `fingerprint` | `engine_finding_id` / `engine_fingerprint` |
| Finding `verification_state` | `engine_verification_state` |
| Finding `evidence_state` | `engine_evidence_state` |
| Finding `calibration` | `engine_calibration` |
| Finding `source` / `sink` | repository-relative `source_location` / `sink_location`, including byte and line/column spans |
| Finding `evidence_path` | kind, relative location, and a local generic description |
| Finding `limitations` | `limitations` |
| Top-level Engine `abstentions` | top-level `engine_abstentions`, separate from findings and human decisions |

Unknown Engine evidence fields are retained only in the raw local report. They
are not copied into the normalized manifest, which prevents incidental source
text, host paths, or semantic payloads from crossing this adapter projection.
Titles, invariants, and limitations are intentional imported evidence and must
still be treated as local potentially sensitive artifacts.

## Compatibility and failure semantics

The importer accepts only a `secure-json-v1` `scan-report` with a non-empty
Engine version, lowercase report SHA-256 fingerprint, and a findings array. A
graph is optional for compatibility with earlier valid reports. When an older
graph omits additive scope/totals, it is interpreted as `full` and its array
lengths become the totals. New compact reports retain `finding-evidence` plus
full totals.

`secure-evidence-state-v1` is optional for older reports. When present, its
state must be one of `syntactic-lead`, `semantic-path`, `guard-aware-lead`, or
`manually-validated`, and must agree with `verification_state`. This last value
is preserved as scanner metadata only and never grants SecureFlow human
validation.

`secure-evidence-calibration-v1` is also additive and optional for historical
reports. When present, its bounded taxonomy is imported structurally rather
than flattened into a confidence score. Engine abstentions require calibration
with `disposition = explicit-abstention`; malformed abstentions fail the import.
An item under `findings` with that disposition also fails the import: the Engine
must express the distinction structurally. Neither calibration nor abstention
can set a SecureFlow human decision.

Malformed JSON, another schema/document type, invalid fingerprints,
unsupported graph scopes, totals smaller than serialized counts, mismatched
evidence states, absolute/parent/backslash evidence paths, timeouts, signals,
and process exit codes 2 or greater are operational failures. Exit 0 means a
completed scan with no findings; exit 1 means a completed scan with findings.
Neither is a security verdict.

The child runs without a shell or stdin and with a cleared environment. The
adapter retains bounded stdout/stderr, hashes the binary before and after the
run, applies process and Linux resource limits, and can require Bubblewrap with
a read-only root and private network namespace. These controls are not VM-grade
isolation.

## Commands and graph mode

The normal command retains the Engine's default report projection:

```bash
cargo run -p secureflow -- scan \
  --binary /path/to/secure \
  --authorized \
  --authorization-reviewer "researcher" \
  --output /tmp/engine-report.json \
  --manifest-output /tmp/secureflow-run.json \
  /path/to/authorized-target
```

SecureFlow always passes explicit exclusions for root and nested
`node_modules` trees. The target fingerprint applies the same directory
exclusion, so vendored JavaScript dependencies neither consume scan capacity
nor cause a run to fail because an excluded dependency changed. Source files,
tests, fixtures, and other project-owned content remain in scope.

The full graph requirement is non-default and explicit:

```bash
cargo run -p secureflow -- scan \
  --binary /path/to/secure \
  --authorized \
  --authorization-reviewer "researcher" \
  --full-engine-graph \
  --output /tmp/engine-full-report.json \
  --manifest-output /tmp/secureflow-full-run.json \
  /path/to/authorized-target
```

Full mode raises the aggregate retained-output bound (stdout plus stderr) from
32 MiB to 256 MiB. SecureFlow first performs the portable invocation understood
by the public RC2. If the response explicitly declares
`graph.scope = finding-evidence`, the adapter uses bounded capability
negotiation: it retries once with `--full-graph` and an explicit 256 MiB Engine
output ceiling, within the original overall timeout. Historical reports that
already contain a full graph are not retried. The command succeeds only if the
final report is full; otherwise it fails without writing a run manifest.

## Measured evidence

The focused adapter tests cover exit 0/1/2 handling, timeout/process cleanup,
environment clearing, schema and compatibility parsing, deterministic import,
compact/full selection, malformed metadata, evidence-state agreement, graph
accounting, path rejection, and omission of unknown secret/path fields from the
normalized projection. These are contract tests, not vulnerability or coverage
evidence.

A local compatibility smoke used the public Secure Engine `0.1.10-rc2`
qualification binary with SHA-256
`1094f6640d690586da00a5e169e5b5d172580f90b25ff471811ad1c1fbf6fb91`.
Default and full-graph-required runs on the tracked fixture both completed,
validated as `secureflow-run-v2`, and retained an empty full graph. The smoke
explicitly disabled Bubblewrap and its temporary artifacts are not published,
so it demonstrates contract compatibility only. It is not a holdout,
vulnerability result, coverage measurement, sandbox result, or comparison with
human researchers.

## Verification gates

- Rust formatting and `git diff --check`: pass.
- `cargo check --workspace --all-targets --locked`: pass.
- strict workspace Clippy with all targets, the lockfile, and `-D warnings`:
  pass with no warning exemption.
- `cargo test --workspace --locked`: 185 passed, 0 failed with pinned Rust
  1.92.0.
- local `cargo-audit --no-fetch`: 173 locked dependencies checked against
  1,226 retained advisories, with no reported vulnerability.
- normalized-manifest absolute-path/obvious-secret check: pass.

No network transport, model call, target-code execution, vulnerability
validation, or comparative human-performance claim is part of this adapter.

A second local integration used corrected Secure Engine commit `c5c67cd` and
binary SHA-256
`74caae8462bf80f8be45787262d7addf685c7711db4b6c70353487be9723b96f`.
On the neutral calibration fixture, compact and negotiated-full SecureFlow runs
both retained 14 pending candidates and 7 deterministic Engine abstentions; the
full run retained all 688 nodes and 1,247 edges. On the authorized, clean npm
CLI checkout at commit `b888cc9a9ff34a8b023ff47b784692396635397b`, the
compact run retained 0 candidates and 3 explicit Engine abstentions (SE1001,
SE1004, and SE1013), with internal totals of 208,157 nodes and 368,627 edges.
The end-to-end npm run took 25.33 seconds and peaked at 987,332 KiB under GNU
time; its raw report was 2,507,778 bytes. These are single-host engineering
measurements, not benchmark results. Zero candidates is not a clean verdict,
and the three abstentions are neither vulnerabilities nor human decisions.

A later general compact-path optimization at Secure Engine commit
`4eee7eeaf34856416f8acc5719d296efbeffd251` preserved the npm report fingerprint
`0c76afa4aa89f99d7c48bc08edc37f8e7e375a46ebb00aa43149f78bd3635b82`
and every finding, abstention, fact, and conceptual graph total. Two local
release samples reduced mean peak RSS from 987,470 KiB to 737,420 KiB, about
25.3%; wall time was not claimed as a speedup. Full-graph mode remained opt-in
and retained all 57,748 facts in a 539,259,886-byte report. These measurements
are traceable local evidence, not independently reproduced resource guarantees.

Human source triage found no complete supported actor/control/boundary/impact
chain for the three npm abstentions. The test-only process mock, same-authority
CI URL/token pair, and documented owner-managed workspace exception remain
scanner-learning cases rather than vulnerabilities. Exact dispositions and
claim limits are retained in
[`npm-cli-engine-triage-2026-08-29.json`](./evidence/npm-cli-engine-triage-2026-08-29.json).
