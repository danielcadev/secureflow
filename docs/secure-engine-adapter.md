# Secure Engine adapter boundary

## Purpose and authority

`secureflow-engine-adapter` invokes an explicitly selected local Secure Engine
binary and imports the stable subset of `secure-json-v1` needed by
`secureflow-run-v1`. It does not link the Engine crate, copy Engine extraction
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
| Finding `source` / `sink` | repository-relative `source_location` / `sink_location`, including byte and line/column spans |
| Finding `evidence_path` | kind, relative location, and a local generic description |
| Finding `limitations` | `limitations` |

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

The normal command requests the Engine's compact report:

```bash
cargo run -p secureflow -- scan \
  --binary /path/to/secure \
  --authorized \
  --authorization-reviewer "researcher" \
  --output /tmp/engine-report.json \
  --manifest-output /tmp/secureflow-run.json \
  /path/to/authorized-target
```

The full graph is non-default and explicit:

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

Full mode raises the retained-output bound from 32 MiB to 256 MiB. The normal
compact mode remains appropriate for portable finding review.

## Measured evidence

The focused adapter tests cover exit 0/1/2 handling, timeout/process cleanup,
environment clearing, schema and compatibility parsing, deterministic import,
compact/full selection, malformed metadata, evidence-state agreement, graph
accounting, path rejection, and omission of unknown secret/path fields from the
normalized projection. These are contract tests, not vulnerability or coverage
evidence.

A local integration run used Secure Engine commit `e6001c0` and release binary
SHA-256 `ae93a4d156e53d6af90daf8a06541ea76e9c4cb4e41de11c41ce6bd621a7e88a`
against the Engine-owned `lead-quality-vscode-go` regression fixture. Engine
exit 1 was accepted as a completed scan with three deliberately planted
candidates: two SE1010 positive controls and one bounded SE1011 syntactic lead.
All three entered SecureFlow with `human_review.decision = pending`.

The compact raw report was 106,137 bytes and the normalized manifest was 11,005
bytes. The imported Engine report fingerprint was
`3a8707b2d0e36779339249f14a8b0b43224a9ba488ed185ca931a3e6d608dbf2`.
The manifest retained 12 serialized nodes, 13 serialized edges, 203 total
nodes, and 332 total edges. The first run completed in 0.60 seconds with 14,900
KiB peak RSS on the local host. A second independent invocation produced the
same Engine version, report fingerprint, graph summary, ordered findings,
locations, evidence states, limitations, and human states. Volatile run IDs,
timestamps, and raw report byte hashes are not semantic determinism inputs.
An explicit `--full-engine-graph` run retained all 203 nodes and 332 edges in a
523,300-byte raw report, confirming that compact/full selection is deliberate
and separately reflected in the configuration hash.

This fixture run demonstrates adapter compatibility and reproducibility only.
It is not a holdout, vulnerability result, coverage measurement, or comparison
with human researchers.

## Verification gates

- Rust formatting and `git diff --check`: pass.
- `cargo check --workspace --all-targets --locked`: pass.
- strict workspace Clippy with all targets, the lockfile, and `-D warnings`:
  pass with no warning exemption.
- `cargo test --workspace --locked`: 169 tests passed, 0 failed.
- local `cargo-audit --no-fetch`: 173 locked dependencies checked against
  1,225 available advisories with no reported vulnerability.
- two independent compact imports: identical Engine version, report
  fingerprint, graph summary, findings, byte/line locations, states, and
  limitations.
- normalized-manifest absolute-path/obvious-secret check: pass.

No network transport, model call, target-code execution, vulnerability
validation, or comparative human-performance claim is part of this adapter.
