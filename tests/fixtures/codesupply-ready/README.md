# Synthetic CodeSupply fixture v1

This repository-owned fixture is authorized for the local CodeSupply demo.
The operator acknowledges that narrow scope through `scan --authorized`; the
label `codesupply-demo-operator` records that acknowledgement, not a human
vulnerability review. No private target or real vulnerability is represented.

- `target/Cargo.toml` declares the synthetic `crates.io` package
  `secureflow-fixture` at version `1.0.0`. Its source is a harmless identity
  function and is never built or executed.
- `engine.sh` ignores its arguments and prints `engine-report.json` byte for
  byte. It is a contract fixture, not a scanner. Its source and sink labels
  point at lines 2 and 3 of `target/src/lib.rs` without asserting any risk.
- The report's finding fingerprint is SHA-256 of the UTF-8 text
  `codesupply-synthetic-candidate-v1` (no newline); SecureFlow prefixes it with
  `sf_finding_`. The report fingerprint similarly hashes
  `codesupply-synthetic-report-v1`. These are deterministic fixture identities,
  not hashes of a real analysis. The run separately hashes the actual report.
- The fixed target revision is `snapshot:codesupply-synthetic-v1`; SecureFlow
  additionally computes its own target-tree hash before and after execution.
- `../osv-source/advisories/` supplies the matching synthetic package range
  `[0, 1.0.1)` and CVE/GHSA aliases. The local ZIP includes both records. Snapshot
  preparation accepts the GHSA record and quarantines the standalone CVE record
  because its source cannot be attributed by the supported source classifier.
  The accepted record retains the CVE alias. This is one advisory assessment,
  not evidence of a vulnerability or two independent confirmations.
- `../osv-source/LICENSE` is explicitly synthetic CC-BY-4.0 evidence. The
  snapshot's GitHub source label exercises the importer contract; it is not
  evidence that GitHub published this record or licensed a real feed.

The harness supplies the exact package/version context. SecureFlow does not
infer a dependency from the target. Human review remains `pending`; an
`affected` advisory version result does not establish causality, reachability,
exploitability, or an actual security defect.

See [the walkthrough](../../../docs/demo-codesupply.md). Fixture code is covered
by the repository's MIT OR Apache-2.0 license; the reused advisory fixture keeps
its separately declared synthetic license evidence.
