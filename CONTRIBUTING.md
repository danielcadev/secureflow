# Contributing to SecureFlow

SecureFlow accepts narrowly scoped changes that preserve its local-first,
authorized-use, human-validation model.

## Development setup

The repository pins Rust 1.92. Run the same gates as CI:

```bash
rustup run 1.92.0 cargo fmt --all -- --check
rustup run 1.92.0 cargo clippy --workspace --all-targets --locked -- -D warnings
rustup run 1.92.0 cargo test --workspace --locked
rustup run 1.92.0 cargo audit
```

If Rust was installed through a distribution package rather than rustup, use
the pinned CI container or install the pinned rustup toolchain. The local
release script fails closed instead of silently using a different compiler.

Changes to JSON contracts must update the corresponding schema, semantic
validator, positive test, and tamper/negative test. New benchmark data must
state its split, provenance, license, units, failures, and claim limitations.

## Security invariants

- Require explicit authorization before target analysis.
- Keep network execution disabled unless a separately reviewed design changes
  that boundary.
- Never execute target code during static inventory.
- Preserve inputs and create derived artifacts with no silent overwrite.
- Treat automated output as a candidate; only a recorded human decision can
  validate a vulnerability.
- Keep source code, secrets, credentials, raw traffic, and private advisory
  databases out of commits, issues, logs, and model payloads.
- Do not convert synthetic capacity or development fixtures into claims of
  real-world coverage, superiority, or production readiness.

## Pull requests

Describe the threat model or invariant affected, tests executed, compatibility
impact, and any residual risk. Keep external projects and their histories out
of this repository; integrations should use versioned contracts or explicit
adapters with compatible licensing. Update
[`docs/threat-model.md`](./docs/threat-model.md) when a change adds or alters a
trust boundary.

Report suspected vulnerabilities privately as described in
[`SECURITY.md`](./SECURITY.md).
