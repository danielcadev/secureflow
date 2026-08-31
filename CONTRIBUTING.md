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
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 scripts/lint_release_notes.py docs/releases
```

If Rust was installed through a distribution package rather than rustup, use
the pinned CI container or install the pinned rustup toolchain. The local
release script fails closed instead of silently using a different compiler.
Dependency-license evidence changes must also preserve the offline,
checksum-bound behavior and limitations documented in
[`docs/dependency-license-evidence.md`](./docs/dependency-license-evidence.md).

Release-note paragraphs and list items must each use one physical source line;
this lets GitHub use the full rendered content width instead of preserving an
editor's hard wrap. Each release-note file also has exactly one hidden
`secureflow-release-state` marker. Normal CI permits `draft`, but a tag build
fails unless its selected note is marked `final`. A release from a clean commit
creates a host-specific Linux bundle and a separate deterministic source-only
archive:

```bash
bash scripts/release-local.sh /tmp/secureflow-release
(cd /tmp/secureflow-release && sha256sum --check ./*.sha256)
```

Do not describe the Linux bundle as cross-host reproducible without an actual
independent comparison. The complete integrity, attestation, source
reproduction, and limitation procedure is in
[`docs/release-verification.md`](./docs/release-verification.md).

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
