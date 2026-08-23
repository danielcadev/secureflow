# ADR 0001 — Boundaries and external adapters

## Status

Accepted for the MVP.

## Decision

SecureFlow is a new workspace that initially integrates Secure Engine, Secure
Skill, and Secure Bench through external processes and versioned contracts.
Their source code is neither moved nor copied into this repository.

## Rationale

- Preserve each project's history, releases, and ownership.
- Reduce coupling between release cycles.
- Make every consumed version and hash visible.
- Keep Secure Bench outside the production decision path.
- Avoid accidentally mixing MIT, Apache-2.0, and third-party licensing terms.
- Allow a scanner to be replaced without rewriting the orchestrator.

## Consequences

- Schemas and exit codes must be validated.
- The MVP treats binaries as explicit dependencies.
- The Linux adapter uses a process group and resource limits. Stronger
  filesystem isolation requires an explicit, separately reviewed decision.
- Integration tests use fixtures and retained reports.
- A direct Rust API remains a later decision, not part of the first vertical
  slice.

## Decisions deferred at the time

- The repository license was later resolved as `MIT OR Apache-2.0`.
- SQLite versus another local store required profiling and was later resolved
  by ADR 0006.
- A native UI versus a later interface remains open.
- No production AI provider has been selected.
