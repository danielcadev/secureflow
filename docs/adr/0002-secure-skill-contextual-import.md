# ADR 0002 — Secure Skill as a contextual import

## Status

Accepted for the MVP.

## Decision

SecureFlow integrates Secure Skill through a Rust import adapter and a separate
envelope. It does not copy the full methodology, invoke a model, or
automatically project its findings into Secure Engine's canonical validated
type.

## Rationale

- Secure Skill produces contextual reasoning, not deterministic scanner
  evidence.
- `verification_status` belongs to the upstream contract and does not prove
  that a SecureFlow human validated the finding.
- Retaining the payload, hashes, version, commit, and license makes the method
  that produced an assessment reproducible.
- Keeping findings and non-findings separate prevents metric inflation.
- The boundary reduces coupling and allows Secure Skill to evolve without
  moving its code or history.

## Consequences

- The envelope is a parallel artifact linked by `run_id` and target hash.
- Future reconciliation between deterministic and contextual findings must use
  explicit links and must never merge solely on textual similarity.
- The current ledger rejects these candidates because they lack a SecureFlow
  human decision.
- Automating Skill execution is outside this increment.

## License

Secure Skill declares MIT. The adapter targets its public contract 1.1 and
records the hash of the license used. SecureFlow retains a third-party notice
and does not incorporate the full Skill text.
