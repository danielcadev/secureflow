# ADR 0004 — Optional, offline, contract-first AI

## Status

Accepted for the MVP.

## Decision

The first AI integration prepares redacted local requests and applies retained
structured responses. The workspace does not contain provider transport.

## Rationale

- Audit exactly what could leave the machine before enabling network access.
- Measure budgets, model family, prompt version, and tokens without granting
  the model security authority.
- Avoid spending tokens on unselected findings.
- Test privacy and accounting invariants without credentials.
- Decouple the logical Luna family from concrete API model identifiers.

## Consequences

- `ai-prepare` fails without explicit enablement and consent.
- A minimized payload can lose context and must abstain when insufficient.
- The full response remains a local artifact; the run records its hash and
  structured result.
- Future transport requires a separate review of credentials, data residency,
  retries, cost, rate limits, and logging.
- Stronger models are never selected automatically.
