# ADR 0003 — Secure Bench only in the evaluation path

## Status

Accepted for the MVP.

## Decision

SecureFlow imports retained Secure Bench results through a separate adapter.
The adapter is not part of `scan`, prioritization, Secure Skill, human review,
or knowledge import.

## Rationale

- Evaluating a system through the same path that decides production findings
  creates contamination and test-optimization risk.
- Preserving denominators, failures, and provenance prevents operational errors
  from becoming clean results.
- No neutral composite score justifies a general ranking.
- Historical studies, retired holdouts, and post-open recovery runs have
  different interpretations and must not be collapsed.

## Consequences

- Import verifies schemas and hashes but does not rerun the experiment.
- `study_kind` remains an operator declaration.
- TP/FN and FP/TN retain their distinct units instead of feeding a misleading
  accuracy number.
- Any future comparison requires a preregistered protocol, equal capabilities,
  the same population, uncertainty intervals, and stated limitations.
- No result enables superiority or production-readiness claims.
