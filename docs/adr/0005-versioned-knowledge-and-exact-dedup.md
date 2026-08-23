# ADR 0005: Versioned knowledge v2 and traceable exact deduplication

## Status

Accepted for the MVP.

## Context

The v1 record preserved the decision and scanner provenance, but did not make
the source license explicit or link the same observation across runs. Changing
v1 in place would make existing artifacts ambiguous.

## Decision

- Preserve strict v1 reads.
- Write new imports as `secureflow-knowledge-record-v2`.
- Require an operator-declared license status, including `unknown`.
- Require hashed evidence for an SPDX declaration.
- Preserve repeated observations and link them to the first v2 record.
- Limit the ledger to 128 MiB and one writer during the MVP.
- Do not infer equivalence across engines or migrate v1 automatically.

## Consequences

History and human disagreements remain auditable. A ledger may contain v1 and
v2, so consumers must inspect `record_version` per record. Deduplication is
deliberately conservative and may retain semantic duplicates; reducing them
requires a separately evaluated reconciler. A license declaration is not legal
advice.
