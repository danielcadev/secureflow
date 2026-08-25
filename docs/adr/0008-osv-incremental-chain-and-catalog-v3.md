# ADR 0008: Incremental OSV chain and catalog v3

## Status

Accepted on 2026-08-23.

## Context

Reimporting complete ZIPs for every change is expensive. `modified_id.csv`
lists new or modified identifiers, but is not a complete snapshot; absence
therefore cannot represent deletion. Catalog v2 retained only snapshots.

## Decision

- Add `secureflow-advisory-delta-v1` only for per-ecosystem indexes.
- Require indexes, payloads, and licenses acquired outside SecureFlow and bound
  by hash and revision.
- Chain every delta to a complete snapshot and the previous delta.
- Advance the cursor only when every payload is accepted and counts reconcile.
- Treat `withdrawn` as an explicit retained upsert.
- Reserve deactivation by absence for later complete snapshots.
- Store deltas, records, and imports in SQLite schema v3.
- Keep v2 verifiable read-only and migrate only on writable open.
- Maintain FTS row-by-row for deltas and retain rebuilds for bulk loads or
  `dirty` recovery.

## Consequences

Replay and interruption are idempotent, forks and rollbacks are rejected, and
correlations can bind complete deltas. A `preparing` delta blocks advisory and
provenance queries, backups, and unrelated jobs until resume or backup recovery;
counts and integrity checks remain available for diagnosis. Committed batches
may exist physically during recovery but never form a publishable cursor. No
"abort" operation deletes evidence. Complete ZIPs remain necessary to
reconcile presence and detect genuine absence.

On 2026-08-25 the delta classification policy advanced to v2 alongside
snapshot policy v3, adding source-specific PyPA and Go evidence. The manifest
contract and absence semantics did not change; retained policy-v1 deltas remain
valid under their original identity domain.
