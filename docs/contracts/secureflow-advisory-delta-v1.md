# `secureflow-advisory-delta-v1` contract

## Purpose

Process recent changes from an OSV **per-ecosystem** `modified_id.csv` without
renormalizing a complete ZIP and without turning absence into deletion.
Acquisition happens outside the parser. The manifest retains the index,
revision, hash, cursor, payloads, sources, licenses, quarantine, and base
snapshot.

Official OSV documentation defines each row as
`<modified RFC3339>,<ID>`, ordered newest to oldest. It lists new or modified
records; it is not a complete inventory.

## Preparation

`delta-prepare-osv` requires:

- the acquired per-ecosystem index and its locator, generation, or ETag;
- a flat directory containing exactly one `<ID>.json` for every row after the
  exclusive cursor;
- timestamp equality between the row and `record.modified`;
- an ecosystem, primary identifier, source, and license accepted by the same
  snapshot policy;
- a complete base snapshot and, except for the first delta, the previous delta
  identifier;
- an acquisition timestamp no earlier than the newest change.

The complete index is retained. Each file ends in `records/` or `quarantine/`,
uses private permissions, and is bound by SHA-256. A missing payload is an
error, never a deactivation. Any quarantine preserves the evidence but blocks
application and cursor advancement.

## Applying to catalog v3

`catalog-import-delta`:

1. Revalidates the manifest, index, and every file.
2. Transactionally migrates a writable v2 copy to v3 when required.
3. Requires the base snapshot to remain the newest complete snapshot.
4. Requires a linear `previous_delta_id` chain and contiguous cursor.
5. Rejects forks, old timestamps, and different content with the same
   `modified` value.
6. Preserves each raw revision and updates FTS row-by-row in the same
   transaction.
7. Reconciles per-source counts before marking the delta `complete`.

Replaying a complete delta verifies every hash against `delta_records` and does
not reapply historical state. Interruption between batches leaves `preparing`;
the same manifest can resume idempotently. A different delta cannot overtake
it. Destructive recovery starts from a verified backup rather than manually
deleting rows.

Batch resume is not one end-to-end atomic transaction: committed batches exist
physically while the delta remains `preparing`. During that state, advisory and
provenance queries, backups, and unrelated jobs fail conservatively. Only
integrity and count diagnosis plus resuming the exact manifest are allowed. A
consumer that opens SQLite outside SecureFlow's API must enforce the same
barrier and must never present partial state as a valid cursor.

## Deactivation semantics

- `absence_deactivates_record=false` always.
- A record with `withdrawn` is an explicit upsert retained with withdrawn state
  for traceability.
- Only a later complete snapshot can deactivate records no longer present in a
  complete source.
- Neither a model nor a heuristic infers deletion.

`withdrawn` also does not prove that a specific finding is true or false.

## Compatibility and limits

- Current writable SQLite schema: v3.
- V2 catalogs and backups remain verifiable read-only; the first write migrates
  an authorized database or copy.
- At most 256 MiB per index, 1.1 million rows, and 4 MiB per accepted payload.
- V1 accepts only the per-ecosystem format, not the prefixed global index.
- SecureFlow contains no downloader or automatic polling.
- `validation_authority=human-only`.

## Current evidence

Tests cover missing payloads, tampering, quarantine, `withdrawn`, replay,
interruption and resume, forks, and old snapshots. On a copy of the real
229,644-record catalog, the v2-to-v3 migration preserved counts and passed
integrity checks. An official overlapping replay of seven RUSTSEC records
completed with no inserts, updates, or deactivations. This validates the
pipeline and idempotence, not the arrival of seven new vulnerabilities.
