# `secureflow-knowledge-record-v2` contract

## Purpose

This contract represents a security observation with a human decision in the
local JSONL ledger. It is not a global vulnerability database and repetition
does not turn a candidate into truth.

The normative schema is
[`schemas/secureflow-knowledge-record-v2.schema.json`](../../schemas/secureflow-knowledge-record-v2.schema.json).
The reader preserves v1 compatibility. New imports write v2 and neither migrate
nor reinterpret older records.

## Provenance and license

Each record fixes hashes for the manifest, target, and binary, the engine
version, and the target revision when available. `source_license` is an
explicit operator declaration, not a legal conclusion by SecureFlow:

- `spdx-declared` requires a declared expression and the SHA-256 of local
  evidence, such as a `LICENSE` file;
- `private-or-undisclosed` states that the code is not being incorporated into
  a public corpus;
- `unknown` preserves uncertainty instead of inventing a license.

SecureFlow stores the license-evidence hash, not its content or absolute path.
The SPDX expression is not resolved or validated against an external catalog.

## Traceable deduplication

`observation_fingerprint` identifies an exact observation by hashing
length-prefixed fields. It includes the target snapshot, engine name, rule,
upstream fingerprint or finding ID, locations, invariant, and evidence path.
It excludes timestamps and the human decision.

When another import produces the same fingerprint:

1. The new record remains as longitudinal evidence.
2. `duplicate_of_record_id` points to the first v2 record for that observation.
3. Different human decisions remain visible.
4. Records are not deduplicated across targets, engines, or distinct evidence.
5. V1 records never receive retroactively inferred fingerprints.

This is exact, conservative deduplication. It does not establish semantic
equivalence between scanners or modified repository versions.

## Operational limits

- Only findings with a terminal human decision can be imported.
- Rationale and evidence references are stored by SHA-256.
- Source code is not stored.
- This implementation rejects ledgers larger than 128 MiB.
- A single writer atomically replaces the file.
- SQLite/FTS5 remains a separate catalog selected through measurement and real
  query requirements.
