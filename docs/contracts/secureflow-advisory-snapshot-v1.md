# `secureflow-advisory-snapshot-v1` contract

A snapshot is the reproducible boundary between network acquisition and local
processing. SecureFlow does not download inside the parser. It receives an
already acquired OSV ZIP and requires a locator, immutable revision, timestamp,
hash, and local license evidence.

## Invariants

- At most 512 MiB compressed, 16 GiB decompressed, 1.1 million entries, and
  4 MiB per record.
- Reject symlinks, encryption, path traversal, duplicate names, special files,
  and compression ratios greater than 1,000:1.
- Every entry ends in exactly one of `records/` or `quarantine/`; accounting
  must reconcile the whole archive.
- Raw JSON is preserved byte-for-byte. Only indexed fields normalize terminal
  control characters.
- Files use `0600`, directories use `0700`, publication renames into a new
  directory, and every hash is validated afterward.
- GHSA requires CC-BY-4.0 evidence; RUSTSEC requires its supported per-record
  license; MAL requires OpenSSF Apache-2.0 evidence and every `affected` object
  must point to the official
  `ossf/malicious-packages/.../osv/malicious/...` path.
- PYSEC requires PyPA Advisory Database CC-BY-4.0 evidence, and GO requires Go
  Vulnerability Database `data/LICENSE` CC-BY-4.0 evidence. These source
  families remain distinct even when OSV distributes them in one ecosystem ZIP.
- An unknown record or one without accepted provenance remains in quarantine;
  it never disappears or enters the catalog.
- `validation_authority` is always `human-only`.

Policy v2 added the OpenSSF-specific check. Policy v3 adds PyPA and Go source
classification with source-specific license evidence. The validator continues
to read historical v1 and v2 snapshots using each manifest's original identity
domain so retained evidence remains valid.

## Catalog lifecycle

`catalog-import-snapshot` first records the snapshot as `preparing`, imports
idempotent batches, completes each source, deactivates records proven absent
from a complete source, and finally marks the snapshot `complete`. Older
artifacts are blocked. Reprocessing the same hash, revision, and timestamp under
a different policy is allowed; a different artifact with the same timestamp is
not.

Updates through `modified_id.csv` use the separate
`secureflow-advisory-delta-v1` contract, chained to the base snapshot with
replay, recovery, and explicit `withdrawn` handling. Absence from the index
never deactivates a record. Complete ZIPs remain authoritative for periodic
presence and absence reconciliation.
