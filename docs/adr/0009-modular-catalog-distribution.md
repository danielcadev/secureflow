# ADR 0009: Modular catalog distribution

## Status

Accepted for the local prototype on 2026-08-23.

## Context

The retained real pilot catalog occupies 1.20 GB uncompressed and contains two
very different record classes: 9,986 conventional advisory records and 219,658
OpenSSF malicious-package reports. Shipping that database inside the normal
application release would make a small Rust binary unnecessarily expensive to
download and update. A profile label alone would also be unsafe: catalog v3
does not persist the source `kind`, and 12 canonical components in the retained
pilot cross the advisory/malicious boundary.

## Decision

- Keep the application release and catalog data as separate artifacts.
- Use one Zstandard-compressed SQLite payload and one strict manifest.
- Derive `core` and `malicious` by streaming current raw records into fresh
  catalogs, canonicalizing only the selected records and rebuilding FTS.
- Preserve `full` as the byte-exact payload of one logically complete SQLite
  online-backup snapshot, without claiming identity with the live source file.
- Classify only matching stored source/license/locator/identifier declarations
  and fail closed for unknown records in projected profiles; this does not
  authenticate upstream origin.
- Bind compressed bytes, database state, composition and frozen origin in the
  manifest.
- Distinguish internal integrity from authenticity; an unsigned manifest needs
  an external SHA-256 pin.
- Install only to a new destination set after bounded decompression, authenticated
  manifest pinning by default, sidecar rejection and final-path verification.

## Consequences

Users can install a smaller queryable profile without downloading history they
do not need. The malicious profile is a standalone research catalog, not an
overlay to attach beside core. New source families require an explicit profile
policy revision. Publishing catalog data also requires a separate license and
provenance review; adding the bundler does not add data to the repository or
application release.

Delta distribution, signed metadata, rollback protection, cross-profile query
federation and reproducible byte-for-byte projections remain future work.

## 2026-08-25 policy revision

`secureflow-catalog-profile-policy-v2` adds exact PyPA Advisory Database and Go
Vulnerability Database declarations to `core`. OpenSSF records from Go or PyPI
remain in `malicious`. The change was measured on a verified copy and does not
alter or relabel the retained policy-v1 bundle evidence.
