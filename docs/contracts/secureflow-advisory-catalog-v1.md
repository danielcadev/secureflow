# SecureFlow advisory catalog v1

## Purpose

This contract describes the local SQLite catalog of public vulnerability
records. It does not replace the JSONL human-decision ledger; the two stores
have different authorities and lifecycles.

- The catalog stores external advisories, source revisions, and relationships.
- The ledger stores SecureFlow observations that already received a human
  decision.
- Neither an external advisory nor a catalog match validates a finding.

## Physical identity

- `PRAGMA application_id = 0x53464b42`.
- `PRAGMA user_version = 3` for writes; v2 remains verifiable read-only and is
  migrated transactionally on the first writable open.
- SQLite is bundled through `rusqlite`, with WAL, foreign keys, and
  `trusted_schema=OFF`.
- Files use mode `0600` and new directories use `0700` on Unix.
- Database paths that are symlinks are rejected.
- An unrelated SQLite database is never adopted or modified as a SecureFlow
  catalog.

## Entities

| Table | Purpose |
| --- | --- |
| `sources` | stable name, declared SPDX expression, evidence hash, and locator |
| `source_record_revisions` | exact JSON, hash, upstream date, and import time |
| `source_records` | current normalized view of each identifier per source |
| `canonical_vulnerabilities` | internal identity for an exact-alias component |
| `canonical_redirects` | continuity when two components merge |
| `identifiers` | exact CVE, GHSA, RUSTSEC, OSV, or other identifiers |
| `identifier_relationships` | `primary`, `alias`, `upstream`, or `related` with provenance |
| `affected_packages` | ecosystem, package, PURL, and unexpanded ranges or versions |
| `advisory_references` | typed references from the source record |
| `source_record_fts` | local FTS5 index for title and details |
| `advisory_snapshots`, `snapshot_records`, `source_snapshot_imports` | complete snapshots, presence, and deactivation from proven absence |
| `advisory_deltas`, `delta_records`, `source_delta_imports` | incremental chain, replay, and per-source counts |

## Canonicalization rules

1. The primary identifier and `aliases` form equivalence edges.
2. Closure is symmetric and transitive, matching OSV semantics.
3. `upstream` and `related` links are retained but never merge entities.
4. Every merge preserves a redirect from the previous canonical identifier.
5. Text similarity and AI are never used to merge records.
6. An upstream correction that removes an alias requires
   `catalog-rebuild-canonicalization`; rebuilding from active records can split
   components and keeps redirects only when unambiguous.

## Ingestion

The CLI accepts one OSV JSON file or a local tree of `.json` files. Every feed
requires:

- `source_name`;
- `source_license_expression`;
- a local license or terms artifact whose SHA-256 is recorded;
- a stable `source_locator`.

A source definition is immutable within a database. Changing the license,
evidence, or locator requires a new source or an explicit migration. Input
files are never modified.

Current limits:

- 4 MiB per OSV record;
- 1,100,000 files per CLI invocation;
- 1,024 identifier relationships per record;
- 4,096 affected packages and 4,096 references per record;
- 100,000 enumerated versions per affected entry;
- maximum input directory depth of 64;
- batches capped at 50,000 records or 64 MiB.

During bulk loading, FTS is marked `dirty` while batches are normalized. Text
search fails closed until `rebuild_search_index` completes; exact identifier
and package queries do not depend on FTS. `catalog-rebuild-index` recovers an
interrupted import. Deltas maintain FTS row-by-row in the same transaction as
each batch and do not rebuild the complete index. If a delta remains
`preparing`, all advisory and provenance queries fail closed until the exact
manifest resumes or a verified backup is restored. `catalog-stats` and
`catalog-check` remain available for diagnosis.

## Queries

- `catalog-lookup`: exact identifier;
- `catalog-search`: literal phrase over title and details through FTS5;
- `catalog-package`: exact ecosystem and package name;
- `correlate-package --version`: conservative exact/SEMVER evaluation with
  affected, not-affected, unknown, and not-evaluated states;
- `catalog-stats`: logical counts and physical size;
- `catalog-check`: `quick_check`, foreign keys, and FTS state.

Every output declares `validation_authority=human-only`. A match is context for
prioritization or investigation only.

## OSV compatibility

The parser consumes required fields and tolerates additional fields for forward
compatibility. Ranges and versions remain bounded JSON; individual versions are
not expanded into rows. Correlation v2 interprets only exact lists and valid
`SEMVER` ranges; `GIT`, `ECOSYSTEM`, or ambiguous data produces `unknown`.

The format neither downloads sources nor infers their licenses. Snapshots and
deltas verify terms, counts, hashes, and rejections. Absence from
`modified_id.csv` never deletes a record; see
[`secureflow-advisory-delta-v1`](./secureflow-advisory-delta-v1.md).
