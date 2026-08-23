# ADR 0006: Separate SQLite advisory catalog at V1 scale

## Status

Accepted for the local prototype on 2026-08-23.

## Context

The human-decision JSONL ledger was measured up to 10,000 records. At that
scale it loads and validates the whole file in a median of about 91.5 ms, but
rewrites the full ledger, is capped at 128 MiB, and lacks efficient full-text
search and concurrent reads. Extrapolating it to hundreds of thousands of
advisories was not justified.

The target was restated using separate units:

- 300,000–500,000 canonical vulnerabilities as an eventual V1 scope;
- 1,000,000 or more source records and revisions as technical capacity;
- relationships as a separate dimension, not additional vulnerabilities.

## Decision

- Keep JSONL v2 for the small human-decision history.
- Add a separate SQLite advisory catalog inside `secureflow-knowledge`.
- Import OSV from local files without network transport.
- Preserve every raw revision and its hash.
- Record source, declared license, hashed evidence, and locator.
- Merge only exact primary identifiers and `aliases`.
- Preserve `upstream` and `related` links without merging them.
- Store compact ranges instead of materializing every version.
- Use contentless FTS5 and rebuild after bulk loads.
- Bound memory by record count and batch bytes.
- Reserve AI for later prioritization, never bulk ingestion.

## Evidence

The release benchmark on the documented NVMe/Btrfs host measured 100k, 500k,
and 1M synthetic records. One million source records produced 900k canonical
entities, used 2.07 decimal GB, and completed normalization plus FTS in 104.736
seconds. Exact lookup had a median of 66.451 microseconds. See
`docs/knowledge-benchmark.md` for the method, full results, and limitations.

## Consequences

The infrastructure demonstrates capacity for one million synthetic records
without models or external services. It does not mean that SecureFlow contains
one million real vulnerabilities, or that 2.07 GB estimates real feeds. Size
depends on detail, ranges, references, and historical revisions.

The database still has one writer. WAL supports readers, but concurrency has
not been measured. Removing an upstream alias requires a snapshot rebuild to
split components. Before acquiring a real feed, its license, provenance,
incremental strategy, and visible rejection handling must be approved.
