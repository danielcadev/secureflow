# Local storage benchmarks

## Questions

1. How far can a JSONL ledger support human decisions?
2. Can a local SQLite catalog normalize and query 100k, 500k, and 1M records
   without AI or external services?

These are different workloads. JSONL preserves a small, auditable history of
human decisions. SQLite serves external advisories, aliases, packages,
revisions, and text. This benchmark neither compares products nor measures
vulnerability detection.

## Environment

Date: 2026-08-23.

- Fedora Linux 44, kernel 7.1.8-200.fc44.x86_64;
- Rust/Cargo 1.97.1, `release` profile;
- AMD Ryzen 7 5700X, 8 cores/16 threads;
- 15 GiB RAM;
- primary results on NVMe with Btrfs under `/home`;
- five queries per class, reporting the median.

Development results from `tmpfs` are excluded from the primary table because
they would be optimistic relative to persistent storage.

## Ledger JSONL v2

Command:

```bash
cargo run --release -p secureflow-knowledge \
  --example ledger_bench -- \
  --record-version v2 --iterations 5 100 1000 10000
```

The fixture is replicated with unique identifiers. Generation and writing are
not measured; every sample loads, parses, and validates the complete ledger
before filtering.

| Records | Size | Median load + validation | Maximum | Exact filter |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 141,500 B | 0.920 ms | 1.188 ms | 0.270 μs |
| 1,000 | 1,415,000 B | 8.717 ms | 10.197 ms | 3.650 μs |
| 10,000 | 14,150,000 B | 91.508 ms | 102.523 ms | 131.172 μs |

Decision: keep JSONL for the small ledger, with one writer and roughly 10k
records. Do not use it as a global catalog or extrapolate linearly.

## SQLite/FTS5 catalog

Primary command:

```bash
cargo run --release -p secureflow-knowledge \
  --example catalog_bench -- \
  --root target/catalog-bench \
  100000 500000 1000000 --iterations 5
```

Each record is bounded, synthetic OSV. Ten percent share an exact alias with the
previous record, so 1M source records produce 900k canonical entities. Every
record has one package/range. They are not real vulnerabilities.

`normalize_ms` includes JSON generation, parsing, validation, hashing, raw
revisions, relationships, packages, and deduplication. `index_build_ms`
rebuilds FTS5 and checkpoints the WAL. `database_bytes` is the final file after
the checkpoint.

| Source records | Canonical entities | Final DB | Normalization | FTS | Total | Records/s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100,000 | 90,000 | 206,221,312 B | 3.481 s | 0.844 s | 4.326 s | 23,117.1 |
| 500,000 | 450,000 | 1,036,513,280 B | 30.192 s | 10.157 s | 40.348 s | 12,392.2 |
| 1,000,000 | 900,000 | 2,072,891,392 B | 80.797 s | 23.939 s | 104.736 s | 9,547.8 |

| Source records | Exact alias | Broad FTS scenario | Exact package |
| ---: | ---: | ---: | ---: |
| 100,000 | 46.680 μs | 70.584 ms | 112.841 μs |
| 500,000 | 68.291 μs | 408.601 ms | 260.053 μs |
| 1,000,000 | 66.451 μs | 843.406 ms | 450.295 μs |

The FTS query searches for a phrase present in every record and returns only 20
results; it is deliberately difficult. Alias and package lookups are selective.

The exact CSV is retained at
[`docs/evidence/catalog-benchmark-2026-08-23.csv`](./evidence/catalog-benchmark-2026-08-23.csv).

## Modular distribution on the retained real pilot

A release-profile CLI build created all three
`secureflow-catalog-bundle-v1` profiles from the retained 229,644-record
catalog. Projected profiles contain one current revision per record and no
snapshot/delta cursor claims; `full` is the byte-exact compressed payload of a
logically complete 1,202,384,896-byte online-backup artifact. It is not claimed
to be byte-identical to the live source main file.

| Profile | Source records | Canonical entities | Installed DB | Zstd payload | Reduction vs uncompressed origin DB | Create | Peak RSS | Deep verify |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `core` | 9,986 | 9,039 | 87,277,568 B | 20,242,641 B | 98.32% | 22.94 s | 144,128 KiB | 0.44 s |
| `malicious` | 219,658 | 219,647 | 1,042,145,280 B | 138,085,256 B | 88.52% | 65.57 s | 230,748 KiB | 5.29 s |
| `full` | 229,644 | 228,674 | 1,202,384,896 B | 178,149,536 B | 85.18% | 25.13 s | 144,216 KiB | 6.15 s |

Every deep verification used the exact caller-supplied manifest SHA-256,
bounded decompression, database hashes, `quick_check`, foreign keys, the stored
FTS readiness marker and composition. The hashes were supplied from retained
local evidence, not an independently authenticated publisher channel. A real
`core` install took 0.44 seconds, used mode `0600`, retained 9,986 records/9,039
canonical entities and refused overwrite.

These are one-run, warm-cache observations on the documented NVMe host.
Creation timings are order-dependent and should not be compared as independent
cold-start measurements. The final large artifacts remain under ignored
`target/` storage and are neither committed nor published. The run is retained
as observational evidence: its binary hash and command order are recorded, but
the origin database and benchmark binary are not published, so the run is not
independently reproducible. Exact evidence:
[`catalog-bundle-benchmark-2026-08-23.json`](./evidence/catalog-bundle-benchmark-2026-08-23.json).

## Decision

- The V1 target of 300k–500k canonical entities is technically plausible on
  this host.
- Capacity for 1M source records is demonstrated for this synthetic corpus,
  using about 2.07 GB and 104.7 seconds for initial loading.
- Bulk loading remains deterministic and local; no record passes through a
  model.
- The per-ecosystem incremental pipeline processes only the window after the
  cursor and maintains FTS per row. On a copy of the real catalog, an official
  overlapping window of seven RUSTSEC records took 3.99 seconds to register and
  0.99 seconds to replay. All seven were unchanged because the index contained
  no changes after the snapshot. A real insert/update window remains unmeasured.
- JSONL and SQLite remain separate because they serve different authorities and
  workloads.

## Limitations and unmeasured work

- Real records may be much larger and contain more ranges, references, and
  revisions.
- Five to twenty million relationships remain unmeasured. The synthetic million
  has roughly one primary relationship and one package per record.
- Concurrent writers, crash recovery under load, and low-power hardware remain
  unmeasured.
- No OSV/GHSA/NVD/RustSec download or refresh was timed.
- The 4 MiB record limit may reject large real cases; an adapter must account
  for them and never omit them silently.
- This benchmark does not measure precision, false positives, coverage, or
  semantic-deduplication quality.
- Five query samples do not support p95 or p99 reporting.

The evidence therefore supports "local catalog measured to 1M synthetic source
records," not "global database of 1M vulnerabilities" or "production-ready."
