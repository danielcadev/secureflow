# Third-party notices

## rusqlite and SQLite

- Crate: `rusqlite` 0.40.2
- License: MIT
- SQLite linkage: bundled through `libsqlite3-sys`

SecureFlow uses `rusqlite` as a Rust interface and bundles SQLite for a
reproducible local catalog with FTS5. SQLite itself is dedicated to the public
domain. These dependencies contain no advisory feed data.

## Secure Skill

- Project: Secure Skill
- Source inspected as a separate local checkout; it is not redistributed here.
- Upstream contract: `urn:usesecure:review-contract:1.1`
- License: MIT
- Copyright: Copyright (c) 2026 Secure contributors

SecureFlow's adapter implements interoperability with the public review
contract. The Secure Skill source and repository history remain outside this
workspace. An import records the exact source revision and SHA-256 hashes of
the contract, skill instructions and license used.

## Secure Bench

- Project: Secure Bench
- Source inspected as a separate local checkout; it is not redistributed here.
- Interoperability contract: `secure-bench-result-v2`
- License: Apache-2.0

SecureFlow loads Secure Bench's result schema at runtime and verifies retained
artifacts by hash. Secure Bench source, corpora and historical evidence remain
outside this workspace. SecureFlow does not redistribute or alter those
artifacts.

## Advisory data sources

Advisory records are operator-supplied runtime data and are not bundled in this
repository or release artifacts.

- GitHub Advisory Database: CC-BY-4.0. SecureFlow requires a local hash of the
  license evidence and retains attribution per source partition.
- RustSec Advisory Database: primarily CC0-1.0; imported GitHub advisories can
  be CC-BY-4.0 and are separated by the record's declared license.
- OpenSSF Malicious Packages: Apache-2.0. A `MAL-*` record is accepted only
  when all affected entries point to the corresponding official repository
  path; otherwise it stays quarantined.

OSV ecosystem ZIPs are treated as transport. SecureFlow does not assign one
blanket license to the aggregate. Source locator, artifact generation/hash,
license evidence and quarantined records remain in each local snapshot.
