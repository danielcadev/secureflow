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
- Local source inspected: `/home/danielcastrillon/Proyectos/secure-skill`
- Upstream contract: `urn:usesecure:review-contract:1.1`
- License: MIT
- Copyright: Copyright (c) 2026 Secure contributors

SecureFlow's adapter implements interoperability with the public review
contract. The Secure Skill source and repository history remain outside this
workspace. An import records the exact source revision and SHA-256 hashes of
the contract, skill instructions and license used.

## Secure Bench

- Project: Secure Bench
- Local source inspected: `/home/danielcastrillon/Proyectos/secure-bench`
- Interoperability contract: `secure-bench-result-v2`
- License: Apache-2.0

SecureFlow loads Secure Bench's result schema at runtime and verifies retained
artifacts by hash. Secure Bench source, corpora and historical evidence remain
outside this workspace. SecureFlow does not redistribute or alter those
artifacts.
