# `secureflow-catalog-bundle-v1` contract

This contract distributes a SecureFlow SQLite catalog as one Zstandard frame
plus a separate, bounded JSON manifest. It does not download advisory data,
authenticate a publisher, or validate any external record as a vulnerability.

## Profiles

The profile name is recomputed from database records rather than trusted as a
manifest label. `secureflow-catalog-profile-policy-v2` recognizes these stored
source declarations and primary identifier families:

- `core`: GitHub Advisory Database (`CC-BY-4.0`, `GHSA-*`) and RustSec
  (`CC0-1.0` or `CC-BY-4.0`, `RUSTSEC-*`), PyPA Advisory Database
  (`CC-BY-4.0`, `PYSEC-*`), and Go Vulnerability Database (`CC-BY-4.0`,
  `GO-*`);
- `malicious`: OpenSSF Malicious Packages (`Apache-2.0`, `MAL-*`);
- `full`: the byte-exact compressed payload of one consistent SQLite
  online-backup artifact, logically complete for that snapshot and including
  recognized and unclassified records.

The locator, scoped source-name prefix, declared license and identifier prefix
must all match. An unknown active source blocks `core` and `malicious`
creation. It remains visible as `active_unclassified_records` in `full`.
These checks establish consistency with operator-stored declarations; they do
not authenticate the named upstream repositories. Authentic acquisition
manifests, publisher channels and license evidence remain separate obligations.

Profile policy v2 is an intentional classification change. It adds PyPA and Go
to `core`; it does not change the bundle contract or relabel historical policy-v1
evidence.

`core` and `malicious` are standalone, current-record-only projections. Each
is rebuilt from the selected current raw JSON records, canonicalized afresh,
given a new contentless FTS index and checked. Historical revisions and
snapshot/delta cursor claims are deliberately absent. They must not be mounted
as independent overlays: aliases can cross profiles and require a joint
canonicalization pass. `full` may not be byte-identical to the live source main
file because SQLite's online-backup API freezes logical state across WAL and
concurrent activity. It means the complete frozen local snapshot, not a
complete global vulnerability database.

## Manifest binding

The manifest binds:

- profile, policy and derivation;
- compressed and uncompressed SHA-256 and byte sizes;
- SQLite application ID and supported schema version;
- exact statistics, integrity results, provenance and database-derived source
  composition for both the payload and its frozen origin;
- producer compression level 3 plus required content size, checksum and one
  frame. The verifier confirms the latter three; compression level is not
  recoverable from a Zstandard frame.

`database_bytes` measures the portable main SQLite file. Transient local
`-wal` and `-shm` sidecars are not distributed or counted in that field.

The manifest is strict (`additionalProperties: false`) and capped at 2 MiB.
The compressed payload is capped at 8 GiB, the database at 16 GiB, the decoder
window at 128 MiB and the declared compression ratio at 1,000:1 plus 16 MiB of
slack. Verification streams to a private temporary file, stops when the
declared size is exceeded, rejects concatenated frames or trailing bytes, and
runs SQLite quick, foreign-key, schema, provenance, statistics and composition
checks before installation. The FTS check currently confirms the persisted
readiness marker; it does not independently prove semantic index consistency.

## Integrity and authenticity

The internal hashes prove consistency between the unsigned manifest and its
payload; they do not authenticate who produced either file. A consumer should
pass an exact manifest SHA-256 obtained from a separately authenticated release
channel. Verification reports one of:

- `unverified`: internal integrity passed, but no manifest hash was pinned;
- `manifest-sha256-pinned`: internal integrity passed and the caller-provided
  manifest hash matched.

Publisher signatures and rollback/freshness metadata are future work. No
output is presented as human-validated security knowledge. Installation
requires a separately authenticated manifest SHA-256 by default. Trusted local
workflows can make risk acceptance explicit with
`--allow-unverified-manifest`; verification without installation may remain
informational and report `unverified`.

## Filesystem publication

Creation compresses a consistent SQLite online backup, never a live WAL file.
Installation writes and checks a private same-directory temporary file and
publishes it with a no-overwrite hard link. Existing files, directories,
symlinks and destination `-wal`, `-shm` or `-journal` sidecars are rejected.
The installed path is reopened and compared with the verified descriptor before
success. The payload is published first; the JSON manifest is the commit marker
and must be published last. A crash can leave an inert orphan `.sqlite3.zst`,
but never a manifest that verifies against a missing or different payload.

The v1 implementation is descriptor-bound while reading the compressed
payload. It does not claim protection from a privileged local attacker or all
ancestor-directory replacement races; use a trusted destination directory.

## CLI

```bash
secureflow catalog-bundle-create \
  --database advisories.sqlite3 \
  --profile core \
  --output secureflow-core.sqlite3.zst \
  --manifest-output secureflow-core.manifest.json

secureflow catalog-bundle-verify \
  --bundle secureflow-core.sqlite3.zst \
  --manifest secureflow-core.manifest.json \
  --required-profile core \
  --expected-manifest-sha256 <sha256>

secureflow catalog-bundle-install \
  --bundle secureflow-core.sqlite3.zst \
  --manifest secureflow-core.manifest.json \
  --required-profile core \
  --expected-manifest-sha256 <sha256> \
  --output advisories.core.sqlite3
```

The normative manifest schema is
`schemas/secureflow-catalog-bundle-v1.schema.json` and is printed by
`secureflow catalog-bundle-schema`.
