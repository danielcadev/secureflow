# ADR 0010: Offline TUF catalog trust

Status: implementation candidate; qualification gates remain required.

Use `tuf = 0.3.0-beta14` (MIT OR Apache-2.0), without default features,
through its synchronous `Database<Pouf1>` and `verify_signatures` APIs. No
repository client or transport is instantiated. Rust 1.92 is the required build.
The dependency lock fixes transitive versions. This beta dependency's API/version
is explicit; no claim of blanket TUF interoperability or independent audit follows.

`tough 0.24.0` was evaluated and rejected: `olpc-cjson 0.1.4` normalizes Unicode
strings to NFC. The selected library preserves Unicode in its canonical preimage
and accepts an explicit verification time. SecureFlow adds duplicate-member,
integer, depth, size, key identity and strict Ed25519 preflight. Metadata strings
containing C0 controls are outside this initial wire profile: escaping these is
not portable between the evaluated canonical JSON implementations. No input is
normalized. V1 manifest bytes are authenticated directly and retain their format.

The design reference is TUF 1.0.36. The wire declares `spec_version=1.0.0`,
the selected library's supported SemVer spelling; other spellings fail closed.
The profile uses top-level roles, Ed25519, SHA-256,
consistent snapshots and no delegations. Metadata role versions are 1..4294967295
(the library's representable range); release sequences are 1..9007199254740991.
No version arithmetic wraps. A future role-version widening requires a contract
migration. Every accepted unknown TUF field remains in the signed preimage; the
`custom.secureflow` application extension is closed-world. Unknown `critical`
fields and delegations are rejected. SHA-256 lengths/hashes are mandatory in parent
metadata. Names are `<version>.root.json`, `timestamp.json`,
`<version>.snapshot.json`, and `<version>.targets.json`. The logical target name is
`catalogs/<catalog>/<channel>/<profile>.manifest.json`. Payload paths are only
operator arguments, never metadata instructions.

The application retains raw role envelopes and canonical signed digests separately.
It adds conservative, nondecreasing role and parent-reference floors to the
library database, including on partial imports; root rotation does not erase those
floors. This is stricter than TUF's optional recovery through version reset. Known
same-version/different-signed-content is refused. Current-root authorization is
rechecked on each operation, including cached roles. No success may depend on the
library's permissive same-version timestamp early return or ignored bad key IDs.

The operator explicitly enrolls one publisher/catalog/channel and one or more
profiles in a new private store. Thresholds and custody counts are at least
root 2/3, targets 2/3, snapshot 1/2, timestamp 1/2; decoded keys are unique across
all roles. Changes to these local minima require a future explicit policy migration,
not publisher metadata. Root rotation is consecutive and requires both quorums.

Producer signatures are detached Ed25519 over the library's canonical signed bytes.
A local custodian uses standard encrypted PKCS#8/OpenSSL storage (or their own
reviewed offline signer); SecureFlow prepares public signing requests and imports
public signatures. It never generates, ingests, or stores private signing keys.
There is no custom encryption, upload, online signer, or CI signing secret.

Initial durable-state support is Linux on local ext4, XFS, Btrfs, tmpfs or overlayfs
in owner-private directories, with filesystem locks, atomic rename, Linux
`renameat2(RENAME_NOREPLACE)` for new public files, no-overwrite database hard links,
file and parent fsync. tmpfs is process-crash durable only, not power-loss durable.
Private ancestor paths and same-account/administrator trust remain assumptions.
No filesystem or signature mechanism resists rollback of the entire trust store.

Authoritative design: [Trusted Catalog Distribution](../plans/trusted-catalog-distribution.md).
Upstreams: [rust-tuf](https://github.com/theupdateframework/rust-tuf),
[TUF specification](https://theupdateframework.github.io/specification/latest/),
[tough](https://github.com/awslabs/tough).
