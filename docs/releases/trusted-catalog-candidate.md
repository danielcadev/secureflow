# Trusted Catalog Distribution implementation candidate

<!-- secureflow-release-state: draft -->

This is an unversioned local implementation candidate on the existing `0.4.0-rc.3` base. No new version, tag or publication is implied. The authoritative scope is [Trusted Catalog Distribution](../plans/trusted-catalog-distribution.md); the [wire and state contract](../catalog-trust-contract.md) and [custody runbook](../catalog-trust-runbook.md) describe the resulting behavior.

## Implemented behavior

- Explicit offline publisher enrollment and root pinning, closed scope/policy schemas, optional independent first-manifest pin, and separate integrity, authenticity, time and rollback receipt fields.
- Maintained `tuf 0.3.0-beta14` verification without a network transport, strict Ed25519 preflight, exact v1 manifest/payload binding, quorum-separated roles, consecutive dual-quorum roots and root-only revocation.
- Durable role/parent/application floors, locked no-overwrite installation, recoverable pending journals, current-policy status and historical inspection that never grants acceptance.
- Public-data-only signing preparation, external offline signature collection/assembly, independent OpenSSL vectors, synthetic lifecycle tests and release-binary evidence retained by CI and local packaging.

## Qualification boundary

Automated acceptance covers strict parsing/encoding, quorum/key identity, exact bytes, scope, expiry/time floors, sequence/role equivocation, partial progress, rotations, retired keys, read-only snapshots, schema closure, filesystem refusal, real child-process interruption, file-write quotas and the network-disabled CLI ceremony. The demo's copied pending journal is separately labeled synthetic and must not be cited as a physical power-loss test. No scan, exploit, real AI transport, autonomous patch or human validation decision is part of this ceremony.

Before production qualification, obtain an independent human security review of signing and state boundaries and a real multi-person custody/backup/quorum-loss rehearsal. Those gates remain pending. Filesystem allowlisting is not universal power-loss evidence; tmpfs tests establish process-crash behavior only. A complete trust-store rollback, compromised local administrator, withheld updates or trusted publisher falsehood remains outside the protocol's guarantees. No automated test can establish independent people or production custody.

Local qualification logs and exact commit/archive hashes are retained outside the checkout to avoid self-referential commit evidence. Existing historical release notes, workspace version, Review Room assets and capture scripts retain their prior state. Publication requires a separately authorized decision after qualification.
