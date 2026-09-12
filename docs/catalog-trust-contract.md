# Offline catalog trust contract

Status: implementation candidate. See [ADR 0010](adr/0010-offline-tuf-catalog-trust.md), the [authoritative plan](plans/trusted-catalog-distribution.md), and the [operator runbook](catalog-trust-runbook.md). Production qualification still requires independent human review and a real custody rehearsal.

## Meaning of acceptance

A trusted operation authenticates exact catalog bytes to a locally enrolled publisher, at a recorded time and against retained local history. The publisher ID is an operator association, not a verified legal identity. Integrity, publisher authenticity, freshness and rollback are separate receipt fields. None establishes advisory truth, safe dependencies, exploitation, license rights, completeness, globally latest data, or a human validation decision.

The existing `secureflow-catalog-bundle-v1` manifest and legacy commands retain their unsigned-manifest semantics. The new trust path supplies the authenticated exact manifest digest to the existing bounded bundle verifier. It does not rewrite that manifest or accept the legacy unpinned override. No command downloads metadata or payloads, invokes an engine, contacts AI, scans a target, or patches code.

## Wire profile

Use top-level TUF Ed25519 roles, SHA-256 parent links, consistent snapshots and `spec_version: "1.0.0"`. `tuf 0.3.0-beta14` verifies the chain through its synchronous database; no transport/client is constructed. This implementation deliberately supports a restricted profile rather than arbitrary TUF repositories.

| Role | Minimum distinct keys / threshold | File | Byte limit | Maximum expiry horizon |
| --- | --- | --- | --- | --- |
| Root | 3 / 2 | `<version>.root.json` | 65,536 | 366 days |
| Targets | 3 / 2 | `<version>.targets.json` | 2,097,152 | 30 days |
| Snapshot | 2 / 1 | `<version>.snapshot.json` | 262,144 | 30 days |
| Timestamp | 2 / 1 | `timestamp.json` | 16,384 | 7 days |

Every decoded public key is unique across roles; IDs are the SHA-256 of canonical public-key JSON. Encodings must be canonical lowercase Ed25519, nonweak and exactly 32 bytes. Duplicate signature IDs, reused public keys, lowered thresholds, unassigned keys and unsupported schemes fail. Authorized distinct valid signatures count toward quorum; unknown signers grant no authority. Strict Ed25519 checking supplements the maintained TUF verifier.

JSON preflight rejects duplicate members at any depth, floats/exponents, values outside the exact integer range, BOMs, invalid Unicode, trailing content and nesting beyond 32. Metadata excludes C0 controls to avoid canonicalization disagreement. Unknown noncritical TUF fields remain in the signed preimage; Unicode is not normalized. Delegations and unknown critical semantics fail. The `custom.secureflow` extension and public application objects are closed. Role versions range from 1 to 4,294,967,295; release sequences from 1 to 9,007,199,254,740,991. Exhaustion fails rather than wrapping or resetting.

Limits also include 32 root keys, 32 signatures per envelope, 256 target entries, 512 directory entries examined, 128 consecutive root transitions per import and 12 MiB metadata reads per operation. More roots require explicit bounded batches. The store is bounded to 64 MiB, 1,024 retained roots and 4,096 completed installations. Capacity failures preserve the committed state; automatic history compaction is not implemented.

Metadata names are prescribed. A target name is exactly `catalogs/<catalog>/<channel>/<profile>.manifest.json`, with IDs matching `[a-z0-9][a-z0-9-]{0,63}` and profile `core`, `malicious` or `full`. Metadata cannot choose a local payload/output path. Inputs are explicit absolute canonical regular files with no symbolic or hardlink aliases. No archive extraction or recursive lookup occurs.

The signed target is the exact v1 manifest buffer, bound by byte length and SHA-256. `custom.secureflow` binds publisher, catalog, channel, profile, profile policy, bundle ID, release sequence, manifest contract and external-records human-validation boundary. All entries must match the enrolled scope. A consumer can import multiple enrolled profiles; the producer preparation interface deliberately prepares one bundle per request. Import authenticates references without claiming an absent payload has been checked.

Timestamp links exact snapshot bytes/version; snapshot links exact targets bytes/version; targets link exact manifest bytes; the manifest links compressed bytes and the verified database descriptor. Envelope whitespace changes require updated parent hashes even when signatures remain valid. Manifest whitespace changes require a newly signed target digest. Existing limits remain: manifest 2 MiB, compressed payload 8 GiB, database 16 GiB, Zstandard window 128 MiB, ratio and single-frame checks, SQLite integrity and provenance/descriptor validation. Reads and decompression are bounded by actual bytes.

## Enrollment, time and retained history

`catalog-trust-init` creates a new store only. It requires an independently authenticated root digest, explicit publisher/catalog/channel/profiles, minimum sequence, operator and authorization reference. Zero explicitly records no known release history. Optional `--bootstrap-manifest-sha256` constrains the first accepted manifest and requires one profile. It supplements the root pin. After the first authenticated reference, later releases use the retained sequence/digest floor. The root's supplied version becomes the minimum root version.

The initial policy is immutable. Publisher metadata cannot edit local thresholds, horizons, namespaces or initial anchors. This version has no policy-update or history-reset command. A future policy migration needs separate design/review. Creating a different store is explicit re-enrollment with a new lineage, not recovery of prior trust continuity.

Each operation captures one whole-second UTC time, either the operator-trusted OS clock or the pair `--verification-time` / `--time-reference`. The reference is a record, not an online check. Expiry equality is expired. Acceptance refuses times below the maximum retained verification time or expiries beyond local horizons. A wrong forward clock can strand a store; no silent clamping or reset exists.

Root updates are consecutive, each approved by old and new root quorums. Expired intermediate roots can bridge to a currently valid final root; missing versions or an expired final root fail. Each valid root is saved before continuing. Root-only import persists revocation without needing catalog bytes. Every new acceptance rechecks roles under current keys. A disconnected store cannot learn a withheld revocation.

Valid timestamp and snapshot progress is saved even if later data fails. Application sequence/digest floors advance after the complete metadata chain and all scope extensions pass, even when payload bytes are absent or installation fails. Floors never decrease across root rotations. Equal sequence with a different manifest and equal role version with changed signed content fail as equivocation. A higher sequence may legitimately name unchanged bytes. Profiles have separate floors; withdrawing one from current targets does not erase its historical floor.

## Transactions and receipts

`catalog-trusted-verify` holds a shared snapshot lock, checks the full byte chain, and returns an as-of receipt without reserving acceptance or changing disk state. It is not permission for a later install. Installation obtains the exclusive nonblocking store lock and repeats acceptance against current state.

`catalog-trusted-install` prepares and verifies a private temporary database beside a new output, saves conservative metadata/floors, commits a pending descriptor and receipt, publishes the verified inode without overwriting an existing destination, fsyncs file/parent, commits completion, and exports the receipt. State replacement writes/fsyncs a private temporary file then atomically renames it and fsyncs the held store directory. New public metadata/receipt files use Linux `renameat2(RENAME_NOREPLACE)`. Database publication uses a no-overwrite hardlink followed by cleanup. Directory/lock identities are rechecked before commits.

Opening an exclusive session recovers pending work first. An absent output clears the pending operation while keeping floors. Exact matching installed bytes complete the original as-of receipt. A conflicting output or receipt fails and is preserved. Exported receipt files must equal authoritative completed state. An interrupted call can leave a visible database plus a pending journal; recovery establishes the result, not a guessed successful exit. Repeating an installation at a new path creates a new transaction. Reusing an existing output fails.

The store contains `lock`, `state.json` and `receipts/<transaction-id>.json`. Policy, root lineage, role evidence, time/floors and pending/completed records reside in the authoritative state. Exported receipts include raw/canonical role digests, signer IDs/thresholds, manifest/database hashes and lengths, initial/current root hashes, policy hash, scope, sequence, clock, earliest expiry and generation. They are local evidence, not signed portable attestations.

`catalog-trust-status` requires a receipt matching committed completed state. It checks current root/role signatures, expiry, parent links, floors and that the exact target still exists. It reports `checks_installed_bytes: false`: this is current policy evaluation of retained evidence, not a live database inspection. Historical receipt fields keep their original meaning when current policy fails.

`catalog-trusted-inspect --historical` reports requested metadata hashes, versions, signatures and policy/chain failures. It allows a historical clock below the floor only for inspection. It always reports `historical: true`, `current_policy_acceptance: false`, `reserves_acceptance: false`; it never produces an acceptance receipt or changes state. Corrupt/unreadable inputs can still fail before a report.

## Contracts and errors

Standalone JSON Schemas are `secureflow-catalog-target-v1`, `secureflow-catalog-trust-policy-v1`, `secureflow-catalog-trust-state-v1` and `secureflow-catalog-trust-receipt-v1` in `schemas/`. Corresponding `catalog-…-schema` commands emit the same bytes semantically. `scripts/generate_trust_schemas.py` reproduces them. Runtime checks add cryptographic, scope, time and cross-field constraints beyond schema validation.

Trusted-operation failures exit nonzero with JSON stderr containing `error_code`, `message`, `acceptance: "rejected"` and `validation_authority: "human-only"`. Codes include `TRUST_BOOTSTRAP`, `TRUST_SIGNATURE`, `TRUST_FORMAT`, `TRUST_SCOPE`, `TRUST_EXPIRY`, `TRUST_CLOCK`, `TRUST_ROLLBACK`, `TRUST_EQUIVOCATION`, `TRUST_INTEGRITY`, `TRUST_STATE` and `TRUST_FILESYSTEM`. Argument parsing errors retain Clap's usage/error output. A failure can still have saved authenticated conservative progress; it never grants catalog acceptance.

## Assurance boundary

Durable stores require Linux, caller-owned private directories and a local ext4, XFS, Btrfs, tmpfs or overlay filesystem. Required syscalls/fsync failures stop the operation. tmpfs supports process-crash recovery only. Filesystem type admission is not evidence that every mount, storage controller or power-loss mode has been tested. NFS, remote filesystems and unsupported platforms fail closed.

The local account, administrator, private ancestors, kernel, system clock and storage durability are trusted. Replacing the entire store with an old copy defeats local rollback protection; no hardware counter or external checkpoint exists. Offline backup restoration must preserve the highest independently known floors or establish a new explicitly authorized lineage. Crash-orphaned private temporary files may require operator cleanup after reviewing the journal; automatic deletion of unrelated files is intentionally absent. Retain original evidence during recovery.
