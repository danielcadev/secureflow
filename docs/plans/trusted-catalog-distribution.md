# Trusted Catalog Distribution

Status: proposed next milestone; design only. Baseline inspected on 2026-09-12:
`778a5d6ce67399785824c8a051ed052bf0f3bfd3`, workspace version `0.4.0-rc.3`.
This plan does not implement signing, declare a release complete, or authorize
publication. New commands, schemas, defaults, and guarantees below are proposals.

## Milestone decision

Add an offline TUF metadata layer around the existing catalog bundle. An operator
explicitly enrolls a publisher root, imports locally acquired metadata, and installs
only a bundle authorized by that root and accepted by local freshness and rollback
policy. Preserve the exact v1 manifest and compressed payload. Use Ed25519 and
separate root, targets, snapshot, and timestamp keys; require human quorum for
publisher authority and sensitive key changes.

The deliverable is a complete local flow from trust bootstrap through rotation,
revocation, recovery, verification, installation, and an inspectable receipt.
Application releases and catalog releases remain separate. No network service,
account, HTTP client, crawler, real AI transport, active scan, exploit, autonomous
patch, or automated human verdict belongs in this milestone.

## Current evidence and gaps

The following is source inspection, not a fresh execution receipt or a security
audit. Repository citations are relative to the baseline above. The architecture
cross-check was sequential, not an independent agent review, as this assignment
prohibits subagents.

| Observed boundary | Inspected evidence | Consequence for this design |
| --- | --- | --- |
| Manifest hashes cover exact input bytes; the strict typed manifest declares itself unsigned | `crates/secureflow-knowledge/src/catalog_bundle.rs:61`, `:242`, `:320`; `schemas/secureflow-catalog-bundle-v1.schema.json:1` | Do not add signature fields or change the v1 authenticity constant. |
| Verification distinguishes `unverified` and `manifest-sha256-pinned`; installation requires a pin or explicit local override | `crates/secureflow-knowledge/src/catalog_bundle.rs:114`, `:282`, `:361`; `crates/secureflow-cli/src/main.rs:2353`, `:2371` | A hash pin is useful integrity evidence, but supplies no built-in publisher identity or lifecycle. Keep legacy behavior distinct. |
| The CLI reads a bounded manifest once and pretty-serializes newly created manifests | `crates/secureflow-cli/src/main.rs:2326`, `:2353` | Authenticate the retained bytes, never a reconstructed v1 object. |
| Payload verification hashes an opened file, bounds decompression, checks the database descriptor, and rejects trailing frames | `crates/secureflow-knowledge/src/catalog_bundle.rs:394`, `:504`, `:855` | A signature must precede and supplement these checks; it cannot replace them. |
| Install uses a private temporary file beside the output, refuses existing output/sidecars, hard-links without overwrite, and rechecks the installed database | `crates/secureflow-knowledge/src/catalog_bundle.rs:282`, `:959`, `:1001` | Add trust-state transactions around publication without weakening no-overwrite behavior. |
| Profile policy derives composition from stored declarations, not authenticated upstream identity | `docs/contracts/secureflow-catalog-bundle-v1.md`; `docs/adr/0009-modular-catalog-distribution.md`; `crates/secureflow-knowledge/src/catalog_bundle.rs:642` | Publisher authentication does not authenticate every source, license statement, or advisory. |
| Filesystem hardening has explicit limits; non-Unix permission and parent-sync helpers are no-ops | `crates/secureflow-knowledge/src/catalog_bundle.rs:798`, `:1045`; `docs/contracts/secureflow-catalog-bundle-v1.md` | Initial durable-state assurance is scoped to tested Linux local filesystems in private directories. No universal race-resistance claim. |
| Correlation preserves human-only authority and does not assert vulnerability validation | `docs/contracts/secureflow-correlation-v2.md:25`; `schemas/secureflow-correlation-v2.schema.json:69`; `crates/secureflow-knowledge/src/correlation.rs:26` | Signed catalog context remains context. No change to findings or human decisions. |
| Target analysis separately requires explicit authorization | `crates/secureflow-cli/src/main.rs:3437`; `SECURITY.md` | Trust enrollment grants catalog acceptance only, never permission to analyze a target. |
| The current release lane includes archive attestations and CodeSupply evidence | `.github/workflows/release.yml:11`; `.github/workflows/ci.yml`; `scripts/release-local.sh:1`; `docs/releases/v0.4.0-rc.3.md:16` | Archive workflow provenance is separate from catalog publisher trust. Existing attestations must not be relabeled catalog signatures. |
| Existing tests exercise tampering, profile substitution, hash pins, limits, symlinks, and sidecars | `crates/secureflow-knowledge/src/catalog_bundle.rs:1228`, `:1306`, `:1421`, `:1502`, `:1589`, `:1616`; `crates/secureflow-cli/tests/cli.rs:537` | Extend these acceptance gates; retain the old pinned demo as a compatibility test. |

The current knowledge crate has no signing dependency
(`crates/secureflow-knowledge/Cargo.toml`). Trust roots, signed release sequence,
expiry enforcement, revocation import, and durable acceptance state must be added.
The older CodeSupply plan is historical intent; current source and contracts take
precedence over its former gap list.

## Threat model

### Assets, assumptions, and runtime boundaries

Protect publisher authority, trusted root continuity, catalog/profile selection,
exact artifact bytes and provenance, local acceptance history, private signing
keys, and the integrity of installation receipts. Preserve the separate authority
of the human review ledger.

The OS, administrator/operator account, installed verifier, clock when selected as
trusted, and private state directory are trusted. Transport media, repository
copies, bundle files, advisory text, and metadata are untrusted. The attacker may
substitute, reorder, truncate, replay, or withhold those inputs and may compromise
fewer keys than a configured quorum. They do not initially control the operator's
trust policy or local state. A compromised signing quorum or operator account is
an explicitly weaker assurance case, not something hashes can repair.

| Workflow | Resource and controlling actor | Proposed enforcement and effective location |
| --- | --- | --- |
| Enrollment | Operator associates a publisher with a root and scope | Mandatory `--trust-store` names a private local directory; expected root SHA-256 and publisher identity come from an independently authenticated channel. No defaults from the analyzed repository, environment search, embedded bundle keys, or system CA store. |
| Publisher preparation | Maintainers inspect frozen catalog bytes and unsigned metadata | Explicit local staging directory; signing keys remain on separate custodian devices. The staging process cannot select new trust authorities on a consumer. |
| Local metadata import | Removable media/directory supplies untrusted role files | A bounded local file provider exposes only prescribed metadata names; it cannot open URLs or follow metadata-selected absolute paths. |
| Verification | Trust policy plus metadata authorizes one manifest and payload | CLI selects publisher, catalog, channel, and profile explicitly; verifier checks all four against signed data before deep bundle processing. |
| Installation | Operator names output; verifier advances accepted state | Private trust store with an exclusive mutation lock and durable journal; new database path only. Metadata never chooses an output path. |
| Query/correlation | Installed database supplies advisory context | Existing human-only contracts remain in force. A receipt describes distribution trust at a recorded time, not vulnerability validity or perpetual trust. |

### Prioritized scenarios (design hypotheses, not findings)

| Priority | Attacker story and impact | Existing control or counterevidence | Proposed control and remaining limit |
| --- | --- | --- | --- |
| P1 | Media supplies a coherent forged manifest/payload and its own key; operator accepts attacker-selected catalog data | A separately obtained hash pin already prevents substitution of those exact bytes (`catalog_bundle.rs:361`) | Explicit root bootstrap and role quorum, with namespace binding. A root fingerprint from the same untrusted package proves nothing. |
| P1 | Old signed material replaces a newer known catalog, or a valid publisher's `full` bundle is substituted for another channel/profile | Current required-profile check exists; no catalog rollback history (`catalog_bundle.rs:361`) | Persist metadata history and per-scope release sequence/digest; verify signed selection. No protection for history the client never learned. |
| P1 | One stolen operational key becomes apparent publisher authority; removed keys continue to authorize installs | No current publisher-key mechanism | Separate roles, target quorum, root-controlled removal, revalidation under current keys. Withheld revocation remains unknowable until expiry or local import. |
| P1 | Crash or concurrent install publishes a database without preserving its rollback floor | Current atomic publication covers a single catalog, not trust state (`catalog_bundle.rs:282`) | Commit a conservative floor and pending transaction before publication; recovery must never lower it. Availability may be lost on failure. |
| P2 | Signature parser disagreement, duplicate keys/signatures, algorithm confusion, or hostile paths bypass acceptance or consume resources | Existing v1 unknown-field rejection and size limits do not establish a signing parser policy | Bounded strict input profile, standard cryptographic verifier, cross-implementation vectors, fixed local path mapping. No new signature primitive. |
| P2 | A disconnected client accepts stale-but-unexpired metadata or a backdated clock | No current freshness promise | Explicit clock source, expiry, persistent time floor, and truthful bounded freshness wording. Offline operation cannot establish global latest state. |
| P2 | A trusted publisher signs false or malicious advisory content | Database checks establish consistency, not truth (`catalog_bundle.rs:394`; correlation contract) | Preserve quarantine, integrity checks, provenance, and human review. Signatures do not certify safety, accuracy, license rights, or exploitability. |
| P2 | Backup restoration deletes accepted history or state is replaced by the operator | Host/account are already trusted; backup covers a catalog, not trust continuity (`catalog_backup.rs:90`) | Never infer state from a restored catalog. Explicit re-enrollment and externally retained floors are required after state loss; same-account rollback resistance is not claimed. |

Severity is conditional, not assigned to vulnerabilities here. Publisher-authority
substitution could justify high severity if it actually bypasses an enrolled root;
critical impact would require a separate demonstrated downstream execution or
validation-boundary failure. A signed malformed database causing bounded rejection
is not that evidence. Availability failures may be medium depending on recovery;
misleading diagnostics may be low unless they enable a demonstrated trust bypass.
Advisory correlation alone never establishes any of these findings.

## Signature format and implementation choice

Use TUF JSON metadata, initially without delegated targets roles, over a local
directory provider. The design reference is TUF specification **1.0.36**, inspected
2026-09-12. TUF provides role separation, threshold signatures, versioned metadata,
expiry, and root continuity; SecureFlow must still define bootstrap, storage,
clock policy, and application selection. Pin the selected implementation and its
wire profile in an ADR before implementation. Do not claim interoperability until
the acceptance vectors pass. [TUF specification](https://theupdateframework.github.io/specification/latest/)

| Alternative | Assessment |
| --- | --- |
| Detached Ed25519 signature over the v1 manifest | Small and fully offline, but SecureFlow would have to invent authenticated rotation, thresholds, revocation, and replay state. Insufficient by itself for this milestone. |
| DSSE envelope with Ed25519 | Its typed payload and pre-authentication encoding are useful for attestations. It still needs a separate key/lifecycle/update policy, so defer as an optional provenance attachment. [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) |
| Sigstore bundles | Valuable identity and transparency evidence; a complete retained verification bundle can support offline verification. Keyless issuance and identity/log infrastructure add lifecycle and trust dependencies beyond this local-key milestone. Existing archive attestations remain intact. [Sigstore overview](https://docs.sigstore.dev/about/overview/) |
| TUF metadata with Ed25519 — selected | More metadata and persistent state, but a documented update-security model. Retain all four top-level roles even when every file moves by removable media. |

Candidate integration: evaluate `tough` in an isolated future implementation spike,
because its upstream project provides Rust TUF libraries and tooling. This is not
a dependency approval or a claim that its defaults meet this plan. Slice 1 must
verify Rust 1.92 compatibility, persistent rollback behavior, signature semantics,
local-only transport, dependency licenses/audit, and testability of time and crash
handling. Disable or exclude HTTP/network features; if that cannot be enforced,
choose another maintained TUF implementation through an ADR rather than writing a
partial TUF verifier. [Upstream tough project](https://github.com/awslabs/tough)

## Trust and key model

Publisher identity is a locally enrolled association with a root fingerprint, not
a verified legal name, email, domain, GitHub account, or upstream feed identity.
The policy records a human-readable publisher label, immutable publisher ID,
catalog ID, channel, permitted profiles, initial root digest, minimum root version,
bootstrap release floors, operator identity/reference, and time policy. Key IDs are
identifiers, not trust anchors; an unknown key never enrolls itself.

Proposed production profile (synthetic tests may use clearly labeled keys):

| Role | Keys / threshold | Custody and authority |
| --- | --- | --- |
| Root | Three distinct keys, two required | Three independent offline custodians. Authorizes role membership; cannot be a CI secret. |
| Targets | Three distinct keys, two required | Separate release custodians/devices from root keys; approve exact catalog manifest references and release sequence. |
| Snapshot | Two keys, one required | Separate local operational signing custody; binds the metadata set. |
| Timestamp | Two keys, one required | Separate local operational signing custody; renews the bounded acceptance window. |

No key is reused across roles. No quorum member may be represented twice under
different key-object encodings: compare decoded public keys as well as key IDs.
Consumers require at least the configured profile thresholds; a metadata update
cannot silently reduce the local minimum. Changing that floor is a separate
operator policy decision with a retained before/after receipt.

### Generation and signing ceremony

Generate Ed25519 keys using a maintained cryptographic library and OS randomness
on the custodian's local device; never derive production keys from fixture seeds,
passwords, commit IDs, or timestamps. Use the standard Ed25519 variant, not a
home-grown prehash construction; enforce 32-byte public keys and 64-byte signatures
after decoding. [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)

Private keys stay outside the repository, catalog directory, consumer trust store,
logs, command arguments, environment variables, CI artifacts, and screenshots.
Use encrypted offline storage and independently held backups; each custodian tests
restore and signs a challenge with a disposable test setup before enrollment.
File-mode checks alone are not encrypted storage. Select the secret-storage and
local signer interface in slice 1; no bespoke encryption format is authorized.

Producer flow: freeze and deep-verify a bundle; stage metadata referencing its exact
manifest; show scope, sequence, dates, byte digests, and signing preimage digest;
collect independent local signatures; reverify the assembled metadata and bundle;
seal a new staging directory. Any changed signed field invalidates approvals and
requires signing again. Signers never auto-approve based on advisory content or
an AI assessment. Metadata preparation and signature collection perform no upload.

### Rotation, revocation, and recovery

Normal root transitions are consecutive versions, authorized by both the previous
and replacement root quorums. Retain every intermediate root for disconnected
clients; an expired intermediate may bridge to a currently valid final root.
Do not skip missing versions. Revocation removes role authorization through a
verified root update, not an unauthenticated blacklist beside a bundle.
[TUF root update workflow](https://theupdateframework.github.io/specification/latest/#53-update-the-root-role)

SecureFlow-specific lifecycle requirements:

- Rotate before expiry and rehearse overlap: distribute a root containing the
  replacement role keys, issue a new complete metadata set, then remove retiring
  keys in a subsequent root. Keep root and release version ledgers with publisher
  ceremony receipts; never reuse a version for changed signed content.
- A revocation import must be usable without a catalog payload. Persist verified
  root transitions even if later metadata or bundle validation fails. Mark catalog
  acceptance unavailable until remaining metadata verifies under the current root.
  Cached signatures from a removed key must not preserve install eligibility.
- On targets-key compromise, surviving root custodians replace the affected
  authorization and require fresh metadata signed by the replacement targets
  quorum. Inspect previously accepted catalogs; do not retroactively call them safe.
  A revocation does not erase a previously installed database or human evidence.
- Follow the selected TUF implementation's role-specific cache-reset rules during
  recovery. SecureFlow's separate catalog sequence floor survives every key change;
  generic deletion of the trust store is never an automatic recovery step.
- Losing one root key is recoverable with the other two; losing one targets key is
  recoverable with the other two or through root-authorized replacement. Removing
  a lost key, restoring custody, and proving the new quorum must be one rehearsal.
- Loss of the root quorum, or compromise of that quorum, requires out-of-band
  re-enrollment. Stop acceptance, independently authenticate replacement identity,
  preserve the old lineage and incident receipt, and require an explicit new store.
  Do not invent a universal recovery key or treat a signature from compromised root
  keys as proof of recovery. This breaks continuity and must be reported as such.
- A targets quorum can sign a dishonest higher catalog sequence. Preserve the floor;
  normal recovery uses a larger sequence and corrected bytes. Sequence exhaustion
  or unrecoverable poisoned history requires explicit re-enrollment, not wraparound
  or a hidden epoch reset. Threshold custody reduces this risk; it cannot eliminate it.

## Canonicalization, signing boundary, and bounds

The TUF envelope signs the canonical `signed` object; target hashes identify exact
file bytes. Use the selected implementation's documented canonical JSON format and
key-ID derivation. Do not substitute RFC 8785/JCS or Rust pretty JSON and call it
the same format. [TUF document formats](https://theupdateframework.github.io/specification/latest/#4-document-formats)

The SecureFlow wire profile must freeze these additional choices with golden
vectors before code lands:

1. UTF-8, no BOM, no duplicate object members at any depth, no floats, no invalid
   Unicode, no trailing data, and no lossy normalization. Signed strings retain
   their exact Unicode content. Application IDs use bounded ASCII to avoid aliases.
   Apply encoding/duplicate-member preflight to v1 manifests on the trusted path
   as well; do not silently change historical legacy parser behavior.
2. Metadata versions and catalog sequence are positive integers at most
   `9007199254740991`; bootstrap floor zero means explicitly no historical floor.
   Timestamps use whole-second UTC `YYYY-MM-DDTHH:MM:SSZ`. Arithmetic is checked.
3. SHA-256 is mandatory; public-key, digest, and signature text use lowercase hex
   with exact lengths. Reject malformed/unsupported algorithms. Unknown signatures
   confer no authority; duplicate signer IDs are invalid. Thresholds count distinct
   authorized public keys, never signature array length.
4. Preserve unknown TUF fields in signature verification as the standard requires.
   The SecureFlow application extension is separately closed-world and versioned;
   unknown critical semantics fail closed. Never deserialize a signed object into
   a struct that drops fields before verifying it.
5. Maximum root 64 KiB, timestamp 16 KiB, snapshot 256 KiB, targets 2 MiB; at most
   32 keys and 32 signatures per role, 128 root transitions per import, 256 target
   entries, JSON depth 32, and 12 MiB total metadata read per invocation. Hitting a
   limit is a reported failure; never silently stop at an older root and succeed.
   Root-only catch-up can proceed in explicit batches. These are proposed profile
   bounds to validate with fixtures, not measured performance claims.
6. Keep existing manifest (2 MiB), compressed (8 GiB), database (16 GiB), window
   (128 MiB), ratio, one-frame, and descriptor checks. Authentication occurs before
   decompression. Bound actual bytes read, not merely metadata length claims.

The signed target is the **exact v1 manifest file**. Its target entry includes
length and SHA-256 plus the SecureFlow extension below. The manifest already binds
compressed bytes, database digest/state, origin, composition, and provenance;
verification must traverse that whole chain. A second direct TUF target for the
payload is unnecessary for this milestone. Payload location is an explicit CLI
file argument and cannot be chosen by the manifest or metadata.

Use one logical manifest target per `(catalog_id, channel, profile)`, for example
`catalogs/example/stable/core.manifest.json`; IDs use `[a-z0-9][a-z0-9-]{0,63}`.
Enable consistent snapshots and freeze the local provider's versioned/hash-prefixed
file mapping in the wire-profile ADR. Reject traversal, percent-encoded aliases,
backslashes, drive prefixes, absolute paths, symlinks, special files, and target
paths outside the selected scope. No recursive discovery or archive extraction.
Metadata hash links include exact lengths and SHA-256 for snapshot and targets.

Changing whitespace in a manifest changes its target digest and requires new
targets metadata. Different whitespace in a signed metadata envelope may preserve
its cryptographic meaning but changes any parent file hash. Retain raw bytes and
canonical preimages separately in publisher evidence. Deterministic signatures for
fixed keys/preimages do not make newly generated keys, clocks, SQLite projections,
or entire releases byte-reproducible.

## Offline freshness and rollback policy

Define acceptance relative to a **specific local trust state and verification
time**. Never print `latest`, globally `fresh`, or `not-revoked` without qualification.
A disconnected client cannot detect a withheld new root or catalog; signatures
cannot prove feed completeness or data recency.

Proposed standard policy: timestamp validity horizon at most seven days from the
trusted verification time, snapshot/targets at most 30 days, final root at most
366 days. Producer defaults use those same lifetimes from the ceremony time. These
are SecureFlow operating choices, not TUF defaults; an authenticated signer could
still lie about when work occurred. Expiry bounds metadata usability, not advisory
age. Renewing a timestamp alone does not refresh advisory content.

At operation start, capture one UTC time. Default to the operator-trusted system
clock and report that assumption; never take current time from the bundle.
An offline operator may supply `--verification-time` and a required
`--time-reference` identifying their independent time source. No contact with that
source is made. Refuse a time below the persisted accepted time floor, invalid
time, metadata expired at that instant (equality is expired), or expiry beyond the
configured horizon. A wrong forward clock may fail closed; inspect it before
advancing state. Do not silently clamp a backdated clock and call it trustworthy.

| State | Required result |
| --- | --- |
| First enrollment | Require exact root digest, independently verified identity, scope, and a caller-declared minimum catalog sequence per profile. Zero is permitted only as explicit `no-prior-history`; an out-of-band digest pin can additionally constrain first acceptance. Self-signature alone is insufficient. |
| New valid release | Require current role authorization, valid metadata chain/expiry, and catalog sequence above the highest accepted floor; commit sequence with exact manifest digest. |
| Same sequence and same digest | Permit idempotent reinstall to a new output after current-time/current-root revalidation. Cached metadata is usable only while still valid; equal timestamp version is not treated as a new update. |
| Same sequence and different digest | Fail as equivocation, even when both signatures verify. |
| Lower sequence / known older metadata | Refuse trusted acceptance. Expiry renewal and root rotation cannot lower the application floor. |
| Missing, expired, wrong-scope, revoked-key, or invalid metadata | Nonzero result; no catalog publication. Never retry through the unsigned or pinned legacy path automatically. |
| Missing or corrupt trust state | Refuse; do not create a new implicit trust store. Explicit enrollment is a distinct operation. |
| Historical inspection | Explicit read-only `inspect --historical` reports cryptographic evidence and policy failures; never installs, advances state, or reports current-policy acceptance. |
| Existing installed catalog ages past expiry | Preserve bytes for local analysis and historical reproducibility. Its old receipt remains an as-of statement. `trust-status` re-evaluates a receipt against current imported trust/time; no automatic deletion or claim that catalog queries enforce freshness. |

Do not offer `--ignore-expiry`, `--allow-rollback`, or a universal `--force` on the
trusted installation path. Legacy pinned/unverified installation remains an
explicit compatibility operation with its existing labels and no trusted receipt.
Operators can deliberately choose that path, but this milestone does not claim to
prevent an operator from bypassing their own policy. A restored catalog backup has
no implied trust receipt; it must be reverified against retained distribution
artifacts and current state for a new acceptance statement.

## Durable state and safe installation

Keep policy, trusted role metadata, initial root lineage, per-scope accepted
sequence/digest, maximum accepted verification time, and pending/completed receipts
under the explicit trust store. Separate `highest accepted` from `last installed`:
verified metadata can raise an acceptance floor even if disk publication fails.
Store validated role progress according to TUF recovery rules and retain local
application floors separately. Root revocations must survive later failure.
Reject different canonical signed content at an already retained role/version;
envelope-only differences still have to satisfy every parent byte-hash binding.
Full metadata import raises per-scope observed release floors after signature and
extension validation even if target bytes are absent. This is knowledge of an
authorized release, not a claim that its missing payload passed integrity checks.

`verify` and `inspect` operate on a read-only snapshot and report that they do not
reserve acceptance. `trust-import` explicitly mutates root/metadata state without
installing a database. `install` always revalidates under the exclusive store lock;
it cannot consume an old successful verification receipt as authority.

Installation transaction:

1. Open/check the private store, lock it, and recover any pending operation.
   Validate current root/metadata and scope/time against the authoritative state.
2. Read the exact manifest into a bounded immutable buffer. Match its signed target
   length/hash and extension; use that same buffer for v1 parsing and verification.
   Deep-verify the payload into a private same-directory temporary file. The
   verified artifact and its descriptor stay bound through publication.
3. Recheck destination and sidecars. Durably write the new acceptance floor plus a
   pending record naming the transaction, output, manifest/database digests, trust
   generation, and proposed receipt. Sync before any catalog publication.
4. Publish without overwrite, reopen/check the database, and sync. Mark the receipt
   complete durably, then return success. Any error returns nonzero even if a
   recoverable catalog file exists.
5. Recovery never decreases a floor. If the pending output matches exactly, finish
   the receipt; if absent, retain the floor and permit retry; if conflicting,
   preserve the file and report required operator action. Remove only temporary
   artifacts proven to belong to that transaction. Never delete unrelated paths.

Use local filesystem transactions/atomic replacement and parent sync for state;
do not promise atomic commit across two directories. Receipt linkage and the
conservative write ordering are the safety mechanism. Fail on unsupported locking
or durability rather than silently degrading. Initial supported assurance is Linux
on tested local filesystems; network filesystems and Windows/macOS guarantees need
their own acceptance evidence. State cannot resist administrator rollback or an
old full-machine snapshot without an external monotonic anchor.

## CLI and schemas

Use a separate proposed `catalog-trusted-*` command family to avoid changing the
meaning or JSON output of existing `catalog-bundle-*` commands. All examples below
are **future UX, not executable commands in the inspected revision**. Placeholders
describe independently obtained values, never values to copy blindly from media.

```text
secureflow catalog-trust-init --trust-store /private/catalog-trust \
  --root /media/1.root.json --expected-root-sha256 <authenticated-root-digest> \
  --publisher example --catalog advisories --channel stable --profile core \
  --minimum-sequence <authenticated-floor-or-explicit-zero> \
  --operator <name> --authorization-reference <trust-enrollment-reference>

secureflow catalog-trust-import --trust-store /private/catalog-trust \
  --metadata-dir /media/metadata --publisher example

secureflow catalog-trusted-verify --trust-store /private/catalog-trust \
  --metadata-dir /media/metadata --publisher example --catalog advisories \
  --channel stable --required-profile core --manifest /media/core.manifest.json \
  --bundle /media/core.sqlite3.zst

secureflow catalog-trusted-install --trust-store /private/catalog-trust \
  --metadata-dir /media/metadata --publisher example --catalog advisories \
  --channel stable --required-profile core --manifest /media/core.manifest.json \
  --bundle /media/core.sqlite3.zst --output /private/catalogs/core-42.sqlite3

secureflow catalog-trust-status --trust-store /private/catalog-trust \
  --receipt /private/catalog-trust/receipts/<transaction>.json
```

Enrollment never overwrites an existing store. Lifecycle changes print old/new
root digests, scope, key membership, thresholds, expiry, and revocation effects;
explicit import records the operator action without asking for per-file prompts.
Installation is explicit authorization for that local write, not target analysis.
Producer commands should expose local `prepare`, `sign`, `assemble`, and `inspect`
operations with immutable input/output paths and no publish verb. Schema-printing
commands should mirror the existing CLI convention. Freeze final spelling in slice 1.

Successful machine output separates `integrity=verified`,
`publisher_authenticity=tuf-root-authorized`,
`freshness=within-local-policy-as-of`, and `rollback=accepted-against-local-state`.
It includes scope, sequence, initial/current root digests, metadata versions and
raw hashes, accepted signer IDs/quorums, manifest and database hashes, policy hash,
verification time/source, earliest limiting expiry, state generation, and
`validation_authority=human-only`. It never substitutes a boolean `trusted` for
these dimensions. Failure output uses stable error codes for bootstrap, signature,
scope, expiry/clock, rollback/equivocation, integrity, state, and filesystem errors;
failed or historical verification cannot carry a successful acceptance status.

| Proposed contract/artifact | Required contents and compatibility |
| --- | --- |
| TUF wire-profile ADR/contract | Role format, canonicalization vectors, supported algorithms/spec version, local filename mapping, bounds, and exact extension handling. Preserve standard TUF fields; do not claim a JSON Schema alone verifies signatures. |
| `secureflow-catalog-target-v1` schema | Closed-world object at target `custom.secureflow`: `contract_version`, `publisher_id`, `catalog_id`, `channel`, `profile`, `profile_policy_version`, `bundle_id`, `release_sequence`, `manifest_contract_version`, and `validation_authority=external-records-require-human-validation`. Cross-check manifest-derived fields; target length/hash are the standard parent fields. |
| `secureflow-catalog-trust-policy-v1` schema | Bootstrap association/floors, allowed scope, minimum role thresholds, clock/horizon policy, operator/reference, initial root digest. Policy changes are explicit and retained; publisher metadata cannot rewrite them. |
| `secureflow-catalog-trust-state-v1` schema | Store/lineage identity, policy digest, trusted metadata references, acceptance/time floors, state generation, transaction journal. Internal state is versioned but is not signed publisher evidence. |
| `secureflow-catalog-trust-receipt-v1` schema | Separate verification versus completed installation state, dimensions above, transaction/output binding for install, and limitations. Local receipt hashes support traceability, not transferable proof of an honest consumer clock/state. |

All new SecureFlow objects use bounded fields and closed-world schemas plus Rust
semantic validation. Golden positive/negative fixtures must agree between schema
and runtime. Unknown contract major versions fail closed; a future migration must
preserve lineage and floors and refuse unsupported downgrade.

Do not change catalog SQLite schema v2/v3, bundle manifest v1, profile policy v2,
correlation v1/v2, run contracts, or orchestration contracts for this layer.
The v1 `authenticity=unsigned-manifest-requires-external-sha256` describes its own
format; a separate trusted receipt describes external authentication. Internally,
the trusted path can supply the authenticated exact manifest digest to the existing
bundle validator. That is not an instruction to use `--allow-unverified-manifest`.
Keep trusted receipt schemas separate from existing strict verification outputs.

## Adversarial acceptance matrix

Tests use synthetic local publishers and harmless fixture data, fixed test clocks,
and throwaway keys. No third-party targets, real credentials, or vulnerability
reproduction are required. Every rejection asserts no new completed installation,
no weakened state, and truthful errors; valid earlier root progress may persist.

| Gate | Cases and required evidence |
| --- | --- |
| Bootstrap and scope | Same-package substituted root/pin; missing operator reference; wrong publisher/catalog/channel/profile; alias path; absent minimum floor; repeat enrollment. Refuse or require an explicit independent enrollment decision. |
| Signatures and parser | Bit changes; wrong role/key/algorithm; invalid/small-order/noncanonical Ed25519 inputs; duplicate JSON members; duplicate key IDs or decoded keys; below-threshold signatures; altered signed extensions; unknown critical semantics; BOM/Unicode/numeric/depth/size boundaries. Cross-check maintained verifier vectors; no permissive fallback. |
| Byte boundary | Reformat v1 manifest; swap payload; alter origin/profile claims; edit signed metadata after one signature; change a metadata envelope without updating its parent hash. All inconsistent chains fail. |
| Lifecycle | Old/new root dual quorum; missing/out-of-order intermediate; expired intermediate leading to valid final root; expired final root; revoked signer in cached metadata; insufficient recovery quorum; threshold reduction; long bounded root catch-up. Persist verified revocation even when payload fails. |
| Freshness | Exact expiry instant; clock before persisted floor; operator time without reference; implausible future expiry; same timestamp replay; offline stale-but-unexpired package. Assert the last case has only bounded as-of acceptance, never a latest-state claim. |
| Rollback | Lower sequence; same sequence/different digest; same sequence/same digest reinstall; root rotation preserves application floor; cross-profile floor isolation; publisher-signed fast-forward; lost state/old backup; integer exhaustion. No automatic reset or wrap. |
| State and filesystem | Concurrent installs, stale verification snapshot, crash before/after each sync/publication, disk full, corrupt journal, missing output, conflicting output, symlink/hardlink aliases, sidecars, metadata replacement, trust-store replacement, unsupported locking. Recovery preserves unrelated files and conservative floors. |
| Existing integrity | Reuse bundle tests for wrong hashes/sizes, bomb limits, truncated/trailing frames, SQLite/provenance/composition mismatches, projected profile rules and private/no-overwrite installation. Valid signatures cannot bypass them. |
| Authority and offline behavior | Network-denied end-to-end trust and rotation demo; malformed URL inputs; no socket/provider invocation; no engine invocation in the trusted-catalog demo; correlation retains false validation/causality flags; no human decisions created. Preserve the existing authorized synthetic CodeSupply test separately. |
| Compatibility and reproduction | Old v1 unsigned/pinned workflows and output fixtures unchanged; unknown new schemas rejected; fixed keys/metadata inputs yield stable canonical/signature vectors; existing manifest/payload hashes unchanged by adding external metadata. |

## Six vertical slices

Implement sequentially after this plan is approved through the normal repository
review process. Each slice yields one reviewable local behavior; no slice grants
permission to publish or create accounts.

| Slice | Visible result and likely files | Acceptance gate |
| --- | --- | --- |
| 1. Freeze the protocol with an offline fixture | New wire-profile ADR/contracts, proposed schemas, `tests/fixtures/trusted-catalog/`, a bounded library spike in the future trust module. Select dependency/version and local signer interface. | A fixed root and one signed manifest verify with a maintained TUF implementation and independent signature/canonicalization vectors. Show network-disabled operation, all bounds, MSRV/license audit, and explicit bootstrap. Stop implementation if the library cannot meet the profile. |
| 2. Enroll and inspect one publisher | Future `crates/secureflow-knowledge/src/catalog_trust.rs`, CLI commands and trust-policy/receipt schemas. Read-only verify connects authenticated manifest bytes to the existing bundle verifier. | Valid local bundle passes; root substitution, wrong scope, bad quorum, and manifest edits fail. Existing v1 CLI output remains byte/schema compatible. No install or hidden enrollment occurs. |
| 3. Install with durable local policy | Trust-state module, journal, trusted install CLI, Linux integration fixtures. | Time/sequence rules, no-overwrite publication, idempotent reinstall, concurrent operations, and crash recovery pass. Success requires a durable complete receipt; failed publication never lowers a floor. |
| 4. Exercise the complete key lifecycle | Local producer preparation/signature assembly tools, root-only import, custodian/recovery runbook, lifecycle fixtures. | Two independent synthetic signatures; rotation across offline gaps; removal of compromised keys; cached-data revalidation; quorum-loss refusal and explicit re-enrollment rehearsal. No network or key leakage. |
| 5. Retain a hermetic distribution demo | New local trusted-catalog demo and receipt verifier, CLI tests, updates to threat model and documentation in the future implementation. Reuse frozen synthetic catalog bytes. | Bootstrap → accept → rotate → revoke → reject replay → inspect receipts. Demonstrate expiry and interrupted install recovery. Preserve human-only semantics and the old CodeSupply demo; no real engine/AI transport in the new demo. |
| 6. Qualify the release and its claims | Extend CI/release evidence gates, dependency SBOM/provenance and versioned release notes when implementation is ready. | Workspace gates, adversarial matrix, independent human security review of signing/state boundaries, custody rehearsal, and clean-checkout evidence all pass. Any publication is a separately authorized operation. |

## Releases, allowed claims, and deferrals

Do not choose a release tag or claim completion from this document. A future
candidate must retain the exact commit, toolchain, dependency lock, specification
profile, fixture hashes, canonicalization/signature vectors, supported platform,
test results, and local demo receipts. Have a human reviewer inspect the trust
bootstrap, key ceremony, state recovery, and public wording. Product signing keys
are never test fixtures or build secrets. Catalog publication still requires its
own license/provenance review and human authorization.

Allowed after the gates pass: “This catalog's exact manifest and payload were
verified offline against publisher root X, policy P, and retained state S at time
T.” “Key rotation/revocation imported through root version N was enforced.”
“The client rejected a rollback below its retained acceptance floor.”

Prohibited: globally latest/fresh/complete/revocation-aware catalogs while offline;
verified legal publisher identity from a self-signed key; authenticated upstream
records merely because a distributor signed; vulnerability validity, reachability,
causality, exploitability, safe remediation, source safety, license entitlement,
automatic human approval, or cross-host binary/catalog reproducibility without
separate evidence. A catalog `affected` result remains an advisory assertion.

Explicitly defer HTTP acquisition/sync, crawlers, hosted mirrors/services/accounts,
automatic background refresh, transparency/gossip and global equivocation checks,
keyless signing, enterprise PKI, HSM/KMS integrations, threshold cryptography
(quorum here means independent ordinary signatures), target-role delegations,
cross-publisher federation, cross-profile overlays, catalog deltas as distribution
targets, hardware anti-rollback counters, automatic removal of installed catalogs,
freshness enforcement in every downstream query, Windows/macOS durability claims,
cryptographic algorithm agility beyond a versioned future migration, real AI
transport, active scanning/exploitation, autonomous patches, and any expansion of
human validation authority.

## Executive summary and verification commands

Deliver a local TUF/Ed25519 trust layer around unchanged catalog bytes, with explicit
root enrollment, independent signing quorums, offline key lifecycle, bounded
as-of freshness, and crash-safe local rollback history. Preserve every existing
integrity and human-review boundary. Six slices separate protocol selection,
verification, installation, lifecycle, demonstration, and release qualification.

For this documentation-only change, inspect only the new plan and whitespace;
there is no production test result or release qualification claim:

```bash
git status --short
git diff --check
git diff --cached --check
git diff --cached -- docs/plans/trusted-catalog-distribution.md
```

The plan is staged as a new repository file for review. This assignment does not
create a commit; unrelated paths remain untouched.

Future implementation gates, not executed by this planning task:

```bash
cargo +1.92.0 test -p secureflow-knowledge catalog_bundle --locked --offline
cargo +1.92.0 test -p secureflow --test cli --locked --offline
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
python3 scripts/lint_release_notes.py docs/releases
cargo +1.92.0 fmt --all -- --check
cargo +1.92.0 clippy --workspace --all-targets --locked --offline -- -D warnings
cargo +1.92.0 test --workspace --locked --offline
```

Run the new trust-specific matrix/demo once their commands exist. Offline Cargo
requires an already populated locked dependency cache. Separately, the existing
release lane uses `cargo +1.92.0 audit` and
`bash scripts/release-local.sh /absolute/new/release-output` from an authorized
clean release checkout with installed prerequisites; it can fetch dependencies
and is not an offline runtime guarantee. Do not run it merely to verify this plan.
