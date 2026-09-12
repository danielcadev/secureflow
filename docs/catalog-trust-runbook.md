# Offline catalog publisher and consumer runbook

This candidate implements local distribution; production use still needs independent human security review and a real multi-person custody rehearsal. Read the [contract](catalog-trust-contract.md) and [qualification record](releases/trusted-catalog-candidate.md). Authentication never validates an advisory or authorizes analysis of a target.

## Reproduce the synthetic ceremony

On Linux with Rust 1.92, Python 3 and OpenSSL Ed25519 support, install working Bubblewrap user namespaces. The demo fails if the sandbox is unavailable. Build and run from the repository:

```bash
cargo +1.92.0 build --locked -p secureflow
python3 scripts/demo-trusted-catalog.py \
  --binary target/debug/secureflow --output "$PWD/target/trusted-catalog-demo"
python3 scripts/verify-trusted-catalog-demo.py \
  --binary target/debug/secureflow --demo target/trusted-catalog-demo
```

The output directory must not exist. The fixture clock is fixed at `2026-09-12T12:00:00Z`; these public, predictable keys must never identify a production publisher. Every SecureFlow subprocess runs under `bwrap --unshare-all` with only the new demo directory writable. The retained evidence includes requests, canonical preimages, public signatures, three roots, metadata, installed catalog hashes, receipts, rejection logs and a binary hash. Temporary synthetic private keys are deleted by the demo's cleanup handler; uncatchable termination can leave test-only scratch files.

The ceremony covers enrollment, exact verification, installation, overlapping targets keys, removal of old targets keys, root-only revocation, replay/retired-signer/expiry refusal, renewed metadata, historical inspection and recovery. The retained pending-journal example is labeled as a synthetic post-publication journal. Separate Rust child-process tests exercise abrupt termination and file-write quota failure. Neither substitutes for physical power-loss testing or independent custodians.

## Establish real custody before enrollment

Assign at least three independent offline root custodians with two signatures required, three separate targets keys with two required, two snapshot keys with one required, and two timestamp keys with one required. Never reuse a decoded key across roles. Give each custodian independent devices, encrypted offline storage and separately held backups. CI and consumer stores receive public material only. Record responsible people, backup location references, public fingerprints, role assignments and a tested recovery path in the organization's custody record; do not put secrets in the repository.

Each custodian generates a fresh Ed25519 key with their reviewed offline signer. For the supported external OpenSSL interface, keep the private key in encrypted PKCS#8 and let OpenSSL prompt locally for its passphrase:

```bash
umask 077
openssl genpkey -algorithm ED25519 -aes-256-cbc -out custodian.pem
openssl pkey -in custodian.pem -pubout -out custodian-public.pem
```

SecureFlow does not ingest that PEM or passphrase. Derive the TUF public key from the raw 32-byte Ed25519 public value using reviewed tooling; its key ID is SHA-256 of the canonical key JSON defined in the contract. Compare both public fingerprint and role assignment independently. Do not treat a self-signed root, a fingerprint carried on the same medium, or possession of one key as independent identity evidence.

Approve initial scope and root out of band. The consumer records an independently obtained exact root SHA-256, operator, authorization reference and known minimum release sequence. If no history is known, explicitly choose zero. Optionally record an independent first-manifest digest. Wrong time or a poisoned high sequence can prevent further acceptance: verify these before the first mutation.

## Prepare, sign and seal a release

Freeze a legacy v1 manifest and bundle in a new private staging directory. Deeply verify the bundle, provenance and license evidence, then write a targets signed-object JSON matching the contract. Assign a strictly increasing metadata version and appropriate release sequence. Use whole-second UTC expiry within the fixed horizons. Prepare one bundle per targets request; metadata inputs contain public data only.

```bash
secureflow catalog-trusted-prepare \
  --signed-input /private/stage/targets.signed.json \
  --manifest /private/stage/catalog.manifest.json \
  --bundle /private/stage/catalog.sqlite3.zst \
  --output /private/stage/targets.request.json
```

The result identifies `/private/stage/targets.request.canonical` and its hash. Each targets custodian independently reviews exact scope, sequence, expiry, manifest digest, composition and provenance before signing those exact canonical bytes on their offline device:

```bash
openssl pkeyutl -sign -rawin -inkey custodian.pem \
  -in targets.request.canonical -out custodian.sig
secureflow catalog-trusted-sign \
  --request /private/stage/targets.request.json \
  --root /private/stage/1.root.json --key-id <authorized-public-key-id> \
  --signature /private/stage/custodian.sig \
  --output /private/stage/custodian.signature.json
secureflow catalog-trusted-assemble \
  --request /private/stage/targets.request.json --root /private/stage/1.root.json \
  --signature /private/stage/custodian-a.signature.json \
  --signature /private/stage/custodian-b.signature.json \
  --output /private/stage/1.targets.json
```

Repeat preparation/signature collection/assembly for snapshot, then timestamp, binding exact serialized child bytes, lengths, versions and SHA-256. Root preparation needs no bundle; initial assembly checks its self quorum. A root transition additionally uses `--previous-root` and signatures satisfying both old and new root quorums. When role membership changes, collect each signature against the root that authorizes that custodian. There is no private-key import or threshold override.

Nonroot assembly checks role signatures, not a complete consumer chain. Seal a new delivery directory only after a consumer `catalog-trusted-verify` succeeds against an explicitly enrolled test store. Retain its receipt, raw bytes, preimages, signatures and a hash inventory. Never rewrite an approved request; changed fields require a new ceremony and new parent hashes. The CLI refuses output replacement; there is no automatic upload, release publication or implicit seal command.

## Enroll and consume

Create the parent directory privately. All trust/input/output paths must be absolute and canonical; substitute actual independently reviewed values below. The supplied time pair is optional and records an operator attestation. Without it, the tool records reliance on the system clock.

```bash
install -d -m 0700 /private/catalog
secureflow catalog-trust-init \
  --trust-store /private/catalog/trust --root /media/release/1.root.json \
  --expected-root-sha256 <independently-obtained-sha256> \
  --publisher example --catalog advisories --channel stable --profile full \
  --minimum-sequence 0 --operator 'responsible operator' \
  --authorization-reference 'approved publisher enrollment record'
secureflow catalog-trust-import \
  --trust-store /private/catalog/trust --metadata-dir /media/release \
  --publisher example
secureflow catalog-trusted-verify \
  --trust-store /private/catalog/trust --metadata-dir /media/release \
  --publisher example --catalog advisories --channel stable --required-profile full \
  --manifest /media/release/catalog.manifest.json --bundle /media/release/catalog.sqlite3.zst
secureflow catalog-trusted-install \
  --trust-store /private/catalog/trust --metadata-dir /media/release \
  --publisher example --catalog advisories --channel stable --required-profile full \
  --manifest /media/release/catalog.manifest.json --bundle /media/release/catalog.sqlite3.zst \
  --output /private/catalog/installed.sqlite3
```

Read-only verification reserves nothing; install rechecks under the exclusive lock. Metadata import can raise floors without a payload, and rejected install can retain verified progress. Keep raw output/error receipts, including failures. The installed database is separate from the trust store. Existing outputs are never replaced.

`catalog-trust-status --trust-store … --receipt …` evaluates current policy for a committed installation receipt without checking live installed bytes. To examine expired or older evidence, use the same verify inputs with `catalog-trusted-inspect --historical`; a report is never current acceptance. Do not turn historical output into authorization to install.

## Rotation, compromise and recovery

For planned targets rotation, root quorum first signs a consecutive root admitting replacement targets keys alongside old keys. Publish targets signed by the replacement quorum and an exact snapshot/timestamp chain. After the offline overlap window, sign another consecutive root removing old keys. A root rotation changing root keys itself needs both old and new root quorums. Keep every intermediate root available to disconnected consumers. Import more than 128 transitions in explicit ordered batches.

For compromise, surviving root custodians replace the affected role keys promptly. Deliver the root chain separately and run `catalog-trust-import --root-only` with explicit store, metadata directory and publisher. This saves revocation even if catalog bytes are missing. Old receipts remain historical evidence; current acceptance is re-evaluated. Fresh metadata must use versions above every retained role/parent floor, including progress from rejected packages. An offline consumer cannot detect a withheld revocation.

For an interrupted install, retain the output and store intact. Reopen an exclusive import/install at a valid nondecreasing time. Recovery either completes an exact matching published database, clears an absent-output pending operation while preserving floors, or refuses a conflict. Never delete a conflicting file or reset `state.json` to make the tool succeed. Inspect private orphan temporary files only after journal review; clean up solely identified abandoned files. An error after fsync/publication requires examining recovery, not assuming nothing happened.

For lost keys, rehearse retrieving encrypted backups on independent devices, checking public identities, collecting the surviving quorum, rotating keys and retiring the lost material. If root quorum is unavailable, continuity cannot be recovered cryptographically. Preserve the old store and evidence, obtain independently authenticated new root/scope/history/time, record the explicit human decision and enroll a different private store. Never describe this as seamless rotation. Restoring an old whole-store backup loses rollback knowledge unless higher independent checkpoints are restored through an explicitly reviewed process; this version does not automate migration or lowering floors.

Before production, two or more independent people must inspect signing/state boundaries and rehearse real backup recovery, offline catch-up, role-key removal, loss of quorum and explicit new-lineage enrollment. Record exact binary/commit, filesystem/mount assumptions, custody evidence references and residual risks. Synthetic signatures in CI cannot satisfy this gate.
