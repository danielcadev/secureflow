//! Synthetic publishers and harmless empty catalog bytes; no external targets.
use super::{types::*, wire::*, *};
use crate::{
    catalog::{Catalog, CatalogProfile},
    catalog_bundle as bundle,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::PathBuf};

const NOW: &str = "2026-09-12T12:00:00Z";
fn clock() -> Clock {
    Clock::capture(Some(NOW.into()), Some("synthetic test clock".into())).unwrap()
}
struct Fixture {
    dir: tempfile::TempDir,
    keys: BTreeMap<String, Vec<SigningKey>>,
    root: Value,
    manifest: bundle::CatalogBundleManifest,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(dir.path().join("metadata")).unwrap();
        let keys = ROLES
            .iter()
            .enumerate()
            .map(|(r, role)| {
                (
                    (*role).into(),
                    (0..if r < 2 { 3 } else { 2 })
                        .map(|i| SigningKey::from_bytes(&[1 + r as u8 * 8 + i; 32]))
                        .collect(),
                )
            })
            .collect();
        let cat = Catalog::open_or_create(&dir.path().join("source.sqlite3")).unwrap();
        let manifest =
            bundle::create_bundle(&cat, CatalogProfile::Full, &dir.path().join("bundle.zst"))
                .unwrap();
        fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let mut f = Self {
            dir,
            keys,
            root: Value::Null,
            manifest,
        };
        f.root = f.make_root(1);
        f.write("metadata/1.root.json", &f.root);
        f.release(1, 1);
        f
    }
    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }
    fn key(k: &SigningKey) -> Value {
        json!({"keytype":"ed25519","scheme":"ed25519","keyval":{"public":k.verifying_key().to_bytes().iter().map(|b|format!("{b:02x}")).collect::<String>()}})
    }
    fn sign_with(signed: Value, keys: &[SigningKey]) -> Value {
        let msg = canonical(&signed).unwrap();
        let signatures:Vec<_>=keys.iter().map(|k|json!({"keyid":digest(&canonical(&Self::key(k)).unwrap()),"sig":k.sign(&msg).to_bytes().iter().map(|b|format!("{b:02x}")).collect::<String>()})).collect();
        json!({"signed":signed,"signatures":signatures})
    }
    fn sign(&self, signed: Value, role: &str) -> Value {
        Self::sign_with(
            signed,
            &self.keys[role][..if ["root", "targets"].contains(&role) {
                2
            } else {
                1
            }],
        )
    }
    fn make_root(&self, version: u64) -> Value {
        let mut keys = serde_json::Map::new();
        let mut roles = serde_json::Map::new();
        for (role, private) in &self.keys {
            let ids: Vec<_> = private
                .iter()
                .map(|k| {
                    let public = Self::key(k);
                    let id = digest(&canonical(&public).unwrap());
                    keys.insert(id.clone(), public);
                    Value::String(id)
                })
                .collect();
            roles.insert(role.clone(),json!({"keyids":ids,"threshold":if ["root","targets"].contains(&role.as_str()){2}else{1}}));
        }
        self.sign(json!({"_type":"root","spec_version":"1.0.0","version":version,"expires":"2027-09-12T00:00:00Z","consistent_snapshot":true,"keys":keys,"roles":roles}),"root")
    }
    fn write(&self, path: &str, v: &Value) {
        fs::write(self.path(path), serde_json::to_vec_pretty(v).unwrap()).unwrap();
    }
    fn target(&self, sequence: u64) -> Value {
        let raw = fs::read(self.path("manifest.json")).unwrap();
        json!({"length":raw.len(),"hashes":{"sha256":digest(&raw)},"custom":{"secureflow":{"contract_version":"secureflow-catalog-target-v1","publisher_id":"synthetic","catalog_id":"advisories","channel":"stable","profile":"full","profile_policy_version":self.manifest.profile_policy_version,"bundle_id":self.manifest.bundle_id,"release_sequence":sequence,"manifest_contract_version":self.manifest.contract_version,"validation_authority":self.manifest.validation_authority}}})
    }
    fn release(&self, version: u64, sequence: u64) {
        let target = self.target(sequence);
        self.publish_target(version, target);
    }
    fn publish_target(&self, version: u64, target: Value) {
        let targets=self.sign(json!({"_type":"targets","spec_version":"1.0.0","version":version,"expires":"2026-10-01T00:00:00Z","targets":{"catalogs/advisories/stable/full.manifest.json":target}}),"targets");
        self.publish_targets(version, &targets);
    }
    fn publish_targets(&self, version: u64, targets: &Value) {
        let name = format!("metadata/{version}.targets.json");
        self.write(&name, targets);
        let raw = fs::read(self.path(&name)).unwrap();
        let snapshot=self.sign(json!({"_type":"snapshot","spec_version":"1.0.0","version":version,"expires":"2026-10-01T00:00:00Z","meta":{"targets.json":{"version":version,"length":raw.len(),"hashes":{"sha256":digest(&raw)}}}}),"snapshot");
        let name = format!("metadata/{version}.snapshot.json");
        self.write(&name, &snapshot);
        let raw = fs::read(self.path(&name)).unwrap();
        let timestamp=self.sign(json!({"_type":"timestamp","spec_version":"1.0.0","version":version,"expires":"2026-09-15T00:00:00Z","meta":{"snapshot.json":{"version":version,"length":raw.len(),"hashes":{"sha256":digest(&raw)}}}}),"timestamp");
        self.write("metadata/timestamp.json", &timestamp);
    }
    fn enroll(&self) -> Result<Value> {
        enroll(
            &self.path("trust"),
            &self.path("metadata/1.root.json"),
            Enrollment {
                publisher: "synthetic".into(),
                catalog: "advisories".into(),
                channel: "stable".into(),
                profiles: vec!["full".into()],
                minimum_sequence: 0,
                bootstrap_manifest_sha256: None,
                operator: "test human".into(),
                authorization_reference: "synthetic ceremony".into(),
                expected_root_sha256: digest(&fs::read(self.path("metadata/1.root.json")).unwrap()),
                clock: clock(),
            },
        )
    }
    fn session(&self, write: bool) -> Session {
        Session::open(&self.path("trust"), clock(), write).unwrap()
    }
    fn scope(&self) -> Scope {
        Scope {
            publisher_id: "synthetic".into(),
            catalog_id: "advisories".into(),
            channel: "stable".into(),
            profile: "full".into(),
        }
    }
    fn verify(&self) -> Result<Receipt> {
        self.session(false).verify(
            &self.path("metadata"),
            &self.scope(),
            &self.path("manifest.json"),
            &self.path("bundle.zst"),
        )
    }
    fn install(&self, out: &str) -> Result<Receipt> {
        self.session(true).install(
            &self.path("metadata"),
            &self.scope(),
            &self.path("manifest.json"),
            &self.path("bundle.zst"),
            &self.path(out),
        )
    }
    fn import(&self, root_only: bool) -> Result<Value> {
        self.session(true)
            .import(&self.path("metadata"), "synthetic", root_only)
    }
    fn state(&self) -> State {
        self.session(false).state.clone()
    }
}
#[test]
fn trusted_catalog_bootstrap_verify_install_and_idempotent_receipts() {
    let f = Fixture::new();
    f.enroll().unwrap();
    let initial = fs::read(f.path("trust/state.json")).unwrap();
    let receipt = f.verify().unwrap();
    assert!(!receipt.reserves_acceptance);
    assert_eq!(initial, fs::read(f.path("trust/state.json")).unwrap());
    validate_schema("receipt", &serde_json::to_value(&receipt).unwrap()).unwrap();
    let installed = f.install("installed.sqlite3").unwrap();
    assert_eq!(installed.installation, "complete");
    let receipt_path = f.path(&format!(
        "trust/receipts/{}.json",
        installed.transaction_id.as_ref().unwrap()
    ));
    assert!(
        f.session(false).status(&receipt_path).unwrap()["current_policy_acceptance"]
            .as_bool()
            .unwrap()
    );
    let again = f.install("again.sqlite3").unwrap();
    assert_eq!(installed.manifest_sha256, again.manifest_sha256);
    assert_ne!(installed.transaction_id, again.transaction_id);
    assert_eq!(f.state().completed.len(), 2);
    assert!(f.install("installed.sqlite3").is_err());
    assert!(f.enroll().is_err());
}
#[test]
fn trusted_catalog_bootstrap_and_scope_fail_closed() {
    let f = Fixture::new();
    let root = f.path("metadata/1.root.json");
    let args = || Enrollment {
        publisher: "synthetic".into(),
        catalog: "advisories".into(),
        channel: "stable".into(),
        profiles: vec!["full".into()],
        minimum_sequence: 0,
        bootstrap_manifest_sha256: None,
        operator: "human".into(),
        authorization_reference: "reference".into(),
        expected_root_sha256: "0".repeat(64),
        clock: clock(),
    };
    assert_eq!(
        enroll(&f.path("bad"), &root, args()).unwrap_err().code,
        "TRUST_BOOTSTRAP"
    );
    assert!(!f.path("bad").exists());
    let mut a = args();
    a.expected_root_sha256 = digest(&fs::read(&root).unwrap());
    a.authorization_reference = " ".into();
    assert!(enroll(&f.path("bad"), &root, a).is_err());
    f.enroll().unwrap();
    for changed in ["publisher", "catalog", "channel", "profile"] {
        let mut scope = f.scope();
        match changed {
            "publisher" => scope.publisher_id = "other".into(),
            "catalog" => scope.catalog_id = "other".into(),
            "channel" => scope.channel = "other".into(),
            _ => scope.profile = "core".into(),
        }
        assert_eq!(
            f.session(false)
                .verify(
                    &f.path("metadata"),
                    &scope,
                    &f.path("manifest.json"),
                    &f.path("bundle.zst")
                )
                .unwrap_err()
                .code,
            "TRUST_SCOPE"
        );
    }
    assert!(Session::open(&f.path("absent"), clock(), true).is_err());
}
#[test]
fn trusted_catalog_byte_chain_quorum_and_unknown_extensions() {
    for kind in [
        "manifest-whitespace",
        "payload",
        "quorum",
        "signature",
        "parent-envelope",
        "extension",
        "algorithm",
        "duplicate-signature",
    ] {
        let f = Fixture::new();
        f.enroll().unwrap();
        match kind {
            "manifest-whitespace" => {
                let mut b = fs::read(f.path("manifest.json")).unwrap();
                b.push(b' ');
                fs::write(f.path("manifest.json"), b).unwrap();
            }
            "payload" => {
                let mut b = fs::read(f.path("bundle.zst")).unwrap();
                b[10] ^= 1;
                fs::write(f.path("bundle.zst"), b).unwrap();
            }
            "parent-envelope" => {
                let mut b = fs::read(f.path("metadata/1.targets.json")).unwrap();
                b.push(b' ');
                fs::write(f.path("metadata/1.targets.json"), b).unwrap();
            }
            _ => {
                let mut v: Value =
                    serde_json::from_slice(&fs::read(f.path("metadata/1.targets.json")).unwrap())
                        .unwrap();
                match kind {
                    "quorum" => {
                        v["signatures"].as_array_mut().unwrap().pop();
                    }
                    "signature" => v["signatures"][0]["sig"] = "0".repeat(128).into(),
                    "duplicate-signature" => {
                        let sig = v["signatures"][0].clone();
                        v["signatures"].as_array_mut().unwrap().push(sig);
                    }
                    "algorithm" => v["signed"]["critical"] = json!(["new-signature-algorithm"]),
                    _ => {
                        v["signed"]["targets"]["catalogs/advisories/stable/full.manifest.json"]["custom"]
                            ["secureflow"]["extra"] = true.into();
                        v = f.sign(v["signed"].clone(), "targets");
                    }
                }
                f.publish_targets(1, &v);
            }
        }
        assert!(f.install("rejected.sqlite3").is_err(), "{kind}");
        assert!(!f.path("rejected.sqlite3").exists(), "{kind}");
        assert!(f.state().completed.is_empty());
    }
}
#[test]
fn trusted_catalog_release_floors_survive_missing_payload_and_expiry() {
    let f = Fixture::new();
    f.enroll().unwrap();
    f.release(2, 42);
    f.import(false).unwrap();
    assert_eq!(f.state().floors["full"].sequence, 42);
    f.release(3, 41);
    assert_eq!(f.verify().unwrap_err().code, "TRUST_ROLLBACK");
    f.release(3, 42);
    assert!(f.verify().is_ok());
    let mut target = f.target(42);
    target["hashes"]["sha256"] = "f".repeat(64).into();
    f.publish_target(4, target);
    assert_eq!(f.verify().unwrap_err().code, "TRUST_EQUIVOCATION");
    f.release(4, 43);
    fs::remove_file(f.path("bundle.zst")).unwrap();
    assert!(f.install("missing.sqlite3").is_err());
    assert_eq!(f.state().floors["full"].sequence, 43);
    let expired =
        Clock::capture(Some("2026-09-15T00:00:00Z".into()), Some("fixture".into())).unwrap();
    assert_eq!(
        Session::open(&f.path("trust"), expired, false)
            .unwrap()
            .import_metadata(&f.path("metadata"), false)
            .unwrap_err()
            .code,
        "TRUST_EXPIRY"
    );
    let past = Clock::capture(Some("2026-09-11T00:00:00Z".into()), Some("fixture".into())).unwrap();
    assert!(Session::open(&f.path("trust"), past, true).is_err());
    assert!(Clock::capture(Some(NOW.into()), None).is_err());
}
#[test]
fn trusted_catalog_partial_parent_progress_prevents_rollback() {
    let f = Fixture::new();
    f.enroll().unwrap();
    f.release(2, 2);
    fs::remove_file(f.path("metadata/2.snapshot.json")).unwrap();
    assert!(f.import(false).is_err());
    assert_eq!(f.state().roles["timestamp"].evidence.version, 2);
    f.release(1, 1);
    assert_eq!(f.verify().unwrap_err().code, "TRUST_ROLLBACK");
    f.release(3, 3);
    let mut ts: Value =
        serde_json::from_slice(&fs::read(f.path("metadata/timestamp.json")).unwrap()).unwrap();
    ts["signed"]["meta"]["snapshot.json"]["version"] = 1.into();
    let ts = f.sign(ts["signed"].clone(), "timestamp");
    f.write("metadata/timestamp.json", &ts);
    assert_eq!(f.verify().unwrap_err().code, "TRUST_ROLLBACK");
}
#[test]
fn trusted_catalog_rotation_revokes_cached_authority_and_keeps_floors() {
    let mut f = Fixture::new();
    f.enroll().unwrap();
    let receipt = f.install("initial.sqlite3").unwrap();
    f.keys.insert(
        "targets".into(),
        (40..43).map(|b| SigningKey::from_bytes(&[b; 32])).collect(),
    );
    f.root = f.make_root(2);
    f.write("metadata/2.root.json", &f.root);
    f.import(true).unwrap();
    assert_eq!(f.state().roots.len(), 2);
    assert_eq!(f.verify().unwrap_err().code, "TRUST_SIGNATURE");
    let status = f
        .session(false)
        .status(&f.path(&format!(
            "trust/receipts/{}.json",
            receipt.transaction_id.unwrap()
        )))
        .unwrap();
    assert_eq!(status["current_policy_acceptance"], false);
    f.release(2, 2);
    let mut b = fs::read(f.path("bundle.zst")).unwrap();
    b[10] ^= 1;
    fs::write(f.path("bundle.zst"), b).unwrap();
    assert!(f.install("bad.sqlite3").is_err());
    assert_eq!(f.state().roots.len(), 2);
    assert_eq!(f.state().floors["full"].sequence, 2);
    assert!(!f.path("bad.sqlite3").exists());
}
#[test]
fn trusted_catalog_root_dual_quorum_gap_expired_bridge_and_threshold_floor() {
    let mut f = Fixture::new();
    f.enroll().unwrap();
    let old = f.keys["root"].clone();
    f.keys.insert(
        "root".into(),
        (60..63).map(|b| SigningKey::from_bytes(&[b; 32])).collect(),
    );
    let new = f.make_root(2);
    f.write("metadata/2.root.json", &new);
    assert!(f.import(true).is_err());
    assert_eq!(f.state().roots.len(), 1);
    let mut signed = new["signed"].clone();
    signed["expires"] = "2026-09-01T00:00:00Z".into();
    let mut root = Selfless::dual(&signed, &old, &f.keys["root"]);
    f.write("metadata/2.root.json", &root);
    let third = f.make_root(3);
    f.write("metadata/3.root.json", &third);
    f.import(true).unwrap();
    assert_eq!(f.state().roots.len(), 3);
    root = f.make_root(5);
    f.write("metadata/5.root.json", &root);
    assert!(f.import(true).is_err());
    assert_eq!(f.state().roots.len(), 3);
    fs::remove_file(f.path("metadata/5.root.json")).unwrap();
    root = f.make_root(4);
    root["signed"]["roles"]["targets"]["threshold"] = 1.into();
    root = f.sign(root["signed"].clone(), "root");
    f.write("metadata/4.root.json", &root);
    assert!(f.import(true).is_err());
}
struct Selfless;
impl Selfless {
    fn dual(signed: &Value, old: &[SigningKey], new: &[SigningKey]) -> Value {
        let mut keys = old[..2].to_vec();
        keys.extend_from_slice(&new[..2]);
        Fixture::sign_with(signed.clone(), &keys)
    }
}
#[test]
fn trusted_catalog_transaction_checkpoints_recover_conservatively() {
    for point in [
        "verified",
        "pending-durable",
        "published",
        "receipt-durable",
    ] {
        let f = Fixture::new();
        f.enroll().unwrap();
        let result = f.session(true).install_with_checkpoint(
            &f.path("metadata"),
            &f.scope(),
            &f.path("manifest.json"),
            &f.path("bundle.zst"),
            &f.path("output.sqlite3"),
            |p| {
                if p == point {
                    Err(error("TRUST_FILESYSTEM", "injected interruption"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err());
        let before = f.state();
        assert_eq!(before.floors["full"].sequence, 1);
        let recovered = Session::open(&f.path("trust"), clock(), true);
        assert!(
            recovered.is_ok(),
            "checkpoint {point}: {:?}; files: {:?}",
            recovered.as_ref().err(),
            fs::read_dir(f.dir.path())
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>()
        );
        drop(recovered);
        let after = f.state();
        assert!(after.pending.is_none());
        assert_eq!(after.floors["full"].sequence, 1);
        if ["published", "receipt-durable"].contains(&point) {
            assert_eq!(after.completed.len(), 1);
            assert!(f.path("output.sqlite3").exists());
        } else {
            assert!(after.completed.is_empty());
            f.install("retry.sqlite3").unwrap();
        }
    }
}
#[test]
fn trusted_catalog_recovery_preserves_conflicting_output_and_concurrency() {
    let f = Fixture::new();
    f.enroll().unwrap();
    let _ = f.session(true).install_with_checkpoint(
        &f.path("metadata"),
        &f.scope(),
        &f.path("manifest.json"),
        &f.path("bundle.zst"),
        &f.path("output.sqlite3"),
        |p| {
            if p == "pending-durable" {
                Err(error("TRUST_STATE", "interrupted"))
            } else {
                Ok(())
            }
        },
    );
    fs::write(f.path("output.sqlite3"), b"unrelated file").unwrap();
    assert!(Session::open(&f.path("trust"), clock(), true).is_err());
    assert_eq!(
        fs::read(f.path("output.sqlite3")).unwrap(),
        b"unrelated file"
    );
    assert!(f.state().pending.is_some());
    let lock = f.session(false);
    assert!(Session::open(&f.path("trust"), clock(), true).is_err());
    drop(lock);
}
#[test]
fn trusted_catalog_filesystem_aliases_and_sidecars_are_rejected() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    f.enroll().unwrap();
    symlink(f.path("manifest.json"), f.path("alias.json")).unwrap();
    assert!(
        f.session(false)
            .verify(
                &f.path("metadata"),
                &f.scope(),
                &f.path("alias.json"),
                &f.path("bundle.zst")
            )
            .is_err()
    );
    fs::hard_link(f.path("bundle.zst"), f.path("hard.zst")).unwrap();
    assert!(f.verify().is_err());
    fs::remove_file(f.path("hard.zst")).unwrap();
    fs::write(f.path("output.sqlite3-wal"), b"keep sidecar").unwrap();
    assert!(f.install("output.sqlite3").is_err());
    assert_eq!(
        fs::read(f.path("output.sqlite3-wal")).unwrap(),
        b"keep sidecar"
    );
    fs::write(f.path("trust/state.json"), b"{}").unwrap();
    assert!(Session::open(&f.path("trust"), clock(), true).is_err());
}
#[test]
fn trusted_catalog_producer_public_signature_ceremony() {
    let f = Fixture::new();
    let raw: Value =
        serde_json::from_slice(&fs::read(f.path("metadata/1.targets.json")).unwrap()).unwrap();
    f.write("signed.json", &raw["signed"]);
    producer::prepare(
        &f.path("signed.json"),
        &f.path("request.json"),
        Some(&f.path("manifest.json")),
        Some(&f.path("bundle.zst")),
    )
    .unwrap();
    let preimage = fs::read(f.path("request.canonical")).unwrap();
    let mut fragments = Vec::new();
    for (i, key) in f.keys["targets"][..2].iter().enumerate() {
        let rawsig = f.path(&format!("sig{i}.bin"));
        fs::write(&rawsig, key.sign(&preimage).to_bytes()).unwrap();
        let out = f.path(&format!("sig{i}.json"));
        let id = digest(&canonical(&Fixture::key(key)).unwrap());
        producer::sign(
            &f.path("request.json"),
            &f.path("metadata/1.root.json"),
            &id,
            &rawsig,
            &out,
        )
        .unwrap();
        fragments.push(out);
    }
    assert!(
        producer::assemble(
            &f.path("request.json"),
            &f.path("metadata/1.root.json"),
            None,
            &fragments[..1],
            &f.path("insufficient.json")
        )
        .is_err()
    );
    producer::assemble(
        &f.path("request.json"),
        &f.path("metadata/1.root.json"),
        None,
        &fragments,
        &f.path("assembled.json"),
    )
    .unwrap();
    assert!(envelope(&fs::read(f.path("assembled.json")).unwrap(), "targets").is_ok());
}

#[test]
fn trusted_catalog_same_role_equivocation_stale_snapshot_and_time_horizons() {
    let f = Fixture::new();
    f.enroll().unwrap();
    let verified = f.verify().unwrap();
    f.release(2, 2);
    f.import(false).unwrap();
    f.release(1, 1);
    assert_eq!(verified.release_sequence, 1);
    assert!(f.install("stale.sqlite3").is_err());
    f.release(2, 2);
    let mut ts: Value =
        serde_json::from_slice(&fs::read(f.path("metadata/timestamp.json")).unwrap()).unwrap();
    ts["signed"]["comment"] = "same version, altered signed content".into();
    ts = f.sign(ts["signed"].clone(), "timestamp");
    f.write("metadata/timestamp.json", &ts);
    assert_eq!(f.verify().unwrap_err().code, "TRUST_EQUIVOCATION");
    ts["signed"]["version"] = 3.into();
    ts["signed"]["expires"] = "2026-09-20T00:00:00Z".into();
    ts = f.sign(ts["signed"].clone(), "timestamp");
    f.write("metadata/timestamp.json", &ts);
    assert_eq!(f.verify().unwrap_err().code, "TRUST_EXPIRY");
    let state = fs::read(f.path("trust/state.json")).unwrap();
    let inspected = f
        .session(false)
        .inspect(
            &f.path("metadata"),
            &f.scope(),
            &f.path("manifest.json"),
            &f.path("bundle.zst"),
        )
        .unwrap();
    assert_eq!(inspected["current_policy_acceptance"], false);
    assert!(!inspected["policy_failures"].as_array().unwrap().is_empty());
    assert!(inspected.get("integrity").is_none());
    assert_eq!(state, fs::read(f.path("trust/state.json")).unwrap());
}

#[test]
fn trusted_catalog_key_parser_and_numeric_exhaustion_boundaries() {
    let f = Fixture::new();
    for kind in [
        "reused",
        "weak",
        "unknown-algorithm",
        "bad-id",
        "duplicate-keys",
        "low-threshold",
    ] {
        let mut root = f.root.clone();
        let id = root["signed"]["roles"]["root"]["keyids"][0]
            .as_str()
            .unwrap()
            .to_owned();
        match kind {
            "reused" => root["signed"]["roles"]["targets"]["keyids"][0] = id.clone().into(),
            "weak" => root["signed"]["keys"][&id]["keyval"]["public"] = "0".repeat(64).into(),
            "unknown-algorithm" => root["signed"]["keys"][&id]["scheme"] = "ed25519ph".into(),
            "bad-id" => {
                let key = root["signed"]["keys"][&id].clone();
                root["signed"]["keys"].as_object_mut().unwrap().remove(&id);
                root["signed"]["keys"]["0".repeat(64)] = key;
            }
            "duplicate-keys" => {
                let other = root["signed"]["roles"]["root"]["keyids"][1]
                    .as_str()
                    .unwrap()
                    .to_owned();
                root["signed"]["keys"][other] = root["signed"]["keys"][id].clone();
            }
            _ => root["signed"]["roles"]["root"]["threshold"] = 1.into(),
        }
        assert!(root_profile(&root).is_err(), "{kind}");
    }
    let mut root = f.root.clone();
    root["signed"]["version"] = json!(4294967296_u64);
    assert!(envelope(&serde_json::to_vec(&root).unwrap(), "root").is_err());
    f.enroll().unwrap();
    f.release(1, MAX_SEQUENCE);
    f.import(false).unwrap();
    assert_eq!(f.state().floors["full"].sequence, MAX_SEQUENCE);
    f.release(2, MAX_SEQUENCE + 1);
    assert!(f.import(false).is_err());
    assert_eq!(f.state().floors["full"].sequence, MAX_SEQUENCE);
}

#[test]
fn trusted_catalog_bounded_root_catchup_never_silently_truncates() {
    let f = Fixture::new();
    f.enroll().unwrap();
    // Explicitly exceed the transition bound: no silent older-root success.
    for version in 2..=130 {
        f.write(
            &format!("metadata/{version}.root.json"),
            &f.make_root(version),
        );
    }
    assert_eq!(f.import(true).unwrap_err().code, "TRUST_FORMAT");
    assert_eq!(f.state().roots.len(), 1);
    fs::remove_file(f.path("metadata/130.root.json")).unwrap();
    f.import(true).unwrap();
    assert_eq!(f.state().roots.len(), 129);
}

#[test]
fn trusted_catalog_multi_profile_floors_are_isolated() {
    let f = Fixture::new();
    enroll(
        &f.path("trust"),
        &f.path("metadata/1.root.json"),
        Enrollment {
            publisher: "synthetic".into(),
            catalog: "advisories".into(),
            channel: "stable".into(),
            profiles: vec!["full".into(), "core".into()],
            minimum_sequence: 0,
            bootstrap_manifest_sha256: None,
            operator: "test".into(),
            authorization_reference: "fixture".into(),
            expected_root_sha256: digest(&fs::read(f.path("metadata/1.root.json")).unwrap()),
            clock: clock(),
        },
    )
    .unwrap();
    f.release(1, 42);
    f.import(false).unwrap();
    let receipt = f.install("before-withdrawal.sqlite3").unwrap();
    let receipt_path = f.path(&format!(
        "trust/receipts/{}.json",
        receipt.transaction_id.unwrap()
    ));
    assert_eq!(
        f.session(false).status(&receipt_path).unwrap()["current_policy_acceptance"],
        true
    );
    let mut core = f.target(1);
    core["custom"]["secureflow"]["profile"] = "core".into();
    let targets=f.sign(json!({"_type":"targets","spec_version":"1.0.0","version":2,"expires":"2026-10-01T00:00:00Z","targets":{"catalogs/advisories/stable/core.manifest.json":core}}),"targets");
    f.publish_targets(2, &targets);
    f.import(false).unwrap();
    let state = f.state();
    assert_eq!(state.floors["full"].sequence, 42);
    assert_eq!(state.floors["core"].sequence, 1);
    assert_eq!(
        f.session(false).status(&receipt_path).unwrap()["current_policy_acceptance"],
        false
    );
    // Import observes publisher-authorized manifest references without asserting
    // their absent payload's profile or integrity. Installation still checks it.
    assert!(
        f.session(false)
            .verify(
                &f.path("metadata"),
                &Scope {
                    profile: "core".into(),
                    ..f.scope()
                },
                &f.path("manifest.json"),
                &f.path("bundle.zst")
            )
            .is_err()
    );
}

#[test]
fn trusted_catalog_public_objects_agree_with_closed_schemas() {
    let f = Fixture::new();
    f.enroll().unwrap();
    let receipt = f.install("schema.sqlite3").unwrap();
    let target = f.target(1)["custom"]["secureflow"].clone();
    let state = serde_json::to_value(f.state()).unwrap();
    for (kind, value) in [
        ("target", target),
        ("policy", state["policy"].clone()),
        ("state", state),
        ("receipt", serde_json::to_value(receipt).unwrap()),
    ] {
        validate_schema(kind, &value).unwrap();
        let mut changed = value.clone();
        changed["unknown"] = true.into();
        assert!(validate_schema(kind, &changed).is_err());
        let mut changed = value.clone();
        changed["contract_version"] = "unsupported-v99".into();
        assert!(validate_schema(kind, &changed).is_err());
    }
    let clock = Clock {
        verification_time: NOW.into(),
        time_source: "operator-attested".into(),
        time_reference: " ".into(),
    };
    assert!(Session::open(&f.path("trust"), clock, true).is_err());
}

#[test]
fn trusted_catalog_crash_child() {
    let Ok(path) = std::env::var("SECUREFLOW_TRUST_TEST_CRASH_PATH") else {
        return;
    };
    let base = PathBuf::from(path);
    let point = std::env::var("SECUREFLOW_TRUST_TEST_CRASH_POINT").unwrap();
    if point == "quota" {
        let limit = libc::rlimit {
            rlim_cur: 512,
            rlim_max: 512,
        };
        // SAFETY: this test-only child sets its own file-size quota; limit is valid.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) }, 0);
    }
    let mut session = Session::open(&base.join("trust"), clock(), true).unwrap();
    let scope = Scope {
        publisher_id: "synthetic".into(),
        catalog_id: "advisories".into(),
        channel: "stable".into(),
        profile: "full".into(),
    };
    let result = session.install_with_checkpoint(
        &base.join("metadata"),
        &scope,
        &base.join("manifest.json"),
        &base.join("bundle.zst"),
        &base.join("crash.sqlite3"),
        |p| {
            if p == point {
                std::process::exit(86);
            }
            Ok(())
        },
    );
    assert!(result.is_err(), "quota child must fail before publishing");
    std::process::exit(87);
}

#[test]
fn trusted_catalog_process_crash_and_file_quota_preserve_committed_state() {
    for point in ["pending-durable", "published", "receipt-durable", "quota"] {
        let f = Fixture::new();
        f.enroll().unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "catalog_trust::acceptance::trusted_catalog_crash_child",
            ])
            .env("SECUREFLOW_TRUST_TEST_CRASH_PATH", f.dir.path())
            .env("SECUREFLOW_TRUST_TEST_CRASH_POINT", point)
            .output()
            .unwrap();
        assert!(!result.status.success(), "child must be interrupted");
        if point != "quota" {
            assert_eq!(
                result.status.code(),
                Some(86),
                "{}",
                String::from_utf8_lossy(&result.stdout)
            );
        }
        drop(f.session(true));
        let state = f.state();
        assert!(state.pending.is_none());
        if ["published", "receipt-durable"].contains(&point) {
            assert_eq!(state.completed.len(), 1);
            assert!(f.path("crash.sqlite3").exists());
        } else {
            assert!(state.completed.is_empty());
            assert!(!f.path("crash.sqlite3").exists());
        }
        if point != "quota" {
            assert_eq!(state.floors["full"].sequence, 1);
        }
    }
}

#[test]
fn trusted_catalog_historical_backdated_clock_never_accepts_or_mutates() {
    let f = Fixture::new();
    f.enroll().unwrap();
    f.import(false).unwrap();
    let before = fs::read(f.path("trust/state.json")).unwrap();
    let old = Clock::capture(
        Some("2026-09-11T12:00:00Z".into()),
        Some("historical test".into()),
    )
    .unwrap();
    assert!(Session::open(&f.path("trust"), old.clone(), false).is_err());
    let report = inspect_historical(
        &f.path("trust"),
        old,
        &f.path("metadata"),
        &f.scope(),
        &f.path("manifest.json"),
        &f.path("bundle.zst"),
    )
    .unwrap();
    assert_eq!(report["current_policy_acceptance"], false);
    assert!(
        report["policy_failures"]
            .to_string()
            .contains("TRUST_CLOCK")
    );
    assert_eq!(before, fs::read(f.path("trust/state.json")).unwrap());
}

#[test]
fn trusted_catalog_bootstrap_manifest_pin_is_independent_and_one_time() {
    for matching in [true, false] {
        let f = Fixture::new();
        f.enroll().unwrap();
        let mut policy = f.state().policy;
        policy.bootstrap_manifest_sha256 = Some(if matching {
            digest(&fs::read(f.path("manifest.json")).unwrap())
        } else {
            "0".repeat(64)
        });
        initialize(&f.path("pinned"), &f.path("metadata/1.root.json"), policy).unwrap();
        let mut session = Session::open(&f.path("pinned"), clock(), true).unwrap();
        let result = session.import(&f.path("metadata"), "synthetic", false);
        if matching {
            result.unwrap();
            // The pin constrains only the first accepted manifest; signed later releases can change bytes.
            let mut bytes = fs::read(f.path("manifest.json")).unwrap();
            bytes.push(b'\n');
            fs::write(f.path("manifest.json"), bytes).unwrap();
            f.release(2, 2);
            session
                .import(&f.path("metadata"), "synthetic", false)
                .unwrap();
        } else {
            assert_eq!(result.unwrap_err().code, "TRUST_BOOTSTRAP");
            assert!(session.state.floors["full"].manifest_sha256.is_none());
        }
    }
}
