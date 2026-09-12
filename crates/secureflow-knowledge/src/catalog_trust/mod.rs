//! Offline publisher authentication. This does not validate advisory assertions.
#[cfg(all(test, target_os = "linux"))]
mod acceptance;
mod consumer;
mod install;
pub mod producer;
mod storage;
mod types;
mod wire;
pub use consumer::Session;
pub use types::{Clock, Policy, Receipt, Scope, Target};
pub const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;

use thiserror::Error;

#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct TrustError {
    pub code: &'static str,
    pub message: String,
}
pub type Result<T> = std::result::Result<T, TrustError>;
pub(crate) fn error(code: &'static str, message: impl ToString) -> TrustError {
    TrustError {
        code,
        message: message.to_string(),
    }
}
pub(crate) fn require(ok: bool, code: &'static str, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error(code, message))
    }
}

pub(crate) fn parse_time(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    require(
        s.len() == 20 && s.as_bytes()[10] == b'T' && s.ends_with('Z'),
        "TRUST_CLOCK",
        "whole-second UTC required",
    )?;
    let t = chrono::DateTime::parse_from_rfc3339(s).map_err(|e| error("TRUST_CLOCK", e))?;
    require(
        t.timestamp_subsec_nanos() == 0 && t.offset().local_minus_utc() == 0,
        "TRUST_CLOCK",
        "invalid UTC time",
    )?;
    Ok(t.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tuf::{
        Database,
        metadata::{
            RawSignedMetadata, RootMetadata, SnapshotMetadata, TargetsMetadata, TimestampMetadata,
        },
        pouf::Pouf1,
    };
    #[test]
    fn trusted_catalog_independent_openssl_chain() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/trusted-catalog");
        let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
        let root = read("1.root.json");
        let parsed = wire::envelope(&root, "root").unwrap();
        wire::root_profile(&parsed).unwrap();
        wire::strict_signers(&parsed, &parsed, "root").unwrap();
        let mut db = Database::<Pouf1>::from_trusted_root(
            &RawSignedMetadata::<Pouf1, RootMetadata>::new(root),
        )
        .unwrap();
        let now = parse_time("2026-09-12T12:00:00Z").unwrap();
        db.update_timestamp(
            &now,
            &RawSignedMetadata::<Pouf1, TimestampMetadata>::new(read("timestamp.json")),
        )
        .unwrap();
        db.update_snapshot(
            &now,
            &RawSignedMetadata::<Pouf1, SnapshotMetadata>::new(read("1.snapshot.json")),
        )
        .unwrap();
        db.update_targets(
            &now,
            &RawSignedMetadata::<Pouf1, TargetsMetadata>::new(read("1.targets.json")),
        )
        .unwrap();
        for (role, name) in [
            ("targets", "1.targets.json"),
            ("snapshot", "1.snapshot.json"),
            ("timestamp", "timestamp.json"),
        ] {
            let bytes = read(name);
            let v = wire::envelope(&bytes, role).unwrap();
            wire::strict_signers(&parsed, &v, role).unwrap();
            assert_eq!(
                wire::canonical(&v["signed"]).unwrap(),
                read(&format!("{role}.canonical"))
            );
        }
    }
    #[test]
    fn trusted_catalog_strict_json_boundaries() {
        for bytes in [
            b"{\"x\":1,\"x\":2}".as_slice(),
            b"{\"x\":{\"a\":1,\"a\":1}}",
            b"1.0",
            b"1e0",
            b"9007199254740992",
            b"\xef\xbb\xbf{}",
            b"{} {}",
            br#""\ud800""#,
        ] {
            assert!(wire::parse(bytes, 1000).is_err(), "{:?}", bytes);
        }
        assert!(
            wire::parse(
                &format!("{}0{}", "[".repeat(34), "]".repeat(34)).into_bytes(),
                1000
            )
            .is_err()
        );
        assert!(wire::parse(b"{}", 1).is_err());
        let a = wire::canonical(&serde_json::json!({"name":"e\u{301}"})).unwrap();
        let b = wire::canonical(&serde_json::json!({"name":"é"})).unwrap();
        assert_ne!(a, b);
    }
}

/// Enroll one independently authenticated publisher root. Never overwrites a store.
pub fn initialize(
    store: &std::path::Path,
    root_path: &std::path::Path,
    policy: Policy,
) -> Result<serde_json::Value> {
    policy.validate()?;
    let bytes = storage::read(root_path, wire::LIMITS[0])?;
    require(
        wire::digest(&bytes) == policy.initial_root_sha256,
        "TRUST_BOOTSTRAP",
        "root differs from independently authenticated SHA-256",
    )?;
    let root = wire::envelope(&bytes, "root")?;
    wire::root_profile(&root)?;
    wire::strict_signers(&root, &root, "root")?;
    require(
        wire::number(&root["signed"], "version", u32::MAX as u64)? == policy.minimum_root_version,
        "TRUST_BOOTSTRAP",
        "root version differs from enrollment floor",
    )?;
    let now = parse_time(&policy.enrolled_at.verification_time)?;
    let expires = parse_time(wire::string(&root["signed"], "expires")?)?;
    require(
        expires > now && (expires - now).num_seconds() <= 366 * 86400,
        "TRUST_EXPIRY",
        "bootstrap root expiry outside policy",
    )?;
    let floors = policy
        .profiles
        .iter()
        .map(|p| {
            (
                p.clone(),
                types::Floor {
                    sequence: policy.minimum_sequence,
                    manifest_sha256: None,
                },
            )
        })
        .collect();
    let state = types::State {
        contract_version: "secureflow-catalog-trust-state-v1".into(),
        policy_sha256: wire::digest(&wire::canonical(
            &serde_json::to_value(&policy).map_err(|e| error("TRUST_STATE", e))?,
        )?),
        maximum_verification_time: policy.enrolled_at.verification_time.clone(),
        policy,
        roots: vec![String::from_utf8(bytes).map_err(|e| error("TRUST_FORMAT", e))?],
        roles: Default::default(),
        floors,
        generation: 1,
        pending: None,
        completed: Default::default(),
    };
    consumer::current_root(&state)?;
    storage::create_dir(store)?;
    storage::write_new(&store.join("lock"), b"")?;
    storage::create_dir(&store.join("receipts"))?;
    storage::write_new(&store.join("state.json"), &consumer::encode(&state)?)?;
    Ok(
        serde_json::json!({"operation":"trust-init","policy":state.policy,"policy_sha256":state.policy_sha256,"generation":1,"catalog_acceptance":"unavailable-until-complete-metadata-import","validation_authority":"human-only"}),
    )
}

/// Construct the fixed initial operating profile; no publisher may rewrite it.
#[derive(Debug)]
pub struct Enrollment {
    pub publisher: String,
    pub catalog: String,
    pub channel: String,
    pub profiles: Vec<String>,
    pub minimum_sequence: u64,
    pub bootstrap_manifest_sha256: Option<String>,
    pub operator: String,
    pub authorization_reference: String,
    pub expected_root_sha256: String,
    pub clock: Clock,
}
pub fn enroll(
    store: &std::path::Path,
    root: &std::path::Path,
    args: Enrollment,
) -> Result<serde_json::Value> {
    let bytes = storage::read(root, wire::LIMITS[0])?;
    // Check the independently supplied pin before deriving any policy from root bytes.
    require(
        wire::digest(&bytes) == args.expected_root_sha256,
        "TRUST_BOOTSTRAP",
        "root fingerprint mismatch",
    )?;
    let parsed = wire::envelope(&bytes, "root")?;
    let policy = Policy {
        contract_version: "secureflow-catalog-trust-policy-v1".into(),
        publisher_label: args.publisher.clone(),
        publisher_id: args.publisher,
        catalog_id: args.catalog,
        channel: args.channel,
        profiles: args.profiles,
        initial_root_sha256: args.expected_root_sha256,
        minimum_root_version: wire::number(&parsed["signed"], "version", u32::MAX as u64)?,
        minimum_sequence: args.minimum_sequence,
        bootstrap_manifest_sha256: args.bootstrap_manifest_sha256,
        minimum_thresholds: types::thresholds(),
        maximum_horizon_days: types::horizons(),
        operator: args.operator,
        authorization_reference: args.authorization_reference,
        enrolled_at: args.clock,
    };
    initialize(store, root, policy)
}

impl Session {
    pub fn import(
        &mut self,
        dir: &std::path::Path,
        publisher: &str,
        root_only: bool,
    ) -> Result<serde_json::Value> {
        require(
            self.mutating(),
            "TRUST_STATE",
            "import requires mutation lock",
        )?;
        require(
            self.state.policy.publisher_id == publisher,
            "TRUST_SCOPE",
            "publisher differs from enrollment",
        )?;
        let (before, _) = consumer::current_root(&self.state)?;
        let old_hash = wire::digest(
            self.state
                .roots
                .last()
                .ok_or_else(|| error("TRUST_STATE", "root missing"))?
                .as_bytes(),
        );
        let targets = self.import_metadata(dir, root_only)?;
        self.save()?;
        let (after, _) = consumer::current_root(&self.state)?;
        Ok(
            serde_json::json!({"operation":"trust-import","operator":self.state.policy.operator,"authorization_reference":self.state.policy.authorization_reference,"scope":{"publisher":publisher,"catalog":self.state.policy.catalog_id,"channel":self.state.policy.channel,"profiles":self.state.policy.profiles},"previous_root_sha256":old_hash,"current_root_sha256":wire::digest(self.state.roots.last().unwrap().as_bytes()),"previous_root":before["signed"],"current_root":after["signed"],"revocation_effect":"all metadata revalidated under current role keys; withheld root updates remain unknowable","catalog_acceptance":if root_only{"unavailable-root-only-import"}else{"metadata-authorized-payload-not-checked"},"targets":targets,"floors":self.state.floors,"generation":self.state.generation,"clock":self.clock,"validation_authority":"human-only"}),
        )
    }
    /// Re-evaluate a local installation receipt, retaining its original as-of evidence.
    pub fn status(&self, receipt_path: &std::path::Path) -> Result<serde_json::Value> {
        let bytes = storage::read(receipt_path, 262_144)?;
        let receipt: Receipt = serde_json::from_value(wire::parse(&bytes, 262_144)?)
            .map_err(|e| error("TRUST_STATE", e))?;
        let id = receipt
            .transaction_id
            .as_ref()
            .ok_or_else(|| error("TRUST_STATE", "installation receipt required"))?;
        require(
            self.state.completed.get(id) == Some(&receipt),
            "TRUST_STATE",
            "receipt is not a completed operation in this lineage",
        )?;
        let (root, mut database) = consumer::current_root(&self.state)?;
        let mut failures = Vec::new();
        if let Err(e) = self.expiry(&root, "root") {
            failures.push(e.to_string());
        }
        let now = parse_time(&self.clock.verification_time)?;
        if self.state.pending.is_some() {
            failures.push("TRUST_STATE: pending installation requires recovery".into());
        }
        for role in ["timestamp", "snapshot", "targets"] {
            match self.state.roles.get(role) {
                Some(record) => {
                    let v = wire::envelope(record.raw.as_bytes(), role)?;
                    use tuf::metadata::{
                        RawSignedMetadata, SnapshotMetadata, TargetsMetadata, TimestampMetadata,
                    };
                    use tuf::pouf::Pouf1;
                    let raw = record.raw.as_bytes().to_vec();
                    let result = match role {
                        "timestamp" => database
                            .update_timestamp(
                                &now,
                                &RawSignedMetadata::<Pouf1, TimestampMetadata>::new(raw),
                            )
                            .map(|_| ()),
                        "snapshot" => database
                            .update_snapshot(
                                &now,
                                &RawSignedMetadata::<Pouf1, SnapshotMetadata>::new(raw),
                            )
                            .map(|_| ()),
                        _ => database
                            .update_targets(
                                &now,
                                &RawSignedMetadata::<Pouf1, TargetsMetadata>::new(raw),
                            )
                            .map(|_| ()),
                    };
                    if let Err(e) = result {
                        failures.push(format!("TRUST_SIGNATURE: {e}"));
                    }
                    if role == "targets" {
                        let entry = &v["signed"]["targets"][receipt.scope.target()];
                        let extension: std::result::Result<Target, _> =
                            serde_json::from_value(entry["custom"]["secureflow"].clone());
                        let matches = extension.is_ok_and(|t| {
                            t.validate().is_ok()
                                && t.scope() == receipt.scope
                                && t.release_sequence == receipt.release_sequence
                        }) && entry["hashes"]["sha256"] == receipt.manifest_sha256
                            && entry["length"] == receipt.manifest_bytes;
                        if !matches {
                            failures.push(
                                "TRUST_SCOPE: receipt target absent or changed in current metadata"
                                    .into(),
                            );
                        }
                    }
                    if let Err(e) = wire::strict_signers(&root, &v, role) {
                        failures.push(e.to_string());
                    }
                    if let Err(e) = self.expiry(&v, role) {
                        failures.push(e.to_string());
                    }
                }
                None => failures.push(format!("TRUST_STATE: {role} unavailable")),
            }
        }
        let floor = self
            .state
            .floors
            .get(&receipt.scope.profile)
            .ok_or_else(|| error("TRUST_STATE", "profile floor missing"))?;
        if floor.sequence != receipt.release_sequence
            || floor.manifest_sha256.as_ref() != Some(&receipt.manifest_sha256)
        {
            failures.push("TRUST_ROLLBACK: receipt differs from current observed release".into());
        }
        // Recheck the current retained parent bindings; partial imports must not
        // make a mixture of individually signed roles look acceptable.
        if let (Some(ts), Some(sn), Some(tg)) = (
            self.state.roles.get("timestamp"),
            self.state.roles.get("snapshot"),
            self.state.roles.get("targets"),
        ) {
            let t = wire::envelope(ts.raw.as_bytes(), "timestamp")?;
            let s = wire::envelope(sn.raw.as_bytes(), "snapshot")?;
            if let Err(e) =
                consumer::check_link(&t["signed"]["meta"]["snapshot.json"], sn.raw.as_bytes())
            {
                failures.push(e.to_string());
            }
            if let Err(e) =
                consumer::check_link(&s["signed"]["meta"]["targets.json"], tg.raw.as_bytes())
            {
                failures.push(e.to_string());
            }
        }
        Ok(
            serde_json::json!({"operation":"trust-status","current_policy_acceptance":failures.is_empty(),"policy_failures":failures,"receipt":receipt,"evaluated_at":self.clock,"generation":self.state.generation,"checks_installed_bytes":false,"validation_authority":"human-only"}),
        )
    }
}

pub fn schema(kind: &str) -> Result<&'static str> {
    Ok(match kind {
        "target" => include_str!("../../../../schemas/secureflow-catalog-target-v1.schema.json"),
        "policy" => {
            include_str!("../../../../schemas/secureflow-catalog-trust-policy-v1.schema.json")
        }
        "state" => {
            include_str!("../../../../schemas/secureflow-catalog-trust-state-v1.schema.json")
        }
        "receipt" => {
            include_str!("../../../../schemas/secureflow-catalog-trust-receipt-v1.schema.json")
        }
        _ => return Err(error("TRUST_FORMAT", "unknown schema")),
    })
}
pub(crate) fn validate_schema(kind: &str, value: &serde_json::Value) -> Result<()> {
    static VALIDATORS: std::sync::OnceLock<
        std::collections::BTreeMap<&'static str, jsonschema::Validator>,
    > = std::sync::OnceLock::new();
    let validators = VALIDATORS.get_or_init(|| {
        ["target", "policy", "state", "receipt"]
            .into_iter()
            .map(|k| {
                let schema: serde_json::Value =
                    serde_json::from_str(schema(k).expect("embedded schema"))
                        .expect("embedded schema JSON");
                (
                    k,
                    jsonschema::options()
                        .should_validate_formats(true)
                        .build(&schema)
                        .expect("embedded closed schema"),
                )
            })
            .collect()
    });
    let validator = validators
        .get(kind)
        .ok_or_else(|| error("TRUST_FORMAT", "unknown schema"))?;
    validator
        .validate(value)
        .map_err(|e| error("TRUST_FORMAT", e))
}

/// Historical inspection can report a backdated clock failure without accepting it.
pub fn inspect_historical(
    store: &std::path::Path,
    clock: Clock,
    dir: &std::path::Path,
    scope: &Scope,
    manifest: &std::path::Path,
    payload: &std::path::Path,
) -> Result<serde_json::Value> {
    Session::historical_snapshot(store, clock)?.inspect(dir, scope, manifest, payload)
}

impl Session {
    pub fn inspect(
        &mut self,
        dir: &std::path::Path,
        scope: &Scope,
        manifest: &std::path::Path,
        payload: &std::path::Path,
    ) -> Result<serde_json::Value> {
        use tuf::{
            metadata::{
                MetadataPath, RawSignedMetadata, SnapshotMetadata, TargetsMetadata,
                TimestampMetadata,
            },
            pouf::Pouf1,
            verify::verify_signatures,
        };
        require(
            !self.mutating(),
            "TRUST_STATE",
            "historical inspection requires read-only snapshot",
        )?;
        let policy_result = self.verify(dir, scope, manifest, payload);
        let (root, database) = consumer::current_root(&self.state)?;
        let mut evidence = Vec::new();
        let cryptographic_result = (|| -> Result<()> {
            let timestamp = self.read_metadata(&dir.join("timestamp.json"), wire::LIMITS[3])?;
            let ts = wire::envelope(&timestamp, "timestamp")?;
            let sv = wire::number(
                &ts["signed"]["meta"]["snapshot.json"],
                "version",
                u32::MAX as u64,
            )?;
            let snapshot =
                self.read_metadata(&dir.join(format!("{sv}.snapshot.json")), wire::LIMITS[2])?;
            let sn = wire::envelope(&snapshot, "snapshot")?;
            let tv = wire::number(
                &sn["signed"]["meta"]["targets.json"],
                "version",
                u32::MAX as u64,
            )?;
            let targets =
                self.read_metadata(&dir.join(format!("{tv}.targets.json")), wire::LIMITS[1])?;
            for (role, raw) in [
                ("timestamp", &timestamp),
                ("snapshot", &snapshot),
                ("targets", &targets),
            ] {
                let v = wire::envelope(raw, role)?;
                let threshold =
                    wire::number(&root["signed"]["roles"][role], "threshold", 32)? as u32;
                let key_root = database.trusted_root();
                let maintained = match role {
                    "timestamp" => verify_signatures(
                        &MetadataPath::timestamp(),
                        &RawSignedMetadata::<Pouf1, TimestampMetadata>::new(raw.clone()),
                        threshold,
                        key_root.timestamp_keys(),
                    )
                    .map(|_| ()),
                    "snapshot" => verify_signatures(
                        &MetadataPath::snapshot(),
                        &RawSignedMetadata::<Pouf1, SnapshotMetadata>::new(raw.clone()),
                        threshold,
                        key_root.snapshot_keys(),
                    )
                    .map(|_| ()),
                    _ => verify_signatures(
                        &MetadataPath::targets(),
                        &RawSignedMetadata::<Pouf1, TargetsMetadata>::new(raw.clone()),
                        threshold,
                        key_root.targets_keys(),
                    )
                    .map(|_| ()),
                };
                let signatures = maintained
                    .map_err(|e| error("TRUST_SIGNATURE", e))
                    .and_then(|()| wire::strict_signers(&root, &v, role));
                evidence.push(serde_json::json!({"role":role,"origin":"requested-local-metadata","raw_sha256":wire::digest(raw),"version":wire::number(&v["signed"],"version",u32::MAX as u64)?,"signature_result":match signatures {Ok(ids)=>serde_json::json!({"accepted_signer_ids":ids}),Err(e)=>serde_json::json!({"error_code":e.code,"error":e.message})}}));
            }
            consumer::check_link(&ts["signed"]["meta"]["snapshot.json"], &snapshot)?;
            consumer::check_link(&sn["signed"]["meta"]["targets.json"], &targets)?;
            Ok(())
        })();
        Ok(
            serde_json::json!({"operation":"inspect","historical":true,"current_policy_acceptance":false,"reserves_acceptance":false,"evidence":evidence,"metadata_chain_errors":match cryptographic_result {Ok(())=>Vec::<String>::new(),Err(e)=>vec![e.to_string()]},"policy_check_passed":policy_result.is_ok(),"policy_failures":match policy_result {Ok(_)=>Vec::<String>::new(),Err(e)=>vec![e.to_string()]},"clock":self.clock,"validation_authority":"human-only"}),
        )
    }
}
