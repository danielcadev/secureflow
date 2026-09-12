//! Maintained TUF state machine plus SecureFlow scope and conservative history.
use super::{storage::StoreLock, types::*, wire::*, *};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
use tuf::{
    Database,
    metadata::{
        RawSignedMetadata, RootMetadata, SnapshotMetadata, TargetsMetadata, TimestampMetadata,
    },
    pouf::Pouf1,
};

pub(crate) fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(v).map_err(|e| error("TRUST_STATE", e))
}
fn tuf_error(e: tuf::Error) -> TrustError {
    error("TRUST_SIGNATURE", e)
}
fn evidence(root: &Value, v: &Value, raw: &[u8], role: &str) -> Result<RoleEvidence> {
    Ok(RoleEvidence {
        version: number(&v["signed"], "version", u32::MAX as u64)?,
        raw_sha256: digest(raw),
        signed_sha256: digest(&canonical(&v["signed"])?),
        expires: string(&v["signed"], "expires")?.into(),
        accepted_signer_ids: strict_signers(root, v, role)?,
        threshold: number(&root["signed"]["roles"][role], "threshold", 32)?,
    })
}
pub(crate) fn current_root(state: &State) -> Result<(Value, Database<Pouf1>)> {
    let initial = state
        .roots
        .first()
        .ok_or_else(|| error("TRUST_STATE", "missing root lineage"))?;
    require(
        digest(initial.as_bytes()) == state.policy.initial_root_sha256,
        "TRUST_STATE",
        "initial root digest differs",
    )?;
    let mut root = envelope(initial.as_bytes(), "root")?;
    root_profile(&root)?;
    strict_signers(&root, &root, "root")?;
    require(
        number(&root["signed"], "version", u32::MAX as u64)? == state.policy.minimum_root_version,
        "TRUST_STATE",
        "root floor differs",
    )?;
    let mut db = Database::<Pouf1>::from_trusted_root(
        &RawSignedMetadata::<Pouf1, RootMetadata>::new(initial.as_bytes().to_vec()),
    )
    .map_err(tuf_error)?;
    for bytes in &state.roots[1..] {
        let next = envelope(bytes.as_bytes(), "root")?;
        root_profile(&next)?;
        strict_signers(&root, &next, "root")?;
        strict_signers(&next, &next, "root")?;
        db.update_root(&RawSignedMetadata::new(bytes.as_bytes().to_vec()))
            .map_err(tuf_error)?;
        root = next;
    }
    Ok((root, db))
}
pub(crate) fn load_state(lock: &StoreLock) -> Result<State> {
    let raw = storage::read(&lock.path.join("state.json"), MAX_STATE_BYTES)
        .map_err(|e| error("TRUST_STATE", e))?;
    let v = parse(&raw, MAX_STATE_BYTES)?;
    validate_schema("state", &v)?;
    let state: State = serde_json::from_value(v).map_err(|e| error("TRUST_STATE", e))?;
    state.policy.validate()?;
    require(
        state.contract_version == "secureflow-catalog-trust-state-v1"
            && state.policy_sha256
                == digest(&canonical(
                    &serde_json::to_value(&state.policy).map_err(|e| error("TRUST_STATE", e))?,
                )?)
            && state.generation > 0
            && state.generation <= MAX_SEQUENCE,
        "TRUST_STATE",
        "state contract, generation or policy digest differs",
    )?;
    parse_time(&state.maximum_verification_time)?;
    require(
        state.floors.len() == state.policy.profiles.len(),
        "TRUST_STATE",
        "missing profile floors",
    )?;
    for profile in &state.policy.profiles {
        let floor = state
            .floors
            .get(profile)
            .ok_or_else(|| error("TRUST_STATE", "profile floor missing"))?;
        require(
            floor.sequence >= state.policy.minimum_sequence && floor.sequence <= MAX_SEQUENCE,
            "TRUST_STATE",
            "invalid floor",
        )?;
        if let Some(hash) = &floor.manifest_sha256 {
            hex::<32>(hash)?;
        }
    }
    for (role, record) in &state.roles {
        require(
            ["targets", "snapshot", "timestamp"].contains(&role.as_str()),
            "TRUST_STATE",
            "unknown stored role",
        )?;
        let v = envelope(record.raw.as_bytes(), role)?;
        require(
            record.evidence.raw_sha256 == digest(record.raw.as_bytes())
                && record.evidence.signed_sha256 == digest(&canonical(&v["signed"])?)
                && record.evidence.version == number(&v["signed"], "version", u32::MAX as u64)?,
            "TRUST_STATE",
            "role record corrupted",
        )?;
    }
    current_root(&state)?;
    Ok(state)
}
pub struct Session {
    pub(crate) lock: StoreLock,
    pub(crate) state: State,
    pub(crate) clock: Clock,
    mutating: bool,
    total: usize,
}
impl Session {
    pub(crate) fn historical_snapshot(path: &Path, clock: Clock) -> Result<Self> {
        clock.validate()?;
        let lock = StoreLock::open(path, false)?;
        let state = load_state(&lock)?;
        Ok(Self {
            lock,
            state,
            clock,
            mutating: false,
            total: 0,
        })
    }
    pub(crate) fn mutating(&self) -> bool {
        self.mutating
    }
    pub fn open(path: &Path, clock: Clock, mutating: bool) -> Result<Self> {
        clock.validate()?;
        let lock = StoreLock::open(path, mutating)?;
        let state = load_state(&lock)?;
        require(
            parse_time(&clock.verification_time)? >= parse_time(&state.maximum_verification_time)?,
            "TRUST_CLOCK",
            "verification time below retained floor",
        )?;
        let mut session = Self {
            lock,
            state,
            clock,
            mutating,
            total: 0,
        };
        if mutating {
            session.recover()?;
        }
        Ok(session)
    }
    pub(crate) fn save(&mut self) -> Result<()> {
        if !self.mutating {
            return Ok(());
        }
        self.state.generation = self
            .state
            .generation
            .checked_add(1)
            .filter(|v| *v <= MAX_SEQUENCE)
            .ok_or_else(|| error("TRUST_STATE", "generation exhausted"))?;
        self.state.maximum_verification_time = self.clock.verification_time.clone();
        validate_schema(
            "state",
            &serde_json::to_value(&self.state).map_err(|e| error("TRUST_STATE", e))?,
        )?;
        let bytes = encode(&self.state)?;
        require(
            bytes.len() <= MAX_STATE_BYTES,
            "TRUST_STATE",
            "state capacity exhausted; retain lineage and re-enroll explicitly",
        )?;
        self.lock.replace_state(&bytes)
    }
    pub(crate) fn read_metadata(&mut self, path: &Path, limit: usize) -> Result<Vec<u8>> {
        let bytes = storage::read(path, limit)?;
        self.total += bytes.len();
        require(
            self.total <= 12 * 1024 * 1024,
            "TRUST_FORMAT",
            "total metadata budget exceeded",
        )?;
        Ok(bytes)
    }
    pub(crate) fn expiry(&self, v: &Value, role: &str) -> Result<()> {
        let now = parse_time(&self.clock.verification_time)?;
        let expires = parse_time(string(&v["signed"], "expires")?)?;
        require(
            expires > now,
            "TRUST_EXPIRY",
            "metadata expired at verification time",
        )?;
        let days = *self
            .state
            .policy
            .maximum_horizon_days
            .get(role)
            .ok_or_else(|| error("TRUST_STATE", "missing horizon"))?;
        require(
            (expires - now).num_seconds() <= days as i64 * 86400,
            "TRUST_EXPIRY",
            "expiry exceeds local horizon",
        )
    }
    fn role_floor(&self, role: &str, v: &Value) -> Result<()> {
        if let Some(old) = self.state.roles.get(role) {
            let version = number(&v["signed"], "version", u32::MAX as u64)?;
            require(
                version >= old.evidence.version,
                "TRUST_ROLLBACK",
                "metadata version below retained floor",
            )?;
            if version == old.evidence.version {
                require(
                    digest(&canonical(&v["signed"])?) == old.evidence.signed_sha256,
                    "TRUST_EQUIVOCATION",
                    "same role version with different signed content",
                )?;
            }
            // Keep parent-reference knowledge even when its child never arrived.
            if role == "timestamp" || role == "snapshot" {
                let old_value = envelope(old.raw.as_bytes(), role)?;
                let child = if role == "timestamp" {
                    "snapshot.json"
                } else {
                    "targets.json"
                };
                let old_link = &old_value["signed"]["meta"][child];
                let link = &v["signed"]["meta"][child];
                let ov = number(old_link, "version", u32::MAX as u64)?;
                let nv = number(link, "version", u32::MAX as u64)?;
                require(
                    nv >= ov,
                    "TRUST_ROLLBACK",
                    "parent references an older child",
                )?;
                // Changed envelope bytes at an equal child version are legal, but must
                // still satisfy the new parent hash and the retained signed digest.
            }
        }
        Ok(())
    }
    fn retain_role(&mut self, root: &Value, v: &Value, bytes: Vec<u8>, role: &str) -> Result<()> {
        let ev = evidence(root, v, &bytes, role)?;
        self.state.roles.insert(
            role.into(),
            RoleRecord {
                raw: String::from_utf8(bytes).map_err(|e| error("TRUST_FORMAT", e))?,
                evidence: ev,
            },
        );
        self.save()
    }
    pub fn import_roots(&mut self, dir: &Path) -> Result<Value> {
        storage::checked_path(dir)?;
        let (mut root, mut db) = current_root(&self.state)?;
        let mut current = number(&root["signed"], "version", u32::MAX as u64)?;
        let mut versions = Vec::new();
        let mut entries = 0;
        for entry in std::fs::read_dir(dir).map_err(|e| error("TRUST_FILESYSTEM", e))? {
            entries += 1;
            require(
                entries <= 512,
                "TRUST_FORMAT",
                "metadata directory entry bound",
            )?;
            let entry = entry.map_err(|e| error("TRUST_FILESYSTEM", e))?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| error("TRUST_FORMAT", "metadata filename encoding"))?;
            if let Some(stem) = name.strip_suffix(".root.json") {
                let version = stem.parse::<u64>().map_err(|e| error("TRUST_FORMAT", e))?;
                require(
                    version > 0 && version <= u32::MAX as u64 && stem == version.to_string(),
                    "TRUST_FORMAT",
                    "root version filename alias",
                )?;
                if version > current {
                    versions.push(version);
                } else if version == current {
                    let bytes = self.read_metadata(&dir.join(name), LIMITS[0])?;
                    let seen = envelope(&bytes, "root")?;
                    require(
                        canonical(&seen["signed"])? == canonical(&root["signed"])?,
                        "TRUST_EQUIVOCATION",
                        "retained root version changed",
                    )?;
                }
            }
        }
        versions.sort_unstable();
        require(
            versions.len() <= 128,
            "TRUST_FORMAT",
            "root transition budget exceeded; import explicit bounded batches",
        )?;
        for version in versions {
            require(
                current.checked_add(1) == Some(version),
                "TRUST_ROLLBACK",
                "missing consecutive intermediate root",
            )?;
            let bytes = self.read_metadata(&dir.join(format!("{version}.root.json")), LIMITS[0])?;
            let next = envelope(&bytes, "root")?;
            root_profile(&next)?;
            require(
                number(&next["signed"], "version", u32::MAX as u64)? == version,
                "TRUST_ROLLBACK",
                "root filename/version mismatch",
            )?;
            strict_signers(&root, &next, "root")?;
            strict_signers(&next, &next, "root")?;
            db.update_root(&RawSignedMetadata::new(bytes.clone()))
                .map_err(tuf_error)?;
            self.state
                .roots
                .push(String::from_utf8(bytes).map_err(|e| error("TRUST_FORMAT", e))?);
            self.save()?;
            root = next;
            current = version;
        }
        self.expiry(&root, "root")?;
        Ok(root)
    }
    pub fn import_metadata(
        &mut self,
        dir: &Path,
        root_only: bool,
    ) -> Result<BTreeMap<String, Target>> {
        require(
            parse_time(&self.clock.verification_time)?
                >= parse_time(&self.state.maximum_verification_time)?,
            "TRUST_CLOCK",
            "verification time below retained floor",
        )?;
        let root = self.import_roots(dir)?;
        if root_only {
            return Ok(BTreeMap::new());
        }
        // Rebuild against the current root. Old signatures never authorize new acceptance.
        let (_, mut db) = current_root(&self.state)?;
        let now = parse_time(&self.clock.verification_time)?;
        let timestamp_bytes = self.read_metadata(&dir.join("timestamp.json"), LIMITS[3])?;
        let timestamp = envelope(&timestamp_bytes, "timestamp")?;
        self.expiry(&timestamp, "timestamp")?;
        self.role_floor("timestamp", &timestamp)?;
        let snapshot_link = metadata_link(&timestamp, "snapshot.json")?;
        strict_signers(&root, &timestamp, "timestamp")?;
        db.update_timestamp(
            &now,
            &RawSignedMetadata::<Pouf1, TimestampMetadata>::new(timestamp_bytes.clone()),
        )
        .map_err(tuf_error)?;
        self.retain_role(&root, &timestamp, timestamp_bytes, "timestamp")?;
        let sv = number(snapshot_link, "version", u32::MAX as u64)?;
        let snapshot_bytes =
            self.read_metadata(&dir.join(format!("{sv}.snapshot.json")), LIMITS[2])?;
        check_link(snapshot_link, &snapshot_bytes)?;
        let snapshot = envelope(&snapshot_bytes, "snapshot")?;
        self.expiry(&snapshot, "snapshot")?;
        self.role_floor("snapshot", &snapshot)?;
        let targets_link = metadata_link(&snapshot, "targets.json")?;
        strict_signers(&root, &snapshot, "snapshot")?;
        db.update_snapshot(
            &now,
            &RawSignedMetadata::<Pouf1, SnapshotMetadata>::new(snapshot_bytes.clone()),
        )
        .map_err(tuf_error)?;
        self.retain_role(&root, &snapshot, snapshot_bytes, "snapshot")?;
        let tv = number(targets_link, "version", u32::MAX as u64)?;
        let targets_bytes =
            self.read_metadata(&dir.join(format!("{tv}.targets.json")), LIMITS[1])?;
        check_link(targets_link, &targets_bytes)?;
        let targets = envelope(&targets_bytes, "targets")?;
        self.expiry(&targets, "targets")?;
        self.role_floor("targets", &targets)?;
        strict_signers(&root, &targets, "targets")?;
        db.update_targets(
            &now,
            &RawSignedMetadata::<Pouf1, TargetsMetadata>::new(targets_bytes.clone()),
        )
        .map_err(tuf_error)?;
        let entries = targets["signed"]["targets"]
            .as_object()
            .ok_or_else(|| error("TRUST_FORMAT", "target entries"))?;
        require(
            !entries.is_empty() && entries.len() <= 256,
            "TRUST_FORMAT",
            "target count bound",
        )?;
        let mut accepted = BTreeMap::new();
        for (name, entry) in entries {
            target_link(entry)?;
            closed(&entry["custom"], &["secureflow"])?;
            let target: Target = serde_json::from_value(entry["custom"]["secureflow"].clone())
                .map_err(|e| error("TRUST_SCOPE", e))?;
            target.validate()?;
            self.state.policy.allows(&target.scope())?;
            require(
                *name == target.scope().target(),
                "TRUST_SCOPE",
                "target path does not match signed scope",
            )?;
            let hash = string(&entry["hashes"], "sha256")?;
            let floor = self
                .state
                .floors
                .get(&target.profile)
                .ok_or_else(|| error("TRUST_STATE", "missing floor"))?;
            require(
                target.release_sequence >= floor.sequence,
                "TRUST_ROLLBACK",
                "catalog sequence below retained floor",
            )?;
            if floor.manifest_sha256.is_none()
                && let Some(pin) = &self.state.policy.bootstrap_manifest_sha256
            {
                require(
                    hash == pin,
                    "TRUST_BOOTSTRAP",
                    "first manifest differs from independent enrollment pin",
                )?;
            }
            if target.release_sequence == floor.sequence
                && let Some(previous) = &floor.manifest_sha256
            {
                require(
                    hash == previous,
                    "TRUST_EQUIVOCATION",
                    "same sequence has different manifest",
                )?;
            }
            accepted.insert(target.profile.clone(), target);
        }
        // All extensions must pass before any application floor is advanced.
        for target in accepted.values() {
            let hash = string(&entries[&target.scope().target()]["hashes"], "sha256")?;
            self.state.floors.insert(
                target.profile.clone(),
                Floor {
                    sequence: target.release_sequence,
                    manifest_sha256: Some(hash.into()),
                },
            );
        }
        self.retain_role(&root, &targets, targets_bytes, "targets")?;
        Ok(accepted)
    }
}
fn metadata_link<'a>(v: &'a Value, name: &str) -> Result<&'a Value> {
    closed(&v["signed"]["meta"], &[name])?;
    let link = &v["signed"]["meta"][name];
    number(link, "version", u32::MAX as u64)?;
    target_link(link)?;
    Ok(link)
}
fn target_link(v: &Value) -> Result<()> {
    number(v, "length", 2_097_152)?;
    closed(&v["hashes"], &["sha256"])?;
    hex::<32>(string(&v["hashes"], "sha256")?)?;
    Ok(())
}
pub(crate) fn check_link(v: &Value, bytes: &[u8]) -> Result<()> {
    target_link(v)?;
    if v.get("version").is_some() {
        let child = parse(bytes, 2_097_152)?;
        require(
            number(v, "version", u32::MAX as u64)?
                == number(&child["signed"], "version", u32::MAX as u64)?,
            "TRUST_ROLLBACK",
            "parent/child metadata version mismatch",
        )?;
    }
    require(
        number(v, "length", 2_097_152)? == bytes.len() as u64
            && string(&v["hashes"], "sha256")? == digest(bytes),
        "TRUST_INTEGRITY",
        "exact target/metadata bytes differ from signed parent",
    )
}
