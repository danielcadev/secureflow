use super::{
    consumer::{Session, check_link, current_root, encode},
    types::*,
    wire::*,
    *,
};
use crate::catalog_bundle::{
    self as bundle, CatalogBundleVerificationPolicy, ParsedCatalogBundleManifest,
};
use std::{collections::BTreeMap, path::Path};

fn bundle_error(e: bundle::BundleError) -> TrustError {
    error("TRUST_INTEGRITY", e)
}
impl Session {
    pub(crate) fn recover(&mut self) -> Result<()> {
        if let Some(pending) = self.state.pending.clone() {
            require(
                pending.receipt.database_sha256 == pending.descriptor.database_sha256
                    && pending.receipt.database_bytes == pending.descriptor.database_bytes
                    && pending.receipt.installation == "pending",
                "TRUST_STATE",
                "pending receipt/descriptor conflict",
            )?;
            let output = Path::new(
                pending
                    .receipt
                    .output
                    .as_deref()
                    .ok_or_else(|| error("TRUST_STATE", "pending output missing"))?,
            );
            storage::private_dir(
                output
                    .parent()
                    .ok_or_else(|| error("TRUST_STATE", "pending parent"))?,
            )?;
            match std::fs::symlink_metadata(output) {
                Ok(_) => {
                    // Recovered completion is the old as-of decision, not a new
                    // acceptance under a potentially changed root or clock.
                    storage::checked_path(output)?;
                    bundle::verify_installed_descriptor(output, &pending.descriptor)
                        .map_err(|e| error("TRUST_STATE", e))?;
                    std::fs::File::open(output)
                        .and_then(|f| f.sync_all())
                        .map_err(|e| error("TRUST_FILESYSTEM", e))?;
                    storage::sync_parent(output)?;
                    let mut receipt = pending.receipt;
                    receipt.installation = "complete".into();
                    let id = receipt
                        .transaction_id
                        .clone()
                        .ok_or_else(|| error("TRUST_STATE", "pending transaction missing"))?;
                    self.state.completed.insert(id, receipt);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(error("TRUST_STATE", e)),
            }
            self.state.pending = None;
            self.save()?;
        }
        self.export_receipts()
    }
    fn export_receipts(&self) -> Result<()> {
        let directory = self.lock.path.join("receipts");
        storage::private_dir(&directory)?;
        for (id, receipt) in &self.state.completed {
            hex::<32>(id)?;
            let path = directory.join(format!("{id}.json"));
            let bytes = encode(receipt)?;
            match std::fs::symlink_metadata(&path) {
                Ok(_) => require(
                    storage::read(&path, 262_144)? == bytes,
                    "TRUST_STATE",
                    "receipt file conflicts with committed state",
                )?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    storage::write_new(&path, &bytes)?
                }
                Err(e) => return Err(error("TRUST_STATE", e)),
            }
        }
        Ok(())
    }
    fn authenticate(
        &self,
        scope: &Scope,
        manifest: &Path,
        targets: &BTreeMap<String, Target>,
    ) -> Result<(
        ParsedCatalogBundleManifest,
        Target,
        CatalogBundleVerificationPolicy,
    )> {
        self.state.policy.allows(scope)?;
        let target = targets
            .get(&scope.profile)
            .ok_or_else(|| error("TRUST_SCOPE", "selected profile absent"))?
            .clone();
        require(
            target.scope() == *scope,
            "TRUST_SCOPE",
            "selected scope mismatch",
        )?;
        let raw = storage::read(manifest, bundle::MAX_BUNDLE_MANIFEST_BYTES as usize)?;
        parse(&raw, bundle::MAX_BUNDLE_MANIFEST_BYTES as usize)?;
        let role = self
            .state
            .roles
            .get("targets")
            .ok_or_else(|| error("TRUST_STATE", "targets missing"))?;
        let v = envelope(role.raw.as_bytes(), "targets")?;
        check_link(&v["signed"]["targets"][scope.target()], &raw)?;
        let parsed = bundle::parse_manifest(&raw).map_err(bundle_error)?;
        require(
            parsed.manifest.bundle_id == target.bundle_id
                && parsed.manifest.profile.to_string() == target.profile
                && parsed.manifest.profile_policy_version == target.profile_policy_version
                && parsed.manifest.contract_version == target.manifest_contract_version
                && parsed.manifest.validation_authority == target.validation_authority,
            "TRUST_SCOPE",
            "signed extension differs from manifest",
        )?;
        let policy = CatalogBundleVerificationPolicy {
            required_profile: Some(parsed.manifest.profile),
            expected_manifest_sha256: Some(parsed.manifest_sha256.clone()),
            ..Default::default()
        };
        Ok((parsed, target, policy))
    }
    fn receipt(&self, target: &Target, parsed: &ParsedCatalogBundleManifest) -> Result<Receipt> {
        let targets = self
            .state
            .roles
            .get("targets")
            .ok_or_else(|| error("TRUST_STATE", "targets missing"))?;
        let targets = envelope(targets.raw.as_bytes(), "targets")?;
        let manifest_bytes = number(
            &targets["signed"]["targets"][target.scope().target()],
            "length",
            bundle::MAX_BUNDLE_MANIFEST_BYTES,
        )?;
        let (root, _) = current_root(&self.state)?;
        let mut roles: BTreeMap<String, RoleEvidence> = self
            .state
            .roles
            .iter()
            .map(|(k, v)| (k.clone(), v.evidence.clone()))
            .collect();
        let raw = self
            .state
            .roots
            .last()
            .ok_or_else(|| error("TRUST_STATE", "missing root"))?;
        roles.insert(
            "root".into(),
            RoleEvidence {
                version: number(&root["signed"], "version", u32::MAX as u64)?,
                raw_sha256: digest(raw.as_bytes()),
                signed_sha256: digest(&canonical(&root["signed"])?),
                expires: string(&root["signed"], "expires")?.into(),
                accepted_signer_ids: strict_signers(&root, &root, "root")?,
                threshold: number(&root["signed"]["roles"]["root"], "threshold", 32)?,
            },
        );
        let expiry = roles
            .values()
            .map(|r| r.expires.clone())
            .min()
            .ok_or_else(|| error("TRUST_STATE", "missing expiry"))?;
        Ok(Receipt{contract_version:"secureflow-catalog-trust-receipt-v1".into(),operation:"verify".into(),installation:"not-requested".into(),transaction_id:None,output:None,integrity:"verified".into(),publisher_authenticity:"tuf-root-authorized".into(),freshness:"within-local-policy-as-of".into(),rollback:"accepted-against-local-state".into(),scope:target.scope(),release_sequence:target.release_sequence,initial_root_sha256:self.state.policy.initial_root_sha256.clone(),current_root_sha256:digest(raw.as_bytes()),metadata:roles,manifest_sha256:parsed.manifest_sha256.clone(),manifest_bytes,database_sha256:parsed.manifest.payload.database_sha256.clone(),database_bytes:parsed.manifest.payload.database_bytes,policy_sha256:self.state.policy_sha256.clone(),clock:self.clock.clone(),earliest_expiry:expiry,state_generation:self.state.generation,reserves_acceptance:false,validation_authority:"human-only".into(),limitations:vec!["Offline acceptance cannot establish globally latest metadata or withheld revocations.".into(),"Signatures authenticate distributor authorization of bytes, not advisory truth, upstream identity, license rights, vulnerability validity or safe remediation.".into(),"Local state and clock are operator-trusted; full-machine rollback is outside this assurance.".into(),"Installed catalog queries do not enforce freshness; this receipt is an as-of statement.".into()]})
    }
    pub fn verify(
        &mut self,
        dir: &Path,
        scope: &Scope,
        manifest: &Path,
        payload: &Path,
    ) -> Result<Receipt> {
        require(
            !self.mutating(),
            "TRUST_STATE",
            "verify requires a read-only snapshot",
        )?;
        self.state.policy.allows(scope)?;
        let targets = self.import_metadata(dir, false)?;
        let (parsed, target, policy) = self.authenticate(scope, manifest, &targets)?;
        storage::checked_path(payload)?;
        bundle::verify_trusted_bundle(payload, storage::open_regular(payload)?, &parsed, &policy)
            .map_err(bundle_error)?;
        self.receipt(&target, &parsed)
    }
    pub fn install(
        &mut self,
        dir: &Path,
        scope: &Scope,
        manifest: &Path,
        payload: &Path,
        output: &Path,
    ) -> Result<Receipt> {
        self.install_with_checkpoint(dir, scope, manifest, payload, output, |_| Ok(()))
    }
    pub(crate) fn install_with_checkpoint(
        &mut self,
        dir: &Path,
        scope: &Scope,
        manifest: &Path,
        payload: &Path,
        output: &Path,
        mut checkpoint: impl FnMut(&str) -> Result<()>,
    ) -> Result<Receipt> {
        require(
            self.mutating(),
            "TRUST_STATE",
            "installation requires exclusive mutation lock",
        )?;
        self.state.policy.allows(scope)?;
        storage::private_dir(
            output
                .parent()
                .ok_or_else(|| error("TRUST_FILESYSTEM", "output parent required"))?,
        )?;
        require(
            output.file_name().is_some()
                && output.is_absolute()
                && !output.starts_with(&self.lock.path),
            "TRUST_FILESYSTEM",
            "output must be outside trust store",
        )?;
        let targets = self.import_metadata(dir, false)?;
        let (parsed, target, policy) = self.authenticate(scope, manifest, &targets)?;
        storage::checked_path(payload)?;
        let prepared = bundle::prepare_trusted_install(
            storage::open_regular(payload)?,
            payload,
            &parsed,
            output,
            &policy,
        )
        .map_err(bundle_error)?;
        checkpoint("verified")?;
        let mut receipt = self.receipt(&target, &parsed)?;
        receipt.operation = "install".into();
        receipt.installation = "pending".into();
        receipt.output = Some(output.to_string_lossy().into());
        receipt.reserves_acceptance = true;
        receipt.state_generation = self
            .state
            .generation
            .checked_add(1)
            .filter(|v| *v <= MAX_SEQUENCE)
            .ok_or_else(|| error("TRUST_STATE", "generation exhausted"))?;
        receipt.transaction_id = Some(digest(&encode(&receipt)?));
        self.state.pending = Some(Pending {
            receipt: receipt.clone(),
            descriptor: parsed.manifest.payload.clone(),
        });
        self.save()?;
        checkpoint("pending-durable")?;
        self.lock.check_identity()?;
        prepared.publish(output).map_err(bundle_error)?;
        checkpoint("published")?;
        receipt.installation = "complete".into();
        self.state.completed.insert(
            receipt
                .transaction_id
                .clone()
                .ok_or_else(|| error("TRUST_STATE", "transaction missing"))?,
            receipt.clone(),
        );
        self.state.pending = None;
        self.save()?;
        checkpoint("receipt-durable")?;
        self.export_receipts()?;
        Ok(receipt)
    }
}
