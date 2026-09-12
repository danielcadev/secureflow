//! Public-data-only local signing ceremony. Private keys stay with custodians.
use super::{consumer::check_link, wire::*, *};
use crate::catalog_bundle as bundle;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Value, json};
use std::path::Path;

pub fn prepare(
    signed_input: &Path,
    output: &Path,
    manifest: Option<&Path>,
    payload: Option<&Path>,
) -> Result<Value> {
    let bytes = storage::read(signed_input, LIMITS[1])?;
    let signed = parse(&bytes, LIMITS[1])?;
    let role = string(&signed, "_type")?;
    let request = json!({"signed":signed,"signatures":[]});
    let encoded = consumer::encode(&request)?;
    let value = envelope(&encoded, role)?;
    if role == "root" {
        root_profile(&value)?;
    }
    if role == "targets" {
        let manifest = manifest.ok_or_else(|| {
            error(
                "TRUST_INTEGRITY",
                "targets preparation requires manifest and bundle",
            )
        })?;
        let payload = payload
            .ok_or_else(|| error("TRUST_INTEGRITY", "targets preparation requires bundle"))?;
        let raw = storage::read(manifest, bundle::MAX_BUNDLE_MANIFEST_BYTES as usize)?;
        parse(&raw, bundle::MAX_BUNDLE_MANIFEST_BYTES as usize)?;
        let parsed = bundle::parse_manifest(&raw).map_err(|e| error("TRUST_INTEGRITY", e))?;
        let entries = value["signed"]["targets"]
            .as_object()
            .ok_or_else(|| error("TRUST_SCOPE", "targets object"))?;
        require(
            entries.len() == 1,
            "TRUST_SCOPE",
            "producer prepare freezes one bundle per request",
        )?;
        let (name, entry) = entries
            .iter()
            .next()
            .ok_or_else(|| error("TRUST_SCOPE", "target missing"))?;
        let target: Target = serde_json::from_value(entry["custom"]["secureflow"].clone())
            .map_err(|e| error("TRUST_SCOPE", e))?;
        target.validate()?;
        closed(&entry["custom"], &["secureflow"])?;
        check_link(entry, &raw)?;
        require(
            *name == target.scope().target()
                && target.bundle_id == parsed.manifest.bundle_id
                && target.profile == parsed.manifest.profile.to_string(),
            "TRUST_SCOPE",
            "target/manifest scope mismatch",
        )?;
        let policy = bundle::CatalogBundleVerificationPolicy {
            required_profile: Some(parsed.manifest.profile),
            expected_manifest_sha256: Some(parsed.manifest_sha256),
            ..Default::default()
        };
        bundle::verify_trusted_bundle(
            payload,
            storage::open_regular(payload)?,
            &bundle::parse_manifest(&raw).map_err(|e| error("TRUST_INTEGRITY", e))?,
            &policy,
        )
        .map_err(|e| error("TRUST_INTEGRITY", e))?;
    }
    storage::write_new(output, &encoded)?;
    let canonical_path = output.with_extension("canonical");
    storage::write_new(&canonical_path, &canonical(&value["signed"])?)?;
    Ok(
        json!({"operation":"prepare","role":role,"request":output,"canonical_preimage":canonical_path,"preimage_sha256":digest(&canonical(&value["signed"])?),"signed":value["signed"],"approval":"independent-custodian-signatures-required","validation_authority":"human-only"}),
    )
}
/// Validate and wrap a public detached signature made by a custodian's offline signer.
pub fn sign(
    request: &Path,
    root_path: &Path,
    key_id: &str,
    signature: &Path,
    output: &Path,
) -> Result<Value> {
    let root = envelope(&storage::read(root_path, LIMITS[0])?, "root")?;
    root_profile(&root)?;
    let bytes = storage::read(request, LIMITS[1])?;
    let raw = parse(&bytes, LIMITS[1])?;
    let role = string(&raw["signed"], "_type")?;
    let value = envelope(&bytes, role)?;
    hex::<32>(key_id)?;
    let ids = root["signed"]["roles"][role]["keyids"]
        .as_array()
        .ok_or_else(|| error("TRUST_SIGNATURE", "unknown signing role"))?;
    require(
        ids.iter().any(|v| v == key_id),
        "TRUST_SIGNATURE",
        "key not authorized for requested role",
    )?;
    let sig = storage::read(signature, 64)?;
    let sig = Signature::from_slice(&sig).map_err(|e| error("TRUST_SIGNATURE", e))?;
    let pk = VerifyingKey::from_bytes(&hex::<32>(string(
        &root["signed"]["keys"][key_id]["keyval"],
        "public",
    )?)?)
    .map_err(|e| error("TRUST_SIGNATURE", e))?;
    pk.verify_strict(&canonical(&value["signed"])?, &sig)
        .map_err(|e| error("TRUST_SIGNATURE", e))?;
    let fragment = json!({"keyid":key_id,"sig":sig.to_bytes().iter().map(|b|format!("{b:02x}")).collect::<String>()});
    storage::write_new(output, &consumer::encode(&fragment)?)?;
    Ok(
        json!({"operation":"sign","keyid":key_id,"preimage_sha256":digest(&canonical(&value["signed"])?),"signature_file":output,"private_key_handling":"external-custodian-only"}),
    )
}
pub fn assemble(
    request: &Path,
    root_path: &Path,
    previous_root: Option<&Path>,
    signatures: &[std::path::PathBuf],
    output: &Path,
) -> Result<Value> {
    require(
        signatures.len() <= 32,
        "TRUST_FORMAT",
        "signature count bound",
    )?;
    let root_bytes = storage::read(root_path, LIMITS[0])?;
    let root = envelope(&root_bytes, "root")?;
    root_profile(&root)?;
    let raw = storage::read(request, LIMITS[1])?;
    let mut v = parse(&raw, LIMITS[1])?;
    let role = string(&v["signed"], "_type")?.to_owned();
    require(
        v["signatures"].as_array().is_some_and(|a| a.is_empty()),
        "TRUST_SIGNATURE",
        "immutable unsigned request required",
    )?;
    let mut sigs = Vec::new();
    for path in signatures {
        sigs.push(parse(&storage::read(path, 1024)?, 1024)?);
    }
    v["signatures"] = sigs.into();
    let bytes = consumer::encode(&v)?;
    let v = envelope(&bytes, &role)?;
    strict_signers(&root, &v, &role)?;
    if role == "root" {
        root_profile(&v)?;
        strict_signers(&v, &v, "root")?;
        if let Some(previous) = previous_root {
            let previous_bytes = storage::read(previous, LIMITS[0])?;
            let old = envelope(&previous_bytes, "root")?;
            root_profile(&old)?;
            strict_signers(&old, &v, "root")?;
            let mut db =
                tuf::Database::<tuf::pouf::Pouf1>::from_trusted_root(
                    &tuf::metadata::RawSignedMetadata::<
                        tuf::pouf::Pouf1,
                        tuf::metadata::RootMetadata,
                    >::new(previous_bytes),
                )
                .map_err(|e| error("TRUST_SIGNATURE", e))?;
            db.update_root(&tuf::metadata::RawSignedMetadata::new(bytes.clone()))
                .map_err(|e| error("TRUST_SIGNATURE", e))?;
        } else {
            require(
                number(&v["signed"], "version", u32::MAX as u64)? == 1,
                "TRUST_SIGNATURE",
                "root transitions require previous-root",
            )?;
        }
    }
    storage::write_new(output, &bytes)?;
    Ok(
        json!({"operation":"assemble","metadata":output,"raw_sha256":digest(&bytes),"preimage_sha256":digest(&canonical(&v["signed"])?),"accepted_signer_ids":strict_signers(&root,&v,&role)?,"complete_chain_verification":"required-before-distribution","validation_authority":"human-only"}),
    )
}
