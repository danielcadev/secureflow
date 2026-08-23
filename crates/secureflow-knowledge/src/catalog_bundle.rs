//! Versioned, hash-bound Zstandard distribution bundles for catalog databases.

use crate::catalog::{
    CATALOG_APPLICATION_ID, CATALOG_PROFILE_POLICY_VERSION, CATALOG_SCHEMA_VERSION, Catalog,
    CatalogComposition, CatalogCompositionSource, CatalogIntegrity, CatalogProfile,
    CatalogProvenance, CatalogStats,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const BUNDLE_VERSION: &str = "secureflow-catalog-bundle-v1";
pub const MAX_BUNDLE_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_BUNDLE_COMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_BUNDLE_DATABASE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_BUNDLE_COMPRESSION_RATIO: u64 = 1_000;
pub const MAX_ZSTD_WINDOW_LOG: u32 = 27;
pub const ZSTD_LEVEL: i32 = 3;

const COMPRESSION_RATIO_SLACK: u64 = 16 * 1024 * 1024;
const VALIDATION_AUTHORITY: &str = "external-records-require-human-validation";
const AUTHENTICITY: &str = "unsigned-manifest-requires-external-sha256";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogBundleDerivation {
    ByteExactOnlineBackup,
    CurrentRecordProjectionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogBundleCompression {
    pub algorithm: String,
    pub level: i32,
    pub checksum: bool,
    pub content_size: bool,
    pub single_frame: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogDatabaseDescriptor {
    pub database_sha256: String,
    pub database_bytes: u64,
    pub application_id: u32,
    pub schema_version: u32,
    pub stats: CatalogStats,
    pub integrity: CatalogIntegrity,
    pub provenance: CatalogProvenance,
    pub composition: CatalogComposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogBundleManifest {
    pub contract_version: String,
    pub bundle_id: String,
    pub created_at: String,
    pub profile: CatalogProfile,
    pub profile_policy_version: String,
    pub derivation: CatalogBundleDerivation,
    pub compression: CatalogBundleCompression,
    pub compressed_sha256: String,
    pub compressed_bytes: u64,
    pub payload: CatalogDatabaseDescriptor,
    pub origin: CatalogDatabaseDescriptor,
    pub validation_authority: String,
    pub authenticity: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedCatalogBundleManifest {
    pub manifest: CatalogBundleManifest,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogBundleVerificationPolicy {
    pub required_profile: Option<CatalogProfile>,
    pub expected_manifest_sha256: Option<String>,
    pub allow_unverified_manifest: bool,
    pub max_compressed_bytes: u64,
    pub max_database_bytes: u64,
}

impl Default for CatalogBundleVerificationPolicy {
    fn default() -> Self {
        Self {
            required_profile: None,
            expected_manifest_sha256: None,
            allow_unverified_manifest: false,
            max_compressed_bytes: MAX_BUNDLE_COMPRESSED_BYTES,
            max_database_bytes: MAX_BUNDLE_DATABASE_BYTES,
        }
    }
}

impl std::fmt::Display for CatalogBundleAuthenticity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unverified => "unverified",
            Self::ManifestSha256Pinned => "manifest-sha256-pinned",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogBundleAuthenticity {
    Unverified,
    ManifestSha256Pinned,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogBundleVerification {
    pub bundle_id: String,
    pub profile: CatalogProfile,
    pub compressed_bytes: u64,
    pub database_bytes: u64,
    pub manifest_sha256: String,
    pub integrity: String,
    pub authenticity: CatalogBundleAuthenticity,
}

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("catalog bundle field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("catalog bundle filesystem operation failed for {path}: {source}")]
    Filesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("catalog bundle compressed size does not match its manifest")]
    CompressedSizeMismatch,
    #[error("catalog bundle compressed hash does not match its manifest")]
    CompressedHashMismatch,
    #[error("catalog bundle database size does not match its manifest")]
    DatabaseSizeMismatch,
    #[error("catalog bundle database hash does not match its manifest")]
    DatabaseHashMismatch,
    #[error("catalog bundle manifest hash does not match the required SHA-256")]
    ManifestHashMismatch,
    #[error(
        "catalog bundle installation requires a manifest SHA-256 from a separately authenticated channel or an explicit unverified-manifest override"
    )]
    ManifestAuthenticityRequired,
    #[error("catalog bundle profile does not match the required profile")]
    ProfileMismatch,
    #[error("catalog bundle contains trailing data or more than one Zstandard frame")]
    TrailingData,
    #[error("catalog operation failed: {0}")]
    Catalog(#[from] crate::catalog::CatalogError),
    #[error("invalid catalog bundle manifest JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not format bundle timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
}

pub fn create_bundle(
    source: &Catalog,
    profile: CatalogProfile,
    output: &Path,
) -> Result<CatalogBundleManifest, BundleError> {
    ensure_new_output(output)?;
    let parent = output_parent(output);
    create_private_directories(parent)?;

    let (temporary_root, mut temporary_guard) =
        create_private_temporary_directory(parent, output, "bundle")?;
    let origin_path = temporary_root.join("origin.sqlite3");
    source.backup_to(&origin_path)?;
    let origin = describe_database(&origin_path)?;
    validate_database_descriptor(&origin, MAX_BUNDLE_DATABASE_BYTES)?;

    let (payload_path, derivation) = match profile {
        CatalogProfile::Full => (
            origin_path.clone(),
            CatalogBundleDerivation::ByteExactOnlineBackup,
        ),
        CatalogProfile::Core | CatalogProfile::Malicious => {
            if origin.composition.active_unclassified_records != 0 {
                return Err(BundleError::InvalidField(
                    "origin contains active records outside the profile policy",
                ));
            }
            let path = temporary_root.join("profile.sqlite3");
            let frozen = Catalog::open_existing(&origin_path)?;
            frozen.derive_current_profile_to(profile, &path)?;
            (path, CatalogBundleDerivation::CurrentRecordProjectionV1)
        }
    };
    let payload = describe_database(&payload_path)?;
    validate_database_descriptor(&payload, MAX_BUNDLE_DATABASE_BYTES)?;
    validate_profile(profile, derivation, &payload, &origin)?;

    let compressed_path = temporary_root.join("payload.sqlite3.zst");
    let compressed_file = create_private_file(&compressed_path)?;
    let (compressed_sha256, compressed_bytes) =
        compress_database(&payload_path, compressed_file, payload.database_bytes)?;
    let created_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let bundle_id = calculate_bundle_id(
        profile,
        &compressed_sha256,
        &payload.database_sha256,
        &origin.database_sha256,
    );
    let manifest = CatalogBundleManifest {
        contract_version: BUNDLE_VERSION.into(),
        bundle_id,
        created_at,
        profile,
        profile_policy_version: CATALOG_PROFILE_POLICY_VERSION.into(),
        derivation,
        compression: CatalogBundleCompression {
            algorithm: "zstd".into(),
            level: ZSTD_LEVEL,
            checksum: true,
            content_size: true,
            single_frame: true,
        },
        compressed_sha256,
        compressed_bytes,
        payload,
        origin,
        validation_authority: VALIDATION_AUTHORITY.into(),
        authenticity: AUTHENTICITY.into(),
    };
    manifest.validate()?;
    publish_new(&compressed_path, output)?;
    temporary_guard.cleanup();
    Ok(manifest)
}

pub fn parse_manifest(bytes: &[u8]) -> Result<ParsedCatalogBundleManifest, BundleError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BUNDLE_MANIFEST_BYTES {
        return Err(BundleError::InvalidField("manifest size"));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    for descriptor_name in ["payload", "origin"] {
        let stats = value
            .get(descriptor_name)
            .and_then(|descriptor| descriptor.get("stats"))
            .and_then(serde_json::Value::as_object)
            .ok_or(BundleError::InvalidField("manifest database statistics"))?;
        if !stats.contains_key("deltas") || !stats.contains_key("complete_deltas") {
            return Err(BundleError::InvalidField(
                "manifest database statistics fields",
            ));
        }
    }
    let manifest: CatalogBundleManifest = serde_json::from_value(value)?;
    manifest.validate()?;
    Ok(ParsedCatalogBundleManifest {
        manifest,
        manifest_sha256: sha256_bytes(bytes),
    })
}

pub fn verify_bundle(
    bundle_path: &Path,
    parsed: &ParsedCatalogBundleManifest,
    policy: &CatalogBundleVerificationPolicy,
) -> Result<CatalogBundleVerification, BundleError> {
    validate_policy(parsed, policy)?;
    let temporary_root = std::env::temp_dir();
    let (temporary_directory, mut guard) =
        create_private_temporary_directory(&temporary_root, bundle_path, "verify")?;
    let temporary_path = temporary_directory.join("catalog.sqlite3");
    let verification = decompress_and_verify(bundle_path, parsed, policy, &temporary_path)?;
    guard.cleanup();
    Ok(verification)
}

pub fn install_bundle(
    bundle_path: &Path,
    parsed: &ParsedCatalogBundleManifest,
    output: &Path,
    policy: &CatalogBundleVerificationPolicy,
) -> Result<CatalogBundleVerification, BundleError> {
    ensure_new_catalog_output(output)?;
    let parent = output_parent(output);
    create_private_directories(parent)?;
    let authenticity = validate_policy(parsed, policy)?;
    if authenticity == CatalogBundleAuthenticity::Unverified && !policy.allow_unverified_manifest {
        return Err(BundleError::ManifestAuthenticityRequired);
    }
    let (temporary_directory, mut guard) =
        create_private_temporary_directory(parent, output, "install")?;
    let temporary_path = temporary_directory.join("catalog.sqlite3");
    let verification = decompress_and_verify(bundle_path, parsed, policy, &temporary_path)?;
    ensure_new_catalog_output(output)?;
    publish_new(&temporary_path, output)?;
    let final_verification = (|| {
        let observed = describe_database(output)?;
        if observed != parsed.manifest.payload {
            return Err(BundleError::InvalidField(
                "installed catalog state differs from verified payload",
            ));
        }
        Ok(())
    })();
    if let Err(error) = final_verification {
        remove_catalog_output_set(output);
        return Err(error);
    }
    guard.cleanup();
    sync_parent(parent)?;
    Ok(verification)
}

impl CatalogBundleManifest {
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.contract_version != BUNDLE_VERSION
            || self.profile_policy_version != CATALOG_PROFILE_POLICY_VERSION
            || self.compression.algorithm != "zstd"
            || self.compression.level != ZSTD_LEVEL
            || !self.compression.checksum
            || !self.compression.content_size
            || !self.compression.single_frame
            || !valid_sha256(&self.compressed_sha256)
            || self.compressed_bytes == 0
            || self.compressed_bytes > MAX_BUNDLE_COMPRESSED_BYTES
            || self.payload.database_bytes
                > self
                    .compressed_bytes
                    .saturating_mul(MAX_BUNDLE_COMPRESSION_RATIO)
                    .saturating_add(COMPRESSION_RATIO_SLACK)
            || OffsetDateTime::parse(&self.created_at, &Rfc3339).is_err()
            || self.validation_authority != VALIDATION_AUTHORITY
            || self.authenticity != AUTHENTICITY
        {
            return Err(BundleError::InvalidField("manifest"));
        }
        validate_database_descriptor(&self.payload, MAX_BUNDLE_DATABASE_BYTES)?;
        validate_database_descriptor(&self.origin, MAX_BUNDLE_DATABASE_BYTES)?;
        validate_profile(self.profile, self.derivation, &self.payload, &self.origin)?;
        let expected_id = calculate_bundle_id(
            self.profile,
            &self.compressed_sha256,
            &self.payload.database_sha256,
            &self.origin.database_sha256,
        );
        if self.bundle_id != expected_id {
            return Err(BundleError::InvalidField("bundle_id"));
        }
        if serde_json::to_vec(self)?.len() as u64 > MAX_BUNDLE_MANIFEST_BYTES {
            return Err(BundleError::InvalidField("manifest size"));
        }
        Ok(())
    }
}

fn validate_policy(
    parsed: &ParsedCatalogBundleManifest,
    policy: &CatalogBundleVerificationPolicy,
) -> Result<CatalogBundleAuthenticity, BundleError> {
    parsed.manifest.validate()?;
    if policy.max_compressed_bytes == 0
        || policy.max_compressed_bytes > MAX_BUNDLE_COMPRESSED_BYTES
        || policy.max_database_bytes == 0
        || policy.max_database_bytes > MAX_BUNDLE_DATABASE_BYTES
        || parsed.manifest.compressed_bytes > policy.max_compressed_bytes
        || parsed.manifest.payload.database_bytes > policy.max_database_bytes
    {
        return Err(BundleError::InvalidField("verification policy"));
    }
    if policy
        .required_profile
        .is_some_and(|required| required != parsed.manifest.profile)
    {
        return Err(BundleError::ProfileMismatch);
    }
    if let Some(expected) = &policy.expected_manifest_sha256 {
        if !valid_sha256(expected) {
            return Err(BundleError::InvalidField("expected manifest SHA-256"));
        }
        if expected != &parsed.manifest_sha256 {
            return Err(BundleError::ManifestHashMismatch);
        }
        Ok(CatalogBundleAuthenticity::ManifestSha256Pinned)
    } else {
        Ok(CatalogBundleAuthenticity::Unverified)
    }
}

fn decompress_and_verify(
    bundle_path: &Path,
    parsed: &ParsedCatalogBundleManifest,
    policy: &CatalogBundleVerificationPolicy,
    temporary_path: &Path,
) -> Result<CatalogBundleVerification, BundleError> {
    let authenticity = validate_policy(parsed, policy)?;
    let manifest = &parsed.manifest;
    let mut bundle = open_regular_file(bundle_path)?;
    let observed_size = bundle
        .metadata()
        .map_err(|source| BundleError::Filesystem {
            path: bundle_path.to_owned(),
            source,
        })?
        .len();
    if observed_size != manifest.compressed_bytes {
        return Err(BundleError::CompressedSizeMismatch);
    }
    let (compressed_hash, compressed_bytes) = hash_open_file(&mut bundle, bundle_path)?;
    if compressed_bytes != manifest.compressed_bytes {
        return Err(BundleError::CompressedSizeMismatch);
    }
    if compressed_hash != manifest.compressed_sha256 {
        return Err(BundleError::CompressedHashMismatch);
    }
    verify_zstd_header(&mut bundle, bundle_path, manifest.payload.database_bytes)?;

    let mut output = create_private_file(temporary_path)?;
    let mut decoder = zstd::stream::read::Decoder::new(&mut bundle)
        .map_err(|source| BundleError::Filesystem {
            path: bundle_path.to_owned(),
            source,
        })?
        .single_frame();
    decoder
        .window_log_max(MAX_ZSTD_WINDOW_LOG)
        .map_err(|source| BundleError::Filesystem {
            path: bundle_path.to_owned(),
            source,
        })?;
    let mut database_hasher = Sha256::new();
    let mut database_bytes = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|source| BundleError::Filesystem {
                path: bundle_path.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        database_bytes = database_bytes.saturating_add(read as u64);
        if database_bytes > manifest.payload.database_bytes
            || database_bytes > policy.max_database_bytes
        {
            return Err(BundleError::DatabaseSizeMismatch);
        }
        database_hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|source| BundleError::Filesystem {
                path: temporary_path.to_owned(),
                source,
            })?;
    }
    let mut buffered_bundle = decoder.finish();
    if !buffered_bundle
        .fill_buf()
        .map_err(|source| BundleError::Filesystem {
            path: bundle_path.to_owned(),
            source,
        })?
        .is_empty()
    {
        return Err(BundleError::TrailingData);
    }
    if database_bytes != manifest.payload.database_bytes {
        return Err(BundleError::DatabaseSizeMismatch);
    }
    let database_hash = hex_digest(database_hasher.finalize().as_slice());
    if database_hash != manifest.payload.database_sha256 {
        return Err(BundleError::DatabaseHashMismatch);
    }
    output
        .sync_all()
        .map_err(|source| BundleError::Filesystem {
            path: temporary_path.to_owned(),
            source,
        })?;
    drop(output);
    let observed = describe_database_with_digest(temporary_path, &database_hash, database_bytes)?;
    if observed != manifest.payload {
        return Err(BundleError::InvalidField(
            "decompressed catalog state differs from manifest",
        ));
    }
    Ok(CatalogBundleVerification {
        bundle_id: manifest.bundle_id.clone(),
        profile: manifest.profile,
        compressed_bytes: manifest.compressed_bytes,
        database_bytes: manifest.payload.database_bytes,
        manifest_sha256: parsed.manifest_sha256.clone(),
        integrity: "verified".into(),
        authenticity,
    })
}

fn describe_database(path: &Path) -> Result<CatalogDatabaseDescriptor, BundleError> {
    let mut file = open_regular_file(path)?;
    let (database_sha256, database_bytes) = hash_open_file(&mut file, path)?;
    describe_database_with_digest(path, &database_sha256, database_bytes)
}

fn describe_database_with_digest(
    path: &Path,
    database_sha256: &str,
    database_bytes: u64,
) -> Result<CatalogDatabaseDescriptor, BundleError> {
    if database_bytes == 0 || database_bytes > MAX_BUNDLE_DATABASE_BYTES {
        return Err(BundleError::InvalidField("database size"));
    }
    if !valid_sha256(database_sha256) {
        return Err(BundleError::InvalidField("database SHA-256"));
    }
    let observed_bytes = open_regular_file(path)?
        .metadata()
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })?
        .len();
    if observed_bytes != database_bytes {
        return Err(BundleError::DatabaseSizeMismatch);
    }
    let catalog = Catalog::open_existing(path)?;
    let mut stats = catalog.stats()?;
    // A portable bundle contains the main SQLite database only. Ignore any
    // transient zero-length WAL/SHM bookkeeping left beside a closed backup.
    stats.database_bytes = database_bytes;
    let descriptor = CatalogDatabaseDescriptor {
        database_sha256: database_sha256.to_owned(),
        database_bytes,
        application_id: CATALOG_APPLICATION_ID,
        schema_version: stats.schema_version,
        integrity: catalog.check_integrity()?,
        provenance: catalog.provenance()?,
        composition: catalog.profile_composition()?,
        stats,
    };
    validate_database_descriptor(&descriptor, MAX_BUNDLE_DATABASE_BYTES)?;
    Ok(descriptor)
}

fn validate_database_descriptor(
    descriptor: &CatalogDatabaseDescriptor,
    maximum_bytes: u64,
) -> Result<(), BundleError> {
    if !valid_sha256(&descriptor.database_sha256) {
        return Err(BundleError::InvalidField("database SHA-256"));
    }
    if descriptor.database_bytes == 0 || descriptor.database_bytes > maximum_bytes {
        return Err(BundleError::InvalidField("database byte size"));
    }
    if descriptor.application_id != CATALOG_APPLICATION_ID {
        return Err(BundleError::InvalidField("database application ID"));
    }
    if !(2..=CATALOG_SCHEMA_VERSION).contains(&descriptor.schema_version)
        || descriptor.stats.schema_version != descriptor.schema_version
        || descriptor.provenance.schema_version != descriptor.schema_version
    {
        return Err(BundleError::InvalidField("database schema version"));
    }
    if descriptor.stats.database_bytes != descriptor.database_bytes {
        return Err(BundleError::InvalidField("database statistics byte size"));
    }
    if descriptor.integrity.quick_check != "ok"
        || descriptor.integrity.foreign_key_violations != 0
        || descriptor.integrity.search_index_status != "ready"
        || descriptor.stats.search_index_status != "ready"
    {
        return Err(BundleError::InvalidField("database integrity"));
    }
    if descriptor.composition.policy_version != CATALOG_PROFILE_POLICY_VERSION {
        return Err(BundleError::InvalidField("composition policy"));
    }
    if descriptor.composition.active_records() != descriptor.stats.active_source_records
        || descriptor.composition.inactive_records != descriptor.stats.inactive_source_records
        || descriptor
            .composition
            .active_records()
            .saturating_add(descriptor.composition.inactive_records)
            != descriptor.stats.source_records
    {
        return Err(BundleError::InvalidField("composition record accounting"));
    }
    validate_composition(&descriptor.composition)
}

fn validate_composition(composition: &CatalogComposition) -> Result<(), BundleError> {
    if composition.sources.len() > 10_000 {
        return Err(BundleError::InvalidField("composition sources"));
    }
    let mut names = BTreeSet::new();
    let mut advisory = 0_u64;
    let mut malicious = 0_u64;
    let mut unclassified = 0_u64;
    let mut previous = None::<&str>;
    for source in &composition.sources {
        if source.name.trim().is_empty()
            || source.name.chars().count() > 500
            || source.license_expression.trim().is_empty()
            || source.license_expression.chars().count() > 500
            || source.locator.trim().is_empty()
            || source.locator.chars().count() > 4_096
            || !valid_sha256(&source.license_evidence_sha256)
            || source
                .name
                .chars()
                .chain(source.license_expression.chars())
                .chain(source.locator.chars())
                .any(char::is_control)
            || source
                .active_advisory_records
                .saturating_add(source.active_malicious_package_records)
                .saturating_add(source.active_unclassified_records)
                == 0
            || previous.is_some_and(|value| value >= source.name.as_str())
            || !names.insert(source.name.as_str())
        {
            return Err(BundleError::InvalidField("composition source"));
        }
        previous = Some(&source.name);
        advisory = advisory.saturating_add(source.active_advisory_records);
        malicious = malicious.saturating_add(source.active_malicious_package_records);
        unclassified = unclassified.saturating_add(source.active_unclassified_records);
    }
    if advisory != composition.active_advisory_records
        || malicious != composition.active_malicious_package_records
        || unclassified != composition.active_unclassified_records
    {
        return Err(BundleError::InvalidField("composition accounting"));
    }
    Ok(())
}

fn validate_profile(
    profile: CatalogProfile,
    derivation: CatalogBundleDerivation,
    payload: &CatalogDatabaseDescriptor,
    origin: &CatalogDatabaseDescriptor,
) -> Result<(), BundleError> {
    match profile {
        CatalogProfile::Full => {
            if derivation != CatalogBundleDerivation::ByteExactOnlineBackup || payload != origin {
                return Err(BundleError::InvalidField("full profile"));
            }
        }
        CatalogProfile::Core | CatalogProfile::Malicious => {
            let composition = &payload.composition;
            let expected = match profile {
                CatalogProfile::Core => {
                    composition.active_advisory_records != 0
                        && composition.active_malicious_package_records == 0
                }
                CatalogProfile::Malicious => {
                    composition.active_advisory_records == 0
                        && composition.active_malicious_package_records != 0
                }
                CatalogProfile::Full => unreachable!(),
            };
            if derivation != CatalogBundleDerivation::CurrentRecordProjectionV1
                || !expected
                || composition.active_unclassified_records != 0
                || composition.inactive_records != 0
                || payload.stats.source_records != payload.stats.source_record_revisions
                || payload.stats.snapshots != 0
                || payload.stats.deltas != 0
                || payload.stats.complete_deltas != 0
                || !payload.provenance.complete_snapshot_ids.is_empty()
                || !payload.provenance.complete_delta_ids.is_empty()
                || origin.composition.active_unclassified_records != 0
                || !projection_matches_origin(profile, composition, &origin.composition)
            {
                return Err(BundleError::InvalidField("projected profile"));
            }
        }
    }
    Ok(())
}

fn projection_matches_origin(
    profile: CatalogProfile,
    payload: &CatalogComposition,
    origin: &CatalogComposition,
) -> bool {
    let expected_records = match profile {
        CatalogProfile::Core => origin.active_advisory_records,
        CatalogProfile::Malicious => origin.active_malicious_package_records,
        CatalogProfile::Full => return false,
    };
    if payload.active_records() != expected_records {
        return false;
    }

    let mut expected_sources = Vec::new();
    for source in &origin.sources {
        let declared_profile = source.declared_profile();
        let source_is_consistent = match declared_profile {
            Some(CatalogProfile::Core) => {
                source.active_advisory_records != 0
                    && source.active_malicious_package_records == 0
                    && source.active_unclassified_records == 0
            }
            Some(CatalogProfile::Malicious) => {
                source.active_advisory_records == 0
                    && source.active_malicious_package_records != 0
                    && source.active_unclassified_records == 0
            }
            Some(CatalogProfile::Full) | None => false,
        };
        if !source_is_consistent {
            return false;
        }
        if declared_profile == Some(profile) {
            expected_sources.push(CatalogCompositionSource {
                name: source.name.clone(),
                license_expression: source.license_expression.clone(),
                license_evidence_sha256: source.license_evidence_sha256.clone(),
                locator: source.locator.clone(),
                active_advisory_records: if profile == CatalogProfile::Core {
                    source.active_advisory_records
                } else {
                    0
                },
                active_malicious_package_records: if profile == CatalogProfile::Malicious {
                    source.active_malicious_package_records
                } else {
                    0
                },
                active_unclassified_records: 0,
            });
        }
    }
    payload.sources == expected_sources
}

fn compress_database(
    database_path: &Path,
    output: File,
    expected_bytes: u64,
) -> Result<(String, u64), BundleError> {
    let mut input = open_regular_file(database_path)?;
    let input_bytes = input
        .metadata()
        .map_err(|source| BundleError::Filesystem {
            path: database_path.to_owned(),
            source,
        })?
        .len();
    if input_bytes != expected_bytes {
        return Err(BundleError::DatabaseSizeMismatch);
    }
    let mut encoder = zstd::stream::write::Encoder::new(output, ZSTD_LEVEL).map_err(|source| {
        BundleError::Filesystem {
            path: database_path.to_owned(),
            source,
        }
    })?;
    encoder
        .include_checksum(true)
        .and_then(|()| encoder.include_contentsize(true))
        .and_then(|()| encoder.set_pledged_src_size(Some(expected_bytes)))
        .map_err(|source| BundleError::Filesystem {
            path: database_path.to_owned(),
            source,
        })?;
    let copied =
        std::io::copy(&mut input, &mut encoder).map_err(|source| BundleError::Filesystem {
            path: database_path.to_owned(),
            source,
        })?;
    if copied != expected_bytes {
        return Err(BundleError::DatabaseSizeMismatch);
    }
    let mut output = encoder.finish().map_err(|source| BundleError::Filesystem {
        path: database_path.to_owned(),
        source,
    })?;
    output
        .sync_all()
        .map_err(|source| BundleError::Filesystem {
            path: database_path.to_owned(),
            source,
        })?;
    let result = hash_open_file(&mut output, database_path)?;
    if result.1 == 0 || result.1 > MAX_BUNDLE_COMPRESSED_BYTES {
        return Err(BundleError::InvalidField("compressed size"));
    }
    Ok(result)
}

fn open_regular_file(path: &Path) -> Result<File, BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| BundleError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(BundleError::InvalidField(
            "input must be a regular non-symlink file",
        ));
    }
    let file = File::open(path).map_err(|source| BundleError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if !file
        .metadata()
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })?
        .is_file()
    {
        return Err(BundleError::InvalidField("input must be a regular file"));
    }
    Ok(file)
}

fn hash_open_file(file: &mut File, path: &Path) -> Result<(String, u64), BundleError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| BundleError::Filesystem {
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })?;
    Ok((hex_digest(hasher.finalize().as_slice()), bytes))
}

fn verify_zstd_header(
    file: &mut File,
    path: &Path,
    expected_bytes: u64,
) -> Result<(), BundleError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })?;
    let mut prefix = [0_u8; 18];
    let read = file
        .read(&mut prefix)
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })?;
    if read < 5 || prefix[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
        return Err(BundleError::InvalidField("Zstandard frame header"));
    }
    if prefix[4] & 0x04 == 0 {
        return Err(BundleError::InvalidField("Zstandard frame checksum"));
    }
    let content_size = zstd::zstd_safe::get_frame_content_size(&prefix[..read])
        .map_err(|_| BundleError::InvalidField("Zstandard frame header"))?;
    if content_size != Some(expected_bytes) {
        return Err(BundleError::InvalidField("Zstandard frame content size"));
    }
    Ok(())
}

fn create_private_temporary_directory(
    parent: &Path,
    output: &Path,
    label: &str,
) -> Result<(PathBuf, TemporaryDirectory), BundleError> {
    let name = output
        .file_name()
        .ok_or(BundleError::InvalidField("output must name a file"))?
        .to_string_lossy();
    let nonce = OffsetDateTime::now_utc().unix_timestamp_nanos();
    for attempt in 0..100_u32 {
        let path = parent.join(format!(
            ".{name}.{label}-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => return Ok((path.clone(), TemporaryDirectory::new(path))),
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(BundleError::Filesystem { path, source }),
            }
        }
        #[cfg(not(unix))]
        match fs::create_dir(&path) {
            Ok(()) => return Ok((path.clone(), TemporaryDirectory::new(path))),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(BundleError::Filesystem { path, source }),
        }
    }
    Err(BundleError::InvalidField(
        "could not allocate temporary output",
    ))
}

fn create_private_file(path: &Path) -> Result<File, BundleError> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

fn ensure_new_output(path: &Path) -> Result<(), BundleError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(BundleError::InvalidField("output must name a file"));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => Err(BundleError::InvalidField("output already exists")),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(BundleError::Filesystem {
            path: path.to_owned(),
            source,
        }),
    }
}

fn ensure_new_catalog_output(path: &Path) -> Result<(), BundleError> {
    ensure_new_output(path)?;
    for sidecar in sqlite_sidecar_paths(path) {
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                return Err(BundleError::InvalidField(
                    "catalog output sidecar already exists",
                ));
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(BundleError::Filesystem {
                    path: sidecar,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn sqlite_sidecar_paths(path: &Path) -> [PathBuf; 3] {
    ["-wal", "-shm", "-journal"].map(|suffix| {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    })
}

fn remove_catalog_output_set(path: &Path) {
    let _ = fs::remove_file(path);
    for sidecar in sqlite_sidecar_paths(path) {
        let _ = fs::remove_file(sidecar);
    }
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn publish_new(temporary: &Path, output: &Path) -> Result<(), BundleError> {
    fs::hard_link(temporary, output).map_err(|source| BundleError::Filesystem {
        path: output.to_owned(),
        source,
    })?;
    let publish_result = (|| {
        secure_file_permissions(output)?;
        File::open(output)
            .and_then(|file| file.sync_all())
            .map_err(|source| BundleError::Filesystem {
                path: output.to_owned(),
                source,
            })?;
        sync_parent(output_parent(output))?;
        Ok(())
    })();
    if publish_result.is_err() {
        let _ = fs::remove_file(output);
    }
    publish_result
}

#[cfg(unix)]
fn create_private_directories(path: &Path) -> Result<(), BundleError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
fn create_private_directories(path: &Path) -> Result<(), BundleError> {
    fs::create_dir_all(path).map_err(|source| BundleError::Filesystem {
        path: path.to_owned(),
        source,
    })
}

#[cfg(unix)]
fn secure_file_permissions(path: &Path) -> Result<(), BundleError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        BundleError::Filesystem {
            path: path.to_owned(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn secure_file_permissions(_path: &Path) -> Result<(), BundleError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), BundleError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| BundleError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), BundleError> {
    Ok(())
}

fn calculate_bundle_id(
    profile: CatalogProfile,
    compressed_sha256: &str,
    database_sha256: &str,
    origin_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        "secureflow-catalog-bundle-id-v1",
        &profile.to_string(),
        compressed_sha256,
        database_sha256,
        origin_sha256,
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    format!(
        "sf_catalog_bundle_{}",
        hex_digest(hasher.finalize().as_slice())
    )
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes).as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing into a String cannot fail");
    }
    output
}

struct TemporaryDirectory {
    path: PathBuf,
    active: bool,
}

impl TemporaryDirectory {
    fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    fn cleanup(&mut self) {
        if !self.active {
            return;
        }
        let _ = fs::remove_dir_all(&self.path);
        self.active = false;
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::CatalogSource;

    fn temporary_path(label: &str, extension: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "secureflow-{label}-{}-{}.{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos(),
            extension
        ))
    }

    fn advisory_source() -> CatalogSource {
        CatalogSource {
            name: "github-advisory-database@npm".into(),
            license_expression: "CC-BY-4.0".into(),
            license_evidence_sha256: "a".repeat(64),
            locator: "https://github.com/github/advisory-database".into(),
        }
    }

    fn malicious_source() -> CatalogSource {
        CatalogSource {
            name: "openssf-malicious-packages@npm".into(),
            license_expression: "Apache-2.0".into(),
            license_evidence_sha256: "b".repeat(64),
            locator: "https://github.com/ossf/malicious-packages".into(),
        }
    }

    fn record(identifier: &str, alias: &str, package: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "1.7.3",
            "id": identifier,
            "modified": "2026-08-23T00:00:00Z",
            "aliases": [alias],
            "summary": format!("fixture {identifier}"),
            "details": "bounded fixture",
            "affected": [{
                "package": {"ecosystem": "npm", "name": package},
                "versions": ["1.0.0"]
            }],
            "references": [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}]
        }))
        .expect("fixture JSON")
    }

    fn mixed_catalog(path: &Path) -> Catalog {
        let mut catalog = Catalog::open_or_create(path).expect("catalog");
        catalog
            .import_osv_record(
                &advisory_source(),
                &record("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", "safe-package"),
            )
            .expect("advisory");
        catalog
            .import_osv_record(
                &malicious_source(),
                &record("MAL-2026-example", "CVE-2026-0001", "bad-package"),
            )
            .expect("malicious");
        catalog
    }

    fn remove_paths(paths: &[&Path]) {
        for path in paths {
            let _ = fs::remove_file(path);
            for suffix in ["-wal", "-shm"] {
                let mut value = path.as_os_str().to_os_string();
                value.push(suffix);
                let _ = fs::remove_file(PathBuf::from(value));
            }
        }
    }

    fn pinned_policy(parsed: &ParsedCatalogBundleManifest) -> CatalogBundleVerificationPolicy {
        CatalogBundleVerificationPolicy {
            expected_manifest_sha256: Some(parsed.manifest_sha256.clone()),
            ..Default::default()
        }
    }

    #[test]
    fn core_bundle_round_trip_is_filtered_verified_and_never_overwrites() {
        let source_path = temporary_path("bundle-source", "sqlite3");
        let bundle_path = temporary_path("bundle-core", "sqlite3.zst");
        let installed_path = temporary_path("bundle-installed", "sqlite3");
        let catalog = mixed_catalog(&source_path);
        let manifest = create_bundle(&catalog, CatalogProfile::Core, &bundle_path).expect("bundle");
        assert_eq!(manifest.payload.composition.active_advisory_records, 1);
        assert_eq!(
            manifest
                .payload
                .composition
                .active_malicious_package_records,
            0
        );
        assert_eq!(
            manifest.origin.composition.active_malicious_package_records,
            1
        );
        assert_ne!(
            manifest.payload.database_sha256,
            manifest.origin.database_sha256
        );

        let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest bytes");
        let parsed = parse_manifest(&bytes).expect("parsed manifest");
        let policy = CatalogBundleVerificationPolicy {
            required_profile: Some(CatalogProfile::Core),
            expected_manifest_sha256: Some(parsed.manifest_sha256.clone()),
            ..Default::default()
        };
        let verified = verify_bundle(&bundle_path, &parsed, &policy).expect("verified");
        assert_eq!(
            verified.authenticity,
            CatalogBundleAuthenticity::ManifestSha256Pinned
        );
        install_bundle(&bundle_path, &parsed, &installed_path, &policy).expect("installed");
        let installed = Catalog::open_existing(&installed_path).expect("installed catalog");
        assert_eq!(
            installed
                .lookup_identifier("GHSA-aaaa-bbbb-cccc", 10)
                .expect("lookup")
                .len(),
            1
        );
        assert!(
            installed
                .lookup_identifier("MAL-2026-example", 10)
                .expect("lookup")
                .is_empty()
        );
        assert!(install_bundle(&bundle_path, &parsed, &installed_path, &policy).is_err());
        remove_paths(&[&source_path, &bundle_path, &installed_path]);
    }

    #[test]
    fn malicious_and_full_profiles_have_truthful_composition() {
        let source_path = temporary_path("profiles-source", "sqlite3");
        let malicious_path = temporary_path("profiles-malicious", "sqlite3.zst");
        let full_path = temporary_path("profiles-full", "sqlite3.zst");
        let catalog = mixed_catalog(&source_path);
        let malicious = create_bundle(&catalog, CatalogProfile::Malicious, &malicious_path)
            .expect("malicious bundle");
        assert_eq!(malicious.payload.composition.active_advisory_records, 0);
        assert_eq!(
            malicious
                .payload
                .composition
                .active_malicious_package_records,
            1
        );
        let full = create_bundle(&catalog, CatalogProfile::Full, &full_path).expect("full bundle");
        assert_eq!(full.payload, full.origin);
        assert_eq!(full.payload.composition.active_advisory_records, 1);
        assert_eq!(full.payload.composition.active_malicious_package_records, 1);
        remove_paths(&[&source_path, &malicious_path, &full_path]);
    }

    #[test]
    fn tampering_truncation_and_profile_substitution_fail_closed() {
        let source_path = temporary_path("tamper-source", "sqlite3");
        let bundle_path = temporary_path("tamper-bundle", "sqlite3.zst");
        let catalog = mixed_catalog(&source_path);
        let manifest = create_bundle(&catalog, CatalogProfile::Core, &bundle_path).expect("bundle");
        let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest");
        let parsed = parse_manifest(&bytes).expect("parsed");
        let wrong_profile = CatalogBundleVerificationPolicy {
            required_profile: Some(CatalogProfile::Malicious),
            ..Default::default()
        };
        assert!(matches!(
            verify_bundle(&bundle_path, &parsed, &wrong_profile),
            Err(BundleError::ProfileMismatch)
        ));

        let original = fs::read(&bundle_path).expect("bundle bytes");
        let mut tampered = original.clone();
        let middle = tampered.len() / 2;
        tampered[middle] ^= 1;
        fs::write(&bundle_path, &tampered).expect("tamper");
        assert!(matches!(
            verify_bundle(&bundle_path, &parsed, &Default::default()),
            Err(BundleError::CompressedHashMismatch)
        ));
        fs::write(&bundle_path, &original[..original.len() - 1]).expect("truncate");
        assert!(matches!(
            verify_bundle(&bundle_path, &parsed, &Default::default()),
            Err(BundleError::CompressedSizeMismatch)
        ));
        remove_paths(&[&source_path, &bundle_path]);
    }

    #[test]
    fn trailing_second_frame_is_rejected_even_when_manifest_hashes_match() {
        let source_path = temporary_path("trailing-source", "sqlite3");
        let bundle_path = temporary_path("trailing-bundle", "sqlite3.zst");
        let catalog = mixed_catalog(&source_path);
        let mut manifest =
            create_bundle(&catalog, CatalogProfile::Full, &bundle_path).expect("bundle");
        let mut bundle = fs::OpenOptions::new()
            .append(true)
            .open(&bundle_path)
            .expect("append");
        let second_frame = zstd::stream::encode_all(&b"trailing"[..], ZSTD_LEVEL).expect("frame");
        bundle.write_all(&second_frame).expect("trailing frame");
        bundle.sync_all().expect("sync");
        drop(bundle);
        let bytes = fs::read(&bundle_path).expect("bundle bytes");
        manifest.compressed_bytes = bytes.len() as u64;
        manifest.compressed_sha256 = sha256_bytes(&bytes);
        manifest.bundle_id = calculate_bundle_id(
            manifest.profile,
            &manifest.compressed_sha256,
            &manifest.payload.database_sha256,
            &manifest.origin.database_sha256,
        );
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("manifest");
        let parsed = parse_manifest(&manifest_bytes).expect("parsed");
        assert!(matches!(
            verify_bundle(&bundle_path, &parsed, &Default::default()),
            Err(BundleError::TrailingData)
        ));
        remove_paths(&[&source_path, &bundle_path]);
    }

    #[test]
    fn decompressed_size_and_database_hash_are_enforced_before_publish() {
        let source_path = temporary_path("limits-source", "sqlite3");
        let bundle_path = temporary_path("limits-bundle", "sqlite3.zst");
        let installed_path = temporary_path("limits-installed", "sqlite3");
        let catalog = mixed_catalog(&source_path);
        let manifest = create_bundle(&catalog, CatalogProfile::Full, &bundle_path).expect("bundle");

        let mut undersized = manifest.clone();
        undersized.payload.database_bytes -= 1;
        undersized.payload.stats.database_bytes -= 1;
        undersized.origin = undersized.payload.clone();
        undersized.bundle_id = calculate_bundle_id(
            undersized.profile,
            &undersized.compressed_sha256,
            &undersized.payload.database_sha256,
            &undersized.origin.database_sha256,
        );
        let undersized_bytes = serde_json::to_vec_pretty(&undersized).expect("manifest");
        let undersized = parse_manifest(&undersized_bytes).expect("valid structure");
        let local_policy = CatalogBundleVerificationPolicy {
            allow_unverified_manifest: true,
            ..Default::default()
        };
        assert!(matches!(
            install_bundle(&bundle_path, &undersized, &installed_path, &local_policy),
            Err(BundleError::InvalidField("Zstandard frame content size"))
        ));
        assert!(!installed_path.exists());

        let mut wrong_hash = manifest;
        wrong_hash.payload.database_sha256 = "d".repeat(64);
        wrong_hash.origin = wrong_hash.payload.clone();
        wrong_hash.bundle_id = calculate_bundle_id(
            wrong_hash.profile,
            &wrong_hash.compressed_sha256,
            &wrong_hash.payload.database_sha256,
            &wrong_hash.origin.database_sha256,
        );
        let wrong_hash_bytes = serde_json::to_vec_pretty(&wrong_hash).expect("manifest");
        let wrong_hash = parse_manifest(&wrong_hash_bytes).expect("valid structure");
        assert!(matches!(
            verify_bundle(&bundle_path, &wrong_hash, &Default::default()),
            Err(BundleError::DatabaseHashMismatch)
        ));
        remove_paths(&[&source_path, &bundle_path, &installed_path]);
    }

    #[test]
    fn manifest_hash_pin_and_unknown_fields_fail_closed() {
        let source_path = temporary_path("manifest-source", "sqlite3");
        let bundle_path = temporary_path("manifest-bundle", "sqlite3.zst");
        let catalog = mixed_catalog(&source_path);
        let manifest = create_bundle(&catalog, CatalogProfile::Full, &bundle_path).expect("bundle");
        let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest");
        let parsed = parse_manifest(&bytes).expect("parsed");
        let wrong_pin = CatalogBundleVerificationPolicy {
            expected_manifest_sha256: Some("e".repeat(64)),
            ..Default::default()
        };
        assert!(matches!(
            verify_bundle(&bundle_path, &parsed, &wrong_pin),
            Err(BundleError::ManifestHashMismatch)
        ));

        let mut value = serde_json::to_value(manifest).expect("manifest value");
        value
            .as_object_mut()
            .expect("manifest object")
            .insert("unexpected".into(), serde_json::json!(true));
        assert!(parse_manifest(&serde_json::to_vec(&value).expect("JSON")).is_err());

        let mut nested = serde_json::to_value(&parsed.manifest).expect("manifest value");
        nested["payload"]["stats"]
            .as_object_mut()
            .expect("stats object")
            .insert("unexpected".into(), serde_json::json!(true));
        assert!(parse_manifest(&serde_json::to_vec(&nested).expect("JSON")).is_err());

        let mut missing = serde_json::to_value(&parsed.manifest).expect("manifest value");
        missing["origin"]["stats"]
            .as_object_mut()
            .expect("stats object")
            .remove("deltas");
        assert!(parse_manifest(&serde_json::to_vec(&missing).expect("JSON")).is_err());
        remove_paths(&[&source_path, &bundle_path]);
    }

    #[test]
    fn unclassified_sources_cannot_be_projected() {
        let source_path = temporary_path("unknown-source", "sqlite3");
        let bundle_path = temporary_path("unknown-bundle", "sqlite3.zst");
        let mut catalog = Catalog::open_or_create(&source_path).expect("catalog");
        let unknown = CatalogSource {
            name: "operator-feed".into(),
            license_expression: "MIT".into(),
            license_evidence_sha256: "c".repeat(64),
            locator: "https://example.invalid/feed".into(),
        };
        catalog
            .import_osv_record(
                &unknown,
                &record("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", "package"),
            )
            .expect("record");
        catalog
            .import_osv_record(
                &advisory_source(),
                &record("RUSTSEC-2026-9999", "CVE-2026-0002", "package-two"),
            )
            .expect("mismatched source record");
        assert_eq!(
            catalog
                .profile_composition()
                .expect("composition")
                .active_unclassified_records,
            2
        );
        assert!(matches!(
            create_bundle(&catalog, CatalogProfile::Core, &bundle_path),
            Err(BundleError::InvalidField(
                "origin contains active records outside the profile policy"
            ))
        ));
        assert!(!bundle_path.exists());
        remove_paths(&[&source_path, &bundle_path]);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inputs_are_rejected_and_installed_mode_is_private() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let source_path = temporary_path("symlink-source", "sqlite3");
        let bundle_path = temporary_path("symlink-bundle", "sqlite3.zst");
        let symlink_path = temporary_path("symlink-link", "sqlite3.zst");
        let installed_path = temporary_path("symlink-installed", "sqlite3");
        let catalog = mixed_catalog(&source_path);
        let manifest = create_bundle(&catalog, CatalogProfile::Full, &bundle_path).expect("bundle");
        let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest");
        let parsed = parse_manifest(&bytes).expect("parsed");
        symlink(&bundle_path, &symlink_path).expect("symlink");
        assert!(verify_bundle(&symlink_path, &parsed, &Default::default()).is_err());
        install_bundle(
            &bundle_path,
            &parsed,
            &installed_path,
            &pinned_policy(&parsed),
        )
        .expect("install");
        assert_eq!(
            fs::metadata(&installed_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        remove_paths(&[&source_path, &bundle_path, &symlink_path, &installed_path]);
    }

    #[test]
    fn projected_manifest_must_match_the_exact_origin_subset() {
        let source_path = temporary_path("projection-origin", "sqlite3");
        let bundle_path = temporary_path("projection-bundle", "sqlite3.zst");
        let catalog = mixed_catalog(&source_path);
        let mut manifest =
            create_bundle(&catalog, CatalogProfile::Core, &bundle_path).expect("bundle");
        manifest.origin.composition.sources[0].license_evidence_sha256 = "c".repeat(64);
        let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest");
        assert!(matches!(
            parse_manifest(&bytes),
            Err(BundleError::InvalidField("projected profile"))
        ));
        remove_paths(&[&source_path, &bundle_path]);
    }

    #[test]
    fn checksum_free_frame_is_rejected_even_when_hashes_match() {
        let source_path = temporary_path("checksum-source", "sqlite3");
        let bundle_path = temporary_path("checksum-bundle", "sqlite3.zst");
        let catalog = mixed_catalog(&source_path);
        let mut manifest =
            create_bundle(&catalog, CatalogProfile::Full, &bundle_path).expect("bundle");
        let database =
            zstd::stream::decode_all(fs::File::open(&bundle_path).expect("open original bundle"))
                .expect("decode original bundle");
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), ZSTD_LEVEL)
            .expect("checksum-free encoder");
        encoder.include_checksum(false).expect("disable checksum");
        encoder
            .include_contentsize(true)
            .expect("include content size");
        encoder
            .set_pledged_src_size(Some(database.len() as u64))
            .expect("pledge source size");
        encoder.write_all(&database).expect("encode database");
        let compressed = encoder.finish().expect("finish frame");
        fs::write(&bundle_path, &compressed).expect("replace bundle");
        manifest.compressed_bytes = compressed.len() as u64;
        manifest.compressed_sha256 = sha256_bytes(&compressed);
        manifest.bundle_id = calculate_bundle_id(
            manifest.profile,
            &manifest.compressed_sha256,
            &manifest.payload.database_sha256,
            &manifest.origin.database_sha256,
        );
        let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest");
        let parsed = parse_manifest(&bytes).expect("parsed");
        assert!(matches!(
            verify_bundle(&bundle_path, &parsed, &Default::default()),
            Err(BundleError::InvalidField("Zstandard frame checksum"))
        ));
        remove_paths(&[&source_path, &bundle_path]);
    }

    #[test]
    fn install_requires_manifest_authenticity_or_an_explicit_local_override() {
        let source_path = temporary_path("auth-source", "sqlite3");
        let bundle_path = temporary_path("auth-bundle", "sqlite3.zst");
        let installed_path = temporary_path("auth-installed", "sqlite3");
        let catalog = mixed_catalog(&source_path);
        let manifest = create_bundle(&catalog, CatalogProfile::Full, &bundle_path).expect("bundle");
        let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest");
        let parsed = parse_manifest(&bytes).expect("parsed");
        assert!(matches!(
            install_bundle(&bundle_path, &parsed, &installed_path, &Default::default()),
            Err(BundleError::ManifestAuthenticityRequired)
        ));
        assert!(!installed_path.exists());
        let local_policy = CatalogBundleVerificationPolicy {
            allow_unverified_manifest: true,
            ..Default::default()
        };
        let verification = install_bundle(&bundle_path, &parsed, &installed_path, &local_policy)
            .expect("explicitly allowed local install");
        assert_eq!(
            verification.authenticity,
            CatalogBundleAuthenticity::Unverified
        );
        remove_paths(&[&source_path, &bundle_path, &installed_path]);
    }

    #[test]
    fn preexisting_sqlite_sidecars_are_rejected_and_preserved() {
        let source_path = temporary_path("sidecar-source", "sqlite3");
        let bundle_path = temporary_path("sidecar-bundle", "sqlite3.zst");
        let seed_path = temporary_path("sidecar-seed", "sqlite3");
        let installed_path = temporary_path("sidecar-installed", "sqlite3");
        let catalog = mixed_catalog(&source_path);
        let manifest = create_bundle(&catalog, CatalogProfile::Full, &bundle_path).expect("bundle");
        let bytes = serde_json::to_vec_pretty(&manifest).expect("manifest");
        let parsed = parse_manifest(&bytes).expect("parsed");
        let policy = pinned_policy(&parsed);
        install_bundle(&bundle_path, &parsed, &seed_path, &policy).expect("seed install");

        let connection = rusqlite::Connection::open(&seed_path).expect("writable seed");
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .expect("WAL mode");
        connection
            .pragma_update(None, "wal_autocheckpoint", 0_i64)
            .expect("disable auto-checkpoint");
        connection
            .execute(
                "UPDATE catalog_metadata SET value = 'attacker-controlled-policy'\
                 WHERE key = 'canonicalization'",
                [],
            )
            .expect("write valid WAL");
        let seed_wal = sqlite_sidecar_paths(&seed_path)[0].clone();
        let installed_wal = sqlite_sidecar_paths(&installed_path)[0].clone();
        let wal_bytes = fs::read(&seed_wal).expect("seed WAL");
        fs::write(&installed_wal, &wal_bytes).expect("pre-place WAL");

        assert!(matches!(
            install_bundle(&bundle_path, &parsed, &installed_path, &policy),
            Err(BundleError::InvalidField(
                "catalog output sidecar already exists"
            ))
        ));
        assert!(!installed_path.exists());
        assert_eq!(fs::read(&installed_wal).expect("preserved WAL"), wal_bytes);
        drop(connection);
        remove_paths(&[&source_path, &bundle_path, &seed_path, &installed_path]);
        let _ = fs::remove_file(installed_wal);
    }
}
