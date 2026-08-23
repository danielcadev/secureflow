//! Reproducible, fail-closed preparation of local OSV ecosystem snapshots.
//!
//! Network acquisition deliberately remains outside this module. The input is
//! an operator-supplied ZIP artifact whose locator, immutable revision and hash
//! are bound into the resulting manifest. Accepted records and quarantined
//! records are both retained; no malformed or unsupported record disappears.

use crate::catalog::{CatalogError, MAX_IMPORT_RECORDS, MAX_OSV_RECORD_BYTES, OsvRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zip::ZipArchive;

pub const SNAPSHOT_CONTRACT_VERSION: &str = "secureflow-advisory-snapshot-v1";
pub const SNAPSHOT_POLICY_VERSION: &str = "osv-ecosystem-source-policy-v2";
const LEGACY_SNAPSHOT_POLICY_VERSION: &str = "osv-ecosystem-source-policy-v1";
pub const MAX_SNAPSHOT_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_SNAPSHOT_UNCOMPRESSED_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_SNAPSHOT_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LICENSE_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_RATIO: u64 = 1_000;

#[derive(Clone, Debug)]
pub struct SnapshotPrepareConfig {
    pub archive: PathBuf,
    pub output: PathBuf,
    pub artifact_locator: String,
    pub artifact_revision: String,
    pub expected_ecosystem: String,
    pub acquired_at: String,
    pub github_license_evidence: Option<PathBuf>,
    pub rustsec_license_evidence: Option<PathBuf>,
    pub openssf_malicious_packages_license_evidence: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisorySnapshotManifest {
    pub contract_version: String,
    pub policy_version: String,
    pub snapshot_id: String,
    pub acquired_at: String,
    pub expected_ecosystem: String,
    pub artifact: SnapshotArtifact,
    pub sources: Vec<SnapshotSource>,
    pub records: Vec<SnapshotRecord>,
    pub quarantined: Vec<SnapshotQuarantine>,
    pub accounting: SnapshotAccounting,
    pub validation_authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotArtifact {
    pub file_name: String,
    pub format: String,
    pub locator: String,
    pub revision: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSource {
    pub name: String,
    pub kind: String,
    pub scope: String,
    pub locator: String,
    pub license_expression: String,
    pub license_evidence_path: String,
    pub license_evidence_sha256: String,
    pub record_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    pub archive_entry: String,
    pub stored_path: String,
    pub source_name: String,
    pub id: String,
    pub modified: String,
    pub ecosystems: Vec<String>,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotQuarantine {
    pub archive_entry: String,
    pub stored_path: String,
    pub reason: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotAccounting {
    pub archive_entries: u64,
    pub accepted_records: u64,
    pub quarantined_records: u64,
    pub accepted_bytes: u64,
    pub quarantined_bytes: u64,
    pub uncompressed_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceClass {
    name: String,
    kind: &'static str,
    locator: &'static str,
    license_expression: &'static str,
    evidence_kind: EvidenceKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceKind {
    Github,
    Rustsec,
    OpenssfMaliciousPackages,
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("snapshot configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("snapshot path is invalid: {0}")]
    InvalidPath(&'static str),
    #[error("snapshot filesystem operation failed for {path}: {source}")]
    Filesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("snapshot ZIP operation failed: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("snapshot JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("snapshot timestamp is not RFC3339: {0}")]
    InvalidTimestamp(String),
    #[error("snapshot archive exceeds {maximum} bytes: {bytes}")]
    ArchiveTooLarge { bytes: u64, maximum: u64 },
    #[error("snapshot contains more than {0} entries")]
    TooManyEntries(usize),
    #[error("snapshot uncompressed data exceeds {maximum} bytes")]
    UncompressedTooLarge { maximum: u64 },
    #[error("unsafe ZIP entry: {entry} ({reason})")]
    UnsafeArchiveEntry { entry: String, reason: &'static str },
    #[error("duplicate ZIP entry: {0}")]
    DuplicateArchiveEntry(String),
    #[error("required license evidence is missing for {0}")]
    MissingLicenseEvidence(&'static str),
    #[error("snapshot manifest is invalid: {0}")]
    InvalidManifest(&'static str),
    #[error("snapshot file does not match its manifest: {0}")]
    FileMismatch(String),
    #[error("snapshot contains an unexpected file: {0}")]
    UnexpectedFile(String),
    #[error("snapshot OSV validation failed: {0}")]
    Osv(#[from] CatalogError),
}

pub fn prepare_osv_zip(
    config: &SnapshotPrepareConfig,
) -> Result<AdvisorySnapshotManifest, SnapshotError> {
    validate_prepare_config(config)?;
    let archive_metadata = regular_file_metadata(&config.archive)?;
    if archive_metadata.len() > MAX_SNAPSHOT_ARCHIVE_BYTES {
        return Err(SnapshotError::ArchiveTooLarge {
            bytes: archive_metadata.len(),
            maximum: MAX_SNAPSHOT_ARCHIVE_BYTES,
        });
    }
    let archive_sha256 = sha256_file(&config.archive, MAX_SNAPSHOT_ARCHIVE_BYTES)?;
    let github_evidence = load_optional_evidence(config.github_license_evidence.as_deref())?;
    let rustsec_evidence = load_optional_evidence(config.rustsec_license_evidence.as_deref())?;
    let openssf_evidence = load_optional_evidence(
        config
            .openssf_malicious_packages_license_evidence
            .as_deref(),
    )?;
    let artifact_name = config
        .archive
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(SnapshotError::InvalidPath(
            "archive file name must be valid UTF-8",
        ))?
        .to_owned();

    let temporary = create_temporary_snapshot_directory(&config.output)?;
    let result = prepare_into_directory(
        config,
        &temporary,
        archive_metadata.len(),
        archive_sha256,
        artifact_name,
        github_evidence.as_ref(),
        rustsec_evidence.as_ref(),
        openssf_evidence.as_ref(),
    );
    match result {
        Ok(manifest) => {
            fs::rename(&temporary, &config.output).map_err(|source| SnapshotError::Filesystem {
                path: config.output.clone(),
                source,
            })?;
            Ok(manifest)
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary);
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_into_directory(
    config: &SnapshotPrepareConfig,
    output: &Path,
    archive_bytes: u64,
    archive_sha256: String,
    artifact_name: String,
    github_evidence: Option<&(Vec<u8>, String)>,
    rustsec_evidence: Option<&(Vec<u8>, String)>,
    openssf_evidence: Option<&(Vec<u8>, String)>,
) -> Result<AdvisorySnapshotManifest, SnapshotError> {
    let file = File::open(&config.archive).map_err(|source| SnapshotError::Filesystem {
        path: config.archive.clone(),
        source,
    })?;
    let mut archive = ZipArchive::new(file)?;
    if archive.len() > MAX_IMPORT_RECORDS {
        return Err(SnapshotError::TooManyEntries(MAX_IMPORT_RECORDS));
    }

    let mut seen_names = BTreeSet::new();
    let mut records = Vec::new();
    let mut quarantined = Vec::new();
    let mut source_counts = BTreeMap::<String, (SourceClass, u64)>::new();
    let mut total_uncompressed = 0_u64;
    let mut accepted_bytes = 0_u64;
    let mut quarantined_bytes = 0_u64;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let entry_name = validate_archive_entry(&entry)?;
        if !seen_names.insert(entry_name.clone()) {
            return Err(SnapshotError::DuplicateArchiveEntry(entry_name));
        }
        total_uncompressed = total_uncompressed.checked_add(entry.size()).ok_or(
            SnapshotError::UncompressedTooLarge {
                maximum: MAX_SNAPSHOT_UNCOMPRESSED_BYTES,
            },
        )?;
        if total_uncompressed > MAX_SNAPSHOT_UNCOMPRESSED_BYTES {
            return Err(SnapshotError::UncompressedTooLarge {
                maximum: MAX_SNAPSHOT_UNCOMPRESSED_BYTES,
            });
        }
        let mut bytes = Vec::with_capacity(entry.size().min(MAX_OSV_RECORD_BYTES) as usize);
        entry
            .by_ref()
            .take(MAX_OSV_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| SnapshotError::Filesystem {
                path: config.archive.clone(),
                source,
            })?;
        let raw_sha256 = sha256_bytes(&bytes);
        let decision = classify_record(
            &bytes,
            &entry_name,
            &config.expected_ecosystem,
            openssf_evidence.is_some(),
        );
        match decision {
            Ok((record, ecosystems, class)) => {
                let evidence = match class.evidence_kind {
                    EvidenceKind::Github => github_evidence.ok_or(
                        SnapshotError::MissingLicenseEvidence("GitHub Advisory Database"),
                    )?,
                    EvidenceKind::Rustsec => {
                        rustsec_evidence.ok_or(SnapshotError::MissingLicenseEvidence("RustSec"))?
                    }
                    EvidenceKind::OpenssfMaliciousPackages => openssf_evidence.ok_or(
                        SnapshotError::MissingLicenseEvidence("OpenSSF Malicious Packages"),
                    )?,
                };
                let source_dir = source_slug(&class.name);
                let stored_path = format!("records/{source_dir}/{entry_name}");
                write_private_new(&output.join(&stored_path), &bytes)?;
                accepted_bytes = accepted_bytes.saturating_add(bytes.len() as u64);
                records.push(SnapshotRecord {
                    archive_entry: entry_name,
                    stored_path,
                    source_name: class.name.clone(),
                    id: record.id,
                    modified: record.modified,
                    ecosystems,
                    sha256: raw_sha256,
                    bytes: bytes.len() as u64,
                });
                let count = source_counts
                    .entry(class.name.clone())
                    .or_insert((class, 0));
                count.1 = count.1.saturating_add(1);
                let _ = evidence;
            }
            Err(reason) => {
                let stored_path = format!("quarantine/{entry_name}");
                write_private_new(&output.join(&stored_path), &bytes)?;
                quarantined_bytes = quarantined_bytes.saturating_add(bytes.len() as u64);
                quarantined.push(SnapshotQuarantine {
                    archive_entry: entry_name,
                    stored_path,
                    reason,
                    sha256: raw_sha256,
                    bytes: bytes.len() as u64,
                });
            }
        }
    }

    if records.is_empty() {
        return Err(SnapshotError::InvalidManifest(
            "snapshot contains no accepted records",
        ));
    }
    records.sort();
    quarantined.sort();
    let mut sources = Vec::with_capacity(source_counts.len());
    for (_, (class, record_count)) in source_counts {
        let evidence = match class.evidence_kind {
            EvidenceKind::Github => github_evidence.ok_or(
                SnapshotError::MissingLicenseEvidence("GitHub Advisory Database"),
            )?,
            EvidenceKind::Rustsec => {
                rustsec_evidence.ok_or(SnapshotError::MissingLicenseEvidence("RustSec"))?
            }
            EvidenceKind::OpenssfMaliciousPackages => openssf_evidence.ok_or(
                SnapshotError::MissingLicenseEvidence("OpenSSF Malicious Packages"),
            )?,
        };
        let evidence_path = format!("licenses/{}.txt", evidence.1);
        if !output.join(&evidence_path).exists() {
            write_private_new(&output.join(&evidence_path), &evidence.0)?;
        }
        sources.push(SnapshotSource {
            name: class.name,
            kind: class.kind.to_owned(),
            scope: config.expected_ecosystem.clone(),
            locator: class.locator.to_owned(),
            license_expression: class.license_expression.to_owned(),
            license_evidence_path: evidence_path,
            license_evidence_sha256: evidence.1.clone(),
            record_count,
        });
    }
    sources.sort();
    let accounting = SnapshotAccounting {
        archive_entries: archive.len() as u64,
        accepted_records: records.len() as u64,
        quarantined_records: quarantined.len() as u64,
        accepted_bytes,
        quarantined_bytes,
        uncompressed_bytes: total_uncompressed,
    };
    let artifact = SnapshotArtifact {
        file_name: artifact_name,
        format: "osv-ecosystem-zip".to_owned(),
        locator: config.artifact_locator.clone(),
        revision: config.artifact_revision.clone(),
        sha256: archive_sha256,
        bytes: archive_bytes,
    };
    let snapshot_id = calculate_snapshot_id(
        SNAPSHOT_POLICY_VERSION,
        &config.acquired_at,
        &config.expected_ecosystem,
        &artifact,
        &sources,
        &records,
        &quarantined,
        &accounting,
    )?;
    let manifest = AdvisorySnapshotManifest {
        contract_version: SNAPSHOT_CONTRACT_VERSION.to_owned(),
        policy_version: SNAPSHOT_POLICY_VERSION.to_owned(),
        snapshot_id,
        acquired_at: config.acquired_at.clone(),
        expected_ecosystem: config.expected_ecosystem.clone(),
        artifact,
        sources,
        records,
        quarantined,
        accounting,
        validation_authority: "human-only".to_owned(),
    };
    validate_manifest(&manifest)?;
    let mut bytes = serde_json::to_vec_pretty(&manifest)?;
    bytes.push(b'\n');
    write_private_new(&output.join("manifest.json"), &bytes)?;
    Ok(manifest)
}

pub fn load_and_validate_snapshot(
    manifest_path: &Path,
) -> Result<(AdvisorySnapshotManifest, String), SnapshotError> {
    let metadata = regular_file_metadata(manifest_path)?;
    if metadata.len() == 0 || metadata.len() > MAX_SNAPSHOT_MANIFEST_BYTES {
        return Err(SnapshotError::InvalidManifest(
            "manifest is empty or exceeds the size limit",
        ));
    }
    let bytes = fs::read(manifest_path).map_err(|source| SnapshotError::Filesystem {
        path: manifest_path.to_owned(),
        source,
    })?;
    let manifest: AdvisorySnapshotManifest = serde_json::from_slice(&bytes)?;
    validate_manifest(&manifest)?;
    let root = manifest_path
        .parent()
        .ok_or(SnapshotError::InvalidPath("manifest must have a parent"))?;
    validate_snapshot_files(root, &manifest)?;
    Ok((manifest, sha256_bytes(&bytes)))
}

pub fn validate_snapshot_archive(
    manifest: &AdvisorySnapshotManifest,
    archive: &Path,
) -> Result<(), SnapshotError> {
    let metadata = regular_file_metadata(archive)?;
    if metadata.len() != manifest.artifact.bytes {
        return Err(SnapshotError::FileMismatch(
            "archive byte length changed".to_owned(),
        ));
    }
    let observed = sha256_file(archive, MAX_SNAPSHOT_ARCHIVE_BYTES)?;
    if observed != manifest.artifact.sha256 {
        return Err(SnapshotError::FileMismatch(
            "archive SHA-256 changed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_manifest(manifest: &AdvisorySnapshotManifest) -> Result<(), SnapshotError> {
    if manifest.contract_version != SNAPSHOT_CONTRACT_VERSION
        || !matches!(
            manifest.policy_version.as_str(),
            SNAPSHOT_POLICY_VERSION | LEGACY_SNAPSHOT_POLICY_VERSION
        )
        || manifest.validation_authority != "human-only"
    {
        return Err(SnapshotError::InvalidManifest("contract identity"));
    }
    validate_text(&manifest.acquired_at, 100)?;
    OffsetDateTime::parse(&manifest.acquired_at, &Rfc3339)
        .map_err(|_| SnapshotError::InvalidTimestamp(manifest.acquired_at.clone()))?;
    validate_text(&manifest.expected_ecosystem, 100)?;
    validate_text(&manifest.artifact.file_name, 255)?;
    validate_text(&manifest.artifact.locator, 4_096)?;
    validate_text(&manifest.artifact.revision, 500)?;
    validate_sha256(&manifest.artifact.sha256)?;
    if manifest.artifact.format != "osv-ecosystem-zip"
        || manifest.artifact.bytes == 0
        || manifest.artifact.bytes > MAX_SNAPSHOT_ARCHIVE_BYTES
    {
        return Err(SnapshotError::InvalidManifest("artifact metadata"));
    }
    if manifest.records.is_empty()
        || manifest.records.len() > MAX_IMPORT_RECORDS
        || manifest.records.windows(2).any(|pair| pair[0] >= pair[1])
        || manifest
            .quarantined
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || manifest.sources.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(SnapshotError::InvalidManifest(
            "record/source ordering or limits",
        ));
    }
    let source_names = manifest
        .sources
        .iter()
        .map(|source| source.name.as_str())
        .collect::<BTreeSet<_>>();
    if source_names.len() != manifest.sources.len() {
        return Err(SnapshotError::InvalidManifest("duplicate source"));
    }
    let mut counts = BTreeMap::<&str, u64>::new();
    let mut accepted_bytes = 0_u64;
    let mut paths = BTreeSet::new();
    for source in &manifest.sources {
        validate_text(&source.name, 100)?;
        validate_text(&source.kind, 100)?;
        validate_text(&source.scope, 100)?;
        validate_text(&source.locator, 4_096)?;
        validate_text(&source.license_expression, 200)?;
        validate_relative_path(&source.license_evidence_path, "licenses")?;
        validate_sha256(&source.license_evidence_sha256)?;
        paths.insert(source.license_evidence_path.as_str());
    }
    for record in &manifest.records {
        validate_archive_name(&record.archive_entry)?;
        validate_relative_path(&record.stored_path, "records")?;
        validate_text(&record.source_name, 100)?;
        validate_text(&record.id, 200)?;
        validate_text(&record.modified, 100)?;
        validate_sha256(&record.sha256)?;
        if record.bytes == 0 || record.bytes > MAX_OSV_RECORD_BYTES {
            return Err(SnapshotError::InvalidManifest("record byte limit"));
        }
        if !source_names.contains(record.source_name.as_str())
            || record.ecosystems.is_empty()
            || !record
                .ecosystems
                .iter()
                .any(|value| value == &manifest.expected_ecosystem)
            || !paths.insert(record.stored_path.as_str())
        {
            return Err(SnapshotError::InvalidManifest("record provenance"));
        }
        *counts.entry(&record.source_name).or_default() += 1;
        accepted_bytes = accepted_bytes.saturating_add(record.bytes);
    }
    let mut quarantined_bytes = 0_u64;
    for record in &manifest.quarantined {
        validate_archive_name(&record.archive_entry)?;
        validate_relative_path(&record.stored_path, "quarantine")?;
        validate_text(&record.reason, 200)?;
        validate_sha256(&record.sha256)?;
        if record.bytes == 0
            || record.bytes > MAX_OSV_RECORD_BYTES + 1
            || !paths.insert(record.stored_path.as_str())
        {
            return Err(SnapshotError::InvalidManifest("quarantine provenance"));
        }
        quarantined_bytes = quarantined_bytes.saturating_add(record.bytes);
    }
    if manifest
        .sources
        .iter()
        .any(|source| counts.get(source.name.as_str()).copied().unwrap_or(0) != source.record_count)
        || manifest.accounting.archive_entries
            != manifest.accounting.accepted_records + manifest.accounting.quarantined_records
        || manifest.accounting.accepted_records != manifest.records.len() as u64
        || manifest.accounting.quarantined_records != manifest.quarantined.len() as u64
        || manifest.accounting.accepted_bytes != accepted_bytes
        || manifest.accounting.quarantined_bytes != quarantined_bytes
        || manifest.accounting.uncompressed_bytes != accepted_bytes + quarantined_bytes
    {
        return Err(SnapshotError::InvalidManifest("accounting mismatch"));
    }
    let expected = calculate_snapshot_id(
        &manifest.policy_version,
        &manifest.acquired_at,
        &manifest.expected_ecosystem,
        &manifest.artifact,
        &manifest.sources,
        &manifest.records,
        &manifest.quarantined,
        &manifest.accounting,
    )?;
    if manifest.snapshot_id != expected {
        return Err(SnapshotError::InvalidManifest("snapshot_id mismatch"));
    }
    Ok(())
}

fn validate_snapshot_files(
    root: &Path,
    manifest: &AdvisorySnapshotManifest,
) -> Result<(), SnapshotError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| SnapshotError::Filesystem {
        path: root.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SnapshotError::InvalidPath(
            "snapshot root must be a real directory",
        ));
    }
    let mut expected = BTreeMap::<String, (&str, u64)>::new();
    for source in &manifest.sources {
        expected.insert(
            source.license_evidence_path.clone(),
            (&source.license_evidence_sha256, 0),
        );
    }
    for record in &manifest.records {
        expected.insert(record.stored_path.clone(), (&record.sha256, record.bytes));
    }
    for record in &manifest.quarantined {
        expected.insert(record.stored_path.clone(), (&record.sha256, record.bytes));
    }
    for (relative, (expected_hash, expected_bytes)) in &expected {
        let path = root.join(relative);
        let metadata = regular_file_metadata(&path)?;
        if *expected_bytes != 0 && metadata.len() != *expected_bytes {
            return Err(SnapshotError::FileMismatch(relative.clone()));
        }
        if sha256_file(
            &path,
            MAX_OSV_RECORD_BYTES.max(MAX_LICENSE_EVIDENCE_BYTES) + 1,
        )? != *expected_hash
        {
            return Err(SnapshotError::FileMismatch(relative.clone()));
        }
    }
    let mut observed = BTreeSet::new();
    collect_snapshot_files(root, root, &mut observed, 0)?;
    observed.remove("manifest.json");
    let expected_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
    if let Some(path) = observed.difference(&expected_paths).next() {
        return Err(SnapshotError::UnexpectedFile(path.clone()));
    }
    if let Some(path) = expected_paths.difference(&observed).next() {
        return Err(SnapshotError::FileMismatch(path.clone()));
    }
    Ok(())
}

fn collect_snapshot_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), SnapshotError> {
    if depth > 4 {
        return Err(SnapshotError::InvalidPath("snapshot tree is too deep"));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|source| SnapshotError::Filesystem {
            path: directory.to_owned(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| SnapshotError::Filesystem {
            path: directory.to_owned(),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|source| SnapshotError::Filesystem {
                path: path.clone(),
                source,
            })?;
        if file_type.is_symlink() {
            return Err(SnapshotError::InvalidPath(
                "snapshot tree cannot contain symlinks",
            ));
        }
        if file_type.is_dir() {
            collect_snapshot_files(root, &path, files, depth + 1)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| SnapshotError::InvalidPath("snapshot path escaped root"))?
                .to_str()
                .ok_or(SnapshotError::InvalidPath(
                    "snapshot paths must be valid UTF-8",
                ))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if !files.insert(relative.clone()) {
                return Err(SnapshotError::UnexpectedFile(relative));
            }
        } else {
            return Err(SnapshotError::InvalidPath(
                "snapshot tree contains a special file",
            ));
        }
    }
    Ok(())
}

fn classify_record(
    bytes: &[u8],
    entry_name: &str,
    expected_ecosystem: &str,
    openssf_malicious_packages_enabled: bool,
) -> Result<(OsvRecord, Vec<String>, SourceClass), String> {
    if bytes.is_empty() {
        return Err("empty-record".to_owned());
    }
    if bytes.len() as u64 > MAX_OSV_RECORD_BYTES {
        return Err("record-too-large".to_owned());
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "invalid-json".to_owned())?;
    let record: OsvRecord =
        serde_json::from_value(value.clone()).map_err(|_| "invalid-osv-shape".to_owned())?;
    crate::catalog::validate_osv_record_public(&record)
        .map_err(|_| "invalid-osv-fields".to_owned())?;
    if entry_name != format!("{}.json", record.id) {
        return Err("entry-id-mismatch".to_owned());
    }
    let mut ecosystems = record
        .affected
        .iter()
        .filter_map(|affected| affected.package.as_ref())
        .map(|package| package.ecosystem.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    ecosystems.sort();
    if !ecosystems.iter().any(|value| value == expected_ecosystem) {
        return Err("ecosystem-mismatch".to_owned());
    }
    let scope = source_slug(expected_ecosystem);
    let class = if record.id.starts_with("GHSA-") {
        SourceClass {
            name: format!("github-advisory-database@{scope}"),
            kind: "github-advisory-database",
            locator: "https://github.com/github/advisory-database",
            license_expression: "CC-BY-4.0",
            evidence_kind: EvidenceKind::Github,
        }
    } else if record.id.starts_with("RUSTSEC-") {
        let license = value
            .get("database_specific")
            .and_then(|value| value.get("license"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "rustsec-license-missing".to_owned())?;
        let (suffix, expression) = match license {
            "CC0-1.0" => ("cc0", "CC0-1.0"),
            "CC-BY-4.0" => ("cc-by", "CC-BY-4.0"),
            _ => return Err("rustsec-license-unsupported".to_owned()),
        };
        SourceClass {
            name: format!("rustsec-advisory-db-{suffix}@{scope}"),
            kind: "rustsec-advisory-database",
            locator: "https://github.com/RustSec/advisory-db",
            license_expression: expression,
            evidence_kind: EvidenceKind::Rustsec,
        }
    } else if record.id.starts_with("MAL-") {
        if !openssf_malicious_packages_enabled {
            return Err("malicious-package-license-review-required".to_owned());
        }
        let sources_are_openssf = value
            .get("affected")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|affected| {
                !affected.is_empty()
                    && affected.iter().all(|item| {
                        item.get("database_specific")
                            .and_then(|item| item.get("source"))
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|source| {
                                source
                                    .starts_with("https://github.com/ossf/malicious-packages/blob/")
                                    && source.contains("/osv/malicious/")
                            })
                    })
            });
        if !sources_are_openssf {
            return Err("malicious-package-provenance-not-openssf".to_owned());
        }
        SourceClass {
            name: format!("openssf-malicious-packages@{scope}"),
            kind: "openssf-malicious-packages",
            locator: "https://github.com/ossf/malicious-packages",
            license_expression: "Apache-2.0",
            evidence_kind: EvidenceKind::OpenssfMaliciousPackages,
        }
    } else {
        return Err("unsupported-primary-id".to_owned());
    };
    Ok((record, ecosystems, class))
}

fn validate_archive_entry<R: Read>(
    entry: &zip::read::ZipFile<'_, R>,
) -> Result<String, SnapshotError> {
    let name = entry.name().to_owned();
    validate_archive_name(&name)?;
    if entry.encrypted() {
        return Err(SnapshotError::UnsafeArchiveEntry {
            entry: name,
            reason: "encrypted entries are not accepted",
        });
    }
    if !entry.is_file() || entry.enclosed_name().is_none() {
        return Err(SnapshotError::UnsafeArchiveEntry {
            entry: name,
            reason: "entry is not a regular enclosed file",
        });
    }
    if entry.size() == 0 || entry.size() > MAX_OSV_RECORD_BYTES + 1 {
        return Err(SnapshotError::UnsafeArchiveEntry {
            entry: name,
            reason: "declared size is outside the record limit",
        });
    }
    if entry.compressed_size() > 0
        && entry.size()
            > entry
                .compressed_size()
                .saturating_mul(MAX_ARCHIVE_RATIO)
                .saturating_add(1024 * 1024)
    {
        return Err(SnapshotError::UnsafeArchiveEntry {
            entry: name,
            reason: "compression ratio exceeds policy",
        });
    }
    Ok(name)
}

fn validate_archive_name(name: &str) -> Result<(), SnapshotError> {
    let path = Path::new(name);
    let valid = name.is_ascii()
        && !name.is_empty()
        && name.len() <= 255
        && name.ends_with(".json")
        && !name.contains(['/', '\\', '\0'])
        && path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)));
    if !valid {
        return Err(SnapshotError::UnsafeArchiveEntry {
            entry: name.to_owned(),
            reason: "entry name must be a flat ASCII JSON file",
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn calculate_snapshot_id(
    policy_version: &str,
    acquired_at: &str,
    expected_ecosystem: &str,
    artifact: &SnapshotArtifact,
    sources: &[SnapshotSource],
    records: &[SnapshotRecord],
    quarantined: &[SnapshotQuarantine],
    accounting: &SnapshotAccounting,
) -> Result<String, SnapshotError> {
    #[derive(Serialize)]
    struct Material<'a> {
        domain: &'static str,
        policy_version: &'a str,
        acquired_at: &'a str,
        expected_ecosystem: &'a str,
        artifact: &'a SnapshotArtifact,
        sources: &'a [SnapshotSource],
        records: &'a [SnapshotRecord],
        quarantined: &'a [SnapshotQuarantine],
        accounting: &'a SnapshotAccounting,
    }
    let bytes = serde_json::to_vec(&Material {
        domain: "secureflow-advisory-snapshot-id-v1",
        policy_version,
        acquired_at,
        expected_ecosystem,
        artifact,
        sources,
        records,
        quarantined,
        accounting,
    })?;
    Ok(format!("sf_snapshot_{}", sha256_bytes(&bytes)))
}

fn validate_prepare_config(config: &SnapshotPrepareConfig) -> Result<(), SnapshotError> {
    validate_text(&config.artifact_locator, 4_096)?;
    validate_text(&config.artifact_revision, 500)?;
    validate_text(&config.expected_ecosystem, 100)?;
    validate_text(&config.acquired_at, 100)?;
    OffsetDateTime::parse(&config.acquired_at, &Rfc3339)
        .map_err(|_| SnapshotError::InvalidTimestamp(config.acquired_at.clone()))?;
    if config.output.as_os_str().is_empty() || config.output.file_name().is_none() {
        return Err(SnapshotError::InvalidPath("output must name a directory"));
    }
    match fs::symlink_metadata(&config.output) {
        Ok(_) => Err(SnapshotError::InvalidPath("output already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SnapshotError::Filesystem {
            path: config.output.clone(),
            source,
        }),
    }
}

fn validate_text(value: &str, maximum: usize) -> Result<(), SnapshotError> {
    if value.trim().is_empty()
        || value.chars().count() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(SnapshotError::InvalidConfiguration("bounded text field"));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), SnapshotError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SnapshotError::InvalidManifest("SHA-256"));
    }
    Ok(())
}

fn validate_relative_path(value: &str, prefix: &str) -> Result<(), SnapshotError> {
    let path = Path::new(value);
    if !value.starts_with(&format!("{prefix}/"))
        || value.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SnapshotError::InvalidManifest("relative path"));
    }
    Ok(())
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata, SnapshotError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SnapshotError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SnapshotError::InvalidPath(
            "expected a regular non-symlink file",
        ));
    }
    Ok(metadata)
}

fn load_optional_evidence(path: Option<&Path>) -> Result<Option<(Vec<u8>, String)>, SnapshotError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let metadata = regular_file_metadata(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_LICENSE_EVIDENCE_BYTES {
        return Err(SnapshotError::InvalidConfiguration("license evidence size"));
    }
    let bytes = fs::read(path).map_err(|source| SnapshotError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    let hash = sha256_bytes(&bytes);
    Ok(Some((bytes, hash)))
}

fn sha256_file(path: &Path, maximum: u64) -> Result<String, SnapshotError> {
    let metadata = regular_file_metadata(path)?;
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(SnapshotError::ArchiveTooLarge {
            bytes: metadata.len(),
            maximum,
        });
    }
    let mut file = File::open(path).map_err(|source| SnapshotError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| SnapshotError::Filesystem {
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > maximum {
            return Err(SnapshotError::ArchiveTooLarge {
                bytes: total,
                maximum,
            });
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

fn source_slug(value: &str) -> String {
    let mut slug = String::with_capacity(value.len());
    let mut previous_dash = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }
    slug.trim_matches('-').to_owned()
}

fn create_temporary_snapshot_directory(output: &Path) -> Result<PathBuf, SnapshotError> {
    let parent = output
        .parent()
        .ok_or(SnapshotError::InvalidPath("output must have a parent"))?;
    create_private_directories(parent)?;
    let name =
        output
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(SnapshotError::InvalidPath(
                "output file name must be valid UTF-8",
            ))?;
    let nonce = OffsetDateTime::now_utc().unix_timestamp_nanos();
    for attempt in 0..100_u32 {
        let candidate = parent.join(format!(
            ".{name}.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match create_private_directory(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(SnapshotError::Filesystem { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(SnapshotError::InvalidPath(
        "could not allocate a temporary output directory",
    ))
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), SnapshotError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|source| SnapshotError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), SnapshotError> {
    fs::create_dir(path).map_err(|source| SnapshotError::Filesystem {
        path: path.to_owned(),
        source,
    })
}

#[cfg(unix)]
fn create_private_directories(path: &Path) -> Result<(), SnapshotError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|source| SnapshotError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
fn create_private_directories(path: &Path) -> Result<(), SnapshotError> {
    fs::create_dir_all(path).map_err(|source| SnapshotError::Filesystem {
        path: path.to_owned(),
        source,
    })
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), SnapshotError> {
    let parent = path
        .parent()
        .ok_or(SnapshotError::InvalidPath("output file must have a parent"))?;
    create_private_directories(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| SnapshotError::Filesystem {
            path: path.to_owned(),
            source,
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| SnapshotError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    fn temporary_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "secureflow-snapshot-{label}-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))
    }

    fn osv(id: &str, ecosystem: &str, license: Option<&str>) -> Vec<u8> {
        let mut value = serde_json::json!({
            "schema_version": "1.7.3",
            "id": id,
            "modified": "2026-08-23T00:00:00Z",
            "summary": "bounded fixture",
            "affected": [{
                "package": {"ecosystem": ecosystem, "name": "fixture"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
            }]
        });
        if let Some(license) = license {
            value["database_specific"] = serde_json::json!({"license": license});
        }
        serde_json::to_vec(&value).expect("fixture JSON")
    }

    fn write_zip(path: &Path, entries: &[(&str, Vec<u8>)]) {
        let file = File::create(path).expect("ZIP file");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, bytes) in entries {
            writer.start_file(*name, options).expect("ZIP entry");
            writer.write_all(bytes).expect("ZIP bytes");
        }
        writer.finish().expect("finish ZIP");
    }

    fn config(archive: PathBuf, output: PathBuf, evidence: PathBuf) -> SnapshotPrepareConfig {
        SnapshotPrepareConfig {
            archive,
            output,
            artifact_locator:
                "https://storage.googleapis.com/osv-vulnerabilities/crates.io/all.zip".into(),
            artifact_revision: "gcs-generation:fixture".into(),
            expected_ecosystem: "crates.io".into(),
            acquired_at: "2026-08-23T00:00:00Z".into(),
            github_license_evidence: Some(evidence.clone()),
            rustsec_license_evidence: Some(evidence),
            openssf_malicious_packages_license_evidence: None,
        }
    }

    #[test]
    fn prepares_attributed_records_and_preserves_quarantine() {
        let root = temporary_path("prepare");
        fs::create_dir(&root).expect("root");
        let archive = root.join("source.zip");
        let evidence = root.join("LICENSE");
        fs::write(&evidence, "fixture license evidence").expect("license");
        write_zip(
            &archive,
            &[
                (
                    "GHSA-aaaa-bbbb-cccc.json",
                    osv("GHSA-aaaa-bbbb-cccc", "crates.io", None),
                ),
                (
                    "RUSTSEC-2026-0001.json",
                    osv("RUSTSEC-2026-0001", "crates.io", Some("CC0-1.0")),
                ),
                ("MAL-2026-1.json", osv("MAL-2026-1", "crates.io", None)),
            ],
        );
        let output = root.join("snapshot");
        let manifest =
            prepare_osv_zip(&config(archive.clone(), output.clone(), evidence)).expect("snapshot");
        assert_eq!(manifest.accounting.accepted_records, 2);
        assert_eq!(manifest.accounting.quarantined_records, 1);
        assert_eq!(manifest.sources.len(), 2);
        assert_eq!(
            manifest.quarantined[0].reason,
            "malicious-package-license-review-required"
        );
        let (loaded, _) =
            load_and_validate_snapshot(&output.join("manifest.json")).expect("validated snapshot");
        assert_eq!(loaded.snapshot_id, manifest.snapshot_id);
        validate_snapshot_archive(&loaded, &archive).expect("archive hash");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn validates_a_legacy_policy_snapshot_with_its_original_identity_domain() {
        let root = temporary_path("legacy-policy");
        fs::create_dir(&root).expect("root");
        let archive = root.join("source.zip");
        let evidence = root.join("LICENSE");
        fs::write(&evidence, "fixture license evidence").expect("license");
        write_zip(
            &archive,
            &[(
                "GHSA-aaaa-bbbb-cccc.json",
                osv("GHSA-aaaa-bbbb-cccc", "crates.io", None),
            )],
        );
        let output = root.join("snapshot");
        let mut manifest =
            prepare_osv_zip(&config(archive, output.clone(), evidence)).expect("snapshot");
        let current_id = manifest.snapshot_id.clone();
        manifest.policy_version = LEGACY_SNAPSHOT_POLICY_VERSION.to_owned();
        manifest.snapshot_id = calculate_snapshot_id(
            &manifest.policy_version,
            &manifest.acquired_at,
            &manifest.expected_ecosystem,
            &manifest.artifact,
            &manifest.sources,
            &manifest.records,
            &manifest.quarantined,
            &manifest.accounting,
        )
        .expect("legacy snapshot identity");
        assert_ne!(manifest.snapshot_id, current_id);
        let mut bytes = serde_json::to_vec_pretty(&manifest).expect("manifest JSON");
        bytes.push(b'\n');
        fs::write(output.join("manifest.json"), bytes).expect("replace test manifest");
        let (loaded, _) =
            load_and_validate_snapshot(&output.join("manifest.json")).expect("legacy snapshot");
        assert_eq!(loaded.snapshot_id, manifest.snapshot_id);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rejects_path_traversal_before_writing_output() {
        let root = temporary_path("traversal");
        fs::create_dir(&root).expect("root");
        let archive = root.join("source.zip");
        let evidence = root.join("LICENSE");
        fs::write(&evidence, "fixture license evidence").expect("license");
        write_zip(
            &archive,
            &[(
                "../GHSA-aaaa-bbbb-cccc.json",
                osv("GHSA-aaaa-bbbb-cccc", "crates.io", None),
            )],
        );
        let output = root.join("snapshot");
        assert!(matches!(
            prepare_osv_zip(&config(archive, output.clone(), evidence)),
            Err(SnapshotError::UnsafeArchiveEntry { .. })
        ));
        assert!(!output.exists());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn accepts_malicious_package_only_with_openssf_evidence_and_record_provenance() {
        let root = temporary_path("openssf-malicious");
        fs::create_dir(&root).expect("root");
        let archive = root.join("source.zip");
        let evidence = root.join("LICENSE");
        fs::write(&evidence, "Apache License Version 2.0").expect("license");
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema_version": "1.7.3",
            "id": "MAL-2026-1",
            "modified": "2026-08-23T00:00:00Z",
            "summary": "bounded fixture",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "fixture"},
                "database_specific": {
                    "source": "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/fixture/MAL-2026-1.json"
                }
            }]
        }))
        .expect("fixture JSON");
        write_zip(&archive, &[("MAL-2026-1.json", bytes)]);
        let output = root.join("snapshot");
        let mut config = config(archive, output, evidence.clone());
        config.expected_ecosystem = "npm".into();
        config.openssf_malicious_packages_license_evidence = Some(evidence);
        let manifest = prepare_osv_zip(&config).expect("OpenSSF snapshot");
        assert_eq!(manifest.accounting.accepted_records, 1);
        assert_eq!(manifest.accounting.quarantined_records, 0);
        assert_eq!(manifest.sources[0].license_expression, "Apache-2.0");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn validation_detects_tampering_and_unexpected_files() {
        let root = temporary_path("tamper");
        fs::create_dir(&root).expect("root");
        let archive = root.join("source.zip");
        let evidence = root.join("LICENSE");
        fs::write(&evidence, "fixture license evidence").expect("license");
        write_zip(
            &archive,
            &[(
                "GHSA-aaaa-bbbb-cccc.json",
                osv("GHSA-aaaa-bbbb-cccc", "crates.io", None),
            )],
        );
        let output = root.join("snapshot");
        let manifest =
            prepare_osv_zip(&config(archive, output.clone(), evidence)).expect("snapshot");
        fs::write(output.join(&manifest.records[0].stored_path), "tampered").expect("tamper");
        assert!(matches!(
            load_and_validate_snapshot(&output.join("manifest.json")),
            Err(SnapshotError::FileMismatch(_))
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
