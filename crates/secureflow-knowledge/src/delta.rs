//! Reproducible preparation of local OSV `modified_id.csv` updates.
//!
//! Acquisition remains outside SecureFlow. A delta is accepted only when the
//! per-ecosystem index, every selected JSON payload and the applicable license
//! evidence are present locally and agree byte-for-byte with the manifest.
//! Missing payloads are never interpreted as deletions.

use crate::catalog::{MAX_IMPORT_RECORDS, MAX_OSV_RECORD_BYTES, OsvRecord};
use crate::snapshot::{EvidenceKind, classify_record, source_slug};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const DELTA_CONTRACT_VERSION: &str = "secureflow-advisory-delta-v1";
pub const DELTA_POLICY_VERSION: &str = "osv-per-ecosystem-modified-index-v1";
pub const MAX_DELTA_INDEX_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_DELTA_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;
const MAX_LICENSE_EVIDENCE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct DeltaPrepareConfig {
    pub modified_index: PathBuf,
    pub records: PathBuf,
    pub output: PathBuf,
    pub index_locator: String,
    pub index_revision: String,
    pub expected_ecosystem: String,
    pub acquired_at: String,
    pub after_modified: String,
    pub base_snapshot_id: String,
    pub previous_delta_id: Option<String>,
    pub github_license_evidence: Option<PathBuf>,
    pub rustsec_license_evidence: Option<PathBuf>,
    pub openssf_malicious_packages_license_evidence: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryDeltaManifest {
    pub contract_version: String,
    pub policy_version: String,
    pub delta_id: String,
    pub acquired_at: String,
    pub expected_ecosystem: String,
    pub base_snapshot_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_delta_id: Option<String>,
    pub cursor: DeltaCursor,
    pub index: DeltaIndexArtifact,
    pub sources: Vec<DeltaSource>,
    pub records: Vec<DeltaRecord>,
    pub quarantined: Vec<DeltaQuarantine>,
    pub accounting: DeltaAccounting,
    pub semantics: DeltaSemantics,
    pub validation_authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaCursor {
    pub after_modified_exclusive: String,
    pub through_modified_inclusive: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaIndexArtifact {
    pub stored_path: String,
    pub format: String,
    pub scope: String,
    pub locator: String,
    pub revision: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaSource {
    pub name: String,
    pub kind: String,
    pub scope: String,
    pub locator: String,
    pub license_expression: String,
    pub license_evidence_path: String,
    pub license_evidence_sha256: String,
    pub record_count: u64,
    pub withdrawn_records: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaRecord {
    pub index_line: u64,
    pub index_modified: String,
    pub stored_path: String,
    pub source_name: String,
    pub id: String,
    pub modified: String,
    pub withdrawn: bool,
    pub ecosystems: Vec<String>,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaQuarantine {
    pub index_line: u64,
    pub index_modified: String,
    pub id: String,
    pub stored_path: String,
    pub reason: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaAccounting {
    pub index_entries: u64,
    pub selected_entries: u64,
    pub accepted_records: u64,
    pub quarantined_records: u64,
    pub withdrawn_records: u64,
    pub accepted_bytes: u64,
    pub quarantined_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaSemantics {
    pub absence_deactivates_record: bool,
    pub explicit_withdrawn_is_retained: bool,
    pub cursor_advances_only_without_quarantine: bool,
    pub full_snapshot_required_for_absence: bool,
}

#[derive(Clone, Debug)]
struct IndexEntry {
    line: u64,
    modified_text: String,
    modified: OffsetDateTime,
    id: String,
}

#[derive(Debug, Error)]
pub enum DeltaError {
    #[error("advisory delta configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    #[error("advisory delta path is invalid: {0}")]
    InvalidPath(&'static str),
    #[error("advisory delta filesystem operation failed for {path}: {source}")]
    Filesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("advisory delta JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("advisory delta index is not UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("advisory delta index line {line} is invalid: {reason}")]
    InvalidIndex { line: u64, reason: &'static str },
    #[error("advisory delta index is not reverse chronological at line {0}")]
    IndexOrder(u64),
    #[error("advisory delta index contains duplicate ID: {0}")]
    DuplicateId(String),
    #[error("advisory delta has no records newer than the exclusive cursor")]
    NoChanges,
    #[error("advisory delta payload is missing: {0}")]
    MissingPayload(String),
    #[error("advisory delta input contains an unexpected payload: {0}")]
    UnexpectedPayload(String),
    #[error("advisory delta manifest is invalid: {0}")]
    InvalidManifest(&'static str),
    #[error("advisory delta file does not match its manifest: {0}")]
    FileMismatch(String),
    #[error("advisory delta contains an unexpected file: {0}")]
    UnexpectedFile(String),
    #[error("required license evidence is missing for {0}")]
    MissingLicenseEvidence(&'static str),
}

pub fn prepare_osv_delta(config: &DeltaPrepareConfig) -> Result<AdvisoryDeltaManifest, DeltaError> {
    validate_prepare_config(config)?;
    let index_bytes = read_bounded_regular(&config.modified_index, MAX_DELTA_INDEX_BYTES)?;
    let index_sha256 = sha256_bytes(&index_bytes);
    let entries = parse_index(&index_bytes)?;
    let after = parse_timestamp(&config.after_modified, "after_modified")?;
    let acquired = parse_timestamp(&config.acquired_at, "acquired_at")?;
    let selected = entries
        .iter()
        .filter(|entry| entry.modified > after)
        .cloned()
        .collect::<Vec<_>>();
    let through = selected
        .first()
        .map(|entry| entry.modified)
        .ok_or(DeltaError::NoChanges)?;
    if through > acquired {
        return Err(DeltaError::InvalidConfiguration(
            "index contains a modification newer than acquisition",
        ));
    }
    validate_payload_directory(&config.records, &selected)?;

    let github_evidence = load_optional_evidence(config.github_license_evidence.as_deref())?;
    let rustsec_evidence = load_optional_evidence(config.rustsec_license_evidence.as_deref())?;
    let openssf_evidence = load_optional_evidence(
        config
            .openssf_malicious_packages_license_evidence
            .as_deref(),
    )?;
    let temporary = create_temporary_directory(&config.output)?;
    let result = prepare_into_directory(
        config,
        &temporary,
        &index_bytes,
        index_sha256,
        entries.len() as u64,
        &selected,
        through,
        github_evidence.as_ref(),
        rustsec_evidence.as_ref(),
        openssf_evidence.as_ref(),
    );
    match result {
        Ok(manifest) => {
            fs::rename(&temporary, &config.output).map_err(|source| DeltaError::Filesystem {
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
    config: &DeltaPrepareConfig,
    output: &Path,
    index_bytes: &[u8],
    index_sha256: String,
    index_entries: u64,
    selected: &[IndexEntry],
    through: OffsetDateTime,
    github_evidence: Option<&(Vec<u8>, String)>,
    rustsec_evidence: Option<&(Vec<u8>, String)>,
    openssf_evidence: Option<&(Vec<u8>, String)>,
) -> Result<AdvisoryDeltaManifest, DeltaError> {
    let mut records = Vec::new();
    let mut quarantined = Vec::new();
    let mut source_counts = BTreeMap::new();
    let mut accepted_bytes = 0_u64;
    let mut quarantined_bytes = 0_u64;
    let mut withdrawn_records = 0_u64;

    write_private_new(&output.join("index/modified_id.csv"), index_bytes)?;
    for entry in selected {
        let input = config.records.join(format!("{}.json", entry.id));
        let bytes = read_bounded_regular(&input, MAX_OSV_RECORD_BYTES + 1)?;
        let raw_sha256 = sha256_bytes(&bytes);
        let parsed = serde_json::from_slice::<OsvRecord>(&bytes)
            .map_err(|_| "invalid-osv-shape".to_owned())
            .and_then(|record| {
                crate::catalog::validate_osv_record_public(&record)
                    .map_err(|_| "invalid-osv-fields".to_owned())?;
                if record.id != entry.id {
                    return Err("payload-id-mismatch".to_owned());
                }
                let modified = OffsetDateTime::parse(&record.modified, &Rfc3339)
                    .map_err(|_| "payload-modified-invalid".to_owned())?;
                if modified != entry.modified {
                    return Err("payload-modified-index-mismatch".to_owned());
                }
                Ok(record)
            });
        let classified = parsed.and_then(|record| {
            classify_record(
                &bytes,
                &format!("{}.json", entry.id),
                &config.expected_ecosystem,
                openssf_evidence.is_some(),
            )
            .map(|(_, ecosystems, class)| (record, ecosystems, class))
        });
        match classified {
            Ok((record, ecosystems, class)) => {
                let evidence = evidence_for(
                    class.evidence_kind,
                    github_evidence,
                    rustsec_evidence,
                    openssf_evidence,
                )?;
                let stored_path = format!("records/{}/{}.json", source_slug(&class.name), entry.id);
                write_private_new(&output.join(&stored_path), &bytes)?;
                accepted_bytes = accepted_bytes.saturating_add(bytes.len() as u64);
                let withdrawn = record.withdrawn.is_some();
                withdrawn_records += u64::from(withdrawn);
                records.push(DeltaRecord {
                    index_line: entry.line,
                    index_modified: entry.modified_text.clone(),
                    stored_path,
                    source_name: class.name.clone(),
                    id: record.id,
                    modified: record.modified,
                    withdrawn,
                    ecosystems,
                    sha256: raw_sha256,
                    bytes: bytes.len() as u64,
                });
                let state = source_counts
                    .entry(class.name.clone())
                    .or_insert((class, 0_u64, 0_u64));
                state.1 += 1;
                state.2 += u64::from(withdrawn);
                let _ = evidence;
            }
            Err(reason) => {
                let stored_path = format!("quarantine/{}.json", entry.id);
                write_private_new(&output.join(&stored_path), &bytes)?;
                quarantined_bytes = quarantined_bytes.saturating_add(bytes.len() as u64);
                quarantined.push(DeltaQuarantine {
                    index_line: entry.line,
                    index_modified: entry.modified_text.clone(),
                    id: entry.id.clone(),
                    stored_path,
                    reason,
                    sha256: raw_sha256,
                    bytes: bytes.len() as u64,
                });
            }
        }
    }
    if records.is_empty() {
        return Err(DeltaError::InvalidManifest(
            "delta contains no accepted records",
        ));
    }
    records.sort();
    quarantined.sort();

    let mut sources = Vec::new();
    for (_, (class, record_count, source_withdrawn)) in source_counts {
        let evidence = evidence_for(
            class.evidence_kind,
            github_evidence,
            rustsec_evidence,
            openssf_evidence,
        )?;
        let evidence_path = format!("licenses/{}.txt", evidence.1);
        if !output.join(&evidence_path).exists() {
            write_private_new(&output.join(&evidence_path), &evidence.0)?;
        }
        sources.push(DeltaSource {
            name: class.name,
            kind: class.kind.to_owned(),
            scope: config.expected_ecosystem.clone(),
            locator: class.locator.to_owned(),
            license_expression: class.license_expression.to_owned(),
            license_evidence_path: evidence_path,
            license_evidence_sha256: evidence.1.clone(),
            record_count,
            withdrawn_records: source_withdrawn,
        });
    }
    sources.sort();
    let accounting = DeltaAccounting {
        index_entries,
        selected_entries: selected.len() as u64,
        accepted_records: records.len() as u64,
        quarantined_records: quarantined.len() as u64,
        withdrawn_records,
        accepted_bytes,
        quarantined_bytes,
    };
    let cursor = DeltaCursor {
        after_modified_exclusive: config.after_modified.clone(),
        through_modified_inclusive: through
            .format(&Rfc3339)
            .map_err(|_| DeltaError::InvalidConfiguration("through timestamp"))?,
    };
    let index = DeltaIndexArtifact {
        stored_path: "index/modified_id.csv".into(),
        format: "osv-per-ecosystem-modified-id-csv".into(),
        scope: "per-ecosystem".into(),
        locator: config.index_locator.clone(),
        revision: config.index_revision.clone(),
        sha256: index_sha256,
        bytes: index_bytes.len() as u64,
    };
    let semantics = DeltaSemantics {
        absence_deactivates_record: false,
        explicit_withdrawn_is_retained: true,
        cursor_advances_only_without_quarantine: true,
        full_snapshot_required_for_absence: true,
    };
    let delta_id = calculate_delta_id(
        &config.acquired_at,
        &config.expected_ecosystem,
        &config.base_snapshot_id,
        config.previous_delta_id.as_deref(),
        &cursor,
        &index,
        &sources,
        &records,
        &quarantined,
        &accounting,
        &semantics,
    )?;
    let manifest = AdvisoryDeltaManifest {
        contract_version: DELTA_CONTRACT_VERSION.into(),
        policy_version: DELTA_POLICY_VERSION.into(),
        delta_id,
        acquired_at: config.acquired_at.clone(),
        expected_ecosystem: config.expected_ecosystem.clone(),
        base_snapshot_id: config.base_snapshot_id.clone(),
        previous_delta_id: config.previous_delta_id.clone(),
        cursor,
        index,
        sources,
        records,
        quarantined,
        accounting,
        semantics,
        validation_authority: "human-only".into(),
    };
    validate_manifest(&manifest)?;
    let mut bytes = serde_json::to_vec_pretty(&manifest)?;
    bytes.push(b'\n');
    write_private_new(&output.join("manifest.json"), &bytes)?;
    Ok(manifest)
}

pub fn load_and_validate_delta(
    manifest_path: &Path,
) -> Result<(AdvisoryDeltaManifest, String), DeltaError> {
    let bytes = read_bounded_regular(manifest_path, MAX_DELTA_MANIFEST_BYTES)?;
    let manifest: AdvisoryDeltaManifest = serde_json::from_slice(&bytes)?;
    validate_manifest(&manifest)?;
    let root = manifest_path
        .parent()
        .ok_or(DeltaError::InvalidPath("manifest must have a parent"))?;
    validate_files(root, &manifest)?;
    Ok((manifest, sha256_bytes(&bytes)))
}

fn parse_index(bytes: &[u8]) -> Result<Vec<IndexEntry>, DeltaError> {
    let text = std::str::from_utf8(bytes)?;
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut previous = None;
    for (offset, raw_line) in text.lines().enumerate() {
        let line = (offset + 1) as u64;
        let raw_line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if raw_line.is_empty() || raw_line.len() > 800 {
            return Err(DeltaError::InvalidIndex {
                line,
                reason: "line is empty or too long",
            });
        }
        let (modified_text, id) = raw_line.split_once(',').ok_or(DeltaError::InvalidIndex {
            line,
            reason: "expected <RFC3339>,<ID>",
        })?;
        if id.contains(',') || !safe_id(id) {
            return Err(DeltaError::InvalidIndex {
                line,
                reason: "ID is not a safe flat file name",
            });
        }
        let modified = OffsetDateTime::parse(modified_text, &Rfc3339).map_err(|_| {
            DeltaError::InvalidIndex {
                line,
                reason: "timestamp is not RFC3339",
            }
        })?;
        if previous.is_some_and(|value| modified > value) {
            return Err(DeltaError::IndexOrder(line));
        }
        previous = Some(modified);
        if !seen.insert(id.to_owned()) {
            return Err(DeltaError::DuplicateId(id.to_owned()));
        }
        entries.push(IndexEntry {
            line,
            modified_text: modified_text.to_owned(),
            modified,
            id: id.to_owned(),
        });
        if entries.len() > MAX_IMPORT_RECORDS {
            return Err(DeltaError::InvalidConfiguration("too many index entries"));
        }
    }
    if entries.is_empty() {
        return Err(DeltaError::InvalidConfiguration("empty modified index"));
    }
    Ok(entries)
}

fn validate_payload_directory(root: &Path, selected: &[IndexEntry]) -> Result<(), DeltaError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| DeltaError::Filesystem {
        path: root.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DeltaError::InvalidPath(
            "records must be a real flat directory",
        ));
    }
    let expected = selected
        .iter()
        .map(|entry| format!("{}.json", entry.id))
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for item in fs::read_dir(root).map_err(|source| DeltaError::Filesystem {
        path: root.to_owned(),
        source,
    })? {
        let item = item.map_err(|source| DeltaError::Filesystem {
            path: root.to_owned(),
            source,
        })?;
        let file_type = item.file_type().map_err(|source| DeltaError::Filesystem {
            path: item.path(),
            source,
        })?;
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| DeltaError::InvalidPath("payload name must be UTF-8"))?;
        if file_type.is_symlink() || !file_type.is_file() || !observed.insert(name.clone()) {
            return Err(DeltaError::UnexpectedPayload(name));
        }
    }
    if let Some(missing) = expected.difference(&observed).next() {
        return Err(DeltaError::MissingPayload(missing.clone()));
    }
    if let Some(extra) = observed.difference(&expected).next() {
        return Err(DeltaError::UnexpectedPayload(extra.clone()));
    }
    Ok(())
}

fn validate_manifest(manifest: &AdvisoryDeltaManifest) -> Result<(), DeltaError> {
    if manifest.contract_version != DELTA_CONTRACT_VERSION
        || manifest.policy_version != DELTA_POLICY_VERSION
        || manifest.validation_authority != "human-only"
        || !prefixed_hash(&manifest.delta_id, "sf_delta_")
        || !prefixed_hash(&manifest.base_snapshot_id, "sf_snapshot_")
        || manifest
            .previous_delta_id
            .as_ref()
            .is_some_and(|value| !prefixed_hash(value, "sf_delta_"))
    {
        return Err(DeltaError::InvalidManifest("identity"));
    }
    validate_text(&manifest.expected_ecosystem, 100)?;
    let acquired = parse_timestamp(&manifest.acquired_at, "acquired_at")?;
    let after = parse_timestamp(
        &manifest.cursor.after_modified_exclusive,
        "after_modified_exclusive",
    )?;
    let through = parse_timestamp(
        &manifest.cursor.through_modified_inclusive,
        "through_modified_inclusive",
    )?;
    if after >= through || through > acquired {
        return Err(DeltaError::InvalidManifest("cursor"));
    }
    if manifest.index.format != "osv-per-ecosystem-modified-id-csv"
        || manifest.index.scope != "per-ecosystem"
        || manifest.index.stored_path != "index/modified_id.csv"
        || manifest.index.bytes == 0
        || manifest.index.bytes > MAX_DELTA_INDEX_BYTES
        || !valid_sha256(&manifest.index.sha256)
    {
        return Err(DeltaError::InvalidManifest("index"));
    }
    validate_text(&manifest.index.locator, 4_096)?;
    validate_text(&manifest.index.revision, 500)?;
    if manifest.records.is_empty()
        || manifest.sources.is_empty()
        || manifest.sources.len() > 100
        || manifest
            .records
            .len()
            .saturating_add(manifest.quarantined.len())
            > MAX_IMPORT_RECORDS
        || manifest.records.windows(2).any(|pair| pair[0] >= pair[1])
        || manifest
            .quarantined
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || manifest.sources.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(DeltaError::InvalidManifest("ordering or empty records"));
    }
    let source_names = manifest
        .sources
        .iter()
        .map(|source| source.name.as_str())
        .collect::<BTreeSet<_>>();
    if source_names.len() != manifest.sources.len() {
        return Err(DeltaError::InvalidManifest("duplicate source"));
    }
    let mut paths = BTreeSet::from([manifest.index.stored_path.as_str()]);
    let mut license_paths = BTreeMap::<&str, &str>::new();
    let mut ids = BTreeSet::new();
    let mut counts = BTreeMap::<&str, (u64, u64)>::new();
    let mut accepted_bytes = 0_u64;
    let mut withdrawn_records = 0_u64;
    for source in &manifest.sources {
        validate_text(&source.name, 100)?;
        validate_text(&source.kind, 100)?;
        validate_text(&source.scope, 100)?;
        validate_text(&source.locator, 4_096)?;
        validate_text(&source.license_expression, 200)?;
        validate_relative_path(&source.license_evidence_path, "licenses")?;
        let conflicting_evidence = license_paths
            .insert(
                source.license_evidence_path.as_str(),
                source.license_evidence_sha256.as_str(),
            )
            .is_some_and(|existing| existing != source.license_evidence_sha256);
        if source.scope != manifest.expected_ecosystem
            || source.record_count == 0
            || !valid_sha256(&source.license_evidence_sha256)
            || conflicting_evidence
        {
            return Err(DeltaError::InvalidManifest("source"));
        }
        paths.insert(&source.license_evidence_path);
    }
    for record in &manifest.records {
        validate_record_common(
            RecordValidation {
                line: record.index_line,
                index_modified: &record.index_modified,
                id: &record.id,
                stored_path: &record.stored_path,
                sha256: &record.sha256,
                bytes: record.bytes,
                maximum_bytes: MAX_OSV_RECORD_BYTES,
                prefix: "records",
            },
            after,
            through,
        )?;
        let modified = parse_timestamp(&record.modified, "record.modified")?;
        let index_modified = parse_timestamp(&record.index_modified, "record.index_modified")?;
        if modified != index_modified
            || !source_names.contains(record.source_name.as_str())
            || record.ecosystems.is_empty()
            || !record
                .ecosystems
                .iter()
                .any(|value| value == &manifest.expected_ecosystem)
            || !ids.insert(record.id.as_str())
            || !paths.insert(record.stored_path.as_str())
        {
            return Err(DeltaError::InvalidManifest("record"));
        }
        let count = counts.entry(&record.source_name).or_default();
        count.0 += 1;
        count.1 += u64::from(record.withdrawn);
        accepted_bytes = accepted_bytes.saturating_add(record.bytes);
        withdrawn_records += u64::from(record.withdrawn);
    }
    let mut quarantined_bytes = 0_u64;
    for record in &manifest.quarantined {
        validate_record_common(
            RecordValidation {
                line: record.index_line,
                index_modified: &record.index_modified,
                id: &record.id,
                stored_path: &record.stored_path,
                sha256: &record.sha256,
                bytes: record.bytes,
                maximum_bytes: MAX_OSV_RECORD_BYTES + 1,
                prefix: "quarantine",
            },
            after,
            through,
        )?;
        validate_text(&record.reason, 200)?;
        if !ids.insert(record.id.as_str()) || !paths.insert(record.stored_path.as_str()) {
            return Err(DeltaError::InvalidManifest("quarantine"));
        }
        quarantined_bytes = quarantined_bytes.saturating_add(record.bytes);
    }
    if manifest.sources.iter().any(|source| {
        counts
            .get(source.name.as_str())
            .copied()
            .unwrap_or_default()
            != (source.record_count, source.withdrawn_records)
    }) || manifest.accounting.selected_entries
        != manifest.accounting.accepted_records + manifest.accounting.quarantined_records
        || manifest.accounting.accepted_records != manifest.records.len() as u64
        || manifest.accounting.quarantined_records != manifest.quarantined.len() as u64
        || manifest.accounting.withdrawn_records != withdrawn_records
        || manifest.accounting.accepted_bytes != accepted_bytes
        || manifest.accounting.quarantined_bytes != quarantined_bytes
        || manifest.accounting.index_entries < manifest.accounting.selected_entries
        || manifest.semantics.absence_deactivates_record
        || !manifest.semantics.explicit_withdrawn_is_retained
        || !manifest.semantics.cursor_advances_only_without_quarantine
        || !manifest.semantics.full_snapshot_required_for_absence
    {
        return Err(DeltaError::InvalidManifest("accounting or semantics"));
    }
    let expected = calculate_delta_id(
        &manifest.acquired_at,
        &manifest.expected_ecosystem,
        &manifest.base_snapshot_id,
        manifest.previous_delta_id.as_deref(),
        &manifest.cursor,
        &manifest.index,
        &manifest.sources,
        &manifest.records,
        &manifest.quarantined,
        &manifest.accounting,
        &manifest.semantics,
    )?;
    if manifest.delta_id != expected {
        return Err(DeltaError::InvalidManifest("delta_id"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn calculate_delta_id(
    acquired_at: &str,
    expected_ecosystem: &str,
    base_snapshot_id: &str,
    previous_delta_id: Option<&str>,
    cursor: &DeltaCursor,
    index: &DeltaIndexArtifact,
    sources: &[DeltaSource],
    records: &[DeltaRecord],
    quarantined: &[DeltaQuarantine],
    accounting: &DeltaAccounting,
    semantics: &DeltaSemantics,
) -> Result<String, DeltaError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        domain: &'static str,
        policy_version: &'static str,
        acquired_at: &'a str,
        expected_ecosystem: &'a str,
        base_snapshot_id: &'a str,
        previous_delta_id: Option<&'a str>,
        cursor: &'a DeltaCursor,
        index: &'a DeltaIndexArtifact,
        sources: &'a [DeltaSource],
        records: &'a [DeltaRecord],
        quarantined: &'a [DeltaQuarantine],
        accounting: &'a DeltaAccounting,
        semantics: &'a DeltaSemantics,
    }
    let bytes = serde_json::to_vec(&Identity {
        domain: "secureflow-advisory-delta-id-v1",
        policy_version: DELTA_POLICY_VERSION,
        acquired_at,
        expected_ecosystem,
        base_snapshot_id,
        previous_delta_id,
        cursor,
        index,
        sources,
        records,
        quarantined,
        accounting,
        semantics,
    })?;
    Ok(format!("sf_delta_{}", sha256_bytes(&bytes)))
}

fn validate_files(root: &Path, manifest: &AdvisoryDeltaManifest) -> Result<(), DeltaError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| DeltaError::Filesystem {
        path: root.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DeltaError::InvalidPath(
            "delta root must be a real directory",
        ));
    }
    let mut expected = BTreeMap::<String, (&str, Option<u64>, u64)>::new();
    expected.insert(
        manifest.index.stored_path.clone(),
        (
            &manifest.index.sha256,
            Some(manifest.index.bytes),
            MAX_DELTA_INDEX_BYTES,
        ),
    );
    for source in &manifest.sources {
        expected.insert(
            source.license_evidence_path.clone(),
            (
                &source.license_evidence_sha256,
                None,
                MAX_LICENSE_EVIDENCE_BYTES,
            ),
        );
    }
    for record in &manifest.records {
        expected.insert(
            record.stored_path.clone(),
            (&record.sha256, Some(record.bytes), MAX_OSV_RECORD_BYTES),
        );
    }
    for record in &manifest.quarantined {
        expected.insert(
            record.stored_path.clone(),
            (&record.sha256, Some(record.bytes), MAX_OSV_RECORD_BYTES + 1),
        );
    }
    for (relative, (hash, exact_size, maximum)) in &expected {
        let path = root.join(relative);
        let metadata = regular_file_metadata(&path)?;
        if metadata.len() == 0
            || metadata.len() > *maximum
            || exact_size.is_some_and(|size| metadata.len() != size)
            || sha256_file(&path, *maximum)? != *hash
        {
            return Err(DeltaError::FileMismatch(relative.clone()));
        }
    }
    let mut observed = BTreeSet::new();
    collect_files(root, root, &mut observed, 0)?;
    observed.remove("manifest.json");
    let expected = expected.keys().cloned().collect::<BTreeSet<_>>();
    if let Some(path) = observed.difference(&expected).next() {
        return Err(DeltaError::UnexpectedFile(path.clone()));
    }
    if let Some(path) = expected.difference(&observed).next() {
        return Err(DeltaError::FileMismatch(path.clone()));
    }
    let index_bytes = read_bounded_regular(
        &root.join(&manifest.index.stored_path),
        MAX_DELTA_INDEX_BYTES,
    )?;
    let entries = parse_index(&index_bytes)?;
    let after = parse_timestamp(
        &manifest.cursor.after_modified_exclusive,
        "after_modified_exclusive",
    )?;
    let through = parse_timestamp(
        &manifest.cursor.through_modified_inclusive,
        "through_modified_inclusive",
    )?;
    let selected = entries
        .iter()
        .filter(|entry| entry.modified > after)
        .collect::<Vec<_>>();
    if entries.len() as u64 != manifest.accounting.index_entries
        || selected.len() as u64 != manifest.accounting.selected_entries
        || selected.first().map(|entry| entry.modified) != Some(through)
    {
        return Err(DeltaError::InvalidManifest("index cursor reconciliation"));
    }
    let indexed = selected
        .iter()
        .map(|entry| (entry.id.as_str(), *entry))
        .collect::<BTreeMap<_, _>>();
    for record in &manifest.records {
        let entry = indexed
            .get(record.id.as_str())
            .ok_or(DeltaError::InvalidManifest("record absent from index"))?;
        if entry.line != record.index_line
            || entry.modified != parse_timestamp(&record.index_modified, "index_modified")?
        {
            return Err(DeltaError::InvalidManifest("record/index mismatch"));
        }
        let bytes = read_bounded_regular(&root.join(&record.stored_path), MAX_OSV_RECORD_BYTES)?;
        let parsed: OsvRecord = serde_json::from_slice(&bytes)?;
        crate::catalog::validate_osv_record_public(&parsed)
            .map_err(|_| DeltaError::InvalidManifest("accepted OSV record"))?;
        let openssf_enabled = manifest
            .sources
            .iter()
            .any(|source| source.kind == "openssf-malicious-packages");
        let (_, ecosystems, class) = classify_record(
            &bytes,
            &format!("{}.json", parsed.id),
            &manifest.expected_ecosystem,
            openssf_enabled,
        )
        .map_err(|_| DeltaError::InvalidManifest("accepted record classification"))?;
        if parsed.id != record.id
            || parsed.modified != record.modified
            || parsed.withdrawn.is_some() != record.withdrawn
            || ecosystems != record.ecosystems
            || class.name != record.source_name
        {
            return Err(DeltaError::InvalidManifest("accepted record provenance"));
        }
    }
    for record in &manifest.quarantined {
        let entry = indexed
            .get(record.id.as_str())
            .ok_or(DeltaError::InvalidManifest("quarantine absent from index"))?;
        if entry.line != record.index_line
            || entry.modified != parse_timestamp(&record.index_modified, "index_modified")?
        {
            return Err(DeltaError::InvalidManifest("quarantine/index mismatch"));
        }
    }
    Ok(())
}

struct RecordValidation<'a> {
    line: u64,
    index_modified: &'a str,
    id: &'a str,
    stored_path: &'a str,
    sha256: &'a str,
    bytes: u64,
    maximum_bytes: u64,
    prefix: &'a str,
}

fn validate_record_common(
    record: RecordValidation<'_>,
    after: OffsetDateTime,
    through: OffsetDateTime,
) -> Result<(), DeltaError> {
    let modified = parse_timestamp(record.index_modified, "index_modified")?;
    if record.line == 0
        || modified <= after
        || modified > through
        || !safe_id(record.id)
        || !valid_sha256(record.sha256)
        || record.bytes == 0
        || record.bytes > record.maximum_bytes
    {
        return Err(DeltaError::InvalidManifest("record metadata"));
    }
    validate_relative_path(record.stored_path, record.prefix)
}

fn validate_prepare_config(config: &DeltaPrepareConfig) -> Result<(), DeltaError> {
    validate_text(&config.index_locator, 4_096)?;
    validate_text(&config.index_revision, 500)?;
    validate_text(&config.expected_ecosystem, 100)?;
    parse_timestamp(&config.acquired_at, "acquired_at")?;
    parse_timestamp(&config.after_modified, "after_modified")?;
    if !prefixed_hash(&config.base_snapshot_id, "sf_snapshot_")
        || config
            .previous_delta_id
            .as_ref()
            .is_some_and(|value| !prefixed_hash(value, "sf_delta_"))
    {
        return Err(DeltaError::InvalidConfiguration(
            "base or previous identity",
        ));
    }
    if config.output.as_os_str().is_empty() || config.output.file_name().is_none() {
        return Err(DeltaError::InvalidPath("output must name a directory"));
    }
    match fs::symlink_metadata(&config.output) {
        Ok(_) => Err(DeltaError::InvalidPath("output already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DeltaError::Filesystem {
            path: config.output.clone(),
            source,
        }),
    }
}

fn evidence_for<'a>(
    kind: EvidenceKind,
    github: Option<&'a (Vec<u8>, String)>,
    rustsec: Option<&'a (Vec<u8>, String)>,
    openssf: Option<&'a (Vec<u8>, String)>,
) -> Result<&'a (Vec<u8>, String), DeltaError> {
    match kind {
        EvidenceKind::Github => github.ok_or(DeltaError::MissingLicenseEvidence(
            "GitHub Advisory Database",
        )),
        EvidenceKind::Rustsec => rustsec.ok_or(DeltaError::MissingLicenseEvidence("RustSec")),
        EvidenceKind::OpenssfMaliciousPackages => openssf.ok_or(
            DeltaError::MissingLicenseEvidence("OpenSSF Malicious Packages"),
        ),
    }
}

fn load_optional_evidence(path: Option<&Path>) -> Result<Option<(Vec<u8>, String)>, DeltaError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = read_bounded_regular(path, MAX_LICENSE_EVIDENCE_BYTES)?;
    let sha256 = sha256_bytes(&bytes);
    Ok(Some((bytes, sha256)))
}

fn read_bounded_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, DeltaError> {
    let metadata = regular_file_metadata(path)?;
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(DeltaError::InvalidPath(
            "file is empty or exceeds its limit",
        ));
    }
    let mut file = File::open(path).map_err(|source| DeltaError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| DeltaError::Filesystem {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > maximum {
        return Err(DeltaError::InvalidPath("file grew beyond its limit"));
    }
    Ok(bytes)
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata, DeltaError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DeltaError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DeltaError::InvalidPath(
            "expected a regular non-symlink file",
        ));
    }
    Ok(metadata)
}

fn sha256_file(path: &Path, maximum: u64) -> Result<String, DeltaError> {
    let bytes = read_bounded_regular(path, maximum)?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

fn validate_text(value: &str, maximum: usize) -> Result<(), DeltaError> {
    if value.trim().is_empty()
        || value.chars().count() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(DeltaError::InvalidConfiguration("bounded text field"));
    }
    Ok(())
}

fn parse_timestamp(value: &str, _field: &'static str) -> Result<OffsetDateTime, DeltaError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| DeltaError::InvalidConfiguration("timestamp is not RFC3339"))
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'+')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn prefixed_hash(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

fn validate_relative_path(value: &str, prefix: &str) -> Result<(), DeltaError> {
    let path = Path::new(value);
    if !value.starts_with(&format!("{prefix}/"))
        || value.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(DeltaError::InvalidManifest("relative path"));
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), DeltaError> {
    if depth > 4 {
        return Err(DeltaError::InvalidPath("delta tree is too deep"));
    }
    for entry in fs::read_dir(directory).map_err(|source| DeltaError::Filesystem {
        path: directory.to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| DeltaError::Filesystem {
            path: directory.to_owned(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| DeltaError::Filesystem {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(DeltaError::InvalidPath(
                "delta tree cannot contain symlinks",
            ));
        }
        if file_type.is_dir() {
            collect_files(root, &path, files, depth + 1)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| DeltaError::InvalidPath("delta path escaped root"))?
                .to_str()
                .ok_or(DeltaError::InvalidPath("delta paths must be UTF-8"))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if !files.insert(relative.clone()) {
                return Err(DeltaError::UnexpectedFile(relative));
            }
        } else {
            return Err(DeltaError::InvalidPath(
                "delta tree contains a special file",
            ));
        }
    }
    Ok(())
}

fn create_temporary_directory(output: &Path) -> Result<PathBuf, DeltaError> {
    let parent = output
        .parent()
        .ok_or(DeltaError::InvalidPath("output must have a parent"))?;
    create_private_directories(parent)?;
    let name = output
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(DeltaError::InvalidPath("output name must be UTF-8"))?;
    let nonce = OffsetDateTime::now_utc().unix_timestamp_nanos();
    for attempt in 0..100_u32 {
        let candidate = parent.join(format!(
            ".{name}.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        match create_private_directory(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(DeltaError::Filesystem { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(DeltaError::InvalidPath(
        "could not allocate temporary output directory",
    ))
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), DeltaError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|source| DeltaError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), DeltaError> {
    fs::create_dir(path).map_err(|source| DeltaError::Filesystem {
        path: path.to_owned(),
        source,
    })
}

#[cfg(unix)]
fn create_private_directories(path: &Path) -> Result<(), DeltaError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|source| DeltaError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
fn create_private_directories(path: &Path) -> Result<(), DeltaError> {
    fs::create_dir_all(path).map_err(|source| DeltaError::Filesystem {
        path: path.to_owned(),
        source,
    })
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), DeltaError> {
    let parent = path
        .parent()
        .ok_or(DeltaError::InvalidPath("output file must have a parent"))?;
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
        .map_err(|source| DeltaError::Filesystem {
            path: path.to_owned(),
            source,
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| DeltaError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "secureflow-delta-{label}-{}-{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))
    }

    fn record(id: &str, modified: &str, withdrawn: bool) -> Vec<u8> {
        let mut value = serde_json::json!({
            "id": id,
            "modified": modified,
            "summary": "delta fixture",
            "affected": [{
                "package": {"ecosystem": "crates.io", "name": "fixture"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
            }]
        });
        if withdrawn {
            value["withdrawn"] = serde_json::Value::String(modified.into());
        }
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn prepares_validates_and_detects_tampering() {
        let root = temporary_path("roundtrip");
        let payloads = root.join("payloads");
        fs::create_dir_all(&payloads).unwrap();
        fs::write(
            root.join("modified_id.csv"),
            b"2026-08-23T12:00:00Z,GHSA-aaaa-bbbb-cccc\n2026-08-22T12:00:00Z,GHSA-old0-old0-old0\n",
        )
        .unwrap();
        fs::write(
            payloads.join("GHSA-aaaa-bbbb-cccc.json"),
            record("GHSA-aaaa-bbbb-cccc", "2026-08-23T12:00:00Z", true),
        )
        .unwrap();
        fs::write(root.join("github-license.txt"), b"CC-BY-4.0 evidence").unwrap();
        let output = root.join("prepared");
        let manifest = prepare_osv_delta(&DeltaPrepareConfig {
            modified_index: root.join("modified_id.csv"),
            records: payloads,
            output: output.clone(),
            index_locator:
                "https://storage.googleapis.com/osv-vulnerabilities/crates.io/modified_id.csv"
                    .into(),
            index_revision: "etag-fixture".into(),
            expected_ecosystem: "crates.io".into(),
            acquired_at: "2026-08-23T13:00:00Z".into(),
            after_modified: "2026-08-23T00:00:00Z".into(),
            base_snapshot_id: format!("sf_snapshot_{}", "1".repeat(64)),
            previous_delta_id: None,
            github_license_evidence: Some(root.join("github-license.txt")),
            rustsec_license_evidence: None,
            openssf_malicious_packages_license_evidence: None,
        })
        .unwrap();
        assert_eq!(manifest.accounting.accepted_records, 1);
        assert_eq!(manifest.accounting.withdrawn_records, 1);
        assert!(!manifest.semantics.absence_deactivates_record);
        load_and_validate_delta(&output.join("manifest.json")).unwrap();
        fs::write(output.join(&manifest.records[0].stored_path), b"tampered").unwrap();
        assert!(load_and_validate_delta(&output.join("manifest.json")).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn missing_payload_is_not_a_deletion() {
        let root = temporary_path("missing");
        fs::create_dir_all(root.join("payloads")).unwrap();
        fs::write(
            root.join("modified_id.csv"),
            b"2026-08-23T12:00:00Z,GHSA-aaaa-bbbb-cccc\n",
        )
        .unwrap();
        let error = prepare_osv_delta(&DeltaPrepareConfig {
            modified_index: root.join("modified_id.csv"),
            records: root.join("payloads"),
            output: root.join("prepared"),
            index_locator: "https://example.invalid/modified_id.csv".into(),
            index_revision: "etag".into(),
            expected_ecosystem: "crates.io".into(),
            acquired_at: "2026-08-23T13:00:00Z".into(),
            after_modified: "2026-08-23T00:00:00Z".into(),
            base_snapshot_id: format!("sf_snapshot_{}", "1".repeat(64)),
            previous_delta_id: None,
            github_license_evidence: None,
            rustsec_license_evidence: None,
            openssf_malicious_packages_license_evidence: None,
        })
        .unwrap_err();
        assert!(matches!(error, DeltaError::MissingPayload(_)));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rustsec_license_evidence_can_be_shared_by_distinct_source_classes() {
        let root = temporary_path("shared-rustsec-license");
        let payloads = root.join("payloads");
        fs::create_dir_all(&payloads).unwrap();
        fs::write(
            root.join("modified_id.csv"),
            b"2026-08-23T12:00:00Z,RUSTSEC-2026-0001\n2026-08-23T11:00:00Z,RUSTSEC-2026-0002\n",
        )
        .unwrap();
        for (id, modified, license) in [
            ("RUSTSEC-2026-0001", "2026-08-23T12:00:00Z", "CC0-1.0"),
            ("RUSTSEC-2026-0002", "2026-08-23T11:00:00Z", "CC-BY-4.0"),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "id": id,
                "modified": modified,
                "database_specific": {"license": license},
                "affected": [{
                    "package": {"ecosystem": "crates.io", "name": "fixture"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
                }]
            }))
            .unwrap();
            fs::write(payloads.join(format!("{id}.json")), bytes).unwrap();
        }
        fs::write(root.join("rustsec-license.txt"), b"RustSec license policy").unwrap();
        let output = root.join("prepared");
        let manifest = prepare_osv_delta(&DeltaPrepareConfig {
            modified_index: root.join("modified_id.csv"),
            records: payloads,
            output: output.clone(),
            index_locator: "https://example.invalid/crates.io/modified_id.csv".into(),
            index_revision: "etag-shared-license".into(),
            expected_ecosystem: "crates.io".into(),
            acquired_at: "2026-08-23T13:00:00Z".into(),
            after_modified: "2026-08-23T00:00:00Z".into(),
            base_snapshot_id: format!("sf_snapshot_{}", "1".repeat(64)),
            previous_delta_id: None,
            github_license_evidence: None,
            rustsec_license_evidence: Some(root.join("rustsec-license.txt")),
            openssf_malicious_packages_license_evidence: None,
        })
        .unwrap();
        assert_eq!(manifest.sources.len(), 2);
        assert_eq!(
            manifest.sources[0].license_evidence_path,
            manifest.sources[1].license_evidence_path
        );
        load_and_validate_delta(&output.join("manifest.json")).unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
