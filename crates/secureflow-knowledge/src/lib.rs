//! Small append-only knowledge ledger for human-reviewed run results.
//!
//! This is deliberately a bootstrap layer, not the future global knowledge
//! base. It stores JSON Lines locally, rejects pending findings, preserves
//! provenance hashes and never stores source text or full review rationale.

pub mod catalog;
pub mod catalog_backup;
pub mod correlation;
pub mod snapshot;

use secureflow_model::{
    Confidence, EvidenceKind, EvidenceStep, Finding, HumanDecision, Location, Revision,
    RunManifest, Severity, TaxonomyCoordinates,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const RECORD_VERSION_V1: &str = "secureflow-knowledge-record-v1";
pub const RECORD_VERSION: &str = "secureflow-knowledge-record-v2";
pub const MAX_LEDGER_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeRecordV1 {
    pub record_version: String,
    pub record_id: String,
    pub manifest_sha256: String,
    pub manifest_created_at: String,
    pub target_sha256: String,
    pub engine_name: String,
    pub engine_version: String,
    pub engine_binary_sha256: String,
    pub finding_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_fingerprint: Option<String>,
    pub title: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taxonomy: Option<TaxonomyCoordinates>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    pub confidence: Confidence,
    pub source_location: Location,
    pub sink_location: Location,
    pub invariant: String,
    pub evidence_path: Vec<EvidenceStep>,
    pub decision: HumanDecision,
    pub reviewer: String,
    pub reviewed_at: String,
    pub rationale_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_reference_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceLicenseStatus {
    SpdxDeclared,
    PrivateOrUndisclosed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLicense {
    pub status: SourceLicenseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spdx_expression: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
    pub assertion: String,
}

impl SourceLicense {
    pub fn operator_declared(
        status: SourceLicenseStatus,
        spdx_expression: Option<String>,
        evidence_sha256: Option<String>,
    ) -> Result<Self, KnowledgeError> {
        let value = Self {
            status,
            spdx_expression,
            evidence_sha256,
            assertion: "operator-declared".into(),
        };
        validate_source_license(&value)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeRecordV2 {
    pub record_version: String,
    pub record_id: String,
    pub observation_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate_of_record_id: Option<String>,
    pub manifest_sha256: String,
    pub manifest_created_at: String,
    pub target_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_revision: Option<Revision>,
    pub source_license: SourceLicense,
    pub engine_name: String,
    pub engine_version: String,
    pub engine_binary_sha256: String,
    pub finding_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_fingerprint: Option<String>,
    pub title: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taxonomy: Option<TaxonomyCoordinates>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    pub confidence: Confidence,
    pub source_location: Location,
    pub sink_location: Location,
    pub invariant: String,
    pub evidence_path: Vec<EvidenceStep>,
    pub decision: HumanDecision,
    pub reviewer: String,
    pub reviewed_at: String,
    pub rationale_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_reference_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum KnowledgeRecord {
    V1(KnowledgeRecordV1),
    V2(KnowledgeRecordV2),
}

impl KnowledgeRecord {
    pub fn record_version(&self) -> &str {
        match self {
            Self::V1(record) => &record.record_version,
            Self::V2(record) => &record.record_version,
        }
    }

    pub fn record_id(&self) -> &str {
        match self {
            Self::V1(record) => &record.record_id,
            Self::V2(record) => &record.record_id,
        }
    }

    pub fn decision(&self) -> HumanDecision {
        match self {
            Self::V1(record) => record.decision,
            Self::V2(record) => record.decision,
        }
    }

    pub fn rule_id(&self) -> &str {
        match self {
            Self::V1(record) => &record.rule_id,
            Self::V2(record) => &record.rule_id,
        }
    }

    pub fn severity(&self) -> Option<Severity> {
        match self {
            Self::V1(record) => record.severity,
            Self::V2(record) => record.severity,
        }
    }

    pub fn confidence(&self) -> Confidence {
        match self {
            Self::V1(record) => record.confidence,
            Self::V2(record) => record.confidence,
        }
    }

    pub fn source_location(&self) -> &Location {
        match self {
            Self::V1(record) => &record.source_location,
            Self::V2(record) => &record.source_location,
        }
    }

    pub fn finding_id(&self) -> &str {
        match self {
            Self::V1(record) => &record.finding_id,
            Self::V2(record) => &record.finding_id,
        }
    }

    pub fn title(&self) -> &str {
        match self {
            Self::V1(record) => &record.title,
            Self::V2(record) => &record.title,
        }
    }

    pub fn duplicate_of_record_id(&self) -> Option<&str> {
        match self {
            Self::V1(_) => None,
            Self::V2(record) => record.duplicate_of_record_id.as_deref(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportResult {
    pub manifest_sha256: String,
    pub records_added: usize,
    pub records_skipped: usize,
    pub duplicates_linked: usize,
}

#[derive(Debug, Error)]
pub enum KnowledgeError {
    #[error("could not read knowledge ledger {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("could not write knowledge ledger {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("invalid knowledge record at line {line}: {source}")]
    InvalidRecord {
        line: usize,
        source: serde_json::Error,
    },
    #[error("knowledge record has unsupported version: {0}")]
    UnsupportedVersion(String),
    #[error("knowledge record is invalid: {0}")]
    InvalidRecordField(&'static str),
    #[error("finding {0} is still pending human review")]
    PendingFinding(String),
    #[error("manifest has no human-reviewed findings")]
    NoReviewedFindings,
    #[error("knowledge ledger repeats record id: {0}")]
    DuplicateRecordId(String),
    #[error("knowledge duplicate link is invalid for record: {0}")]
    InvalidDuplicateLink(String),
    #[error("knowledge ledger is outside the size limit: {bytes} bytes; maximum {maximum}")]
    LedgerTooLarge { bytes: u64, maximum: u64 },
    #[error("could not serialize knowledge record: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("invalid secureflow run manifest: {0}")]
    Manifest(#[from] secureflow_model::ModelError),
}

/// Imports all non-pending findings from one validated manifest into a local
/// JSONL ledger. Existing records are preserved byte-for-byte and duplicate
/// record IDs are skipped.
pub fn import_manifest_to_ledger(
    manifest_bytes: &[u8],
    manifest: &RunManifest,
    ledger_path: &Path,
    source_license: SourceLicense,
) -> Result<ImportResult, KnowledgeError> {
    manifest.validate()?;
    validate_source_license(&source_license)?;
    let manifest_sha256 = sha256_bytes(manifest_bytes);
    let mut records = manifest
        .findings
        .iter()
        .filter(|finding| finding.human_review.decision != HumanDecision::Pending)
        .map(|finding| {
            record_from_finding(manifest, &manifest_sha256, finding, source_license.clone())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if records.is_empty() {
        return Err(KnowledgeError::NoReviewedFindings);
    }

    let existing = read_optional_bounded(ledger_path)?;
    let existing_records = parse_existing_records(&existing)?;
    let existing_ids = existing_records
        .iter()
        .map(|record| record.record_id().to_owned())
        .collect::<BTreeSet<_>>();
    let mut canonical_by_observation = existing_records
        .iter()
        .filter_map(|record| match record {
            KnowledgeRecord::V1(_) => None,
            KnowledgeRecord::V2(record) if record.duplicate_of_record_id.is_none() => Some((
                record.observation_fingerprint.clone(),
                record.record_id.clone(),
            )),
            KnowledgeRecord::V2(_) => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut appended = Vec::new();
    let mut records_skipped = 0;
    let mut duplicates_linked = 0;
    for mut record in records.drain(..) {
        if existing_ids.contains(&record.record_id) {
            records_skipped += 1;
            continue;
        }
        if let Some(canonical_id) = canonical_by_observation.get(&record.observation_fingerprint) {
            record.duplicate_of_record_id = Some(canonical_id.clone());
            duplicates_linked += 1;
        } else {
            canonical_by_observation.insert(
                record.observation_fingerprint.clone(),
                record.record_id.clone(),
            );
        }
        let line = serde_json::to_vec(&record).map_err(KnowledgeError::Serialize)?;
        appended.extend_from_slice(&line);
        appended.push(b'\n');
    }
    if appended.is_empty() {
        return Ok(ImportResult {
            manifest_sha256,
            records_added: 0,
            records_skipped,
            duplicates_linked,
        });
    }

    let mut output = existing;
    if !output.is_empty() && !output.ends_with(b"\n") {
        output.push(b'\n');
    }
    output.extend_from_slice(&appended);
    write_atomic(ledger_path, &output)?;
    Ok(ImportResult {
        manifest_sha256,
        records_added: appended.iter().filter(|byte| **byte == b'\n').count(),
        records_skipped,
        duplicates_linked,
    })
}

/// Reads and validates every record in an existing knowledge ledger. A
/// malformed line or duplicate record ID fails the complete read.
pub fn read_ledger(path: &Path) -> Result<Vec<KnowledgeRecord>, KnowledgeError> {
    let bytes = read_required_bounded(path)?;
    parse_existing_records(&bytes)
}

fn record_from_finding(
    manifest: &RunManifest,
    manifest_sha256: &str,
    finding: &Finding,
    source_license: SourceLicense,
) -> Result<KnowledgeRecordV2, KnowledgeError> {
    let decision = finding.human_review.decision;
    if decision == HumanDecision::Pending {
        return Err(KnowledgeError::PendingFinding(finding.finding_id.clone()));
    }
    let reviewer = finding
        .human_review
        .reviewer
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(KnowledgeError::InvalidRecordField("reviewer"))?;
    let reviewed_at = finding
        .human_review
        .reviewed_at
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(KnowledgeError::InvalidRecordField("reviewed_at"))?;
    let rationale = finding
        .human_review
        .rationale
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(KnowledgeError::InvalidRecordField("rationale"))?;
    let evidence_reference_sha256 = finding
        .human_review
        .evidence_reference
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| sha256_bytes(value.as_bytes()));
    let record_id = record_id(manifest_sha256, &finding.finding_id, decision);
    let observation_fingerprint = observation_fingerprint(manifest, finding);
    Ok(KnowledgeRecordV2 {
        record_version: RECORD_VERSION.into(),
        record_id,
        observation_fingerprint,
        duplicate_of_record_id: None,
        manifest_sha256: manifest_sha256.into(),
        manifest_created_at: manifest.created_at.clone(),
        target_sha256: manifest.target.root_sha256.clone(),
        target_revision: manifest.target.revision.clone(),
        source_license,
        engine_name: manifest.engine.name.clone(),
        engine_version: manifest.engine.version.clone(),
        engine_binary_sha256: manifest.engine.binary_sha256.clone(),
        finding_id: finding.finding_id.clone(),
        engine_fingerprint: finding.engine_fingerprint.clone(),
        title: finding.title.clone(),
        rule_id: finding.rule_id.clone(),
        taxonomy: finding.taxonomy.clone(),
        severity: finding.severity,
        confidence: finding.confidence,
        source_location: finding.source_location.clone(),
        sink_location: finding.sink_location.clone(),
        invariant: finding.invariant.clone(),
        evidence_path: finding.evidence_path.clone(),
        decision,
        reviewer: reviewer.to_owned(),
        reviewed_at: reviewed_at.to_owned(),
        rationale_sha256: sha256_bytes(rationale.as_bytes()),
        evidence_reference_sha256,
    })
}

fn parse_existing_records(bytes: &[u8]) -> Result<Vec<KnowledgeRecord>, KnowledgeError> {
    let mut ids = BTreeSet::new();
    let mut canonical_by_observation = BTreeMap::new();
    let mut records = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let version = serde_json::from_slice::<serde_json::Value>(line)
            .map_err(|source| KnowledgeError::InvalidRecord {
                line: index + 1,
                source,
            })?
            .get("record_version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        let record = match version.as_str() {
            RECORD_VERSION_V1 => {
                KnowledgeRecord::V1(serde_json::from_slice(line).map_err(|source| {
                    KnowledgeError::InvalidRecord {
                        line: index + 1,
                        source,
                    }
                })?)
            }
            RECORD_VERSION => {
                KnowledgeRecord::V2(serde_json::from_slice(line).map_err(|source| {
                    KnowledgeError::InvalidRecord {
                        line: index + 1,
                        source,
                    }
                })?)
            }
            _ => return Err(KnowledgeError::UnsupportedVersion(version)),
        };
        validate_record(&record)?;
        if !ids.insert(record.record_id().to_owned()) {
            return Err(KnowledgeError::DuplicateRecordId(
                record.record_id().to_owned(),
            ));
        }
        if let KnowledgeRecord::V2(record) = &record {
            match (
                &record.duplicate_of_record_id,
                canonical_by_observation.get(&record.observation_fingerprint),
            ) {
                (None, None) => {
                    canonical_by_observation.insert(
                        record.observation_fingerprint.clone(),
                        record.record_id.clone(),
                    );
                }
                (Some(link), Some(canonical)) if link == canonical => {}
                _ => {
                    return Err(KnowledgeError::InvalidDuplicateLink(
                        record.record_id.clone(),
                    ));
                }
            }
        }
        records.push(record);
    }
    Ok(records)
}

fn validate_record(record: &KnowledgeRecord) -> Result<(), KnowledgeError> {
    match record {
        KnowledgeRecord::V1(record) => validate_record_v1(record),
        KnowledgeRecord::V2(record) => validate_record_v2(record),
    }
}

fn validate_record_v1(record: &KnowledgeRecordV1) -> Result<(), KnowledgeError> {
    if record.record_version != RECORD_VERSION_V1 {
        return Err(KnowledgeError::UnsupportedVersion(
            record.record_version.clone(),
        ));
    }
    validate_common_record(
        &record.record_id,
        &record.manifest_sha256,
        &record.manifest_created_at,
        &record.target_sha256,
        &record.engine_name,
        &record.engine_version,
        &record.engine_binary_sha256,
        &record.finding_id,
        record.engine_fingerprint.as_deref(),
        &record.title,
        &record.rule_id,
        record.taxonomy.as_ref(),
        &record.source_location,
        &record.sink_location,
        &record.invariant,
        &record.evidence_path,
        record.decision,
        &record.reviewer,
        &record.reviewed_at,
        &record.rationale_sha256,
        record.evidence_reference_sha256.as_deref(),
    )
}

fn validate_record_v2(record: &KnowledgeRecordV2) -> Result<(), KnowledgeError> {
    if record.record_version != RECORD_VERSION {
        return Err(KnowledgeError::UnsupportedVersion(
            record.record_version.clone(),
        ));
    }
    if !valid_prefixed_id(&record.observation_fingerprint, "sf_obs_") {
        return Err(KnowledgeError::InvalidRecordField(
            "observation_fingerprint",
        ));
    }
    if let Some(link) = &record.duplicate_of_record_id
        && (!valid_prefixed_id(link, "sf_kb_") || link == &record.record_id)
    {
        return Err(KnowledgeError::InvalidRecordField("duplicate_of_record_id"));
    }
    if let Some(revision) = &record.target_revision {
        validate_bounded(&revision.value, "target_revision.value", 200)?;
    }
    validate_source_license(&record.source_license)?;
    validate_common_record(
        &record.record_id,
        &record.manifest_sha256,
        &record.manifest_created_at,
        &record.target_sha256,
        &record.engine_name,
        &record.engine_version,
        &record.engine_binary_sha256,
        &record.finding_id,
        record.engine_fingerprint.as_deref(),
        &record.title,
        &record.rule_id,
        record.taxonomy.as_ref(),
        &record.source_location,
        &record.sink_location,
        &record.invariant,
        &record.evidence_path,
        record.decision,
        &record.reviewer,
        &record.reviewed_at,
        &record.rationale_sha256,
        record.evidence_reference_sha256.as_deref(),
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_common_record(
    record_id: &str,
    manifest_sha256: &str,
    manifest_created_at: &str,
    target_sha256: &str,
    engine_name: &str,
    engine_version: &str,
    engine_binary_sha256: &str,
    finding_id: &str,
    engine_fingerprint: Option<&str>,
    title: &str,
    rule_id: &str,
    taxonomy: Option<&TaxonomyCoordinates>,
    source_location: &Location,
    sink_location: &Location,
    invariant: &str,
    evidence_path: &[EvidenceStep],
    decision: HumanDecision,
    reviewer: &str,
    reviewed_at: &str,
    rationale_sha256: &str,
    evidence_reference_sha256: Option<&str>,
) -> Result<(), KnowledgeError> {
    if !valid_prefixed_id(record_id, "sf_kb_") {
        return Err(KnowledgeError::InvalidRecordField("record_id"));
    }
    if !valid_identifier(finding_id, "sf_finding_", 16, 100) {
        return Err(KnowledgeError::InvalidRecordField("finding_id"));
    }
    for (value, field) in [
        (manifest_sha256, "manifest_sha256"),
        (target_sha256, "target_sha256"),
        (engine_binary_sha256, "engine_binary_sha256"),
        (rationale_sha256, "rationale_sha256"),
    ] {
        if !valid_sha256(value) {
            return Err(KnowledgeError::InvalidRecordField(field));
        }
    }
    if let Some(value) = evidence_reference_sha256
        && !valid_sha256(value)
    {
        return Err(KnowledgeError::InvalidRecordField(
            "evidence_reference_sha256",
        ));
    }
    if decision == HumanDecision::Pending {
        return Err(KnowledgeError::InvalidRecordField("decision"));
    }
    validate_timestamp(manifest_created_at, "manifest_created_at")?;
    validate_timestamp(reviewed_at, "reviewed_at")?;
    validate_bounded(engine_name, "engine_name", 100)?;
    validate_bounded(engine_version, "engine_version", 100)?;
    validate_optional_bounded(engine_fingerprint, "engine_fingerprint", 200)?;
    validate_bounded(title, "title", 300)?;
    validate_bounded(rule_id, "rule_id", 100)?;
    validate_bounded(invariant, "invariant", 1000)?;
    validate_bounded(reviewer, "reviewer", 200)?;
    if let Some(taxonomy) = taxonomy {
        validate_bounded(&taxonomy.version, "taxonomy.version", 50)?;
        validate_bounded(&taxonomy.category_id, "taxonomy.category_id", 100)?;
        validate_bounded(&taxonomy.invariant_id, "taxonomy.invariant_id", 100)?;
    }
    validate_location(source_location, "source_location")?;
    validate_location(sink_location, "sink_location")?;
    if evidence_path.is_empty() {
        return Err(KnowledgeError::InvalidRecordField("evidence_path"));
    }
    for step in evidence_path {
        validate_location(&step.location, "evidence_path.location")?;
        validate_bounded(&step.description, "evidence_path.description", 1000)?;
    }
    Ok(())
}

fn validate_location(location: &Location, field: &'static str) -> Result<(), KnowledgeError> {
    let path = Path::new(&location.path);
    if location.path.is_empty()
        || path.is_absolute()
        || location.path.contains('\\')
        || location.path.chars().any(char::is_control)
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        || location.start_line == 0
        || location.start_column == 0
        || location.end_line == Some(0)
        || location.end_column == Some(0)
    {
        return Err(KnowledgeError::InvalidRecordField(field));
    }
    if let Some(end_line) = location.end_line
        && (end_line < location.start_line
            || (end_line == location.start_line
                && location
                    .end_column
                    .is_some_and(|column| column < location.start_column)))
    {
        return Err(KnowledgeError::InvalidRecordField(field));
    }
    Ok(())
}

fn validate_bounded(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), KnowledgeError> {
    if value.trim().is_empty() || value.chars().count() > max_chars {
        return Err(KnowledgeError::InvalidRecordField(field));
    }
    Ok(())
}

fn validate_optional_bounded(
    value: Option<&str>,
    field: &'static str,
    max_chars: usize,
) -> Result<(), KnowledgeError> {
    if let Some(value) = value {
        validate_bounded(value, field, max_chars)?;
    }
    Ok(())
}

fn validate_source_license(value: &SourceLicense) -> Result<(), KnowledgeError> {
    if value.assertion != "operator-declared" {
        return Err(KnowledgeError::InvalidRecordField(
            "source_license.assertion",
        ));
    }
    if let Some(evidence_sha256) = &value.evidence_sha256
        && !valid_sha256(evidence_sha256)
    {
        return Err(KnowledgeError::InvalidRecordField(
            "source_license.evidence_sha256",
        ));
    }
    match value.status {
        SourceLicenseStatus::SpdxDeclared => {
            let expression =
                value
                    .spdx_expression
                    .as_deref()
                    .ok_or(KnowledgeError::InvalidRecordField(
                        "source_license.spdx_expression",
                    ))?;
            validate_bounded(expression, "source_license.spdx_expression", 200)?;
            if value.evidence_sha256.is_none() {
                return Err(KnowledgeError::InvalidRecordField(
                    "source_license.evidence_sha256",
                ));
            }
        }
        SourceLicenseStatus::PrivateOrUndisclosed | SourceLicenseStatus::Unknown => {
            if value.spdx_expression.is_some() {
                return Err(KnowledgeError::InvalidRecordField(
                    "source_license.spdx_expression",
                ));
            }
        }
    }
    Ok(())
}

fn validate_timestamp(value: &str, field: &'static str) -> Result<(), KnowledgeError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| KnowledgeError::InvalidRecordField(field))
}

fn record_id(manifest_sha256: &str, finding_id: &str, decision: HumanDecision) -> String {
    let input = format!(
        "{manifest_sha256}|{finding_id}|{}",
        decision_label(decision)
    );
    format!("sf_kb_{}", sha256_bytes(input.as_bytes()))
}

fn observation_fingerprint(manifest: &RunManifest, finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "secureflow-observation-v1");
    hash_field(&mut hasher, &manifest.target.root_sha256);
    hash_field(&mut hasher, &manifest.engine.name);
    hash_field(&mut hasher, &finding.rule_id);
    hash_field(
        &mut hasher,
        finding
            .engine_fingerprint
            .as_deref()
            .unwrap_or(&finding.finding_id),
    );
    hash_location(&mut hasher, &finding.source_location);
    hash_location(&mut hasher, &finding.sink_location);
    hash_field(&mut hasher, &finding.invariant);
    for step in &finding.evidence_path {
        hash_field(&mut hasher, evidence_kind_label(step.kind));
        hash_location(&mut hasher, &step.location);
        hash_field(&mut hasher, &step.description);
    }
    format!("sf_obs_{}", hex_digest(hasher.finalize().as_slice()))
}

fn hash_location(hasher: &mut Sha256, location: &Location) {
    hash_field(hasher, &location.path);
    hash_field(hasher, &location.start_line.to_string());
    hash_field(hasher, &location.start_column.to_string());
    hash_field(hasher, &location.end_line.unwrap_or_default().to_string());
    hash_field(hasher, &location.end_column.unwrap_or_default().to_string());
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn evidence_kind_label(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Source => "source",
        EvidenceKind::Transform => "transform",
        EvidenceKind::Guard => "guard",
        EvidenceKind::Sanitizer => "sanitizer",
        EvidenceKind::Authorization => "authorization",
        EvidenceKind::Sink => "sink",
        EvidenceKind::Barrier => "barrier",
        EvidenceKind::Unknown => "unknown",
    }
}

fn decision_label(decision: HumanDecision) -> &'static str {
    match decision {
        HumanDecision::Pending => "pending",
        HumanDecision::Validated => "validated",
        HumanDecision::Rejected => "rejected",
        HumanDecision::Abstained => "abstained",
    }
}

fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    suffix.len() == 64
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_identifier(value: &str, prefix: &str, min_suffix: usize, max_suffix: usize) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    (min_suffix..=max_suffix).contains(&suffix.len())
        && suffix
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(hasher.finalize().as_slice())
}

fn hex_digest(digest: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for &byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn read_optional_bounded(path: &Path) -> Result<Vec<u8>, KnowledgeError> {
    match std::fs::metadata(path) {
        Ok(metadata) => read_with_metadata(path, metadata),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(source) => Err(KnowledgeError::Read {
            path: path.to_owned(),
            source,
        }),
    }
}

fn read_required_bounded(path: &Path) -> Result<Vec<u8>, KnowledgeError> {
    let metadata = std::fs::metadata(path).map_err(|source| KnowledgeError::Read {
        path: path.to_owned(),
        source,
    })?;
    read_with_metadata(path, metadata)
}

fn read_with_metadata(path: &Path, metadata: std::fs::Metadata) -> Result<Vec<u8>, KnowledgeError> {
    if !metadata.is_file() {
        return Err(KnowledgeError::Read {
            path: path.to_owned(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "ledger is not a regular file"),
        });
    }
    if metadata.len() > MAX_LEDGER_BYTES {
        return Err(KnowledgeError::LedgerTooLarge {
            bytes: metadata.len(),
            maximum: MAX_LEDGER_BYTES,
        });
    }
    let bytes = std::fs::read(path).map_err(|source| KnowledgeError::Read {
        path: path.to_owned(),
        source,
    })?;
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return Err(KnowledgeError::LedgerTooLarge {
            bytes: bytes.len() as u64,
            maximum: MAX_LEDGER_BYTES,
        });
    }
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), KnowledgeError> {
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return Err(KnowledgeError::LedgerTooLarge {
            bytes: bytes.len() as u64,
            maximum: MAX_LEDGER_BYTES,
        });
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(parent)
            .map_err(|source| KnowledgeError::Write {
                path: path.to_owned(),
                source,
            })?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(parent).map_err(|source| KnowledgeError::Write {
        path: path.to_owned(),
        source,
    })?;
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy())
        .unwrap_or_else(|| std::borrow::Cow::Borrowed("knowledge.jsonl"));
    let mut temporary = None;
    for counter in 0..1024_u16 {
        let candidate = parent.join(format!(".{name}.tmp-{}-{counter}", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(mut file) => {
                if let Err(source) = file.write_all(bytes).and_then(|_| file.sync_all()) {
                    let _ = std::fs::remove_file(&candidate);
                    return Err(KnowledgeError::Write {
                        path: path.to_owned(),
                        source,
                    });
                }
                temporary = Some(candidate);
                break;
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(KnowledgeError::Write {
                    path: path.to_owned(),
                    source,
                });
            }
        }
    }
    let temporary = temporary.ok_or_else(|| KnowledgeError::Write {
        path: path.to_owned(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary ledger file",
        ),
    })?;
    if let Err(source) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(KnowledgeError::Write {
            path: path.to_owned(),
            source,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureflow_model::EvidenceKind;

    fn record() -> KnowledgeRecordV2 {
        let location = Location {
            path: "src/app.ts".into(),
            start_line: 1,
            start_column: 1,
            end_line: Some(1),
            end_column: Some(2),
        };
        KnowledgeRecordV2 {
            record_version: RECORD_VERSION.into(),
            record_id: format!("sf_kb_{}", "a".repeat(64)),
            observation_fingerprint: format!("sf_obs_{}", "f".repeat(64)),
            duplicate_of_record_id: None,
            manifest_sha256: "b".repeat(64),
            manifest_created_at: "2026-08-23T03:00:00Z".into(),
            target_sha256: "c".repeat(64),
            target_revision: None,
            source_license: SourceLicense::operator_declared(
                SourceLicenseStatus::Unknown,
                None,
                None,
            )
            .expect("unknown is explicit and valid"),
            engine_name: "secure-engine".into(),
            engine_version: "0.1.10".into(),
            engine_binary_sha256: "d".repeat(64),
            finding_id: "sf_finding_0000000000000000".into(),
            engine_fingerprint: Some("engine-fingerprint".into()),
            title: "candidate".into(),
            rule_id: "SE1001".into(),
            taxonomy: None,
            severity: Some(Severity::High),
            confidence: Confidence::High,
            source_location: location.clone(),
            sink_location: location.clone(),
            invariant: "invariant".into(),
            evidence_path: vec![EvidenceStep {
                kind: EvidenceKind::Source,
                location,
                description: "source".into(),
            }],
            decision: HumanDecision::Validated,
            reviewer: "human".into(),
            reviewed_at: "2026-08-23T03:00:01Z".into(),
            rationale_sha256: "e".repeat(64),
            evidence_reference_sha256: None,
        }
    }

    #[test]
    fn record_ids_are_stable_and_lowercase() {
        let first = record_id(
            &"a".repeat(64),
            "sf_finding_0000000000000000",
            HumanDecision::Validated,
        );
        let second = record_id(
            &"a".repeat(64),
            "sf_finding_0000000000000000",
            HumanDecision::Validated,
        );
        assert_eq!(first, second);
        assert!(valid_prefixed_id(&first, "sf_kb_"));
    }

    #[test]
    fn manifests_without_reviewed_findings_are_rejected() {
        let bytes = include_bytes!("../../../tests/fixtures/minimal-run.json");
        let manifest: RunManifest = serde_json::from_slice(bytes).expect("fixture is valid");
        assert!(matches!(
            import_manifest_to_ledger(
                bytes,
                &manifest,
                Path::new("/tmp/not-written.jsonl"),
                SourceLicense::operator_declared(SourceLicenseStatus::Unknown, None, None)
                    .expect("valid license state"),
            ),
            Err(KnowledgeError::NoReviewedFindings)
        ));
    }

    #[test]
    fn validates_complete_record() {
        assert!(validate_record(&KnowledgeRecord::V2(record())).is_ok());
    }

    #[test]
    fn rejects_pending_or_escaping_records() {
        let mut pending = record();
        pending.decision = HumanDecision::Pending;
        assert!(matches!(
            validate_record(&KnowledgeRecord::V2(pending)),
            Err(KnowledgeError::InvalidRecordField("decision"))
        ));

        let mut escaping = record();
        escaping.source_location.path = "../secret".into();
        assert!(matches!(
            validate_record(&KnowledgeRecord::V2(escaping)),
            Err(KnowledgeError::InvalidRecordField("source_location"))
        ));
    }

    #[test]
    fn reads_legacy_v1_records_without_reinterpreting_them() {
        let records = parse_existing_records(include_bytes!(
            "../../../tests/fixtures/minimal-knowledge.jsonl"
        ))
        .expect("legacy fixture should remain readable");
        assert_eq!(records.len(), 1);
        assert!(matches!(records[0], KnowledgeRecord::V1(_)));
        assert_eq!(records[0].record_version(), RECORD_VERSION_V1);
        assert_eq!(records[0].duplicate_of_record_id(), None);
    }

    #[test]
    fn spdx_declared_license_requires_hashed_evidence() {
        assert!(matches!(
            SourceLicense::operator_declared(
                SourceLicenseStatus::SpdxDeclared,
                Some("MIT".into()),
                None,
            ),
            Err(KnowledgeError::InvalidRecordField(
                "source_license.evidence_sha256"
            ))
        ));
    }

    #[test]
    fn repeated_exact_observations_are_linked_not_discarded() {
        let bytes = include_bytes!("../../../tests/fixtures/minimal-run-with-finding.json");
        let mut first: RunManifest = serde_json::from_slice(bytes).expect("fixture is valid");
        let finding = first.findings.first_mut().expect("fixture finding");
        finding.human_review.decision = HumanDecision::Validated;
        finding.human_review.reviewer = Some("human".into());
        finding.human_review.reviewed_at = Some("2026-08-23T12:01:00Z".into());
        finding.human_review.rationale = Some("verified locally".into());
        first.phases.validation = secureflow_model::PhaseStatus::Completed;
        first.refresh_summary();
        first.validate().expect("first reviewed manifest");

        let mut second = first.clone();
        second.run_id = "sf_run_fixture_abcdef1234567890".into();
        second.created_at = "2026-08-23T13:00:00Z".into();
        second.completed_at = Some("2026-08-23T13:00:01Z".into());
        second.validate().expect("second reviewed manifest");

        let first_bytes = serde_json::to_vec(&first).expect("serialize first");
        let second_bytes = serde_json::to_vec(&second).expect("serialize second");
        let path = std::env::temp_dir().join(format!(
            "secureflow-knowledge-dedup-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let license =
            SourceLicense::operator_declared(SourceLicenseStatus::PrivateOrUndisclosed, None, None)
                .expect("valid private state");

        let first_result = import_manifest_to_ledger(&first_bytes, &first, &path, license.clone())
            .expect("first import");
        let second_result = import_manifest_to_ledger(&second_bytes, &second, &path, license)
            .expect("second import");
        assert_eq!(first_result.records_added, 1);
        assert_eq!(first_result.duplicates_linked, 0);
        assert_eq!(second_result.records_added, 1);
        assert_eq!(second_result.duplicates_linked, 1);

        let records = read_ledger(&path).expect("observation ledger");
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1].duplicate_of_record_id(),
            Some(records[0].record_id())
        );
        std::fs::remove_file(path).expect("temporary ledger cleanup");
    }
}
