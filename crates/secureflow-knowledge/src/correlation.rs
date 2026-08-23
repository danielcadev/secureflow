//! Conservative linkage between one scanner candidate and package advisories.
//!
//! Correlation enriches review context. It never changes the finding's human
//! decision or asserts a causal link. The v2 contract can evaluate exact OSV
//! enumerations and strict `SEMVER` ranges while preserving unknown outcomes.

use crate::catalog::{
    CatalogHit, CatalogProvenance, CatalogVersionHit, VersionAssessment, VersionEvaluationBasis,
    VersionEvaluationStatus,
};
use secureflow_model::{HumanDecision, RunManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const CORRELATION_VERSION: &str = "secureflow-correlation-v1";
pub const CORRELATION_VERSION_V2: &str = "secureflow-correlation-v2";
pub const MAX_CORRELATION_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_CORRELATION_MATCHES: usize = 100;

const PACKAGE_ASSERTION: &str = "operator-supplied-exact-package-context";
const MATCH_KIND: &str = "exact-ecosystem-and-package-name";
const MATCH_KIND_V2: &str = "exact-ecosystem-package-with-osv-version-evaluation";
const VERSION_EVALUATOR: &str = "osv-semver-and-enumerated-v1";
const VALIDATION_AUTHORITY: &str = "human-only";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationEnvelope {
    pub contract_version: String,
    pub correlation_id: String,
    pub created_at: String,
    pub linked_run: LinkedRun,
    pub package_context: PackageContext,
    pub catalog: CatalogProvenance,
    pub semantics: CorrelationSemantics,
    pub advisories: Vec<AdvisoryContext>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkedRun {
    pub run_id: String,
    pub manifest_sha256: String,
    pub finding_id: String,
    pub human_decision: HumanDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageContext {
    pub assertion: String,
    pub ecosystem: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationSemantics {
    pub advisory_match_kind: String,
    pub affected_version_evaluated: bool,
    pub causal_relationship_asserted: bool,
    pub changes_human_decision: bool,
    pub validation_authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryContext {
    pub canonical_id: String,
    pub source_name: String,
    pub source_record_id: String,
    pub title: String,
    pub modified_at: String,
    pub withdrawn: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationEnvelopeV2 {
    pub contract_version: String,
    pub correlation_id: String,
    pub created_at: String,
    pub linked_run: LinkedRun,
    pub package_context: PackageContext,
    pub catalog: CatalogProvenance,
    pub semantics: CorrelationSemanticsV2,
    pub version_summary: VersionSummary,
    pub advisories: Vec<AdvisoryContextV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationSemanticsV2 {
    pub advisory_match_kind: String,
    pub version_evaluator: String,
    pub affected_version_evaluated: bool,
    pub version_result_validates_vulnerability: bool,
    pub causal_relationship_asserted: bool,
    pub changes_human_decision: bool,
    pub validation_authority: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VersionSummary {
    pub affected: u64,
    pub not_affected: u64,
    pub unknown: u64,
    pub not_evaluated: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryContextV2 {
    pub canonical_id: String,
    pub source_name: String,
    pub source_record_id: String,
    pub title: String,
    pub modified_at: String,
    pub withdrawn: bool,
    pub version_assessment: VersionAssessment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorrelationDocument {
    V1(CorrelationEnvelope),
    V2(CorrelationEnvelopeV2),
}

impl CorrelationDocument {
    pub fn linked_run(&self) -> &LinkedRun {
        match self {
            Self::V1(envelope) => &envelope.linked_run,
            Self::V2(envelope) => &envelope.linked_run,
        }
    }

    pub fn advisories_len(&self) -> usize {
        match self {
            Self::V1(envelope) => envelope.advisories.len(),
            Self::V2(envelope) => envelope.advisories.len(),
        }
    }

    pub fn contract_version(&self) -> &'static str {
        match self {
            Self::V1(_) => CORRELATION_VERSION,
            Self::V2(_) => CORRELATION_VERSION_V2,
        }
    }

    pub fn affected_version_evaluated(&self) -> bool {
        match self {
            Self::V1(_) => false,
            Self::V2(envelope) => envelope.semantics.affected_version_evaluated,
        }
    }
}

#[derive(Debug, Error)]
pub enum CorrelationError {
    #[error("finding not found in linked run: {0}")]
    FindingNotFound(String),
    #[error("invalid correlation field: {0}")]
    InvalidField(&'static str),
    #[error("too many advisory matches: {provided} (maximum {maximum})")]
    TooManyMatches { provided: usize, maximum: usize },
    #[error("could not format correlation timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    #[error("invalid correlation JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[allow(clippy::too_many_arguments)]
pub fn build_correlation(
    manifest: &RunManifest,
    manifest_sha256: String,
    finding_id: &str,
    ecosystem: String,
    package: String,
    version: Option<String>,
    catalog: CatalogProvenance,
    hits: Vec<CatalogHit>,
) -> Result<CorrelationEnvelope, CorrelationError> {
    let finding = manifest
        .findings
        .iter()
        .find(|finding| finding.finding_id == finding_id)
        .ok_or_else(|| CorrelationError::FindingNotFound(finding_id.to_owned()))?;
    if hits.len() > MAX_CORRELATION_MATCHES {
        return Err(CorrelationError::TooManyMatches {
            provided: hits.len(),
            maximum: MAX_CORRELATION_MATCHES,
        });
    }

    let mut advisories = hits
        .into_iter()
        .map(|hit| AdvisoryContext {
            canonical_id: hit.canonical_id,
            source_name: hit.source_name,
            source_record_id: hit.source_record_id,
            title: hit.title,
            modified_at: hit.modified_at,
            withdrawn: hit.withdrawn,
        })
        .collect::<Vec<_>>();
    advisories.sort_by(|left, right| {
        (
            &left.canonical_id,
            &left.source_name,
            &left.source_record_id,
        )
            .cmp(&(
                &right.canonical_id,
                &right.source_name,
                &right.source_record_id,
            ))
    });

    let mut envelope = CorrelationEnvelope {
        contract_version: CORRELATION_VERSION.into(),
        correlation_id: String::new(),
        created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        linked_run: LinkedRun {
            run_id: manifest.run_id.clone(),
            manifest_sha256,
            finding_id: finding_id.to_owned(),
            human_decision: finding.human_review.decision,
        },
        package_context: PackageContext {
            assertion: PACKAGE_ASSERTION.into(),
            ecosystem,
            name: package,
            version,
        },
        catalog,
        semantics: CorrelationSemantics {
            advisory_match_kind: MATCH_KIND.into(),
            affected_version_evaluated: false,
            causal_relationship_asserted: false,
            changes_human_decision: false,
            validation_authority: VALIDATION_AUTHORITY.into(),
        },
        advisories,
    };
    envelope.correlation_id = expected_correlation_id(&envelope);
    envelope.validate()?;
    Ok(envelope)
}

#[allow(clippy::too_many_arguments)]
pub fn build_correlation_v2(
    manifest: &RunManifest,
    manifest_sha256: String,
    finding_id: &str,
    ecosystem: String,
    package: String,
    version: Option<String>,
    catalog: CatalogProvenance,
    hits: Vec<CatalogVersionHit>,
) -> Result<CorrelationEnvelopeV2, CorrelationError> {
    let finding = manifest
        .findings
        .iter()
        .find(|finding| finding.finding_id == finding_id)
        .ok_or_else(|| CorrelationError::FindingNotFound(finding_id.to_owned()))?;
    if hits.len() > MAX_CORRELATION_MATCHES {
        return Err(CorrelationError::TooManyMatches {
            provided: hits.len(),
            maximum: MAX_CORRELATION_MATCHES,
        });
    }

    let mut advisories = hits
        .into_iter()
        .map(|hit| AdvisoryContextV2 {
            canonical_id: hit.advisory.canonical_id,
            source_name: hit.advisory.source_name,
            source_record_id: hit.advisory.source_record_id,
            title: hit.advisory.title,
            modified_at: hit.advisory.modified_at,
            withdrawn: hit.advisory.withdrawn,
            version_assessment: hit.version_assessment,
        })
        .collect::<Vec<_>>();
    advisories.sort_by(|left, right| {
        (
            &left.canonical_id,
            &left.source_name,
            &left.source_record_id,
        )
            .cmp(&(
                &right.canonical_id,
                &right.source_name,
                &right.source_record_id,
            ))
    });
    let version_summary = summarize_versions(&advisories);
    let version_requested = version.is_some();
    let mut envelope = CorrelationEnvelopeV2 {
        contract_version: CORRELATION_VERSION_V2.into(),
        correlation_id: String::new(),
        created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        linked_run: LinkedRun {
            run_id: manifest.run_id.clone(),
            manifest_sha256,
            finding_id: finding_id.to_owned(),
            human_decision: finding.human_review.decision,
        },
        package_context: PackageContext {
            assertion: PACKAGE_ASSERTION.into(),
            ecosystem,
            name: package,
            version,
        },
        catalog,
        semantics: CorrelationSemanticsV2 {
            advisory_match_kind: MATCH_KIND_V2.into(),
            version_evaluator: VERSION_EVALUATOR.into(),
            affected_version_evaluated: version_requested,
            version_result_validates_vulnerability: false,
            causal_relationship_asserted: false,
            changes_human_decision: false,
            validation_authority: VALIDATION_AUTHORITY.into(),
        },
        version_summary,
        advisories,
    };
    envelope.correlation_id = expected_correlation_id_v2(&envelope);
    envelope.validate()?;
    Ok(envelope)
}

pub fn parse_correlation(bytes: &[u8]) -> Result<CorrelationEnvelope, CorrelationError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CORRELATION_BYTES {
        return Err(CorrelationError::InvalidField("document size"));
    }
    let envelope: CorrelationEnvelope = serde_json::from_slice(bytes)?;
    envelope.validate()?;
    Ok(envelope)
}

pub fn parse_correlation_document(bytes: &[u8]) -> Result<CorrelationDocument, CorrelationError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CORRELATION_BYTES {
        return Err(CorrelationError::InvalidField("document size"));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    match value
        .get("contract_version")
        .and_then(serde_json::Value::as_str)
    {
        Some(CORRELATION_VERSION) => {
            let envelope: CorrelationEnvelope = serde_json::from_value(value)?;
            envelope.validate()?;
            Ok(CorrelationDocument::V1(envelope))
        }
        Some(CORRELATION_VERSION_V2) => {
            let envelope: CorrelationEnvelopeV2 = serde_json::from_value(value)?;
            envelope.validate()?;
            Ok(CorrelationDocument::V2(envelope))
        }
        _ => Err(CorrelationError::InvalidField("contract_version")),
    }
}

impl CorrelationEnvelope {
    pub fn validate(&self) -> Result<(), CorrelationError> {
        if self.contract_version != CORRELATION_VERSION {
            return Err(CorrelationError::InvalidField("contract_version"));
        }
        if OffsetDateTime::parse(&self.created_at, &Rfc3339).is_err() {
            return Err(CorrelationError::InvalidField("created_at"));
        }
        if !valid_run_id(&self.linked_run.run_id) {
            return Err(CorrelationError::InvalidField("linked_run.run_id"));
        }
        if !valid_sha256(&self.linked_run.manifest_sha256) {
            return Err(CorrelationError::InvalidField("linked_run.manifest_sha256"));
        }
        if self.linked_run.finding_id.trim().is_empty() || self.linked_run.finding_id.len() > 256 {
            return Err(CorrelationError::InvalidField("linked_run.finding_id"));
        }
        if self.package_context.assertion != PACKAGE_ASSERTION
            || !valid_short(&self.package_context.ecosystem, 100)
            || !valid_short(&self.package_context.name, 512)
            || self
                .package_context
                .version
                .as_ref()
                .is_some_and(|version| !valid_short(version, 256))
        {
            return Err(CorrelationError::InvalidField("package_context"));
        }
        if self.catalog.schema_version == 0
            || self.catalog.complete_snapshot_ids.is_empty()
            || self
                .catalog
                .complete_snapshot_ids
                .iter()
                .any(|value| !valid_hash_identifier(value, "sf_snapshot_"))
            || !self
                .catalog
                .complete_snapshot_ids
                .windows(2)
                .all(|window| window[0] < window[1])
            || self
                .catalog
                .complete_delta_ids
                .iter()
                .any(|value| !valid_hash_identifier(value, "sf_delta_"))
            || !self
                .catalog
                .complete_delta_ids
                .windows(2)
                .all(|window| window[0] < window[1])
            || self.catalog.canonicalization.trim().is_empty()
            || self
                .catalog
                .last_canonical_rebuild_id
                .as_ref()
                .is_some_and(|value| !valid_hash_identifier(value, "sf_canonical_"))
        {
            return Err(CorrelationError::InvalidField("catalog"));
        }
        if self.semantics.advisory_match_kind != MATCH_KIND
            || self.semantics.affected_version_evaluated
            || self.semantics.causal_relationship_asserted
            || self.semantics.changes_human_decision
            || self.semantics.validation_authority != VALIDATION_AUTHORITY
        {
            return Err(CorrelationError::InvalidField("semantics"));
        }
        if self.advisories.len() > MAX_CORRELATION_MATCHES {
            return Err(CorrelationError::TooManyMatches {
                provided: self.advisories.len(),
                maximum: MAX_CORRELATION_MATCHES,
            });
        }
        if self.advisories.iter().any(|advisory| {
            !valid_short(&advisory.canonical_id, 256)
                || !valid_short(&advisory.source_name, 128)
                || !valid_short(&advisory.source_record_id, 256)
                || advisory.title.len() > 16_384
                || OffsetDateTime::parse(&advisory.modified_at, &Rfc3339).is_err()
        }) {
            return Err(CorrelationError::InvalidField("advisories"));
        }
        if !self.advisories.windows(2).all(|window| {
            (
                &window[0].canonical_id,
                &window[0].source_name,
                &window[0].source_record_id,
            ) < (
                &window[1].canonical_id,
                &window[1].source_name,
                &window[1].source_record_id,
            )
        }) {
            return Err(CorrelationError::InvalidField(
                "advisories order or uniqueness",
            ));
        }
        if self.correlation_id != expected_correlation_id(self) {
            return Err(CorrelationError::InvalidField("correlation_id"));
        }
        Ok(())
    }
}

impl CorrelationEnvelopeV2 {
    pub fn validate(&self) -> Result<(), CorrelationError> {
        if self.contract_version != CORRELATION_VERSION_V2 {
            return Err(CorrelationError::InvalidField("contract_version"));
        }
        if OffsetDateTime::parse(&self.created_at, &Rfc3339).is_err()
            || !valid_run_id(&self.linked_run.run_id)
            || !valid_sha256(&self.linked_run.manifest_sha256)
            || self.linked_run.finding_id.trim().is_empty()
            || self.linked_run.finding_id.len() > 256
        {
            return Err(CorrelationError::InvalidField("linked_run or created_at"));
        }
        if self.package_context.assertion != PACKAGE_ASSERTION
            || !valid_short(&self.package_context.ecosystem, 100)
            || !valid_short(&self.package_context.name, 512)
            || self
                .package_context
                .version
                .as_ref()
                .is_some_and(|version| !valid_short(version, 256))
        {
            return Err(CorrelationError::InvalidField("package_context"));
        }
        if self.catalog.schema_version == 0
            || self.catalog.complete_snapshot_ids.is_empty()
            || self
                .catalog
                .complete_snapshot_ids
                .iter()
                .any(|value| !valid_hash_identifier(value, "sf_snapshot_"))
            || !self
                .catalog
                .complete_snapshot_ids
                .windows(2)
                .all(|window| window[0] < window[1])
            || self
                .catalog
                .complete_delta_ids
                .iter()
                .any(|value| !valid_hash_identifier(value, "sf_delta_"))
            || !self
                .catalog
                .complete_delta_ids
                .windows(2)
                .all(|window| window[0] < window[1])
            || self.catalog.canonicalization.trim().is_empty()
            || self
                .catalog
                .last_canonical_rebuild_id
                .as_ref()
                .is_some_and(|value| !valid_hash_identifier(value, "sf_canonical_"))
        {
            return Err(CorrelationError::InvalidField("catalog"));
        }
        let version_requested = self.package_context.version.is_some();
        if self.semantics.advisory_match_kind != MATCH_KIND_V2
            || self.semantics.version_evaluator != VERSION_EVALUATOR
            || self.semantics.affected_version_evaluated != version_requested
            || self.semantics.version_result_validates_vulnerability
            || self.semantics.causal_relationship_asserted
            || self.semantics.changes_human_decision
            || self.semantics.validation_authority != VALIDATION_AUTHORITY
        {
            return Err(CorrelationError::InvalidField("semantics"));
        }
        if self.advisories.len() > MAX_CORRELATION_MATCHES {
            return Err(CorrelationError::TooManyMatches {
                provided: self.advisories.len(),
                maximum: MAX_CORRELATION_MATCHES,
            });
        }
        if self.advisories.iter().any(|advisory| {
            !valid_short(&advisory.canonical_id, 256)
                || !valid_short(&advisory.source_name, 128)
                || !valid_short(&advisory.source_record_id, 256)
                || advisory.title.len() > 16_384
                || OffsetDateTime::parse(&advisory.modified_at, &Rfc3339).is_err()
                || !valid_version_assessment(
                    &advisory.version_assessment,
                    self.package_context.version.as_deref(),
                )
        }) {
            return Err(CorrelationError::InvalidField("advisories"));
        }
        if !self.advisories.windows(2).all(|window| {
            (
                &window[0].canonical_id,
                &window[0].source_name,
                &window[0].source_record_id,
            ) < (
                &window[1].canonical_id,
                &window[1].source_name,
                &window[1].source_record_id,
            )
        }) {
            return Err(CorrelationError::InvalidField(
                "advisories order or uniqueness",
            ));
        }
        if self.version_summary != summarize_versions(&self.advisories) {
            return Err(CorrelationError::InvalidField("version_summary"));
        }
        if self.correlation_id != expected_correlation_id_v2(self) {
            return Err(CorrelationError::InvalidField("correlation_id"));
        }
        Ok(())
    }
}

fn valid_version_assessment(assessment: &VersionAssessment, requested: Option<&str>) -> bool {
    if assessment.affected_data_sha256.is_empty()
        || assessment
            .affected_data_sha256
            .iter()
            .any(|value| !valid_sha256(value))
        || !assessment
            .affected_data_sha256
            .windows(2)
            .all(|window| window[0] < window[1])
        || !assessment
            .issues
            .windows(2)
            .all(|window| window[0] < window[1])
    {
        return false;
    }
    match assessment.status {
        VersionEvaluationStatus::NotEvaluated => {
            requested.is_none()
                && assessment.basis == VersionEvaluationBasis::NotRequested
                && assessment.evaluated_version.is_none()
                && assessment.matched_value.is_none()
                && assessment.issues.is_empty()
        }
        VersionEvaluationStatus::Affected => {
            let Some(requested) = requested else {
                return false;
            };
            assessment.evaluated_version.as_deref() == Some(requested)
                && assessment.issues.is_empty()
                && match assessment.basis {
                    VersionEvaluationBasis::ExactEnumeratedVersion => {
                        assessment.matched_value.as_deref() == Some(requested)
                    }
                    VersionEvaluationBasis::OsvSemverRange => assessment
                        .matched_value
                        .as_deref()
                        .is_some_and(valid_sha256),
                    _ => false,
                }
        }
        VersionEvaluationStatus::NotAffected => {
            requested.is_some()
                && assessment.evaluated_version.as_deref() == requested
                && assessment.basis == VersionEvaluationBasis::SupportedDataExcludesVersion
                && assessment.matched_value.is_none()
                && assessment.issues.is_empty()
        }
        VersionEvaluationStatus::Unknown => {
            requested.is_some()
                && assessment.evaluated_version.as_deref() == requested
                && assessment.basis == VersionEvaluationBasis::UnsupportedOrInvalidData
                && assessment.matched_value.is_none()
                && !assessment.issues.is_empty()
        }
    }
}

fn summarize_versions(advisories: &[AdvisoryContextV2]) -> VersionSummary {
    let mut summary = VersionSummary {
        affected: 0,
        not_affected: 0,
        unknown: 0,
        not_evaluated: 0,
    };
    for advisory in advisories {
        match advisory.version_assessment.status {
            VersionEvaluationStatus::Affected => summary.affected += 1,
            VersionEvaluationStatus::NotAffected => summary.not_affected += 1,
            VersionEvaluationStatus::Unknown => summary.unknown += 1,
            VersionEvaluationStatus::NotEvaluated => summary.not_evaluated += 1,
        }
    }
    summary
}

fn expected_correlation_id(envelope: &CorrelationEnvelope) -> String {
    #[derive(Serialize)]
    struct Identity<'a> {
        linked_run: &'a LinkedRun,
        package_context: &'a PackageContext,
        catalog: &'a CatalogProvenance,
        semantics: &'a CorrelationSemantics,
        advisories: &'a [AdvisoryContext],
    }
    let bytes = serde_json::to_vec(&Identity {
        linked_run: &envelope.linked_run,
        package_context: &envelope.package_context,
        catalog: &envelope.catalog,
        semantics: &envelope.semantics,
        advisories: &envelope.advisories,
    })
    .expect("correlation identity contains only serializable fields");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing into a String cannot fail");
    }
    format!("sf_correlation_{encoded}")
}

fn expected_correlation_id_v2(envelope: &CorrelationEnvelopeV2) -> String {
    #[derive(Serialize)]
    struct Identity<'a> {
        linked_run: &'a LinkedRun,
        package_context: &'a PackageContext,
        catalog: &'a CatalogProvenance,
        semantics: &'a CorrelationSemanticsV2,
        version_summary: &'a VersionSummary,
        advisories: &'a [AdvisoryContextV2],
    }
    let bytes = serde_json::to_vec(&Identity {
        linked_run: &envelope.linked_run,
        package_context: &envelope.package_context,
        catalog: &envelope.catalog,
        semantics: &envelope.semantics,
        version_summary: &envelope.version_summary,
        advisories: &envelope.advisories,
    })
    .expect("correlation identity contains only serializable fields");
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing into a String cannot fail");
    }
    format!("sf_correlation_{encoded}")
}

fn valid_hash_identifier(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 64 && valid_sha256(suffix))
}

fn valid_run_id(value: &str) -> bool {
    value.strip_prefix("sf_run_").is_some_and(|suffix| {
        (16..=80).contains(&suffix.len())
            && suffix.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_short(value: &str, max: usize) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= max
        && !trimmed.chars().any(|character| character.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> CorrelationEnvelope {
        let mut envelope = CorrelationEnvelope {
            contract_version: CORRELATION_VERSION.into(),
            correlation_id: String::new(),
            created_at: "2026-08-23T16:00:00Z".into(),
            linked_run: LinkedRun {
                run_id: format!("sf_run_{}", "1".repeat(64)),
                manifest_sha256: "2".repeat(64),
                finding_id: "sf_finding_example".into(),
                human_decision: HumanDecision::Pending,
            },
            package_context: PackageContext {
                assertion: PACKAGE_ASSERTION.into(),
                ecosystem: "crates.io".into(),
                name: "example".into(),
                version: Some("1.0.0".into()),
            },
            catalog: CatalogProvenance {
                schema_version: 2,
                complete_snapshot_ids: vec![format!("sf_snapshot_{}", "3".repeat(64))],
                complete_delta_ids: Vec::new(),
                canonicalization: "exact-osv-alias-rebuild-v2".into(),
                last_canonical_rebuild_id: Some(format!("sf_canonical_{}", "4".repeat(64))),
            },
            semantics: CorrelationSemantics {
                advisory_match_kind: MATCH_KIND.into(),
                affected_version_evaluated: false,
                causal_relationship_asserted: false,
                changes_human_decision: false,
                validation_authority: VALIDATION_AUTHORITY.into(),
            },
            advisories: vec![],
        };
        envelope.correlation_id = expected_correlation_id(&envelope);
        envelope
    }

    fn fixture_v2() -> CorrelationEnvelopeV2 {
        let advisories = vec![AdvisoryContextV2 {
            canonical_id: format!("sf_vuln_{}", "5".repeat(64)),
            source_name: "fixture-osv".into(),
            source_record_id: "GHSA-aaaa-bbbb-cccc".into(),
            title: "bounded fixture".into(),
            modified_at: "2026-08-23T16:00:00Z".into(),
            withdrawn: false,
            version_assessment: VersionAssessment {
                status: VersionEvaluationStatus::Affected,
                basis: VersionEvaluationBasis::OsvSemverRange,
                evaluated_version: Some("1.5.0".into()),
                matched_value: Some("6".repeat(64)),
                affected_data_sha256: vec!["7".repeat(64)],
                issues: vec![],
            },
        }];
        let mut envelope = CorrelationEnvelopeV2 {
            contract_version: CORRELATION_VERSION_V2.into(),
            correlation_id: String::new(),
            created_at: "2026-08-23T16:00:00Z".into(),
            linked_run: LinkedRun {
                run_id: format!("sf_run_{}", "1".repeat(64)),
                manifest_sha256: "2".repeat(64),
                finding_id: "sf_finding_example".into(),
                human_decision: HumanDecision::Pending,
            },
            package_context: PackageContext {
                assertion: PACKAGE_ASSERTION.into(),
                ecosystem: "crates.io".into(),
                name: "example".into(),
                version: Some("1.5.0".into()),
            },
            catalog: CatalogProvenance {
                schema_version: 2,
                complete_snapshot_ids: vec![format!("sf_snapshot_{}", "3".repeat(64))],
                complete_delta_ids: Vec::new(),
                canonicalization: "exact-osv-alias-rebuild-v2".into(),
                last_canonical_rebuild_id: Some(format!("sf_canonical_{}", "4".repeat(64))),
            },
            semantics: CorrelationSemanticsV2 {
                advisory_match_kind: MATCH_KIND_V2.into(),
                version_evaluator: VERSION_EVALUATOR.into(),
                affected_version_evaluated: true,
                version_result_validates_vulnerability: false,
                causal_relationship_asserted: false,
                changes_human_decision: false,
                validation_authority: VALIDATION_AUTHORITY.into(),
            },
            version_summary: summarize_versions(&advisories),
            advisories,
        };
        envelope.correlation_id = expected_correlation_id_v2(&envelope);
        envelope
    }

    #[test]
    fn accepts_conservative_pending_context() {
        let envelope = fixture();
        envelope.validate().unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(parse_correlation(&bytes).unwrap(), envelope);
    }

    #[test]
    fn rejects_a_claim_that_correlation_changes_human_decision() {
        let mut envelope = fixture();
        envelope.semantics.changes_human_decision = true;
        envelope.correlation_id = expected_correlation_id(&envelope);
        assert!(matches!(
            envelope.validate(),
            Err(CorrelationError::InvalidField("semantics"))
        ));
    }

    #[test]
    fn identity_is_stable_across_creation_time() {
        let left = fixture();
        let mut right = left.clone();
        right.created_at = "2026-08-24T16:00:00Z".into();
        right.correlation_id = expected_correlation_id(&right);
        assert_eq!(left.correlation_id, right.correlation_id);
        left.validate().unwrap();
        right.validate().unwrap();
    }

    #[test]
    fn v2_preserves_affected_as_context_without_validation_authority() {
        let envelope = fixture_v2();
        envelope.validate().unwrap();
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let parsed = parse_correlation_document(&bytes).unwrap();
        assert_eq!(parsed.contract_version(), CORRELATION_VERSION_V2);
        assert!(parsed.affected_version_evaluated());
        assert_eq!(parsed.advisories_len(), 1);
    }

    #[test]
    fn v2_rejects_a_version_result_that_claims_to_validate_a_vulnerability() {
        let mut envelope = fixture_v2();
        envelope.semantics.version_result_validates_vulnerability = true;
        envelope.correlation_id = expected_correlation_id_v2(&envelope);
        assert!(matches!(
            envelope.validate(),
            Err(CorrelationError::InvalidField("semantics"))
        ));
    }
}
