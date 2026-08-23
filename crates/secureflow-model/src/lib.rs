//! Stable local data model for the first SecureFlow run contract.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const CONTRACT_VERSION: &str = "secureflow-run-v1";
pub const ENGINE_REPORT_SCHEMA: &str = "secure-json-v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    pub contract_version: String,
    pub run_id: String,
    pub status: RunStatus,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub target: Target,
    pub engine: EngineProvenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_sha256: Option<String>,
    pub phases: Phases,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<Summary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<EvaluationReference>,
}

impl RunManifest {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ModelError::UnsupportedContract(self.contract_version.clone()));
        }
        if !valid_identifier(&self.run_id, "sf_run_", 16, 80) {
            return Err(ModelError::InvalidIdentifier("run_id"));
        }
        let created_at = validate_timestamp(&self.created_at, "created_at")?;
        match (self.status.is_terminal(), self.completed_at.as_deref()) {
            (true, None) => {
                return Err(ModelError::InconsistentState(
                    "terminal runs require completed_at",
                ));
            }
            (false, Some(_)) => {
                return Err(ModelError::InconsistentState(
                    "non-terminal runs cannot have completed_at",
                ));
            }
            (_, _) => {}
        }
        if let Some(value) = &self.completed_at {
            let completed_at = validate_timestamp(value, "completed_at")?;
            if completed_at < created_at {
                return Err(ModelError::InconsistentState(
                    "completed_at cannot precede created_at",
                ));
            }
        }
        if let Some(value) = &self.configuration_sha256 {
            validate_sha256(value, "configuration_sha256")?;
        }
        self.target.validate()?;
        self.engine.validate()?;
        let mut artifact_paths = BTreeSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_paths.insert(&artifact.relative_path) {
                return Err(ModelError::DuplicateIdentifier("artifact.relative_path"));
            }
        }
        let mut finding_ids = BTreeSet::new();
        for finding in &self.findings {
            finding.validate()?;
            if !finding_ids.insert(&finding.finding_id) {
                return Err(ModelError::DuplicateIdentifier("finding_id"));
            }
        }
        self.phases.validate(&self.findings)?;
        if let Some(summary) = &self.summary {
            summary.validate(&self.findings)?;
        }
        if let Some(evaluation) = &self.evaluation {
            evaluation.validate()?;
        }
        Ok(())
    }

    pub fn validated_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.human_review.decision == HumanDecision::Validated)
    }
}

/// Orders candidates reproducibly without asserting that the first item is
/// more likely to be a vulnerability. Human review remains authoritative.
pub fn prioritize_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| confidence_rank(right.confidence).cmp(&confidence_rank(left.confidence)))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.source_location.path.cmp(&right.source_location.path))
            .then_with(|| left.source_location.start_line.cmp(&right.source_location.start_line))
            .then_with(|| left.sink_location.path.cmp(&right.sink_location.path))
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });
}

/// Removes exact duplicate candidates from one engine run. The first item is
/// retained, so callers should prioritize before calling this function when
/// duplicate metadata differs. Cross-engine equivalence is intentionally not
/// inferred here.
pub fn deduplicate_findings(findings: &mut Vec<Finding>) -> usize {
    let original_len = findings.len();
    let mut seen = BTreeSet::new();
    findings.retain(|finding| {
        let fingerprint = finding
            .engine_fingerprint
            .as_deref()
            .unwrap_or(&finding.finding_id);
        let key = format!(
            "{fingerprint}|{}|{}|{}",
            finding.rule_id,
            location_key(&finding.source_location),
            location_key(&finding.sink_location)
        );
        seen.insert(key)
    });
    original_len - findings.len()
}

fn location_key(location: &Location) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        location.path,
        location.start_line,
        location.start_column,
        location.end_line.unwrap_or_default(),
        location.end_column.unwrap_or_default()
    )
}

fn severity_rank(value: Option<Severity>) -> u8 {
    match value {
        Some(Severity::Critical) => 5,
        Some(Severity::High) => 4,
        Some(Severity::Medium) => 3,
        Some(Severity::Low) => 2,
        Some(Severity::Unknown) | None => 1,
    }
}

fn confidence_rank(value: Confidence) -> u8 {
    match value {
        Confidence::High => 4,
        Confidence::Medium => 3,
        Confidence::Low => 2,
        Confidence::Unknown => 1,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Created,
    Running,
    Completed,
    Partial,
    Failed,
    Cancelled,
}

impl RunStatus {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Partial | Self::Failed | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub label: String,
    pub root_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
    pub authorization: Authorization,
}

impl Target {
    fn validate(&self) -> Result<(), ModelError> {
        validate_sha256(&self.root_sha256, "target.root_sha256")?;
        validate_bounded_string(&self.label, "target.label", 200)?;
        if let Some(revision) = &self.revision {
            revision.validate()?;
        }
        self.authorization.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub kind: RevisionKind,
    pub value: String,
}

impl Revision {
    fn validate(&self) -> Result<(), ModelError> {
        validate_bounded_string(&self.value, "target.revision.value", 200)?;
        if self.kind == RevisionKind::Git
            && !is_lower_hex_of_length(&self.value, 40)
            && !is_lower_hex_of_length(&self.value, 64)
        {
            return Err(ModelError::InvalidRevision);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevisionKind {
    Git,
    Snapshot,
    WorkingTree,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub status: AuthorizationStatus,
    pub basis: AuthorizationBasis,
    pub reviewer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl Authorization {
    fn validate(&self) -> Result<(), ModelError> {
        if self.status != AuthorizationStatus::Authorized {
            return Err(ModelError::AuthorizationRequired);
        }
        validate_bounded_string(&self.reviewer, "target.authorization.reviewer", 200)?;
        validate_optional_string(
            self.reference.as_deref(),
            "target.authorization.reference",
            300,
        )?;
        if let Some(value) = &self.expires_at {
            validate_timestamp(value, "target.authorization.expires_at")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationStatus {
    Authorized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationBasis {
    RepositoryOwner,
    WrittenConsent,
    OrganizationPolicy,
    LocalProject,
    OtherDocumented,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngineProvenance {
    pub name: String,
    pub version: String,
    pub binary_sha256: String,
    pub report_schema: String,
    pub report_sha256: String,
}

impl EngineProvenance {
    fn validate(&self) -> Result<(), ModelError> {
        validate_bounded_string(&self.name, "engine.name", 100)?;
        validate_bounded_string(&self.version, "engine.version", 100)?;
        if self.report_schema != ENGINE_REPORT_SCHEMA {
            return Err(ModelError::UnsupportedReportSchema(self.report_schema.clone()));
        }
        validate_sha256(&self.binary_sha256, "engine.binary_sha256")?;
        validate_sha256(&self.report_sha256, "engine.report_sha256")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Phases {
    pub deterministic: PhaseStatus,
    pub prioritization: PhaseStatus,
    pub validation: PhaseStatus,
    pub evaluation: PhaseStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Pending,
    Running,
    Completed,
    Partial,
    Failed,
    Skipped,
}

impl Phases {
    fn validate(&self, findings: &[Finding]) -> Result<(), ModelError> {
        let pending = findings
            .iter()
            .filter(|finding| finding.human_review.decision == HumanDecision::Pending)
            .count();
        let reviewed = findings.len().saturating_sub(pending);
        match self.validation {
            PhaseStatus::Completed if pending != 0 => Err(ModelError::InconsistentState(
                "completed validation cannot contain pending findings",
            )),
            PhaseStatus::Partial if pending == 0 || reviewed == 0 => {
                Err(ModelError::InconsistentState(
                    "partial validation requires reviewed and pending findings",
                ))
            }
            PhaseStatus::Skipped if reviewed != 0 => Err(ModelError::InconsistentState(
                "skipped validation cannot contain reviewed findings",
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub relative_path: String,
    pub sha256: String,
    pub bytes: u64,
}

impl Artifact {
    fn validate(&self) -> Result<(), ModelError> {
        validate_relative_path(&self.relative_path, "artifact.relative_path")?;
        validate_sha256(&self.sha256, "artifact.sha256")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    RawReport,
    AdaptedReport,
    RedactedPayload,
    Log,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
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
    #[serde(default)]
    pub limitations: Vec<String>,
    pub human_review: HumanReview,
    pub ai_validation: AiValidation,
}

impl Finding {
    fn validate(&self) -> Result<(), ModelError> {
        if !valid_identifier(&self.finding_id, "sf_finding_", 16, 100) {
            return Err(ModelError::InvalidIdentifier("finding_id"));
        }
        validate_optional_string(
            self.engine_fingerprint.as_deref(),
            "finding.engine_fingerprint",
            200,
        )?;
        validate_bounded_string(&self.title, "finding.title", 300)?;
        validate_bounded_string(&self.rule_id, "finding.rule_id", 100)?;
        validate_bounded_string(&self.invariant, "finding.invariant", 1000)?;
        if let Some(taxonomy) = &self.taxonomy {
            taxonomy.validate()?;
        }
        self.source_location.validate()?;
        self.sink_location.validate()?;
        if self.evidence_path.is_empty() {
            return Err(ModelError::EmptyEvidencePath);
        }
        for step in &self.evidence_path {
            step.location.validate()?;
            validate_bounded_string(&step.description, "finding.evidence.description", 1000)?;
        }
        for limitation in &self.limitations {
            validate_bounded_string(limitation, "finding.limitations", 500)?;
        }
        self.human_review.validate()?;
        self.ai_validation.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyCoordinates {
    pub version: String,
    pub category_id: String,
    pub invariant_id: String,
}

impl TaxonomyCoordinates {
    fn validate(&self) -> Result<(), ModelError> {
        validate_bounded_string(&self.version, "finding.taxonomy.version", 50)?;
        validate_bounded_string(&self.category_id, "finding.taxonomy.category_id", 100)?;
        validate_bounded_string(
            &self.invariant_id,
            "finding.taxonomy.invariant_id",
            100,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub path: String,
    pub start_line: u32,
    pub start_column: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
}

impl Location {
    fn validate(&self) -> Result<(), ModelError> {
        validate_relative_path(&self.path, "location.path")?;
        if self.start_line == 0 || self.start_column == 0 {
            return Err(ModelError::InvalidLocation);
        }
        if self.end_line == Some(0) || self.end_column == Some(0) {
            return Err(ModelError::InvalidLocation);
        }
        if let Some(end_line) = self.end_line {
            if end_line < self.start_line
                || (end_line == self.start_line
                    && self.end_column.is_some_and(|column| column < self.start_column))
            {
                return Err(ModelError::InvalidLocation);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStep {
    pub kind: EvidenceKind,
    pub location: Location,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceKind {
    Source,
    Transform,
    Guard,
    Sanitizer,
    Authorization,
    Sink,
    Barrier,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanReview {
    pub decision: HumanDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_reference: Option<String>,
}

impl HumanReview {
    fn validate(&self) -> Result<(), ModelError> {
        validate_optional_string(self.reviewer.as_deref(), "human_review.reviewer", 200)?;
        validate_optional_string(self.rationale.as_deref(), "human_review.rationale", 3000)?;
        validate_optional_string(
            self.evidence_reference.as_deref(),
            "human_review.evidence_reference",
            300,
        )?;
        if let Some(value) = &self.reviewed_at {
            validate_timestamp(value, "human_review.reviewed_at")?;
        }
        let has_review_metadata = self.reviewer.is_some()
            || self.reviewed_at.is_some()
            || self.rationale.is_some()
            || self.evidence_reference.is_some();
        if self.decision == HumanDecision::Pending && has_review_metadata {
            return Err(ModelError::InconsistentState(
                "pending human review cannot contain review metadata",
            ));
        }
        if self.decision != HumanDecision::Pending
            && (self.reviewer.is_none() || self.reviewed_at.is_none() || self.rationale.is_none())
        {
            return Err(ModelError::InconsistentState(
                "human decisions require reviewer, reviewed_at and rationale",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HumanDecision {
    Pending,
    Validated,
    Rejected,
    Abstained,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiValidation {
    pub status: AiValidationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_payload_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment: Option<AiAssessment>,
}

impl AiValidation {
    fn validate(&self) -> Result<(), ModelError> {
        if let Some(value) = &self.request_id {
            if !valid_identifier(value, "sf_ai_request_", 64, 64) {
                return Err(ModelError::InvalidIdentifier("ai_validation.request_id"));
            }
        }
        validate_optional_string(self.provider.as_deref(), "ai_validation.provider", 100)?;
        validate_optional_string(self.model.as_deref(), "ai_validation.model", 100)?;
        validate_optional_string(
            self.prompt_version.as_deref(),
            "ai_validation.prompt_version",
            100,
        )?;
        if let Some(value) = &self.redacted_payload_sha256 {
            validate_sha256(value, "ai_validation.redacted_payload_sha256")?;
        }
        if let Some(value) = &self.response_sha256 {
            validate_sha256(value, "ai_validation.response_sha256")?;
        }
        if self.input_tokens.is_some_and(|value| value > 10_000_000)
            || self.output_tokens.is_some_and(|value| value > 10_000_000)
        {
            return Err(ModelError::InconsistentState(
                "AI token counts exceed the contract limit",
            ));
        }
        let request_metadata_complete = self.request_id.is_some()
            && self.provider.is_some()
            && self.model.is_some()
            && self.prompt_version.is_some()
            && self.redacted_payload_sha256.is_some();
        let has_any_metadata = self.request_id.is_some()
            || self.provider.is_some()
            || self.model.is_some()
            || self.prompt_version.is_some()
            || self.redacted_payload_sha256.is_some()
            || self.response_sha256.is_some()
            || self.input_tokens.is_some()
            || self.output_tokens.is_some()
            || self.assessment.is_some();
        match self.status {
            AiValidationStatus::NotRequested | AiValidationStatus::Skipped
                if has_any_metadata =>
            {
                return Err(ModelError::InconsistentState(
                    "inactive AI validation cannot contain request or response metadata",
                ));
            }
            AiValidationStatus::Queued
                if !request_metadata_complete
                    || self.response_sha256.is_some()
                    || self.input_tokens.is_some()
                    || self.output_tokens.is_some()
                    || self.assessment.is_some() =>
            {
                return Err(ModelError::InconsistentState(
                    "queued AI validation requires request metadata only",
                ));
            }
            AiValidationStatus::Completed
                if !request_metadata_complete
                    || self.response_sha256.is_none()
                    || self.input_tokens.is_none()
                    || self.output_tokens.is_none()
                    || self.assessment.is_none() =>
            {
                return Err(ModelError::InconsistentState(
                    "completed AI validation requires request, response, token and assessment metadata",
                ));
            }
            AiValidationStatus::Failed
                if !request_metadata_complete || self.assessment.is_some() =>
            {
                return Err(ModelError::InconsistentState(
                    "failed AI validation requires request metadata and cannot assess",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiValidationStatus {
    NotRequested,
    Queued,
    Completed,
    Failed,
    Skipped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AiAssessment {
    Supports,
    Insufficient,
    Contradicts,
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub candidate_count: u64,
    #[serde(default)]
    pub duplicate_count: u64,
    pub validated_count: u64,
    pub rejected_count: u64,
    pub abstained_count: u64,
    pub ai_calls: u64,
    pub ai_input_tokens: u64,
    pub ai_output_tokens: u64,
}

impl Summary {
    fn validate(&self, findings: &[Finding]) -> Result<(), ModelError> {
        let validated = findings
            .iter()
            .filter(|finding| finding.human_review.decision == HumanDecision::Validated)
            .count() as u64;
        let rejected = findings
            .iter()
            .filter(|finding| finding.human_review.decision == HumanDecision::Rejected)
            .count() as u64;
        let abstained = findings
            .iter()
            .filter(|finding| finding.human_review.decision == HumanDecision::Abstained)
            .count() as u64;
        let ai_calls = findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.ai_validation.status,
                    AiValidationStatus::Completed | AiValidationStatus::Failed
                )
            })
            .count() as u64;
        let ai_input_tokens = findings
            .iter()
            .filter_map(|finding| finding.ai_validation.input_tokens)
            .sum::<u64>();
        let ai_output_tokens = findings
            .iter()
            .filter_map(|finding| finding.ai_validation.output_tokens)
            .sum::<u64>();
        if self.candidate_count != findings.len() as u64
            || self.validated_count != validated
            || self.rejected_count != rejected
            || self.abstained_count != abstained
            || self.ai_calls != ai_calls
            || self.ai_input_tokens != ai_input_tokens
            || self.ai_output_tokens != ai_output_tokens
        {
            return Err(ModelError::SummaryMismatch);
        }
        Ok(())
    }
}

impl RunManifest {
    /// Recomputes review and AI counters while preserving only the
    /// deduplication count recorded for this run.
    pub fn refresh_summary(&mut self) {
        let (validated_count, rejected_count, abstained_count) = self
            .findings
            .iter()
            .fold((0_u64, 0_u64, 0_u64), |counts, finding| {
                let (validated, rejected, abstained) = counts;
                match finding.human_review.decision {
                    HumanDecision::Validated => (validated + 1, rejected, abstained),
                    HumanDecision::Rejected => (validated, rejected + 1, abstained),
                    HumanDecision::Abstained => (validated, rejected, abstained + 1),
                    HumanDecision::Pending => counts,
                }
            });
        let ai_calls = self
            .findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.ai_validation.status,
                    AiValidationStatus::Completed | AiValidationStatus::Failed
                )
            })
            .count() as u64;
        let ai_input_tokens = self
            .findings
            .iter()
            .filter_map(|finding| finding.ai_validation.input_tokens)
            .sum();
        let ai_output_tokens = self
            .findings
            .iter()
            .filter_map(|finding| finding.ai_validation.output_tokens)
            .sum();
        let previous = self.summary.take().unwrap_or(Summary {
            candidate_count: 0,
            duplicate_count: 0,
            validated_count: 0,
            rejected_count: 0,
            abstained_count: 0,
            ai_calls: 0,
            ai_input_tokens: 0,
            ai_output_tokens: 0,
        });
        self.summary = Some(Summary {
            candidate_count: self.findings.len() as u64,
            duplicate_count: previous.duplicate_count,
            validated_count,
            rejected_count,
            abstained_count,
            ai_calls,
            ai_input_tokens,
            ai_output_tokens,
        });
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReference {
    pub harness: EvaluationHarness,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_sha256: Option<String>,
    pub status: EvaluationStatus,
}

impl EvaluationReference {
    fn validate(&self) -> Result<(), ModelError> {
        validate_optional_string(self.harness_version.as_deref(), "evaluation.harness_version", 100)?;
        if let Some(value) = &self.manifest_sha256 {
            validate_sha256(value, "evaluation.manifest_sha256")?;
        }
        if let Some(value) = &self.result_sha256 {
            validate_sha256(value, "evaluation.result_sha256")?;
        }
        if self.status == EvaluationStatus::Completed
            && (self.manifest_sha256.is_none() || self.result_sha256.is_none())
        {
            return Err(ModelError::InconsistentState(
                "completed evaluation requires manifest and result hashes",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluationHarness {
    SecureBench,
    LocalFixture,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationStatus {
    NotRun,
    Completed,
    Partial,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    UnsupportedContract(String),
    UnsupportedReportSchema(String),
    InvalidIdentifier(&'static str),
    DuplicateIdentifier(&'static str),
    InvalidSha256(&'static str),
    InvalidRelativePath(&'static str),
    EmptyField(&'static str),
    FieldTooLong(&'static str),
    InvalidTimestamp(&'static str),
    InvalidRevision,
    InconsistentState(&'static str),
    SummaryMismatch,
    AuthorizationRequired,
    InvalidLocation,
    EmptyEvidencePath,
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedContract(value) => write!(formatter, "unsupported contract: {value}"),
            Self::UnsupportedReportSchema(value) => write!(formatter, "unsupported report schema: {value}"),
            Self::InvalidIdentifier(field) => write!(formatter, "invalid identifier: {field}"),
            Self::DuplicateIdentifier(field) => write!(formatter, "duplicate identifier: {field}"),
            Self::InvalidSha256(field) => write!(formatter, "invalid SHA-256: {field}"),
            Self::InvalidRelativePath(field) => write!(formatter, "invalid relative path: {field}"),
            Self::EmptyField(field) => write!(formatter, "empty field: {field}"),
            Self::FieldTooLong(field) => write!(formatter, "field exceeds maximum length: {field}"),
            Self::InvalidTimestamp(field) => write!(formatter, "invalid RFC3339 timestamp: {field}"),
            Self::InvalidRevision => write!(formatter, "invalid full Git revision"),
            Self::InconsistentState(message) => write!(formatter, "inconsistent state: {message}"),
            Self::SummaryMismatch => write!(formatter, "summary does not match findings"),
            Self::AuthorizationRequired => write!(formatter, "explicit authorization is required"),
            Self::InvalidLocation => write!(formatter, "invalid source location"),
            Self::EmptyEvidencePath => write!(formatter, "evidence path cannot be empty"),
        }
    }
}

impl std::error::Error for ModelError {}

fn valid_identifier(value: &str, prefix: &str, min_suffix: usize, max_suffix: usize) -> bool {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return false;
    };
    (min_suffix..=max_suffix).contains(&suffix.len())
        && suffix.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
        })
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidSha256(field))
    }
}

fn is_lower_hex_of_length(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_bounded_string(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(ModelError::EmptyField(field));
    }
    if value.chars().count() > max_chars {
        return Err(ModelError::FieldTooLong(field));
    }
    Ok(())
}

fn validate_optional_string(
    value: Option<&str>,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ModelError> {
    if let Some(value) = value {
        validate_bounded_string(value, field, max_chars)?;
    }
    Ok(())
}

fn validate_timestamp(
    value: &str,
    field: &'static str,
) -> Result<OffsetDateTime, ModelError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| ModelError::InvalidTimestamp(field))
}

fn validate_relative_path(value: &str, field: &'static str) -> Result<(), ModelError> {
    let path = std::path::Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || path.components().any(|component| component == std::path::Component::ParentDir)
    {
        Err(ModelError::InvalidRelativePath(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, severity: Severity, confidence: Confidence) -> Finding {
        let location = Location {
            path: "src/app.ts".into(),
            start_line: 1,
            start_column: 1,
            end_line: Some(1),
            end_column: Some(2),
        };
        Finding {
            finding_id: format!("sf_finding_{id}"),
            engine_fingerprint: None,
            title: "candidate".into(),
            rule_id: "SE1001".into(),
            taxonomy: None,
            severity: Some(severity),
            confidence,
            source_location: location.clone(),
            sink_location: location.clone(),
            invariant: "invariant".into(),
            evidence_path: vec![EvidenceStep {
                kind: EvidenceKind::Source,
                location,
                description: "source".into(),
            }],
            limitations: Vec::new(),
            human_review: HumanReview {
                decision: HumanDecision::Pending,
                reviewer: None,
                reviewed_at: None,
                rationale: None,
                evidence_reference: None,
            },
            ai_validation: AiValidation {
                status: AiValidationStatus::NotRequested,
                request_id: None,
                provider: None,
                model: None,
                prompt_version: None,
                redacted_payload_sha256: None,
                response_sha256: None,
                input_tokens: None,
                output_tokens: None,
                assessment: None,
            },
        }
    }

    fn manifest() -> RunManifest {
        RunManifest {
            contract_version: CONTRACT_VERSION.into(),
            run_id: "sf_run_test_0000000000000000".into(),
            status: RunStatus::Completed,
            created_at: "2026-08-23T03:00:00Z".into(),
            completed_at: Some("2026-08-23T03:00:01Z".into()),
            target: Target {
                label: "fixture".into(),
                root_sha256: "a".repeat(64),
                revision: None,
                authorization: Authorization {
                    status: AuthorizationStatus::Authorized,
                    basis: AuthorizationBasis::LocalProject,
                    reviewer: "human".into(),
                    reference: None,
                    expires_at: None,
                },
            },
            engine: EngineProvenance {
                name: "secure-engine".into(),
                version: "0.1.10-rc2".into(),
                binary_sha256: "b".repeat(64),
                report_schema: ENGINE_REPORT_SCHEMA.into(),
                report_sha256: "c".repeat(64),
            },
            configuration_sha256: None,
            phases: Phases {
                deterministic: PhaseStatus::Completed,
                prioritization: PhaseStatus::Completed,
                validation: PhaseStatus::Skipped,
                evaluation: PhaseStatus::Skipped,
            },
            artifacts: Vec::new(),
            findings: Vec::new(),
            summary: None,
            evaluation: None,
        }
    }

    #[test]
    fn validates_minimal_authorized_manifest() {
        assert!(manifest().validate().is_ok());
    }

    #[test]
    fn rejects_unknown_contract_fields_at_root_and_nested_levels() {
        let mut root = serde_json::to_value(manifest()).expect("serialize manifest");
        root.as_object_mut()
            .expect("manifest object")
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<RunManifest>(root).is_err());

        let mut nested = serde_json::to_value(manifest()).expect("serialize manifest");
        nested["target"]
            .as_object_mut()
            .expect("target object")
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<RunManifest>(nested).is_err());
    }

    #[test]
    fn rejects_empty_target_label() {
        let mut value = manifest();
        value.target.label.clear();
        assert_eq!(value.validate(), Err(ModelError::EmptyField("target.label")));
    }

    #[test]
    fn git_revision_requires_a_full_lowercase_object_id() {
        let mut value = manifest();
        value.target.revision = Some(Revision {
            kind: RevisionKind::Git,
            value: "4c3de58".into(),
        });
        assert_eq!(value.validate(), Err(ModelError::InvalidRevision));
        value.target.revision.as_mut().expect("revision").value = "a".repeat(40);
        assert!(value.validate().is_ok());
    }

    #[test]
    fn rejects_terminal_run_without_completed_at() {
        let mut value = manifest();
        value.completed_at = None;
        assert_eq!(
            value.validate(),
            Err(ModelError::InconsistentState(
                "terminal runs require completed_at"
            ))
        );
    }

    #[test]
    fn rejects_invalid_created_at() {
        let mut value = manifest();
        value.created_at = "yesterday".into();
        assert_eq!(
            value.validate(),
            Err(ModelError::InvalidTimestamp("created_at"))
        );
    }

    #[test]
    fn rejects_absolute_artifact_path() {
        let mut value = manifest();
        value.artifacts.push(Artifact {
            kind: ArtifactKind::Log,
            relative_path: "/tmp/log".into(),
            sha256: "d".repeat(64),
            bytes: 1,
        });
        assert_eq!(
            value.validate(),
            Err(ModelError::InvalidRelativePath("artifact.relative_path"))
        );
    }

    #[test]
    fn rejects_uppercase_sha256() {
        let mut value = manifest();
        value.target.root_sha256 = "A".repeat(64);
        assert_eq!(
            value.validate(),
            Err(ModelError::InvalidSha256("target.root_sha256"))
        );
    }

    #[test]
    fn prioritizes_by_severity_then_confidence_then_id() {
        let mut findings = vec![
            finding("b000000000000000", Severity::Medium, Confidence::High),
            finding("a000000000000000", Severity::High, Confidence::Low),
            finding("c000000000000000", Severity::High, Confidence::Low),
        ];
        prioritize_findings(&mut findings);
        assert_eq!(
            findings
                .iter()
                .map(|value| value.finding_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "sf_finding_a000000000000000",
                "sf_finding_c000000000000000",
                "sf_finding_b000000000000000",
            ]
        );
    }

    #[test]
    fn deduplicates_same_engine_fingerprint_and_locations() {
        let mut first = finding("a000000000000000", Severity::High, Confidence::High);
        first.engine_fingerprint = Some("engine-fingerprint".into());
        let mut duplicate = finding("b000000000000000", Severity::Medium, Confidence::Low);
        duplicate.engine_fingerprint = Some("engine-fingerprint".into());
        let mut findings = vec![first, duplicate];
        assert_eq!(deduplicate_findings(&mut findings), 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_id, "sf_finding_a000000000000000");
    }

    #[test]
    fn rejects_human_decision_without_review_provenance() {
        let mut value = manifest();
        let mut reviewed = finding("a000000000000000", Severity::High, Confidence::High);
        reviewed.human_review.decision = HumanDecision::Validated;
        value.findings.push(reviewed);
        value.phases.validation = PhaseStatus::Completed;
        assert_eq!(
            value.validate(),
            Err(ModelError::InconsistentState(
                "human decisions require reviewer, reviewed_at and rationale"
            ))
        );
    }

    #[test]
    fn rejects_completed_validation_with_pending_findings() {
        let mut value = manifest();
        value
            .findings
            .push(finding("a000000000000000", Severity::High, Confidence::High));
        value.phases.validation = PhaseStatus::Completed;
        assert_eq!(
            value.validate(),
            Err(ModelError::InconsistentState(
                "completed validation cannot contain pending findings"
            ))
        );
    }

    #[test]
    fn rejects_summary_that_does_not_match_findings() {
        let mut value = manifest();
        value.summary = Some(Summary {
            candidate_count: 1,
            duplicate_count: 0,
            validated_count: 0,
            rejected_count: 0,
            abstained_count: 0,
            ai_calls: 0,
            ai_input_tokens: 0,
            ai_output_tokens: 0,
        });
        assert_eq!(value.validate(), Err(ModelError::SummaryMismatch));
    }

    #[test]
    fn rejects_completed_ai_validation_without_response_accounting() {
        let mut candidate = finding("a000000000000000", Severity::High, Confidence::High);
        candidate.ai_validation.status = AiValidationStatus::Completed;
        candidate.ai_validation.request_id = Some(format!("sf_ai_request_{}", "d".repeat(64)));
        candidate.ai_validation.provider = Some("openai".into());
        candidate.ai_validation.model = Some("luna".into());
        candidate.ai_validation.prompt_version = Some("secureflow-ai-triage-v1".into());
        candidate.ai_validation.redacted_payload_sha256 = Some("e".repeat(64));
        assert_eq!(
            candidate.validate(),
            Err(ModelError::InconsistentState(
                "completed AI validation requires request, response, token and assessment metadata"
            ))
        );
    }

    #[test]
    fn rejects_summary_that_omits_completed_ai_usage() {
        let mut value = manifest();
        let mut candidate = finding("a000000000000000", Severity::High, Confidence::High);
        candidate.ai_validation = AiValidation {
            status: AiValidationStatus::Completed,
            request_id: Some(format!("sf_ai_request_{}", "d".repeat(64))),
            provider: Some("openai".into()),
            model: Some("luna".into()),
            prompt_version: Some("secureflow-ai-triage-v1".into()),
            redacted_payload_sha256: Some("e".repeat(64)),
            response_sha256: Some("f".repeat(64)),
            input_tokens: Some(500),
            output_tokens: Some(100),
            assessment: Some(AiAssessment::Uncertain),
        };
        value.findings.push(candidate);
        value.summary = Some(Summary {
            candidate_count: 1,
            duplicate_count: 0,
            validated_count: 0,
            rejected_count: 0,
            abstained_count: 0,
            ai_calls: 0,
            ai_input_tokens: 0,
            ai_output_tokens: 0,
        });
        assert_eq!(value.validate(), Err(ModelError::SummaryMismatch));
    }
}
