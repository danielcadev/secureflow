//! Fail-closed contracts for a prospective SecureFlow/human comparison.
//!
//! This module freezes a label-free dataset, seals a protocol before execution,
//! and validates one mutually exclusive outcome per case and lane. It does not
//! open ground truth, execute a system, adjudicate a result, or declare a winner.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const DATASET_VERSION: &str = "secureflow-prospective-dataset-v1";
pub const PROTOCOL_VERSION: &str = "secureflow-prospective-protocol-v2";
pub const SUBMISSION_VERSION: &str = "secureflow-prospective-submission-v1";
pub const MAX_DATASET_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_PROTOCOL_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_SUBMISSION_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_CASE_BYTES: u64 = 8 * 1024 * 1024;
const MIN_COMPARATIVE_HOLDOUT_CASES: u64 = 20;
const MIN_COMPARATIVE_POSITIVE_CASES: u64 = 10;
const MIN_COMPARATIVE_SAFE_CONTROLS: u64 = 10;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetDraft {
    pub frozen_at: String,
    pub purpose: DatasetPurpose,
    pub authorization: DatasetAuthorization,
    pub provenance_sha256: String,
    pub license_manifest_sha256: String,
    pub ground_truth_commitment_sha256: String,
    pub cases: Vec<CaseCommitment>,
    pub accounting: DatasetAccounting,
    pub anti_leakage: AntiLeakageCommitment,
    pub claims: DatasetClaimBoundary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenDataset {
    pub contract_version: String,
    pub dataset_id: String,
    #[serde(flatten)]
    pub draft: DatasetDraft,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatasetPurpose {
    SyntheticContractTest,
    PreregisteredHoldout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetAuthorization {
    pub scope_reference_sha256: String,
    pub reviewer_commitment_sha256: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseCommitment {
    pub case_id: String,
    pub relative_path: String,
    pub artifact_sha256: String,
    pub language: String,
    pub split: DatasetSplit,
    pub lineage_sha256: String,
    pub principal_invariant_count: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatasetSplit {
    Development,
    Validation,
    Holdout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetAccounting {
    pub total_cases: u64,
    pub development_cases: u64,
    pub validation_cases: u64,
    pub holdout_cases: u64,
    pub vulnerable_cases: u64,
    pub safe_controls: u64,
    pub holdout_vulnerable_cases: u64,
    pub holdout_safe_controls: u64,
    pub label_counts_custodian_declared: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AntiLeakageCommitment {
    pub labels_included: bool,
    pub labels_hidden_from_all_lanes: bool,
    pub ground_truth_custodian_separate: bool,
    pub case_order_label_independent: bool,
    pub lineage_disjoint_across_splits: bool,
    pub holdout_known_to_system_authors: bool,
    pub holdout_known_to_participants: bool,
    pub overlap_audit_sha256: String,
    pub historical_inventory_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetClaimBoundary {
    pub fixture_only: bool,
    pub independent_holdout: bool,
    pub comparison_eligible: bool,
    pub production_evidence: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolDraftV2 {
    pub study_mode: StudyMode,
    pub research_question: String,
    pub dataset: DatasetBinding,
    pub artifacts: StudyArtifacts,
    pub lanes: Vec<ComparisonLane>,
    pub equivalence: EquivalentCapabilityCommitment,
    pub blinding: BlindingCommitmentV2,
    pub execution: ExecutionCommitmentV2,
    pub outcomes: OutcomePolicy,
    pub metrics: MetricPolicy,
    pub success: SuccessPolicy,
    pub claims: ProspectiveClaimBoundaryV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProspectiveProtocolV2 {
    pub contract_version: String,
    pub protocol_id: String,
    pub sealed_at: String,
    #[serde(flatten)]
    pub draft: ProtocolDraftV2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StudyMode {
    SyntheticContractTest,
    PreregisteredHoldout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetBinding {
    pub dataset_id: String,
    pub dataset_sha256: String,
    pub total_cases: u64,
    pub holdout_cases: u64,
    pub holdout_vulnerable_cases: u64,
    pub holdout_safe_controls: u64,
    pub ground_truth_commitment_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StudyArtifacts {
    pub provenance_sha256: String,
    pub license_manifest_sha256: String,
    pub overlap_audit_sha256: String,
    pub environment_sha256: String,
    pub shared_capability_manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonLane {
    pub lane_id: String,
    pub kind: LaneKind,
    pub treatment: LaneTreatment,
    pub equivalent_capability_group: String,
    pub cohort_or_version: String,
    pub lane_configuration_sha256: String,
    pub shared_capability_manifest_sha256: String,
    pub environment_sha256: String,
    pub time_limit_seconds_per_case: u64,
    pub network_policy: NetworkPolicy,
    pub case_access_policy: CaseAccessPolicy,
    pub human_reviewer_count: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaneKind {
    SecureflowAssistedHuman,
    HumanComparator,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaneTreatment {
    SecureflowAvailable,
    SecureflowUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    Disabled,
    RecordedRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseAccessPolicy {
    OpaqueCaseOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EquivalentCapabilityCommitment {
    pub group_id: String,
    pub secureflow_lane_id: String,
    pub human_lane_id: String,
    pub same_case_inputs: bool,
    pub same_time_limit: bool,
    pub same_network_policy: bool,
    pub same_environment_class: bool,
    pub same_non_treatment_tools: bool,
    pub treatment_is_only_planned_difference: bool,
    pub native_and_equivalent_lanes_reported_separately: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindingCommitmentV2 {
    pub participant_ground_truth_hidden: bool,
    pub system_ground_truth_hidden: bool,
    pub lane_identity_hidden_from_adjudicators: bool,
    pub submissions_close_before_labels_open: bool,
    pub randomized_case_order: bool,
    pub randomization_commitment_sha256: String,
    pub independent_primary_adjudicators: u64,
    pub independent_tie_breaker_required: bool,
    pub adjudicators_independent_from_corpus_authors: bool,
    pub adjudicators_independent_from_system_developers: bool,
    pub disagreement_resolution: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCommitmentV2 {
    pub attempt_ordinal_starts_at_zero: bool,
    pub default_attempts_per_case_lane: u64,
    pub retries_only_for_predeclared_infrastructure_failure: bool,
    pub retry_policy: String,
    pub timeout_is_operational_error: bool,
    pub crash_is_operational_error: bool,
    pub malformed_output_is_operational_error: bool,
    pub operational_errors_never_count_as_clean: bool,
    pub raw_artifacts_retained_by_hash: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomePolicy {
    pub one_atomic_case_per_principal_invariant: bool,
    pub finding_requires_source_evidence_impact_and_repair: bool,
    pub outcome_kinds: Vec<OutcomeKind>,
    pub findings_abstentions_errors_separate: bool,
    pub abstentions_are_neither_positive_nor_negative: bool,
    pub errors_are_neither_findings_nor_clean_controls: bool,
    pub positive_unit: PositiveUnit,
    pub safe_control_unit: SafeControlUnit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeKind {
    Findings,
    Abstention,
    OperationalError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PositiveUnit {
    PrincipalInvariant,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafeControlUnit {
    Case,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricPolicy {
    pub required_metrics: Vec<RequiredMetric>,
    pub report_per_case: bool,
    pub report_per_lane: bool,
    pub report_findings_abstentions_errors_separately: bool,
    pub no_composite_winner_score: bool,
    pub integer_units_only: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequiredMetric {
    ValidatedRecall,
    ValidatedPrecision,
    FalsePositiveRate,
    FalseNegativeCount,
    AnalystActiveTimeNanoseconds,
    WallClockTimeNanoseconds,
    CostMicrousd,
    InputTokens,
    OutputTokens,
    PeakRssBytes,
    AbstentionCount,
    OperationalErrorCount,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessPolicy {
    pub preregistered_criterion: String,
    pub uncertainty_method: String,
    pub multiplicity_policy: String,
    pub negative_and_mixed_results_published: bool,
    pub criterion_changes_require_new_protocol: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProspectiveClaimBoundaryV2 {
    pub evaluation_only: bool,
    pub task_bounded_claim_status: TaskBoundedClaimStatus,
    pub task_bounded_comparison_eligible_after_adjudication: bool,
    pub requires_preregistered_criterion: bool,
    pub requires_independent_adjudication: bool,
    pub requires_uncertainty_analysis: bool,
    pub limited_to_frozen_dataset_cohort_and_configuration: bool,
    pub global_superiority_claim_allowed: bool,
    pub best_or_always_human_claim_allowed: bool,
    pub human_replacement_claim_allowed: bool,
    pub production_safety_claim_allowed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskBoundedClaimStatus {
    NotEstablished,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionDraft {
    pub protocol_id: String,
    pub dataset_id: String,
    pub lane_id: String,
    pub case_id: String,
    pub attempt_ordinal: u64,
    pub recorded_at: String,
    pub raw_artifact_sha256: String,
    pub outcome: SubmissionOutcome,
    pub metrics: SubmissionMetrics,
    pub claims: SubmissionClaimBoundary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProspectiveSubmission {
    pub contract_version: String,
    pub submission_id: String,
    #[serde(flatten)]
    pub draft: SubmissionDraft,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SubmissionOutcome {
    Findings {
        findings: Vec<SubmissionFinding>,
    },
    Abstention {
        reason_code: AbstentionReason,
        rationale_sha256: String,
    },
    OperationalError {
        error_kind: OperationalErrorKind,
        stage: String,
        detail_sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionFinding {
    pub finding_id: String,
    pub invariant_id: String,
    pub location: String,
    pub evidence_sha256: String,
    pub impact: String,
    pub repair: String,
    pub classification: SubmissionFindingClassification,
    pub human_validation_status: SubmissionValidationStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubmissionFindingClassification {
    Candidate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubmissionValidationStatus {
    PendingIndependentAdjudication,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbstentionReason {
    InsufficientEvidence,
    UnsupportedCapability,
    AmbiguousTrustBoundary,
    ScopeUnclear,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationalErrorKind {
    Crash,
    Timeout,
    MalformedOutput,
    Unavailable,
    InfrastructureFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionMetrics {
    pub analyst_active_time_ns: u64,
    pub wall_clock_time_ns: u64,
    pub cost_microusd: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub peak_rss_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionClaimBoundary {
    pub result_is_independently_adjudicated: bool,
    pub task_bounded_comparative_claim_established: bool,
    pub global_superiority_claim_allowed: bool,
    pub human_replacement_claim_allowed: bool,
    pub production_safety_claim_allowed: bool,
}

#[derive(Debug, Error)]
pub enum ProspectiveV2Error {
    #[error("invalid prospective v2 field: {0}")]
    InvalidField(&'static str),
    #[error("invalid prospective v2 JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not read case artifact {path}: {source}")]
    ReadCase {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("case artifact is not a regular file: {0}")]
    NotAFile(PathBuf),
    #[error("case artifact path contains or resolves through a symlink: {0}")]
    Symlink(PathBuf),
    #[error("case artifact escapes the authorized root: {0}")]
    PathEscape(PathBuf),
    #[error("case artifact is outside size limits: {path} ({bytes} bytes)")]
    CaseTooLarge { path: PathBuf, bytes: u64 },
    #[error("case artifact hash mismatch: {0}")]
    CaseHashMismatch(String),
    #[error("prospective artifact hash mismatch: {0}")]
    ArtifactHashMismatch(&'static str),
    #[error("could not format timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
}

pub fn freeze_dataset(bytes: &[u8], case_root: &Path) -> Result<FrozenDataset, ProspectiveV2Error> {
    validate_document_size(bytes, MAX_DATASET_BYTES)?;
    let draft: DatasetDraft = serde_json::from_slice(bytes)?;
    validate_dataset_draft(&draft)?;
    verify_case_artifacts(case_root, &draft.cases)?;
    let mut dataset = FrozenDataset {
        contract_version: DATASET_VERSION.into(),
        dataset_id: String::new(),
        draft,
    };
    dataset.dataset_id = expected_prefixed_id("sf_dataset_", &dataset.draft);
    dataset.validate()?;
    Ok(dataset)
}

pub fn parse_dataset(bytes: &[u8]) -> Result<FrozenDataset, ProspectiveV2Error> {
    validate_document_size(bytes, MAX_DATASET_BYTES)?;
    let dataset: FrozenDataset = serde_json::from_slice(bytes)?;
    dataset.validate()?;
    Ok(dataset)
}

pub fn seal_protocol(
    bytes: &[u8],
    sealed_at: Option<String>,
) -> Result<ProspectiveProtocolV2, ProspectiveV2Error> {
    validate_document_size(bytes, MAX_PROTOCOL_BYTES)?;
    let draft: ProtocolDraftV2 = serde_json::from_slice(bytes)?;
    let mut protocol = ProspectiveProtocolV2 {
        contract_version: PROTOCOL_VERSION.into(),
        protocol_id: String::new(),
        sealed_at: sealed_at.unwrap_or(OffsetDateTime::now_utc().format(&Rfc3339)?),
        draft,
    };
    protocol.protocol_id = expected_protocol_id(&protocol);
    protocol.validate()?;
    Ok(protocol)
}

pub fn parse_protocol(bytes: &[u8]) -> Result<ProspectiveProtocolV2, ProspectiveV2Error> {
    validate_document_size(bytes, MAX_PROTOCOL_BYTES)?;
    let protocol: ProspectiveProtocolV2 = serde_json::from_slice(bytes)?;
    protocol.validate()?;
    Ok(protocol)
}

pub fn bind_protocol_to_dataset(
    protocol: &ProspectiveProtocolV2,
    dataset: &FrozenDataset,
    dataset_bytes: &[u8],
) -> Result<(), ProspectiveV2Error> {
    let binding = &protocol.draft.dataset;
    let accounting = &dataset.draft.accounting;
    if binding.dataset_id != dataset.dataset_id
        || binding.dataset_sha256 != sha256_bytes(dataset_bytes)
        || binding.total_cases != accounting.total_cases
        || binding.holdout_cases != accounting.holdout_cases
        || binding.holdout_vulnerable_cases != accounting.holdout_vulnerable_cases
        || binding.holdout_safe_controls != accounting.holdout_safe_controls
        || binding.ground_truth_commitment_sha256 != dataset.draft.ground_truth_commitment_sha256
    {
        return Err(ProspectiveV2Error::InvalidField("dataset binding"));
    }
    match protocol.draft.study_mode {
        StudyMode::SyntheticContractTest => {
            if dataset.draft.purpose != DatasetPurpose::SyntheticContractTest {
                return Err(ProspectiveV2Error::InvalidField("study mode"));
            }
        }
        StudyMode::PreregisteredHoldout => {
            if dataset.draft.purpose != DatasetPurpose::PreregisteredHoldout {
                return Err(ProspectiveV2Error::InvalidField("study mode"));
            }
        }
    }
    Ok(())
}

pub fn verify_protocol_artifacts(
    protocol: &ProspectiveProtocolV2,
    provenance: &[u8],
    licenses: &[u8],
    overlap_audit: &[u8],
    environment: &[u8],
    capabilities: &[u8],
) -> Result<(), ProspectiveV2Error> {
    let expected = &protocol.draft.artifacts;
    for (field, actual, retained) in [
        (
            "artifacts.provenance_sha256",
            sha256_bytes(provenance),
            &expected.provenance_sha256,
        ),
        (
            "artifacts.license_manifest_sha256",
            sha256_bytes(licenses),
            &expected.license_manifest_sha256,
        ),
        (
            "artifacts.overlap_audit_sha256",
            sha256_bytes(overlap_audit),
            &expected.overlap_audit_sha256,
        ),
        (
            "artifacts.environment_sha256",
            sha256_bytes(environment),
            &expected.environment_sha256,
        ),
        (
            "artifacts.shared_capability_manifest_sha256",
            sha256_bytes(capabilities),
            &expected.shared_capability_manifest_sha256,
        ),
    ] {
        if actual != *retained {
            return Err(ProspectiveV2Error::ArtifactHashMismatch(field));
        }
    }
    Ok(())
}

pub fn seal_submission(
    bytes: &[u8],
    protocol: &ProspectiveProtocolV2,
    dataset: &FrozenDataset,
) -> Result<ProspectiveSubmission, ProspectiveV2Error> {
    validate_document_size(bytes, MAX_SUBMISSION_BYTES)?;
    let draft: SubmissionDraft = serde_json::from_slice(bytes)?;
    let mut submission = ProspectiveSubmission {
        contract_version: SUBMISSION_VERSION.into(),
        submission_id: String::new(),
        draft,
    };
    submission.submission_id = expected_prefixed_id("sf_submission_", &submission.draft);
    submission.validate(protocol, dataset)?;
    Ok(submission)
}

pub fn parse_submission(
    bytes: &[u8],
    protocol: &ProspectiveProtocolV2,
    dataset: &FrozenDataset,
) -> Result<ProspectiveSubmission, ProspectiveV2Error> {
    validate_document_size(bytes, MAX_SUBMISSION_BYTES)?;
    let submission: ProspectiveSubmission = serde_json::from_slice(bytes)?;
    submission.validate(protocol, dataset)?;
    Ok(submission)
}

impl FrozenDataset {
    pub fn validate(&self) -> Result<(), ProspectiveV2Error> {
        if self.contract_version != DATASET_VERSION
            || !valid_prefixed_hash(&self.dataset_id, "sf_dataset_")
            || self.dataset_id != expected_prefixed_id("sf_dataset_", &self.draft)
        {
            return Err(ProspectiveV2Error::InvalidField("dataset identity"));
        }
        validate_dataset_draft(&self.draft)
    }
}

impl ProspectiveProtocolV2 {
    pub fn validate(&self) -> Result<(), ProspectiveV2Error> {
        if self.contract_version != PROTOCOL_VERSION
            || !valid_prefixed_hash(&self.protocol_id, "sf_protocol_v2_")
            || OffsetDateTime::parse(&self.sealed_at, &Rfc3339).is_err()
            || !valid_text(&self.draft.research_question, 1_000)
            || self.protocol_id != expected_protocol_id(self)
        {
            return Err(ProspectiveV2Error::InvalidField("protocol identity"));
        }
        validate_dataset_binding(&self.draft.dataset)?;
        validate_study_artifacts(&self.draft.artifacts)?;
        validate_lanes(&self.draft.lanes, &self.draft.equivalence)?;
        validate_blinding(&self.draft.blinding)?;
        validate_execution(&self.draft.execution)?;
        validate_outcome_policy(&self.draft.outcomes)?;
        validate_metric_policy(&self.draft.metrics)?;
        validate_success_policy(&self.draft.success)?;
        validate_protocol_claims(self.draft.study_mode, &self.draft.claims)
    }
}

impl ProspectiveSubmission {
    pub fn validate(
        &self,
        protocol: &ProspectiveProtocolV2,
        dataset: &FrozenDataset,
    ) -> Result<(), ProspectiveV2Error> {
        if self.contract_version != SUBMISSION_VERSION
            || !valid_prefixed_hash(&self.submission_id, "sf_submission_")
            || self.submission_id != expected_prefixed_id("sf_submission_", &self.draft)
            || self.draft.protocol_id != protocol.protocol_id
            || self.draft.dataset_id != dataset.dataset_id
            || !protocol
                .draft
                .lanes
                .iter()
                .any(|lane| lane.lane_id == self.draft.lane_id)
            || !dataset
                .draft
                .cases
                .iter()
                .any(|case| case.case_id == self.draft.case_id)
            || OffsetDateTime::parse(&self.draft.recorded_at, &Rfc3339).is_err()
            || !valid_sha256(&self.draft.raw_artifact_sha256)
        {
            return Err(ProspectiveV2Error::InvalidField("submission identity"));
        }
        validate_submission_outcome(&self.draft.outcome)?;
        let metrics = &self.draft.metrics;
        if metrics.wall_clock_time_ns == 0
            || metrics.analyst_active_time_ns > metrics.wall_clock_time_ns
            || metrics.peak_rss_bytes == 0
        {
            return Err(ProspectiveV2Error::InvalidField("submission metrics"));
        }
        let claims = &self.draft.claims;
        if claims.result_is_independently_adjudicated
            || claims.task_bounded_comparative_claim_established
            || claims.global_superiority_claim_allowed
            || claims.human_replacement_claim_allowed
            || claims.production_safety_claim_allowed
        {
            return Err(ProspectiveV2Error::InvalidField("submission claims"));
        }
        Ok(())
    }
}

fn validate_dataset_draft(draft: &DatasetDraft) -> Result<(), ProspectiveV2Error> {
    if OffsetDateTime::parse(&draft.frozen_at, &Rfc3339).is_err()
        || !valid_sha256(&draft.authorization.scope_reference_sha256)
        || !valid_sha256(&draft.authorization.reviewer_commitment_sha256)
        || OffsetDateTime::parse(&draft.authorization.expires_at, &Rfc3339).is_err()
        || OffsetDateTime::parse(&draft.authorization.expires_at, &Rfc3339).is_ok_and(|expires| {
            OffsetDateTime::parse(&draft.frozen_at, &Rfc3339).is_ok_and(|frozen| expires <= frozen)
        })
        || !valid_sha256(&draft.provenance_sha256)
        || !valid_sha256(&draft.license_manifest_sha256)
        || !valid_sha256(&draft.ground_truth_commitment_sha256)
    {
        return Err(ProspectiveV2Error::InvalidField("dataset provenance"));
    }
    if draft.cases.is_empty() || draft.cases.len() > 10_000 {
        return Err(ProspectiveV2Error::InvalidField("dataset cases"));
    }
    let mut case_ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut artifact_hashes = BTreeSet::new();
    let mut lineage_splits = BTreeMap::new();
    let mut split_counts = BTreeMap::new();
    for case in &draft.cases {
        if !valid_case_id(&case.case_id)
            || !valid_relative_path(&case.relative_path)
            || !case_ids.insert(&case.case_id)
            || !paths.insert(&case.relative_path)
            || !valid_sha256(&case.artifact_sha256)
            || !artifact_hashes.insert(&case.artifact_sha256)
            || !valid_text(&case.language, 100)
            || !valid_sha256(&case.lineage_sha256)
            || case.principal_invariant_count != 1
        {
            return Err(ProspectiveV2Error::InvalidField("dataset case"));
        }
        if lineage_splits
            .insert(&case.lineage_sha256, case.split)
            .is_some_and(|existing| existing != case.split)
        {
            return Err(ProspectiveV2Error::InvalidField(
                "lineage crosses dataset splits",
            ));
        }
        *split_counts.entry(case.split).or_insert(0_u64) += 1;
    }
    let accounting = &draft.accounting;
    if accounting.total_cases != draft.cases.len() as u64
        || accounting.development_cases
            != split_counts
                .get(&DatasetSplit::Development)
                .copied()
                .unwrap_or(0)
        || accounting.validation_cases
            != split_counts
                .get(&DatasetSplit::Validation)
                .copied()
                .unwrap_or(0)
        || accounting.holdout_cases
            != split_counts
                .get(&DatasetSplit::Holdout)
                .copied()
                .unwrap_or(0)
        || accounting.vulnerable_cases + accounting.safe_controls != accounting.total_cases
        || accounting.holdout_vulnerable_cases + accounting.holdout_safe_controls
            != accounting.holdout_cases
        || !accounting.label_counts_custodian_declared
    {
        return Err(ProspectiveV2Error::InvalidField("dataset accounting"));
    }
    let anti_leakage = &draft.anti_leakage;
    if anti_leakage.labels_included
        || !anti_leakage.labels_hidden_from_all_lanes
        || !anti_leakage.ground_truth_custodian_separate
        || !anti_leakage.case_order_label_independent
        || !anti_leakage.lineage_disjoint_across_splits
        || !valid_sha256(&anti_leakage.overlap_audit_sha256)
        || !valid_sha256(&anti_leakage.historical_inventory_sha256)
    {
        return Err(ProspectiveV2Error::InvalidField("anti-leakage"));
    }
    match draft.purpose {
        DatasetPurpose::SyntheticContractTest => {
            if !draft.claims.fixture_only
                || draft.claims.independent_holdout
                || draft.claims.comparison_eligible
                || draft.claims.production_evidence
            {
                return Err(ProspectiveV2Error::InvalidField("fixture claims"));
            }
        }
        DatasetPurpose::PreregisteredHoldout => {
            if draft.claims.fixture_only
                || !draft.claims.independent_holdout
                || !draft.claims.comparison_eligible
                || draft.claims.production_evidence
                || anti_leakage.holdout_known_to_system_authors
                || anti_leakage.holdout_known_to_participants
                || accounting.holdout_cases < MIN_COMPARATIVE_HOLDOUT_CASES
                || accounting.holdout_vulnerable_cases < MIN_COMPARATIVE_POSITIVE_CASES
                || accounting.holdout_safe_controls < MIN_COMPARATIVE_SAFE_CONTROLS
            {
                return Err(ProspectiveV2Error::InvalidField(
                    "prospective holdout claims",
                ));
            }
        }
    }
    Ok(())
}

fn validate_dataset_binding(binding: &DatasetBinding) -> Result<(), ProspectiveV2Error> {
    if !valid_prefixed_hash(&binding.dataset_id, "sf_dataset_")
        || !valid_sha256(&binding.dataset_sha256)
        || binding.total_cases == 0
        || binding.holdout_cases == 0
        || binding.holdout_vulnerable_cases + binding.holdout_safe_controls != binding.holdout_cases
        || !valid_sha256(&binding.ground_truth_commitment_sha256)
    {
        return Err(ProspectiveV2Error::InvalidField("dataset binding"));
    }
    Ok(())
}

fn validate_study_artifacts(artifacts: &StudyArtifacts) -> Result<(), ProspectiveV2Error> {
    if [
        &artifacts.provenance_sha256,
        &artifacts.license_manifest_sha256,
        &artifacts.overlap_audit_sha256,
        &artifacts.environment_sha256,
        &artifacts.shared_capability_manifest_sha256,
    ]
    .into_iter()
    .any(|value| !valid_sha256(value))
    {
        return Err(ProspectiveV2Error::InvalidField("study artifacts"));
    }
    Ok(())
}

fn validate_lanes(
    lanes: &[ComparisonLane],
    equivalence: &EquivalentCapabilityCommitment,
) -> Result<(), ProspectiveV2Error> {
    if lanes.len() != 2
        || !valid_text(&equivalence.group_id, 100)
        || !valid_text(&equivalence.secureflow_lane_id, 100)
        || !valid_text(&equivalence.human_lane_id, 100)
        || !equivalence.same_case_inputs
        || !equivalence.same_time_limit
        || !equivalence.same_network_policy
        || !equivalence.same_environment_class
        || !equivalence.same_non_treatment_tools
        || !equivalence.treatment_is_only_planned_difference
        || !equivalence.native_and_equivalent_lanes_reported_separately
    {
        return Err(ProspectiveV2Error::InvalidField("lane equivalence"));
    }
    let mut ids = BTreeSet::new();
    for lane in lanes {
        if !valid_text(&lane.lane_id, 100)
            || !ids.insert(&lane.lane_id)
            || !valid_text(&lane.equivalent_capability_group, 100)
            || !valid_text(&lane.cohort_or_version, 300)
            || !valid_sha256(&lane.lane_configuration_sha256)
            || !valid_sha256(&lane.shared_capability_manifest_sha256)
            || !valid_sha256(&lane.environment_sha256)
            || !(1..=86_400).contains(&lane.time_limit_seconds_per_case)
            || lane.case_access_policy != CaseAccessPolicy::OpaqueCaseOnly
            || lane.human_reviewer_count < 3
        {
            return Err(ProspectiveV2Error::InvalidField("comparison lane"));
        }
        match lane.kind {
            LaneKind::SecureflowAssistedHuman
                if lane.treatment != LaneTreatment::SecureflowAvailable =>
            {
                return Err(ProspectiveV2Error::InvalidField("lane treatment"));
            }
            LaneKind::HumanComparator if lane.treatment != LaneTreatment::SecureflowUnavailable => {
                return Err(ProspectiveV2Error::InvalidField("lane treatment"));
            }
            _ => {}
        }
    }
    let secureflow = lanes
        .iter()
        .find(|lane| lane.lane_id == equivalence.secureflow_lane_id)
        .filter(|lane| lane.kind == LaneKind::SecureflowAssistedHuman)
        .ok_or(ProspectiveV2Error::InvalidField("SecureFlow lane"))?;
    let human = lanes
        .iter()
        .find(|lane| lane.lane_id == equivalence.human_lane_id)
        .filter(|lane| lane.kind == LaneKind::HumanComparator)
        .ok_or(ProspectiveV2Error::InvalidField("human comparator lane"))?;
    if secureflow.equivalent_capability_group != equivalence.group_id
        || human.equivalent_capability_group != equivalence.group_id
        || secureflow.shared_capability_manifest_sha256 != human.shared_capability_manifest_sha256
        || secureflow.environment_sha256 != human.environment_sha256
        || secureflow.time_limit_seconds_per_case != human.time_limit_seconds_per_case
        || secureflow.network_policy != human.network_policy
        || secureflow.case_access_policy != human.case_access_policy
    {
        return Err(ProspectiveV2Error::InvalidField(
            "equivalent-capability mismatch",
        ));
    }
    Ok(())
}

fn validate_blinding(blinding: &BlindingCommitmentV2) -> Result<(), ProspectiveV2Error> {
    if !blinding.participant_ground_truth_hidden
        || !blinding.system_ground_truth_hidden
        || !blinding.lane_identity_hidden_from_adjudicators
        || !blinding.submissions_close_before_labels_open
        || !blinding.randomized_case_order
        || !valid_sha256(&blinding.randomization_commitment_sha256)
        || blinding.independent_primary_adjudicators < 2
        || !blinding.independent_tie_breaker_required
        || !blinding.adjudicators_independent_from_corpus_authors
        || !blinding.adjudicators_independent_from_system_developers
        || !valid_text(&blinding.disagreement_resolution, 1_000)
    {
        return Err(ProspectiveV2Error::InvalidField("blinding"));
    }
    Ok(())
}

fn validate_execution(execution: &ExecutionCommitmentV2) -> Result<(), ProspectiveV2Error> {
    if !execution.attempt_ordinal_starts_at_zero
        || execution.default_attempts_per_case_lane != 1
        || !execution.retries_only_for_predeclared_infrastructure_failure
        || !valid_text(&execution.retry_policy, 1_000)
        || !execution.timeout_is_operational_error
        || !execution.crash_is_operational_error
        || !execution.malformed_output_is_operational_error
        || !execution.operational_errors_never_count_as_clean
        || !execution.raw_artifacts_retained_by_hash
    {
        return Err(ProspectiveV2Error::InvalidField("execution"));
    }
    Ok(())
}

fn validate_outcome_policy(outcomes: &OutcomePolicy) -> Result<(), ProspectiveV2Error> {
    let kinds = outcomes
        .outcome_kinds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let required = BTreeSet::from([
        OutcomeKind::Findings,
        OutcomeKind::Abstention,
        OutcomeKind::OperationalError,
    ]);
    if !outcomes.one_atomic_case_per_principal_invariant
        || !outcomes.finding_requires_source_evidence_impact_and_repair
        || kinds != required
        || kinds.len() != outcomes.outcome_kinds.len()
        || !outcomes.findings_abstentions_errors_separate
        || !outcomes.abstentions_are_neither_positive_nor_negative
        || !outcomes.errors_are_neither_findings_nor_clean_controls
        || outcomes.positive_unit != PositiveUnit::PrincipalInvariant
        || outcomes.safe_control_unit != SafeControlUnit::Case
    {
        return Err(ProspectiveV2Error::InvalidField("outcome policy"));
    }
    Ok(())
}

fn validate_metric_policy(metrics: &MetricPolicy) -> Result<(), ProspectiveV2Error> {
    let actual = metrics
        .required_metrics
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let required = BTreeSet::from([
        RequiredMetric::ValidatedRecall,
        RequiredMetric::ValidatedPrecision,
        RequiredMetric::FalsePositiveRate,
        RequiredMetric::FalseNegativeCount,
        RequiredMetric::AnalystActiveTimeNanoseconds,
        RequiredMetric::WallClockTimeNanoseconds,
        RequiredMetric::CostMicrousd,
        RequiredMetric::InputTokens,
        RequiredMetric::OutputTokens,
        RequiredMetric::PeakRssBytes,
        RequiredMetric::AbstentionCount,
        RequiredMetric::OperationalErrorCount,
    ]);
    if actual != required
        || actual.len() != metrics.required_metrics.len()
        || !metrics.report_per_case
        || !metrics.report_per_lane
        || !metrics.report_findings_abstentions_errors_separately
        || !metrics.no_composite_winner_score
        || !metrics.integer_units_only
    {
        return Err(ProspectiveV2Error::InvalidField("metric policy"));
    }
    Ok(())
}

fn validate_success_policy(success: &SuccessPolicy) -> Result<(), ProspectiveV2Error> {
    if !valid_text(&success.preregistered_criterion, 2_000)
        || !valid_text(&success.uncertainty_method, 1_000)
        || !valid_text(&success.multiplicity_policy, 1_000)
        || !success.negative_and_mixed_results_published
        || !success.criterion_changes_require_new_protocol
    {
        return Err(ProspectiveV2Error::InvalidField("success policy"));
    }
    Ok(())
}

fn validate_protocol_claims(
    study_mode: StudyMode,
    claims: &ProspectiveClaimBoundaryV2,
) -> Result<(), ProspectiveV2Error> {
    if !claims.evaluation_only
        || claims.task_bounded_claim_status != TaskBoundedClaimStatus::NotEstablished
        || !claims.requires_preregistered_criterion
        || !claims.requires_independent_adjudication
        || !claims.requires_uncertainty_analysis
        || !claims.limited_to_frozen_dataset_cohort_and_configuration
        || claims.global_superiority_claim_allowed
        || claims.best_or_always_human_claim_allowed
        || claims.human_replacement_claim_allowed
        || claims.production_safety_claim_allowed
        || (study_mode == StudyMode::SyntheticContractTest
            && claims.task_bounded_comparison_eligible_after_adjudication)
        || (study_mode == StudyMode::PreregisteredHoldout
            && !claims.task_bounded_comparison_eligible_after_adjudication)
    {
        return Err(ProspectiveV2Error::InvalidField("claims"));
    }
    Ok(())
}

fn validate_submission_outcome(outcome: &SubmissionOutcome) -> Result<(), ProspectiveV2Error> {
    match outcome {
        SubmissionOutcome::Findings { findings } => {
            if findings.is_empty() || findings.len() > 100 {
                return Err(ProspectiveV2Error::InvalidField("submission findings"));
            }
            let mut ids = BTreeSet::new();
            let mut invariants = BTreeSet::new();
            for finding in findings {
                if !valid_text(&finding.finding_id, 100)
                    || !ids.insert(&finding.finding_id)
                    || !valid_text(&finding.invariant_id, 200)
                    || !invariants.insert(&finding.invariant_id)
                    || !valid_text(&finding.location, 500)
                    || !valid_sha256(&finding.evidence_sha256)
                    || !valid_text(&finding.impact, 2_000)
                    || !valid_text(&finding.repair, 2_000)
                    || finding.classification != SubmissionFindingClassification::Candidate
                    || finding.human_validation_status
                        != SubmissionValidationStatus::PendingIndependentAdjudication
                {
                    return Err(ProspectiveV2Error::InvalidField("submission finding"));
                }
            }
        }
        SubmissionOutcome::Abstention {
            rationale_sha256, ..
        } => {
            if !valid_sha256(rationale_sha256) {
                return Err(ProspectiveV2Error::InvalidField("submission abstention"));
            }
        }
        SubmissionOutcome::OperationalError {
            stage,
            detail_sha256,
            ..
        } => {
            if !valid_text(stage, 200) || !valid_sha256(detail_sha256) {
                return Err(ProspectiveV2Error::InvalidField(
                    "submission operational error",
                ));
            }
        }
    }
    Ok(())
}

fn verify_case_artifacts(
    case_root: &Path,
    cases: &[CaseCommitment],
) -> Result<(), ProspectiveV2Error> {
    let root_metadata =
        fs::symlink_metadata(case_root).map_err(|source| ProspectiveV2Error::ReadCase {
            path: case_root.to_path_buf(),
            source,
        })?;
    if root_metadata.file_type().is_symlink() {
        return Err(ProspectiveV2Error::Symlink(case_root.to_path_buf()));
    }
    if !root_metadata.is_dir() {
        return Err(ProspectiveV2Error::NotAFile(case_root.to_path_buf()));
    }
    let canonical_root =
        fs::canonicalize(case_root).map_err(|source| ProspectiveV2Error::ReadCase {
            path: case_root.to_path_buf(),
            source,
        })?;
    for case in cases {
        let relative = Path::new(&case.relative_path);
        reject_symlink_components(&canonical_root, relative)?;
        let path = canonical_root.join(relative);
        let canonical = fs::canonicalize(&path).map_err(|source| ProspectiveV2Error::ReadCase {
            path: path.clone(),
            source,
        })?;
        if !canonical.starts_with(&canonical_root) {
            return Err(ProspectiveV2Error::PathEscape(path));
        }
        let metadata =
            fs::symlink_metadata(&canonical).map_err(|source| ProspectiveV2Error::ReadCase {
                path: canonical.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(ProspectiveV2Error::Symlink(canonical));
        }
        if !metadata.is_file() {
            return Err(ProspectiveV2Error::NotAFile(canonical));
        }
        if metadata.len() == 0 || metadata.len() > MAX_CASE_BYTES {
            return Err(ProspectiveV2Error::CaseTooLarge {
                path: canonical,
                bytes: metadata.len(),
            });
        }
        let bytes = fs::read(&canonical).map_err(|source| ProspectiveV2Error::ReadCase {
            path: canonical,
            source,
        })?;
        if sha256_bytes(&bytes) != case.artifact_sha256 {
            return Err(ProspectiveV2Error::CaseHashMismatch(case.case_id.clone()));
        }
    }
    Ok(())
}

fn reject_symlink_components(root: &Path, relative: &Path) -> Result<(), ProspectiveV2Error> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(ProspectiveV2Error::PathEscape(relative.to_path_buf()));
        };
        current.push(component);
        let metadata =
            fs::symlink_metadata(&current).map_err(|source| ProspectiveV2Error::ReadCase {
                path: current.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(ProspectiveV2Error::Symlink(current));
        }
    }
    Ok(())
}

fn validate_document_size(bytes: &[u8], maximum: u64) -> Result<(), ProspectiveV2Error> {
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(ProspectiveV2Error::InvalidField("document size"));
    }
    Ok(())
}

fn valid_case_id(value: &str) -> bool {
    value
        .strip_prefix("case-")
        .is_some_and(|suffix| suffix.len() == 4 && suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 500
        && !value.contains('\\')
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_text(value: &str, maximum: usize) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && value == trimmed
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

fn expected_prefixed_id<T: Serialize>(prefix: &str, value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("identity input is serializable");
    format!("{prefix}{}", sha256_bytes(&bytes))
}

fn expected_protocol_id(protocol: &ProspectiveProtocolV2) -> String {
    let bytes = serde_json::to_vec(&(&protocol.sealed_at, &protocol.draft))
        .expect("protocol identity input is serializable");
    format!("sf_protocol_v2_{}", sha256_bytes(&bytes))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    encode_hex(&hasher.finalize())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing into a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hashes() -> impl Iterator<Item = String> {
        (1_u8..).map(|value| format!("{value:02x}").repeat(32))
    }

    fn dataset_draft() -> DatasetDraft {
        let mut hashes = hashes();
        let cases = (1..=24)
            .map(|index| CaseCommitment {
                case_id: format!("case-{index:04}"),
                relative_path: format!("cases/case-{index:04}.json"),
                artifact_sha256: hashes.next().unwrap(),
                language: if index % 2 == 0 { "Rust" } else { "TypeScript" }.into(),
                split: match index {
                    1..=2 => DatasetSplit::Development,
                    3..=4 => DatasetSplit::Validation,
                    _ => DatasetSplit::Holdout,
                },
                lineage_sha256: format!("{:02x}", 100 + ((index - 1) / 2)).repeat(32),
                principal_invariant_count: 1,
            })
            .collect();
        DatasetDraft {
            frozen_at: "2026-08-29T12:00:00Z".into(),
            purpose: DatasetPurpose::SyntheticContractTest,
            authorization: DatasetAuthorization {
                scope_reference_sha256: "a1".repeat(32),
                reviewer_commitment_sha256: "a2".repeat(32),
                expires_at: "2027-08-29T12:00:00Z".into(),
            },
            provenance_sha256: "a3".repeat(32),
            license_manifest_sha256: "a4".repeat(32),
            ground_truth_commitment_sha256: "a5".repeat(32),
            cases,
            accounting: DatasetAccounting {
                total_cases: 24,
                development_cases: 2,
                validation_cases: 2,
                holdout_cases: 20,
                vulnerable_cases: 12,
                safe_controls: 12,
                holdout_vulnerable_cases: 10,
                holdout_safe_controls: 10,
                label_counts_custodian_declared: true,
            },
            anti_leakage: AntiLeakageCommitment {
                labels_included: false,
                labels_hidden_from_all_lanes: true,
                ground_truth_custodian_separate: true,
                case_order_label_independent: true,
                lineage_disjoint_across_splits: true,
                holdout_known_to_system_authors: true,
                holdout_known_to_participants: true,
                overlap_audit_sha256: "a6".repeat(32),
                historical_inventory_sha256: "a7".repeat(32),
            },
            claims: DatasetClaimBoundary {
                fixture_only: true,
                independent_holdout: false,
                comparison_eligible: false,
                production_evidence: false,
            },
        }
    }

    fn frozen_dataset() -> (FrozenDataset, Vec<u8>) {
        let draft = dataset_draft();
        let mut dataset = FrozenDataset {
            contract_version: DATASET_VERSION.into(),
            dataset_id: String::new(),
            draft,
        };
        dataset.dataset_id = expected_prefixed_id("sf_dataset_", &dataset.draft);
        dataset.validate().unwrap();
        let bytes = serde_json::to_vec(&dataset).unwrap();
        (dataset, bytes)
    }

    fn protocol_draft(dataset: &FrozenDataset, dataset_bytes: &[u8]) -> ProtocolDraftV2 {
        let shared_capabilities = "b1".repeat(32);
        let environment = "b2".repeat(32);
        ProtocolDraftV2 {
            study_mode: StudyMode::SyntheticContractTest,
            research_question:
                "Does the fixture exercise a task-bounded comparison contract without claiming a result?"
                    .into(),
            dataset: DatasetBinding {
                dataset_id: dataset.dataset_id.clone(),
                dataset_sha256: sha256_bytes(dataset_bytes),
                total_cases: 24,
                holdout_cases: 20,
                holdout_vulnerable_cases: 10,
                holdout_safe_controls: 10,
                ground_truth_commitment_sha256: dataset
                    .draft
                    .ground_truth_commitment_sha256
                    .clone(),
            },
            artifacts: StudyArtifacts {
                provenance_sha256: "b3".repeat(32),
                license_manifest_sha256: "b4".repeat(32),
                overlap_audit_sha256: "b5".repeat(32),
                environment_sha256: environment.clone(),
                shared_capability_manifest_sha256: shared_capabilities.clone(),
            },
            lanes: vec![
                ComparisonLane {
                    lane_id: "secureflow-assisted".into(),
                    kind: LaneKind::SecureflowAssistedHuman,
                    treatment: LaneTreatment::SecureflowAvailable,
                    equivalent_capability_group: "local-equivalent-v1".into(),
                    cohort_or_version: "three synthetic reviewers with SecureFlow".into(),
                    lane_configuration_sha256: "b6".repeat(32),
                    shared_capability_manifest_sha256: shared_capabilities.clone(),
                    environment_sha256: environment.clone(),
                    time_limit_seconds_per_case: 600,
                    network_policy: NetworkPolicy::Disabled,
                    case_access_policy: CaseAccessPolicy::OpaqueCaseOnly,
                    human_reviewer_count: 3,
                },
                ComparisonLane {
                    lane_id: "human-comparator".into(),
                    kind: LaneKind::HumanComparator,
                    treatment: LaneTreatment::SecureflowUnavailable,
                    equivalent_capability_group: "local-equivalent-v1".into(),
                    cohort_or_version: "three synthetic reviewers without SecureFlow".into(),
                    lane_configuration_sha256: "b7".repeat(32),
                    shared_capability_manifest_sha256: shared_capabilities,
                    environment_sha256: environment,
                    time_limit_seconds_per_case: 600,
                    network_policy: NetworkPolicy::Disabled,
                    case_access_policy: CaseAccessPolicy::OpaqueCaseOnly,
                    human_reviewer_count: 3,
                },
            ],
            equivalence: EquivalentCapabilityCommitment {
                group_id: "local-equivalent-v1".into(),
                secureflow_lane_id: "secureflow-assisted".into(),
                human_lane_id: "human-comparator".into(),
                same_case_inputs: true,
                same_time_limit: true,
                same_network_policy: true,
                same_environment_class: true,
                same_non_treatment_tools: true,
                treatment_is_only_planned_difference: true,
                native_and_equivalent_lanes_reported_separately: true,
            },
            blinding: BlindingCommitmentV2 {
                participant_ground_truth_hidden: true,
                system_ground_truth_hidden: true,
                lane_identity_hidden_from_adjudicators: true,
                submissions_close_before_labels_open: true,
                randomized_case_order: true,
                randomization_commitment_sha256: "b8".repeat(32),
                independent_primary_adjudicators: 2,
                independent_tie_breaker_required: true,
                adjudicators_independent_from_corpus_authors: true,
                adjudicators_independent_from_system_developers: true,
                disagreement_resolution: "A third independent adjudicator resolves retained disagreements."
                    .into(),
            },
            execution: ExecutionCommitmentV2 {
                attempt_ordinal_starts_at_zero: true,
                default_attempts_per_case_lane: 1,
                retries_only_for_predeclared_infrastructure_failure: true,
                retry_policy: "No retry except a retained infrastructure failure before case analysis."
                    .into(),
                timeout_is_operational_error: true,
                crash_is_operational_error: true,
                malformed_output_is_operational_error: true,
                operational_errors_never_count_as_clean: true,
                raw_artifacts_retained_by_hash: true,
            },
            outcomes: OutcomePolicy {
                one_atomic_case_per_principal_invariant: true,
                finding_requires_source_evidence_impact_and_repair: true,
                outcome_kinds: vec![
                    OutcomeKind::Findings,
                    OutcomeKind::Abstention,
                    OutcomeKind::OperationalError,
                ],
                findings_abstentions_errors_separate: true,
                abstentions_are_neither_positive_nor_negative: true,
                errors_are_neither_findings_nor_clean_controls: true,
                positive_unit: PositiveUnit::PrincipalInvariant,
                safe_control_unit: SafeControlUnit::Case,
            },
            metrics: MetricPolicy {
                required_metrics: vec![
                    RequiredMetric::ValidatedRecall,
                    RequiredMetric::ValidatedPrecision,
                    RequiredMetric::FalsePositiveRate,
                    RequiredMetric::FalseNegativeCount,
                    RequiredMetric::AnalystActiveTimeNanoseconds,
                    RequiredMetric::WallClockTimeNanoseconds,
                    RequiredMetric::CostMicrousd,
                    RequiredMetric::InputTokens,
                    RequiredMetric::OutputTokens,
                    RequiredMetric::PeakRssBytes,
                    RequiredMetric::AbstentionCount,
                    RequiredMetric::OperationalErrorCount,
                ],
                report_per_case: true,
                report_per_lane: true,
                report_findings_abstentions_errors_separately: true,
                no_composite_winner_score: true,
                integer_units_only: true,
            },
            success: SuccessPolicy {
                preregistered_criterion: "A later adjudicated result must satisfy the frozen paired recall, precision, and analyst-time thresholds."
                    .into(),
                uncertainty_method: "Paired bootstrap intervals with a frozen seed commitment."
                    .into(),
                multiplicity_policy: "Report all predeclared families; no post-hoc family selection."
                    .into(),
                negative_and_mixed_results_published: true,
                criterion_changes_require_new_protocol: true,
            },
            claims: ProspectiveClaimBoundaryV2 {
                evaluation_only: true,
                task_bounded_claim_status: TaskBoundedClaimStatus::NotEstablished,
                task_bounded_comparison_eligible_after_adjudication: false,
                requires_preregistered_criterion: true,
                requires_independent_adjudication: true,
                requires_uncertainty_analysis: true,
                limited_to_frozen_dataset_cohort_and_configuration: true,
                global_superiority_claim_allowed: false,
                best_or_always_human_claim_allowed: false,
                human_replacement_claim_allowed: false,
                production_safety_claim_allowed: false,
            },
        }
    }

    #[test]
    fn fixture_mode_rejects_comparison_claims_and_cross_split_lineage() {
        let mut draft = dataset_draft();
        validate_dataset_draft(&draft).unwrap();
        draft.claims.comparison_eligible = true;
        assert!(validate_dataset_draft(&draft).is_err());
        draft.claims.comparison_eligible = false;
        draft.cases[2].lineage_sha256 = draft.cases[0].lineage_sha256.clone();
        assert!(validate_dataset_draft(&draft).is_err());
    }

    #[test]
    fn prospective_mode_requires_unseen_balanced_holdout() {
        let mut draft = dataset_draft();
        draft.purpose = DatasetPurpose::PreregisteredHoldout;
        draft.claims.fixture_only = false;
        draft.claims.independent_holdout = true;
        draft.claims.comparison_eligible = true;
        draft.anti_leakage.holdout_known_to_system_authors = false;
        draft.anti_leakage.holdout_known_to_participants = false;
        validate_dataset_draft(&draft).unwrap();
        draft.accounting.holdout_safe_controls = 9;
        assert!(validate_dataset_draft(&draft).is_err());
    }

    #[test]
    fn protocol_binds_equal_lanes_and_keeps_claim_unestablished() {
        let (dataset, dataset_bytes) = frozen_dataset();
        let bytes = serde_json::to_vec(&protocol_draft(&dataset, &dataset_bytes)).unwrap();
        let mut protocol = seal_protocol(&bytes, Some("2026-08-29T13:00:00Z".into())).unwrap();
        bind_protocol_to_dataset(&protocol, &dataset, &dataset_bytes).unwrap();
        assert_eq!(
            protocol.draft.claims.task_bounded_claim_status,
            TaskBoundedClaimStatus::NotEstablished
        );
        assert!(!protocol.draft.claims.global_superiority_claim_allowed);
        protocol.draft.lanes[1].time_limit_seconds_per_case += 1;
        protocol.protocol_id = expected_protocol_id(&protocol);
        assert!(protocol.validate().is_err());
    }

    #[test]
    fn submission_variants_remain_mutually_exclusive_and_unadjudicated() {
        let (dataset, dataset_bytes) = frozen_dataset();
        let protocol_bytes = serde_json::to_vec(&protocol_draft(&dataset, &dataset_bytes)).unwrap();
        let protocol = seal_protocol(&protocol_bytes, Some("2026-08-29T13:00:00Z".into())).unwrap();
        for outcome in [
            SubmissionOutcome::Findings {
                findings: vec![SubmissionFinding {
                    finding_id: "finding-001".into(),
                    invariant_id: "fixture.invariant.authorization".into(),
                    location: "entry.ts:1".into(),
                    evidence_sha256: "c1".repeat(32),
                    impact: "A bounded synthetic impact description.".into(),
                    repair: "A bounded synthetic invariant-restoring repair.".into(),
                    classification: SubmissionFindingClassification::Candidate,
                    human_validation_status:
                        SubmissionValidationStatus::PendingIndependentAdjudication,
                }],
            },
            SubmissionOutcome::Abstention {
                reason_code: AbstentionReason::InsufficientEvidence,
                rationale_sha256: "c2".repeat(32),
            },
            SubmissionOutcome::OperationalError {
                error_kind: OperationalErrorKind::Timeout,
                stage: "analysis".into(),
                detail_sha256: "c3".repeat(32),
            },
        ] {
            let draft = SubmissionDraft {
                protocol_id: protocol.protocol_id.clone(),
                dataset_id: dataset.dataset_id.clone(),
                lane_id: "secureflow-assisted".into(),
                case_id: "case-0005".into(),
                attempt_ordinal: 0,
                recorded_at: "2026-08-29T14:00:00Z".into(),
                raw_artifact_sha256: "c4".repeat(32),
                outcome,
                metrics: SubmissionMetrics {
                    analyst_active_time_ns: 1_000,
                    wall_clock_time_ns: 2_000,
                    cost_microusd: 0,
                    input_tokens: 0,
                    output_tokens: 0,
                    peak_rss_bytes: 1_048_576,
                },
                claims: SubmissionClaimBoundary {
                    result_is_independently_adjudicated: false,
                    task_bounded_comparative_claim_established: false,
                    global_superiority_claim_allowed: false,
                    human_replacement_claim_allowed: false,
                    production_safety_claim_allowed: false,
                },
            };
            let bytes = serde_json::to_vec(&draft).unwrap();
            seal_submission(&bytes, &protocol, &dataset).unwrap();
        }
    }
}
