//! Deterministic, local-only phase planning for SecureFlow runs.
//!
//! This crate executes no scanner and performs no network calls. It derives a
//! fail-closed next action from validated run state and retained evidence.

use secureflow_model::{AiValidationStatus, HumanDecision, PhaseStatus, RunManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const ORCHESTRATION_VERSION: &str = "secureflow-orchestration-v1";
pub const MAX_ORCHESTRATION_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_EVIDENCE_ARTIFACTS: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationEnvelope {
    pub contract_version: String,
    pub plan_id: String,
    pub created_at: String,
    pub linked_run_id: String,
    pub manifest_sha256: String,
    pub target_sha256: String,
    pub policy: OrchestrationPolicy,
    pub evidence: Vec<EvidenceArtifact>,
    pub state: RunState,
    pub phases: Vec<OrchestratedPhase>,
    pub next_action: NextAction,
    pub claim_status: ClaimStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationPolicy {
    pub authorization_required: bool,
    pub deterministic_first: bool,
    pub ai_optional: bool,
    pub ai_validation_authority: String,
    pub benchmark_evaluation_only: bool,
    pub no_evidence_action: String,
    pub network_execution: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifact {
    pub kind: EvidenceKind,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    ContextualReview,
    AdvisoryCorrelation,
    BenchmarkResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunState {
    pub candidate_count: u64,
    pub pending_human_reviews: u64,
    pub terminal_human_reviews: u64,
    pub ai_completed: u64,
    pub ai_failed_or_queued: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestratedPhase {
    pub name: PhaseName,
    pub status: OrchestratedStatus,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PhaseName {
    Authorization,
    DeterministicAnalysis,
    DeterministicPrioritization,
    ContextEnrichment,
    OptionalAiAdvisory,
    HumanValidation,
    ReproducibleEvaluation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OrchestratedStatus {
    Blocked,
    Ready,
    Partial,
    Completed,
    OptionalNotRequested,
    EvaluationOnly,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NextAction {
    CompleteDeterministicAnalysis,
    CompleteDeterministicPrioritization,
    HumanReviewOrAbstain,
    RunProspectiveEvaluation,
    PreserveAuditableEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStatus {
    CandidatesRequireHumanReview,
    HumanDecisionsAvailable,
    NoCandidatesIsNotProofOfSafety,
}

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("invalid orchestration field: {0}")]
    InvalidField(&'static str),
    #[error("too many evidence artifacts: {provided} (maximum {maximum})")]
    TooManyArtifacts { provided: usize, maximum: usize },
    #[error("run manifest is invalid: {0}")]
    Run(#[from] secureflow_model::ModelError),
    #[error("could not format orchestration timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    #[error("invalid orchestration JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn derive_plan(
    manifest: &RunManifest,
    manifest_sha256: String,
    mut evidence: Vec<EvidenceArtifact>,
) -> Result<OrchestrationEnvelope, OrchestratorError> {
    manifest.validate()?;
    if evidence.len() > MAX_EVIDENCE_ARTIFACTS {
        return Err(OrchestratorError::TooManyArtifacts {
            provided: evidence.len(),
            maximum: MAX_EVIDENCE_ARTIFACTS,
        });
    }
    evidence.sort();
    if !evidence.windows(2).all(|pair| pair[0] != pair[1]) {
        return Err(OrchestratorError::InvalidField(
            "duplicate evidence artifact",
        ));
    }
    if evidence.iter().any(|item| !valid_sha256(&item.sha256)) {
        return Err(OrchestratorError::InvalidField("evidence.sha256"));
    }

    let pending = manifest
        .findings
        .iter()
        .filter(|finding| finding.human_review.decision == HumanDecision::Pending)
        .count() as u64;
    let ai_completed = manifest
        .findings
        .iter()
        .filter(|finding| finding.ai_validation.status == AiValidationStatus::Completed)
        .count() as u64;
    let ai_failed_or_queued = manifest
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.ai_validation.status,
                AiValidationStatus::Failed | AiValidationStatus::Queued
            )
        })
        .count() as u64;
    let state = RunState {
        candidate_count: manifest.findings.len() as u64,
        pending_human_reviews: pending,
        terminal_human_reviews: manifest.findings.len() as u64 - pending,
        ai_completed,
        ai_failed_or_queued,
    };
    let has_context = evidence.iter().any(|artifact| {
        matches!(
            artifact.kind,
            EvidenceKind::ContextualReview | EvidenceKind::AdvisoryCorrelation
        )
    });
    let has_benchmark = evidence
        .iter()
        .any(|artifact| artifact.kind == EvidenceKind::BenchmarkResult);
    let phases = derive_phases(manifest, &state, has_context, has_benchmark);
    let next_action = if manifest.phases.deterministic != PhaseStatus::Completed {
        NextAction::CompleteDeterministicAnalysis
    } else if manifest.phases.prioritization != PhaseStatus::Completed {
        NextAction::CompleteDeterministicPrioritization
    } else if pending > 0 {
        NextAction::HumanReviewOrAbstain
    } else if !has_benchmark {
        NextAction::RunProspectiveEvaluation
    } else {
        NextAction::PreserveAuditableEvidence
    };
    let claim_status = if manifest.findings.is_empty() {
        ClaimStatus::NoCandidatesIsNotProofOfSafety
    } else if pending > 0 {
        ClaimStatus::CandidatesRequireHumanReview
    } else {
        ClaimStatus::HumanDecisionsAvailable
    };

    let mut envelope = OrchestrationEnvelope {
        contract_version: ORCHESTRATION_VERSION.into(),
        plan_id: String::new(),
        created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        linked_run_id: manifest.run_id.clone(),
        manifest_sha256,
        target_sha256: manifest.target.root_sha256.clone(),
        policy: OrchestrationPolicy {
            authorization_required: true,
            deterministic_first: true,
            ai_optional: true,
            ai_validation_authority: "human-only".into(),
            benchmark_evaluation_only: true,
            no_evidence_action: "abstain".into(),
            network_execution: "not-implemented".into(),
        },
        evidence,
        state,
        phases,
        next_action,
        claim_status,
    };
    envelope.plan_id = expected_plan_id(&envelope);
    envelope.validate()?;
    Ok(envelope)
}

pub fn parse_plan(bytes: &[u8]) -> Result<OrchestrationEnvelope, OrchestratorError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_ORCHESTRATION_BYTES {
        return Err(OrchestratorError::InvalidField("document size"));
    }
    let envelope: OrchestrationEnvelope = serde_json::from_slice(bytes)?;
    envelope.validate()?;
    Ok(envelope)
}

impl OrchestrationEnvelope {
    pub fn validate(&self) -> Result<(), OrchestratorError> {
        if self.contract_version != ORCHESTRATION_VERSION
            || !valid_prefixed_hash(&self.plan_id, "sf_plan_")
            || OffsetDateTime::parse(&self.created_at, &Rfc3339).is_err()
            || !valid_run_id(&self.linked_run_id)
            || !valid_sha256(&self.manifest_sha256)
            || !valid_sha256(&self.target_sha256)
        {
            return Err(OrchestratorError::InvalidField("identity"));
        }
        if !self.policy.authorization_required
            || !self.policy.deterministic_first
            || !self.policy.ai_optional
            || self.policy.ai_validation_authority != "human-only"
            || !self.policy.benchmark_evaluation_only
            || self.policy.no_evidence_action != "abstain"
            || self.policy.network_execution != "not-implemented"
        {
            return Err(OrchestratorError::InvalidField("policy"));
        }
        if self.evidence.len() > MAX_EVIDENCE_ARTIFACTS
            || self.evidence.iter().any(|item| !valid_sha256(&item.sha256))
            || !self.evidence.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(OrchestratorError::InvalidField("evidence"));
        }
        let expected_names = [
            PhaseName::Authorization,
            PhaseName::DeterministicAnalysis,
            PhaseName::DeterministicPrioritization,
            PhaseName::ContextEnrichment,
            PhaseName::OptionalAiAdvisory,
            PhaseName::HumanValidation,
            PhaseName::ReproducibleEvaluation,
        ];
        if self.phases.len() != expected_names.len()
            || !self
                .phases
                .iter()
                .zip(expected_names)
                .all(|(phase, expected)| phase.name == expected && !phase.reason.trim().is_empty())
        {
            return Err(OrchestratorError::InvalidField("phases"));
        }
        if self.state.pending_human_reviews + self.state.terminal_human_reviews
            != self.state.candidate_count
            || self.state.ai_completed + self.state.ai_failed_or_queued > self.state.candidate_count
        {
            return Err(OrchestratorError::InvalidField("state counts"));
        }
        self.validate_derived_state()?;
        if self.plan_id != expected_plan_id(self) {
            return Err(OrchestratorError::InvalidField("plan_id"));
        }
        Ok(())
    }

    fn validate_derived_state(&self) -> Result<(), OrchestratorError> {
        let deterministic = self.phases[1].status;
        let prioritization = self.phases[2].status;
        if self.phases[0].status != OrchestratedStatus::Completed
            || matches!(
                deterministic,
                OrchestratedStatus::OptionalNotRequested | OrchestratedStatus::EvaluationOnly
            )
            || (deterministic != OrchestratedStatus::Completed
                && prioritization != OrchestratedStatus::Blocked)
            || matches!(
                prioritization,
                OrchestratedStatus::OptionalNotRequested | OrchestratedStatus::EvaluationOnly
            )
        {
            return Err(OrchestratorError::InvalidField("required phase ordering"));
        }
        let has_context = self.evidence.iter().any(|artifact| {
            matches!(
                artifact.kind,
                EvidenceKind::ContextualReview | EvidenceKind::AdvisoryCorrelation
            )
        });
        let has_benchmark = self
            .evidence
            .iter()
            .any(|artifact| artifact.kind == EvidenceKind::BenchmarkResult);
        let expected_context = if prioritization != OrchestratedStatus::Completed {
            OrchestratedStatus::Blocked
        } else if has_context {
            OrchestratedStatus::Completed
        } else {
            OrchestratedStatus::OptionalNotRequested
        };
        let expected_ai = if self.state.ai_completed > 0 {
            OrchestratedStatus::Completed
        } else if self.state.ai_failed_or_queued > 0 {
            OrchestratedStatus::Partial
        } else {
            OrchestratedStatus::OptionalNotRequested
        };
        let expected_validation = if prioritization != OrchestratedStatus::Completed {
            OrchestratedStatus::Blocked
        } else if self.state.pending_human_reviews == 0 {
            OrchestratedStatus::Completed
        } else if self.state.terminal_human_reviews > 0 {
            OrchestratedStatus::Partial
        } else {
            OrchestratedStatus::Ready
        };
        let expected_evaluation = if self.state.pending_human_reviews > 0
            || prioritization != OrchestratedStatus::Completed
        {
            OrchestratedStatus::Blocked
        } else if has_benchmark {
            OrchestratedStatus::EvaluationOnly
        } else {
            OrchestratedStatus::Ready
        };
        let expected_next = if deterministic != OrchestratedStatus::Completed {
            NextAction::CompleteDeterministicAnalysis
        } else if prioritization != OrchestratedStatus::Completed {
            NextAction::CompleteDeterministicPrioritization
        } else if self.state.pending_human_reviews > 0 {
            NextAction::HumanReviewOrAbstain
        } else if !has_benchmark {
            NextAction::RunProspectiveEvaluation
        } else {
            NextAction::PreserveAuditableEvidence
        };
        let expected_claim = if self.state.candidate_count == 0 {
            ClaimStatus::NoCandidatesIsNotProofOfSafety
        } else if self.state.pending_human_reviews > 0 {
            ClaimStatus::CandidatesRequireHumanReview
        } else {
            ClaimStatus::HumanDecisionsAvailable
        };
        if self.phases[3].status != expected_context
            || self.phases[4].status != expected_ai
            || self.phases[5].status != expected_validation
            || self.phases[6].status != expected_evaluation
            || self.next_action != expected_next
            || self.claim_status != expected_claim
        {
            return Err(OrchestratorError::InvalidField("derived phase state"));
        }
        Ok(())
    }
}

fn derive_phases(
    manifest: &RunManifest,
    state: &RunState,
    has_context: bool,
    has_benchmark: bool,
) -> Vec<OrchestratedPhase> {
    let deterministic = map_required_phase(
        manifest.phases.deterministic,
        "deterministic scanner state retained in run manifest",
    );
    let prioritization = if manifest.phases.deterministic != PhaseStatus::Completed {
        phase(
            PhaseName::DeterministicPrioritization,
            OrchestratedStatus::Blocked,
            "blocked until deterministic analysis completes",
        )
    } else {
        map_named_phase(
            PhaseName::DeterministicPrioritization,
            manifest.phases.prioritization,
            "deterministic ordering and exact dedup state retained in run manifest",
        )
    };
    let context = if manifest.phases.prioritization != PhaseStatus::Completed {
        phase(
            PhaseName::ContextEnrichment,
            OrchestratedStatus::Blocked,
            "blocked until deterministic prioritization completes",
        )
    } else if has_context {
        phase(
            PhaseName::ContextEnrichment,
            OrchestratedStatus::Completed,
            "validated contextual artifact retained; it does not validate a finding",
        )
    } else {
        phase(
            PhaseName::ContextEnrichment,
            OrchestratedStatus::OptionalNotRequested,
            "no contextual artifact supplied; human review may continue",
        )
    };
    let ai = if state.ai_completed > 0 {
        phase(
            PhaseName::OptionalAiAdvisory,
            OrchestratedStatus::Completed,
            "measured AI advisory responses retained; human decisions remain unchanged",
        )
    } else if state.ai_failed_or_queued > 0 {
        phase(
            PhaseName::OptionalAiAdvisory,
            OrchestratedStatus::Partial,
            "AI advisory work is queued or failed and cannot validate findings",
        )
    } else {
        phase(
            PhaseName::OptionalAiAdvisory,
            OrchestratedStatus::OptionalNotRequested,
            "AI is optional and was not completed",
        )
    };
    let validation = if manifest.phases.prioritization != PhaseStatus::Completed {
        phase(
            PhaseName::HumanValidation,
            OrchestratedStatus::Blocked,
            "blocked until deterministic prioritization completes",
        )
    } else if state.pending_human_reviews == 0 {
        phase(
            PhaseName::HumanValidation,
            OrchestratedStatus::Completed,
            "all candidates have terminal human decisions",
        )
    } else if state.terminal_human_reviews > 0 {
        phase(
            PhaseName::HumanValidation,
            OrchestratedStatus::Partial,
            "some candidates still require human review or abstention",
        )
    } else {
        phase(
            PhaseName::HumanValidation,
            OrchestratedStatus::Ready,
            "candidates require human review or abstention",
        )
    };
    let evaluation = if state.pending_human_reviews > 0
        || manifest.phases.prioritization != PhaseStatus::Completed
    {
        phase(
            PhaseName::ReproducibleEvaluation,
            OrchestratedStatus::Blocked,
            "benchmarking follows deterministic processing and human adjudication",
        )
    } else if has_benchmark {
        phase(
            PhaseName::ReproducibleEvaluation,
            OrchestratedStatus::EvaluationOnly,
            "benchmark evidence is retained outside the production decision path",
        )
    } else {
        phase(
            PhaseName::ReproducibleEvaluation,
            OrchestratedStatus::Ready,
            "eligible for a preregistered prospective evaluation",
        )
    };

    vec![
        phase(
            PhaseName::Authorization,
            OrchestratedStatus::Completed,
            "linked run contains validated explicit authorization",
        ),
        deterministic,
        prioritization,
        context,
        ai,
        validation,
        evaluation,
    ]
}

fn map_required_phase(status: PhaseStatus, reason: &str) -> OrchestratedPhase {
    map_named_phase(PhaseName::DeterministicAnalysis, status, reason)
}

fn map_named_phase(name: PhaseName, status: PhaseStatus, reason: &str) -> OrchestratedPhase {
    let status = match status {
        PhaseStatus::Completed => OrchestratedStatus::Completed,
        PhaseStatus::Partial | PhaseStatus::Running => OrchestratedStatus::Partial,
        PhaseStatus::Failed => OrchestratedStatus::Failed,
        PhaseStatus::Pending | PhaseStatus::Skipped => OrchestratedStatus::Ready,
    };
    phase(name, status, reason)
}

fn phase(name: PhaseName, status: OrchestratedStatus, reason: &str) -> OrchestratedPhase {
    OrchestratedPhase {
        name,
        status,
        reason: reason.into(),
    }
}

fn expected_plan_id(envelope: &OrchestrationEnvelope) -> String {
    #[derive(Serialize)]
    struct Identity<'a> {
        linked_run_id: &'a str,
        manifest_sha256: &'a str,
        target_sha256: &'a str,
        policy: &'a OrchestrationPolicy,
        evidence: &'a [EvidenceArtifact],
        state: &'a RunState,
        phases: &'a [OrchestratedPhase],
        next_action: NextAction,
        claim_status: ClaimStatus,
    }
    let bytes = serde_json::to_vec(&Identity {
        linked_run_id: &envelope.linked_run_id,
        manifest_sha256: &envelope.manifest_sha256,
        target_sha256: &envelope.target_sha256,
        policy: &envelope.policy,
        evidence: &envelope.evidence,
        state: &envelope.state,
        phases: &envelope.phases,
        next_action: envelope.next_action,
        claim_status: envelope.claim_status,
    })
    .expect("orchestration identity contains only serializable fields");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sf_plan_{}", encode_hex(&hasher.finalize()))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing into a String cannot fail");
    }
    output
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

fn valid_run_id(value: &str) -> bool {
    value.strip_prefix("sf_run_").is_some_and(|suffix| {
        (16..=80).contains(&suffix.len())
            && suffix.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn evidence_order_is_deterministic_and_unique() {
        let mut evidence = BTreeSet::new();
        evidence.insert(EvidenceArtifact {
            kind: EvidenceKind::AdvisoryCorrelation,
            sha256: "1".repeat(64),
        });
        evidence.insert(EvidenceArtifact {
            kind: EvidenceKind::ContextualReview,
            sha256: "2".repeat(64),
        });
        assert_eq!(evidence.len(), 2);
    }

    #[test]
    fn rejects_a_rehashed_plan_that_skips_human_review() {
        let bytes = include_bytes!("../../../tests/fixtures/minimal-run-with-finding.json");
        let manifest: RunManifest = serde_json::from_slice(bytes).unwrap();
        let mut plan = derive_plan(&manifest, "a".repeat(64), vec![]).unwrap();
        assert_eq!(plan.next_action, NextAction::HumanReviewOrAbstain);
        plan.next_action = NextAction::RunProspectiveEvaluation;
        plan.plan_id = expected_plan_id(&plan);
        assert!(matches!(
            plan.validate(),
            Err(OrchestratorError::InvalidField("derived phase state"))
        ));
    }
}
