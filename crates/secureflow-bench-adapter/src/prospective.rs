//! Preregistered prospective-study contract.
//!
//! Sealing commits to a corpus, systems, outcomes and claim boundaries before
//! results are observed. This module does not execute the study.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const PROTOCOL_VERSION: &str = "secureflow-prospective-protocol-v1";
pub const MAX_PROTOCOL_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolDraft {
    pub research_question: String,
    pub corpus: CorpusCommitment,
    pub systems: Vec<SystemCommitment>,
    pub blinding: BlindingCommitment,
    pub execution: ExecutionCommitment,
    pub outcomes: OutcomeCommitment,
    pub claims: ProspectiveClaimBoundary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProspectiveProtocol {
    pub contract_version: String,
    pub protocol_id: String,
    pub sealed_at: String,
    #[serde(flatten)]
    pub draft: ProtocolDraft,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusCommitment {
    pub manifest_sha256: String,
    pub provenance_sha256: String,
    pub license_manifest_sha256: String,
    pub total_cases: u64,
    pub vulnerable_cases: u64,
    pub safe_controls: u64,
    pub languages: Vec<String>,
    pub weakness_families: Vec<String>,
    pub previously_unseen_holdout: bool,
    pub labels_hidden_from_systems: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemCommitment {
    pub system_id: String,
    pub kind: SystemKind,
    pub version_or_cohort: String,
    pub configuration_sha256: String,
    pub capability_profile: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemKind {
    Secureflow,
    AutomatedComparator,
    HumanResearcher,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlindingCommitment {
    pub participant_ground_truth_hidden: bool,
    pub system_ground_truth_hidden: bool,
    pub randomized_case_order: bool,
    pub independent_adjudicators: u64,
    pub disagreement_resolution: String,
    pub leakage_audit_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCommitment {
    pub repetitions_per_automated_system: u64,
    pub timeout_seconds_per_case: u64,
    pub equal_machine_resource_limits: bool,
    pub network_policy: String,
    pub retry_policy: String,
    pub crash_timeout_policy: String,
    pub environment_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeCommitment {
    pub primary_metrics: Vec<PrimaryMetric>,
    pub report_precision_recall_separately: bool,
    pub report_false_positives_negatives_separately: bool,
    pub report_time_and_cost: bool,
    pub report_abstentions: bool,
    pub uncertainty_method: String,
    pub success_criterion: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrimaryMetric {
    ValidatedRecall,
    ValidatedPrecision,
    FalsePositiveRate,
    AnalystMinutes,
    WallClockSeconds,
    TokenCost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProspectiveClaimBoundary {
    pub task_bounded_comparison_only: bool,
    pub no_global_superiority_claim: bool,
    pub no_production_safety_claim: bool,
    pub publish_negative_results: bool,
    pub disclose_conflicts_and_limitations: bool,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid prospective protocol field: {0}")]
    InvalidField(&'static str),
    #[error("invalid prospective protocol JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not format protocol timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
}

pub fn seal_draft(
    bytes: &[u8],
    sealed_at: Option<String>,
) -> Result<ProspectiveProtocol, ProtocolError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_PROTOCOL_BYTES {
        return Err(ProtocolError::InvalidField("document size"));
    }
    let draft: ProtocolDraft = serde_json::from_slice(bytes)?;
    let mut protocol = ProspectiveProtocol {
        contract_version: PROTOCOL_VERSION.into(),
        protocol_id: String::new(),
        sealed_at: sealed_at.unwrap_or(OffsetDateTime::now_utc().format(&Rfc3339)?),
        draft,
    };
    protocol.protocol_id = expected_protocol_id(&protocol);
    protocol.validate()?;
    Ok(protocol)
}

pub fn parse_protocol(bytes: &[u8]) -> Result<ProspectiveProtocol, ProtocolError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_PROTOCOL_BYTES {
        return Err(ProtocolError::InvalidField("document size"));
    }
    let protocol: ProspectiveProtocol = serde_json::from_slice(bytes)?;
    protocol.validate()?;
    Ok(protocol)
}

impl ProspectiveProtocol {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.contract_version != PROTOCOL_VERSION
            || !valid_prefixed_hash(&self.protocol_id, "sf_protocol_")
            || OffsetDateTime::parse(&self.sealed_at, &Rfc3339).is_err()
            || !valid_text(&self.draft.research_question, 1_000)
        {
            return Err(ProtocolError::InvalidField("identity"));
        }
        let corpus = &self.draft.corpus;
        if !valid_sha256(&corpus.manifest_sha256)
            || !valid_sha256(&corpus.provenance_sha256)
            || !valid_sha256(&corpus.license_manifest_sha256)
            || corpus.total_cases < 20
            || corpus.vulnerable_cases < 10
            || corpus.safe_controls < 10
            || corpus.vulnerable_cases + corpus.safe_controls != corpus.total_cases
            || !valid_unique_texts(&corpus.languages, 1, 20, 100)
            || !valid_unique_texts(&corpus.weakness_families, 1, 100, 200)
            || !corpus.previously_unseen_holdout
            || !corpus.labels_hidden_from_systems
        {
            return Err(ProtocolError::InvalidField("corpus"));
        }
        if self.draft.systems.len() < 2 || self.draft.systems.len() > 100 {
            return Err(ProtocolError::InvalidField("systems"));
        }
        let mut system_ids = BTreeSet::new();
        let mut has_secureflow = false;
        let mut has_human = false;
        for system in &self.draft.systems {
            if !valid_text(&system.system_id, 100)
                || !system_ids.insert(&system.system_id)
                || !valid_text(&system.version_or_cohort, 200)
                || !valid_sha256(&system.configuration_sha256)
                || !valid_unique_texts(&system.capability_profile, 1, 100, 300)
            {
                return Err(ProtocolError::InvalidField("systems"));
            }
            has_secureflow |= system.kind == SystemKind::Secureflow;
            has_human |= system.kind == SystemKind::HumanResearcher;
        }
        if !has_secureflow || !has_human {
            return Err(ProtocolError::InvalidField(
                "systems require SecureFlow and a human cohort",
            ));
        }
        let blinding = &self.draft.blinding;
        if !blinding.participant_ground_truth_hidden
            || !blinding.system_ground_truth_hidden
            || !blinding.randomized_case_order
            || blinding.independent_adjudicators < 2
            || !valid_text(&blinding.disagreement_resolution, 1_000)
            || !blinding.leakage_audit_required
        {
            return Err(ProtocolError::InvalidField("blinding"));
        }
        let execution = &self.draft.execution;
        if !(1..=100).contains(&execution.repetitions_per_automated_system)
            || !(1..=86_400).contains(&execution.timeout_seconds_per_case)
            || !execution.equal_machine_resource_limits
            || !matches!(
                execution.network_policy.as_str(),
                "disabled" | "recorded-required"
            )
            || !valid_text(&execution.retry_policy, 1_000)
            || !valid_text(&execution.crash_timeout_policy, 1_000)
            || !valid_sha256(&execution.environment_sha256)
        {
            return Err(ProtocolError::InvalidField("execution"));
        }
        let outcomes = &self.draft.outcomes;
        let metrics = outcomes
            .primary_metrics
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if metrics.len() != outcomes.primary_metrics.len()
            || !metrics.contains(&PrimaryMetric::ValidatedRecall)
            || !metrics.contains(&PrimaryMetric::ValidatedPrecision)
            || !metrics.contains(&PrimaryMetric::AnalystMinutes)
            || !outcomes.report_precision_recall_separately
            || !outcomes.report_false_positives_negatives_separately
            || !outcomes.report_time_and_cost
            || !outcomes.report_abstentions
            || !valid_text(&outcomes.uncertainty_method, 500)
            || !valid_text(&outcomes.success_criterion, 1_000)
        {
            return Err(ProtocolError::InvalidField("outcomes"));
        }
        let claims = &self.draft.claims;
        if !claims.task_bounded_comparison_only
            || !claims.no_global_superiority_claim
            || !claims.no_production_safety_claim
            || !claims.publish_negative_results
            || !claims.disclose_conflicts_and_limitations
        {
            return Err(ProtocolError::InvalidField("claims"));
        }
        if self.protocol_id != expected_protocol_id(self) {
            return Err(ProtocolError::InvalidField("protocol_id"));
        }
        Ok(())
    }
}

fn expected_protocol_id(protocol: &ProspectiveProtocol) -> String {
    let bytes = serde_json::to_vec(&(&protocol.sealed_at, &protocol.draft))
        .expect("protocol identity contains only serializable fields");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sf_protocol_{}", encode_hex(&hasher.finalize()))
}

fn valid_unique_texts(values: &[String], min: usize, max: usize, text_max: usize) -> bool {
    if !(min..=max).contains(&values.len()) {
        return false;
    }
    let unique = values.iter().collect::<BTreeSet<_>>();
    unique.len() == values.len() && values.iter().all(|value| valid_text(value, text_max))
}

fn valid_text(value: &str, max: usize) -> bool {
    let value = value.trim();
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
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

    fn draft() -> ProtocolDraft {
        ProtocolDraft {
            research_question: "Does SecureFlow improve validated recall per analyst minute?"
                .into(),
            corpus: CorpusCommitment {
                manifest_sha256: "1".repeat(64),
                provenance_sha256: "2".repeat(64),
                license_manifest_sha256: "3".repeat(64),
                total_cases: 20,
                vulnerable_cases: 10,
                safe_controls: 10,
                languages: vec!["Rust".into(), "TypeScript".into()],
                weakness_families: vec!["authorization".into()],
                previously_unseen_holdout: true,
                labels_hidden_from_systems: true,
            },
            systems: vec![
                SystemCommitment {
                    system_id: "secureflow-v1".into(),
                    kind: SystemKind::Secureflow,
                    version_or_cohort: "local build".into(),
                    configuration_sha256: "4".repeat(64),
                    capability_profile: vec!["static-analysis".into()],
                },
                SystemCommitment {
                    system_id: "human-cohort".into(),
                    kind: SystemKind::HumanResearcher,
                    version_or_cohort: "three authorized reviewers".into(),
                    configuration_sha256: "5".repeat(64),
                    capability_profile: vec!["manual-review".into()],
                },
            ],
            blinding: BlindingCommitment {
                participant_ground_truth_hidden: true,
                system_ground_truth_hidden: true,
                randomized_case_order: true,
                independent_adjudicators: 2,
                disagreement_resolution: "third independent adjudicator".into(),
                leakage_audit_required: true,
            },
            execution: ExecutionCommitment {
                repetitions_per_automated_system: 3,
                timeout_seconds_per_case: 600,
                equal_machine_resource_limits: true,
                network_policy: "disabled".into(),
                retry_policy: "no retry except documented infrastructure failure".into(),
                crash_timeout_policy: "score separately as operational failures".into(),
                environment_sha256: "6".repeat(64),
            },
            outcomes: OutcomeCommitment {
                primary_metrics: vec![
                    PrimaryMetric::ValidatedRecall,
                    PrimaryMetric::ValidatedPrecision,
                    PrimaryMetric::AnalystMinutes,
                ],
                report_precision_recall_separately: true,
                report_false_positives_negatives_separately: true,
                report_time_and_cost: true,
                report_abstentions: true,
                uncertainty_method: "paired bootstrap confidence intervals".into(),
                success_criterion: "predeclared non-inferiority and time threshold".into(),
            },
            claims: ProspectiveClaimBoundary {
                task_bounded_comparison_only: true,
                no_global_superiority_claim: true,
                no_production_safety_claim: true,
                publish_negative_results: true,
                disclose_conflicts_and_limitations: true,
            },
        }
    }

    #[test]
    fn seals_and_detects_tampering() {
        let bytes = serde_json::to_vec(&draft()).unwrap();
        let mut protocol = seal_draft(&bytes, Some("2026-08-23T16:00:00Z".into())).unwrap();
        protocol.validate().unwrap();
        protocol.draft.corpus.total_cases += 1;
        assert!(protocol.validate().is_err());
    }

    #[test]
    fn rejects_missing_human_comparator() {
        let mut draft = draft();
        draft
            .systems
            .retain(|system| system.kind != SystemKind::HumanResearcher);
        let bytes = serde_json::to_vec(&draft).unwrap();
        assert!(seal_draft(&bytes, Some("2026-08-23T16:00:00Z".into())).is_err());
    }
}
