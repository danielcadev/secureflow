//! Universal, local Security Case contract.
//!
//! A case is an evidence and decision boundary, not a vulnerability oracle.
//! Candidate authority is retained explicitly and only a named human decision
//! may be final.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const CONTRACT_VERSION: &str = "secureflow-security-case-v1";
pub const SARIF_VERSION: &str = "2.1.0";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityCase {
    pub contract_version: String,
    pub case_id: String,
    pub created_at: String,
    pub target: CaseTarget,
    #[serde(default)] pub sources: Vec<Source>,
    #[serde(default)] pub evidence: Vec<Evidence>,
    #[serde(default)] pub candidates: Vec<Candidate>,
    #[serde(default)] pub staged_recommendations: Vec<StagedRecommendation>,
    #[serde(default)] pub decisions: Vec<HumanDecision>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTarget {
    pub label: String,
    pub root_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub revision: Option<CaseRevision>,
    pub authorization: CaseAuthorization,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRevision { pub kind: String, pub value: String }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseAuthorization { pub status: String, pub basis: String, pub reviewer: String, #[serde(skip_serializing_if = "Option::is_none")] pub reference: Option<String>, #[serde(skip_serializing_if = "Option::is_none")] pub expires_at: Option<String> }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source { pub source_id: String, pub kind: SourceKind, pub name: String, pub version: String, pub artifact_sha256: String, #[serde(skip_serializing_if = "Option::is_none")] pub methodology: Option<String> }
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind { SecureEngine, SecureSkillContextual, ExternalSarif, Agent }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence { pub evidence_id: String, pub source_id: String, pub sha256: String, pub description: String, #[serde(skip_serializing_if = "Option::is_none")] pub relative_path: Option<String> }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate { pub candidate_id: String, pub source_id: String, pub class: CandidateClass, pub title: String, #[serde(skip_serializing_if = "Option::is_none")] pub severity: Option<String>, pub confidence: String, #[serde(default)] pub evidence_ids: Vec<String>, #[serde(default)] pub limitations: Vec<String> }
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateClass { EngineCandidate, ContextualCandidate, ExternalToolCandidate }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedRecommendation { pub stage_id: String, pub candidate_id: String, pub agent_name: String, pub recommendation: String, pub rationale: String, pub created_at: String }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanDecision { pub decision_id: String, pub candidate_id: String, pub decision: Decision, pub reviewer: String, pub rationale: String, pub decided_at: String, #[serde(skip_serializing_if = "Option::is_none")] pub evidence_reference: Option<String> }
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision { Validated, Rejected, Abstained }

#[derive(Debug, Error)]
pub enum CaseError { #[error("unsupported contract: {0}")] UnsupportedContract(String), #[error("invalid field: {0}")] InvalidField(&'static str), #[error("duplicate identifier: {0}")] Duplicate(&'static str), #[error("missing referenced {0}")] MissingReference(&'static str), #[error("invalid state: {0}")] InvalidState(&'static str), #[error("invalid JSON: {0}")] Json(#[from] serde_json::Error) }

impl SecurityCase {
    pub fn validate(&self) -> Result<(), CaseError> {
        if self.contract_version != CONTRACT_VERSION { return Err(CaseError::UnsupportedContract(self.contract_version.clone())); }
        id(&self.case_id, "sf_case_", "case_id")?; timestamp(&self.created_at, "created_at")?;
        text(&self.target.label, "target.label", 200)?; sha(&self.target.root_sha256, "target.root_sha256")?;
        if self.target.authorization.status != "authorized" { return Err(CaseError::InvalidState("target authorization is required")); }
        text(&self.target.authorization.basis, "target.authorization.basis", 100)?; text(&self.target.authorization.reviewer, "target.authorization.reviewer", 200)?;
        if let Some(value) = &self.target.authorization.reference { text(value, "target.authorization.reference", 300)?; }
        if let Some(value) = &self.target.authorization.expires_at { timestamp(value, "target.authorization.expires_at")?; }
        if let Some(revision) = &self.target.revision { text(&revision.kind, "target.revision.kind", 40)?; text(&revision.value, "target.revision.value", 200)?; }
        let mut source_ids = BTreeSet::new();
        for value in &self.sources { id(&value.source_id, "sf_source_", "source.source_id")?; if !source_ids.insert(&value.source_id) { return Err(CaseError::Duplicate("source_id")); } text(&value.name, "source.name", 200)?; text(&value.version, "source.version", 200)?; sha(&value.artifact_sha256, "source.artifact_sha256")?; if let Some(method) = &value.methodology { text(method, "source.methodology", 2000)?; } }
        let mut evidence_ids = BTreeSet::new();
        for value in &self.evidence { id(&value.evidence_id, "sf_evidence_", "evidence.evidence_id")?; if !evidence_ids.insert(&value.evidence_id) { return Err(CaseError::Duplicate("evidence_id")); } if !source_ids.contains(&value.source_id) { return Err(CaseError::MissingReference("evidence.source_id")); } sha(&value.sha256, "evidence.sha256")?; text(&value.description, "evidence.description", 4000)?; if let Some(path) = &value.relative_path { path_text(path, "evidence.relative_path")?; } }
        let mut candidate_ids = BTreeSet::new();
        for value in &self.candidates { id(&value.candidate_id, "sf_candidate_", "candidate.candidate_id")?; if !candidate_ids.insert(&value.candidate_id) { return Err(CaseError::Duplicate("candidate_id")); } if !source_ids.contains(&value.source_id) { return Err(CaseError::MissingReference("candidate.source_id")); } text(&value.title, "candidate.title", 500)?; text(&value.confidence, "candidate.confidence", 40)?; if let Some(severity) = &value.severity { text(severity, "candidate.severity", 40)?; } for evidence in &value.evidence_ids { if !evidence_ids.contains(evidence) { return Err(CaseError::MissingReference("candidate.evidence_id")); } } for limitation in &value.limitations { text(limitation, "candidate.limitation", 4000)?; } }
        let mut stages = BTreeSet::new();
        for value in &self.staged_recommendations { id(&value.stage_id, "sf_stage_", "stage.stage_id")?; if !stages.insert(&value.stage_id) { return Err(CaseError::Duplicate("stage_id")); } if !candidate_ids.contains(&value.candidate_id) { return Err(CaseError::MissingReference("stage.candidate_id")); } text(&value.agent_name, "stage.agent_name", 200)?; text(&value.recommendation, "stage.recommendation", 40)?; text(&value.rationale, "stage.rationale", 3000)?; timestamp(&value.created_at, "stage.created_at")?; }
        let mut decided = BTreeSet::new();
        for value in &self.decisions { id(&value.decision_id, "sf_decision_", "decision.decision_id")?; if !decided.insert(&value.candidate_id) { return Err(CaseError::Duplicate("decision.candidate_id")); } if !candidate_ids.contains(&value.candidate_id) { return Err(CaseError::MissingReference("decision.candidate_id")); } text(&value.reviewer, "decision.reviewer", 200)?; text(&value.rationale, "decision.rationale", 3000)?; timestamp(&value.decided_at, "decision.decided_at")?; if let Some(reference) = &value.evidence_reference { text(reference, "decision.evidence_reference", 300)?; } }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, CaseError> { let value: Self = serde_json::from_slice(bytes)?; value.validate()?; Ok(value) }
    pub fn case_id_for(target_sha256: &str) -> String { format!("sf_case_{}", &digest(target_sha256.as_bytes())[..32]) }
    pub fn derived_id(prefix: &str, bytes: &[u8]) -> String { format!("{prefix}{}", &digest(bytes)[..32]) }
    pub fn add_human_decision(&mut self, candidate_id: String, decision: Decision, reviewer: String, rationale: String, evidence_reference: Option<String>, decided_at: String) -> Result<(), CaseError> { if self.decisions.iter().any(|entry| entry.candidate_id == candidate_id) { return Err(CaseError::InvalidState("candidate already has a final human decision")); } self.decisions.push(HumanDecision { decision_id: Self::derived_id("sf_decision_", format!("{candidate_id}|{reviewer}|{decided_at}").as_bytes()), candidate_id, decision, reviewer, rationale, decided_at, evidence_reference }); self.validate() }
}

pub fn digest(bytes: &[u8]) -> String { let mut hash = Sha256::new(); hash.update(bytes); hash.finalize().as_slice().iter().map(|byte| format!("{byte:02x}")).collect() }
fn sha(value: &str, field: &'static str) -> Result<(), CaseError> { if value.len() == 64 && value.bytes().all(|value| value.is_ascii_lowercase() || value.is_ascii_digit()) { Ok(()) } else { Err(CaseError::InvalidField(field)) } }
fn id(value: &str, prefix: &str, field: &'static str) -> Result<(), CaseError> { if value.starts_with(prefix) && value.len() >= prefix.len() + 16 && value.len() <= 100 && value.bytes().all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'_') { Ok(()) } else { Err(CaseError::InvalidField(field)) } }
fn text(value: &str, field: &'static str, max: usize) -> Result<(), CaseError> { if value.trim().is_empty() || value.len() > max { Err(CaseError::InvalidField(field)) } else { Ok(()) } }
fn path_text(value: &str, field: &'static str) -> Result<(), CaseError> { if value.is_empty() || value.starts_with('/') || value.split('/').any(|part| part == ".." || part.is_empty()) { Err(CaseError::InvalidField(field)) } else { Ok(()) } }
fn timestamp(value: &str, field: &'static str) -> Result<(), CaseError> { OffsetDateTime::parse(value, &Rfc3339).map(|_| ()).map_err(|_| CaseError::InvalidField(field)) }

pub fn import_sarif(case: &mut SecurityCase, bytes: &[u8], source_name: String, source_version: String) -> Result<usize, CaseError> {
    let document: serde_json::Value = serde_json::from_slice(bytes)?;
    if document.get("version").and_then(serde_json::Value::as_str) != Some(SARIF_VERSION) { return Err(CaseError::InvalidField("sarif.version")); }
    let source_id = SecurityCase::derived_id("sf_source_", bytes);
    case.sources.push(Source { source_id: source_id.clone(), kind: SourceKind::ExternalSarif, name: source_name, version: source_version, artifact_sha256: digest(bytes), methodology: Some("SARIF 2.1.0 import; results remain external-tool candidates".into()) });
    let evidence_id = SecurityCase::derived_id("sf_evidence_", bytes);
    case.evidence.push(Evidence { evidence_id: evidence_id.clone(), source_id: source_id.clone(), sha256: digest(bytes), description: "retained imported SARIF document".into(), relative_path: None });
    let mut count = 0usize;
    for result in document.get("runs").and_then(serde_json::Value::as_array).into_iter().flatten().flat_map(|run| run.get("results").and_then(serde_json::Value::as_array).into_iter().flatten()) {
        let title = result.get("message").and_then(|m| m.get("text")).and_then(serde_json::Value::as_str).unwrap_or("external SARIF result").to_owned();
        let candidate_id = SecurityCase::derived_id("sf_candidate_", format!("{source_id}|{count}|{title}").as_bytes());
        let severity = result.get("level").and_then(serde_json::Value::as_str).map(str::to_owned);
        case.candidates.push(Candidate { candidate_id, source_id: source_id.clone(), class: CandidateClass::ExternalToolCandidate, title, severity, confidence: "unknown".into(), evidence_ids: vec![evidence_id.clone()], limitations: vec!["Imported tool result is unvalidated and does not establish a vulnerability.".into()] }); count += 1;
    }
    case.validate()?; Ok(count)
}

pub fn export_sarif(case: &SecurityCase) -> Result<serde_json::Value, CaseError> { case.validate()?; Ok(serde_json::json!({"version": SARIF_VERSION, "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "SecureFlow", "informationUri": "https://github.com/danielcadev/secureflow"}}, "results": case.candidates.iter().map(|candidate| serde_json::json!({"ruleId": candidate.source_id, "level": candidate.severity.as_deref().unwrap_or("note"), "message": {"text": candidate.title}, "properties": {"secureflow_candidate_id": candidate.candidate_id, "candidate_class": format!("{:?}", candidate.class), "human_decision": case.decisions.iter().find(|decision| decision.candidate_id == candidate.candidate_id).map(|decision| format!("{:?}", decision.decision)).unwrap_or_else(|| "pending".into()), "not_a_vulnerability_verdict": true}})).collect::<Vec<_>>() }]})) }
