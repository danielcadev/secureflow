//! Explicit, review-bound remediation handoff.
//!
//! Browser and agent surfaces may create drafts. Only the CLI authorization
//! flow can bind one to exact, validated Security Cases and a named human.

use crate::{CaseError, CaseRevision, Decision, SecurityCase, digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const CONTRACT_VERSION: &str = "secureflow-remediation-handoff-v1";
const MAX_CASES: usize = 1_024;
const MAX_CANDIDATES_PER_CASE: usize = 4_096;
const MAX_ALLOWED_PATHS: usize = 4_096;
const MAX_PROHIBITED_ACTIONS: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationHandoff {
    pub contract_version: String,
    pub handoff_id: String,
    pub created_at: String,
    pub status: HandoffStatus,
    pub cases: Vec<CaseSelection>,
    pub scope: RemediationScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<RemediationAuthorization>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HandoffStatus {
    Draft,
    Authorized,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSelection {
    pub case_id: String,
    pub case_sha256: String,
    pub target_root_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<CaseRevision>,
    pub candidate_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationScope {
    pub allowed_paths: Vec<String>,
    pub prohibited_actions: Vec<String>,
    pub merge_authorized: bool,
    pub deploy_authorized: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationAuthorization {
    pub reviewer: String,
    pub rationale: String,
    pub authorized_at: String,
}

impl RemediationHandoff {
    pub fn parse(bytes: &[u8]) -> Result<Self, CaseError> {
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), CaseError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(CaseError::UnsupportedContract(
                self.contract_version.clone(),
            ));
        }
        identifier(&self.handoff_id, "sf_handoff_", "handoff_id")?;
        timestamp(&self.created_at, "created_at")?;
        if self.cases.is_empty() || self.cases.len() > MAX_CASES {
            return Err(CaseError::InvalidState("remediation selection is empty"));
        }

        let mut case_ids = BTreeSet::new();
        let mut selected = BTreeSet::new();
        for case in &self.cases {
            identifier(&case.case_id, "sf_case_", "case.case_id")?;
            if !case_ids.insert(case.case_id.as_str()) {
                return Err(CaseError::Duplicate("case.case_id"));
            }
            sha(&case.case_sha256, "case.case_sha256")?;
            sha(&case.target_root_sha256, "case.target_root_sha256")?;
            if let Some(revision) = &case.revision {
                text(&revision.kind, "case.revision.kind", 40)?;
                text(&revision.value, "case.revision.value", 200)?;
            }
            if case.candidate_ids.is_empty() || case.candidate_ids.len() > MAX_CANDIDATES_PER_CASE {
                return Err(CaseError::InvalidState(
                    "each remediation case needs a candidate",
                ));
            }
            for candidate_id in &case.candidate_ids {
                identifier(candidate_id, "sf_candidate_", "case.candidate_id")?;
                if !selected.insert((case.case_id.as_str(), candidate_id.as_str())) {
                    return Err(CaseError::Duplicate("case.candidate_id"));
                }
            }
        }

        if self.scope.allowed_paths.is_empty() || self.scope.allowed_paths.len() > MAX_ALLOWED_PATHS
        {
            return Err(CaseError::InvalidState(
                "remediation scope needs at least one allowed path",
            ));
        }
        unique_paths(&self.scope.allowed_paths, "scope.allowed_paths")?;
        if self.scope.prohibited_actions.is_empty()
            || self.scope.prohibited_actions.len() > MAX_PROHIBITED_ACTIONS
        {
            return Err(CaseError::InvalidState(
                "remediation scope needs prohibited actions",
            ));
        }
        let mut actions = BTreeSet::new();
        for action in &self.scope.prohibited_actions {
            text(action, "scope.prohibited_actions", 100)?;
            if !actions.insert(action) {
                return Err(CaseError::Duplicate("scope.prohibited_actions"));
            }
        }
        if self.scope.merge_authorized || self.scope.deploy_authorized {
            return Err(CaseError::InvalidState(
                "a remediation handoff cannot authorize merge or deployment",
            ));
        }

        match (self.status, &self.authorization) {
            (HandoffStatus::Draft, None) => {}
            (HandoffStatus::Authorized, Some(authorization)) => {
                text(&authorization.reviewer, "authorization.reviewer", 200)?;
                text(&authorization.rationale, "authorization.rationale", 3000)?;
                timestamp(&authorization.authorized_at, "authorization.authorized_at")?;
                let created_at = OffsetDateTime::parse(&self.created_at, &Rfc3339)
                    .map_err(|_| CaseError::InvalidField("created_at"))?;
                let authorized_at =
                    OffsetDateTime::parse(&authorization.authorized_at, &Rfc3339)
                        .map_err(|_| CaseError::InvalidField("authorization.authorized_at"))?;
                if authorized_at < created_at {
                    return Err(CaseError::InvalidState(
                        "remediation authorization predates its draft",
                    ));
                }
                let identity =
                    serde_json::to_vec(&(&self.cases, &self.scope, self.authorization.as_ref()))
                        .map_err(CaseError::Json)?;
                let expected = format!("sf_handoff_{}", &digest(&identity)[..32]);
                if self.handoff_id != expected {
                    return Err(CaseError::InvalidState(
                        "authorized remediation identity does not match its content",
                    ));
                }
            }
            (HandoffStatus::Draft, Some(_)) => {
                return Err(CaseError::InvalidState(
                    "a draft cannot contain remediation authorization",
                ));
            }
            (HandoffStatus::Authorized, None) => {
                return Err(CaseError::InvalidState(
                    "an authorized handoff needs named human authorization",
                ));
            }
        }
        Ok(())
    }

    pub fn authorize(
        &mut self,
        cases: &[(&[u8], &SecurityCase)],
        reviewer: String,
        rationale: String,
        authorized_at: String,
    ) -> Result<(), CaseError> {
        self.validate()?;
        if self.status != HandoffStatus::Draft {
            return Err(CaseError::InvalidState(
                "only a remediation draft can be authorized",
            ));
        }
        let supplied: BTreeMap<&str, (&[u8], &SecurityCase)> = cases
            .iter()
            .map(|(bytes, case)| (case.case_id.as_str(), (*bytes, *case)))
            .collect();
        if supplied.len() != cases.len() || supplied.len() != self.cases.len() {
            return Err(CaseError::InvalidState(
                "exactly one source case is required for every selection",
            ));
        }
        for selection in &self.cases {
            let (bytes, case) = supplied
                .get(selection.case_id.as_str())
                .ok_or(CaseError::MissingReference("remediation.case_id"))?;
            if digest(bytes) != selection.case_sha256
                || case.target.root_sha256 != selection.target_root_sha256
                || revision_tuple(case.target.revision.as_ref())
                    != revision_tuple(selection.revision.as_ref())
            {
                return Err(CaseError::InvalidState(
                    "remediation source case identity changed",
                ));
            }
            for candidate_id in &selection.candidate_ids {
                let validated = case.decisions.iter().any(|decision| {
                    decision.candidate_id == *candidate_id
                        && decision.decision == Decision::Validated
                });
                if !validated {
                    return Err(CaseError::InvalidState(
                        "remediation requires a final validated human decision",
                    ));
                }
            }
        }
        text(&reviewer, "authorization.reviewer", 200)?;
        text(&rationale, "authorization.rationale", 3000)?;
        timestamp(&authorized_at, "authorization.authorized_at")?;
        self.status = HandoffStatus::Authorized;
        self.authorization = Some(RemediationAuthorization {
            reviewer,
            rationale,
            authorized_at,
        });
        let identity = serde_json::to_vec(&(&self.cases, &self.scope, self.authorization.as_ref()))
            .map_err(CaseError::Json)?;
        self.handoff_id = format!("sf_handoff_{}", &digest(&identity)[..32]);
        self.validate()
    }
}

fn revision_tuple(revision: Option<&CaseRevision>) -> Option<(&str, &str)> {
    revision.map(|value| (value.kind.as_str(), value.value.as_str()))
}

fn identifier(value: &str, prefix: &str, field: &'static str) -> Result<(), CaseError> {
    if value.starts_with(prefix)
        && value.len() >= prefix.len() + 16
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Ok(())
    } else {
        Err(CaseError::InvalidField(field))
    }
}

fn sha(value: &str, field: &'static str) -> Result<(), CaseError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CaseError::InvalidField(field))
    }
}

fn text(value: &str, field: &'static str, max: usize) -> Result<(), CaseError> {
    if value.trim().is_empty() || value.len() > max {
        Err(CaseError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn timestamp(value: &str, field: &'static str) -> Result<(), CaseError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| CaseError::InvalidField(field))
}

fn unique_paths(paths: &[String], field: &'static str) -> Result<(), CaseError> {
    let mut unique = BTreeSet::new();
    for path in paths {
        if path.is_empty()
            || path.starts_with('/')
            || path.contains('\\')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(CaseError::InvalidField(field));
        }
        if !unique.insert(path) {
            return Err(CaseError::Duplicate(field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Candidate, CandidateClass, CaseAuthorization, CaseTarget, HumanDecision, Source, SourceKind,
    };

    fn fixture() -> (Vec<u8>, SecurityCase, RemediationHandoff) {
        let candidate_id = "sf_candidate_0000000000000000".to_owned();
        let case = SecurityCase {
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            case_id: "sf_case_0000000000000000".to_owned(),
            created_at: "2026-09-18T00:00:00Z".to_owned(),
            target: CaseTarget {
                label: "fixture".to_owned(),
                root_sha256: "0".repeat(64),
                revision: Some(CaseRevision {
                    kind: "git".to_owned(),
                    value: "abc123".to_owned(),
                }),
                authorization: CaseAuthorization {
                    status: "authorized".to_owned(),
                    basis: "test".to_owned(),
                    reviewer: "owner".to_owned(),
                    reference: None,
                    expires_at: None,
                },
            },
            sources: vec![Source {
                source_id: "sf_source_0000000000000000".to_owned(),
                kind: SourceKind::SecureEngine,
                name: "fixture".to_owned(),
                version: "1".to_owned(),
                artifact_sha256: "1".repeat(64),
                methodology: None,
            }],
            evidence: vec![],
            candidates: vec![Candidate {
                candidate_id: candidate_id.clone(),
                source_id: "sf_source_0000000000000000".to_owned(),
                class: CandidateClass::EngineCandidate,
                title: "candidate".to_owned(),
                severity: Some("high".to_owned()),
                confidence: "high".to_owned(),
                evidence_ids: vec![],
                limitations: vec![],
            }],
            staged_recommendations: vec![],
            decisions: vec![HumanDecision {
                decision_id: "sf_decision_0000000000000000".to_owned(),
                candidate_id: candidate_id.clone(),
                decision: Decision::Validated,
                reviewer: "owner".to_owned(),
                rationale: "confirmed from retained evidence".to_owned(),
                decided_at: "2026-09-18T00:01:00Z".to_owned(),
                evidence_reference: None,
            }],
        };
        let bytes = serde_json::to_vec_pretty(&case).unwrap();
        let draft = RemediationHandoff {
            contract_version: CONTRACT_VERSION.to_owned(),
            handoff_id: "sf_handoff_0000000000000000".to_owned(),
            created_at: "2026-09-18T00:02:00Z".to_owned(),
            status: HandoffStatus::Draft,
            cases: vec![CaseSelection {
                case_id: case.case_id.clone(),
                case_sha256: digest(&bytes),
                target_root_sha256: case.target.root_sha256.clone(),
                revision: case.target.revision.clone(),
                candidate_ids: vec![candidate_id],
            }],
            scope: RemediationScope {
                allowed_paths: vec!["src/auth.rs".to_owned()],
                prohibited_actions: vec!["merge".to_owned(), "deploy".to_owned()],
                merge_authorized: false,
                deploy_authorized: false,
            },
            authorization: None,
        };
        (bytes, case, draft)
    }

    #[test]
    fn authorizes_only_exact_cases_with_validated_decisions() {
        let (bytes, case, mut draft) = fixture();
        draft
            .authorize(
                &[(&bytes, &case)],
                "Daniel".to_owned(),
                "Authorize the selected local fix only".to_owned(),
                "2026-09-18T00:03:00Z".to_owned(),
            )
            .unwrap();
        assert_eq!(draft.status, HandoffStatus::Authorized);
        assert_eq!(draft.authorization.unwrap().reviewer, "Daniel");
    }

    #[test]
    fn rejects_unvalidated_or_changed_cases_and_expanded_actions() {
        let (bytes, mut case, draft) = fixture();
        case.decisions[0].decision = Decision::Abstained;
        let mut unvalidated = draft.clone();
        assert!(
            unvalidated
                .authorize(
                    &[(&bytes, &case)],
                    "Daniel".to_owned(),
                    "This rationale is sufficiently explicit".to_owned(),
                    "2026-09-18T00:03:00Z".to_owned(),
                )
                .is_err()
        );
        let (_, exact_case, mut changed) = fixture();
        assert!(
            changed
                .authorize(
                    &[(b"changed", &exact_case)],
                    "Daniel".to_owned(),
                    "This rationale is sufficiently explicit".to_owned(),
                    "2026-09-18T00:03:00Z".to_owned(),
                )
                .is_err()
        );
        let (_, _, mut expanded) = fixture();
        expanded.scope.merge_authorized = true;
        assert!(expanded.validate().is_err());
    }
}
