//! Reconcile every candidate without deriving human verdicts from scanner counts.
use crate::remediation::{HandoffStatus, RemediationHandoff};
use crate::{CaseError, Decision, SecurityCase, digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const CONTRACT_VERSION: &str = "secureflow-remediation-closure-v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureReport {
    pub contract_version: String,
    pub base_commit: String,
    pub cases: Vec<ClosureCase>,
    pub files: Vec<ChangedFile>,
    pub checks: Vec<Check>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureCase {
    pub case_id: String,
    pub case_sha256: String,
    pub outcomes: Vec<Outcome>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub candidate_id: String,
    pub outcome: OutcomeKind,
    pub rationale: String,
    pub evidence: Vec<Artifact>,
    pub changed_paths: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Fixed,
    NoChange,
    Blocked,
    PendingReview,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub kind: ArtifactKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    SourceReview,
    RegressionTest,
    Rescan,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedFile {
    pub path: String,
    /// Git file mode after the change: 100644, 100755, or 000000 for deletion.
    pub mode: String,
    /// None records a deletion; other entries bind the exact resulting bytes.
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub evidence: Artifact,
}

#[derive(Debug, Serialize)]
pub struct ClosureSummary {
    pub fixed_candidates: usize,
    pub no_change_candidates: usize,
    pub blocked_candidates: usize,
    pub pending_review_candidates: usize,
    pub ready_for_review: bool,
}

fn invalid(message: &'static str) -> CaseError {
    CaseError::InvalidState(message)
}

pub fn relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.contains(['\\', ':'])
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".." | ".git"))
}

fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Artifact {
    fn validate(&self) -> Result<(), CaseError> {
        if !relative_path(&self.path) || !sha(&self.sha256) {
            return Err(invalid(
                "closure evidence requires a relative path and SHA-256",
            ));
        }
        Ok(())
    }
}

impl ClosureReport {
    pub fn reconcile(
        &self,
        cases: &[(&[u8], &SecurityCase)],
        handoff: Option<&RemediationHandoff>,
    ) -> Result<ClosureSummary, CaseError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(CaseError::UnsupportedContract(
                self.contract_version.clone(),
            ));
        }
        if !matches!(self.base_commit.len(), 40 | 64)
            || !self
                .base_commit
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(invalid("closure requires a full base commit identity"));
        }
        if self.cases.is_empty() || self.cases.len() > 1024 || self.files.len() > 4096 {
            return Err(invalid("closure collection limit exceeded or cases empty"));
        }
        let mut loaded = BTreeMap::new();
        for (bytes, case) in cases {
            case.validate()?;
            // Do not let a caller pair trusted bytes with a different parsed object.
            let parsed = SecurityCase::parse(bytes)?;
            if serde_json::to_value(&parsed)? != serde_json::to_value(case)?
                || loaded
                    .insert(case.case_id.as_str(), (*bytes, *case))
                    .is_some()
            {
                return Err(invalid("duplicate or mismatched closure source case"));
            }
        }
        if loaded.len() != self.cases.len() {
            return Err(invalid("closure needs every exact source case"));
        }
        let mut selected = BTreeSet::new();
        if let Some(handoff) = handoff {
            handoff.validate()?;
            if handoff.status != HandoffStatus::Authorized {
                return Err(invalid("closure requires an authorized handoff"));
            }
            for selection in &handoff.cases {
                let (bytes, case) = loaded
                    .get(selection.case_id.as_str())
                    .ok_or_else(|| invalid("handoff source case missing from closure"))?;
                if digest(bytes) != selection.case_sha256
                    || case.target.root_sha256 != selection.target_root_sha256
                    || serde_json::to_value(&case.target.revision)?
                        != serde_json::to_value(&selection.revision)?
                {
                    return Err(invalid("handoff source identity changed"));
                }
                for id in &selection.candidate_ids {
                    if !case
                        .decisions
                        .iter()
                        .any(|d| d.candidate_id == *id && d.decision == Decision::Validated)
                    {
                        return Err(invalid("handoff candidate is not human validated"));
                    }
                    selected.insert((case.case_id.as_str(), id.as_str()));
                }
            }
        }
        let mut files = BTreeSet::new();
        for file in &self.files {
            if !relative_path(&file.path)
                || file.sha256.as_deref().is_some_and(|value| !sha(value))
                || !matches!(file.mode.as_str(), "100644" | "100755" | "000000")
                || (file.mode == "000000") != file.sha256.is_none()
                || !files.insert(file.path.as_str())
            {
                return Err(invalid("invalid or duplicate closure file"));
            }
            if !handoff.is_some_and(|h| {
                h.scope.allowed_paths.iter().any(|allowed| {
                    file.path == *allowed || file.path.starts_with(&format!("{allowed}/"))
                })
            }) {
                return Err(invalid("closure file is outside the authorized scope"));
            }
        }
        let mut accounted_files = BTreeSet::new();
        let mut seen_cases = BTreeSet::new();
        let mut summary = ClosureSummary {
            fixed_candidates: 0,
            no_change_candidates: 0,
            blocked_candidates: 0,
            pending_review_candidates: 0,
            ready_for_review: false,
        };
        for entry in &self.cases {
            if !seen_cases.insert(entry.case_id.as_str()) {
                return Err(invalid("duplicate closure case"));
            }
            let (bytes, case) = loaded
                .get(entry.case_id.as_str())
                .ok_or_else(|| invalid("unknown closure case"))?;
            if digest(bytes) != entry.case_sha256 || entry.outcomes.len() != case.candidates.len() {
                return Err(invalid(
                    "closure needs exact case bytes and one outcome per candidate",
                ));
            }
            let mut seen = BTreeSet::new();
            for outcome in &entry.outcomes {
                let id = outcome.candidate_id.as_str();
                if !seen.insert(id) || !case.candidates.iter().any(|c| c.candidate_id == id) {
                    return Err(invalid("duplicate or unknown closure candidate"));
                }
                if outcome.rationale.trim().is_empty()
                    || outcome.rationale.len() > 3000
                    || outcome.evidence.len() > 64
                    || outcome.changed_paths.len() > 4096
                {
                    return Err(invalid("invalid closure rationale or evidence count"));
                }
                for artifact in &outcome.evidence {
                    artifact.validate()?;
                }
                let decision = case
                    .decisions
                    .iter()
                    .find(|d| d.candidate_id == id)
                    .map(|d| d.decision);
                let authorized = selected.contains(&(entry.case_id.as_str(), id));
                match outcome.outcome {
                    OutcomeKind::Fixed => {
                        if decision != Some(Decision::Validated)
                            || !authorized
                            || outcome.changed_paths.is_empty()
                            || !outcome
                                .evidence
                                .iter()
                                .any(|e| e.kind == ArtifactKind::SourceReview)
                            || !outcome
                                .evidence
                                .iter()
                                .any(|e| e.kind == ArtifactKind::RegressionTest)
                        {
                            return Err(invalid(
                                "fixed requires human validation, handoff, patch, source review and regression evidence",
                            ));
                        }
                        summary.fixed_candidates += 1;
                    }
                    OutcomeKind::NoChange => {
                        if decision != Some(Decision::Rejected)
                            || authorized
                            || !outcome.changed_paths.is_empty()
                            || !outcome
                                .evidence
                                .iter()
                                .any(|e| e.kind == ArtifactKind::SourceReview)
                        {
                            return Err(invalid(
                                "no_change requires a recorded rejection and source evidence; it cannot close a validated candidate",
                            ));
                        }
                        summary.no_change_candidates += 1;
                    }
                    OutcomeKind::Blocked => {
                        if !outcome.changed_paths.is_empty() && !authorized {
                            return Err(invalid("partial patches still require authorization"));
                        }
                        summary.blocked_candidates += 1;
                    }
                    OutcomeKind::PendingReview => {
                        if !outcome.changed_paths.is_empty() {
                            return Err(invalid("pending review cannot account for a patch"));
                        }
                        summary.pending_review_candidates += 1;
                    }
                }
                let mut paths = BTreeSet::new();
                for path in &outcome.changed_paths {
                    if !files.contains(path.as_str()) || !paths.insert(path.as_str()) {
                        return Err(invalid("candidate patch path is missing or duplicated"));
                    }
                    accounted_files.insert(path.as_str());
                }
            }
        }
        if accounted_files != files {
            return Err(invalid(
                "every changed file must be linked to an authorized candidate",
            ));
        }
        if self.checks.len() > 64 {
            return Err(invalid("too many closure checks"));
        }
        let mut checks = BTreeSet::new();
        for check in &self.checks {
            if check.name.trim().is_empty() || check.name.len() > 200 || !checks.insert(&check.name)
            {
                return Err(invalid("invalid or duplicate closure check"));
            }
            check.evidence.validate()?;
        }
        summary.ready_for_review = summary.blocked_candidates == 0
            && summary.pending_review_candidates == 0
            && !self.checks.is_empty()
            && self.checks.iter().all(|c| c.passed);
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation::{CaseSelection, RemediationScope};

    fn fixture() -> (Vec<u8>, SecurityCase, RemediationHandoff, ClosureReport) {
        let case: SecurityCase = serde_json::from_value(serde_json::json!({
            "contract_version": crate::CONTRACT_VERSION,
            "case_id": "sf_case_0000000000000000", "created_at": "2026-09-20T00:00:00Z",
            "target": {"label": "test", "root_sha256": "0".repeat(64),
                "authorization": {"status": "authorized", "basis": "local-project", "reviewer": "owner"}},
            "sources": [{"source_id": "sf_source_0000000000000000", "kind": "secure-engine",
                "name": "test", "version": "1", "artifact_sha256": "0".repeat(64)}],
            "candidates": [{"candidate_id": "sf_candidate_0000000000000000",
                "source_id": "sf_source_0000000000000000", "class": "engine-candidate",
                "title": "test", "confidence": "high", "evidence_ids": [], "limitations": []}],
            "decisions": [{"decision_id": "sf_decision_0000000000000000",
                "candidate_id": "sf_candidate_0000000000000000", "decision": "validated",
                "reviewer": "owner", "rationale": "Reviewed source and test", "decided_at": "2026-09-20T00:01:00Z"}]
        })).unwrap();
        case.validate().unwrap();
        let bytes = serde_json::to_vec(&case).unwrap();
        let mut handoff = RemediationHandoff {
            contract_version: crate::remediation::CONTRACT_VERSION.into(),
            handoff_id: "sf_handoff_0000000000000000".into(),
            created_at: "2026-09-20T00:02:00Z".into(),
            status: HandoffStatus::Draft,
            cases: vec![CaseSelection {
                case_id: case.case_id.clone(),
                case_sha256: digest(&bytes),
                target_root_sha256: case.target.root_sha256.clone(),
                revision: None,
                candidate_ids: vec![case.candidates[0].candidate_id.clone()],
            }],
            scope: RemediationScope {
                allowed_paths: vec!["src".into()],
                prohibited_actions: vec!["merge".into()],
                merge_authorized: false,
                deploy_authorized: false,
            },
            authorization: None,
        };
        handoff
            .authorize(
                &[(&bytes, &case)],
                "owner".into(),
                "Fix the selected candidate".into(),
                "2026-09-20T00:03:00Z".into(),
            )
            .unwrap();
        let artifact = Artifact {
            path: "review.txt".into(),
            sha256: "1".repeat(64),
            kind: ArtifactKind::SourceReview,
        };
        let mut regression = artifact.clone();
        regression.path = "test.txt".into();
        regression.kind = ArtifactKind::RegressionTest;
        let report = ClosureReport {
            contract_version: CONTRACT_VERSION.into(),
            base_commit: "a".repeat(40),
            cases: vec![ClosureCase {
                case_id: case.case_id.clone(),
                case_sha256: digest(&bytes),
                outcomes: vec![Outcome {
                    candidate_id: case.candidates[0].candidate_id.clone(),
                    outcome: OutcomeKind::Fixed,
                    rationale: "Boundary restored and regression covered".into(),
                    evidence: vec![artifact, regression.clone()],
                    changed_paths: vec!["src/auth.rs".into()],
                }],
            }],
            files: vec![ChangedFile {
                path: "src/auth.rs".into(),
                mode: "100644".into(),
                sha256: Some("2".repeat(64)),
            }],
            checks: vec![Check {
                name: "tests".into(),
                passed: true,
                evidence: regression,
            }],
        };
        (bytes, case, handoff, report)
    }

    #[test]
    fn reconciles_without_changing_decisions() {
        let (bytes, case, handoff, report) = fixture();
        let summary = report
            .reconcile(&[(&bytes, &case)], Some(&handoff))
            .unwrap();
        assert!(summary.ready_for_review);
        assert_eq!(summary.fixed_candidates, 1);
        assert_eq!(serde_json::to_vec(&case).unwrap(), bytes);
    }

    #[test]
    fn scanner_disappearance_and_permission_do_not_prove_a_fix() {
        let (bytes, case, handoff, mut report) = fixture();
        report.cases[0].outcomes[0]
            .evidence
            .retain(|e| e.kind != ArtifactKind::RegressionTest);
        assert!(
            report
                .reconcile(&[(&bytes, &case)], Some(&handoff))
                .is_err()
        );
        let (_, _, _, report) = fixture();
        assert!(report.reconcile(&[(&bytes, &case)], None).is_err());
    }

    #[test]
    fn validated_false_positive_cannot_be_closed_as_no_change() {
        let (bytes, case, handoff, mut report) = fixture();
        report.cases[0].outcomes[0].outcome = OutcomeKind::NoChange;
        report.cases[0].outcomes[0].changed_paths.clear();
        report.files.clear();
        assert!(
            report
                .reconcile(&[(&bytes, &case)], Some(&handoff))
                .is_err()
        );
        assert!(report.reconcile(&[(&bytes, &case)], None).is_err());
        let mut rejected = case;
        rejected.decisions[0].decision = Decision::Rejected;
        let bytes = serde_json::to_vec(&rejected).unwrap();
        report.cases[0].case_sha256 = digest(&bytes);
        let result = report.reconcile(&[(&bytes, &rejected)], None).unwrap();
        assert_eq!(result.no_change_candidates, 1);
        assert!(result.ready_for_review);
    }

    #[test]
    fn pending_and_failed_checks_remain_incomplete() {
        let (bytes, case, handoff, mut report) = fixture();
        report.checks[0].passed = false;
        assert!(
            !report
                .reconcile(&[(&bytes, &case)], Some(&handoff))
                .unwrap()
                .ready_for_review
        );
        report.checks[0].passed = true;
        report.cases[0].outcomes[0].outcome = OutcomeKind::PendingReview;
        report.cases[0].outcomes[0].changed_paths.clear();
        report.files.clear();
        assert!(
            !report
                .reconcile(&[(&bytes, &case)], Some(&handoff))
                .unwrap()
                .ready_for_review
        );
    }

    #[test]
    fn missing_candidates_changed_cases_and_unrelated_files_fail() {
        let (bytes, case, handoff, original) = fixture();
        let mut report = original.clone();
        report.cases[0].outcomes.clear();
        assert!(
            report
                .reconcile(&[(&bytes, &case)], Some(&handoff))
                .is_err()
        );
        let mut report = original.clone();
        report.cases[0].case_sha256 = "3".repeat(64);
        assert!(
            report
                .reconcile(&[(&bytes, &case)], Some(&handoff))
                .is_err()
        );
        let mut report = original.clone();
        report.files.push(ChangedFile {
            path: "src/unrelated.rs".into(),
            mode: "100644".into(),
            sha256: Some("4".repeat(64)),
        });
        assert!(
            report
                .reconcile(&[(&bytes, &case)], Some(&handoff))
                .is_err()
        );
        let mut report = original;
        report.files[0].path = "src-other/escape.rs".into();
        report.cases[0].outcomes[0].changed_paths[0] = "src-other/escape.rs".into();
        assert!(
            report
                .reconcile(&[(&bytes, &case)], Some(&handoff))
                .is_err()
        );
    }
}
