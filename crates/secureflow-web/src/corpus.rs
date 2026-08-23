use crate::inference::{
    ApiCandidateKind, CandidateDisposition, CandidateOrigin, VulnerabilityStatus, WebInference,
};
use crate::inventory::{HttpMethod, RouteKind, WebInventory};
use crate::lab::{CaseLicense, CaseSplit};
use crate::scope::{sha256_hex, valid_sha256, valid_text};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CORPUS_VERSION: &str = "secureflow-web-development-corpus-v1";
pub const CORPUS_RESULT_VERSION: &str = "secureflow-web-corpus-result-v1";
pub const MAX_CORPUS_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_CORPUS_RESULT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebDevelopmentCorpus {
    pub contract_version: String,
    pub corpus_id: String,
    pub name: String,
    pub split: CaseSplit,
    pub license: CaseLicense,
    pub cases: Vec<CorpusCase>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusCase {
    pub case_id: String,
    pub description: String,
    pub expectation: CorpusExpectation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CorpusExpectation {
    InventoryRoutePresent {
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<String>,
        route_kind: RouteKind,
        methods: Vec<HttpMethod>,
    },
    InferenceCandidatePresent {
        #[serde(skip_serializing_if = "Option::is_none")]
        route: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        operation: Option<String>,
        candidate_kind: ApiCandidateKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        origin: Option<CandidateOrigin>,
        disposition: CandidateDisposition,
    },
    InferenceRouteAbsent {
        route: String,
    },
    SemanticInvariant {
        invariant: CorpusSemanticInvariant,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorpusSemanticInvariant {
    NetworkNotUsed,
    TargetCodeNotExecuted,
    NoAutomaticVulnerability,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebCorpusResult {
    pub contract_version: String,
    pub result_id: String,
    pub corpus_id: String,
    pub corpus_sha256: String,
    pub inventory_id: String,
    pub inference_id: String,
    pub counts: CorpusCounts,
    pub cases: Vec<CorpusCaseResult>,
    pub claims: CorpusClaims,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusCounts {
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusCaseResult {
    pub case_id: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusClaims {
    pub development_only: bool,
    pub independent_holdout: bool,
    pub superiority_claim_allowed: bool,
    pub production_safety_claim_allowed: bool,
}

#[derive(Debug, Error)]
pub enum CorpusError {
    #[error("invalid web corpus field: {0}")]
    InvalidField(&'static str),
    #[error("web corpus artifacts do not refer to the same target and inventory")]
    ArtifactLinkMismatch,
    #[error("invalid web corpus JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn parse_corpus(bytes: &[u8]) -> Result<WebDevelopmentCorpus, CorpusError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CORPUS_BYTES {
        return Err(CorpusError::InvalidField("corpus document size"));
    }
    let corpus: WebDevelopmentCorpus = serde_json::from_slice(bytes)?;
    corpus.validate()?;
    Ok(corpus)
}

pub fn evaluate_corpus(
    inventory: &WebInventory,
    inference: &WebInference,
    corpus_bytes: &[u8],
) -> Result<WebCorpusResult, CorpusError> {
    inventory
        .validate()
        .map_err(|_| CorpusError::InvalidField("inventory"))?;
    inference
        .validate()
        .map_err(|_| CorpusError::InvalidField("inference"))?;
    if inference.scope_id != inventory.scope_id
        || inference.repository_root_sha256 != inventory.repository_root_sha256
        || !inference.inventory_ids.contains(&inventory.inventory_id)
    {
        return Err(CorpusError::ArtifactLinkMismatch);
    }
    let corpus = parse_corpus(corpus_bytes)?;
    let cases = corpus
        .cases
        .iter()
        .map(|case| {
            let passed = expectation_satisfied(&case.expectation, inventory, inference);
            CorpusCaseResult {
                case_id: case.case_id.clone(),
                passed,
                detail: if passed {
                    "expectation satisfied"
                } else {
                    "expectation not satisfied"
                }
                .into(),
            }
        })
        .collect::<Vec<_>>();
    let passed = cases.iter().filter(|case| case.passed).count() as u64;
    let mut result = WebCorpusResult {
        contract_version: CORPUS_RESULT_VERSION.into(),
        result_id: String::new(),
        corpus_id: corpus.corpus_id,
        corpus_sha256: sha256_hex(corpus_bytes),
        inventory_id: inventory.inventory_id.clone(),
        inference_id: inference.inference_id.clone(),
        counts: CorpusCounts {
            total: cases.len() as u64,
            passed,
            failed: cases.len() as u64 - passed,
        },
        cases,
        claims: CorpusClaims {
            development_only: true,
            independent_holdout: false,
            superiority_claim_allowed: false,
            production_safety_claim_allowed: false,
        },
    };
    result.result_id = expected_result_id(&result);
    result.validate()?;
    Ok(result)
}

pub fn parse_corpus_result(bytes: &[u8]) -> Result<WebCorpusResult, CorpusError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CORPUS_RESULT_BYTES {
        return Err(CorpusError::InvalidField("corpus result document size"));
    }
    let result: WebCorpusResult = serde_json::from_slice(bytes)?;
    result.validate()?;
    Ok(result)
}

impl WebDevelopmentCorpus {
    fn validate(&self) -> Result<(), CorpusError> {
        if self.contract_version != CORPUS_VERSION
            || !valid_identifier(&self.corpus_id, "sf_web_corpus_")
            || self.corpus_id != expected_corpus_id(self)
            || !valid_text(&self.name, 200)
            || self.split != CaseSplit::Development
            || !valid_text(&self.license.spdx, 100)
            || !valid_text(&self.license.provenance, 500)
            || !valid_sha256(&self.license.license_sha256)
            || !(20..=40).contains(&self.cases.len())
            || !self
                .cases
                .windows(2)
                .all(|pair| pair[0].case_id < pair[1].case_id)
        {
            return Err(CorpusError::InvalidField("corpus"));
        }
        for case in &self.cases {
            if !valid_case_id(&case.case_id) || !valid_text(&case.description, 500) {
                return Err(CorpusError::InvalidField("case"));
            }
            validate_expectation(&case.expectation)?;
        }
        Ok(())
    }
}

impl WebCorpusResult {
    fn validate(&self) -> Result<(), CorpusError> {
        if self.contract_version != CORPUS_RESULT_VERSION
            || !valid_identifier(&self.result_id, "sf_web_corpus_result_")
            || self.result_id != expected_result_id(self)
            || !valid_identifier(&self.corpus_id, "sf_web_corpus_")
            || !valid_sha256(&self.corpus_sha256)
            || !valid_identifier(&self.inventory_id, "sf_web_inventory_")
            || !valid_identifier(&self.inference_id, "sf_web_inference_")
            || !(20..=40).contains(&self.cases.len())
            || self.counts.total != self.cases.len() as u64
            || self.counts.passed + self.counts.failed != self.counts.total
            || self.cases.iter().filter(|case| case.passed).count() as u64 != self.counts.passed
            || !self
                .cases
                .windows(2)
                .all(|pair| pair[0].case_id < pair[1].case_id)
            || !self.claims.development_only
            || self.claims.independent_holdout
            || self.claims.superiority_claim_allowed
            || self.claims.production_safety_claim_allowed
        {
            return Err(CorpusError::InvalidField("corpus result"));
        }
        for case in &self.cases {
            if !valid_case_id(&case.case_id) || !valid_text(&case.detail, 500) {
                return Err(CorpusError::InvalidField("corpus case result"));
            }
        }
        Ok(())
    }
}

fn validate_expectation(expectation: &CorpusExpectation) -> Result<(), CorpusError> {
    match expectation {
        CorpusExpectation::InventoryRoutePresent {
            route,
            route_kind,
            methods,
        } => {
            if methods.len() > 7
                || !methods.windows(2).all(|pair| pair[0] < pair[1])
                || matches!(route_kind, RouteKind::ApiRoute | RouteKind::PageRoute)
                    != route.is_some()
            {
                return Err(CorpusError::InvalidField("inventory expectation"));
            }
            validate_optional_route(route)?;
        }
        CorpusExpectation::InferenceCandidatePresent {
            route,
            operation,
            candidate_kind,
            ..
        } => {
            validate_optional_route(route)?;
            if operation
                .as_deref()
                .is_some_and(|value| !valid_text(value, 300))
            {
                return Err(CorpusError::InvalidField("inference operation"));
            }
            let invalid = match candidate_kind {
                ApiCandidateKind::HttpEndpoint => route.is_none(),
                ApiCandidateKind::GraphQlOperation => operation.is_none(),
                ApiCandidateKind::TrpcProcedure => route.is_none() || operation.is_none(),
                ApiCandidateKind::ServerAction => operation.is_none(),
                ApiCandidateKind::UnresolvedClientCall => route.is_some() || operation.is_none(),
            };
            if invalid {
                return Err(CorpusError::InvalidField("inference expectation"));
            }
        }
        CorpusExpectation::InferenceRouteAbsent { route } => validate_route(route)?,
        CorpusExpectation::SemanticInvariant { .. } => {}
    }
    Ok(())
}

fn expectation_satisfied(
    expectation: &CorpusExpectation,
    inventory: &WebInventory,
    inference: &WebInference,
) -> bool {
    match expectation {
        CorpusExpectation::InventoryRoutePresent {
            route,
            route_kind,
            methods,
        } => inventory.routes.iter().any(|actual| {
            &actual.route == route && actual.kind == *route_kind && &actual.methods == methods
        }),
        CorpusExpectation::InferenceCandidatePresent {
            route,
            operation,
            candidate_kind,
            origin,
            disposition,
        } => inference.candidates.iter().any(|actual| {
            &actual.route == route
                && &actual.operation == operation
                && actual.kind == *candidate_kind
                && actual.disposition == *disposition
                && origin.is_none_or(|expected| {
                    actual
                        .evidence
                        .iter()
                        .any(|evidence| evidence.origin == expected)
                })
        }),
        CorpusExpectation::InferenceRouteAbsent { route } => inference
            .candidates
            .iter()
            .all(|actual| actual.route.as_deref() != Some(route)),
        CorpusExpectation::SemanticInvariant { invariant } => match invariant {
            CorpusSemanticInvariant::NetworkNotUsed => {
                !inventory.semantics.network_used && !inference.semantics.network_used
            }
            CorpusSemanticInvariant::TargetCodeNotExecuted => {
                !inventory.semantics.target_code_executed
                    && !inference.semantics.target_code_executed
            }
            CorpusSemanticInvariant::NoAutomaticVulnerability => {
                inference.candidates.iter().all(|candidate| {
                    candidate.vulnerability_status == VulnerabilityStatus::NotAssessed
                })
            }
        },
    }
}

fn validate_optional_route(route: &Option<String>) -> Result<(), CorpusError> {
    if let Some(route) = route {
        validate_route(route)?;
    }
    Ok(())
}

fn validate_route(route: &str) -> Result<(), CorpusError> {
    if !route.starts_with('/') || route.len() > 2_000 || route.contains("..") {
        return Err(CorpusError::InvalidField("route"));
    }
    Ok(())
}

fn expected_corpus_id(corpus: &WebDevelopmentCorpus) -> String {
    let mut stable = corpus.clone();
    stable.corpus_id.clear();
    format!(
        "sf_web_corpus_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("corpus serialization"))
    )
}

fn expected_result_id(result: &WebCorpusResult) -> String {
    let mut stable = result.clone();
    stable.result_id.clear();
    format!(
        "sf_web_corpus_result_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("corpus result serialization"))
    )
}

fn valid_case_id(value: &str) -> bool {
    (8..=80).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_identifier(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}
