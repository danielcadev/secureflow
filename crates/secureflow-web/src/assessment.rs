use crate::inventory::{EvidenceState, HttpMethod};
use crate::scope::{sha256_hex, valid_sha256, valid_text};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const ASSESSMENT_VERSION: &str = "secureflow-web-assessment-v1";
pub const MAX_ASSESSMENT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageRoute {
    pub route_key: String,
    pub method: HttpMethod,
    pub route: String,
    pub implemented: bool,
    pub documented: bool,
    pub observed: bool,
    pub access_intent: AccessIntent,
    pub expected: ControlExpectation,
    pub observed_controls: ObservedControls,
    #[serde(default)]
    pub allowed_response_fields: Vec<String>,
    pub response_allowlist_declared: bool,
    #[serde(default)]
    pub observed_response_fields: Vec<String>,
    pub evidence: Vec<EvidenceReference>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessIntent {
    Public,
    Authenticated,
    Privileged,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlExpectation {
    pub authentication_required: bool,
    pub authorization_required: bool,
    pub owner_scope_required: bool,
    pub tenant_scope_required: bool,
    pub restricted_cors_required: bool,
    pub private_cache_required: bool,
    pub sanitized_errors_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedControls {
    pub authentication: ControlState,
    pub authorization: ControlState,
    pub owner_scope: ControlState,
    pub tenant_scope: ControlState,
    pub restricted_cors: ControlState,
    pub private_cache: ControlState,
    pub sanitized_errors: ControlState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlState {
    Present,
    Missing,
    Inconsistent,
    Unknown,
    NotApplicable,
}

impl From<EvidenceState> for ControlState {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Present => Self::Present,
            EvidenceState::Missing => Self::Missing,
            EvidenceState::Inconsistent => Self::Inconsistent,
            EvidenceState::Unknown => Self::Unknown,
            EvidenceState::NotApplicable => Self::NotApplicable,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReference {
    pub kind: AssessmentEvidenceKind,
    pub reference: String,
    pub sha256: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssessmentEvidenceKind {
    Code,
    Build,
    Documentation,
    AuthorizedTraffic,
    ControlFlow,
    Response,
    HumanReproduction,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebAssessment {
    pub contract_version: String,
    pub assessment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_assessment_id: Option<String>,
    pub created_at: String,
    pub scope_id: String,
    pub inventory_ids: Vec<String>,
    pub observations: Vec<Observation>,
    pub summary: AssessmentSummary,
    pub semantics: AssessmentSemantics,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub observation_id: String,
    pub rule_id: String,
    pub class: ObservationClass,
    pub route_key: String,
    pub method: HttpMethod,
    pub route: String,
    pub title: String,
    pub invariant: String,
    pub evidence: Vec<EvidenceReference>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_validation: Option<HumanValidation>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationClass {
    Candidate,
    Hardening,
    HumanValidatedVulnerability,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanValidation {
    pub reviewer: String,
    pub reviewed_at: String,
    pub rationale: String,
    pub evidence_reference: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentSummary {
    pub candidates: u64,
    pub hardening: u64,
    pub human_validated_vulnerabilities: u64,
    pub abstentions: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentSemantics {
    pub automated_validation_authority: bool,
    pub validation_authority: String,
    pub obscurity_is_a_control: bool,
    pub no_observations_mean_safe: bool,
    pub network_used: bool,
}

#[derive(Debug, Error)]
pub enum AssessmentError {
    #[error("invalid web assessment field: {0}")]
    InvalidField(&'static str),
    #[error("invalid web assessment JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not format assessment timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    #[error("web assessment observation not found: {0}")]
    ObservationNotFound(String),
    #[error("only a candidate observation can receive human vulnerability validation: {0}")]
    ObservationNotCandidate(String),
}

pub fn assess_routes(
    scope_id: String,
    mut inventory_ids: Vec<String>,
    mut routes: Vec<CoverageRoute>,
    created_at: Option<String>,
) -> Result<WebAssessment, AssessmentError> {
    if !valid_identifier(&scope_id, "sf_web_scope_") {
        return Err(AssessmentError::InvalidField("scope_id"));
    }
    inventory_ids.sort();
    if inventory_ids.is_empty()
        || inventory_ids.len() > 100_000
        || !inventory_ids
            .iter()
            .all(|value| valid_identifier(value, "sf_web_inventory_"))
        || !inventory_ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(AssessmentError::InvalidField("inventory_ids"));
    }
    routes.sort_by(|left, right| {
        (&left.route, left.method, &left.route_key).cmp(&(
            &right.route,
            right.method,
            &right.route_key,
        ))
    });
    if routes.len() > 2_000_000 {
        return Err(AssessmentError::InvalidField("routes"));
    }
    if !routes.windows(2).all(|pair| {
        (&pair[0].route, pair[0].method, &pair[0].route_key)
            < (&pair[1].route, pair[1].method, &pair[1].route_key)
    }) {
        return Err(AssessmentError::InvalidField("duplicate routes"));
    }
    let mut observations = Vec::new();
    let mut abstentions = 0;
    for route in &routes {
        validate_coverage_route(route)?;
        if route.implemented && !route.documented {
            observations.push(observation(
                route,
                "SFWEB001",
                ObservationClass::Hardening,
                "Implemented API is absent from declared documentation",
                "Every implemented API should have an explicit documentation disposition; obscurity is not an access control.",
                vec!["Undocumented status alone does not prove exposure or impact".into()],
            ));
        }
        if route.observed && !route.implemented {
            observations.push(observation(
                route,
                "SFWEB002",
                ObservationClass::Candidate,
                "Authorized traffic contains an API absent from the implementation inventory",
                "Every observed API should map to a current implementation or an explicitly retained external component.",
                vec!["The traffic may refer to an older deployment or upstream proxy".into()],
            ));
        }
        apply_required_control(
            route,
            route.expected.authentication_required,
            route.observed_controls.authentication,
            RequiredControlRule {
                rule_id: "SFWEB003",
                title: "Required authentication does not dominate the route",
                invariant: "Every path to an authenticated endpoint must pass through trusted authentication before the handler or sensitive error response.",
            },
            &mut observations,
            &mut abstentions,
        );
        apply_required_control(
            route,
            route.expected.authorization_required,
            route.observed_controls.authorization,
            RequiredControlRule {
                rule_id: "SFWEB004",
                title: "Required authorization does not dominate the route",
                invariant: "Every path to a privileged operation must pass through role and object authorization before the sensitive sink.",
            },
            &mut observations,
            &mut abstentions,
        );
        apply_required_control(
            route,
            route.expected.owner_scope_required,
            route.observed_controls.owner_scope,
            RequiredControlRule {
                rule_id: "SFWEB005",
                title: "Required owner scope is absent or inconsistent",
                invariant: "Object reads and mutations must constrain owner scope at the query or mutation boundary.",
            },
            &mut observations,
            &mut abstentions,
        );
        apply_required_control(
            route,
            route.expected.tenant_scope_required,
            route.observed_controls.tenant_scope,
            RequiredControlRule {
                rule_id: "SFWEB006",
                title: "Required tenant scope is absent or inconsistent",
                invariant: "Object reads and mutations must constrain tenant scope at the query or mutation boundary.",
            },
            &mut observations,
            &mut abstentions,
        );
        apply_required_control(
            route,
            route.expected.restricted_cors_required,
            route.observed_controls.restricted_cors,
            RequiredControlRule {
                rule_id: "SFWEB007",
                title: "Required CORS restriction is absent or inconsistent",
                invariant: "Browser-readable authenticated APIs must restrict origins and credential behavior to the authorized policy.",
            },
            &mut observations,
            &mut abstentions,
        );
        apply_required_control(
            route,
            route.expected.private_cache_required,
            route.observed_controls.private_cache,
            RequiredControlRule {
                rule_id: "SFWEB008",
                title: "Private response cache policy is absent or inconsistent",
                invariant: "Responses containing non-public data must not be reusable by shared caches.",
            },
            &mut observations,
            &mut abstentions,
        );
        apply_required_control(
            route,
            route.expected.sanitized_errors_required,
            route.observed_controls.sanitized_errors,
            RequiredControlRule {
                rule_id: "SFWEB009",
                title: "Error sanitization is absent or inconsistent",
                invariant: "Client responses must not expose stack traces, internal paths, queries or secret-bearing provider errors.",
            },
            &mut observations,
            &mut abstentions,
        );

        let allowed = route
            .allowed_response_fields
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let excessive = route
            .observed_response_fields
            .iter()
            .filter(|field| !allowed.contains(field.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if route.response_allowlist_declared && !excessive.is_empty() {
            observations.push(observation(
                route,
                "SFWEB010",
                ObservationClass::Candidate,
                "Response contains fields outside the declared allowlist",
                "API responses should expose only fields required by their declared consumer contract.",
                vec![format!("Fields requiring human sensitivity review: {}", excessive.join(", "))],
            ));
        }
    }
    observations.sort_by(|left, right| {
        (&left.route, left.method, &left.rule_id, &left.route_key).cmp(&(
            &right.route,
            right.method,
            &right.rule_id,
            &right.route_key,
        ))
    });
    for observation in &mut observations {
        observation.observation_id = expected_observation_id(observation);
    }
    let summary = summarize(&observations, abstentions);
    let mut assessment = WebAssessment {
        contract_version: ASSESSMENT_VERSION.into(),
        assessment_id: String::new(),
        parent_assessment_id: None,
        created_at: created_at.unwrap_or(OffsetDateTime::now_utc().format(&Rfc3339)?),
        scope_id,
        inventory_ids,
        observations,
        summary,
        semantics: AssessmentSemantics {
            automated_validation_authority: false,
            validation_authority: "human-only".into(),
            obscurity_is_a_control: false,
            no_observations_mean_safe: false,
            network_used: false,
        },
    };
    assessment.assessment_id = expected_assessment_id(&assessment);
    assessment.validate()?;
    Ok(assessment)
}

pub fn record_human_validation(
    assessment: &WebAssessment,
    observation_id: &str,
    validation: HumanValidation,
    reproduction: EvidenceReference,
    recorded_at: String,
) -> Result<WebAssessment, AssessmentError> {
    assessment.validate()?;
    let recorded_timestamp = OffsetDateTime::parse(&recorded_at, &Rfc3339)
        .map_err(|_| AssessmentError::InvalidField("recorded_at"))?;
    let reviewed_timestamp = OffsetDateTime::parse(&validation.reviewed_at, &Rfc3339)
        .map_err(|_| AssessmentError::InvalidField("human_validation.reviewed_at"))?;
    let previous_timestamp = OffsetDateTime::parse(&assessment.created_at, &Rfc3339)
        .map_err(|_| AssessmentError::InvalidField("created_at"))?;
    if reproduction.kind != AssessmentEvidenceKind::HumanReproduction
        || reproduction.reference != validation.evidence_reference
        || reviewed_timestamp > recorded_timestamp
        || recorded_timestamp < previous_timestamp
    {
        return Err(AssessmentError::InvalidField("human validation evidence"));
    }
    let mut derived = assessment.clone();
    let observation = derived
        .observations
        .iter_mut()
        .find(|observation| observation.observation_id == observation_id)
        .ok_or_else(|| AssessmentError::ObservationNotFound(observation_id.into()))?;
    if observation.class != ObservationClass::Candidate || observation.human_validation.is_some() {
        return Err(AssessmentError::ObservationNotCandidate(
            observation_id.into(),
        ));
    }
    observation.evidence.push(reproduction);
    observation.evidence.sort();
    observation.evidence.dedup();
    observation.class = ObservationClass::HumanValidatedVulnerability;
    observation.human_validation = Some(validation);
    observation.observation_id = expected_observation_id(observation);

    derived.parent_assessment_id = Some(assessment.assessment_id.clone());
    derived.created_at = recorded_at;
    derived.summary = summarize(&derived.observations, derived.summary.abstentions);
    derived.assessment_id = expected_assessment_id(&derived);
    derived.validate()?;
    Ok(derived)
}

pub fn parse_assessment(bytes: &[u8]) -> Result<WebAssessment, AssessmentError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_ASSESSMENT_BYTES {
        return Err(AssessmentError::InvalidField("document size"));
    }
    let assessment: WebAssessment = serde_json::from_slice(bytes)?;
    assessment.validate()?;
    Ok(assessment)
}

impl WebAssessment {
    pub fn validate(&self) -> Result<(), AssessmentError> {
        if self.contract_version != ASSESSMENT_VERSION
            || !valid_identifier(&self.assessment_id, "sf_web_assessment_")
            || self.assessment_id != expected_assessment_id(self)
            || self.parent_assessment_id.as_deref().is_some_and(|parent| {
                !valid_identifier(parent, "sf_web_assessment_") || parent == self.assessment_id
            })
            || OffsetDateTime::parse(&self.created_at, &Rfc3339).is_err()
            || !valid_identifier(&self.scope_id, "sf_web_scope_")
            || self.inventory_ids.is_empty()
            || self.inventory_ids.len() > 100_000
            || !self
                .inventory_ids
                .iter()
                .all(|value| valid_identifier(value, "sf_web_inventory_"))
            || !self.inventory_ids.windows(2).all(|pair| pair[0] < pair[1])
            || self.semantics.automated_validation_authority
            || self.semantics.validation_authority != "human-only"
            || self.semantics.obscurity_is_a_control
            || self.semantics.no_observations_mean_safe
            || self.semantics.network_used
            || self.observations.len() > 2_000_000
        {
            return Err(AssessmentError::InvalidField("identity or semantics"));
        }
        for observation in &self.observations {
            validate_observation(observation)?;
        }
        if !self.observations.windows(2).all(|pair| {
            (
                &pair[0].route,
                pair[0].method,
                &pair[0].rule_id,
                &pair[0].route_key,
            ) < (
                &pair[1].route,
                pair[1].method,
                &pair[1].rule_id,
                &pair[1].route_key,
            )
        }) {
            return Err(AssessmentError::InvalidField("observation order"));
        }
        if self.summary != summarize(&self.observations, self.summary.abstentions) {
            return Err(AssessmentError::InvalidField("summary"));
        }
        let created_at = OffsetDateTime::parse(&self.created_at, &Rfc3339)
            .map_err(|_| AssessmentError::InvalidField("created_at"))?;
        let human_validations = self
            .observations
            .iter()
            .filter_map(|observation| observation.human_validation.as_ref())
            .collect::<Vec<_>>();
        if self.parent_assessment_id.is_none() != human_validations.is_empty()
            || human_validations.iter().any(|validation| {
                match OffsetDateTime::parse(&validation.reviewed_at, &Rfc3339) {
                    Ok(reviewed_at) => reviewed_at > created_at,
                    Err(_) => true,
                }
            })
        {
            return Err(AssessmentError::InvalidField("assessment lineage"));
        }
        Ok(())
    }
}

struct RequiredControlRule<'a> {
    rule_id: &'a str,
    title: &'a str,
    invariant: &'a str,
}

fn apply_required_control(
    route: &CoverageRoute,
    required: bool,
    state: ControlState,
    rule: RequiredControlRule<'_>,
    observations: &mut Vec<Observation>,
    abstentions: &mut u64,
) {
    if !required {
        return;
    }
    match state {
        ControlState::Missing | ControlState::Inconsistent => observations.push(observation(
            route,
            rule.rule_id,
            ObservationClass::Candidate,
            rule.title,
            rule.invariant,
            vec!["Automated evidence does not by itself establish reproducible impact".into()],
        )),
        ControlState::Unknown => *abstentions += 1,
        ControlState::Present => {}
        ControlState::NotApplicable => *abstentions += 1,
    }
}

fn observation(
    route: &CoverageRoute,
    rule_id: &str,
    class: ObservationClass,
    title: &str,
    invariant: &str,
    limitations: Vec<String>,
) -> Observation {
    Observation {
        observation_id: String::new(),
        rule_id: rule_id.into(),
        class,
        route_key: route.route_key.clone(),
        method: route.method,
        route: route.route.clone(),
        title: title.into(),
        invariant: invariant.into(),
        evidence: route.evidence.clone(),
        limitations,
        human_validation: None,
    }
}

fn validate_coverage_route(route: &CoverageRoute) -> Result<(), AssessmentError> {
    if !valid_text(&route.route_key, 200)
        || route.route_key != format!("{} {}", method_label(route.method), route.route)
        || !valid_route_path(&route.route)
        || route.evidence.is_empty()
        || route.evidence.len() > 100
        || !unique_sorted_text(&route.allowed_response_fields)
        || !unique_sorted_text(&route.observed_response_fields)
        || (!route.observed && !route.observed_response_fields.is_empty())
        || (route.access_intent == AccessIntent::Public
            && (route.expected.authentication_required || route.expected.authorization_required))
        || (matches!(
            route.access_intent,
            AccessIntent::Authenticated | AccessIntent::Privileged
        ) && !route.expected.authentication_required)
        || (route.access_intent == AccessIntent::Privileged
            && !route.expected.authorization_required)
        || ((route.expected.owner_scope_required || route.expected.tenant_scope_required)
            && (!route.expected.authentication_required || !route.expected.authorization_required))
    {
        return Err(AssessmentError::InvalidField("coverage route"));
    }
    validate_evidence(&route.evidence)
}

fn validate_observation(observation: &Observation) -> Result<(), AssessmentError> {
    if !valid_identifier(&observation.observation_id, "sf_web_observation_")
        || observation.observation_id != expected_observation_id(observation)
        || !valid_text(&observation.rule_id, 100)
        || !valid_text(&observation.route_key, 200)
        || !valid_route_path(&observation.route)
        || !valid_text(&observation.title, 300)
        || !valid_text(&observation.invariant, 1_000)
        || observation.evidence.is_empty()
        || observation.limitations.len() > 100
        || !observation
            .limitations
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(AssessmentError::InvalidField("observation"));
    }
    validate_evidence(&observation.evidence)?;
    if observation
        .limitations
        .iter()
        .any(|limitation| !valid_text(limitation, 500))
    {
        return Err(AssessmentError::InvalidField("observation limitation"));
    }
    match (observation.class, &observation.human_validation) {
        (ObservationClass::HumanValidatedVulnerability, Some(validation)) => {
            if !valid_text(&validation.reviewer, 200)
                || OffsetDateTime::parse(&validation.reviewed_at, &Rfc3339).is_err()
                || !valid_text(&validation.rationale, 3_000)
                || !valid_text(&validation.evidence_reference, 300)
                || !observation
                    .evidence
                    .iter()
                    .any(|item| item.kind == AssessmentEvidenceKind::HumanReproduction)
                || !observation
                    .evidence
                    .iter()
                    .any(|item| item.reference == validation.evidence_reference)
            {
                return Err(AssessmentError::InvalidField("human validation"));
            }
        }
        (ObservationClass::HumanValidatedVulnerability, None) => {
            return Err(AssessmentError::InvalidField("human validation"));
        }
        (_, Some(_)) => return Err(AssessmentError::InvalidField("human validation class")),
        (_, None) => {}
    }
    Ok(())
}

fn validate_evidence(evidence: &[EvidenceReference]) -> Result<(), AssessmentError> {
    if evidence.len() > 100 || !evidence.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(AssessmentError::InvalidField("evidence order"));
    }
    for item in evidence {
        if !valid_text(&item.reference, 500)
            || !valid_sha256(&item.sha256)
            || !valid_text(&item.description, 1_000)
        {
            return Err(AssessmentError::InvalidField("evidence"));
        }
    }
    Ok(())
}

fn method_label(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Options => "OPTIONS",
    }
}

fn summarize(observations: &[Observation], abstentions: u64) -> AssessmentSummary {
    AssessmentSummary {
        candidates: observations
            .iter()
            .filter(|item| item.class == ObservationClass::Candidate)
            .count() as u64,
        hardening: observations
            .iter()
            .filter(|item| item.class == ObservationClass::Hardening)
            .count() as u64,
        human_validated_vulnerabilities: observations
            .iter()
            .filter(|item| item.class == ObservationClass::HumanValidatedVulnerability)
            .count() as u64,
        abstentions,
    }
}

fn expected_observation_id(observation: &Observation) -> String {
    let mut stable = observation.clone();
    stable.observation_id.clear();
    format!(
        "sf_web_observation_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("observation serialization"))
    )
}

fn expected_assessment_id(assessment: &WebAssessment) -> String {
    let mut stable = assessment.clone();
    stable.assessment_id.clear();
    stable.created_at.clear();
    format!(
        "sf_web_assessment_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("assessment serialization"))
    )
}

fn valid_identifier(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

fn valid_route_path(value: &str) -> bool {
    value.starts_with('/') && value.len() <= 2_000 && !value.contains("..") && !value.contains('\0')
}

fn unique_sorted_text(values: &[String]) -> bool {
    values.len() <= 10_000
        && values.iter().all(|value| valid_text(value, 300))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Vec<EvidenceReference> {
        vec![EvidenceReference {
            kind: AssessmentEvidenceKind::Code,
            reference: "app/api/users/[id]/route.ts:1".into(),
            sha256: "1".repeat(64),
            description: "route handler and query".into(),
        }]
    }

    fn route() -> CoverageRoute {
        CoverageRoute {
            route_key: "GET /api/users/{id}".into(),
            method: HttpMethod::Get,
            route: "/api/users/{id}".into(),
            implemented: true,
            documented: false,
            observed: true,
            access_intent: AccessIntent::Authenticated,
            expected: ControlExpectation {
                authentication_required: true,
                authorization_required: true,
                owner_scope_required: true,
                tenant_scope_required: true,
                restricted_cors_required: true,
                private_cache_required: true,
                sanitized_errors_required: true,
            },
            observed_controls: ObservedControls {
                authentication: ControlState::Present,
                authorization: ControlState::Inconsistent,
                owner_scope: ControlState::Missing,
                tenant_scope: ControlState::Missing,
                restricted_cors: ControlState::Unknown,
                private_cache: ControlState::Present,
                sanitized_errors: ControlState::Present,
            },
            allowed_response_fields: vec!["id".into()],
            response_allowlist_declared: true,
            observed_response_fields: vec!["email".into(), "id".into()],
            evidence: evidence(),
        }
    }

    #[test]
    fn emits_atomic_candidates_hardening_and_abstention() {
        let mut assessment = assess_routes(
            format!("sf_web_scope_{}", "2".repeat(64)),
            vec![format!("sf_web_inventory_{}", "3".repeat(64))],
            vec![route()],
            Some("2026-08-23T12:00:00Z".into()),
        )
        .expect("assessment");
        assert_eq!(assessment.summary.candidates, 4);
        assert_eq!(assessment.summary.hardening, 1);
        assert_eq!(assessment.summary.abstentions, 1);
        assert!(
            assessment
                .observations
                .iter()
                .all(|item| item.human_validation.is_none())
        );
        let candidate_id = assessment
            .observations
            .iter()
            .find(|item| item.class == ObservationClass::Candidate)
            .expect("candidate")
            .observation_id
            .clone();
        let reviewed = record_human_validation(
            &assessment,
            &candidate_id,
            HumanValidation {
                reviewer: "fixture-reviewer".into(),
                reviewed_at: "2026-08-24T12:00:00Z".into(),
                rationale: "reproduced with synthetic identities and verified the invariant".into(),
                evidence_reference: "reproductions/WEB-001.json".into(),
            },
            EvidenceReference {
                kind: AssessmentEvidenceKind::HumanReproduction,
                reference: "reproductions/WEB-001.json".into(),
                sha256: "4".repeat(64),
                description: "retained synthetic reproduction".into(),
            },
            "2026-08-24T12:00:01Z".into(),
        )
        .expect("human validation");
        assert_eq!(
            reviewed.parent_assessment_id,
            Some(assessment.assessment_id.clone())
        );
        assert_eq!(
            reviewed.summary.candidates,
            assessment.summary.candidates - 1
        );
        assert_eq!(reviewed.summary.human_validated_vulnerabilities, 1);
        assessment.summary.candidates += 1;
        assessment.assessment_id = expected_assessment_id(&assessment);
        assert!(matches!(
            assessment.validate(),
            Err(AssessmentError::InvalidField("summary"))
        ));
    }
}
