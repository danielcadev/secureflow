use crate::inventory::HttpMethod;
use crate::scope::{WebScheme, sha256_hex, valid_sha256, valid_text};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const OBSERVATION_PILOT_VERSION: &str = "secureflow-web-observation-pilot-v1";
pub const MAX_OBSERVATION_PILOT_BYTES: u64 = 1024 * 1024;
const BOUNDED_TRANSPORT_COMPILED: bool = false;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PilotDraft {
    pub authorization: ObservationAuthorization,
    pub target: PilotTarget,
    pub policy: ObservationPolicy,
    pub prerequisites: PilotPrerequisites,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebObservationPilot {
    pub contract_version: String,
    pub pilot_id: String,
    pub created_at: String,
    pub authorization: ObservationAuthorization,
    pub target: PilotTarget,
    pub policy: ObservationPolicy,
    pub prerequisites: PilotPrerequisites,
    pub readiness: PilotReadiness,
    pub blockers: Vec<PilotBlocker>,
    pub claims: PilotClaims,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationAuthorization {
    pub reference: String,
    pub owner_assertion: String,
    pub assertion_sha256: String,
    pub evidence_kind: AuthorizationEvidenceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership_evidence_sha256: Option<String>,
    pub reviewer: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationEvidenceKind {
    OwnerAssertion,
    VerifiedOwnershipArtifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PilotTarget {
    pub apex_host: String,
    pub include_subdomains: bool,
    pub scheme: WebScheme,
    pub port: u16,
    pub redirect_policy: RedirectPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedirectPolicy {
    SameHostOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationPolicy {
    pub allowed_methods: Vec<HttpMethod>,
    pub allowed_paths: Vec<String>,
    pub max_requests: u16,
    pub requests_per_minute: u16,
    pub max_concurrency: u8,
    pub max_redirects: u8,
    pub timeout_milliseconds: u32,
    pub max_response_bytes: u64,
    pub max_total_response_bytes: u64,
    pub stop_after_consecutive_5xx: u8,
    pub dns_revalidate_before_every_request: bool,
    pub redirect_revalidate_before_every_hop: bool,
    pub retain_response_body: bool,
    pub send_credentials: bool,
    pub use_proxy: bool,
    pub authentication_comparisons_enabled: bool,
    pub allowed_response_headers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PilotPrerequisites {
    pub authorization_record_bound: bool,
    pub ownership_evidence_verified: bool,
    pub bounded_transport_implemented: bool,
    pub dns_revalidation_tested: bool,
    pub redirect_revalidation_tested: bool,
    pub redaction_tested: bool,
    pub staging_completed: bool,
    pub dedicated_test_accounts_available: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PilotReadiness {
    Blocked,
    Ready,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PilotBlocker {
    AuthorizationRecordMissing,
    OwnershipEvidenceUnverified,
    BoundedTransportMissing,
    DnsRevalidationUntested,
    RedirectRevalidationUntested,
    RedactionUntested,
    StagingNotCompleted,
    DedicatedTestAccountsMissing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PilotClaims {
    pub authorization_acknowledged: bool,
    pub network_executed: bool,
    pub production_execution_allowed: bool,
    pub vulnerability_validation_allowed: bool,
    pub production_safety_claim_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardedObservationRequest {
    pub method: HttpMethod,
    pub scheme: WebScheme,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub redirect_hop: u8,
    pub resolved_addresses: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSession {
    pub pilot_id: String,
    pub requests_started: u16,
    pub requests_completed: u16,
    pub total_response_bytes: u64,
    pub consecutive_5xx: u8,
    pub request_timestamps_unix: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped: Option<PilotStopReason>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PilotStopReason {
    RateLimited,
    RepeatedServerErrors,
    ScopeDrift,
    UnexpectedBehavior,
    ResponseLimitExceeded,
    RequestBudgetExhausted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEvidence {
    pub status: u16,
    pub headers: Vec<ObservationHeader>,
    pub body_sha256: String,
    pub body_bytes: u64,
    pub body_retained: bool,
    pub secrets_retained: bool,
    pub pii_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Error)]
pub enum PilotError {
    #[error("invalid observation pilot field: {0}")]
    InvalidField(&'static str),
    #[error("observation pilot is blocked by unmet prerequisites")]
    PilotBlocked,
    #[error("observation session has stopped: {0:?}")]
    SessionStopped(PilotStopReason),
    #[error("request method is outside the read-only policy")]
    MethodNotAllowed,
    #[error("request target or redirect is outside the exact allowlist")]
    ScopeDrift,
    #[error("DNS revalidation returned no usable public address")]
    DnsRevalidationFailed,
    #[error("request budget or rate limit is exhausted")]
    RequestBudgetExhausted,
    #[error("invalid observation pilot JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not format observation pilot timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
}

pub fn mitiquete_pilot_draft(
    authorization_reference: &str,
    issued_at: &str,
    expires_at: &str,
) -> Result<PilotDraft, PilotError> {
    let owner_assertion = "The requesting user states that they own and authorize bounded security observation of https://mitiqueteonline.com for the SecureFlow Web pilot.";
    let draft = PilotDraft {
        authorization: ObservationAuthorization {
            reference: authorization_reference.into(),
            owner_assertion: owner_assertion.into(),
            assertion_sha256: sha256_hex(owner_assertion.as_bytes()),
            evidence_kind: AuthorizationEvidenceKind::OwnerAssertion,
            ownership_evidence_sha256: None,
            reviewer: "pending-independent-ownership-review".into(),
            issued_at: issued_at.into(),
            expires_at: expires_at.into(),
        },
        target: PilotTarget {
            apex_host: "mitiqueteonline.com".into(),
            include_subdomains: false,
            scheme: WebScheme::Https,
            port: 443,
            redirect_policy: RedirectPolicy::SameHostOnly,
        },
        policy: ObservationPolicy {
            allowed_methods: vec![HttpMethod::Get, HttpMethod::Head, HttpMethod::Options],
            allowed_paths: vec![
                "/".into(),
                "/.well-known/security.txt".into(),
                "/robots.txt".into(),
                "/sitemap.xml".into(),
            ],
            max_requests: 12,
            requests_per_minute: 3,
            max_concurrency: 1,
            max_redirects: 2,
            timeout_milliseconds: 5_000,
            max_response_bytes: 1024 * 1024,
            max_total_response_bytes: 4 * 1024 * 1024,
            stop_after_consecutive_5xx: 2,
            dns_revalidate_before_every_request: true,
            redirect_revalidate_before_every_hop: true,
            retain_response_body: false,
            send_credentials: false,
            use_proxy: false,
            authentication_comparisons_enabled: false,
            allowed_response_headers: vec![
                "access-control-allow-origin".into(),
                "cache-control".into(),
                "content-length".into(),
                "content-type".into(),
                "location".into(),
                "vary".into(),
            ],
        },
        prerequisites: PilotPrerequisites {
            authorization_record_bound: true,
            ownership_evidence_verified: false,
            bounded_transport_implemented: false,
            dns_revalidation_tested: true,
            redirect_revalidation_tested: true,
            redaction_tested: true,
            staging_completed: false,
            dedicated_test_accounts_available: false,
        },
    };
    validate_draft(&draft)?;
    Ok(draft)
}

pub fn seal_observation_pilot(
    draft_bytes: &[u8],
    created_at: Option<String>,
) -> Result<WebObservationPilot, PilotError> {
    if draft_bytes.is_empty() || draft_bytes.len() as u64 > MAX_OBSERVATION_PILOT_BYTES {
        return Err(PilotError::InvalidField("draft document size"));
    }
    let draft: PilotDraft = serde_json::from_slice(draft_bytes)?;
    validate_draft(&draft)?;
    let blockers = blockers_for(&draft.prerequisites, &draft.policy);
    let readiness = if blockers.is_empty() {
        PilotReadiness::Ready
    } else {
        PilotReadiness::Blocked
    };
    let mut pilot = WebObservationPilot {
        contract_version: OBSERVATION_PILOT_VERSION.into(),
        pilot_id: String::new(),
        created_at: created_at.unwrap_or(OffsetDateTime::now_utc().format(&Rfc3339)?),
        authorization: draft.authorization,
        target: draft.target,
        policy: draft.policy,
        prerequisites: draft.prerequisites,
        readiness,
        blockers,
        claims: PilotClaims {
            authorization_acknowledged: true,
            network_executed: false,
            production_execution_allowed: readiness == PilotReadiness::Ready,
            vulnerability_validation_allowed: false,
            production_safety_claim_allowed: false,
        },
    };
    pilot.pilot_id = expected_pilot_id(&pilot);
    pilot.validate()?;
    Ok(pilot)
}

pub fn parse_observation_pilot(
    bytes: &[u8],
    now: OffsetDateTime,
) -> Result<WebObservationPilot, PilotError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_OBSERVATION_PILOT_BYTES {
        return Err(PilotError::InvalidField("document size"));
    }
    let pilot: WebObservationPilot = serde_json::from_slice(bytes)?;
    pilot.validate()?;
    validate_authorization_window(&pilot.authorization, now)?;
    Ok(pilot)
}

pub fn authorize_observation_request(
    pilot: &WebObservationPilot,
    session: &mut ObservationSession,
    request: &GuardedObservationRequest,
    now_unix: i64,
) -> Result<(), PilotError> {
    pilot.validate()?;
    validate_session_identity(pilot, session)?;
    let now = OffsetDateTime::from_unix_timestamp(now_unix)
        .map_err(|_| PilotError::InvalidField("request timestamp"))?;
    validate_authorization_window(&pilot.authorization, now)?;
    if pilot.readiness != PilotReadiness::Ready || !pilot.claims.production_execution_allowed {
        return Err(PilotError::PilotBlocked);
    }
    validate_request_constraints(pilot, session, request, now_unix)
}

fn validate_request_constraints(
    pilot: &WebObservationPilot,
    session: &mut ObservationSession,
    request: &GuardedObservationRequest,
    now_unix: i64,
) -> Result<(), PilotError> {
    if let Some(reason) = session.stopped {
        return Err(PilotError::SessionStopped(reason));
    }
    if !pilot.policy.allowed_methods.contains(&request.method) {
        session.stopped = Some(PilotStopReason::ScopeDrift);
        return Err(PilotError::MethodNotAllowed);
    }
    if request.host != pilot.target.apex_host
        || request.scheme != pilot.target.scheme
        || request.port != pilot.target.port
        || request.redirect_hop > pilot.policy.max_redirects
        || !pilot.policy.allowed_paths.contains(&request.path)
        || !valid_observation_path(&request.path)
    {
        session.stopped = Some(PilotStopReason::ScopeDrift);
        return Err(PilotError::ScopeDrift);
    }
    if request.resolved_addresses.is_empty()
        || request
            .resolved_addresses
            .iter()
            .any(|address| address.parse::<IpAddr>().is_err() || !is_public_address(address))
    {
        session.stopped = Some(PilotStopReason::ScopeDrift);
        return Err(PilotError::DnsRevalidationFailed);
    }
    let in_last_minute = session
        .request_timestamps_unix
        .iter()
        .filter(|timestamp| now_unix.saturating_sub(**timestamp) < 60)
        .count();
    if session.requests_started >= pilot.policy.max_requests
        || in_last_minute >= usize::from(pilot.policy.requests_per_minute)
        || session
            .requests_started
            .saturating_sub(session.requests_completed)
            >= u16::from(pilot.policy.max_concurrency)
    {
        if session.requests_started >= pilot.policy.max_requests {
            session.stopped = Some(PilotStopReason::RequestBudgetExhausted);
        }
        return Err(PilotError::RequestBudgetExhausted);
    }
    if session
        .request_timestamps_unix
        .last()
        .is_some_and(|last| now_unix < *last)
    {
        return Err(PilotError::InvalidField("non-monotonic request time"));
    }
    session.requests_started = session.requests_started.saturating_add(1);
    session.request_timestamps_unix.push(now_unix);
    Ok(())
}

pub fn record_observation_result(
    pilot: &WebObservationPilot,
    session: &mut ObservationSession,
    status: u16,
    response_bytes: u64,
    unexpected_behavior: bool,
) -> Result<(), PilotError> {
    pilot.validate()?;
    validate_session_identity(pilot, session)?;
    if session.requests_completed >= session.requests_started || !(100..=599).contains(&status) {
        return Err(PilotError::InvalidField("observation result"));
    }
    session.requests_completed = session.requests_completed.saturating_add(1);
    session.total_response_bytes = session
        .total_response_bytes
        .checked_add(response_bytes)
        .ok_or(PilotError::InvalidField("response byte count"))?;
    if response_bytes > pilot.policy.max_response_bytes
        || session.total_response_bytes > pilot.policy.max_total_response_bytes
    {
        session.stopped = Some(PilotStopReason::ResponseLimitExceeded);
    } else if status == 429 {
        session.stopped = Some(PilotStopReason::RateLimited);
    } else if unexpected_behavior {
        session.stopped = Some(PilotStopReason::UnexpectedBehavior);
    } else if (500..=599).contains(&status) {
        session.consecutive_5xx = session.consecutive_5xx.saturating_add(1);
        if session.consecutive_5xx >= pilot.policy.stop_after_consecutive_5xx {
            session.stopped = Some(PilotStopReason::RepeatedServerErrors);
        }
    } else {
        session.consecutive_5xx = 0;
    }
    Ok(())
}

pub fn sanitize_response_metadata(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    allowed_headers: &[String],
) -> Result<ObservationEvidence, PilotError> {
    if !(100..=599).contains(&status) || body.len() as u64 > 16 * 1024 * 1024 {
        return Err(PilotError::InvalidField("response metadata"));
    }
    let allowed = allowed_headers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut retained = Vec::new();
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        if !allowed.contains(&name) || matches!(name.as_str(), "set-cookie" | "authorization") {
            continue;
        }
        let value = if name == "location" {
            sanitize_location(value)
        } else {
            sanitize_header_value(value)
        };
        retained.push(ObservationHeader { name, value });
    }
    retained.sort();
    retained.dedup();
    Ok(ObservationEvidence {
        status,
        headers: retained,
        body_sha256: sha256_hex(body),
        body_bytes: body.len() as u64,
        body_retained: false,
        secrets_retained: false,
        pii_retained: false,
    })
}

impl ObservationSession {
    pub fn new(pilot: &WebObservationPilot) -> Result<Self, PilotError> {
        pilot.validate()?;
        Ok(Self {
            pilot_id: pilot.pilot_id.clone(),
            requests_started: 0,
            requests_completed: 0,
            total_response_bytes: 0,
            consecutive_5xx: 0,
            request_timestamps_unix: Vec::new(),
            stopped: None,
        })
    }
}

impl WebObservationPilot {
    pub fn validate(&self) -> Result<(), PilotError> {
        let draft = PilotDraft {
            authorization: self.authorization.clone(),
            target: self.target.clone(),
            policy: self.policy.clone(),
            prerequisites: self.prerequisites.clone(),
        };
        validate_draft(&draft)?;
        let created_at = OffsetDateTime::parse(&self.created_at, &Rfc3339)
            .map_err(|_| PilotError::InvalidField("pilot creation time"))?;
        validate_authorization_window(&self.authorization, created_at)?;
        let blockers = blockers_for(&self.prerequisites, &self.policy);
        let readiness = if blockers.is_empty() {
            PilotReadiness::Ready
        } else {
            PilotReadiness::Blocked
        };
        if self.contract_version != OBSERVATION_PILOT_VERSION
            || !valid_prefixed_hash(&self.pilot_id, "sf_web_pilot_")
            || self.pilot_id != expected_pilot_id(self)
            || self.blockers != blockers
            || self.readiness != readiness
            || !self.claims.authorization_acknowledged
            || self.claims.network_executed
            || self.claims.production_execution_allowed != (readiness == PilotReadiness::Ready)
            || self.claims.vulnerability_validation_allowed
            || self.claims.production_safety_claim_allowed
        {
            return Err(PilotError::InvalidField("pilot"));
        }
        Ok(())
    }
}

fn validate_draft(draft: &PilotDraft) -> Result<(), PilotError> {
    let authorization = &draft.authorization;
    let issued_at = OffsetDateTime::parse(&authorization.issued_at, &Rfc3339)
        .map_err(|_| PilotError::InvalidField("authorization issued_at"))?;
    let expires_at = OffsetDateTime::parse(&authorization.expires_at, &Rfc3339)
        .map_err(|_| PilotError::InvalidField("authorization expires_at"))?;
    let ownership_evidence_is_consistent = match authorization.evidence_kind {
        AuthorizationEvidenceKind::OwnerAssertion => {
            authorization.ownership_evidence_sha256.is_none()
                && !draft.prerequisites.ownership_evidence_verified
        }
        AuthorizationEvidenceKind::VerifiedOwnershipArtifact => {
            authorization
                .ownership_evidence_sha256
                .as_deref()
                .is_some_and(valid_sha256)
                && draft.prerequisites.ownership_evidence_verified
                && authorization.reviewer != "pending-independent-ownership-review"
        }
    };
    if !valid_text(&authorization.reference, 500)
        || !valid_text(&authorization.owner_assertion, 1_000)
        || authorization.assertion_sha256 != sha256_hex(authorization.owner_assertion.as_bytes())
        || authorization
            .ownership_evidence_sha256
            .as_deref()
            .is_some_and(|value| !valid_sha256(value))
        || !valid_text(&authorization.reviewer, 300)
        || !ownership_evidence_is_consistent
        || expires_at <= issued_at
        || draft.prerequisites.bounded_transport_implemented != BOUNDED_TRANSPORT_COMPILED
        || !valid_host(&draft.target.apex_host)
        || draft.target.include_subdomains
        || draft.target.scheme != WebScheme::Https
        || draft.target.port != 443
    {
        return Err(PilotError::InvalidField("authorization or target"));
    }
    validate_policy(&draft.policy)?;
    Ok(())
}

fn validate_authorization_window(
    authorization: &ObservationAuthorization,
    now: OffsetDateTime,
) -> Result<(), PilotError> {
    let issued_at = OffsetDateTime::parse(&authorization.issued_at, &Rfc3339)
        .map_err(|_| PilotError::InvalidField("authorization issued_at"))?;
    let expires_at = OffsetDateTime::parse(&authorization.expires_at, &Rfc3339)
        .map_err(|_| PilotError::InvalidField("authorization expires_at"))?;
    if now < issued_at {
        return Err(PilotError::InvalidField("authorization not yet valid"));
    }
    if now >= expires_at {
        return Err(PilotError::InvalidField("expired authorization"));
    }
    Ok(())
}

fn validate_policy(policy: &ObservationPolicy) -> Result<(), PilotError> {
    let expected_methods = [HttpMethod::Get, HttpMethod::Head, HttpMethod::Options];
    if policy.allowed_methods != expected_methods
        || policy.allowed_paths.is_empty()
        || policy.allowed_paths.len() > 100
        || !policy
            .allowed_paths
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || policy
            .allowed_paths
            .iter()
            .any(|path| !valid_observation_path(path))
        || policy.max_requests == 0
        || policy.max_requests > 20
        || policy.requests_per_minute == 0
        || policy.requests_per_minute > 5
        || policy.max_concurrency != 1
        || policy.max_redirects > 3
        || !(1_000..=10_000).contains(&policy.timeout_milliseconds)
        || policy.max_response_bytes == 0
        || policy.max_response_bytes > 2 * 1024 * 1024
        || policy.max_total_response_bytes < policy.max_response_bytes
        || policy.max_total_response_bytes > 8 * 1024 * 1024
        || !(1..=3).contains(&policy.stop_after_consecutive_5xx)
        || !policy.dns_revalidate_before_every_request
        || !policy.redirect_revalidate_before_every_hop
        || policy.retain_response_body
        || policy.send_credentials
        || policy.use_proxy
        || policy.allowed_response_headers.len() > 20
        || !policy
            .allowed_response_headers
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || policy.allowed_response_headers.iter().any(|name| {
            !valid_header_name(name)
                || matches!(
                    name.as_str(),
                    "set-cookie" | "authorization" | "proxy-authenticate"
                )
        })
    {
        return Err(PilotError::InvalidField("observation policy"));
    }
    Ok(())
}

fn blockers_for(
    prerequisites: &PilotPrerequisites,
    policy: &ObservationPolicy,
) -> Vec<PilotBlocker> {
    let mut blockers = Vec::new();
    if !prerequisites.authorization_record_bound {
        blockers.push(PilotBlocker::AuthorizationRecordMissing);
    }
    if !prerequisites.ownership_evidence_verified {
        blockers.push(PilotBlocker::OwnershipEvidenceUnverified);
    }
    if !prerequisites.bounded_transport_implemented || !BOUNDED_TRANSPORT_COMPILED {
        blockers.push(PilotBlocker::BoundedTransportMissing);
    }
    if !prerequisites.dns_revalidation_tested {
        blockers.push(PilotBlocker::DnsRevalidationUntested);
    }
    if !prerequisites.redirect_revalidation_tested {
        blockers.push(PilotBlocker::RedirectRevalidationUntested);
    }
    if !prerequisites.redaction_tested {
        blockers.push(PilotBlocker::RedactionUntested);
    }
    if !prerequisites.staging_completed {
        blockers.push(PilotBlocker::StagingNotCompleted);
    }
    if policy.authentication_comparisons_enabled && !prerequisites.dedicated_test_accounts_available
    {
        blockers.push(PilotBlocker::DedicatedTestAccountsMissing);
    }
    blockers.sort();
    blockers
}

fn validate_session_identity(
    pilot: &WebObservationPilot,
    session: &ObservationSession,
) -> Result<(), PilotError> {
    if session.pilot_id != pilot.pilot_id
        || session.requests_completed > session.requests_started
        || session.requests_started as usize != session.request_timestamps_unix.len()
    {
        return Err(PilotError::InvalidField("observation session"));
    }
    Ok(())
}

fn is_public_address(value: &str) -> bool {
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => is_public_v4(address),
        Ok(IpAddr::V6(address)) => is_public_v6(address),
        Err(_) => false,
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_unspecified()
        || octets[0] == 0
        || octets[0] >= 224
        || octets[0] == 100 && (64..=127).contains(&octets[1])
        || octets[0] == 192 && octets[1] == 0
        || octets[0] == 192 && octets[1] == 88 && octets[2] == 99
        || octets[0] == 198 && (18..=19).contains(&octets[1])
        || octets[0] == 198 && octets[1] == 51 && octets[2] == 100
        || octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let segments = address.segments();
    (segments[0] & 0xe000) == 0x2000
        && !(address.is_loopback()
            || address.is_unspecified()
            || address.is_multicast()
            || (segments[0] & 0xfe00) == 0xfc00
            || (segments[0] & 0xffc0) == 0xfe80
            || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

fn sanitize_header_value(value: &str) -> String {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 500
        || value.contains(['\r', '\n', '\0', '@'])
        || ["token", "secret", "password", "session", "bearer", "cookie"]
            .iter()
            .any(|keyword| lower.contains(keyword))
    {
        "<redacted>".into()
    } else {
        value.into()
    }
}

fn sanitize_location(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || value.len() > 2_000 || value.contains(['\r', '\n', '\0']) {
        return "<redacted-location>".into();
    }
    format!("sha256:{}", sha256_hex(value.as_bytes()))
}

fn valid_observation_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && path.len() <= 2_000
        && !path.contains(['?', '#', '\\', '\0'])
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host == host.to_ascii_lowercase()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
}

fn expected_pilot_id(pilot: &WebObservationPilot) -> String {
    let mut stable = pilot.clone();
    stable.pilot_id.clear();
    format!(
        "sf_web_pilot_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("pilot serialization"))
    )
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUED: &str = "2026-08-24T12:00:00Z";
    const EXPIRES: &str = "2026-09-24T12:00:00Z";

    fn guard_fixture_pilot() -> WebObservationPilot {
        let mut draft = mitiquete_pilot_draft("TEST-AUTH", ISSUED, EXPIRES).expect("draft");
        draft.authorization.evidence_kind = AuthorizationEvidenceKind::VerifiedOwnershipArtifact;
        draft.authorization.ownership_evidence_sha256 = Some("a".repeat(64));
        draft.authorization.reviewer = "fixture-independent-reviewer".into();
        draft.prerequisites.ownership_evidence_verified = true;
        draft.prerequisites.staging_completed = true;
        seal_observation_pilot(
            &serde_json::to_vec(&draft).expect("draft JSON"),
            Some(ISSUED.into()),
        )
        .expect("guard fixture pilot")
    }

    fn request() -> GuardedObservationRequest {
        GuardedObservationRequest {
            method: HttpMethod::Get,
            scheme: WebScheme::Https,
            host: "mitiqueteonline.com".into(),
            port: 443,
            path: "/".into(),
            redirect_hop: 0,
            resolved_addresses: vec!["8.8.8.8".into()],
        }
    }

    #[test]
    fn mitiquete_plan_is_blocked_before_transport_ownership_and_staging() {
        let draft = mitiquete_pilot_draft("OWNER-ASSERTION", ISSUED, EXPIRES).expect("draft");
        let pilot = seal_observation_pilot(
            &serde_json::to_vec(&draft).expect("draft JSON"),
            Some(ISSUED.into()),
        )
        .expect("pilot");
        assert_eq!(pilot.readiness, PilotReadiness::Blocked);
        assert_eq!(
            pilot.blockers,
            vec![
                PilotBlocker::OwnershipEvidenceUnverified,
                PilotBlocker::BoundedTransportMissing,
                PilotBlocker::StagingNotCompleted,
            ]
        );
        assert!(!pilot.claims.production_execution_allowed);
        let mut session = ObservationSession::new(&pilot).expect("session");
        assert!(matches!(
            authorize_observation_request(
                &pilot,
                &mut session,
                &request(),
                OffsetDateTime::parse(ISSUED, &Rfc3339)
                    .expect("issued time")
                    .unix_timestamp(),
            ),
            Err(PilotError::PilotBlocked)
        ));
    }

    #[test]
    fn authorization_window_rejects_future_and_expired_use() {
        let draft = mitiquete_pilot_draft("OWNER-ASSERTION", ISSUED, EXPIRES).expect("draft");
        let pilot = seal_observation_pilot(
            &serde_json::to_vec(&draft).expect("draft JSON"),
            Some(ISSUED.into()),
        )
        .expect("pilot");
        let bytes = serde_json::to_vec(&pilot).expect("pilot JSON");
        let before_issue =
            OffsetDateTime::parse("2026-08-24T11:59:59Z", &Rfc3339).expect("before issue time");
        let at_expiry = OffsetDateTime::parse(EXPIRES, &Rfc3339).expect("expiry time");
        assert!(matches!(
            parse_observation_pilot(&bytes, before_issue),
            Err(PilotError::InvalidField("authorization not yet valid"))
        ));
        assert!(matches!(
            parse_observation_pilot(&bytes, at_expiry),
            Err(PilotError::InvalidField("expired authorization"))
        ));

        let mut session = ObservationSession::new(&pilot).expect("session");
        assert!(matches!(
            authorize_observation_request(
                &pilot,
                &mut session,
                &request(),
                before_issue.unix_timestamp(),
            ),
            Err(PilotError::InvalidField("authorization not yet valid"))
        ));
    }

    #[test]
    fn ownership_readiness_requires_bound_verified_evidence() {
        let mut draft = mitiquete_pilot_draft("OWNER-ASSERTION", ISSUED, EXPIRES).expect("draft");
        draft.prerequisites.ownership_evidence_verified = true;
        assert!(matches!(
            seal_observation_pilot(
                &serde_json::to_vec(&draft).expect("draft JSON"),
                Some(ISSUED.into()),
            ),
            Err(PilotError::InvalidField("authorization or target"))
        ));

        draft.authorization.evidence_kind = AuthorizationEvidenceKind::VerifiedOwnershipArtifact;
        draft.authorization.ownership_evidence_sha256 = Some("a".repeat(64));
        assert!(matches!(
            seal_observation_pilot(
                &serde_json::to_vec(&draft).expect("draft JSON"),
                Some(ISSUED.into()),
            ),
            Err(PilotError::InvalidField("authorization or target"))
        ));

        draft.authorization.reviewer = "fixture-independent-reviewer".into();
        assert!(
            seal_observation_pilot(
                &serde_json::to_vec(&draft).expect("draft JSON"),
                Some(ISSUED.into()),
            )
            .is_ok()
        );
    }

    #[test]
    fn guard_rejects_scope_drift_private_dns_and_state_changing_methods() {
        let pilot = guard_fixture_pilot();
        let mut session = ObservationSession::new(&pilot).expect("session");
        let mut unsafe_request = request();
        unsafe_request.method = HttpMethod::Post;
        assert!(matches!(
            validate_request_constraints(&pilot, &mut session, &unsafe_request, 1),
            Err(PilotError::MethodNotAllowed)
        ));
        let mut session = ObservationSession::new(&pilot).expect("host session");
        unsafe_request = request();
        unsafe_request.host = "www.mitiqueteonline.com".into();
        assert!(matches!(
            validate_request_constraints(&pilot, &mut session, &unsafe_request, 2),
            Err(PilotError::ScopeDrift)
        ));

        let mut session = ObservationSession::new(&pilot).expect("second session");
        unsafe_request = request();
        unsafe_request.resolved_addresses = vec!["127.0.0.1".into()];
        assert!(matches!(
            validate_request_constraints(&pilot, &mut session, &unsafe_request, 3),
            Err(PilotError::DnsRevalidationFailed)
        ));
    }

    #[test]
    fn session_stops_on_rate_limit_repeated_errors_and_unexpected_behavior() {
        let pilot = guard_fixture_pilot();
        let mut session = ObservationSession::new(&pilot).expect("session");
        validate_request_constraints(&pilot, &mut session, &request(), 1).expect("request");
        record_observation_result(&pilot, &mut session, 429, 10, false).expect("result");
        assert_eq!(session.stopped, Some(PilotStopReason::RateLimited));

        let mut session = ObservationSession::new(&pilot).expect("5xx session");
        validate_request_constraints(&pilot, &mut session, &request(), 1).expect("request one");
        record_observation_result(&pilot, &mut session, 500, 10, false).expect("500 one");
        validate_request_constraints(&pilot, &mut session, &request(), 22).expect("request two");
        record_observation_result(&pilot, &mut session, 503, 10, false).expect("500 two");
        assert_eq!(session.stopped, Some(PilotStopReason::RepeatedServerErrors));

        let mut session = ObservationSession::new(&pilot).expect("unexpected session");
        validate_request_constraints(&pilot, &mut session, &request(), 1).expect("request");
        record_observation_result(&pilot, &mut session, 200, 10, true).expect("unexpected");
        assert_eq!(session.stopped, Some(PilotStopReason::UnexpectedBehavior));
    }

    #[test]
    fn evidence_retains_only_allowlisted_metadata_and_body_hash() {
        let pilot = guard_fixture_pilot();
        let headers = vec![
            ("Content-Type".into(), "text/html".into()),
            ("Set-Cookie".into(), "session=secret".into()),
            (
                "Location".into(),
                "https://mitiqueteonline.com/login?token=secret#fragment".into(),
            ),
        ];
        let evidence = sanitize_response_metadata(
            302,
            &headers,
            b"person@example.test token=secret",
            &pilot.policy.allowed_response_headers,
        )
        .expect("evidence");
        assert_eq!(evidence.headers.len(), 2);
        assert!(
            evidence
                .headers
                .iter()
                .all(|header| !header.value.contains("secret"))
        );
        assert!(
            evidence
                .headers
                .iter()
                .find(|header| header.name == "location")
                .is_some_and(|header| header.value.starts_with("sha256:"))
        );
        assert!(!evidence.body_retained);
        assert!(!evidence.secrets_retained);
        assert!(!evidence.pii_retained);
        assert!(valid_sha256(&evidence.body_sha256));
    }

    #[test]
    fn dns_guard_rejects_mapped_loopback_and_documentation_ranges() {
        assert!(!is_public_address("::ffff:127.0.0.1"));
        assert!(!is_public_address("192.0.2.1"));
        assert!(!is_public_address("2001:db8::1"));
        assert!(is_public_address("8.8.8.8"));
        assert!(is_public_address("2606:4700:4700::1111"));
    }
}
