use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const SCOPE_VERSION: &str = "secureflow-web-scope-v1";
pub const MAX_SCOPE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebScopeDraft {
    pub authorization: ScopeAuthorization,
    pub repositories: Vec<AuthorizedRepository>,
    #[serde(default)]
    pub assets: Vec<AuthorizedAsset>,
    pub policy: ScopePolicy,
    pub limits: ScopeLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebScope {
    pub contract_version: String,
    pub scope_id: String,
    pub created_at: String,
    #[serde(flatten)]
    pub draft: WebScopeDraft,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeAuthorization {
    pub status: AuthorizationStatus,
    pub reference: String,
    pub reviewer: String,
    pub expires_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationStatus {
    Authorized,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedRepository {
    pub label: String,
    pub root_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedAsset {
    pub kind: TargetKind,
    pub value: String,
    pub include_subdomains: bool,
    pub schemes: Vec<WebScheme>,
    pub ports: Vec<u16>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    DnsName,
    IpAddress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WebScheme {
    Http,
    Https,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicy {
    pub passive_only: bool,
    pub network_execution: NetworkExecution,
    pub follow_redirects: bool,
    pub third_party_scanning: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkExecution {
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeLimits {
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_routes: u64,
    pub max_sources: u64,
    pub max_requests: u64,
    pub requests_per_minute: u64,
    pub max_concurrency: u64,
}

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("invalid web scope field: {0}")]
    InvalidField(&'static str),
    #[error("web scope authorization expired at {0}")]
    AuthorizationExpired(String),
    #[error("invalid web scope JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not format web scope timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
}

pub fn seal_scope(bytes: &[u8], created_at: Option<String>) -> Result<WebScope, ScopeError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_SCOPE_BYTES {
        return Err(ScopeError::InvalidField("document size"));
    }
    let draft: WebScopeDraft = serde_json::from_slice(bytes)?;
    let mut scope = WebScope {
        contract_version: SCOPE_VERSION.into(),
        scope_id: String::new(),
        created_at: created_at.unwrap_or(OffsetDateTime::now_utc().format(&Rfc3339)?),
        draft,
    };
    scope.scope_id = expected_scope_id(&scope);
    scope.validate_structure()?;
    Ok(scope)
}

pub fn parse_scope(bytes: &[u8], now: OffsetDateTime) -> Result<WebScope, ScopeError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_SCOPE_BYTES {
        return Err(ScopeError::InvalidField("document size"));
    }
    let scope: WebScope = serde_json::from_slice(bytes)?;
    scope.validate_at(now)?;
    Ok(scope)
}

impl WebScope {
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), ScopeError> {
        self.validate_structure()?;
        let expiry = OffsetDateTime::parse(&self.draft.authorization.expires_at, &Rfc3339)
            .map_err(|_| ScopeError::InvalidField("authorization.expires_at"))?;
        if expiry <= now {
            return Err(ScopeError::AuthorizationExpired(
                self.draft.authorization.expires_at.clone(),
            ));
        }
        Ok(())
    }

    pub fn authorizes_repository(&self, root_sha256: &str) -> bool {
        self.draft
            .repositories
            .iter()
            .any(|repository| repository.root_sha256 == root_sha256)
    }

    fn validate_structure(&self) -> Result<(), ScopeError> {
        if self.contract_version != SCOPE_VERSION
            || !valid_prefixed_hash(&self.scope_id, "sf_web_scope_")
            || OffsetDateTime::parse(&self.created_at, &Rfc3339).is_err()
            || self.scope_id != expected_scope_id(self)
        {
            return Err(ScopeError::InvalidField("identity"));
        }
        let authorization = &self.draft.authorization;
        let created_at = OffsetDateTime::parse(&self.created_at, &Rfc3339)
            .map_err(|_| ScopeError::InvalidField("created_at"))?;
        let expires_at = OffsetDateTime::parse(&authorization.expires_at, &Rfc3339)
            .map_err(|_| ScopeError::InvalidField("authorization.expires_at"))?;
        if authorization.status != AuthorizationStatus::Authorized
            || !valid_text(&authorization.reference, 300)
            || !valid_text(&authorization.reviewer, 200)
            || expires_at <= created_at
        {
            return Err(ScopeError::InvalidField("authorization"));
        }
        validate_repositories(&self.draft.repositories)?;
        validate_assets(&self.draft.assets)?;
        let policy = &self.draft.policy;
        if !policy.passive_only
            || policy.network_execution != NetworkExecution::Disabled
            || policy.follow_redirects
            || policy.third_party_scanning
        {
            return Err(ScopeError::InvalidField("policy"));
        }
        let limits = &self.draft.limits;
        if !(1..=1_000_000).contains(&limits.max_files)
            || !(1..=64 * 1024 * 1024).contains(&limits.max_file_bytes)
            || limits.max_total_bytes < limits.max_file_bytes
            || limits.max_total_bytes > 16 * 1024 * 1024 * 1024
            || !(1..=2_000_000).contains(&limits.max_routes)
            || !(1..=100_000).contains(&limits.max_sources)
            || limits.max_requests != 0
            || limits.requests_per_minute != 0
            || limits.max_concurrency != 0
        {
            return Err(ScopeError::InvalidField("limits"));
        }
        Ok(())
    }
}

fn validate_repositories(repositories: &[AuthorizedRepository]) -> Result<(), ScopeError> {
    if repositories.is_empty() || repositories.len() > 1_000 {
        return Err(ScopeError::InvalidField("repositories"));
    }
    let mut previous: Option<&AuthorizedRepository> = None;
    for repository in repositories {
        if !valid_text(&repository.label, 200) || !valid_sha256(&repository.root_sha256) {
            return Err(ScopeError::InvalidField("repositories"));
        }
        if previous.is_some_and(|item| item >= repository) {
            return Err(ScopeError::InvalidField("repositories order"));
        }
        previous = Some(repository);
    }
    Ok(())
}

fn validate_assets(assets: &[AuthorizedAsset]) -> Result<(), ScopeError> {
    if assets.len() > 100_000 {
        return Err(ScopeError::InvalidField("assets"));
    }
    let mut previous: Option<&AuthorizedAsset> = None;
    for asset in assets {
        let valid_target = match asset.kind {
            TargetKind::DnsName => valid_dns_name(&asset.value),
            TargetKind::IpAddress => {
                !asset.include_subdomains && asset.value.parse::<IpAddr>().is_ok()
            }
        };
        if !valid_target
            || asset.schemes.is_empty()
            || asset.schemes.len() > 2
            || !strictly_sorted_unique(&asset.schemes)
            || asset.ports.is_empty()
            || asset.ports.len() > 100
            || asset.ports.contains(&0)
            || !strictly_sorted_unique(&asset.ports)
            || previous.is_some_and(|item| item >= asset)
        {
            return Err(ScopeError::InvalidField("assets"));
        }
        previous = Some(asset);
    }
    Ok(())
}

fn valid_dns_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn expected_scope_id(scope: &WebScope) -> String {
    let mut stable = scope.clone();
    stable.scope_id.clear();
    let bytes = serde_json::to_vec(&stable).expect("serializing WebScope cannot fail");
    format!("sf_web_scope_{}", sha256_hex(&bytes))
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

pub(crate) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.contains('\0')
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> WebScopeDraft {
        WebScopeDraft {
            authorization: ScopeAuthorization {
                status: AuthorizationStatus::Authorized,
                reference: "AUTH-TEST".into(),
                reviewer: "reviewer".into(),
                expires_at: "2027-01-01T00:00:00Z".into(),
            },
            repositories: vec![AuthorizedRepository {
                label: "fixture".into(),
                root_sha256: "1".repeat(64),
            }],
            assets: vec![],
            policy: ScopePolicy {
                passive_only: true,
                network_execution: NetworkExecution::Disabled,
                follow_redirects: false,
                third_party_scanning: false,
            },
            limits: ScopeLimits {
                max_files: 100,
                max_file_bytes: 1024,
                max_total_bytes: 4096,
                max_routes: 100,
                max_sources: 100,
                max_requests: 0,
                requests_per_minute: 0,
                max_concurrency: 0,
            },
        }
    }

    #[test]
    fn offline_v1_rejects_request_budget() {
        let mut draft = draft();
        draft.limits.max_requests = 1;
        assert!(
            seal_scope(
                &serde_json::to_vec(&draft).expect("draft JSON"),
                Some("2026-01-01T00:00:00Z".into())
            )
            .is_err()
        );
    }

    #[test]
    fn authorization_must_outlive_scope_creation() {
        let mut draft = draft();
        draft.authorization.expires_at = "2025-01-01T00:00:00Z".into();
        assert!(
            seal_scope(
                &serde_json::to_vec(&draft).expect("draft JSON"),
                Some("2026-01-01T00:00:00Z".into())
            )
            .is_err()
        );
    }
}
