use crate::inventory::{
    EvidenceState, HttpMethod, InventorySource, RouteKind, SourceKind, SourceLocation,
    WebInventory, hash_repository_tree, validate_source,
};
use crate::scope::{WebScope, sha256_hex, valid_sha256, valid_text};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const INFERENCE_VERSION: &str = "secureflow-web-inference-v1";
pub const MAX_INFERENCE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebInference {
    pub contract_version: String,
    pub inference_id: String,
    pub generated_at: String,
    pub scope_id: String,
    pub repository_root_sha256: String,
    pub inventory_ids: Vec<String>,
    pub sources: Vec<InventorySource>,
    pub candidates: Vec<ApiCandidate>,
    #[serde(default)]
    pub issues: Vec<InferenceIssue>,
    pub stats: InferenceStats,
    pub semantics: InferenceSemantics,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiCandidate {
    pub candidate_id: String,
    pub kind: ApiCandidateKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default)]
    pub methods: Vec<HttpMethod>,
    pub presence: CandidatePresence,
    pub confidence: CandidateConfidence,
    pub disposition: CandidateDisposition,
    pub classification: CandidateClassification,
    pub vulnerability_status: VulnerabilityStatus,
    pub evidence: Vec<CandidateEvidence>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiCandidateKind {
    HttpEndpoint,
    GraphQlOperation,
    TrpcProcedure,
    ServerAction,
    UnresolvedClientCall,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePresence {
    pub implemented: EvidenceState,
    pub documented: EvidenceState,
    pub observed: EvidenceState,
    pub inferred: EvidenceState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateConfidence {
    pub level: ConfidenceLevel,
    pub score_basis_points: u16,
    pub rationale: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateDisposition {
    CorrelatedLocal,
    NeedsHumanReview,
    Abstained,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateClassification {
    Candidate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VulnerabilityStatus {
    NotAssessed,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidence {
    pub origin: CandidateOrigin,
    pub source: SourceLocation,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateOrigin {
    ImplementedRoute,
    ClientCall,
    BuildManifest,
    OpenApi,
    GraphQlSchema,
    TrpcRouter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceIssue {
    pub kind: InferenceIssueKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InferenceIssueKind {
    UnsupportedPattern,
    MalformedArtifact,
    FileSkipped,
    LimitReached,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceStats {
    pub files_seen: u64,
    pub files_read: u64,
    pub bytes_read: u64,
    pub candidates: u64,
    pub correlated_local: u64,
    pub needs_human_review: u64,
    pub abstentions: u64,
    pub symlinks_skipped: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceSemantics {
    pub network_used: bool,
    pub target_code_executed: bool,
    pub target_preserved: bool,
    pub obscurity_is_control: bool,
    pub guesses_are_vulnerabilities: bool,
}

#[derive(Debug, Error)]
pub enum InferenceError {
    #[error("invalid web inference field: {0}")]
    InvalidField(&'static str),
    #[error("repository or inventory is outside the authorized scope")]
    UnauthorizedRepository,
    #[error("target root may not be a symlink")]
    SymlinkRoot,
    #[error("target changed while inference was running")]
    TargetModified,
    #[error("could not read target path {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid web inference JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid web scope: {0}")]
    Scope(#[from] crate::scope::ScopeError),
    #[error("invalid web inventory: {0}")]
    Inventory(#[from] crate::inventory::InventoryError),
    #[error("could not format inference timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CandidateKey {
    kind: ApiCandidateKind,
    route: Option<String>,
    operation: Option<String>,
}

#[derive(Clone, Debug)]
struct CandidateAccumulator {
    key: CandidateKey,
    methods: BTreeSet<HttpMethod>,
    origins: BTreeSet<CandidateOrigin>,
    evidence: BTreeSet<CandidateEvidence>,
    limitations: BTreeSet<String>,
}

struct CandidateAccumulators {
    entries: BTreeMap<CandidateKey, CandidateAccumulator>,
    maximum: u64,
    limit_reached: bool,
}

impl CandidateAccumulators {
    fn new(maximum: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            maximum,
            limit_reached: false,
        }
    }

    fn into_values(self) -> impl Iterator<Item = CandidateAccumulator> {
        self.entries.into_values()
    }
}

impl CandidateAccumulator {
    fn new(key: CandidateKey) -> Self {
        Self {
            key,
            methods: BTreeSet::new(),
            origins: BTreeSet::new(),
            evidence: BTreeSet::new(),
            limitations: BTreeSet::new(),
        }
    }
}

pub fn infer_local_apis(
    root: &Path,
    scope: &WebScope,
    repository_root_sha256: &str,
    inventory: &WebInventory,
    now: OffsetDateTime,
) -> Result<WebInference, InferenceError> {
    scope.validate_at(now)?;
    inventory.validate()?;
    if !scope.authorizes_repository(repository_root_sha256)
        || inventory.scope_id != scope.scope_id
        || inventory.repository_root_sha256 != repository_root_sha256
    {
        return Err(InferenceError::UnauthorizedRepository);
    }
    let repository_source = inventory
        .sources
        .iter()
        .find(|source| {
            source.kind == SourceKind::Repository && source.sha256 == repository_root_sha256
        })
        .ok_or(InferenceError::UnauthorizedRepository)?;
    let metadata = fs::symlink_metadata(root).map_err(|source| InferenceError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(InferenceError::SymlinkRoot);
    }
    if !metadata.is_dir() {
        return Err(InferenceError::InvalidField("target root"));
    }
    let limits = &scope.draft.limits;
    let before_sha256 = hash_repository_tree(
        root,
        limits.max_files,
        limits.max_file_bytes,
        limits.max_total_bytes,
    )?;
    if before_sha256 != repository_root_sha256 {
        return Err(InferenceError::UnauthorizedRepository);
    }

    let mut accumulators = CandidateAccumulators::new(limits.max_routes);
    for route in &inventory.routes {
        if !matches!(route.kind, RouteKind::ApiRoute | RouteKind::ServerAction) {
            continue;
        }
        let kind = if route.kind == RouteKind::ServerAction {
            ApiCandidateKind::ServerAction
        } else {
            ApiCandidateKind::HttpEndpoint
        };
        add_candidate(
            &mut accumulators,
            CandidateKey {
                kind,
                route: route.route.clone(),
                operation: (route.kind == RouteKind::ServerAction)
                    .then(|| route.source.path.clone()),
            },
            route.methods.iter().copied(),
            CandidateOrigin::ImplementedRoute,
            CandidateEvidence {
                origin: CandidateOrigin::ImplementedRoute,
                source: route.source.clone(),
                description: "route implemented through a framework convention".into(),
            },
            route.limitations.iter().cloned(),
        );
    }

    let implemented_routes = inventory
        .routes
        .iter()
        .filter(|route| route.kind == RouteKind::ApiRoute)
        .filter_map(|route| route.route.as_deref())
        .collect::<Vec<_>>();
    let mut stats = InferenceStats::empty();
    let mut files = collect_files(root, limits.max_files, &mut stats)?;
    files.sort();
    let mut issues = Vec::new();
    if stats.truncated {
        issues.push(InferenceIssue {
            kind: InferenceIssueKind::LimitReached,
            path: None,
            detail: "max_files reached while enumerating inference inputs".into(),
        });
    }
    for path in files {
        let metadata = fs::symlink_metadata(&path).map_err(|source| InferenceError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.len() > limits.max_file_bytes {
            issues.push(InferenceIssue {
                kind: InferenceIssueKind::FileSkipped,
                path: Some(relative_path(root, &path)?),
                detail: "file exceeds max_file_bytes".into(),
            });
            continue;
        }
        if stats.bytes_read.saturating_add(metadata.len()) > limits.max_total_bytes {
            stats.truncated = true;
            issues.push(InferenceIssue {
                kind: InferenceIssueKind::LimitReached,
                path: None,
                detail: "max_total_bytes reached during inference".into(),
            });
            break;
        }
        let relative = relative_path(root, &path)?;
        let content = fs::read(&path).map_err(|source| InferenceError::Io {
            path: path.clone(),
            source,
        })?;
        stats.files_read += 1;
        stats.bytes_read += content.len() as u64;
        let location = |line| SourceLocation {
            source_id: repository_source.source_id.clone(),
            path: relative.clone(),
            sha256: sha256_hex(&content),
            line,
        };

        if is_script(&path) {
            let client_scan = javascript_client_calls(&content);
            for call in client_scan.calls {
                let Some(local_route) = normalize_local_route(&call.route) else {
                    continue;
                };
                let route =
                    canonical_route(&local_route, &implemented_routes).unwrap_or(local_route);
                let mut limitations = Vec::new();
                if call.method.is_none() {
                    limitations.push(
                        "HTTP method was not inferred because fetch options were not evaluated"
                            .into(),
                    );
                }
                add_candidate(
                    &mut accumulators,
                    CandidateKey {
                        kind: ApiCandidateKind::HttpEndpoint,
                        route: Some(route),
                        operation: None,
                    },
                    call.method,
                    CandidateOrigin::ClientCall,
                    CandidateEvidence {
                        origin: CandidateOrigin::ClientCall,
                        source: location(Some(call.line)),
                        description: "same-origin endpoint referenced by local client code".into(),
                    },
                    limitations,
                );
            }
            for line in client_scan.unresolved_lines {
                add_candidate(
                    &mut accumulators,
                    CandidateKey {
                        kind: ApiCandidateKind::UnresolvedClientCall,
                        route: None,
                        operation: Some(format!("{relative}:{line}")),
                    },
                    [],
                    CandidateOrigin::ClientCall,
                    CandidateEvidence {
                        origin: CandidateOrigin::ClientCall,
                        source: location(Some(line)),
                        description: "client call contains an unresolved dynamic or escaped URL"
                            .into(),
                    },
                    ["dynamic URL was not converted into a route or network target".into()],
                );
            }
            if looks_like_trpc(&relative, &content) {
                for (procedure, line) in trpc_procedures(&content) {
                    add_candidate(
                        &mut accumulators,
                        CandidateKey {
                            kind: ApiCandidateKind::TrpcProcedure,
                            route: Some(format!("/api/trpc/{procedure}")),
                            operation: Some(procedure),
                        },
                        [],
                        CandidateOrigin::TrpcRouter,
                        CandidateEvidence {
                            origin: CandidateOrigin::TrpcRouter,
                            source: location(Some(line)),
                            description: "procedure name found in a local tRPC router".into(),
                        },
                        ["tRPC mount path and HTTP transport require router composition analysis".into()],
                    );
                }
            }
        } else if is_graphql(&path) {
            for (operation, line) in graphql_operations(&content) {
                add_candidate(
                    &mut accumulators,
                    CandidateKey {
                        kind: ApiCandidateKind::GraphQlOperation,
                        route: None,
                        operation: Some(operation),
                    },
                    [],
                    CandidateOrigin::GraphQlSchema,
                    CandidateEvidence {
                        origin: CandidateOrigin::GraphQlSchema,
                        source: location(Some(line)),
                        description: "operation declared in a local GraphQL schema".into(),
                    },
                    ["GraphQL transport endpoint is not proven by the schema".into()],
                );
            }
        } else if is_json(&path) {
            match serde_json::from_slice::<Value>(&content) {
                Ok(value) => {
                    extract_openapi(&value, &implemented_routes, &location, &mut accumulators);
                    extract_build_manifest(&relative, &value, &location, &mut accumulators);
                }
                Err(_) if is_named_artifact(&relative) => issues.push(InferenceIssue {
                    kind: InferenceIssueKind::MalformedArtifact,
                    path: Some(relative),
                    detail: "named JSON API artifact could not be parsed".into(),
                }),
                Err(_) => {}
            }
        }
        if accumulators.limit_reached {
            stats.truncated = true;
            issues.push(InferenceIssue {
                kind: InferenceIssueKind::LimitReached,
                path: None,
                detail: "max_routes reached during inference".into(),
            });
            break;
        }
    }

    let mut candidates = accumulators
        .into_values()
        .map(finalize_candidate)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        (&left.route, &left.operation, left.kind, &left.methods).cmp(&(
            &right.route,
            &right.operation,
            right.kind,
            &right.methods,
        ))
    });
    stats.candidates = candidates.len() as u64;
    stats.correlated_local = candidates
        .iter()
        .filter(|candidate| candidate.disposition == CandidateDisposition::CorrelatedLocal)
        .count() as u64;
    stats.needs_human_review = candidates
        .iter()
        .filter(|candidate| candidate.disposition == CandidateDisposition::NeedsHumanReview)
        .count() as u64;
    stats.abstentions = candidates
        .iter()
        .filter(|candidate| candidate.disposition == CandidateDisposition::Abstained)
        .count() as u64;

    let mut result = WebInference {
        contract_version: INFERENCE_VERSION.into(),
        inference_id: String::new(),
        generated_at: now.format(&Rfc3339)?,
        scope_id: scope.scope_id.clone(),
        repository_root_sha256: repository_root_sha256.into(),
        inventory_ids: vec![inventory.inventory_id.clone()],
        sources: inventory.sources.clone(),
        candidates,
        issues,
        stats,
        semantics: InferenceSemantics {
            network_used: false,
            target_code_executed: false,
            target_preserved: true,
            obscurity_is_control: false,
            guesses_are_vulnerabilities: false,
        },
    };
    result.inference_id = expected_inference_id(&result);
    result.validate()?;
    let after_sha256 = hash_repository_tree(
        root,
        limits.max_files,
        limits.max_file_bytes,
        limits.max_total_bytes,
    )?;
    if before_sha256 != after_sha256 {
        return Err(InferenceError::TargetModified);
    }
    Ok(result)
}

pub fn parse_inference(bytes: &[u8]) -> Result<WebInference, InferenceError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_INFERENCE_BYTES {
        return Err(InferenceError::InvalidField("document size"));
    }
    let inference: WebInference = serde_json::from_slice(bytes)?;
    inference.validate()?;
    Ok(inference)
}

impl WebInference {
    pub fn validate(&self) -> Result<(), InferenceError> {
        if self.contract_version != INFERENCE_VERSION
            || !valid_prefixed_hash(&self.inference_id, "sf_web_inference_")
            || self.inference_id != expected_inference_id(self)
            || OffsetDateTime::parse(&self.generated_at, &Rfc3339).is_err()
            || !valid_prefixed_hash(&self.scope_id, "sf_web_scope_")
            || !valid_sha256(&self.repository_root_sha256)
            || self.inventory_ids.is_empty()
            || self.inventory_ids.len() > 100_000
            || !self
                .inventory_ids
                .iter()
                .all(|value| valid_prefixed_hash(value, "sf_web_inventory_"))
            || !self.inventory_ids.windows(2).all(|pair| pair[0] < pair[1])
            || self.sources.is_empty()
            || self.sources.len() > 100_000
        {
            return Err(InferenceError::InvalidField("identity"));
        }
        if self.semantics.network_used
            || self.semantics.target_code_executed
            || !self.semantics.target_preserved
            || self.semantics.obscurity_is_control
            || self.semantics.guesses_are_vulnerabilities
            || self.stats.candidates != self.candidates.len() as u64
            || self.stats.files_read > self.stats.files_seen
            || self.stats.correlated_local + self.stats.needs_human_review + self.stats.abstentions
                != self.stats.candidates
        {
            return Err(InferenceError::InvalidField("semantics"));
        }
        for source in &self.sources {
            validate_source(source)?;
        }
        let source_ids = self
            .sources
            .iter()
            .map(|source| source.source_id.as_str())
            .collect::<BTreeSet<_>>();
        if source_ids.len() != self.sources.len()
            || !self
                .sources
                .windows(2)
                .all(|pair| pair[0].source_id < pair[1].source_id)
            || !self.sources.iter().any(|source| {
                source.kind == SourceKind::Repository
                    && source.sha256 == self.repository_root_sha256
            })
            || self.issues.len() > 2_000_000
        {
            return Err(InferenceError::InvalidField("sources or issues"));
        }
        for candidate in &self.candidates {
            validate_candidate(candidate, &source_ids)?;
        }
        if !self.candidates.windows(2).all(|pair| {
            (
                &pair[0].route,
                &pair[0].operation,
                pair[0].kind,
                &pair[0].methods,
            ) < (
                &pair[1].route,
                &pair[1].operation,
                pair[1].kind,
                &pair[1].methods,
            )
        }) {
            return Err(InferenceError::InvalidField("candidate order"));
        }
        for issue in &self.issues {
            if !valid_text(&issue.detail, 1_000)
                || issue
                    .path
                    .as_deref()
                    .is_some_and(|path| !valid_relative_path(path))
            {
                return Err(InferenceError::InvalidField("issue"));
            }
        }
        Ok(())
    }
}

impl InferenceStats {
    fn empty() -> Self {
        Self {
            files_seen: 0,
            files_read: 0,
            bytes_read: 0,
            candidates: 0,
            correlated_local: 0,
            needs_human_review: 0,
            abstentions: 0,
            symlinks_skipped: 0,
            truncated: false,
        }
    }
}

fn collect_files(
    root: &Path,
    max_files: u64,
    stats: &mut InferenceStats,
) -> Result<Vec<PathBuf>, InferenceError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| InferenceError::Io {
            path: directory.clone(),
            source,
        })?;
        let mut entries =
            entries
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| InferenceError::Io {
                    path: directory.clone(),
                    source,
                })?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| InferenceError::Io {
                path: path.clone(),
                source,
            })?;
            if metadata.file_type().is_symlink() {
                stats.symlinks_skipped += 1;
            } else if metadata.is_dir() {
                if !is_ignored_directory(&path) {
                    pending.push(path);
                }
            } else if metadata.is_file() {
                stats.files_seen += 1;
                if stats.files_seen > max_files {
                    stats.truncated = true;
                    break;
                }
                if is_inference_file(&path) {
                    files.push(path);
                }
            }
        }
        if stats.truncated {
            break;
        }
    }
    Ok(files)
}

fn add_candidate(
    accumulators: &mut CandidateAccumulators,
    key: CandidateKey,
    methods: impl IntoIterator<Item = HttpMethod>,
    origin: CandidateOrigin,
    evidence: CandidateEvidence,
    limitations: impl IntoIterator<Item = String>,
) {
    if !accumulators.entries.contains_key(&key)
        && accumulators.entries.len() as u64 >= accumulators.maximum
    {
        accumulators.limit_reached = true;
        return;
    }
    let candidate = accumulators
        .entries
        .entry(key.clone())
        .or_insert_with(|| CandidateAccumulator::new(key));
    candidate.methods.extend(methods);
    candidate.origins.insert(origin);
    candidate.evidence.insert(evidence);
    candidate.limitations.extend(limitations);
}

fn finalize_candidate(accumulator: CandidateAccumulator) -> ApiCandidate {
    let implemented = accumulator
        .origins
        .contains(&CandidateOrigin::ImplementedRoute);
    let documented = accumulator.origins.contains(&CandidateOrigin::OpenApi);
    let inferred = accumulator.origins.len() > usize::from(implemented);
    let confidence = confidence_for(accumulator.key.kind, &accumulator.origins);
    let disposition = if implemented {
        CandidateDisposition::CorrelatedLocal
    } else if accumulator.key.route.is_none() {
        CandidateDisposition::Abstained
    } else {
        CandidateDisposition::NeedsHumanReview
    };
    let mut candidate = ApiCandidate {
        candidate_id: String::new(),
        kind: accumulator.key.kind,
        route: accumulator.key.route,
        operation: accumulator.key.operation,
        methods: accumulator.methods.into_iter().collect(),
        presence: CandidatePresence {
            implemented: state(implemented),
            documented: state(documented),
            observed: EvidenceState::Unknown,
            inferred: state(inferred),
        },
        confidence,
        disposition,
        classification: CandidateClassification::Candidate,
        vulnerability_status: VulnerabilityStatus::NotAssessed,
        evidence: accumulator.evidence.into_iter().collect(),
        limitations: accumulator.limitations.into_iter().collect(),
    };
    candidate.candidate_id = expected_candidate_id(&candidate);
    candidate
}

fn state(present: bool) -> EvidenceState {
    if present {
        EvidenceState::Present
    } else {
        EvidenceState::Unknown
    }
}

#[derive(Clone, Debug)]
struct ClientCall {
    route: String,
    method: Option<HttpMethod>,
    line: u32,
}

#[derive(Clone, Debug)]
struct ClientCallScan {
    calls: Vec<ClientCall>,
    unresolved_lines: Vec<u32>,
}

fn javascript_client_calls(content: &[u8]) -> ClientCallScan {
    let mut calls = Vec::new();
    let mut unresolved_lines = Vec::new();
    let mut index = 0;
    let mut line = 1_u32;
    while index < content.len() {
        match content[index] {
            b'\n' => {
                line = line.saturating_add(1);
                index += 1;
            }
            b'/' if content.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < content.len() && content[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if content.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < content.len() {
                    if content[index] == b'\n' {
                        line = line.saturating_add(1);
                    }
                    if content[index] == b'*' && content[index + 1] == b'/' {
                        index += 2;
                        break;
                    }
                    index += 1;
                }
            }
            quote @ (b'\'' | b'"' | b'`') => {
                let start = index;
                let literal_line = line;
                index += 1;
                let mut value = Vec::new();
                let mut supported = true;
                while index < content.len() {
                    let byte = content[index];
                    if byte == b'\n' {
                        line = line.saturating_add(1);
                    }
                    if byte == b'\\' {
                        supported = false;
                        index = index.saturating_add(2);
                        continue;
                    }
                    if quote == b'`' && byte == b'$' && content.get(index + 1) == Some(&b'{') {
                        supported = false;
                    }
                    if byte == quote {
                        index += 1;
                        break;
                    }
                    value.push(byte);
                    index += 1;
                }
                let prefix_start = start.saturating_sub(96);
                let prefix = String::from_utf8_lossy(&content[prefix_start..start]);
                let prefix = prefix.trim_end();
                let method = if prefix.ends_with("axios.get(") {
                    Some(HttpMethod::Get)
                } else if prefix.ends_with("axios.post(") {
                    Some(HttpMethod::Post)
                } else if prefix.ends_with("axios.put(") {
                    Some(HttpMethod::Put)
                } else if prefix.ends_with("axios.patch(") {
                    Some(HttpMethod::Patch)
                } else if prefix.ends_with("axios.delete(") {
                    Some(HttpMethod::Delete)
                } else if prefix.ends_with("fetch(") {
                    None
                } else {
                    continue;
                };
                if !supported {
                    unresolved_lines.push(literal_line);
                } else if let Ok(route) = String::from_utf8(value) {
                    calls.push(ClientCall {
                        route,
                        method,
                        line: literal_line,
                    });
                }
            }
            _ => index += 1,
        }
    }
    ClientCallScan {
        calls,
        unresolved_lines,
    }
}

fn extract_openapi(
    value: &Value,
    implemented_routes: &[&str],
    location: &impl Fn(Option<u32>) -> SourceLocation,
    accumulators: &mut CandidateAccumulators,
) {
    if value.get("openapi").is_none() && value.get("swagger").is_none() {
        return;
    }
    let Some(paths) = value.get("paths").and_then(Value::as_object) else {
        return;
    };
    for (raw_route, operations) in paths {
        let Some(local_route) = normalize_local_route(raw_route) else {
            continue;
        };
        let route = canonical_route(&local_route, implemented_routes).unwrap_or(local_route);
        let methods = operations
            .as_object()
            .into_iter()
            .flat_map(|operations| operations.keys())
            .filter_map(|method| parse_lower_method(method))
            .collect::<Vec<_>>();
        add_candidate(
            accumulators,
            CandidateKey {
                kind: ApiCandidateKind::HttpEndpoint,
                route: Some(route),
                operation: None,
            },
            methods,
            CandidateOrigin::OpenApi,
            CandidateEvidence {
                origin: CandidateOrigin::OpenApi,
                source: location(None),
                description: "path declared in a local OpenAPI or Swagger document".into(),
            },
            [],
        );
    }
}

fn extract_build_manifest(
    relative: &str,
    value: &Value,
    location: &impl Fn(Option<u32>) -> SourceLocation,
    accumulators: &mut CandidateAccumulators,
) {
    let name = Path::new(relative)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let mut routes = BTreeSet::new();
    if matches!(name, "app-paths-manifest.json" | "pages-manifest.json") {
        if let Some(entries) = value.as_object() {
            routes.extend(
                entries
                    .keys()
                    .filter_map(|route| normalize_manifest_route(route)),
            );
        }
    } else if name == "routes-manifest.json" {
        for section in ["staticRoutes", "dynamicRoutes"] {
            if let Some(entries) = value.get(section).and_then(Value::as_array) {
                routes.extend(entries.iter().filter_map(|entry| {
                    entry
                        .get("page")
                        .and_then(Value::as_str)
                        .and_then(normalize_manifest_route)
                }));
            }
        }
    } else {
        return;
    }
    for route in routes
        .into_iter()
        .filter(|route| route.starts_with("/api/"))
    {
        add_candidate(
            accumulators,
            CandidateKey {
                kind: ApiCandidateKind::HttpEndpoint,
                route: Some(route),
                operation: None,
            },
            [],
            CandidateOrigin::BuildManifest,
            CandidateEvidence {
                origin: CandidateOrigin::BuildManifest,
                source: location(None),
                description: "API route retained in a local Next.js build manifest".into(),
            },
            ["build artifact presence does not prove current deployment reachability".into()],
        );
    }
}

fn normalize_manifest_route(value: &str) -> Option<String> {
    let mut segments = Vec::new();
    for raw in value
        .trim_end_matches("/route")
        .split('/')
        .filter(|item| !item.is_empty())
    {
        if (raw.starts_with('(') && raw.ends_with(')')) || raw.starts_with('@') {
            continue;
        }
        let segment = if raw.starts_with("[[...") && raw.ends_with("]]") {
            format!("{{{}*}}", &raw[5..raw.len() - 2])
        } else if raw.starts_with("[...") && raw.ends_with(']') {
            format!("{{{}+}}", &raw[4..raw.len() - 1])
        } else if raw.starts_with('[') && raw.ends_with(']') {
            format!("{{{}}}", &raw[1..raw.len() - 1])
        } else {
            raw.to_owned()
        };
        segments.push(segment);
    }
    normalize_local_route(&format!("/{}", segments.join("/")))
}

fn graphql_operations(content: &[u8]) -> Vec<(String, u32)> {
    let text = String::from_utf8_lossy(content);
    let mut current_type = None::<&str>;
    let mut operations = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with("type Query") && line.contains('{') {
            current_type = Some("Query");
            continue;
        }
        if line.starts_with("type Mutation") && line.contains('{') {
            current_type = Some("Mutation");
            continue;
        }
        if line.starts_with("type Subscription") && line.contains('{') {
            current_type = Some("Subscription");
            continue;
        }
        if line.starts_with('}') {
            current_type = None;
            continue;
        }
        let Some(kind) = current_type else {
            continue;
        };
        let name = line.split(['(', ':', ' ', '\t']).next().unwrap_or_default();
        if valid_operation_name(name) {
            operations.push((format!("{kind}.{name}"), index as u32 + 1));
        }
    }
    operations
}

fn trpc_procedures(content: &[u8]) -> Vec<(String, u32)> {
    String::from_utf8_lossy(content)
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.split("//").next().unwrap_or_default();
            let (name, value) = line.split_once(':')?;
            let name = name.trim().trim_matches(['\'', '"']);
            (valid_operation_name(name)
                && (value.contains("Procedure") || value.contains("procedure")))
            .then(|| (name.to_owned(), index as u32 + 1))
        })
        .collect()
}

fn looks_like_trpc(relative: &str, content: &[u8]) -> bool {
    relative.to_ascii_lowercase().contains("trpc")
        || content.windows(9).any(|window| window == b"Procedure")
        || content.windows(9).any(|window| window == b"procedure")
}

fn valid_operation_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 300
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
        })
}

fn canonical_route(route: &str, implemented_routes: &[&str]) -> Option<String> {
    implemented_routes
        .iter()
        .find(|candidate| **candidate == route)
        .or_else(|| {
            implemented_routes
                .iter()
                .find(|candidate| route_matches(candidate, route))
        })
        .map(|value| (*value).to_owned())
}

fn route_matches(pattern: &str, concrete: &str) -> bool {
    let pattern = pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let concrete = concrete
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let mut index = 0;
    while index < pattern.len() {
        let segment = pattern[index];
        if segment.starts_with('{') && segment.ends_with("+}") {
            return index < concrete.len();
        }
        if segment.starts_with('{') && segment.ends_with("*}") {
            return true;
        }
        if index >= concrete.len()
            || (!(segment.starts_with('{') && segment.ends_with('}')) && segment != concrete[index])
        {
            return false;
        }
        index += 1;
    }
    index == concrete.len()
}

fn normalize_local_route(value: &str) -> Option<String> {
    let route = value.split(['?', '#']).next()?.trim();
    if !route.starts_with('/')
        || route.starts_with("//")
        || route.len() > 2_000
        || route.contains('\\')
        || route.contains('\0')
        || route
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return None;
    }
    Some(if route.len() > 1 {
        route.trim_end_matches('/').to_owned()
    } else {
        route.to_owned()
    })
}

fn parse_lower_method(value: &str) -> Option<HttpMethod> {
    match value {
        "get" => Some(HttpMethod::Get),
        "head" => Some(HttpMethod::Head),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "patch" => Some(HttpMethod::Patch),
        "delete" => Some(HttpMethod::Delete),
        "options" => Some(HttpMethod::Options),
        _ => None,
    }
}

fn is_inference_file(path: &Path) -> bool {
    is_script(path) || is_graphql(path) || is_json(path)
}

fn is_script(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx")
    )
}

fn is_graphql(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("graphql" | "gql")
    )
}

fn is_json(path: &Path) -> bool {
    path.extension().and_then(|value| value.to_str()) == Some("json")
}

fn is_named_artifact(relative: &str) -> bool {
    let name = Path::new(relative)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    matches!(
        name,
        "openapi.json"
            | "swagger.json"
            | "app-paths-manifest.json"
            | "pages-manifest.json"
            | "routes-manifest.json"
    )
}

fn is_ignored_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| matches!(name, ".git" | ".next" | "node_modules" | "target"))
}

fn relative_path(root: &Path, path: &Path) -> Result<String, InferenceError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| InferenceError::InvalidField("source path"))?;
    if relative.components().any(|component| {
        !matches!(component, Component::Normal(_))
            || component
                .as_os_str()
                .to_str()
                .is_none_or(|value| value.contains('\\') || value.contains('\0'))
    }) {
        return Err(InferenceError::InvalidField("source path"));
    }
    Ok(relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn validate_candidate(
    candidate: &ApiCandidate,
    source_ids: &BTreeSet<&str>,
) -> Result<(), InferenceError> {
    if !valid_prefixed_hash(&candidate.candidate_id, "sf_web_candidate_")
        || candidate.candidate_id != expected_candidate_id(candidate)
        || candidate.route.is_none() && candidate.operation.is_none()
        || candidate.methods.len() > 7
        || !candidate.methods.windows(2).all(|pair| pair[0] < pair[1])
        || candidate.confidence.score_basis_points > 10_000
        || candidate.confidence.rationale.is_empty()
        || candidate.evidence.is_empty()
        || candidate.evidence.len() > 100
        || !candidate.evidence.windows(2).all(|pair| pair[0] < pair[1])
        || candidate.limitations.len() > 100
        || !candidate
            .limitations
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || candidate.presence.observed != EvidenceState::Unknown
        || candidate.classification != CandidateClassification::Candidate
        || candidate.vulnerability_status != VulnerabilityStatus::NotAssessed
    {
        return Err(InferenceError::InvalidField("candidate"));
    }
    if let Some(route) = &candidate.route
        && normalize_local_route(route).as_deref() != Some(route)
    {
        return Err(InferenceError::InvalidField("candidate route"));
    }
    if match candidate.kind {
        ApiCandidateKind::HttpEndpoint => candidate.route.is_none(),
        ApiCandidateKind::GraphQlOperation => candidate.operation.is_none(),
        ApiCandidateKind::TrpcProcedure => {
            candidate.route.is_none() || candidate.operation.is_none()
        }
        ApiCandidateKind::ServerAction => candidate.operation.is_none(),
        ApiCandidateKind::UnresolvedClientCall => {
            candidate.route.is_some() || candidate.operation.is_none()
        }
    } {
        return Err(InferenceError::InvalidField("candidate applicability"));
    }
    if candidate
        .operation
        .as_deref()
        .is_some_and(|value| !valid_text(value, 300))
        || candidate
            .confidence
            .rationale
            .iter()
            .any(|value| !valid_text(value, 500))
        || candidate
            .limitations
            .iter()
            .any(|value| !valid_text(value, 500))
    {
        return Err(InferenceError::InvalidField("candidate text"));
    }
    for evidence in &candidate.evidence {
        if !source_ids.contains(evidence.source.source_id.as_str())
            || !valid_relative_path(&evidence.source.path)
            || !valid_sha256(&evidence.source.sha256)
            || evidence.source.line == Some(0)
            || !valid_text(&evidence.description, 1_000)
        {
            return Err(InferenceError::InvalidField("candidate evidence"));
        }
    }
    let origins = candidate
        .evidence
        .iter()
        .map(|evidence| evidence.origin)
        .collect::<BTreeSet<_>>();
    let implemented = origins.contains(&CandidateOrigin::ImplementedRoute);
    let documented = origins.contains(&CandidateOrigin::OpenApi);
    let inferred = origins.len() > usize::from(implemented);
    let expected_disposition = if implemented {
        CandidateDisposition::CorrelatedLocal
    } else if candidate.route.is_none() {
        CandidateDisposition::Abstained
    } else {
        CandidateDisposition::NeedsHumanReview
    };
    if candidate.presence.implemented != state(implemented)
        || candidate.presence.documented != state(documented)
        || candidate.presence.inferred != state(inferred)
        || candidate.confidence != confidence_for(candidate.kind, &origins)
        || candidate.disposition != expected_disposition
    {
        return Err(InferenceError::InvalidField("candidate derivation"));
    }
    Ok(())
}

fn confidence_for(
    kind: ApiCandidateKind,
    origins: &BTreeSet<CandidateOrigin>,
) -> CandidateConfidence {
    let implemented = origins.contains(&CandidateOrigin::ImplementedRoute);
    let inferred = origins.len() > usize::from(implemented);
    let (level, score_basis_points, rationale) = if kind == ApiCandidateKind::UnresolvedClientCall {
        (
            ConfidenceLevel::Low,
            2_500,
            "a client call exists but its dynamic URL was intentionally not resolved",
        )
    } else if implemented && inferred {
        (
            ConfidenceLevel::High,
            9_500,
            "implemented route is corroborated by an independent local artifact",
        )
    } else if implemented {
        (
            ConfidenceLevel::High,
            9_000,
            "framework route implementation is present in the authorized repository",
        )
    } else if origins.contains(&CandidateOrigin::BuildManifest) {
        (
            ConfidenceLevel::High,
            8_500,
            "route is retained in a local build manifest",
        )
    } else if origins.len() >= 2 {
        (
            ConfidenceLevel::High,
            8_000,
            "multiple independent local artifacts reference the same API surface",
        )
    } else if origins.contains(&CandidateOrigin::OpenApi) {
        (
            ConfidenceLevel::Medium,
            7_000,
            "route is documented locally but may be stale or unimplemented",
        )
    } else if origins.contains(&CandidateOrigin::ClientCall) {
        (
            ConfidenceLevel::Medium,
            6_500,
            "same-origin client code references the endpoint",
        )
    } else {
        (
            ConfidenceLevel::Low,
            4_500,
            "framework convention suggests an API surface but its transport is unresolved",
        )
    };
    CandidateConfidence {
        level,
        score_basis_points,
        rationale: vec![rationale.into()],
    }
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4_096
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value
            .split('/')
            .any(|segment| segment.is_empty() || segment == ".." || segment == ".")
}

fn expected_candidate_id(candidate: &ApiCandidate) -> String {
    let mut stable = candidate.clone();
    stable.candidate_id.clear();
    format!(
        "sf_web_candidate_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("candidate serialization"))
    )
}

fn expected_inference_id(inference: &WebInference) -> String {
    let mut stable = inference.clone();
    stable.inference_id.clear();
    stable.generated_at.clear();
    format!(
        "sf_web_inference_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("inference serialization"))
    )
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_calls_not_comments_or_decoy_strings() {
        let scan = javascript_client_calls(
            br#"
            // fetch("/api/comment")
            const decoy = "fetch('/api/decoy')";
            fetch("/api/health");
            axios.delete('/api/users/1');
            fetch(`https://third-party.test/api`);
            fetch(`/api/users/${userId}`);
            "#,
        );
        let calls = scan.calls;
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].route, "/api/health");
        assert_eq!(calls[0].method, None);
        assert_eq!(calls[1].method, Some(HttpMethod::Delete));
        assert!(normalize_local_route(&calls[2].route).is_none());
        assert_eq!(scan.unresolved_lines.len(), 1);
    }

    #[test]
    fn matches_concrete_calls_to_parameterized_routes() {
        assert!(route_matches(
            "/api/admin/{tenantId}/users/{id}",
            "/api/admin/acme/users/user-1"
        ));
        assert!(!route_matches(
            "/api/admin/{tenantId}/users/{id}",
            "/api/admin/acme/users"
        ));
    }

    #[test]
    fn rejects_external_and_traversal_candidates() {
        assert!(normalize_local_route("https://example.test/api").is_none());
        assert!(normalize_local_route("//example.test/api").is_none());
        assert!(normalize_local_route("/api/../secret").is_none());
        assert_eq!(
            normalize_local_route("/api/health?verbose=1").as_deref(),
            Some("/api/health")
        );
    }

    #[test]
    fn candidate_accumulator_enforces_the_route_budget_before_insertion() {
        let mut candidates = CandidateAccumulators::new(1);
        let evidence = |path: &str| CandidateEvidence {
            origin: CandidateOrigin::ClientCall,
            source: SourceLocation {
                source_id: format!("sf_web_source_{}", "1".repeat(64)),
                path: path.into(),
                sha256: "2".repeat(64),
                line: Some(1),
            },
            description: "bounded test evidence".into(),
        };
        add_candidate(
            &mut candidates,
            CandidateKey {
                kind: ApiCandidateKind::HttpEndpoint,
                route: Some("/api/one".into()),
                operation: None,
            },
            [HttpMethod::Get],
            CandidateOrigin::ClientCall,
            evidence("one.ts"),
            [],
        );
        add_candidate(
            &mut candidates,
            CandidateKey {
                kind: ApiCandidateKind::HttpEndpoint,
                route: Some("/api/two".into()),
                operation: None,
            },
            [HttpMethod::Get],
            CandidateOrigin::ClientCall,
            evidence("two.ts"),
            [],
        );
        assert_eq!(candidates.entries.len(), 1);
        assert!(candidates.limit_reached);
    }
}
