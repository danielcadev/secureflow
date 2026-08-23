use crate::scope::{WebScope, sha256_hex, valid_sha256, valid_text};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const INVENTORY_VERSION: &str = "secureflow-web-inventory-v1";
pub const MAX_INVENTORY_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebInventory {
    pub contract_version: String,
    pub inventory_id: String,
    pub generated_at: String,
    pub scope_id: String,
    pub repository_root_sha256: String,
    pub sources: Vec<InventorySource>,
    pub routes: Vec<RouteRecord>,
    #[serde(default)]
    pub issues: Vec<InventoryIssue>,
    pub stats: InventoryStats,
    pub semantics: InventorySemantics,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventorySource {
    pub source_id: String,
    pub kind: SourceKind,
    pub name: String,
    pub revision: String,
    pub sha256: String,
    pub license_spdx: String,
}

impl InventorySource {
    pub fn new(
        kind: SourceKind,
        name: String,
        revision: String,
        sha256: String,
        license_spdx: String,
    ) -> Result<Self, InventoryError> {
        let mut source = Self {
            source_id: String::new(),
            kind,
            name,
            revision,
            sha256,
            license_spdx,
        };
        source.source_id = expected_source_id(&source);
        validate_source(&source)?;
        Ok(source)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Repository,
    BuildManifest,
    OpenApi,
    GraphQl,
    Trpc,
    AuthorizedLog,
    SimulatedDns,
    SimulatedCertificateTransparency,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRecord {
    pub route_id: String,
    pub framework: Framework,
    pub kind: RouteKind,
    pub method_evidence: MethodEvidence,
    #[serde(default)]
    pub methods: Vec<HttpMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default)]
    pub parameters: Vec<RouteParameter>,
    pub presence: ApiPresence,
    pub controls: RouteControls,
    #[serde(default)]
    pub response_fields: Vec<ResponseField>,
    pub source: SourceLocation,
    pub evidence: Vec<EvidenceAnchor>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Framework {
    NextAppRouter,
    NextPagesRouter,
    NextShared,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteKind {
    ApiRoute,
    PageRoute,
    Middleware,
    ServerAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MethodEvidence {
    DeclaredExport,
    FrameworkDefault,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub catch_all: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParameterLocation {
    Path,
    Query,
    Body,
    Header,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiPresence {
    pub implemented: bool,
    pub documented: EvidenceState,
    pub observed: EvidenceState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteControls {
    pub access: AccessLevel,
    pub authentication: EvidenceState,
    pub authorization: EvidenceState,
    pub owner_scope: EvidenceState,
    pub tenant_scope: EvidenceState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessLevel {
    Public,
    Authenticated,
    Privileged,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceState {
    Present,
    Missing,
    Inconsistent,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseField {
    pub name: String,
    pub sensitivity: FieldSensitivity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldSensitivity {
    Public,
    Internal,
    Personal,
    AuthorizationMetadata,
    Secret,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLocation {
    pub source_id: String,
    pub path: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAnchor {
    pub kind: EvidenceKind,
    pub reference: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Code,
    Build,
    Documentation,
    AuthorizedTraffic,
    Control,
    Response,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryIssue {
    pub kind: InventoryIssueKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InventoryIssueKind {
    UnsupportedPattern,
    FileSkipped,
    LimitReached,
    MalformedInput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryStats {
    pub files_seen: u64,
    pub files_read: u64,
    pub bytes_read: u64,
    pub routes: u64,
    pub symlinks_skipped: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventorySemantics {
    pub network_used: bool,
    pub target_code_executed: bool,
    pub unknown_controls_are_safe: bool,
    pub undocumented_means_vulnerable: bool,
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("invalid web inventory field: {0}")]
    InvalidField(&'static str),
    #[error("repository is outside the authorized scope")]
    UnauthorizedRepository,
    #[error("target root may not be a symlink")]
    SymlinkRoot,
    #[error("target changed while the inventory was running")]
    TargetModified,
    #[error("could not read target path {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid web inventory JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid web scope: {0}")]
    Scope(#[from] crate::scope::ScopeError),
    #[error("could not format inventory timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
}

pub fn discover_nextjs(
    root: &Path,
    scope: &WebScope,
    repository_root_sha256: &str,
    source: InventorySource,
    now: OffsetDateTime,
) -> Result<WebInventory, InventoryError> {
    scope.validate_at(now)?;
    if !scope.authorizes_repository(repository_root_sha256)
        || source.kind != SourceKind::Repository
        || source.sha256 != repository_root_sha256
    {
        return Err(InventoryError::UnauthorizedRepository);
    }
    validate_source(&source)?;
    let root_metadata = fs::symlink_metadata(root).map_err(|source| InventoryError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if root_metadata.file_type().is_symlink() {
        return Err(InventoryError::SymlinkRoot);
    }
    if !root_metadata.is_dir() {
        return Err(InventoryError::InvalidField("target root"));
    }

    let limits = &scope.draft.limits;
    let before_sha256 = hash_repository_tree(
        root,
        limits.max_files,
        limits.max_file_bytes,
        limits.max_total_bytes,
    )?;
    if before_sha256 != repository_root_sha256 {
        return Err(InventoryError::UnauthorizedRepository);
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut stats = InventoryStats {
        files_seen: 0,
        files_read: 0,
        bytes_read: 0,
        routes: 0,
        symlinks_skipped: 0,
        truncated: false,
    };
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| InventoryError::Io {
            path: directory.clone(),
            source,
        })?;
        let mut entries =
            entries
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| InventoryError::Io {
                    path: directory.clone(),
                    source,
                })?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| InventoryError::Io {
                path: path.clone(),
                source,
            })?;
            if metadata.file_type().is_symlink() {
                stats.symlinks_skipped += 1;
                continue;
            }
            if metadata.is_dir() {
                if !is_ignored_directory(&path) {
                    pending.push(path);
                }
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            stats.files_seen += 1;
            if stats.files_seen > limits.max_files {
                stats.truncated = true;
                break;
            }
            if is_javascript_or_typescript(&path) {
                files.push((path, metadata.len()));
            }
        }
        if stats.truncated {
            break;
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut routes = Vec::new();
    let mut issues = Vec::new();
    for (path, bytes) in files {
        let relative = relative_path(root, &path)?;
        if bytes > limits.max_file_bytes {
            issues.push(InventoryIssue {
                kind: InventoryIssueKind::FileSkipped,
                path: Some(relative),
                detail: "file exceeds max_file_bytes".into(),
            });
            continue;
        }
        if stats.bytes_read.saturating_add(bytes) > limits.max_total_bytes {
            stats.truncated = true;
            issues.push(InventoryIssue {
                kind: InventoryIssueKind::LimitReached,
                path: None,
                detail: "max_total_bytes reached".into(),
            });
            break;
        }
        let content = fs::read(&path).map_err(|source| InventoryError::Io {
            path: path.clone(),
            source,
        })?;
        stats.files_read += 1;
        stats.bytes_read += content.len() as u64;
        if let Some(mut route) = classify_next_file(&relative, &content, &source.source_id) {
            route.source.sha256 = sha256_hex(&content);
            route.route_id = expected_route_id(&route);
            routes.push(route);
            if routes.len() as u64 >= limits.max_routes {
                stats.truncated = true;
                issues.push(InventoryIssue {
                    kind: InventoryIssueKind::LimitReached,
                    path: None,
                    detail: "max_routes reached".into(),
                });
                break;
            }
        }
    }
    routes.sort_by(|left, right| {
        (&left.route, left.kind, &left.methods, &left.source.path).cmp(&(
            &right.route,
            right.kind,
            &right.methods,
            &right.source.path,
        ))
    });
    if !routes
        .windows(2)
        .all(|pair| pair[0].route_id != pair[1].route_id)
    {
        return Err(InventoryError::InvalidField("duplicate route"));
    }
    stats.routes = routes.len() as u64;
    let mut inventory = WebInventory {
        contract_version: INVENTORY_VERSION.into(),
        inventory_id: String::new(),
        generated_at: now.format(&Rfc3339)?,
        scope_id: scope.scope_id.clone(),
        repository_root_sha256: repository_root_sha256.into(),
        sources: vec![source],
        routes,
        issues,
        stats,
        semantics: InventorySemantics {
            network_used: false,
            target_code_executed: false,
            unknown_controls_are_safe: false,
            undocumented_means_vulnerable: false,
        },
    };
    inventory.inventory_id = expected_inventory_id(&inventory);
    inventory.validate()?;
    let after_sha256 = hash_repository_tree(
        root,
        limits.max_files,
        limits.max_file_bytes,
        limits.max_total_bytes,
    )?;
    if before_sha256 != after_sha256 {
        return Err(InventoryError::TargetModified);
    }
    Ok(inventory)
}

pub fn hash_repository_tree(
    root: &Path,
    max_files: u64,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> Result<String, InventoryError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| InventoryError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(InventoryError::SymlinkRoot);
    }
    if !metadata.is_dir() {
        return Err(InventoryError::InvalidField("target root"));
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| InventoryError::Io {
            path: directory.clone(),
            source,
        })?;
        let mut entries =
            entries
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| InventoryError::Io {
                    path: directory.clone(),
                    source,
                })?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| InventoryError::Io {
                path: path.clone(),
                source,
            })?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                if !is_ignored_directory(&path) {
                    pending.push(path);
                }
            } else if metadata.is_file() {
                if metadata.len() > max_file_bytes {
                    return Err(InventoryError::InvalidField("tree file size"));
                }
                files.push((path, metadata.len()));
                if files.len() as u64 > max_files {
                    return Err(InventoryError::InvalidField("tree file count"));
                }
            }
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    hasher.update(b"secureflow-web-tree-v1\0");
    for (path, declared_bytes) in files {
        total = total
            .checked_add(declared_bytes)
            .ok_or(InventoryError::InvalidField("tree byte count"))?;
        if total > max_total_bytes {
            return Err(InventoryError::InvalidField("tree total bytes"));
        }
        let relative = relative_path(root, &path)?;
        let content = fs::read(&path).map_err(|source| InventoryError::Io {
            path: path.clone(),
            source,
        })?;
        if content.len() as u64 != declared_bytes {
            return Err(InventoryError::TargetModified);
        }
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((content.len() as u64).to_be_bytes());
        hasher.update(&content);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

pub fn parse_inventory(bytes: &[u8]) -> Result<WebInventory, InventoryError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_INVENTORY_BYTES {
        return Err(InventoryError::InvalidField("document size"));
    }
    let inventory: WebInventory = serde_json::from_slice(bytes)?;
    inventory.validate()?;
    Ok(inventory)
}

impl WebInventory {
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.contract_version != INVENTORY_VERSION
            || !valid_prefixed_hash(&self.inventory_id, "sf_web_inventory_")
            || OffsetDateTime::parse(&self.generated_at, &Rfc3339).is_err()
            || !valid_prefixed_hash(&self.scope_id, "sf_web_scope_")
            || !valid_sha256(&self.repository_root_sha256)
            || self.inventory_id != expected_inventory_id(self)
            || self.sources.is_empty()
            || self.sources.len() > 100_000
        {
            return Err(InventoryError::InvalidField("identity"));
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
        {
            return Err(InventoryError::InvalidField("sources"));
        }
        if self.routes.len() > 2_000_000
            || self.routes.len() as u64 != self.stats.routes
            || self.stats.files_read > self.stats.files_seen
            || self.issues.len() > 2_000_000
            || self.semantics.network_used
            || self.semantics.target_code_executed
            || self.semantics.unknown_controls_are_safe
            || self.semantics.undocumented_means_vulnerable
        {
            return Err(InventoryError::InvalidField("semantics"));
        }
        for route in &self.routes {
            validate_route(route, &source_ids)?;
        }
        for issue in &self.issues {
            if !valid_text(&issue.detail, 1_000)
                || issue
                    .path
                    .as_deref()
                    .is_some_and(|path| !valid_relative_path(path))
            {
                return Err(InventoryError::InvalidField("issue"));
            }
        }
        if !self.routes.windows(2).all(|pair| {
            (
                &pair[0].route,
                pair[0].kind,
                &pair[0].methods,
                &pair[0].source.path,
            ) < (
                &pair[1].route,
                pair[1].kind,
                &pair[1].methods,
                &pair[1].source.path,
            )
        }) {
            return Err(InventoryError::InvalidField("route order"));
        }
        Ok(())
    }
}

fn classify_next_file(relative: &str, content: &[u8], source_id: &str) -> Option<RouteRecord> {
    let path = Path::new(relative);
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str().map(str::to_owned),
            _ => None,
        })
        .collect::<Vec<_>>();
    if components.is_empty() {
        return None;
    }
    let file_name = components.last()?;
    let stem = script_stem(file_name)?;
    let (framework, kind, route, methods, method_evidence, limitations) =
        if components.first().is_some_and(|value| value == "app") && stem == "route" {
            let route = next_route_path(&components[1..components.len() - 1]);
            let methods = exported_http_methods(content);
            let evidence = if methods.is_empty() {
                MethodEvidence::Unknown
            } else {
                MethodEvidence::DeclaredExport
            };
            let limitations = if methods.is_empty() {
                vec!["HTTP methods were not proven from named exports".into()]
            } else {
                vec![]
            };
            (
                Framework::NextAppRouter,
                RouteKind::ApiRoute,
                Some(route),
                methods,
                evidence,
                limitations,
            )
        } else if components.first().is_some_and(|value| value == "app") && stem == "page" {
            (
                Framework::NextAppRouter,
                RouteKind::PageRoute,
                Some(next_route_path(&components[1..components.len() - 1])),
                vec![HttpMethod::Get],
                MethodEvidence::FrameworkDefault,
                vec![],
            )
        } else if components.first().is_some_and(|value| value == "pages")
            && components.get(1).is_some_and(|value| value == "api")
            && !stem.starts_with('_')
        {
            let mut segments = components[1..components.len() - 1].to_vec();
            if stem != "index" {
                segments.push(stem.into());
            }
            (
                Framework::NextPagesRouter,
                RouteKind::ApiRoute,
                Some(next_route_path(&segments)),
                vec![],
                MethodEvidence::Unknown,
                vec!["Pages Router handler methods require control-flow analysis".into()],
            )
        } else if components.first().is_some_and(|value| value == "pages") && !stem.starts_with('_')
        {
            let mut segments = components[1..components.len() - 1].to_vec();
            if stem != "index" {
                segments.push(stem.into());
            }
            (
                Framework::NextPagesRouter,
                RouteKind::PageRoute,
                Some(next_route_path(&segments)),
                vec![HttpMethod::Get],
                MethodEvidence::FrameworkDefault,
                vec![],
            )
        } else if components.len() == 1 && stem == "middleware" {
            (
                Framework::NextShared,
                RouteKind::Middleware,
                None,
                vec![],
                MethodEvidence::NotApplicable,
                vec!["Middleware matcher extraction is not implemented in v1".into()],
            )
        } else if has_use_server_directive(content) {
            (
                Framework::NextAppRouter,
                RouteKind::ServerAction,
                None,
                vec![HttpMethod::Post],
                MethodEvidence::FrameworkDefault,
                vec!["Server action reachability requires call-site analysis".into()],
            )
        } else {
            return None;
        };

    let parameters = route
        .as_deref()
        .map(extract_path_parameters)
        .unwrap_or_default();
    let mut record = RouteRecord {
        route_id: String::new(),
        framework,
        kind,
        method_evidence,
        methods,
        route,
        parameters,
        presence: ApiPresence {
            implemented: true,
            documented: EvidenceState::Unknown,
            observed: EvidenceState::Unknown,
        },
        controls: RouteControls {
            access: AccessLevel::Unknown,
            authentication: EvidenceState::Unknown,
            authorization: EvidenceState::Unknown,
            owner_scope: EvidenceState::Unknown,
            tenant_scope: EvidenceState::Unknown,
        },
        response_fields: vec![],
        source: SourceLocation {
            source_id: source_id.into(),
            path: relative.into(),
            sha256: String::new(),
            line: Some(1),
        },
        evidence: vec![EvidenceAnchor {
            kind: EvidenceKind::Code,
            reference: relative.into(),
            description: "framework route convention".into(),
        }],
        limitations,
    };
    record.methods.sort();
    record.methods.dedup();
    Some(record)
}

fn next_route_path(segments: &[String]) -> String {
    let normalized = segments
        .iter()
        .filter_map(|segment| normalize_segment(segment))
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        "/".into()
    } else {
        format!("/{}", normalized.join("/"))
    }
}

fn normalize_segment(segment: &str) -> Option<String> {
    if (segment.starts_with('(') && segment.ends_with(')')) || segment.starts_with('@') {
        return None;
    }
    let mut value = segment;
    for prefix in ["(...)", "(..)(..)", "(..)", "(.)"] {
        while let Some(stripped) = value.strip_prefix(prefix) {
            value = stripped;
        }
    }
    if value.starts_with("[[...") && value.ends_with("]]") {
        return Some(format!("{{{}*}}", &value[5..value.len() - 2]));
    }
    if value.starts_with("[...") && value.ends_with(']') {
        return Some(format!("{{{}+}}", &value[4..value.len() - 1]));
    }
    if value.starts_with('[') && value.ends_with(']') {
        return Some(format!("{{{}}}", &value[1..value.len() - 1]));
    }
    (!value.is_empty()).then(|| value.to_owned())
}

fn extract_path_parameters(route: &str) -> Vec<RouteParameter> {
    route
        .split('/')
        .filter_map(|segment| {
            let value = segment.strip_prefix('{')?.strip_suffix('}')?;
            let catch_all = value.ends_with('+') || value.ends_with('*');
            let required = !value.ends_with('*');
            let name = value.trim_end_matches(['+', '*']);
            (!name.is_empty()).then(|| RouteParameter {
                name: name.into(),
                location: ParameterLocation::Path,
                required,
                catch_all,
            })
        })
        .collect()
}

fn exported_http_methods(content: &[u8]) -> Vec<HttpMethod> {
    let tokens = javascript_identifiers(content);
    let mut methods = BTreeSet::new();
    for index in 0..tokens.len() {
        if tokens[index] != "export" {
            continue;
        }
        let mut cursor = index + 1;
        if tokens.get(cursor).is_some_and(|token| token == "async") {
            cursor += 1;
        }
        if !tokens
            .get(cursor)
            .is_some_and(|token| matches!(token.as_str(), "function" | "const" | "let" | "var"))
        {
            continue;
        }
        if let Some(method) = tokens.get(cursor + 1).and_then(|token| parse_method(token)) {
            methods.insert(method);
        }
    }
    methods.into_iter().collect()
}

fn javascript_identifiers(content: &[u8]) -> Vec<String> {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        LineComment,
        BlockComment,
        SingleQuote,
        DoubleQuote,
        Template,
    }
    let mut state = State::Code;
    let mut tokens = Vec::new();
    let mut current = Vec::new();
    let mut index = 0;
    while index < content.len() {
        let byte = content[index];
        match state {
            State::Code => {
                if byte == b'/' && content.get(index + 1) == Some(&b'/') {
                    flush_identifier(&mut current, &mut tokens);
                    state = State::LineComment;
                    index += 1;
                } else if byte == b'/' && content.get(index + 1) == Some(&b'*') {
                    flush_identifier(&mut current, &mut tokens);
                    state = State::BlockComment;
                    index += 1;
                } else if byte == b'\'' || byte == b'"' || byte == b'`' {
                    flush_identifier(&mut current, &mut tokens);
                    state = match byte {
                        b'\'' => State::SingleQuote,
                        b'"' => State::DoubleQuote,
                        _ => State::Template,
                    };
                } else if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' {
                    current.push(byte);
                } else {
                    flush_identifier(&mut current, &mut tokens);
                }
            }
            State::LineComment => {
                if byte == b'\n' {
                    state = State::Code;
                }
            }
            State::BlockComment => {
                if byte == b'*' && content.get(index + 1) == Some(&b'/') {
                    state = State::Code;
                    index += 1;
                }
            }
            State::SingleQuote | State::DoubleQuote | State::Template => {
                let terminator = match state {
                    State::SingleQuote => b'\'',
                    State::DoubleQuote => b'"',
                    _ => b'`',
                };
                if byte == b'\\' {
                    index += 1;
                } else if byte == terminator {
                    state = State::Code;
                }
            }
        }
        index += 1;
    }
    flush_identifier(&mut current, &mut tokens);
    tokens
}

fn flush_identifier(current: &mut Vec<u8>, tokens: &mut Vec<String>) {
    if !current.is_empty()
        && let Ok(token) = String::from_utf8(std::mem::take(current))
    {
        tokens.push(token);
    }
}

fn parse_method(value: &str) -> Option<HttpMethod> {
    match value {
        "GET" => Some(HttpMethod::Get),
        "HEAD" => Some(HttpMethod::Head),
        "POST" => Some(HttpMethod::Post),
        "PUT" => Some(HttpMethod::Put),
        "PATCH" => Some(HttpMethod::Patch),
        "DELETE" => Some(HttpMethod::Delete),
        "OPTIONS" => Some(HttpMethod::Options),
        _ => None,
    }
}

fn has_use_server_directive(content: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&content[..content.len().min(4096)]);
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("//"))
        .is_some_and(|line| {
            matches!(
                line,
                "\"use server\";" | "\"use server\"" | "'use server';" | "'use server'"
            )
        })
}

fn script_stem(file_name: &str) -> Option<&str> {
    for extension in [".tsx", ".ts", ".jsx", ".js", ".mjs", ".cjs"] {
        if let Some(stem) = file_name.strip_suffix(extension) {
            return (!stem.ends_with(".d")).then_some(stem);
        }
    }
    None
}

fn is_javascript_or_typescript(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .and_then(script_stem)
        .is_some()
}

fn is_ignored_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| matches!(name, ".git" | ".next" | "node_modules" | "target"))
}

fn relative_path(root: &Path, path: &Path) -> Result<String, InventoryError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| InventoryError::InvalidField("source path"))?;
    if relative.components().any(|component| {
        !matches!(component, Component::Normal(_))
            || component
                .as_os_str()
                .to_str()
                .is_none_or(|value| value.contains('\\') || value.contains('\0'))
    }) {
        return Err(InventoryError::InvalidField("source path"));
    }
    Ok(relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

pub(crate) fn validate_source(source: &InventorySource) -> Result<(), InventoryError> {
    if !valid_identifier(&source.source_id, "sf_web_source_")
        || source.source_id != expected_source_id(source)
        || !valid_text(&source.name, 200)
        || !valid_text(&source.revision, 200)
        || !valid_sha256(&source.sha256)
        || !valid_text(&source.license_spdx, 100)
    {
        return Err(InventoryError::InvalidField("source"));
    }
    Ok(())
}

fn validate_route(route: &RouteRecord, source_ids: &BTreeSet<&str>) -> Result<(), InventoryError> {
    if !valid_identifier(&route.route_id, "sf_web_route_")
        || route.route_id != expected_route_id(route)
        || route.methods.len() > 7
        || !route.methods.windows(2).all(|pair| pair[0] < pair[1])
        || !route.presence.implemented
        || !source_ids.contains(route.source.source_id.as_str())
        || !valid_relative_path(&route.source.path)
        || !valid_sha256(&route.source.sha256)
        || route.source.line == Some(0)
        || route.parameters.len() > 1_000
        || route.parameters.iter().collect::<BTreeSet<_>>().len() != route.parameters.len()
        || route.response_fields.len() > 10_000
        || !route
            .response_fields
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || route.evidence.is_empty()
        || route.evidence.len() > 100
        || !route.evidence.windows(2).all(|pair| pair[0] < pair[1])
        || route.limitations.len() > 100
        || !route.limitations.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(InventoryError::InvalidField("route"));
    }
    if let Some(path) = &route.route
        && (!path.starts_with('/') || path.len() > 2_000 || path.contains(".."))
    {
        return Err(InventoryError::InvalidField("route path"));
    }
    if matches!(route.kind, RouteKind::ApiRoute | RouteKind::PageRoute) != route.route.is_some() {
        return Err(InventoryError::InvalidField("route applicability"));
    }
    let expected_parameters = route
        .route
        .as_deref()
        .map(extract_path_parameters)
        .unwrap_or_default();
    if route.parameters != expected_parameters {
        return Err(InventoryError::InvalidField("route parameters"));
    }
    let valid_method_evidence = match route.method_evidence {
        MethodEvidence::DeclaredExport => {
            route.kind == RouteKind::ApiRoute && !route.methods.is_empty()
        }
        MethodEvidence::FrameworkDefault => matches!(
            (route.kind, route.methods.as_slice()),
            (RouteKind::PageRoute, [HttpMethod::Get])
                | (RouteKind::ServerAction, [HttpMethod::Post])
        ),
        MethodEvidence::Unknown => route.kind == RouteKind::ApiRoute && route.methods.is_empty(),
        MethodEvidence::NotApplicable => {
            route.kind == RouteKind::Middleware && route.methods.is_empty()
        }
    };
    if !valid_method_evidence {
        return Err(InventoryError::InvalidField("method evidence"));
    }
    for parameter in &route.parameters {
        if !valid_text(&parameter.name, 300) {
            return Err(InventoryError::InvalidField("route parameter"));
        }
    }
    for field in &route.response_fields {
        if !valid_text(&field.name, 300) {
            return Err(InventoryError::InvalidField("response field"));
        }
    }
    for evidence in &route.evidence {
        if !valid_text(&evidence.reference, 500) || !valid_text(&evidence.description, 1_000) {
            return Err(InventoryError::InvalidField("route evidence"));
        }
    }
    for limitation in &route.limitations {
        if !valid_text(limitation, 500) {
            return Err(InventoryError::InvalidField("route limitation"));
        }
    }
    Ok(())
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

fn expected_route_id(route: &RouteRecord) -> String {
    let mut stable = route.clone();
    stable.route_id.clear();
    format!(
        "sf_web_route_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("route serialization"))
    )
}

fn expected_source_id(source: &InventorySource) -> String {
    let mut stable = source.clone();
    stable.source_id.clear();
    format!(
        "sf_web_source_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("source serialization"))
    )
}

fn expected_inventory_id(inventory: &WebInventory) -> String {
    let mut stable = inventory.clone();
    stable.inventory_id.clear();
    stable.generated_at.clear();
    format!(
        "sf_web_inventory_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("inventory serialization"))
    )
}

fn valid_identifier(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_named_app_router_methods_without_comments_or_strings() {
        let methods = exported_http_methods(
            br#"
            // export function DELETE() {}
            const decoy = "export const PATCH = handler";
            export async function GET() {}
            export const POST = handler;
            "#,
        );
        assert_eq!(methods, vec![HttpMethod::Get, HttpMethod::Post]);
    }

    #[test]
    fn normalizes_next_dynamic_segments() {
        assert_eq!(
            next_route_path(&[
                "(admin)".into(),
                "users".into(),
                "[id]".into(),
                "[[...rest]]".into(),
            ]),
            "/users/{id}/{rest*}"
        );
    }

    #[test]
    fn rejects_path_traversal_and_windows_separators() {
        assert!(!valid_relative_path("../secret.ts"));
        assert!(!valid_relative_path("app\\route.ts"));
        assert!(valid_relative_path("app/api/route.ts"));
    }

    #[test]
    fn source_identity_is_bound_to_provenance_fields() {
        let mut source = InventorySource::new(
            SourceKind::Repository,
            "fixture".into(),
            "revision-1".into(),
            "1".repeat(64),
            "MIT".into(),
        )
        .expect("source");
        assert!(validate_source(&source).is_ok());
        source.revision = "revision-2".into();
        assert!(matches!(
            validate_source(&source),
            Err(InventoryError::InvalidField("source"))
        ));
    }
}
