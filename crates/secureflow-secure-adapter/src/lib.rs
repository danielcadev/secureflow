//! Strict, local-only import boundary for Secure Skill review-contract 1.1.
//!
//! Imported findings remain contextual candidates. This adapter never turns a
//! Secure Skill assessment into a human-validated SecureFlow finding.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};
use std::process::Command;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const ENVELOPE_VERSION: &str = "secureflow-secure-review-v1";
pub const UPSTREAM_SCHEMA_VERSION: &str = "1.1";
pub const UPSTREAM_SCHEMA_ID: &str = "urn:usesecure:review-contract:1.1";
pub const MAX_REVIEW_BYTES: u64 = 16 * 1024 * 1024;

const MAX_PACKAGE_BYTES: u64 = 256 * 1024;
const MAX_SKILL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CONTRACT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_LICENSE_BYTES: u64 = 512 * 1024;
const MAX_ITEMS: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureReviewEnvelope {
    pub contract_version: String,
    pub import_id: String,
    pub imported_at: String,
    pub linked_run_id: String,
    pub target_sha256: String,
    pub payload_sha256: String,
    pub payload_bytes: u64,
    pub source: SecureSkillProvenance,
    pub semantics: AssessmentSemantics,
    pub review: SecureReview,
}

impl SecureReviewEnvelope {
    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.contract_version != ENVELOPE_VERSION {
            return Err(AdapterError::UnsupportedEnvelope(
                self.contract_version.clone(),
            ));
        }
        if !valid_prefixed_hash(&self.import_id, "sf_secure_review_") {
            return Err(AdapterError::InvalidField("import_id"));
        }
        parse_timestamp(&self.imported_at, "imported_at")?;
        validate_run_id(&self.linked_run_id)?;
        validate_sha256(&self.target_sha256, "target_sha256")?;
        validate_sha256(&self.payload_sha256, "payload_sha256")?;
        if self.payload_bytes == 0 || self.payload_bytes > MAX_REVIEW_BYTES {
            return Err(AdapterError::InvalidField("payload_bytes"));
        }
        self.source.validate()?;
        self.semantics.validate()?;
        self.review.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureSkillProvenance {
    pub name: String,
    pub version: String,
    pub revision: String,
    pub skill_sha256: String,
    pub review_contract_schema: String,
    pub review_contract_sha256: String,
    pub license_spdx: String,
    pub license_sha256: String,
}

impl SecureSkillProvenance {
    fn validate(&self) -> Result<(), AdapterError> {
        if self.name != "secure-skill" {
            return Err(AdapterError::UnsupportedSource(self.name.clone()));
        }
        validate_text(&self.version, "source.version", 100)?;
        if !is_lower_hex_of_length(&self.revision, 40)
            && !is_lower_hex_of_length(&self.revision, 64)
        {
            return Err(AdapterError::InvalidField("source.revision"));
        }
        validate_sha256(&self.skill_sha256, "source.skill_sha256")?;
        if self.review_contract_schema != UPSTREAM_SCHEMA_VERSION {
            return Err(AdapterError::UnsupportedReviewSchema(
                self.review_contract_schema.clone(),
            ));
        }
        validate_sha256(
            &self.review_contract_sha256,
            "source.review_contract_sha256",
        )?;
        validate_text(&self.license_spdx, "source.license_spdx", 100)?;
        validate_sha256(&self.license_sha256, "source.license_sha256")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentSemantics {
    pub imported_findings_are: ImportedFindingClass,
    pub validation_authority: ValidationAuthority,
    pub no_findings_mean_safe: bool,
}

impl AssessmentSemantics {
    fn contextual_only() -> Self {
        Self {
            imported_findings_are: ImportedFindingClass::ContextualCandidates,
            validation_authority: ValidationAuthority::HumanOnly,
            no_findings_mean_safe: false,
        }
    }

    fn validate(&self) -> Result<(), AdapterError> {
        if self.imported_findings_are != ImportedFindingClass::ContextualCandidates
            || self.validation_authority != ValidationAuthority::HumanOnly
            || self.no_findings_mean_safe
        {
            return Err(AdapterError::InvalidSemantics);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportedFindingClass {
    ContextualCandidates,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationAuthority {
    HumanOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureReview {
    pub schema_version: String,
    pub mode: ReviewMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<ReviewAuthorization>,
    pub scope: ReviewScope,
    pub findings: Vec<ReviewFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub non_findings: Vec<NonFinding>,
    pub verification: Vec<VerificationCheck>,
    pub coverage: Coverage,
    pub residual_risk: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_model: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<serde_json::Value>,
}

impl SecureReview {
    pub fn validate(&self) -> Result<(), AdapterError> {
        if self.schema_version != UPSTREAM_SCHEMA_VERSION {
            return Err(AdapterError::UnsupportedReviewSchema(
                self.schema_version.clone(),
            ));
        }
        if self.mode == ReviewMode::Fix
            && (self.authorization != Some(ReviewAuthorization::Explicit)
                || self.remediation.is_none())
        {
            return Err(AdapterError::InvalidModeContract(
                "fix requires explicit authorization and remediation",
            ));
        }
        if self.mode == ReviewMode::ThreatModel && self.threat_model.is_none() {
            return Err(AdapterError::InvalidModeContract(
                "threat-model requires threat_model",
            ));
        }
        self.scope.validate()?;
        validate_count(self.findings.len(), "findings")?;
        let mut finding_ids = BTreeSet::new();
        for finding in &self.findings {
            finding.validate()?;
            if !finding_ids.insert(&finding.id) {
                return Err(AdapterError::DuplicateFindingId(finding.id.clone()));
            }
        }
        validate_count(self.non_findings.len(), "non_findings")?;
        for non_finding in &self.non_findings {
            non_finding.validate()?;
        }
        validate_count(self.verification.len(), "verification")?;
        for check in &self.verification {
            check.validate()?;
        }
        self.coverage.validate()?;
        validate_string_list(&self.residual_risk, "residual_risk", 4_000, false)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewMode {
    Review,
    DiffReview,
    Audit,
    ThreatModel,
    Fix,
    Verify,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewAuthorization {
    ReadOnly,
    Explicit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewScope {
    pub paths: Vec<String>,
    pub basis: String,
    pub exclusions: Vec<String>,
}

impl ReviewScope {
    fn validate(&self) -> Result<(), AdapterError> {
        validate_path_list(&self.paths, "scope.paths")?;
        validate_text(&self.basis, "scope.basis", 2_000)?;
        validate_path_list(&self.exclusions, "scope.exclusions")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewFinding {
    pub id: String,
    pub severity: ReviewSeverity,
    pub confidence: ReviewConfidence,
    pub title: String,
    pub location: ReviewLocation,
    pub evidence: String,
    pub invariant: String,
    pub source_to_sink: String,
    pub attacker_path: AttackerPath,
    pub impact: String,
    pub prerequisites: Vec<String>,
    pub recommendation: String,
    pub verification_status: VerificationStatus,
    pub residual_risk: String,
}

impl ReviewFinding {
    fn validate(&self) -> Result<(), AdapterError> {
        if !valid_secure_finding_id(&self.id) {
            return Err(AdapterError::InvalidField("finding.id"));
        }
        validate_text(&self.title, "finding.title", 500)?;
        self.location.validate()?;
        validate_text(&self.evidence, "finding.evidence", 20_000)?;
        validate_text(&self.invariant, "finding.invariant", 4_000)?;
        validate_text(&self.source_to_sink, "finding.source_to_sink", 10_000)?;
        self.attacker_path.validate()?;
        validate_text(&self.impact, "finding.impact", 10_000)?;
        validate_string_list(&self.prerequisites, "finding.prerequisites", 4_000, false)?;
        validate_text(&self.recommendation, "finding.recommendation", 10_000)?;
        validate_text(&self.residual_risk, "finding.residual_risk", 10_000)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewConfidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLocation {
    pub file: String,
    pub line: Option<u64>,
    pub symbol: Option<String>,
}

impl ReviewLocation {
    fn validate(&self) -> Result<(), AdapterError> {
        validate_relative_path(&self.file, "finding.location.file")?;
        if self.line == Some(0) {
            return Err(AdapterError::InvalidField("finding.location.line"));
        }
        validate_optional_text(self.symbol.as_deref(), "finding.location.symbol", 500)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttackerPath {
    pub actor: String,
    pub required_access: Vec<String>,
    pub controlled_input: String,
    pub victim_action: String,
    pub steps: Vec<String>,
    pub achieved_result: String,
    pub limitations: Vec<String>,
}

impl AttackerPath {
    fn validate(&self) -> Result<(), AdapterError> {
        validate_text(&self.actor, "finding.attacker_path.actor", 2_000)?;
        validate_string_list(
            &self.required_access,
            "finding.attacker_path.required_access",
            4_000,
            true,
        )?;
        validate_text(
            &self.controlled_input,
            "finding.attacker_path.controlled_input",
            4_000,
        )?;
        validate_text(
            &self.victim_action,
            "finding.attacker_path.victim_action",
            4_000,
        )?;
        validate_string_list(&self.steps, "finding.attacker_path.steps", 4_000, true)?;
        validate_text(
            &self.achieved_result,
            "finding.attacker_path.achieved_result",
            4_000,
        )?;
        validate_string_list(
            &self.limitations,
            "finding.attacker_path.limitations",
            4_000,
            false,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationStatus {
    Verified,
    Unverified,
    Fixed,
    RetestFailed,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonFinding {
    pub classification: NonFindingClassification,
    pub title: String,
    pub evidence: String,
    pub missing_gate: String,
    pub next_step: String,
}

impl NonFinding {
    fn validate(&self) -> Result<(), AdapterError> {
        validate_text(&self.title, "non_finding.title", 500)?;
        validate_text(&self.evidence, "non_finding.evidence", 10_000)?;
        validate_text(&self.missing_gate, "non_finding.missing_gate", 4_000)?;
        validate_text(&self.next_step, "non_finding.next_step", 4_000)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NonFindingClassification {
    UnverifiedLead,
    Hardening,
    Correctness,
    CompatibilityQuestion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationCheck {
    pub check: String,
    pub status: VerificationCheckStatus,
    pub summary: String,
}

impl VerificationCheck {
    fn validate(&self) -> Result<(), AdapterError> {
        validate_text(&self.check, "verification.check", 1_000)?;
        validate_text(&self.summary, "verification.summary", 4_000)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationCheckStatus {
    Passed,
    Failed,
    NotRun,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub reviewed: Vec<String>,
    pub not_reviewed: Vec<String>,
}

impl Coverage {
    fn validate(&self) -> Result<(), AdapterError> {
        validate_string_list(&self.reviewed, "coverage.reviewed", 2_000, false)?;
        validate_string_list(&self.not_reviewed, "coverage.not_reviewed", 2_000, false)
    }
}

#[derive(Clone, Debug)]
pub struct ImportContext {
    pub imported_at: String,
    pub linked_run_id: String,
    pub target_sha256: String,
}

pub fn parse_review(bytes: &[u8]) -> Result<SecureReview, AdapterError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_REVIEW_BYTES {
        return Err(AdapterError::ReviewSize(bytes.len() as u64));
    }
    let review: SecureReview = serde_json::from_slice(bytes)?;
    review.validate()?;
    Ok(review)
}

pub fn parse_envelope(bytes: &[u8]) -> Result<SecureReviewEnvelope, AdapterError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_REVIEW_BYTES {
        return Err(AdapterError::ReviewSize(bytes.len() as u64));
    }
    let envelope: SecureReviewEnvelope = serde_json::from_slice(bytes)?;
    envelope.validate()?;
    Ok(envelope)
}

pub fn import_review(
    payload: &[u8],
    context: ImportContext,
    source: SecureSkillProvenance,
) -> Result<SecureReviewEnvelope, AdapterError> {
    let review = parse_review(payload)?;
    parse_timestamp(&context.imported_at, "imported_at")?;
    validate_run_id(&context.linked_run_id)?;
    validate_sha256(&context.target_sha256, "target_sha256")?;
    source.validate()?;
    let payload_sha256 = sha256_hex(payload);
    let import_hash = sha256_hex(
        format!(
            "{}\0{}\0{}\0{}",
            context.linked_run_id, context.target_sha256, payload_sha256, source.revision
        )
        .as_bytes(),
    );
    let envelope = SecureReviewEnvelope {
        contract_version: ENVELOPE_VERSION.into(),
        import_id: format!("sf_secure_review_{import_hash}"),
        imported_at: context.imported_at,
        linked_run_id: context.linked_run_id,
        target_sha256: context.target_sha256,
        payload_sha256,
        payload_bytes: payload.len() as u64,
        source,
        semantics: AssessmentSemantics::contextual_only(),
        review,
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Reads and fingerprints the canonical Secure Skill files without executing
/// repository code. Every resolved file must remain under the supplied root.
pub fn load_source_provenance(
    root: &Path,
    revision: &str,
) -> Result<SecureSkillProvenance, AdapterError> {
    let root = fs::canonicalize(root).map_err(|source| AdapterError::Read {
        path: root.display().to_string(),
        source,
    })?;
    verify_git_revision_if_present(&root, revision)?;
    let package = read_source_file(&root, Path::new("package.json"), MAX_PACKAGE_BYTES)?;
    let skill = read_source_file(&root, Path::new("skills/secure/SKILL.md"), MAX_SKILL_BYTES)?;
    let contract = read_source_file(
        &root,
        Path::new("skills/secure/references/review-contract.json"),
        MAX_CONTRACT_BYTES,
    )?;
    let license = read_source_file(&root, Path::new("LICENSE"), MAX_LICENSE_BYTES)?;

    let package: PackageMetadata = serde_json::from_slice(&package)?;
    if package.name != "secure-skill" {
        return Err(AdapterError::UnsupportedSource(package.name));
    }
    validate_text(&package.version, "source.version", 100)?;
    validate_text(&package.license, "source.license_spdx", 100)?;
    validate_review_contract_source(&contract)?;

    let source = SecureSkillProvenance {
        name: package.name,
        version: package.version,
        revision: revision.to_owned(),
        skill_sha256: sha256_hex(&skill),
        review_contract_schema: UPSTREAM_SCHEMA_VERSION.into(),
        review_contract_sha256: sha256_hex(&contract),
        license_spdx: package.license,
        license_sha256: sha256_hex(&license),
    };
    source.validate()?;
    Ok(source)
}

fn verify_git_revision_if_present(root: &Path, expected: &str) -> Result<(), AdapterError> {
    if !is_lower_hex_of_length(expected, 40) && !is_lower_hex_of_length(expected, 64) {
        return Err(AdapterError::InvalidField("source.revision"));
    }
    match fs::symlink_metadata(root.join(".git")) {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(AdapterError::Read {
                path: root.join(".git").display().to_string(),
                source,
            });
        }
    }
    let git = [Path::new("/usr/bin/git"), Path::new("/bin/git")]
        .into_iter()
        .find(|path| path.is_file())
        .ok_or(AdapterError::GitUnavailable)?;
    let output = Command::new(git)
        .args(["-C"])
        .arg(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .env_clear()
        .output()
        .map_err(AdapterError::GitRevisionRead)?;
    if !output.status.success() {
        return Err(AdapterError::GitRevisionUnavailable);
    }
    let actual = std::str::from_utf8(&output.stdout)
        .map_err(|_| AdapterError::GitRevisionUnavailable)?
        .trim();
    if actual != expected {
        return Err(AdapterError::GitRevisionMismatch {
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

pub fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, AdapterError> {
    let metadata = fs::metadata(path).map_err(|source| AdapterError::Read {
        path: path.display().to_string(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::NotAFile(path.display().to_string()));
    }
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(AdapterError::FileSize {
            path: path.display().to_string(),
            bytes: metadata.len(),
            maximum,
        });
    }
    let bytes = fs::read(path).map_err(|source| AdapterError::Read {
        path: path.display().to_string(),
        source,
    })?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(AdapterError::FileSize {
            path: path.display().to_string(),
            bytes: bytes.len() as u64,
            maximum,
        });
    }
    Ok(bytes)
}

fn read_source_file(root: &Path, relative: &Path, maximum: u64) -> Result<Vec<u8>, AdapterError> {
    let path = root.join(relative);
    let canonical = fs::canonicalize(&path).map_err(|source| AdapterError::Read {
        path: path.display().to_string(),
        source,
    })?;
    if !canonical.starts_with(root) {
        return Err(AdapterError::SourceEscapesRoot(
            relative.display().to_string(),
        ));
    }
    read_bounded(&canonical, maximum)
}

fn validate_review_contract_source(bytes: &[u8]) -> Result<(), AdapterError> {
    let contract: serde_json::Value = serde_json::from_slice(bytes)?;
    if contract.get("$id").and_then(serde_json::Value::as_str) != Some(UPSTREAM_SCHEMA_ID)
        || contract
            .pointer("/properties/schema_version/const")
            .and_then(serde_json::Value::as_str)
            != Some(UPSTREAM_SCHEMA_VERSION)
    {
        return Err(AdapterError::InvalidSourceContract);
    }
    Ok(())
}

fn validate_run_id(value: &str) -> Result<(), AdapterError> {
    let suffix = value.strip_prefix("sf_run_").unwrap_or_default();
    if !(16..=80).contains(&suffix.len())
        || !suffix
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(AdapterError::InvalidField("linked_run_id"));
    }
    Ok(())
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| is_lower_hex_of_length(suffix, 64))
}

fn valid_secure_finding_id(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("SEC-") else {
        return false;
    };
    (3..=20).contains(&suffix.len()) && suffix.chars().all(|character| character.is_ascii_digit())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), AdapterError> {
    if !is_lower_hex_of_length(value, 64) {
        return Err(AdapterError::InvalidField(field));
    }
    Ok(())
}

fn is_lower_hex_of_length(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_timestamp(value: &str, field: &'static str) -> Result<OffsetDateTime, AdapterError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AdapterError::InvalidField(field))
}

fn validate_count(count: usize, field: &'static str) -> Result<(), AdapterError> {
    if count > MAX_ITEMS {
        return Err(AdapterError::TooManyItems(field));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<(), AdapterError> {
    if value.trim().is_empty()
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(AdapterError::InvalidField(field));
    }
    if value.chars().count() > maximum {
        return Err(AdapterError::FieldTooLong(field));
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    field: &'static str,
    maximum: usize,
) -> Result<(), AdapterError> {
    if let Some(value) = value {
        validate_text(value, field, maximum)?;
    }
    Ok(())
}

fn validate_string_list(
    values: &[String],
    field: &'static str,
    maximum: usize,
    require_one: bool,
) -> Result<(), AdapterError> {
    validate_count(values.len(), field)?;
    if require_one && values.is_empty() {
        return Err(AdapterError::InvalidField(field));
    }
    for value in values {
        validate_text(value, field, maximum)?;
    }
    Ok(())
}

fn validate_path_list(values: &[String], field: &'static str) -> Result<(), AdapterError> {
    validate_count(values.len(), field)?;
    for value in values {
        validate_relative_path(value, field)?;
    }
    Ok(())
}

fn validate_relative_path(value: &str, field: &'static str) -> Result<(), AdapterError> {
    if value.trim().is_empty()
        || value.chars().count() > 2_000
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || Path::new(value).is_absolute()
        || Path::new(value).components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(AdapterError::InvalidPath(field));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in digest.as_slice() {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Deserialize)]
struct PackageMetadata {
    name: String,
    version: String,
    license: String,
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("expected a regular file: {0}")]
    NotAFile(String),
    #[error("file size is outside limits for {path}: {bytes} bytes (maximum {maximum})")]
    FileSize {
        path: String,
        bytes: u64,
        maximum: u64,
    },
    #[error("review payload size is outside limits: {0} bytes")]
    ReviewSize(u64),
    #[error("Secure Skill source file resolves outside its root: {0}")]
    SourceEscapesRoot(String),
    #[error("Git is unavailable for source revision verification")]
    GitUnavailable,
    #[error("could not read the source Git revision: {0}")]
    GitRevisionRead(#[source] std::io::Error),
    #[error("could not resolve the source Git HEAD")]
    GitRevisionUnavailable,
    #[error("source Git revision mismatch: expected {expected}, actual {actual}")]
    GitRevisionMismatch { expected: String, actual: String },
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported SecureFlow review envelope: {0}")]
    UnsupportedEnvelope(String),
    #[error("unsupported Secure Skill review schema: {0}")]
    UnsupportedReviewSchema(String),
    #[error("unsupported review source: {0}")]
    UnsupportedSource(String),
    #[error("Secure Skill review-contract source does not identify schema 1.1")]
    InvalidSourceContract,
    #[error("invalid review mode contract: {0}")]
    InvalidModeContract(&'static str),
    #[error("duplicate Secure Skill finding ID: {0}")]
    DuplicateFindingId(String),
    #[error("invalid contextual assessment semantics")]
    InvalidSemantics,
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("field is too long: {0}")]
    FieldTooLong(&'static str),
    #[error("too many items: {0}")]
    TooManyItems(&'static str),
    #[error("path is not target-relative: {0}")]
    InvalidPath(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review_json() -> Vec<u8> {
        br#"{
          "schema_version":"1.1",
          "mode":"review",
          "authorization":"read-only",
          "scope":{"paths":["src/auth.rs"],"basis":"authorized local review","exclusions":["vendor"]},
          "findings":[{
            "id":"SEC-001","severity":"high","confidence":"medium","title":"Tenant guard is missing",
            "location":{"file":"src/auth.rs","line":42,"symbol":"update_record"},
            "evidence":"The lookup uses the object ID only.","invariant":"Tenant scope must dominate writes.",
            "source_to_sink":"request id -> lookup -> update",
            "attacker_path":{"actor":"tenant member","required_access":["authenticated session"],"controlled_input":"object id","victim_action":"none","steps":["submit another tenant ID"],"achieved_result":"cross-tenant update","limitations":["requires a known ID"]},
            "impact":"Cross-tenant modification.","prerequisites":["known object ID"],"recommendation":"Scope the update by tenant.","verification_status":"unverified","residual_risk":"Equivalent jobs were not reviewed."
          }],
          "verification":[{"check":"source inspection","status":"passed","summary":"Relevant path was read."}],
          "coverage":{"reviewed":["auth write path"],"not_reviewed":["background jobs"]},
          "residual_risk":["Runtime behavior was not exercised."]
        }"#.to_vec()
    }

    fn provenance() -> SecureSkillProvenance {
        SecureSkillProvenance {
            name: "secure-skill".into(),
            version: "2.0.0".into(),
            revision: "a".repeat(40),
            skill_sha256: "b".repeat(64),
            review_contract_schema: "1.1".into(),
            review_contract_sha256: "c".repeat(64),
            license_spdx: "MIT".into(),
            license_sha256: "d".repeat(64),
        }
    }

    fn context() -> ImportContext {
        ImportContext {
            imported_at: "2026-08-23T12:00:00Z".into(),
            linked_run_id: "sf_run_1234567890abcdef".into(),
            target_sha256: "e".repeat(64),
        }
    }

    #[test]
    fn imports_candidates_without_granting_validation_authority() {
        let envelope = import_review(&review_json(), context(), provenance()).unwrap();
        assert_eq!(envelope.review.findings.len(), 1);
        assert_eq!(
            envelope.semantics.validation_authority,
            ValidationAuthority::HumanOnly
        );
        assert_eq!(
            envelope.semantics.imported_findings_are,
            ImportedFindingClass::ContextualCandidates
        );
        assert!(!envelope.semantics.no_findings_mean_safe);
    }

    #[test]
    fn import_id_is_stable_for_the_same_inputs() {
        let first = import_review(&review_json(), context(), provenance()).unwrap();
        let second = import_review(&review_json(), context(), provenance()).unwrap();
        assert_eq!(first.import_id, second.import_id);
    }

    #[test]
    fn rejects_unknown_fields() {
        let input = String::from_utf8(review_json()).unwrap().replace(
            "\"schema_version\":\"1.1\"",
            "\"schema_version\":\"1.1\",\"validated\":true",
        );
        assert!(matches!(
            parse_review(input.as_bytes()),
            Err(AdapterError::Json(_))
        ));
    }

    #[test]
    fn rejects_parent_traversal_in_finding_location() {
        let input = String::from_utf8(review_json())
            .unwrap()
            .replace("src/auth.rs", "../outside.rs");
        assert!(matches!(
            parse_review(input.as_bytes()),
            Err(AdapterError::InvalidPath(_))
        ));
    }

    #[test]
    fn rejects_duplicate_finding_ids() {
        let mut review = parse_review(&review_json()).unwrap();
        review.findings.push(review.findings[0].clone());
        assert!(matches!(
            review.validate(),
            Err(AdapterError::DuplicateFindingId(_))
        ));
    }

    #[test]
    fn fix_mode_requires_explicit_authorization_and_remediation() {
        let input = String::from_utf8(review_json())
            .unwrap()
            .replace("\"mode\":\"review\"", "\"mode\":\"fix\"");
        assert!(matches!(
            parse_review(input.as_bytes()),
            Err(AdapterError::InvalidModeContract(_))
        ));
    }

    #[test]
    fn envelope_rejects_claim_that_no_findings_means_safe() {
        let mut envelope = import_review(&review_json(), context(), provenance()).unwrap();
        envelope.semantics.no_findings_mean_safe = true;
        assert!(matches!(
            envelope.validate(),
            Err(AdapterError::InvalidSemantics)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_declared_revision_that_does_not_match_git_head() {
        let git = Path::new("/usr/bin/git");
        if !git.is_file() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "secureflow-skill-git-revision-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("temporary repository should be created");
        assert!(
            Command::new(git)
                .args(["init", "-q"])
                .arg(&root)
                .status()
                .expect("git init")
                .success()
        );
        std::fs::write(root.join("tracked"), "content\n").expect("tracked file");
        assert!(
            Command::new(git)
                .args(["-C"])
                .arg(&root)
                .args(["add", "tracked"])
                .status()
                .expect("git add")
                .success()
        );
        assert!(
            Command::new(git)
                .args(["-C"])
                .arg(&root)
                .args([
                    "-c",
                    "user.name=SecureFlow Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ])
                .status()
                .expect("git commit")
                .success()
        );
        assert!(matches!(
            verify_git_revision_if_present(&root, &"a".repeat(40)),
            Err(AdapterError::GitRevisionMismatch { .. })
        ));
        std::fs::remove_dir_all(root).expect("temporary repository should be removable");
    }
}
