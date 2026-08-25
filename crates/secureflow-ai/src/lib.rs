//! Offline preparation and accounting for optional AI assistance.
//!
//! This crate contains no network client. It minimizes and redacts one finding,
//! records explicit budgets, and can attach a structured advisory response to a
//! derived run manifest without changing human review state.

use secureflow_model::{
    AiAssessment, AiValidationStatus, Confidence, EvidenceKind, RunManifest, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const REQUEST_VERSION: &str = "secureflow-ai-request-v1";
pub const RESPONSE_VERSION: &str = "secureflow-ai-response-v1";
pub const REDACTION_VERSION: &str = "secureflow-redaction-v1";
pub const PROMPT_VERSION: &str = "secureflow-ai-triage-v1";
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_INPUT_TOKENS: u64 = 6_000;
pub const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 1_000;
pub const DEFAULT_MAX_PAYLOAD_BYTES: u64 = 16_384;
pub const RESERVED_PROMPT_TOKENS: u64 = 700;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiRequestEnvelope {
    pub contract_version: String,
    pub request_id: String,
    pub created_at: String,
    pub linked_run_id: String,
    pub target_sha256: String,
    pub finding_id: String,
    pub purpose: AiPurpose,
    pub provider: String,
    pub model_family: ModelFamily,
    pub prompt_version: String,
    pub budget: AiBudget,
    pub data_policy: DataPolicy,
    pub escalation: EscalationPolicy,
    pub authority: AdvisoryAuthority,
    pub payload_sha256: String,
    pub payload_bytes: u64,
    pub payload: RedactedFinding,
}

impl AiRequestEnvelope {
    pub fn validate(&self) -> Result<(), AiError> {
        if self.contract_version != REQUEST_VERSION {
            return Err(AiError::UnsupportedRequest(self.contract_version.clone()));
        }
        if !valid_prefixed_hash(&self.request_id, "sf_ai_request_") {
            return Err(AiError::InvalidField("request_id"));
        }
        validate_timestamp(&self.created_at, "created_at")?;
        validate_prefixed_identifier(&self.linked_run_id, "sf_run_", "linked_run_id")?;
        validate_sha256(&self.target_sha256, "target_sha256")?;
        validate_prefixed_identifier(&self.finding_id, "sf_finding_", "finding_id")?;
        if self.provider != "openai" {
            return Err(AiError::InvalidField("provider"));
        }
        if self.model_family != ModelFamily::Luna || self.prompt_version != PROMPT_VERSION {
            return Err(AiError::InvalidRouting);
        }
        self.budget.validate()?;
        self.data_policy.validate()?;
        self.escalation.validate()?;
        self.authority.validate()?;
        self.payload.validate()?;
        let payload_bytes = serde_json::to_vec(&self.payload)?;
        if self.payload_bytes != payload_bytes.len() as u64
            || self.payload_sha256 != sha256_hex(&payload_bytes)
        {
            return Err(AiError::PayloadFingerprintMismatch);
        }
        if self.payload_bytes > self.budget.max_payload_bytes
            || self.budget.payload_token_upper_bound != self.payload_bytes
            || self
                .budget
                .payload_token_upper_bound
                .saturating_add(self.budget.reserved_prompt_tokens)
                > self.budget.max_input_tokens
        {
            return Err(AiError::BudgetExceeded("prepared payload"));
        }
        let expected_request_id = request_id(
            &self.linked_run_id,
            &self.target_sha256,
            &self.finding_id,
            &self.payload_sha256,
            &self.created_at,
            self.purpose,
            self.data_policy.redaction_events,
            &self.budget,
        );
        if self.request_id != expected_request_id {
            return Err(AiError::RequestFingerprintMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AiPurpose {
    AmbiguityAnalysis,
    CandidatePrioritization,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFamily {
    Luna,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiBudget {
    pub max_calls: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_payload_bytes: u64,
    pub reserved_prompt_tokens: u64,
    pub payload_token_upper_bound: u64,
    pub token_bound_method: String,
}

impl AiBudget {
    fn validate(&self) -> Result<(), AiError> {
        if self.max_calls != 1
            || !(1_000..=200_000).contains(&self.max_input_tokens)
            || !(1..=20_000).contains(&self.max_output_tokens)
            || !(256..=262_144).contains(&self.max_payload_bytes)
            || self.reserved_prompt_tokens != RESERVED_PROMPT_TOKENS
            || self.token_bound_method != "utf8-bytes-conservative-upper-bound"
        {
            return Err(AiError::InvalidBudget);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataPolicy {
    pub local_preparation_only: bool,
    pub source_code_included: bool,
    pub evidence_descriptions_included: bool,
    pub secret_redaction_enabled: bool,
    pub external_transmission_consented: bool,
    pub redaction_version: String,
    pub redaction_events: u64,
}

impl DataPolicy {
    fn validate(&self) -> Result<(), AiError> {
        if !self.local_preparation_only
            || self.source_code_included
            || self.evidence_descriptions_included
            || !self.secret_redaction_enabled
            || !self.external_transmission_consented
            || self.redaction_version != REDACTION_VERSION
        {
            return Err(AiError::InvalidDataPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationPolicy {
    pub policy: EscalationKind,
    pub automatic: bool,
    pub max_escalations: u64,
    pub requires_human_approval: bool,
}

impl EscalationPolicy {
    fn restricted() -> Self {
        Self {
            policy: EscalationKind::OnlyIfAmbiguous,
            automatic: false,
            max_escalations: 1,
            requires_human_approval: true,
        }
    }

    fn validate(&self) -> Result<(), AiError> {
        if self.policy != EscalationKind::OnlyIfAmbiguous
            || self.automatic
            || self.max_escalations != 1
            || !self.requires_human_approval
        {
            return Err(AiError::InvalidEscalation);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EscalationKind {
    OnlyIfAmbiguous,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryAuthority {
    pub assessment_role: AssessmentRole,
    pub validation_authority: ValidationAuthority,
    pub can_change_human_decision: bool,
}

impl AdvisoryAuthority {
    fn advisory_only() -> Self {
        Self {
            assessment_role: AssessmentRole::AdvisoryOnly,
            validation_authority: ValidationAuthority::HumanOnly,
            can_change_human_decision: false,
        }
    }

    fn validate(&self) -> Result<(), AiError> {
        if self.assessment_role != AssessmentRole::AdvisoryOnly
            || self.validation_authority != ValidationAuthority::HumanOnly
            || self.can_change_human_decision
        {
            return Err(AiError::InvalidAuthority);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssessmentRole {
    AdvisoryOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationAuthority {
    HumanOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedFinding {
    pub title: String,
    pub rule_id: String,
    pub taxonomy: Option<RedactedTaxonomy>,
    pub severity: Option<Severity>,
    pub confidence: Confidence,
    pub source: RedactedLocation,
    pub sink: RedactedLocation,
    pub invariant: String,
    pub evidence_path: Vec<RedactedEvidenceStep>,
    pub limitations: Vec<String>,
    pub excluded_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedTaxonomy {
    pub version: String,
    pub category_id: String,
    pub invariant_id: String,
}

impl RedactedTaxonomy {
    fn validate(&self) -> Result<(), AiError> {
        validate_text(&self.version, "payload.taxonomy.version", 50)?;
        validate_text(&self.category_id, "payload.taxonomy.category_id", 100)?;
        validate_text(&self.invariant_id, "payload.taxonomy.invariant_id", 100)
    }
}

impl RedactedFinding {
    fn validate(&self) -> Result<(), AiError> {
        validate_text(&self.title, "payload.title", 300)?;
        validate_text(&self.rule_id, "payload.rule_id", 100)?;
        if let Some(taxonomy) = &self.taxonomy {
            taxonomy.validate()?;
        }
        self.source.validate()?;
        self.sink.validate()?;
        validate_text(&self.invariant, "payload.invariant", 1_000)?;
        if self.evidence_path.is_empty() || self.evidence_path.len() > 1_000 {
            return Err(AiError::InvalidField("payload.evidence_path"));
        }
        for step in &self.evidence_path {
            step.location.validate()?;
        }
        if self.limitations.len() > 1_000 {
            return Err(AiError::InvalidField("payload.limitations"));
        }
        for value in &self.limitations {
            validate_text(value, "payload.limitations", 500)?;
        }
        let expected = [
            "source-code",
            "evidence-descriptions",
            "human-review-metadata",
            "absolute-paths",
        ];
        if self.excluded_fields.iter().map(String::as_str).ne(expected) {
            return Err(AiError::InvalidField("payload.excluded_fields"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedLocation {
    pub path: String,
    pub line: u32,
    pub column: u32,
}

impl RedactedLocation {
    fn validate(&self) -> Result<(), AiError> {
        validate_relative_path(&self.path, "payload.location.path")?;
        if self.line == 0 || self.column == 0 {
            return Err(AiError::InvalidField("payload.location"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedEvidenceStep {
    pub kind: EvidenceKind,
    pub location: RedactedLocation,
}

#[derive(Clone, Debug)]
pub struct PrepareOptions {
    pub enable_ai: bool,
    pub consent_redacted_export: bool,
    pub purpose: AiPurpose,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_payload_bytes: u64,
    pub created_at: String,
}

pub fn prepare_request(
    manifest: &RunManifest,
    finding_id: &str,
    options: PrepareOptions,
) -> Result<AiRequestEnvelope, AiError> {
    manifest.validate()?;
    if !options.enable_ai {
        return Err(AiError::AiDisabled);
    }
    if !options.consent_redacted_export {
        return Err(AiError::ConsentRequired);
    }
    validate_timestamp(&options.created_at, "created_at")?;
    let finding = manifest
        .findings
        .iter()
        .find(|finding| finding.finding_id == finding_id)
        .ok_or_else(|| AiError::FindingNotFound(finding_id.to_owned()))?;
    if finding.ai_validation.status != AiValidationStatus::NotRequested {
        return Err(AiError::AiAlreadyRequested(finding_id.to_owned()));
    }

    let mut redaction_events = 0_u64;
    let mut redact = |value: &str| {
        let (value, redacted) = redact_text(value);
        if redacted {
            redaction_events = redaction_events.saturating_add(1);
        }
        value
    };
    let source = RedactedLocation {
        path: redact(&finding.source_location.path),
        line: finding.source_location.start_line,
        column: finding.source_location.start_column,
    };
    let sink = RedactedLocation {
        path: redact(&finding.sink_location.path),
        line: finding.sink_location.start_line,
        column: finding.sink_location.start_column,
    };
    let evidence_path = finding
        .evidence_path
        .iter()
        .map(|step| RedactedEvidenceStep {
            kind: step.kind,
            location: RedactedLocation {
                path: redact(&step.location.path),
                line: step.location.start_line,
                column: step.location.start_column,
            },
        })
        .collect();
    let taxonomy = finding.taxonomy.as_ref().map(|taxonomy| RedactedTaxonomy {
        version: redact(&taxonomy.version),
        category_id: redact(&taxonomy.category_id),
        invariant_id: redact(&taxonomy.invariant_id),
    });
    let payload = RedactedFinding {
        title: redact(&finding.title),
        rule_id: redact(&finding.rule_id),
        taxonomy,
        severity: finding.severity,
        confidence: finding.confidence,
        source,
        sink,
        invariant: redact(&finding.invariant),
        evidence_path,
        limitations: finding
            .limitations
            .iter()
            .map(|value| redact(value))
            .collect(),
        excluded_fields: vec![
            "source-code".into(),
            "evidence-descriptions".into(),
            "human-review-metadata".into(),
            "absolute-paths".into(),
        ],
    };
    payload.validate()?;
    let payload_bytes = serde_json::to_vec(&payload)?;
    let payload_sha256 = sha256_hex(&payload_bytes);
    let budget = AiBudget {
        max_calls: 1,
        max_input_tokens: options.max_input_tokens,
        max_output_tokens: options.max_output_tokens,
        max_payload_bytes: options.max_payload_bytes,
        reserved_prompt_tokens: RESERVED_PROMPT_TOKENS,
        payload_token_upper_bound: payload_bytes.len() as u64,
        token_bound_method: "utf8-bytes-conservative-upper-bound".into(),
    };
    budget.validate()?;
    let data_policy = DataPolicy {
        local_preparation_only: true,
        source_code_included: false,
        evidence_descriptions_included: false,
        secret_redaction_enabled: true,
        external_transmission_consented: true,
        redaction_version: REDACTION_VERSION.into(),
        redaction_events,
    };
    let request = AiRequestEnvelope {
        contract_version: REQUEST_VERSION.into(),
        request_id: request_id(
            &manifest.run_id,
            &manifest.target.root_sha256,
            finding_id,
            &payload_sha256,
            &options.created_at,
            options.purpose,
            data_policy.redaction_events,
            &budget,
        ),
        created_at: options.created_at,
        linked_run_id: manifest.run_id.clone(),
        target_sha256: manifest.target.root_sha256.clone(),
        finding_id: finding_id.to_owned(),
        purpose: options.purpose,
        provider: "openai".into(),
        model_family: ModelFamily::Luna,
        prompt_version: PROMPT_VERSION.into(),
        budget,
        data_policy,
        escalation: EscalationPolicy::restricted(),
        authority: AdvisoryAuthority::advisory_only(),
        payload_sha256,
        payload_bytes: payload_bytes.len() as u64,
        payload,
    };
    request.validate()?;
    Ok(request)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiResponseEnvelope {
    pub contract_version: String,
    pub request_id: String,
    pub responded_at: String,
    pub provider: String,
    pub model_family: ModelFamily,
    pub prompt_version: String,
    pub request_payload_sha256: String,
    pub assessment: AiAssessment,
    pub analysis_summary: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub limitations: Vec<ResponseLimitation>,
    pub validation_authority: ValidationAuthority,
}

impl AiResponseEnvelope {
    pub fn validate(&self) -> Result<(), AiError> {
        if self.contract_version != RESPONSE_VERSION {
            return Err(AiError::UnsupportedResponse(self.contract_version.clone()));
        }
        if !valid_prefixed_hash(&self.request_id, "sf_ai_request_") {
            return Err(AiError::InvalidField("response.request_id"));
        }
        validate_timestamp(&self.responded_at, "response.responded_at")?;
        if self.provider != "openai"
            || self.model_family != ModelFamily::Luna
            || self.prompt_version != PROMPT_VERSION
            || self.validation_authority != ValidationAuthority::HumanOnly
        {
            return Err(AiError::InvalidRouting);
        }
        validate_sha256(
            &self.request_payload_sha256,
            "response.request_payload_sha256",
        )?;
        if self.input_tokens > 10_000_000 || self.output_tokens > 10_000_000 {
            return Err(AiError::InvalidField("response.tokens"));
        }
        validate_text(&self.analysis_summary, "response.analysis_summary", 8_000)?;
        if self.limitations.len() > 100 {
            return Err(AiError::InvalidField("response.limitations"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseLimitation {
    EvidenceInsufficient,
    RequiresRuntimeValidation,
    RequiresHumanContext,
    PossibleFalsePositive,
}

pub fn parse_request(bytes: &[u8]) -> Result<AiRequestEnvelope, AiError> {
    validate_document_size(bytes)?;
    let request: AiRequestEnvelope = serde_json::from_slice(bytes)?;
    request.validate()?;
    Ok(request)
}

pub fn parse_response(bytes: &[u8]) -> Result<AiResponseEnvelope, AiError> {
    validate_document_size(bytes)?;
    let response: AiResponseEnvelope = serde_json::from_slice(bytes)?;
    response.validate()?;
    Ok(response)
}

pub fn apply_response(
    manifest: &mut RunManifest,
    request: &AiRequestEnvelope,
    response: &AiResponseEnvelope,
    response_bytes: &[u8],
) -> Result<(), AiError> {
    manifest.validate()?;
    request.validate()?;
    response.validate()?;
    validate_document_size(response_bytes)?;
    if request.linked_run_id != manifest.run_id
        || request.target_sha256 != manifest.target.root_sha256
        || response.request_id != request.request_id
        || response.request_payload_sha256 != request.payload_sha256
        || response.provider != request.provider
        || response.model_family != request.model_family
        || response.prompt_version != request.prompt_version
    {
        return Err(AiError::ResponseLinkMismatch);
    }
    if response.input_tokens > request.budget.max_input_tokens
        || response.output_tokens > request.budget.max_output_tokens
    {
        return Err(AiError::BudgetExceeded("provider token usage"));
    }
    let finding_index = manifest
        .findings
        .iter()
        .position(|finding| finding.finding_id == request.finding_id)
        .ok_or_else(|| AiError::FindingNotFound(request.finding_id.clone()))?;
    if manifest.findings[finding_index].ai_validation.status != AiValidationStatus::NotRequested {
        return Err(AiError::AiAlreadyRequested(request.finding_id.clone()));
    }
    let mut derived = manifest.clone();
    let finding = &mut derived.findings[finding_index];
    let human_decision_before = finding.human_review.decision;
    finding.ai_validation.status = AiValidationStatus::Completed;
    finding.ai_validation.request_id = Some(request.request_id.clone());
    finding.ai_validation.provider = Some(request.provider.clone());
    finding.ai_validation.model = Some(model_label(request.model_family).into());
    finding.ai_validation.prompt_version = Some(request.prompt_version.clone());
    finding.ai_validation.redacted_payload_sha256 = Some(request.payload_sha256.clone());
    finding.ai_validation.response_sha256 = Some(sha256_hex(response_bytes));
    finding.ai_validation.input_tokens = Some(response.input_tokens);
    finding.ai_validation.output_tokens = Some(response.output_tokens);
    finding.ai_validation.assessment = Some(response.assessment);
    if finding.human_review.decision != human_decision_before {
        return Err(AiError::HumanDecisionChanged);
    }
    derived.refresh_summary();
    derived.validate()?;
    *manifest = derived;
    Ok(())
}

fn model_label(value: ModelFamily) -> &'static str {
    match value {
        ModelFamily::Luna => "luna",
    }
}

#[allow(clippy::too_many_arguments)]
fn request_id(
    run_id: &str,
    target_sha256: &str,
    finding_id: &str,
    payload_sha256: &str,
    created_at: &str,
    purpose: AiPurpose,
    redaction_events: u64,
    budget: &AiBudget,
) -> String {
    let purpose = match purpose {
        AiPurpose::AmbiguityAnalysis => "ambiguity-analysis",
        AiPurpose::CandidatePrioritization => "candidate-prioritization",
    };
    let material = format!(
        "{run_id}\0{target_sha256}\0{finding_id}\0{payload_sha256}\0{created_at}\0{purpose}\0{redaction_events}\0{}\0{}\0{}\0{}\0{}",
        budget.max_calls,
        budget.max_input_tokens,
        budget.max_output_tokens,
        budget.max_payload_bytes,
        PROMPT_VERSION,
    );
    format!("sf_ai_request_{}", sha256_hex(material.as_bytes()))
}

fn redact_text(value: &str) -> (String, bool) {
    let lower = value.to_ascii_lowercase();
    let sensitive_marker = [
        "bearer ",
        "authorization:",
        "api_key=",
        "api-key=",
        "apikey=",
        "password=",
        "secret=",
        "token=",
        "http://",
        "https://",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let high_entropy_token = value
        .split(|character: char| character.is_whitespace() || "\"'`,;()[]{}".contains(character))
        .any(|token| {
            token.len() >= 40
                && token.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/' | b'+' | b'=')
                })
        });
    let email_like = value
        .split_whitespace()
        .any(|token| token.contains('@') && token.contains('.'));
    if sensitive_marker || high_entropy_token || email_like {
        ("[REDACTED_POTENTIAL_SECRET]".into(), true)
    } else {
        (value.to_owned(), false)
    }
}

fn validate_document_size(bytes: &[u8]) -> Result<(), AiError> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(AiError::InvalidDocumentSize(bytes.len()));
    }
    Ok(())
}

fn validate_timestamp(value: &str, field: &'static str) -> Result<(), AiError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| AiError::InvalidField(field))
}

fn validate_prefixed_identifier(
    value: &str,
    prefix: &str,
    field: &'static str,
) -> Result<(), AiError> {
    let suffix = value.strip_prefix(prefix).unwrap_or_default();
    if !(16..=100).contains(&suffix.len())
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(AiError::InvalidField(field));
    }
    Ok(())
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix.len() == 64 && suffix.bytes().all(is_lower_hex))
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), AiError> {
    if value.len() != 64 || !value.bytes().all(is_lower_hex) {
        return Err(AiError::InvalidField(field));
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn validate_text(value: &str, field: &'static str, maximum: usize) -> Result<(), AiError> {
    if value.trim().is_empty()
        || value.chars().count() > maximum
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(AiError::InvalidField(field));
    }
    Ok(())
}

fn validate_relative_path(value: &str, field: &'static str) -> Result<(), AiError> {
    if value == "[REDACTED_POTENTIAL_SECRET]" {
        return Ok(());
    }
    if value.trim().is_empty()
        || value.contains('\\')
        || value.chars().count() > 2_000
        || value.chars().any(char::is_control)
        || Path::new(value).is_absolute()
        || Path::new(value).components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(AiError::InvalidField(field));
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

#[derive(Debug, Error)]
pub enum AiError {
    #[error("AI is disabled; pass an explicit enable flag to prepare a local request")]
    AiDisabled,
    #[error("explicit consent for the redacted export is required")]
    ConsentRequired,
    #[error("finding not found: {0}")]
    FindingNotFound(String),
    #[error("AI was already requested for finding: {0}")]
    AiAlreadyRequested(String),
    #[error("unsupported AI request contract: {0}")]
    UnsupportedRequest(String),
    #[error("unsupported AI response contract: {0}")]
    UnsupportedResponse(String),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("invalid AI routing; Luna is the only MVP model family")]
    InvalidRouting,
    #[error("invalid AI budget")]
    InvalidBudget,
    #[error("AI budget exceeded: {0}")]
    BudgetExceeded(&'static str),
    #[error("invalid AI data policy")]
    InvalidDataPolicy,
    #[error("invalid AI escalation policy")]
    InvalidEscalation,
    #[error("invalid advisory authority boundary")]
    InvalidAuthority,
    #[error("payload hash or byte count does not match the redacted payload")]
    PayloadFingerprintMismatch,
    #[error("request ID does not match its inputs")]
    RequestFingerprintMismatch,
    #[error("AI response does not match the request or run")]
    ResponseLinkMismatch,
    #[error("AI application attempted to change the human decision")]
    HumanDecisionChanged,
    #[error("AI document size is outside limits: {0} bytes")]
    InvalidDocumentSize(usize),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid SecureFlow run: {0}")]
    Model(#[from] secureflow_model::ModelError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use secureflow_model::{
        AiValidation, Authorization, AuthorizationBasis, AuthorizationStatus, EngineProvenance,
        EvaluationHarness, EvaluationReference, EvaluationStatus, EvidenceStep, Finding,
        HumanDecision, HumanReview, Location, PhaseStatus, Phases, RunStatus, Summary, Target,
    };

    fn manifest() -> RunManifest {
        let location = Location {
            path: "src/handler.ts".into(),
            start_byte: None,
            end_byte: None,
            start_line: 10,
            start_column: 2,
            end_line: None,
            end_column: None,
        };
        RunManifest {
            contract_version: secureflow_model::CONTRACT_VERSION.into(),
            run_id: "sf_run_1234567890abcdef".into(),
            status: RunStatus::Completed,
            created_at: "2026-08-23T12:00:00Z".into(),
            completed_at: Some("2026-08-23T12:00:01Z".into()),
            target: Target {
                label: "fixture".into(),
                root_sha256: "a".repeat(64),
                revision: None,
                authorization: Authorization {
                    status: AuthorizationStatus::Authorized,
                    basis: AuthorizationBasis::LocalProject,
                    reviewer: "tester".into(),
                    reference: None,
                    expires_at: None,
                },
            },
            engine: EngineProvenance {
                name: "secure-engine".into(),
                version: "fixture".into(),
                binary_sha256: "b".repeat(64),
                report_schema: secureflow_model::ENGINE_REPORT_SCHEMA.into(),
                report_sha256: "c".repeat(64),
                report_fingerprint: None,
                graph: None,
                sandbox_name: None,
                sandbox_binary_sha256: None,
            },
            configuration_sha256: None,
            phases: Phases {
                deterministic: PhaseStatus::Completed,
                prioritization: PhaseStatus::Completed,
                validation: PhaseStatus::Skipped,
                evaluation: PhaseStatus::Skipped,
            },
            artifacts: Vec::new(),
            findings: vec![Finding {
                finding_id: "sf_finding_1234567890abcdef".into(),
                engine_fingerprint: None,
                engine_finding_id: None,
                engine_verification_state: None,
                engine_evidence_state: None,
                title: "Potential command injection".into(),
                rule_id: "SE1001".into(),
                taxonomy: None,
                severity: Some(Severity::High),
                confidence: Confidence::Medium,
                source_location: location.clone(),
                sink_location: location.clone(),
                invariant: "Untrusted input must not reach a shell".into(),
                evidence_path: vec![EvidenceStep {
                    kind: EvidenceKind::Source,
                    location,
                    description: "excluded source detail".into(),
                }],
                limitations: vec!["Runtime behavior was not tested".into()],
                human_review: HumanReview {
                    decision: HumanDecision::Pending,
                    reviewer: None,
                    reviewed_at: None,
                    rationale: None,
                    evidence_reference: None,
                },
                ai_validation: AiValidation {
                    status: AiValidationStatus::NotRequested,
                    request_id: None,
                    provider: None,
                    model: None,
                    prompt_version: None,
                    redacted_payload_sha256: None,
                    response_sha256: None,
                    input_tokens: None,
                    output_tokens: None,
                    assessment: None,
                },
            }],
            summary: Some(Summary {
                candidate_count: 1,
                duplicate_count: 0,
                validated_count: 0,
                rejected_count: 0,
                abstained_count: 0,
                ai_calls: 0,
                ai_input_tokens: 0,
                ai_output_tokens: 0,
            }),
            evaluation: Some(EvaluationReference {
                harness: EvaluationHarness::LocalFixture,
                harness_version: None,
                manifest_sha256: None,
                result_sha256: None,
                status: EvaluationStatus::NotRun,
            }),
        }
    }

    fn options() -> PrepareOptions {
        PrepareOptions {
            enable_ai: true,
            consent_redacted_export: true,
            purpose: AiPurpose::AmbiguityAnalysis,
            max_input_tokens: DEFAULT_MAX_INPUT_TOKENS,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            created_at: "2026-08-23T13:00:00Z".into(),
        }
    }

    #[test]
    fn ai_is_disabled_without_an_explicit_flag() {
        let mut options = options();
        options.enable_ai = false;
        assert!(matches!(
            prepare_request(&manifest(), "sf_finding_1234567890abcdef", options),
            Err(AiError::AiDisabled)
        ));
    }

    #[test]
    fn prepared_payload_excludes_evidence_descriptions_and_human_metadata() {
        let request =
            prepare_request(&manifest(), "sf_finding_1234567890abcdef", options()).unwrap();
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("excluded source detail"));
        assert!(!json.contains("human_review"));
        assert_eq!(request.model_family, ModelFamily::Luna);
        assert_eq!(
            request.authority.validation_authority,
            ValidationAuthority::HumanOnly
        );
    }

    #[test]
    fn potential_secrets_are_redacted_before_hashing() {
        let mut manifest = manifest();
        manifest.findings[0].limitations = vec!["token=abcdefghijklmnopqrstuvwxyz123456".into()];
        let request = prepare_request(&manifest, "sf_finding_1234567890abcdef", options()).unwrap();
        assert_eq!(
            request.payload.limitations,
            vec!["[REDACTED_POTENTIAL_SECRET]"]
        );
        assert_eq!(request.data_policy.redaction_events, 1);
    }

    #[test]
    fn request_id_binds_purpose_and_policy_metadata() {
        let mut request =
            prepare_request(&manifest(), "sf_finding_1234567890abcdef", options()).unwrap();
        request.purpose = AiPurpose::CandidatePrioritization;
        assert!(matches!(
            request.validate(),
            Err(AiError::RequestFingerprintMismatch)
        ));
    }

    #[test]
    fn applying_response_records_usage_but_not_a_human_decision() {
        let mut manifest = manifest();
        let request = prepare_request(&manifest, "sf_finding_1234567890abcdef", options()).unwrap();
        let response = AiResponseEnvelope {
            contract_version: RESPONSE_VERSION.into(),
            request_id: request.request_id.clone(),
            responded_at: "2026-08-23T13:01:00Z".into(),
            provider: request.provider.clone(),
            model_family: request.model_family,
            prompt_version: request.prompt_version.clone(),
            request_payload_sha256: request.payload_sha256.clone(),
            assessment: AiAssessment::Uncertain,
            analysis_summary: "Static evidence is insufficient without application context.".into(),
            input_tokens: 500,
            output_tokens: 100,
            limitations: vec![ResponseLimitation::RequiresHumanContext],
            validation_authority: ValidationAuthority::HumanOnly,
        };
        let response_bytes = serde_json::to_vec(&response).unwrap();
        apply_response(&mut manifest, &request, &response, &response_bytes).unwrap();
        let finding = &manifest.findings[0];
        assert_eq!(finding.human_review.decision, HumanDecision::Pending);
        assert_eq!(
            finding.ai_validation.assessment,
            Some(AiAssessment::Uncertain)
        );
        assert_eq!(manifest.summary.as_ref().unwrap().ai_calls, 1);
        assert_eq!(manifest.summary.as_ref().unwrap().ai_input_tokens, 500);
    }

    #[test]
    fn response_over_budget_fails_closed() {
        let mut manifest = manifest();
        let request = prepare_request(&manifest, "sf_finding_1234567890abcdef", options()).unwrap();
        let response = AiResponseEnvelope {
            contract_version: RESPONSE_VERSION.into(),
            request_id: request.request_id.clone(),
            responded_at: "2026-08-23T13:01:00Z".into(),
            provider: request.provider.clone(),
            model_family: request.model_family,
            prompt_version: request.prompt_version.clone(),
            request_payload_sha256: request.payload_sha256.clone(),
            assessment: AiAssessment::Supports,
            analysis_summary: "The redacted path supports the candidate but needs human review."
                .into(),
            input_tokens: request.budget.max_input_tokens + 1,
            output_tokens: 1,
            limitations: Vec::new(),
            validation_authority: ValidationAuthority::HumanOnly,
        };
        let response_bytes = serde_json::to_vec(&response).unwrap();
        assert!(matches!(
            apply_response(&mut manifest, &request, &response, &response_bytes),
            Err(AiError::BudgetExceeded(_))
        ));
        assert_eq!(
            manifest.findings[0].human_review.decision,
            HumanDecision::Pending
        );
    }
}
