//! Read-only import of Secure Bench result-v2 artifacts.
//!
//! Benchmark evidence remains outside the production decision path. The
//! envelope deliberately forbids ranking, superiority and production-safety
//! claims regardless of the imported measurements.

pub mod prospective;
pub mod prospective_v2;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const ENVELOPE_VERSION: &str = "secureflow-benchmark-result-v1";
pub const UPSTREAM_RESULT_VERSION: &str = "secure-bench-result-v2";
pub const UPSTREAM_SCHEMA_ID: &str =
    "https://usesecure.dev/secure-bench/schemas/result-v2.schema.json";
pub const MAX_RESULT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_INPUT_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkEnvelope {
    pub contract_version: String,
    pub import_id: String,
    pub imported_at: String,
    pub study_kind: StudyKind,
    pub source: SecureBenchProvenance,
    pub artifacts: BenchmarkArtifacts,
    pub claims: ClaimBoundary,
    pub reproducibility: ReproducibilityChecks,
    pub result: BenchmarkSummary,
}

impl BenchmarkEnvelope {
    pub fn validate(&self) -> Result<(), BenchAdapterError> {
        if self.contract_version != ENVELOPE_VERSION {
            return Err(BenchAdapterError::UnsupportedEnvelope(
                self.contract_version.clone(),
            ));
        }
        if !valid_prefixed_hash(&self.import_id, "sf_bench_") {
            return Err(BenchAdapterError::InvalidField("import_id"));
        }
        parse_timestamp(&self.imported_at, "imported_at")?;
        self.source.validate()?;
        self.artifacts.validate()?;
        self.claims.validate()?;
        self.reproducibility.validate()?;
        self.result.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StudyKind {
    LocalDevelopmentDiagnostic,
    HistoricalPublicDiagnostic,
    PreregisteredOneShot,
    PostOpenRecovery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureBenchProvenance {
    pub name: String,
    pub version: String,
    pub revision: String,
    pub result_contract: String,
    pub result_schema_sha256: String,
    pub license_spdx: String,
    pub license_sha256: String,
}

impl SecureBenchProvenance {
    fn validate(&self) -> Result<(), BenchAdapterError> {
        if self.name != "secure-bench" {
            return Err(BenchAdapterError::UnsupportedSource(self.name.clone()));
        }
        validate_text(&self.version, "source.version", 100)?;
        if !is_lower_hex_of_length(&self.revision, 40)
            && !is_lower_hex_of_length(&self.revision, 64)
        {
            return Err(BenchAdapterError::InvalidField("source.revision"));
        }
        if self.result_contract != UPSTREAM_RESULT_VERSION {
            return Err(BenchAdapterError::UnsupportedResult(
                self.result_contract.clone(),
            ));
        }
        validate_sha256(&self.result_schema_sha256, "source.result_schema_sha256")?;
        validate_text(&self.license_spdx, "source.license_spdx", 100)?;
        validate_sha256(&self.license_sha256, "source.license_sha256")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkArtifacts {
    pub result_sha256: String,
    pub result_bytes: u64,
    pub run_manifest_sha256: String,
    pub run_manifest_bytes: u64,
    pub suite_sha256: String,
    pub suite_bytes: u64,
}

impl BenchmarkArtifacts {
    fn validate(&self) -> Result<(), BenchAdapterError> {
        validate_sha256(&self.result_sha256, "artifacts.result_sha256")?;
        validate_sha256(&self.run_manifest_sha256, "artifacts.run_manifest_sha256")?;
        validate_sha256(&self.suite_sha256, "artifacts.suite_sha256")?;
        validate_size(
            self.result_bytes,
            MAX_RESULT_BYTES,
            "artifacts.result_bytes",
        )?;
        validate_size(
            self.run_manifest_bytes,
            MAX_INPUT_ARTIFACT_BYTES,
            "artifacts.run_manifest_bytes",
        )?;
        validate_size(
            self.suite_bytes,
            MAX_INPUT_ARTIFACT_BYTES,
            "artifacts.suite_bytes",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimBoundary {
    pub evaluation_only: bool,
    pub ranking_allowed: bool,
    pub superiority_claim_allowed: bool,
    pub production_readiness_claim_allowed: bool,
}

impl ClaimBoundary {
    fn restricted() -> Self {
        Self {
            evaluation_only: true,
            ranking_allowed: false,
            superiority_claim_allowed: false,
            production_readiness_claim_allowed: false,
        }
    }

    fn validate(&self) -> Result<(), BenchAdapterError> {
        if !self.evaluation_only
            || self.ranking_allowed
            || self.superiority_claim_allowed
            || self.production_readiness_claim_allowed
        {
            return Err(BenchAdapterError::InvalidClaimBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReproducibilityChecks {
    pub result_schema_validated: bool,
    pub suite_fingerprint_verified: bool,
    pub run_manifest_fingerprint_verified: bool,
    pub result_fingerprints_retained: bool,
    pub study_kind_operator_declared: bool,
}

impl ReproducibilityChecks {
    fn verified() -> Self {
        Self {
            result_schema_validated: true,
            suite_fingerprint_verified: true,
            run_manifest_fingerprint_verified: true,
            result_fingerprints_retained: true,
            study_kind_operator_declared: true,
        }
    }

    fn validate(&self) -> Result<(), BenchAdapterError> {
        if !self.result_schema_validated
            || !self.suite_fingerprint_verified
            || !self.run_manifest_fingerprint_verified
            || !self.result_fingerprints_retained
            || !self.study_kind_operator_declared
        {
            return Err(BenchAdapterError::InvalidReproducibility);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkSummary {
    pub upstream_schema_version: String,
    pub suite_id: String,
    pub benchmark_run_id: String,
    pub tool: EvaluatedTool,
    pub confusion: ConfusionAccounting,
    pub metrics: QualityMetrics,
    pub counts: BTreeMap<String, Option<u64>>,
    pub failures: BTreeMap<String, Option<u64>>,
    pub performance: PerformanceSummary,
    pub structured_error_count: u64,
    pub provenance: ResultProvenance,
}

impl BenchmarkSummary {
    fn validate(&self) -> Result<(), BenchAdapterError> {
        if self.upstream_schema_version != UPSTREAM_RESULT_VERSION {
            return Err(BenchAdapterError::UnsupportedResult(
                self.upstream_schema_version.clone(),
            ));
        }
        validate_identifier(&self.suite_id, "result.suite_id")?;
        validate_identifier(&self.benchmark_run_id, "result.benchmark_run_id")?;
        self.tool.validate()?;
        self.confusion.validate()?;
        self.metrics.validate()?;
        validate_metric_map(&self.counts, "result.counts")?;
        validate_metric_map(&self.failures, "result.failures")?;
        self.performance.validate()?;
        self.provenance.validate()?;
        validate_accounting(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatedTool {
    pub name: String,
    pub version: String,
    pub report_schema: String,
    pub binary_sha256: String,
    pub configuration_sha256: String,
}

impl EvaluatedTool {
    fn validate(&self) -> Result<(), BenchAdapterError> {
        validate_text(&self.name, "result.tool.name", 200)?;
        validate_text(&self.version, "result.tool.version", 200)?;
        validate_text(&self.report_schema, "result.tool.report_schema", 200)?;
        validate_sha256(&self.binary_sha256, "result.tool.binary_sha256")?;
        validate_sha256(
            &self.configuration_sha256,
            "result.tool.configuration_sha256",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfusionAccounting {
    pub true_positive_expectations: u64,
    pub false_negative_expectations: u64,
    pub false_positive_safe_controls: u64,
    pub true_negative_safe_controls: u64,
    pub positive_unit: String,
    pub negative_unit: String,
    pub failures_are_not_clean: bool,
}

impl ConfusionAccounting {
    fn validate(&self) -> Result<(), BenchAdapterError> {
        if self.positive_unit != "vulnerable-expectation"
            || self.negative_unit != "safe-control-case"
            || !self.failures_are_not_clean
        {
            return Err(BenchAdapterError::InvalidAccounting(
                "confusion units or failure semantics changed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualityMetrics {
    pub vulnerable_recall: RatioMetric,
    pub attempted_vulnerable_recall: RatioMetric,
    pub safe_control_false_positive_rate: RatioMetric,
    pub safe_control_clean_coverage: RatioMetric,
    pub evidence_path_accuracy: RatioMetric,
    pub source_localization_accuracy: RatioMetric,
    pub sink_localization_accuracy: RatioMetric,
    pub severity_calibration_accuracy: RatioMetric,
    pub confidence_calibration_accuracy: RatioMetric,
    pub duplicate_rate: RatioMetric,
}

impl QualityMetrics {
    fn validate(&self) -> Result<(), BenchAdapterError> {
        for (field, ratio) in [
            ("vulnerable_recall", &self.vulnerable_recall),
            (
                "attempted_vulnerable_recall",
                &self.attempted_vulnerable_recall,
            ),
            (
                "safe_control_false_positive_rate",
                &self.safe_control_false_positive_rate,
            ),
            (
                "safe_control_clean_coverage",
                &self.safe_control_clean_coverage,
            ),
            ("evidence_path_accuracy", &self.evidence_path_accuracy),
            (
                "source_localization_accuracy",
                &self.source_localization_accuracy,
            ),
            (
                "sink_localization_accuracy",
                &self.sink_localization_accuracy,
            ),
            (
                "severity_calibration_accuracy",
                &self.severity_calibration_accuracy,
            ),
            (
                "confidence_calibration_accuracy",
                &self.confidence_calibration_accuracy,
            ),
            ("duplicate_rate", &self.duplicate_rate),
        ] {
            ratio.validate(field)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RatioMetric {
    pub numerator: u64,
    pub denominator: u64,
    pub basis_points: Option<u32>,
}

impl RatioMetric {
    fn validate(&self, field: &'static str) -> Result<(), BenchAdapterError> {
        if self.numerator > self.denominator {
            return Err(BenchAdapterError::InvalidRatio(field));
        }
        let expected = if self.denominator == 0 {
            None
        } else {
            Some(((u128::from(self.numerator) * 10_000) / u128::from(self.denominator)) as u32)
        };
        if self.basis_points != expected {
            return Err(BenchAdapterError::InvalidRatio(field));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceSummary {
    pub cold_duration_ms: MeasurementTotal,
    pub warm_duration_ms: MeasurementTotal,
    pub peak_memory_bytes: MeasurementMaximum,
    pub output_bytes: MeasurementTotal,
}

impl PerformanceSummary {
    fn validate(&self) -> Result<(), BenchAdapterError> {
        self.cold_duration_ms
            .validate("performance.cold_duration_ms")?;
        self.warm_duration_ms
            .validate("performance.warm_duration_ms")?;
        self.peak_memory_bytes
            .validate("performance.peak_memory_bytes")?;
        self.output_bytes.validate("performance.output_bytes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementTotal {
    pub total: u64,
    pub samples: u64,
}

impl MeasurementTotal {
    fn validate(&self, field: &'static str) -> Result<(), BenchAdapterError> {
        if self.samples == 0 && self.total != 0 {
            return Err(BenchAdapterError::InvalidMeasurement(field));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementMaximum {
    pub maximum: u64,
    pub samples: u64,
}

impl MeasurementMaximum {
    fn validate(&self, field: &'static str) -> Result<(), BenchAdapterError> {
        if self.samples == 0 && self.maximum != 0 {
            return Err(BenchAdapterError::InvalidMeasurement(field));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultProvenance {
    pub suite_fingerprint: String,
    pub run_manifest_fingerprint: String,
    pub report_fingerprint: String,
    pub schemas: BTreeMap<String, String>,
}

impl ResultProvenance {
    fn validate(&self) -> Result<(), BenchAdapterError> {
        validate_sha256(
            &self.suite_fingerprint,
            "result.provenance.suite_fingerprint",
        )?;
        validate_sha256(
            &self.run_manifest_fingerprint,
            "result.provenance.run_manifest_fingerprint",
        )?;
        validate_sha256(
            &self.report_fingerprint,
            "result.provenance.report_fingerprint",
        )?;
        if self.schemas.is_empty() {
            return Err(BenchAdapterError::InvalidField("result.provenance.schemas"));
        }
        for value in self.schemas.values() {
            validate_text(value, "result.provenance.schemas", 200)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct BenchmarkImport<'a> {
    pub result: &'a [u8],
    pub run_manifest: &'a [u8],
    pub suite: &'a [u8],
    pub result_schema: &'a [u8],
    pub imported_at: String,
    pub study_kind: StudyKind,
    pub source: SecureBenchProvenance,
}

pub fn import_benchmark(
    input: BenchmarkImport<'_>,
) -> Result<BenchmarkEnvelope, BenchAdapterError> {
    validate_size(input.result.len() as u64, MAX_RESULT_BYTES, "result")?;
    validate_size(
        input.run_manifest.len() as u64,
        MAX_INPUT_ARTIFACT_BYTES,
        "run_manifest",
    )?;
    validate_size(input.suite.len() as u64, MAX_INPUT_ARTIFACT_BYTES, "suite")?;
    parse_timestamp(&input.imported_at, "imported_at")?;
    input.source.validate()?;
    if sha256_hex(input.result_schema) != input.source.result_schema_sha256 {
        return Err(BenchAdapterError::FingerprintMismatch("result schema"));
    }

    let schema: serde_json::Value = serde_json::from_slice(input.result_schema)?;
    validate_schema_identity(&schema)?;
    let result: serde_json::Value = serde_json::from_slice(input.result)?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| BenchAdapterError::InvalidSourceSchema(error.to_string()))?;
    validator
        .validate(&result)
        .map_err(|error| BenchAdapterError::InvalidResultSchema(error.to_string()))?;

    let result_sha256 = sha256_hex(input.result);
    let run_manifest_sha256 = sha256_hex(input.run_manifest);
    let suite_sha256 = sha256_hex(input.suite);
    let provenance = extract_provenance(&result)?;
    if provenance.run_manifest_fingerprint != run_manifest_sha256 {
        return Err(BenchAdapterError::FingerprintMismatch("run manifest"));
    }
    if provenance.suite_fingerprint != suite_sha256 {
        return Err(BenchAdapterError::FingerprintMismatch("suite"));
    }

    let result_summary = extract_summary(&result, provenance)?;
    let import_hash = sha256_hex(
        format!(
            "{}\0{}\0{}\0{}",
            result_sha256, run_manifest_sha256, suite_sha256, input.source.revision
        )
        .as_bytes(),
    );
    let envelope = BenchmarkEnvelope {
        contract_version: ENVELOPE_VERSION.into(),
        import_id: format!("sf_bench_{import_hash}"),
        imported_at: input.imported_at,
        study_kind: input.study_kind,
        source: input.source,
        artifacts: BenchmarkArtifacts {
            result_sha256,
            result_bytes: input.result.len() as u64,
            run_manifest_sha256,
            run_manifest_bytes: input.run_manifest.len() as u64,
            suite_sha256,
            suite_bytes: input.suite.len() as u64,
        },
        claims: ClaimBoundary::restricted(),
        reproducibility: ReproducibilityChecks::verified(),
        result: result_summary,
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn parse_envelope(bytes: &[u8]) -> Result<BenchmarkEnvelope, BenchAdapterError> {
    validate_size(bytes.len() as u64, MAX_RESULT_BYTES, "envelope")?;
    let envelope: BenchmarkEnvelope = serde_json::from_slice(bytes)?;
    envelope.validate()?;
    Ok(envelope)
}

/// Loads source identity and the upstream result schema without running Secure
/// Bench or any evaluated scanner.
pub fn load_source_provenance(
    root: &Path,
    revision: &str,
) -> Result<(SecureBenchProvenance, Vec<u8>), BenchAdapterError> {
    let root = fs::canonicalize(root).map_err(|source| BenchAdapterError::Read {
        path: root.display().to_string(),
        source,
    })?;
    verify_git_revision_if_present(&root, revision)?;
    let cargo = read_source_file(&root, Path::new("Cargo.toml"), MAX_SOURCE_FILE_BYTES)?;
    let schema = read_source_file(
        &root,
        Path::new("schemas/result-v2.schema.json"),
        MAX_SOURCE_FILE_BYTES,
    )?;
    let license = read_source_file(&root, Path::new("LICENSE"), MAX_SOURCE_FILE_BYTES)?;

    let cargo_text = std::str::from_utf8(&cargo)
        .map_err(|_| BenchAdapterError::InvalidSourceMetadata("Cargo.toml is not UTF-8"))?;
    let cargo: toml::Value = toml::from_str(cargo_text)
        .map_err(|error| BenchAdapterError::InvalidSourceMetadataOwned(error.to_string()))?;
    let version = cargo
        .get("workspace")
        .and_then(|value| value.get("package"))
        .and_then(|value| value.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or(BenchAdapterError::InvalidSourceMetadata(
            "workspace.package.version is missing",
        ))?;
    let license_spdx = cargo
        .get("workspace")
        .and_then(|value| value.get("package"))
        .and_then(|value| value.get("license"))
        .and_then(toml::Value::as_str)
        .ok_or(BenchAdapterError::InvalidSourceMetadata(
            "workspace.package.license is missing",
        ))?;
    let schema_value: serde_json::Value = serde_json::from_slice(&schema)?;
    validate_schema_identity(&schema_value)?;

    let source = SecureBenchProvenance {
        name: "secure-bench".into(),
        version: version.to_owned(),
        revision: revision.to_owned(),
        result_contract: UPSTREAM_RESULT_VERSION.into(),
        result_schema_sha256: sha256_hex(&schema),
        license_spdx: license_spdx.to_owned(),
        license_sha256: sha256_hex(&license),
    };
    source.validate()?;
    Ok((source, schema))
}

fn verify_git_revision_if_present(root: &Path, expected: &str) -> Result<(), BenchAdapterError> {
    if !is_lower_hex_of_length(expected, 40) && !is_lower_hex_of_length(expected, 64) {
        return Err(BenchAdapterError::InvalidField("source.revision"));
    }
    match fs::symlink_metadata(root.join(".git")) {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(BenchAdapterError::Read {
                path: root.join(".git").display().to_string(),
                source,
            });
        }
    }
    let git = [Path::new("/usr/bin/git"), Path::new("/bin/git")]
        .into_iter()
        .find(|path| path.is_file())
        .ok_or(BenchAdapterError::GitUnavailable)?;
    let output = Command::new(git)
        .args(["-C"])
        .arg(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .env_clear()
        .output()
        .map_err(BenchAdapterError::GitRevisionRead)?;
    if !output.status.success() {
        return Err(BenchAdapterError::GitRevisionUnavailable);
    }
    let actual = std::str::from_utf8(&output.stdout)
        .map_err(|_| BenchAdapterError::GitRevisionUnavailable)?
        .trim();
    if actual != expected {
        return Err(BenchAdapterError::GitRevisionMismatch {
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

pub fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BenchAdapterError> {
    let metadata = fs::metadata(path).map_err(|source| BenchAdapterError::Read {
        path: path.display().to_string(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(BenchAdapterError::NotAFile(path.display().to_string()));
    }
    validate_size(metadata.len(), maximum, "input file")?;
    let bytes = fs::read(path).map_err(|source| BenchAdapterError::Read {
        path: path.display().to_string(),
        source,
    })?;
    validate_size(bytes.len() as u64, maximum, "input file")?;
    Ok(bytes)
}

fn extract_summary(
    result: &serde_json::Value,
    provenance: ResultProvenance,
) -> Result<BenchmarkSummary, BenchAdapterError> {
    let metrics = QualityMetrics {
        vulnerable_recall: extract_ratio(result, "vulnerable_recall")?,
        attempted_vulnerable_recall: extract_ratio(result, "attempted_vulnerable_recall")?,
        safe_control_false_positive_rate: extract_ratio(
            result,
            "safe_control_false_positive_rate",
        )?,
        safe_control_clean_coverage: extract_ratio(result, "safe_control_clean_coverage")?,
        evidence_path_accuracy: extract_ratio(result, "evidence_path_accuracy")?,
        source_localization_accuracy: extract_ratio(result, "source_localization_accuracy")?,
        sink_localization_accuracy: extract_ratio(result, "sink_localization_accuracy")?,
        severity_calibration_accuracy: extract_ratio(result, "severity_calibration_accuracy")?,
        confidence_calibration_accuracy: extract_ratio(result, "confidence_calibration_accuracy")?,
        duplicate_rate: extract_ratio(result, "duplicate_rate")?,
    };
    let counts = extract_integer_map(pointer(result, "/score/counts")?, "score.counts")?;
    let failures = extract_integer_map(pointer(result, "/score/failures")?, "score.failures")?;
    let performance = PerformanceSummary {
        cold_duration_ms: extract_total(result, "/score/performance/cold_duration")?,
        warm_duration_ms: extract_total(result, "/score/performance/warm_duration")?,
        peak_memory_bytes: extract_maximum(result, "/score/performance/peak_memory")?,
        output_bytes: extract_total(result, "/score/performance/output_size")?,
    };
    let tp = metrics.vulnerable_recall.numerator;
    let fn_count = metrics
        .vulnerable_recall
        .denominator
        .checked_sub(tp)
        .ok_or(BenchAdapterError::InvalidRatio("vulnerable_recall"))?;
    let confusion = ConfusionAccounting {
        true_positive_expectations: tp,
        false_negative_expectations: fn_count,
        false_positive_safe_controls: metrics.safe_control_false_positive_rate.numerator,
        true_negative_safe_controls: metrics.safe_control_clean_coverage.numerator,
        positive_unit: "vulnerable-expectation".into(),
        negative_unit: "safe-control-case".into(),
        failures_are_not_clean: true,
    };
    let tool = EvaluatedTool {
        name: string_at(result, "/provenance/tool/name")?.to_owned(),
        version: string_at(result, "/provenance/tool/version")?.to_owned(),
        report_schema: string_at(result, "/provenance/tool/report_schema")?.to_owned(),
        binary_sha256: string_at(result, "/provenance/tool/binary_fingerprint")?.to_owned(),
        configuration_sha256: string_at(result, "/provenance/tool/configuration_fingerprint")?
            .to_owned(),
    };
    let structured_error_count = pointer(result, "/errors")?
        .as_array()
        .ok_or(BenchAdapterError::InvalidField("result.errors"))?
        .len() as u64;
    Ok(BenchmarkSummary {
        upstream_schema_version: string_at(result, "/schema_version")?.to_owned(),
        suite_id: string_at(result, "/suite_id")?.to_owned(),
        benchmark_run_id: string_at(result, "/run_id")?.to_owned(),
        tool,
        confusion,
        metrics,
        counts,
        failures,
        performance,
        structured_error_count,
        provenance,
    })
}

fn extract_provenance(result: &serde_json::Value) -> Result<ResultProvenance, BenchAdapterError> {
    let schemas_value = pointer(result, "/provenance/schemas")?
        .as_object()
        .ok_or(BenchAdapterError::InvalidField("provenance.schemas"))?;
    let mut schemas = BTreeMap::new();
    for (key, value) in schemas_value {
        let value = value
            .as_str()
            .ok_or(BenchAdapterError::InvalidField("provenance.schemas"))?;
        schemas.insert(key.clone(), value.to_owned());
    }
    Ok(ResultProvenance {
        suite_fingerprint: string_at(result, "/provenance/suite_fingerprint")?.to_owned(),
        run_manifest_fingerprint: string_at(result, "/provenance/run_manifest_fingerprint")?
            .to_owned(),
        report_fingerprint: string_at(result, "/provenance/report_fingerprint")?.to_owned(),
        schemas,
    })
}

fn extract_ratio(
    result: &serde_json::Value,
    name: &'static str,
) -> Result<RatioMetric, BenchAdapterError> {
    let path = format!("/score/{name}");
    let value = pointer(result, &path)?;
    let numerator = integer_field(value, "numerator", name)?;
    let denominator = integer_field(value, "denominator", name)?;
    let basis_points = match value.get("basis_points") {
        Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            u32::try_from(
                value
                    .as_u64()
                    .ok_or(BenchAdapterError::InvalidField(name))?,
            )
            .map_err(|_| BenchAdapterError::InvalidField(name))?,
        ),
        None => return Err(BenchAdapterError::InvalidField(name)),
    };
    let ratio = RatioMetric {
        numerator,
        denominator,
        basis_points,
    };
    ratio.validate(name)?;
    Ok(ratio)
}

fn extract_integer_map(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<BTreeMap<String, Option<u64>>, BenchAdapterError> {
    let object = value
        .as_object()
        .ok_or(BenchAdapterError::InvalidField(field))?;
    let mut output = BTreeMap::new();
    for (key, value) in object {
        let number = if value.is_null() {
            None
        } else {
            Some(
                value
                    .as_u64()
                    .ok_or(BenchAdapterError::InvalidField(field))?,
            )
        };
        output.insert(key.clone(), number);
    }
    Ok(output)
}

fn extract_total(
    result: &serde_json::Value,
    path: &'static str,
) -> Result<MeasurementTotal, BenchAdapterError> {
    let value = pointer(result, path)?;
    Ok(MeasurementTotal {
        total: integer_field(value, "total", path)?,
        samples: integer_field(value, "samples", path)?,
    })
}

fn extract_maximum(
    result: &serde_json::Value,
    path: &'static str,
) -> Result<MeasurementMaximum, BenchAdapterError> {
    let value = pointer(result, path)?;
    Ok(MeasurementMaximum {
        maximum: integer_field(value, "maximum", path)?,
        samples: integer_field(value, "samples", path)?,
    })
}

fn integer_field(
    value: &serde_json::Value,
    key: &str,
    field: &'static str,
) -> Result<u64, BenchAdapterError> {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or(BenchAdapterError::InvalidField(field))
}

fn validate_accounting(summary: &BenchmarkSummary) -> Result<(), BenchAdapterError> {
    let required = |map: &BTreeMap<String, Option<u64>>, key: &'static str| {
        map.get(key)
            .copied()
            .flatten()
            .ok_or(BenchAdapterError::MissingMetric(key))
    };
    let tp = summary.confusion.true_positive_expectations;
    let fn_count = summary.confusion.false_negative_expectations;
    let fp = summary.confusion.false_positive_safe_controls;
    let tn = summary.confusion.true_negative_safe_controls;
    if required(&summary.counts, "detected_expectations")? != tp
        || required(&summary.counts, "eligible_expectations")? != tp.saturating_add(fn_count)
        || required(&summary.counts, "false_positive_safe_controls")? != fp
        || required(&summary.counts, "clean_safe_controls")? != tn
    {
        return Err(BenchAdapterError::InvalidAccounting(
            "confusion counts do not match the score card",
        ));
    }
    for key in [
        "crashes",
        "timeouts",
        "missing",
        "unsupported",
        "parse_failures",
    ] {
        required(&summary.failures, key)?;
    }
    Ok(())
}

fn validate_schema_identity(schema: &serde_json::Value) -> Result<(), BenchAdapterError> {
    if schema.get("$id").and_then(serde_json::Value::as_str) != Some(UPSTREAM_SCHEMA_ID)
        || schema
            .pointer("/properties/schema_version/const")
            .and_then(serde_json::Value::as_str)
            != Some(UPSTREAM_RESULT_VERSION)
    {
        return Err(BenchAdapterError::InvalidSourceSchema(
            "unexpected result-v2 identity".into(),
        ));
    }
    Ok(())
}

fn pointer<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Result<&'a serde_json::Value, BenchAdapterError> {
    value
        .pointer(path)
        .ok_or(BenchAdapterError::MissingField(path.to_owned()))
}

fn string_at<'a>(value: &'a serde_json::Value, path: &str) -> Result<&'a str, BenchAdapterError> {
    pointer(value, path)?
        .as_str()
        .ok_or_else(|| BenchAdapterError::MissingField(path.to_owned()))
}

fn read_source_file(
    root: &Path,
    relative: &Path,
    maximum: u64,
) -> Result<Vec<u8>, BenchAdapterError> {
    let path = root.join(relative);
    let canonical = fs::canonicalize(&path).map_err(|source| BenchAdapterError::Read {
        path: path.display().to_string(),
        source,
    })?;
    if !canonical.starts_with(root) {
        return Err(BenchAdapterError::SourceEscapesRoot(
            relative.display().to_string(),
        ));
    }
    read_bounded(&canonical, maximum)
}

fn validate_metric_map(
    values: &BTreeMap<String, Option<u64>>,
    field: &'static str,
) -> Result<(), BenchAdapterError> {
    if values.is_empty() || values.len() > 10_000 {
        return Err(BenchAdapterError::InvalidField(field));
    }
    for key in values.keys() {
        validate_identifier(key, field)?;
    }
    Ok(())
}

fn validate_size(bytes: u64, maximum: u64, field: &'static str) -> Result<(), BenchAdapterError> {
    if bytes == 0 || bytes > maximum {
        return Err(BenchAdapterError::InvalidSize {
            field,
            bytes,
            maximum,
        });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), BenchAdapterError> {
    if value.is_empty()
        || value.len() > 200
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(BenchAdapterError::InvalidField(field));
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), BenchAdapterError> {
    if value.trim().is_empty()
        || value.chars().count() > maximum
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(BenchAdapterError::InvalidField(field));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &'static str) -> Result<(), BenchAdapterError> {
    if !is_lower_hex_of_length(value, 64) {
        return Err(BenchAdapterError::InvalidField(field));
    }
    Ok(())
}

fn is_lower_hex_of_length(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| is_lower_hex_of_length(suffix, 64))
}

fn parse_timestamp(value: &str, field: &'static str) -> Result<OffsetDateTime, BenchAdapterError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| BenchAdapterError::InvalidField(field))
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
pub enum BenchAdapterError {
    #[error("could not read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("expected a regular file: {0}")]
    NotAFile(String),
    #[error("Secure Bench source file resolves outside its root: {0}")]
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
    #[error("unsupported SecureFlow benchmark envelope: {0}")]
    UnsupportedEnvelope(String),
    #[error("unsupported Secure Bench result: {0}")]
    UnsupportedResult(String),
    #[error("unsupported benchmark source: {0}")]
    UnsupportedSource(String),
    #[error("invalid Secure Bench source schema: {0}")]
    InvalidSourceSchema(String),
    #[error("result does not satisfy Secure Bench result-v2: {0}")]
    InvalidResultSchema(String),
    #[error("invalid Secure Bench source metadata: {0}")]
    InvalidSourceMetadata(&'static str),
    #[error("invalid Secure Bench source metadata: {0}")]
    InvalidSourceMetadataOwned(String),
    #[error("artifact fingerprint mismatch: {0}")]
    FingerprintMismatch(&'static str),
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("missing required benchmark metric: {0}")]
    MissingMetric(&'static str),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("invalid size for {field}: {bytes} bytes (maximum {maximum})")]
    InvalidSize {
        field: &'static str,
        bytes: u64,
        maximum: u64,
    },
    #[error("invalid ratio: {0}")]
    InvalidRatio(&'static str),
    #[error("invalid measurement: {0}")]
    InvalidMeasurement(&'static str),
    #[error("invalid TP/FP/TN/FN accounting: {0}")]
    InvalidAccounting(&'static str),
    #[error("benchmark claim boundary is not restrictive")]
    InvalidClaimBoundary,
    #[error("benchmark reproducibility checks are incomplete")]
    InvalidReproducibility,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ratio(numerator: u64, denominator: u64) -> RatioMetric {
        RatioMetric {
            numerator,
            denominator,
            basis_points: if denominator == 0 {
                None
            } else {
                Some(((u128::from(numerator) * 10_000) / u128::from(denominator)) as u32)
            },
        }
    }

    #[test]
    fn ratio_rejects_inconsistent_basis_points() {
        let mut value = ratio(1, 3);
        value.basis_points = Some(3_334);
        assert!(matches!(
            value.validate("test"),
            Err(BenchAdapterError::InvalidRatio("test"))
        ));
    }

    #[test]
    fn claim_boundary_can_never_allow_marketing_claims() {
        let mut claims = ClaimBoundary::restricted();
        claims.superiority_claim_allowed = true;
        assert!(matches!(
            claims.validate(),
            Err(BenchAdapterError::InvalidClaimBoundary)
        ));
    }

    #[test]
    fn zero_denominator_has_no_rate() {
        assert!(ratio(0, 0).validate("test").is_ok());
        let invalid = RatioMetric {
            numerator: 0,
            denominator: 0,
            basis_points: Some(0),
        };
        assert!(invalid.validate("test").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_declared_revision_that_does_not_match_git_head() {
        let git = Path::new("/usr/bin/git");
        if !git.is_file() {
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "secureflow-bench-git-revision-{}",
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
            Err(BenchAdapterError::GitRevisionMismatch { .. })
        ));
        std::fs::remove_dir_all(root).expect("temporary repository should be removable");
    }
}
