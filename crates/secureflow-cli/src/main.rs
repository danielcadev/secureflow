use clap::{Parser, Subcommand, ValueEnum};
use secureflow_ai as ai;
use secureflow_bench_adapter as bench_adapter;
use secureflow_engine_adapter::{
    EngineConfig, MAX_ENGINE_TIMEOUT_SECONDS, SandboxMode, project_findings, run, sha256_bytes,
    sha256_target,
};
use secureflow_knowledge::catalog::{
    Catalog, CatalogDelta, CatalogImportResult, CatalogSnapshot, CatalogSource, MAX_IMPORT_RECORDS,
    MAX_OSV_RECORD_BYTES,
};
use secureflow_knowledge::catalog_backup::{
    MAX_BACKUP_MANIFEST_BYTES, create_backup, parse_manifest as parse_backup_manifest,
    restore_backup, verify_backup,
};
use secureflow_knowledge::correlation::{
    MAX_CORRELATION_BYTES, MAX_CORRELATION_MATCHES, build_correlation_v2,
    parse_correlation_document,
};
use secureflow_knowledge::delta::{DeltaPrepareConfig, load_and_validate_delta, prepare_osv_delta};
use secureflow_knowledge::snapshot::{
    SnapshotPrepareConfig, load_and_validate_snapshot, prepare_osv_zip, validate_snapshot_archive,
};
use secureflow_knowledge::{
    KnowledgeRecord, SourceLicense, SourceLicenseStatus, import_manifest_to_ledger, read_ledger,
};
use secureflow_model::{
    Authorization, AuthorizationBasis, AuthorizationStatus, CONTRACT_VERSION, Confidence,
    ENGINE_REPORT_SCHEMA, EngineProvenance, EvaluationReference, HumanDecision, PhaseStatus,
    Phases, Revision, RevisionKind, RunManifest, RunStatus, Severity, Summary, Target,
    deduplicate_findings, prioritize_findings,
};
use secureflow_orchestrator::{
    EvidenceArtifact as OrchestrationEvidence, EvidenceKind as OrchestrationEvidenceKind,
    MAX_ORCHESTRATION_BYTES, derive_plan, parse_plan,
};
use secureflow_secure_adapter::{
    ImportContext, MAX_REVIEW_BYTES, SecureReviewEnvelope, import_review, load_source_provenance,
    parse_envelope, read_bounded,
};
use secureflow_web::{
    AuthorizationStatus as WebAuthorizationStatus, AuthorizedRepository, InventorySource,
    NetworkExecution as WebNetworkExecution, ScopeAuthorization, ScopeLimits, ScopePolicy,
    SourceKind as WebSourceKind, WebScopeDraft,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const RUN_SCHEMA: &str = include_str!("../../../schemas/secureflow-run-v1.schema.json");
const KNOWLEDGE_SCHEMA_V1: &str =
    include_str!("../../../schemas/secureflow-knowledge-record-v1.schema.json");
const KNOWLEDGE_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-knowledge-record-v2.schema.json");
const SECURE_REVIEW_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-secure-review-v1.schema.json");
const BENCHMARK_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-benchmark-result-v1.schema.json");
const AI_REQUEST_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-ai-request-v1.schema.json");
const AI_RESPONSE_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-ai-response-v1.schema.json");
const CORRELATION_SCHEMA_V1: &str =
    include_str!("../../../schemas/secureflow-correlation-v1.schema.json");
const CORRELATION_SCHEMA_V2: &str =
    include_str!("../../../schemas/secureflow-correlation-v2.schema.json");
const ORCHESTRATION_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-orchestration-v1.schema.json");
const PROSPECTIVE_PROTOCOL_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-prospective-protocol-v1.schema.json");
const ADVISORY_DELTA_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-advisory-delta-v1.schema.json");
const WEB_SCOPE_SCHEMA: &str = include_str!("../../../schemas/secureflow-web-scope-v1.schema.json");
const WEB_INVENTORY_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-web-inventory-v1.schema.json");
const WEB_INFERENCE_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-web-inference-v1.schema.json");
const WEB_ASSESSMENT_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-web-assessment-v1.schema.json");
const WEB_CASE_SCHEMA: &str = include_str!("../../../schemas/secureflow-web-case-v1.schema.json");
const WEB_LAB_RESULT_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-web-lab-result-v1.schema.json");
const WEB_CORPUS_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-web-development-corpus-v1.schema.json");
const WEB_CORPUS_RESULT_SCHEMA: &str =
    include_str!("../../../schemas/secureflow-web-corpus-result-v1.schema.json");

const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
const MAX_LICENSE_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_PROSPECTIVE_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HUMAN_EVIDENCE_BYTES: u64 = 64 * 1024 * 1024;
const CATALOG_BATCH_BYTES: usize = 64 * 1024 * 1024;
const CATALOG_BATCH_RECORDS: usize = 50_000;
const MAX_CATALOG_INPUT_DEPTH: usize = 64;
const AUTHORIZATION_EXPIRY_MARGIN: Duration = Duration::from_millis(100);

#[derive(Debug, Parser)]
#[command(
    name = "secureflow",
    version,
    about = "Local-first orchestration for authorized security analysis"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the normative SecureFlow run schema.
    Schema,
    /// Print the normative SecureFlow knowledge-record schema.
    KnowledgeSchema {
        /// Contract version to print; v2 is the current write format.
        #[arg(long, value_enum, default_value_t = KnowledgeSchemaVersion::V2)]
        version: KnowledgeSchemaVersion,
    },
    /// Print the normative SecureFlow contextual-review envelope schema.
    SecureReviewSchema,
    /// Print the normative SecureFlow benchmark-result envelope schema.
    BenchmarkSchema,
    /// Print the normative redacted AI request schema.
    AiRequestSchema,
    /// Print the normative structured AI response schema.
    AiResponseSchema,
    /// Print a normative finding-to-advisory correlation schema.
    CorrelationSchema {
        /// Contract version to print; v2 evaluates exact versions and SEMVER ranges.
        #[arg(long, value_enum, default_value_t = CorrelationSchemaVersion::V2)]
        version: CorrelationSchemaVersion,
    },
    /// Print the normative deterministic orchestration-plan schema.
    OrchestrationSchema,
    /// Print the normative sealed prospective benchmark protocol schema.
    ProspectiveProtocolSchema,
    /// Print one normative SecureFlow Web schema.
    WebSchema {
        #[arg(value_enum)]
        kind: WebArtifactKind,
    },
    /// Create a sealed offline scope for one explicitly authorized local repository.
    WebScopeCreate {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        repository_label: String,
        #[arg(long)]
        authorization_reference: String,
        #[arg(long)]
        authorization_reviewer: String,
        /// RFC3339 expiration for the authorization.
        #[arg(long)]
        authorization_expires_at: String,
        #[arg(long, default_value_t = 100_000)]
        max_files: u64,
        #[arg(long, default_value_t = 8_388_608)]
        max_file_bytes: u64,
        #[arg(long, default_value_t = 1_073_741_824)]
        max_total_bytes: u64,
        #[arg(long, default_value_t = 100_000)]
        max_routes: u64,
        #[arg(long, default_value_t = 10_000)]
        max_sources: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Seal a reviewed SecureFlow Web scope draft without enabling network execution.
    WebScopeSeal {
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build a deterministic Next.js route inventory from an authorized local repository.
    WebInventoryNextjs {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        scope: PathBuf,
        #[arg(long)]
        source_name: String,
        #[arg(long)]
        source_revision: String,
        #[arg(long)]
        source_license_spdx: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Infer local API candidates without network access or target-code execution.
    WebInfer {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        scope: PathBuf,
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Assess an operator-provided route/control matrix without automatic validation.
    WebAssess {
        #[arg(long)]
        scope: PathBuf,
        #[arg(long)]
        inventory: PathBuf,
        /// JSON array of strict CoverageRoute records.
        #[arg(long)]
        coverage: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Record a human reproduction decision as a new linked web assessment.
    WebReviewAssessment {
        #[arg(long)]
        assessment: PathBuf,
        #[arg(long)]
        observation_id: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        rationale: String,
        /// Retained local reproduction artifact to hash; its contents are not embedded.
        #[arg(long)]
        evidence: PathBuf,
        /// Stable, non-secret reference recorded in the assessment.
        #[arg(long)]
        evidence_reference: String,
        #[arg(long)]
        evidence_description: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a retained SecureFlow Web artifact.
    WebValidate {
        #[arg(value_enum)]
        kind: WebArtifactKind,
        path: PathBuf,
    },
    /// Compare a retained web inventory against a labeled, licensed case.
    WebLab {
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        sarif_output: PathBuf,
    },
    /// Evaluate the 20-40 case synthetic development corpus against retained artifacts.
    WebCorpusEvaluate {
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        inference: PathBuf,
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a local secureflow-run-v1 manifest.
    ValidateRun { path: PathBuf },
    /// Export a validated run as a local Markdown report.
    ExportReport {
        /// Input secureflow-run-v1 manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Markdown output path.
        #[arg(long)]
        output: PathBuf,
        /// Include human rationale text; omitted by default for safer sharing.
        #[arg(long)]
        include_human_rationale: bool,
    },
    /// List findings from a validated run manifest.
    ListFindings {
        /// Input secureflow-run-v1 manifest.
        manifest: PathBuf,
        /// Optional human-decision filter.
        #[arg(long, value_enum)]
        decision: Option<FindingDecision>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Show one complete canonical finding as JSON.
    ShowFinding {
        /// Input secureflow-run-v1 manifest.
        manifest: PathBuf,
        /// Stable finding ID.
        finding_id: String,
    },
    /// Import reviewed findings into a local append-only JSONL ledger.
    KnowledgeImport {
        /// Input secureflow-run-v1 manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Local knowledge ledger path.
        #[arg(long)]
        ledger: PathBuf,
        /// Operator-declared license state for the analyzed source snapshot.
        #[arg(long, value_enum)]
        source_license_status: KnowledgeLicenseStatus,
        /// Operator-declared SPDX expression; required only for spdx-declared.
        #[arg(long)]
        source_license_expression: Option<String>,
        /// Local license evidence to hash; required for spdx-declared.
        #[arg(long)]
        source_license_evidence: Option<PathBuf>,
    },
    /// Query a validated local knowledge ledger.
    KnowledgeList {
        /// Local knowledge ledger path.
        ledger: PathBuf,
        /// Optional terminal human-decision filter.
        #[arg(long, value_enum)]
        decision: Option<ReviewDecision>,
        /// Optional exact rule ID filter.
        #[arg(long)]
        rule: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Prepare a bounded, attributed and reproducible snapshot from an OSV ecosystem ZIP.
    SnapshotPrepareOsv {
        /// Previously acquired OSV ecosystem ZIP. SecureFlow does not download it.
        #[arg(long)]
        archive: PathBuf,
        /// New snapshot directory. Existing paths are never overwritten.
        #[arg(long)]
        output: PathBuf,
        /// Public immutable or versioned artifact URL.
        #[arg(long)]
        artifact_locator: String,
        /// Immutable HTTP/GCS/Git revision for the acquired artifact.
        #[arg(long)]
        artifact_revision: String,
        /// Exact OSV ecosystem expected in every accepted record.
        #[arg(long)]
        expected_ecosystem: String,
        /// RFC3339 acquisition timestamp supplied by the acquisition boundary.
        #[arg(long)]
        acquired_at: String,
        /// Local GitHub Advisory Database license evidence.
        #[arg(long)]
        github_license_evidence: Option<PathBuf>,
        /// Local RustSec license policy evidence.
        #[arg(long)]
        rustsec_license_evidence: Option<PathBuf>,
        /// Local OpenSSF Malicious Packages Apache-2.0 license evidence.
        #[arg(long)]
        openssf_malicious_packages_license_evidence: Option<PathBuf>,
    },
    /// Validate an extracted advisory snapshot and optionally its original ZIP.
    SnapshotValidate {
        /// Snapshot manifest path.
        manifest: PathBuf,
        /// Original ZIP to re-hash against artifact provenance.
        #[arg(long)]
        archive: Option<PathBuf>,
    },
    /// Print the normative reproducible OSV incremental-delta schema.
    AdvisoryDeltaSchema,
    /// Prepare a local delta from an acquired per-ecosystem OSV modified index and payloads.
    DeltaPrepareOsv {
        /// Acquired per-ecosystem `modified_id.csv`.
        #[arg(long)]
        modified_index: PathBuf,
        /// Flat directory containing exactly one `<ID>.json` payload per selected index row.
        #[arg(long)]
        records: PathBuf,
        /// New immutable delta directory. Existing paths are never overwritten.
        #[arg(long)]
        output: PathBuf,
        /// Public locator for the exact per-ecosystem modified index.
        #[arg(long)]
        index_locator: String,
        /// Immutable ETag, generation or acquisition revision for the index.
        #[arg(long)]
        index_revision: String,
        /// Exact OSV ecosystem expected in every accepted payload.
        #[arg(long)]
        expected_ecosystem: String,
        /// RFC3339 time at which the index and payload set were acquired.
        #[arg(long)]
        acquired_at: String,
        /// Exclusive RFC3339 modified cursor already fully processed.
        #[arg(long)]
        after_modified: String,
        /// Complete catalog snapshot on which this delta chain is based.
        #[arg(long)]
        base_snapshot_id: String,
        /// Previous complete delta in this exact chain; omitted only for the first delta after a snapshot.
        #[arg(long)]
        previous_delta_id: Option<String>,
        /// Local GitHub Advisory Database license evidence.
        #[arg(long)]
        github_license_evidence: Option<PathBuf>,
        /// Local RustSec license policy evidence.
        #[arg(long)]
        rustsec_license_evidence: Option<PathBuf>,
        /// Local OpenSSF Malicious Packages Apache-2.0 license evidence.
        #[arg(long)]
        openssf_malicious_packages_license_evidence: Option<PathBuf>,
    },
    /// Validate an extracted advisory delta and every retained hash.
    DeltaValidate {
        /// Delta manifest path.
        manifest: PathBuf,
    },
    /// Create or verify the indexed local advisory catalog.
    CatalogInit {
        /// SQLite catalog path.
        database: PathBuf,
    },
    /// Import local OSV JSON records with explicit source provenance.
    CatalogImportOsv {
        /// SQLite catalog path.
        #[arg(long)]
        database: PathBuf,
        /// One OSV JSON file or a directory tree of individual JSON records.
        #[arg(long)]
        input: PathBuf,
        /// Stable home-database or feed name.
        #[arg(long)]
        source_name: String,
        /// SPDX expression asserted for this exact source feed.
        #[arg(long)]
        source_license_expression: String,
        /// Local license or terms artifact whose bytes will be hashed.
        #[arg(long)]
        source_license_evidence: PathBuf,
        /// Public URL, repository revision or other stable source locator.
        #[arg(long)]
        source_locator: String,
    },
    /// Import every accepted partition from a validated advisory snapshot.
    CatalogImportSnapshot {
        /// SQLite catalog path outside the immutable snapshot tree.
        #[arg(long)]
        database: PathBuf,
        /// Snapshot manifest path.
        #[arg(long)]
        manifest: PathBuf,
        /// Original ZIP to verify again before importing.
        #[arg(long)]
        archive: Option<PathBuf>,
    },
    /// Import a validated OSV incremental delta without inferring deletion from absence.
    CatalogImportDelta {
        /// Existing SQLite catalog containing the complete base snapshot.
        #[arg(long)]
        database: PathBuf,
        /// Validated advisory delta manifest.
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Report physical and logical catalog counts as JSON.
    CatalogStats {
        /// Existing SQLite catalog path.
        database: PathBuf,
    },
    /// Run explicit SQLite and foreign-key integrity checks.
    CatalogCheck {
        /// Existing SQLite catalog path.
        database: PathBuf,
    },
    /// Rebuild a dirty or stale full-text index from normalized records.
    CatalogRebuildIndex {
        /// Existing SQLite catalog path.
        database: PathBuf,
    },
    /// Recompute exact-alias components from active source records, allowing splits.
    CatalogRebuildCanonicalization {
        /// Existing SQLite catalog path.
        database: PathBuf,
    },
    /// Create a consistent, hash-bound catalog backup without overwriting files.
    CatalogBackup {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        manifest_output: PathBuf,
    },
    /// Verify a catalog backup against its manifest and SQLite integrity.
    CatalogBackupVerify {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Restore a verified backup to a new catalog path without overwriting files.
    CatalogRestore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        manifest_output: PathBuf,
    },
    /// Resolve an exact CVE, GHSA, OSV, RUSTSEC or other identifier.
    CatalogLookup {
        /// Existing SQLite catalog path.
        #[arg(long)]
        database: PathBuf,
        /// Exact identifier or alias.
        identifier: String,
        /// Maximum source records returned.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Full-text search advisory titles and details.
    CatalogSearch {
        /// Existing SQLite catalog path.
        #[arg(long)]
        database: PathBuf,
        /// Literal phrase to search.
        query: String,
        /// Maximum source records returned.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Find advisories for an exact ecosystem and package name.
    CatalogPackage {
        /// Existing SQLite catalog path.
        #[arg(long)]
        database: PathBuf,
        /// OSV ecosystem, for example crates.io or npm.
        ecosystem: String,
        /// Exact package name.
        package: String,
        /// Maximum source records returned.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Link one finding to exact package advisory context without validating it.
    CorrelatePackage {
        /// Validated SecureFlow run manifest containing the candidate.
        #[arg(long)]
        manifest: PathBuf,
        /// Stable finding ID in the run.
        #[arg(long)]
        finding_id: String,
        /// Existing advisory catalog with at least one complete snapshot.
        #[arg(long)]
        database: PathBuf,
        /// Exact OSV ecosystem declared by the operator.
        #[arg(long)]
        ecosystem: String,
        /// Exact package name declared by the operator.
        #[arg(long)]
        package: String,
        /// Optional installed version evaluated against exact lists and strict OSV SEMVER ranges.
        #[arg(long)]
        version: Option<String>,
        /// New correlation envelope. Inputs are never modified.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a local conservative correlation envelope.
    CorrelationValidate { path: PathBuf },
    /// Derive a fail-closed local phase plan from validated retained artifacts.
    OrchestratePlan {
        /// Validated SecureFlow run manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Optional validated Secure Skill contextual-review envelope.
        #[arg(long)]
        secure_review: Option<PathBuf>,
        /// Zero or more validated package-correlation envelopes.
        #[arg(long)]
        correlation: Vec<PathBuf>,
        /// Optional evaluation-only benchmark envelope.
        #[arg(long)]
        benchmark: Option<PathBuf>,
        /// Optional validated web inventory linked to the run target hash.
        #[arg(long)]
        web_inventory: Option<PathBuf>,
        /// Optional validated local-only API inference linked to the web inventory.
        #[arg(long)]
        web_inference: Option<PathBuf>,
        /// Optional conservative web assessment; requires --web-inventory.
        #[arg(long)]
        web_assessment: Option<PathBuf>,
        /// Optional evaluation-only web lab result; requires --web-inventory.
        #[arg(long)]
        web_lab_result: Option<PathBuf>,
        /// Optional synthetic development-corpus result; requires web inventory and inference.
        #[arg(long)]
        web_corpus_result: Option<PathBuf>,
        /// New orchestration envelope. Inputs are never modified.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a local orchestration-plan envelope.
    OrchestrationValidate { path: PathBuf },
    /// Import a Secure Skill review-contract 1.1 payload as contextual candidates.
    SecureReviewImport {
        /// Secure Skill review-contract 1.1 JSON payload.
        #[arg(long)]
        review: PathBuf,
        /// Validated SecureFlow run that binds this review to an authorized target.
        #[arg(long)]
        manifest: PathBuf,
        /// Local Secure Skill repository or release root used for this review.
        #[arg(long)]
        secure_skill_root: PathBuf,
        /// Exact lowercase Git commit hash of the Secure Skill source.
        #[arg(long)]
        secure_skill_revision: String,
        /// Output contextual-review envelope. Inputs are never modified.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a local SecureFlow contextual-review envelope.
    SecureReviewValidate { path: PathBuf },
    /// List contextual candidates without asserting human validation.
    SecureReviewList {
        /// Validated SecureFlow contextual-review envelope.
        envelope: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Import a retained Secure Bench result-v2 without executing a scanner.
    BenchmarkImport {
        /// Secure Bench result-v2 JSON.
        #[arg(long)]
        result: PathBuf,
        /// Exact retained run manifest referenced by the result.
        #[arg(long)]
        run_manifest: PathBuf,
        /// Exact retained suite manifest referenced by the result.
        #[arg(long)]
        suite: PathBuf,
        /// Local Secure Bench repository or release root.
        #[arg(long)]
        secure_bench_root: PathBuf,
        /// Exact lowercase Git commit hash of Secure Bench.
        #[arg(long)]
        secure_bench_revision: String,
        /// Study interpretation declared by the operator; it is retained as such.
        #[arg(long, value_enum)]
        study_kind: BenchmarkStudyKind,
        /// Output evaluation-only envelope. Inputs are never modified.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a local SecureFlow benchmark-result envelope.
    BenchmarkValidate { path: PathBuf },
    /// Summarize separate benchmark metrics and limitations.
    BenchmarkSummary {
        /// Validated SecureFlow benchmark-result envelope.
        envelope: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Seal a strict prospective-study draft before observing results.
    BenchmarkProtocolSeal {
        /// Protocol draft JSON without identity or timestamp.
        #[arg(long)]
        draft: PathBuf,
        /// New immutable-by-convention sealed protocol.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify real public holdout commitments and seal the protocol without opening labels.
    BenchmarkProtocolPreflight {
        /// Protocol draft JSON whose commitment hashes must match the supplied artifacts.
        #[arg(long)]
        draft: PathBuf,
        /// Public opaque-case corpus manifest; must not contain ground-truth labels.
        #[arg(long)]
        corpus_manifest: PathBuf,
        /// Corpus provenance manifest.
        #[arg(long)]
        provenance_manifest: PathBuf,
        /// Corpus license manifest.
        #[arg(long)]
        license_manifest: PathBuf,
        /// Frozen execution environment/configuration manifest.
        #[arg(long)]
        environment_manifest: PathBuf,
        /// New sealed protocol written only after all four hashes match.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a sealed prospective-study protocol and its content-derived ID.
    BenchmarkProtocolValidate { path: PathBuf },
    /// Prepare one local redacted AI request. This command performs no network call.
    AiPrepare {
        /// Validated SecureFlow run manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Candidate to minimize and redact.
        #[arg(long)]
        finding_id: String,
        /// Explicitly enable optional AI preparation.
        #[arg(long)]
        enable_ai: bool,
        /// Record consent for potential transmission of the redacted payload.
        #[arg(long)]
        consent_redacted_export: bool,
        /// Narrow advisory purpose.
        #[arg(long, value_enum, default_value_t = AiPurposeArg::AmbiguityAnalysis)]
        purpose: AiPurposeArg,
        /// Hard provider input-token budget.
        #[arg(long, default_value_t = ai::DEFAULT_MAX_INPUT_TOKENS)]
        max_input_tokens: u64,
        /// Hard provider output-token budget.
        #[arg(long, default_value_t = ai::DEFAULT_MAX_OUTPUT_TOKENS)]
        max_output_tokens: u64,
        /// Hard local redacted-payload byte budget.
        #[arg(long, default_value_t = ai::DEFAULT_MAX_PAYLOAD_BYTES)]
        max_payload_bytes: u64,
        /// Output request envelope. No data is transmitted.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a local redacted AI request envelope.
    AiValidateRequest { path: PathBuf },
    /// Validate a structured advisory AI response envelope.
    AiValidateResponse { path: PathBuf },
    /// Attach a measured advisory response to a derived manifest.
    AiApplyResponse {
        /// Original validated SecureFlow run manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Exact redacted request sent to the provider.
        #[arg(long)]
        request: PathBuf,
        /// Structured local response record.
        #[arg(long)]
        response: PathBuf,
        /// Derived manifest output. The original is not modified.
        #[arg(long)]
        output: PathBuf,
    },
    /// Apply one explicit human review decision and write a new manifest.
    ReviewRun {
        /// Input secureflow-run-v1 manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Stable finding ID to review.
        #[arg(long)]
        finding_id: String,
        /// Human decision; AI cannot invoke this command on its own.
        #[arg(long, value_enum)]
        decision: ReviewDecision,
        /// Human reviewer identity.
        #[arg(long)]
        reviewer: String,
        /// Rationale for the decision.
        #[arg(long)]
        rationale: String,
        /// Optional local evidence reference or note.
        #[arg(long)]
        evidence_reference: Option<String>,
        /// Output manifest. The input is never changed implicitly.
        #[arg(long)]
        output: PathBuf,
    },
    /// Execute an explicitly supplied Secure Engine binary against an authorized target.
    Scan {
        /// Engine binary path.
        #[arg(long)]
        binary: PathBuf,
        /// Authorized repository or fixture path.
        target: PathBuf,
        /// Require an explicit authorization acknowledgement.
        #[arg(long)]
        authorized: bool,
        /// Human identity asserting that this target is in scope.
        #[arg(long)]
        authorization_reviewer: String,
        /// Documented basis for authorization.
        #[arg(long, value_enum, default_value_t = ScanAuthorizationBasis::LocalProject)]
        authorization_basis: ScanAuthorizationBasis,
        /// Local ticket, policy, agreement or other scope reference.
        #[arg(long)]
        authorization_reference: Option<String>,
        /// Optional RFC3339 expiration for the authorization.
        #[arg(long)]
        authorization_expires_at: Option<String>,
        /// Kind of explicitly recorded target revision.
        #[arg(long, value_enum, requires = "target_revision")]
        target_revision_kind: Option<TargetRevisionKind>,
        /// Commit, snapshot or working-tree identifier supplied by the operator.
        #[arg(long, requires = "target_revision_kind")]
        target_revision: Option<String>,
        /// Raw secure-json-v1 output path.
        #[arg(long)]
        output: PathBuf,
        /// secureflow-run-v1 manifest output path.
        #[arg(long)]
        manifest_output: PathBuf,
        /// Process timeout in seconds.
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
        /// Linux process isolation policy. Required is the secure default.
        #[arg(long, value_enum, default_value_t = ScanSandbox::Required)]
        sandbox: ScanSandbox,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReviewDecision {
    Validated,
    Rejected,
    Abstained,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FindingDecision {
    Pending,
    Validated,
    Rejected,
    Abstained,
}

impl From<FindingDecision> for HumanDecision {
    fn from(value: FindingDecision) -> Self {
        match value {
            FindingDecision::Pending => Self::Pending,
            FindingDecision::Validated => Self::Validated,
            FindingDecision::Rejected => Self::Rejected,
            FindingDecision::Abstained => Self::Abstained,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KnowledgeSchemaVersion {
    V1,
    V2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CorrelationSchemaVersion {
    V1,
    V2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum WebArtifactKind {
    Scope,
    Inventory,
    Inference,
    Assessment,
    Case,
    LabResult,
    Corpus,
    CorpusResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum KnowledgeLicenseStatus {
    SpdxDeclared,
    PrivateOrUndisclosed,
    Unknown,
}

impl From<KnowledgeLicenseStatus> for SourceLicenseStatus {
    fn from(value: KnowledgeLicenseStatus) -> Self {
        match value {
            KnowledgeLicenseStatus::SpdxDeclared => Self::SpdxDeclared,
            KnowledgeLicenseStatus::PrivateOrUndisclosed => Self::PrivateOrUndisclosed,
            KnowledgeLicenseStatus::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BenchmarkStudyKind {
    LocalDevelopmentDiagnostic,
    HistoricalPublicDiagnostic,
    PreregisteredOneShot,
    PostOpenRecovery,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AiPurposeArg {
    AmbiguityAnalysis,
    CandidatePrioritization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ScanAuthorizationBasis {
    RepositoryOwner,
    WrittenConsent,
    OrganizationPolicy,
    LocalProject,
    OtherDocumented,
}

impl From<ScanAuthorizationBasis> for AuthorizationBasis {
    fn from(value: ScanAuthorizationBasis) -> Self {
        match value {
            ScanAuthorizationBasis::RepositoryOwner => Self::RepositoryOwner,
            ScanAuthorizationBasis::WrittenConsent => Self::WrittenConsent,
            ScanAuthorizationBasis::OrganizationPolicy => Self::OrganizationPolicy,
            ScanAuthorizationBasis::LocalProject => Self::LocalProject,
            ScanAuthorizationBasis::OtherDocumented => Self::OtherDocumented,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum TargetRevisionKind {
    Git,
    Snapshot,
    WorkingTree,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ScanSandbox {
    Required,
    Disabled,
}

impl From<ScanSandbox> for SandboxMode {
    fn from(value: ScanSandbox) -> Self {
        match value {
            ScanSandbox::Required => Self::RequiredLinuxBubblewrap,
            ScanSandbox::Disabled => Self::Disabled,
        }
    }
}

impl From<TargetRevisionKind> for RevisionKind {
    fn from(value: TargetRevisionKind) -> Self {
        match value {
            TargetRevisionKind::Git => Self::Git,
            TargetRevisionKind::Snapshot => Self::Snapshot,
            TargetRevisionKind::WorkingTree => Self::WorkingTree,
            TargetRevisionKind::Unknown => Self::Unknown,
        }
    }
}

impl From<AiPurposeArg> for ai::AiPurpose {
    fn from(value: AiPurposeArg) -> Self {
        match value {
            AiPurposeArg::AmbiguityAnalysis => Self::AmbiguityAnalysis,
            AiPurposeArg::CandidatePrioritization => Self::CandidatePrioritization,
        }
    }
}

impl From<BenchmarkStudyKind> for bench_adapter::StudyKind {
    fn from(value: BenchmarkStudyKind) -> Self {
        match value {
            BenchmarkStudyKind::LocalDevelopmentDiagnostic => Self::LocalDevelopmentDiagnostic,
            BenchmarkStudyKind::HistoricalPublicDiagnostic => Self::HistoricalPublicDiagnostic,
            BenchmarkStudyKind::PreregisteredOneShot => Self::PreregisteredOneShot,
            BenchmarkStudyKind::PostOpenRecovery => Self::PostOpenRecovery,
        }
    }
}

impl From<ReviewDecision> for HumanDecision {
    fn from(value: ReviewDecision) -> Self {
        match value {
            ReviewDecision::Validated => Self::Validated,
            ReviewDecision::Rejected => Self::Rejected,
            ReviewDecision::Abstained => Self::Abstained,
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("authorization acknowledgement is required: pass --authorized")]
    AuthorizationRequired,
    #[error("authorization reference is required for basis {0}")]
    AuthorizationReferenceRequired(&'static str),
    #[error("authorization expired or is too close to expiry for this scan")]
    AuthorizationExpired,
    #[error("invalid timeout: {provided} seconds (expected 1..={maximum})")]
    InvalidTimeout { provided: u64, maximum: u64 },
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not fingerprint target {path}: {source}")]
    TargetHash {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("review field cannot be empty: {0}")]
    EmptyReviewField(&'static str),
    #[error("review field is too long: {field} (maximum {max} characters)")]
    ReviewFieldTooLong { field: &'static str, max: usize },
    #[error("finding not found: {0}")]
    FindingNotFound(String),
    #[error("finding already has a human decision: {0}")]
    FindingAlreadyReviewed(String),
    #[error("could not format run timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid run manifest: {0}")]
    Manifest(#[from] secureflow_model::ModelError),
    #[error("engine adapter failed: {0}")]
    Adapter(#[from] secureflow_engine_adapter::AdapterError),
    #[error("knowledge import failed: {0}")]
    Knowledge(secureflow_knowledge::KnowledgeError),
    #[error("knowledge catalog failed: {0}")]
    Catalog(#[from] secureflow_knowledge::catalog::CatalogError),
    #[error("advisory snapshot failed: {0}")]
    Snapshot(#[from] secureflow_knowledge::snapshot::SnapshotError),
    #[error("advisory delta failed: {0}")]
    Delta(#[from] secureflow_knowledge::delta::DeltaError),
    #[error("catalog backup failed: {0}")]
    CatalogBackup(#[from] secureflow_knowledge::catalog_backup::BackupError),
    #[error("Secure Skill adapter failed: {0}")]
    SecureReview(#[from] secureflow_secure_adapter::AdapterError),
    #[error("Secure Bench adapter failed: {0}")]
    Benchmark(#[from] bench_adapter::BenchAdapterError),
    #[error("prospective benchmark protocol failed: {0}")]
    BenchmarkProtocol(#[from] bench_adapter::prospective::ProtocolError),
    #[error("prospective protocol artifact hash does not match draft field: {0}")]
    ProspectiveArtifactHashMismatch(&'static str),
    #[error("AI contract failed: {0}")]
    Ai(#[from] ai::AiError),
    #[error("correlation contract failed: {0}")]
    Correlation(#[from] secureflow_knowledge::correlation::CorrelationError),
    #[error("orchestration contract failed: {0}")]
    Orchestration(#[from] secureflow_orchestrator::OrchestratorError),
    #[error("web scope contract failed: {0}")]
    WebScope(#[from] secureflow_web::ScopeError),
    #[error("web inventory contract failed: {0}")]
    WebInventory(#[from] secureflow_web::InventoryError),
    #[error("web inference contract failed: {0}")]
    WebInference(#[from] secureflow_web::InferenceError),
    #[error("web assessment contract failed: {0}")]
    WebAssessment(#[from] secureflow_web::AssessmentError),
    #[error("web lab contract failed: {0}")]
    WebLab(#[from] secureflow_web::LabError),
    #[error("web development corpus contract failed: {0}")]
    WebCorpus(#[from] secureflow_web::CorpusError),
    #[error("artifact does not link to the exact run: {0}")]
    ArtifactLinkMismatch(&'static str),
    #[error("expected a regular file: {0}")]
    NotAFile(PathBuf),
    #[error("catalog input contains a symlink: {0}")]
    CatalogInputSymlink(PathBuf),
    #[error("catalog input contains no JSON records: {0}")]
    EmptyCatalogInput(PathBuf),
    #[error("catalog input exceeds {maximum} records")]
    CatalogInputTooLarge { maximum: usize },
    #[error("catalog input exceeds {maximum} directory levels at {path}")]
    CatalogInputTooDeep { path: PathBuf, maximum: usize },
    #[error("input is outside the size limit: {path} ({bytes} bytes; maximum {maximum})")]
    InputTooLarge {
        path: PathBuf,
        bytes: u64,
        maximum: u64,
    },
    #[error("refusing to write {output}: it aliases protected input {input}")]
    OutputAliasesInput { output: PathBuf, input: PathBuf },
    #[error("refusing to write {output}: it is inside protected input tree {root}")]
    OutputInsideInputTree { output: PathBuf, root: PathBuf },
    #[error("could not resolve {path} for output-safety checks: {source}")]
    PathResolution {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("target changed while the scan was running: {0}")]
    TargetChangedDuringScan(PathBuf),
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("secureflow: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Schema => {
            print!("{RUN_SCHEMA}");
            Ok(())
        }
        Command::KnowledgeSchema { version } => {
            print!(
                "{}",
                match version {
                    KnowledgeSchemaVersion::V1 => KNOWLEDGE_SCHEMA_V1,
                    KnowledgeSchemaVersion::V2 => KNOWLEDGE_SCHEMA,
                }
            );
            Ok(())
        }
        Command::SecureReviewSchema => {
            print!("{SECURE_REVIEW_SCHEMA}");
            Ok(())
        }
        Command::BenchmarkSchema => {
            print!("{BENCHMARK_SCHEMA}");
            Ok(())
        }
        Command::AiRequestSchema => {
            print!("{AI_REQUEST_SCHEMA}");
            Ok(())
        }
        Command::AiResponseSchema => {
            print!("{AI_RESPONSE_SCHEMA}");
            Ok(())
        }
        Command::CorrelationSchema { version } => {
            print!(
                "{}",
                match version {
                    CorrelationSchemaVersion::V1 => CORRELATION_SCHEMA_V1,
                    CorrelationSchemaVersion::V2 => CORRELATION_SCHEMA_V2,
                }
            );
            Ok(())
        }
        Command::OrchestrationSchema => {
            print!("{ORCHESTRATION_SCHEMA}");
            Ok(())
        }
        Command::ProspectiveProtocolSchema => {
            print!("{PROSPECTIVE_PROTOCOL_SCHEMA}");
            Ok(())
        }
        Command::WebSchema { kind } => {
            print!(
                "{}",
                match kind {
                    WebArtifactKind::Scope => WEB_SCOPE_SCHEMA,
                    WebArtifactKind::Inventory => WEB_INVENTORY_SCHEMA,
                    WebArtifactKind::Inference => WEB_INFERENCE_SCHEMA,
                    WebArtifactKind::Assessment => WEB_ASSESSMENT_SCHEMA,
                    WebArtifactKind::Case => WEB_CASE_SCHEMA,
                    WebArtifactKind::LabResult => WEB_LAB_RESULT_SCHEMA,
                    WebArtifactKind::Corpus => WEB_CORPUS_SCHEMA,
                    WebArtifactKind::CorpusResult => WEB_CORPUS_RESULT_SCHEMA,
                }
            );
            Ok(())
        }
        Command::WebScopeCreate {
            root,
            repository_label,
            authorization_reference,
            authorization_reviewer,
            authorization_expires_at,
            max_files,
            max_file_bytes,
            max_total_bytes,
            max_routes,
            max_sources,
            output,
        } => {
            ensure_output_outside_tree(&output, &root)?;
            let root_sha256 = secureflow_web::hash_repository_tree(
                &root,
                max_files,
                max_file_bytes,
                max_total_bytes,
            )?;
            let draft = WebScopeDraft {
                authorization: ScopeAuthorization {
                    status: WebAuthorizationStatus::Authorized,
                    reference: checked_review_field(
                        authorization_reference.trim(),
                        "authorization_reference",
                        300,
                    )?,
                    reviewer: checked_review_field(
                        authorization_reviewer.trim(),
                        "authorization_reviewer",
                        200,
                    )?,
                    expires_at: authorization_expires_at,
                },
                repositories: vec![AuthorizedRepository {
                    label: checked_review_field(repository_label.trim(), "repository_label", 200)?,
                    root_sha256,
                }],
                assets: vec![],
                policy: ScopePolicy {
                    passive_only: true,
                    network_execution: WebNetworkExecution::Disabled,
                    follow_redirects: false,
                    third_party_scanning: false,
                },
                limits: ScopeLimits {
                    max_files,
                    max_file_bytes,
                    max_total_bytes,
                    max_routes,
                    max_sources,
                    max_requests: 0,
                    requests_per_minute: 0,
                    max_concurrency: 0,
                },
            };
            let scope = secureflow_web::seal_scope(&serde_json::to_vec(&draft)?, None)?;
            write_atomic_new(&output, &serde_json::to_vec_pretty(&scope)?)?;
            println!(
                "web scope sealed: output={} scope_id={} network=disabled authorization_status=authorized",
                output.display(),
                scope.scope_id
            );
            Ok(())
        }
        Command::WebScopeSeal { draft, output } => {
            ensure_output_distinct(&output, &[&draft])?;
            let bytes = read_bounded_file(&draft, secureflow_web::MAX_SCOPE_BYTES)?;
            let scope = secureflow_web::seal_scope(&bytes, None)?;
            write_atomic_new(&output, &serde_json::to_vec_pretty(&scope)?)?;
            println!(
                "web scope sealed: output={} scope_id={} network=disabled authorization_status=authorized",
                output.display(),
                scope.scope_id
            );
            Ok(())
        }
        Command::WebInventoryNextjs {
            root,
            scope,
            source_name,
            source_revision,
            source_license_spdx,
            output,
        } => {
            ensure_output_distinct(&output, &[&scope])?;
            ensure_output_outside_tree(&output, &root)?;
            let now = OffsetDateTime::now_utc();
            let scope_bytes = read_bounded_file(&scope, secureflow_web::MAX_SCOPE_BYTES)?;
            let web_scope = secureflow_web::parse_scope(&scope_bytes, now)?;
            let root_sha256 = secureflow_web::hash_repository_tree(
                &root,
                web_scope.draft.limits.max_files,
                web_scope.draft.limits.max_file_bytes,
                web_scope.draft.limits.max_total_bytes,
            )?;
            let source = InventorySource::new(
                WebSourceKind::Repository,
                source_name,
                source_revision,
                root_sha256.clone(),
                source_license_spdx,
            )?;
            let inventory =
                secureflow_web::discover_nextjs(&root, &web_scope, &root_sha256, source, now)?;
            write_atomic_new(&output, &serde_json::to_vec_pretty(&inventory)?)?;
            println!(
                "web inventory complete: output={} inventory_id={} routes={} network_used=false target_code_executed=false",
                output.display(),
                inventory.inventory_id,
                inventory.stats.routes
            );
            Ok(())
        }
        Command::WebInfer {
            root,
            scope,
            inventory,
            output,
        } => {
            ensure_output_distinct(&output, &[&scope, &inventory])?;
            ensure_output_outside_tree(&output, &root)?;
            let now = OffsetDateTime::now_utc();
            let scope_bytes = read_bounded_file(&scope, secureflow_web::MAX_SCOPE_BYTES)?;
            let inventory_bytes =
                read_bounded_file(&inventory, secureflow_web::MAX_INVENTORY_BYTES)?;
            let web_scope = secureflow_web::parse_scope(&scope_bytes, now)?;
            let web_inventory = secureflow_web::parse_inventory(&inventory_bytes)?;
            let root_sha256 = secureflow_web::hash_repository_tree(
                &root,
                web_scope.draft.limits.max_files,
                web_scope.draft.limits.max_file_bytes,
                web_scope.draft.limits.max_total_bytes,
            )?;
            let inference = secureflow_web::infer_local_apis(
                &root,
                &web_scope,
                &root_sha256,
                &web_inventory,
                now,
            )?;
            write_atomic_new(&output, &serde_json::to_vec_pretty(&inference)?)?;
            println!(
                "web inference complete: output={} inference_id={} candidates={} review={} abstentions={} network_used=false",
                output.display(),
                inference.inference_id,
                inference.stats.candidates,
                inference.stats.needs_human_review,
                inference.stats.abstentions
            );
            Ok(())
        }
        Command::WebAssess {
            scope,
            inventory,
            coverage,
            output,
        } => {
            ensure_output_distinct(&output, &[&scope, &inventory, &coverage])?;
            let now = OffsetDateTime::now_utc();
            let scope_bytes = read_bounded_file(&scope, secureflow_web::MAX_SCOPE_BYTES)?;
            let inventory_bytes =
                read_bounded_file(&inventory, secureflow_web::MAX_INVENTORY_BYTES)?;
            let coverage_bytes =
                read_bounded_file(&coverage, secureflow_web::MAX_ASSESSMENT_BYTES)?;
            let web_scope = secureflow_web::parse_scope(&scope_bytes, now)?;
            let web_inventory = secureflow_web::parse_inventory(&inventory_bytes)?;
            if web_inventory.scope_id != web_scope.scope_id
                || !web_scope.authorizes_repository(&web_inventory.repository_root_sha256)
            {
                return Err(CliError::ArtifactLinkMismatch("web coverage assessment"));
            }
            let routes: Vec<secureflow_web::CoverageRoute> =
                serde_json::from_slice(&coverage_bytes)?;
            let assessment = secureflow_web::assess_routes(
                web_scope.scope_id,
                vec![web_inventory.inventory_id],
                routes,
                None,
            )?;
            write_atomic_new(&output, &serde_json::to_vec_pretty(&assessment)?)?;
            println!(
                "web assessment complete: output={} candidates={} hardening={} abstentions={} human_validated={} validation_authority=human-only",
                output.display(),
                assessment.summary.candidates,
                assessment.summary.hardening,
                assessment.summary.abstentions,
                assessment.summary.human_validated_vulnerabilities
            );
            Ok(())
        }
        Command::WebReviewAssessment {
            assessment,
            observation_id,
            reviewer,
            rationale,
            evidence,
            evidence_reference,
            evidence_description,
            output,
        } => {
            ensure_output_distinct(&output, &[&assessment, &evidence])?;
            let assessment_bytes =
                read_bounded_file(&assessment, secureflow_web::MAX_ASSESSMENT_BYTES)?;
            let evidence_bytes = read_bounded_file(&evidence, MAX_HUMAN_EVIDENCE_BYTES)?;
            let assessment = secureflow_web::parse_assessment(&assessment_bytes)?;
            let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
            let evidence_reference =
                checked_review_field(evidence_reference.trim(), "evidence_reference", 300)?;
            let reviewed = secureflow_web::record_human_validation(
                &assessment,
                &observation_id,
                secureflow_web::HumanValidation {
                    reviewer: checked_review_field(reviewer.trim(), "reviewer", 200)?,
                    reviewed_at: now.clone(),
                    rationale: checked_review_field(rationale.trim(), "rationale", 3_000)?,
                    evidence_reference: evidence_reference.clone(),
                },
                secureflow_web::EvidenceReference {
                    kind: secureflow_web::AssessmentEvidenceKind::HumanReproduction,
                    reference: evidence_reference,
                    sha256: sha256_bytes(&evidence_bytes),
                    description: checked_review_field(
                        evidence_description.trim(),
                        "evidence_description",
                        1_000,
                    )?,
                },
                now,
            )?;
            write_atomic_new(&output, &serde_json::to_vec_pretty(&reviewed)?)?;
            println!(
                "web human validation recorded: output={} parent={} human_validated={} validation_authority=human-only",
                output.display(),
                reviewed.parent_assessment_id.as_deref().unwrap_or("none"),
                reviewed.summary.human_validated_vulnerabilities
            );
            Ok(())
        }
        Command::WebValidate { kind, path } => {
            match kind {
                WebArtifactKind::Scope => {
                    let bytes = read_bounded_file(&path, secureflow_web::MAX_SCOPE_BYTES)?;
                    secureflow_web::parse_scope(&bytes, OffsetDateTime::now_utc())?;
                }
                WebArtifactKind::Inventory => {
                    let bytes = read_bounded_file(&path, secureflow_web::MAX_INVENTORY_BYTES)?;
                    secureflow_web::parse_inventory(&bytes)?;
                }
                WebArtifactKind::Inference => {
                    let bytes = read_bounded_file(&path, secureflow_web::MAX_INFERENCE_BYTES)?;
                    secureflow_web::parse_inference(&bytes)?;
                }
                WebArtifactKind::Assessment => {
                    let bytes = read_bounded_file(&path, secureflow_web::MAX_ASSESSMENT_BYTES)?;
                    secureflow_web::parse_assessment(&bytes)?;
                }
                WebArtifactKind::Case => {
                    let bytes = read_bounded_file(&path, secureflow_web::MAX_CASE_BYTES)?;
                    secureflow_web::parse_case(&bytes)?;
                }
                WebArtifactKind::LabResult => {
                    let bytes = read_bounded_file(&path, secureflow_web::MAX_LAB_RESULT_BYTES)?;
                    secureflow_web::parse_lab_result(&bytes)?;
                }
                WebArtifactKind::Corpus => {
                    let bytes = read_bounded_file(&path, secureflow_web::MAX_CORPUS_BYTES)?;
                    secureflow_web::parse_corpus(&bytes)?;
                }
                WebArtifactKind::CorpusResult => {
                    let bytes = read_bounded_file(&path, secureflow_web::MAX_CORPUS_RESULT_BYTES)?;
                    secureflow_web::parse_corpus_result(&bytes)?;
                }
            }
            println!("valid SecureFlow Web {kind:?} artifact: {}", path.display());
            Ok(())
        }
        Command::WebLab {
            inventory,
            expected,
            output,
            sarif_output,
        } => {
            ensure_output_distinct(&output, &[&inventory, &expected, &sarif_output])?;
            ensure_output_distinct(&sarif_output, &[&inventory, &expected, &output])?;
            let inventory_bytes =
                read_bounded_file(&inventory, secureflow_web::MAX_INVENTORY_BYTES)?;
            let expected_bytes = read_bounded_file(&expected, secureflow_web::MAX_CASE_BYTES)?;
            let inventory = secureflow_web::parse_inventory(&inventory_bytes)?;
            let result = secureflow_web::compare_inventory(&inventory, &expected_bytes)?;
            let sarif = secureflow_web::lab_result_sarif(&result)?;
            write_atomic_new(&output, &serde_json::to_vec_pretty(&result)?)?;
            write_atomic_new(&sarif_output, &serde_json::to_vec_pretty(&sarif)?)?;
            println!(
                "web lab complete: output={} matched={} missing={} unexpected={} evaluation_only=true superiority_claim_allowed=false",
                output.display(),
                result.counts.matched_routes,
                result.counts.missing_routes,
                result.counts.unexpected_routes
            );
            Ok(())
        }
        Command::WebCorpusEvaluate {
            inventory,
            inference,
            corpus,
            output,
        } => {
            ensure_output_distinct(&output, &[&inventory, &inference, &corpus])?;
            let inventory_bytes =
                read_bounded_file(&inventory, secureflow_web::MAX_INVENTORY_BYTES)?;
            let inference_bytes =
                read_bounded_file(&inference, secureflow_web::MAX_INFERENCE_BYTES)?;
            let corpus_bytes = read_bounded_file(&corpus, secureflow_web::MAX_CORPUS_BYTES)?;
            let inventory = secureflow_web::parse_inventory(&inventory_bytes)?;
            let inference = secureflow_web::parse_inference(&inference_bytes)?;
            let result = secureflow_web::evaluate_corpus(&inventory, &inference, &corpus_bytes)?;
            write_atomic_new(&output, &serde_json::to_vec_pretty(&result)?)?;
            println!(
                "web development corpus complete: output={} passed={} failed={} total={} independent_holdout=false superiority_claim_allowed=false",
                output.display(),
                result.counts.passed,
                result.counts.failed,
                result.counts.total
            );
            Ok(())
        }
        Command::AdvisoryDeltaSchema => {
            print!("{ADVISORY_DELTA_SCHEMA}");
            Ok(())
        }
        Command::ValidateRun { path } => {
            load_manifest(&path)?;
            println!("valid secureflow-run-v1: {}", path.display());
            Ok(())
        }
        Command::ExportReport {
            manifest,
            output,
            include_human_rationale,
        } => {
            ensure_output_distinct(&output, &[&manifest])?;
            let (_, run_manifest) = load_manifest(&manifest)?;
            let report = render_markdown_report(&run_manifest, include_human_rationale);
            write_atomic(&output, report.as_bytes())?;
            println!(
                "local Markdown report exported: report={} candidates={} human_rationale_included={}",
                output.display(),
                run_manifest.findings.len(),
                include_human_rationale,
            );
            Ok(())
        }
        Command::ListFindings {
            manifest,
            decision,
            format,
        } => {
            let (_, run_manifest) = load_manifest(&manifest)?;
            let decision = decision.map(HumanDecision::from);
            let findings = run_manifest
                .findings
                .iter()
                .filter(|finding| {
                    decision.is_none_or(|value| finding.human_review.decision == value)
                })
                .collect::<Vec<_>>();
            match format {
                OutputFormat::Json => {
                    let output = serde_json::json!({
                        "contract_version": run_manifest.contract_version,
                        "run_id": run_manifest.run_id,
                        "count": findings.len(),
                        "findings": findings,
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                }
                OutputFormat::Text => print_findings(&findings),
            }
            Ok(())
        }
        Command::ShowFinding {
            manifest,
            finding_id,
        } => {
            let (_, run_manifest) = load_manifest(&manifest)?;
            let finding = run_manifest
                .findings
                .iter()
                .find(|finding| finding.finding_id == finding_id)
                .ok_or_else(|| CliError::FindingNotFound(finding_id))?;
            println!("{}", serde_json::to_string_pretty(finding)?);
            Ok(())
        }
        Command::KnowledgeImport {
            manifest,
            ledger,
            source_license_status,
            source_license_expression,
            source_license_evidence,
        } => {
            ensure_output_distinct(&ledger, &[&manifest])?;
            if let Some(evidence) = source_license_evidence.as_deref() {
                ensure_output_distinct(&ledger, &[evidence])?;
            }
            let (bytes, run_manifest) = load_manifest(&manifest)?;
            let evidence_sha256 = source_license_evidence
                .as_ref()
                .map(|path| {
                    read_bounded_file(path, MAX_LICENSE_EVIDENCE_BYTES)
                        .map(|bytes| sha256_bytes(&bytes))
                })
                .transpose()?;
            let source_license = SourceLicense::operator_declared(
                source_license_status.into(),
                source_license_expression,
                evidence_sha256,
            )
            .map_err(CliError::Knowledge)?;
            let result = import_manifest_to_ledger(&bytes, &run_manifest, &ledger, source_license)
                .map_err(CliError::Knowledge)?;
            println!(
                "knowledge import: ledger={} added={} skipped={} duplicate_observations_linked={} manifest_sha256={}",
                ledger.display(),
                result.records_added,
                result.records_skipped,
                result.duplicates_linked,
                result.manifest_sha256
            );
            Ok(())
        }
        Command::KnowledgeList {
            ledger,
            decision,
            rule,
            format,
        } => {
            let records = read_ledger(&ledger).map_err(CliError::Knowledge)?;
            let decision = decision.map(HumanDecision::from);
            let records = records
                .iter()
                .filter(|record| decision.is_none_or(|value| record.decision() == value))
                .filter(|record| rule.as_ref().is_none_or(|value| record.rule_id() == value))
                .collect::<Vec<_>>();
            match format {
                OutputFormat::Json => {
                    let output = serde_json::json!({
                        "latest_record_version": secureflow_knowledge::RECORD_VERSION,
                        "count": records.len(),
                        "records": records,
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                }
                OutputFormat::Text => print_knowledge_records(&records),
            }
            Ok(())
        }
        Command::SnapshotPrepareOsv {
            archive,
            output,
            artifact_locator,
            artifact_revision,
            expected_ecosystem,
            acquired_at,
            github_license_evidence,
            rustsec_license_evidence,
            openssf_malicious_packages_license_evidence,
        } => {
            ensure_output_distinct(&output, &[&archive])?;
            let manifest = prepare_osv_zip(&SnapshotPrepareConfig {
                archive,
                output: output.clone(),
                artifact_locator,
                artifact_revision,
                expected_ecosystem,
                acquired_at,
                github_license_evidence,
                rustsec_license_evidence,
                openssf_malicious_packages_license_evidence,
            })?;
            println!(
                "snapshot prepared: directory={} snapshot_id={} accepted={} quarantined={} sources={} archive_sha256={} validation_authority=human-only",
                output.display(),
                manifest.snapshot_id,
                manifest.accounting.accepted_records,
                manifest.accounting.quarantined_records,
                manifest.sources.len(),
                manifest.artifact.sha256,
            );
            Ok(())
        }
        Command::SnapshotValidate { manifest, archive } => {
            let (snapshot, manifest_sha256) = load_and_validate_snapshot(&manifest)?;
            if let Some(archive) = archive.as_deref() {
                validate_snapshot_archive(&snapshot, archive)?;
            }
            println!(
                "valid {}: manifest={} snapshot_id={} manifest_sha256={} accepted={} quarantined={} archive_verified={} validation_authority=human-only",
                snapshot.contract_version,
                manifest.display(),
                snapshot.snapshot_id,
                manifest_sha256,
                snapshot.accounting.accepted_records,
                snapshot.accounting.quarantined_records,
                archive.is_some(),
            );
            Ok(())
        }
        Command::DeltaPrepareOsv {
            modified_index,
            records,
            output,
            index_locator,
            index_revision,
            expected_ecosystem,
            acquired_at,
            after_modified,
            base_snapshot_id,
            previous_delta_id,
            github_license_evidence,
            rustsec_license_evidence,
            openssf_malicious_packages_license_evidence,
        } => {
            ensure_output_distinct(&output, &[&modified_index])?;
            ensure_output_outside_tree(&output, &records)?;
            let manifest = prepare_osv_delta(&DeltaPrepareConfig {
                modified_index,
                records,
                output: output.clone(),
                index_locator,
                index_revision,
                expected_ecosystem,
                acquired_at,
                after_modified,
                base_snapshot_id,
                previous_delta_id,
                github_license_evidence,
                rustsec_license_evidence,
                openssf_malicious_packages_license_evidence,
            })?;
            println!(
                "advisory delta prepared: directory={} delta_id={} selected={} accepted={} quarantined={} withdrawn={} through={} absence_deactivates_record=false validation_authority=human-only",
                output.display(),
                manifest.delta_id,
                manifest.accounting.selected_entries,
                manifest.accounting.accepted_records,
                manifest.accounting.quarantined_records,
                manifest.accounting.withdrawn_records,
                manifest.cursor.through_modified_inclusive,
            );
            Ok(())
        }
        Command::DeltaValidate { manifest } => {
            let (delta, manifest_sha256) = load_and_validate_delta(&manifest)?;
            println!(
                "valid {}: manifest={} delta_id={} manifest_sha256={} base_snapshot_id={} accepted={} quarantined={} withdrawn={} through={} absence_deactivates_record=false validation_authority=human-only",
                delta.contract_version,
                manifest.display(),
                delta.delta_id,
                manifest_sha256,
                delta.base_snapshot_id,
                delta.accounting.accepted_records,
                delta.accounting.quarantined_records,
                delta.accounting.withdrawn_records,
                delta.cursor.through_modified_inclusive,
            );
            Ok(())
        }
        Command::CatalogInit { database } => {
            let catalog = Catalog::open_or_create(&database)?;
            let stats = catalog.stats()?;
            println!(
                "catalog ready: database={} schema_version={} source_records={} canonical_vulnerabilities={}",
                database.display(),
                stats.schema_version,
                stats.source_records,
                stats.canonical_vulnerabilities,
            );
            Ok(())
        }
        Command::CatalogImportOsv {
            database,
            input,
            source_name,
            source_license_expression,
            source_license_evidence,
            source_locator,
        } => {
            ensure_catalog_database_outside_input(&database, &input)?;
            ensure_output_distinct(&database, &[&source_license_evidence])?;
            let evidence = read_bounded_file(&source_license_evidence, MAX_LICENSE_EVIDENCE_BYTES)?;
            let source = CatalogSource {
                name: source_name,
                license_expression: source_license_expression,
                license_evidence_sha256: sha256_bytes(&evidence),
                locator: source_locator,
            };
            let files = collect_osv_files(&input)?;
            let mut catalog = Catalog::open_or_create(&database)?;
            let mut total = CatalogImportResult::default();
            let mut batch = Vec::new();
            let mut batch_bytes = 0_usize;
            for path in files {
                let bytes = read_bounded_file(&path, MAX_OSV_RECORD_BYTES)?;
                batch_bytes = batch_bytes.saturating_add(bytes.len());
                batch.push(bytes);
                if batch.len() >= CATALOG_BATCH_RECORDS || batch_bytes >= CATALOG_BATCH_BYTES {
                    total
                        .merge(catalog.import_osv_batch_deferred_search(&source, batch.drain(..))?);
                    batch_bytes = 0;
                }
            }
            if !batch.is_empty() {
                total.merge(catalog.import_osv_batch_deferred_search(&source, batch.drain(..))?);
            }
            catalog.rebuild_search_index()?;
            let stats = catalog.stats()?;
            println!(
                "OSV catalog import: database={} seen={} inserted={} updated={} unchanged={} duplicate_records_linked={} canonical_groups_merged={} total_source_records={} total_canonical_vulnerabilities={}",
                database.display(),
                total.records_seen,
                total.records_inserted,
                total.records_updated,
                total.records_unchanged,
                total.duplicate_records_linked,
                total.canonical_groups_merged,
                stats.source_records,
                stats.canonical_vulnerabilities,
            );
            Ok(())
        }
        Command::CatalogImportSnapshot {
            database,
            manifest,
            archive,
        } => {
            let snapshot_root = manifest
                .parent()
                .ok_or(CliError::NotAFile(manifest.clone()))?;
            ensure_output_outside_tree(&database, snapshot_root)?;
            let (snapshot, manifest_sha256) = load_and_validate_snapshot(&manifest)?;
            if let Some(archive) = archive.as_deref() {
                validate_snapshot_archive(&snapshot, archive)?;
            }
            let mut catalog = Catalog::open_or_create(&database)?;
            catalog.register_snapshot(&CatalogSnapshot {
                snapshot_id: snapshot.snapshot_id.clone(),
                manifest_sha256: manifest_sha256.clone(),
                artifact_sha256: snapshot.artifact.sha256.clone(),
                artifact_revision: snapshot.artifact.revision.clone(),
                expected_ecosystem: snapshot.expected_ecosystem.clone(),
                acquired_at: snapshot.acquired_at.clone(),
                accepted_records: snapshot.accounting.accepted_records,
                quarantined_records: snapshot.accounting.quarantined_records,
            })?;
            let mut total = CatalogImportResult::default();
            for source_metadata in &snapshot.sources {
                let source = CatalogSource {
                    name: source_metadata.name.clone(),
                    license_expression: source_metadata.license_expression.clone(),
                    license_evidence_sha256: source_metadata.license_evidence_sha256.clone(),
                    locator: source_metadata.locator.clone(),
                };
                let mut batch = Vec::new();
                let mut batch_bytes = 0_usize;
                for record in snapshot
                    .records
                    .iter()
                    .filter(|record| record.source_name == source_metadata.name)
                {
                    let path = snapshot_root.join(&record.stored_path);
                    let bytes = read_bounded_file(&path, MAX_OSV_RECORD_BYTES)?;
                    batch_bytes = batch_bytes.saturating_add(bytes.len());
                    batch.push(bytes);
                    if batch.len() >= CATALOG_BATCH_RECORDS || batch_bytes >= CATALOG_BATCH_BYTES {
                        total.merge(catalog.import_osv_snapshot_batch_deferred_search(
                            &source,
                            &snapshot.snapshot_id,
                            batch.drain(..),
                        )?);
                        batch_bytes = 0;
                    }
                }
                if !batch.is_empty() {
                    total.merge(catalog.import_osv_snapshot_batch_deferred_search(
                        &source,
                        &snapshot.snapshot_id,
                        batch.drain(..),
                    )?);
                }
                total.merge(catalog.complete_snapshot_source(
                    &source,
                    &snapshot.snapshot_id,
                    source_metadata.record_count,
                )?);
            }
            catalog.complete_snapshot(&snapshot.snapshot_id)?;
            catalog.rebuild_search_index()?;
            let stats = catalog.stats()?;
            println!(
                "snapshot imported: database={} snapshot_id={} manifest_sha256={} seen={} inserted={} updated={} unchanged={} deactivated={} quarantined_not_imported={} total_source_records={} active_source_records={} total_canonical_vulnerabilities={} archive_verified={} validation_authority=human-only",
                database.display(),
                snapshot.snapshot_id,
                manifest_sha256,
                total.records_seen,
                total.records_inserted,
                total.records_updated,
                total.records_unchanged,
                total.records_deactivated,
                snapshot.accounting.quarantined_records,
                stats.source_records,
                stats.active_source_records,
                stats.canonical_vulnerabilities,
                archive.is_some(),
            );
            Ok(())
        }
        Command::CatalogImportDelta { database, manifest } => {
            let delta_root = manifest
                .parent()
                .ok_or(CliError::NotAFile(manifest.clone()))?;
            ensure_output_outside_tree(&database, delta_root)?;
            let (delta, manifest_sha256) = load_and_validate_delta(&manifest)?;
            let mut catalog = Catalog::open_existing_writable(&database)?;
            catalog.register_delta(&CatalogDelta {
                delta_id: delta.delta_id.clone(),
                manifest_sha256: manifest_sha256.clone(),
                index_sha256: delta.index.sha256.clone(),
                index_revision: delta.index.revision.clone(),
                expected_ecosystem: delta.expected_ecosystem.clone(),
                acquired_at: delta.acquired_at.clone(),
                after_modified: delta.cursor.after_modified_exclusive.clone(),
                through_modified: delta.cursor.through_modified_inclusive.clone(),
                base_snapshot_id: delta.base_snapshot_id.clone(),
                previous_delta_id: delta.previous_delta_id.clone(),
                accepted_records: delta.accounting.accepted_records,
                quarantined_records: delta.accounting.quarantined_records,
                withdrawn_records: delta.accounting.withdrawn_records,
            })?;
            let mut total = CatalogImportResult::default();
            for source_metadata in &delta.sources {
                let source = CatalogSource {
                    name: source_metadata.name.clone(),
                    license_expression: source_metadata.license_expression.clone(),
                    license_evidence_sha256: source_metadata.license_evidence_sha256.clone(),
                    locator: source_metadata.locator.clone(),
                };
                let mut batch = Vec::new();
                let mut batch_bytes = 0_usize;
                for record in delta
                    .records
                    .iter()
                    .filter(|record| record.source_name == source_metadata.name)
                {
                    let bytes = read_bounded_file(
                        &delta_root.join(&record.stored_path),
                        MAX_OSV_RECORD_BYTES,
                    )?;
                    batch_bytes = batch_bytes.saturating_add(bytes.len());
                    batch.push(bytes);
                    if batch.len() >= CATALOG_BATCH_RECORDS || batch_bytes >= CATALOG_BATCH_BYTES {
                        total.merge(catalog.import_osv_delta_batch(
                            &source,
                            &delta.delta_id,
                            batch.drain(..),
                        )?);
                        batch_bytes = 0;
                    }
                }
                if !batch.is_empty() {
                    total.merge(catalog.import_osv_delta_batch(
                        &source,
                        &delta.delta_id,
                        batch.drain(..),
                    )?);
                }
                catalog.complete_delta_source(
                    &source,
                    &delta.delta_id,
                    source_metadata.record_count,
                    source_metadata.withdrawn_records,
                )?;
            }
            catalog.complete_delta(&delta.delta_id)?;
            let stats = catalog.stats()?;
            println!(
                "advisory delta imported: database={} delta_id={} manifest_sha256={} seen={} inserted={} updated={} unchanged={} withdrawn={} quarantined_not_imported={} complete_deltas={} active_source_records={} through={} absence_deactivates_record=false validation_authority=human-only",
                database.display(),
                delta.delta_id,
                manifest_sha256,
                total.records_seen,
                total.records_inserted,
                total.records_updated,
                total.records_unchanged,
                delta.accounting.withdrawn_records,
                delta.accounting.quarantined_records,
                stats.complete_deltas,
                stats.active_source_records,
                delta.cursor.through_modified_inclusive,
            );
            Ok(())
        }
        Command::CatalogStats { database } => {
            let catalog = Catalog::open_existing(&database)?;
            println!("{}", serde_json::to_string_pretty(&catalog.stats()?)?);
            Ok(())
        }
        Command::CatalogCheck { database } => {
            let catalog = Catalog::open_existing(&database)?;
            let result = catalog.check_integrity()?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if result.quick_check != "ok" || result.foreign_key_violations != 0 {
                return Err(CliError::Catalog(
                    secureflow_knowledge::catalog::CatalogError::InvalidPath(
                        "catalog integrity check failed",
                    ),
                ));
            }
            Ok(())
        }
        Command::CatalogRebuildIndex { database } => {
            let mut catalog = Catalog::open_existing_writable(&database)?;
            catalog.rebuild_search_index()?;
            println!(
                "catalog search index rebuilt: database={}",
                database.display()
            );
            Ok(())
        }
        Command::CatalogRebuildCanonicalization { database } => {
            let mut catalog = Catalog::open_existing_writable(&database)?;
            let result = catalog.rebuild_canonicalization()?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        Command::CatalogBackup {
            database,
            output,
            manifest_output,
        } => {
            ensure_output_distinct(&output, &[&database, &manifest_output])?;
            ensure_output_distinct(&manifest_output, &[&database])?;
            let catalog = Catalog::open_existing(&database)?;
            let manifest = create_backup(&catalog, &output)?;
            write_atomic_new(&manifest_output, &serde_json::to_vec_pretty(&manifest)?)?;
            println!(
                "catalog backup complete: backup={} manifest={} backup_id={} bytes={} sha256={} integrity=ok",
                output.display(),
                manifest_output.display(),
                manifest.backup_id,
                manifest.database_bytes,
                manifest.database_sha256,
            );
            Ok(())
        }
        Command::CatalogBackupVerify { backup, manifest } => {
            let manifest_bytes = read_bounded_file(&manifest, MAX_BACKUP_MANIFEST_BYTES)?;
            let manifest = parse_backup_manifest(&manifest_bytes)?;
            verify_backup(&backup, &manifest)?;
            println!(
                "catalog backup verified: backup={} backup_id={} bytes={} integrity=ok",
                backup.display(),
                manifest.backup_id,
                manifest.database_bytes,
            );
            Ok(())
        }
        Command::CatalogRestore {
            backup,
            manifest,
            output,
            manifest_output,
        } => {
            ensure_output_distinct(&output, &[&backup, &manifest, &manifest_output])?;
            ensure_output_distinct(&manifest_output, &[&backup, &manifest])?;
            let manifest_bytes = read_bounded_file(&manifest, MAX_BACKUP_MANIFEST_BYTES)?;
            let manifest = parse_backup_manifest(&manifest_bytes)?;
            let restored = restore_backup(&backup, &manifest, &output)?;
            write_atomic_new(&manifest_output, &serde_json::to_vec_pretty(&restored)?)?;
            println!(
                "catalog restored: database={} manifest={} backup_id={} bytes={} integrity=ok source_verified=true",
                output.display(),
                manifest_output.display(),
                restored.backup_id,
                restored.database_bytes,
            );
            Ok(())
        }
        Command::CatalogLookup {
            database,
            identifier,
            limit,
            format,
        } => {
            let catalog = Catalog::open_existing(&database)?;
            print_catalog_hits(catalog.lookup_identifier(&identifier, limit)?, format)?;
            Ok(())
        }
        Command::CatalogSearch {
            database,
            query,
            limit,
            format,
        } => {
            let catalog = Catalog::open_existing(&database)?;
            print_catalog_hits(catalog.search_text(&query, limit)?, format)?;
            Ok(())
        }
        Command::CatalogPackage {
            database,
            ecosystem,
            package,
            limit,
            format,
        } => {
            let catalog = Catalog::open_existing(&database)?;
            print_catalog_hits(catalog.search_package(&ecosystem, &package, limit)?, format)?;
            Ok(())
        }
        Command::CorrelatePackage {
            manifest,
            finding_id,
            database,
            ecosystem,
            package,
            version,
            output,
        } => {
            ensure_output_distinct(&output, &[&manifest, &database])?;
            let (manifest_bytes, run_manifest) = load_manifest(&manifest)?;
            let catalog = Catalog::open_existing(&database)?;
            let provenance = catalog.provenance()?;
            let hits = catalog.search_package_version(
                &ecosystem,
                &package,
                version.as_deref(),
                MAX_CORRELATION_MATCHES,
            )?;
            let envelope = build_correlation_v2(
                &run_manifest,
                sha256_bytes(&manifest_bytes),
                &finding_id,
                ecosystem,
                package,
                version,
                provenance,
                hits,
            )?;
            let advisory_count = envelope.advisories.len();
            let version_summary = envelope.version_summary.clone();
            let human_decision = envelope.linked_run.human_decision;
            let correlation_id = envelope.correlation_id.clone();
            write_atomic(&output, &serde_json::to_vec_pretty(&envelope)?)?;
            println!(
                "package context correlated: envelope={} correlation_id={} contract=secureflow-correlation-v2 advisories={} affected={} not_affected={} unknown={} not_evaluated={} affected_version_evaluated={} causal_relationship_asserted=false human_decision={:?} validation_authority=human-only",
                output.display(),
                correlation_id,
                advisory_count,
                version_summary.affected,
                version_summary.not_affected,
                version_summary.unknown,
                version_summary.not_evaluated,
                envelope.semantics.affected_version_evaluated,
                human_decision,
            );
            Ok(())
        }
        Command::CorrelationValidate { path } => {
            let bytes = read_bounded_file(&path, MAX_CORRELATION_BYTES)?;
            let envelope = parse_correlation_document(&bytes)?;
            println!(
                "valid {}: {} advisories={} affected_version_evaluated={} validation_authority=human-only",
                envelope.contract_version(),
                path.display(),
                envelope.advisories_len(),
                envelope.affected_version_evaluated(),
            );
            Ok(())
        }
        Command::OrchestratePlan {
            manifest,
            secure_review,
            correlation,
            benchmark,
            web_inventory,
            web_inference,
            web_assessment,
            web_lab_result,
            web_corpus_result,
            output,
        } => {
            ensure_output_distinct(&output, &[&manifest])?;
            let (manifest_bytes, run_manifest) = load_manifest(&manifest)?;
            let manifest_sha256 = sha256_bytes(&manifest_bytes);
            let mut evidence = Vec::new();

            if let Some(path) = secure_review.as_ref() {
                ensure_output_distinct(&output, &[path])?;
                let bytes = read_bounded(path, MAX_REVIEW_BYTES)?;
                let envelope = parse_envelope(&bytes)?;
                if envelope.linked_run_id != run_manifest.run_id
                    || envelope.target_sha256 != run_manifest.target.root_sha256
                {
                    return Err(CliError::ArtifactLinkMismatch("secure review"));
                }
                evidence.push(OrchestrationEvidence {
                    kind: OrchestrationEvidenceKind::ContextualReview,
                    sha256: sha256_bytes(&bytes),
                });
            }
            for path in &correlation {
                ensure_output_distinct(&output, &[path])?;
                let bytes = read_bounded_file(path, MAX_CORRELATION_BYTES)?;
                let envelope = parse_correlation_document(&bytes)?;
                let linked_run = envelope.linked_run();
                if linked_run.run_id != run_manifest.run_id
                    || linked_run.manifest_sha256 != manifest_sha256
                    || !run_manifest
                        .findings
                        .iter()
                        .any(|finding| finding.finding_id == linked_run.finding_id)
                {
                    return Err(CliError::ArtifactLinkMismatch("advisory correlation"));
                }
                evidence.push(OrchestrationEvidence {
                    kind: OrchestrationEvidenceKind::AdvisoryCorrelation,
                    sha256: sha256_bytes(&bytes),
                });
            }
            if let Some(path) = benchmark.as_ref() {
                ensure_output_distinct(&output, &[path])?;
                let bytes = bench_adapter::read_bounded(path, bench_adapter::MAX_RESULT_BYTES)?;
                let envelope = bench_adapter::parse_envelope(&bytes)?;
                if envelope.artifacts.run_manifest_sha256 != manifest_sha256 {
                    return Err(CliError::ArtifactLinkMismatch("benchmark"));
                }
                evidence.push(OrchestrationEvidence {
                    kind: OrchestrationEvidenceKind::BenchmarkResult,
                    sha256: sha256_bytes(&bytes),
                });
            }

            let retained_web_inventory = if let Some(path) = web_inventory.as_ref() {
                ensure_output_distinct(&output, &[path])?;
                let bytes = read_bounded_file(path, secureflow_web::MAX_INVENTORY_BYTES)?;
                let inventory = secureflow_web::parse_inventory(&bytes)?;
                if inventory.repository_root_sha256 != run_manifest.target.root_sha256 {
                    return Err(CliError::ArtifactLinkMismatch("web inventory"));
                }
                evidence.push(OrchestrationEvidence {
                    kind: OrchestrationEvidenceKind::WebInventory,
                    sha256: sha256_bytes(&bytes),
                });
                Some(inventory)
            } else {
                None
            };
            let retained_web_inference = if let Some(path) = web_inference.as_ref() {
                ensure_output_distinct(&output, &[path])?;
                let bytes = read_bounded_file(path, secureflow_web::MAX_INFERENCE_BYTES)?;
                let inference = secureflow_web::parse_inference(&bytes)?;
                if inference.repository_root_sha256 != run_manifest.target.root_sha256
                    || retained_web_inventory.as_ref().is_some_and(|inventory| {
                        inference.scope_id != inventory.scope_id
                            || !inference.inventory_ids.contains(&inventory.inventory_id)
                    })
                {
                    return Err(CliError::ArtifactLinkMismatch("web inference"));
                }
                evidence.push(OrchestrationEvidence {
                    kind: OrchestrationEvidenceKind::WebInference,
                    sha256: sha256_bytes(&bytes),
                });
                Some(inference)
            } else {
                None
            };
            if let Some(path) = web_assessment.as_ref() {
                ensure_output_distinct(&output, &[path])?;
                let inventory =
                    retained_web_inventory
                        .as_ref()
                        .ok_or(CliError::ArtifactLinkMismatch(
                            "web assessment requires web inventory",
                        ))?;
                let bytes = read_bounded_file(path, secureflow_web::MAX_ASSESSMENT_BYTES)?;
                let assessment = secureflow_web::parse_assessment(&bytes)?;
                if assessment.scope_id != inventory.scope_id
                    || !assessment.inventory_ids.contains(&inventory.inventory_id)
                {
                    return Err(CliError::ArtifactLinkMismatch("web assessment"));
                }
                evidence.push(OrchestrationEvidence {
                    kind: OrchestrationEvidenceKind::WebAssessment,
                    sha256: sha256_bytes(&bytes),
                });
            }
            if let Some(path) = web_lab_result.as_ref() {
                ensure_output_distinct(&output, &[path])?;
                let inventory =
                    retained_web_inventory
                        .as_ref()
                        .ok_or(CliError::ArtifactLinkMismatch(
                            "web lab result requires web inventory",
                        ))?;
                let bytes = read_bounded_file(path, secureflow_web::MAX_LAB_RESULT_BYTES)?;
                let result = secureflow_web::parse_lab_result(&bytes)?;
                if result.inventory_id != inventory.inventory_id {
                    return Err(CliError::ArtifactLinkMismatch("web lab result"));
                }
                evidence.push(OrchestrationEvidence {
                    kind: OrchestrationEvidenceKind::WebLabResult,
                    sha256: sha256_bytes(&bytes),
                });
            }
            if let Some(path) = web_corpus_result.as_ref() {
                ensure_output_distinct(&output, &[path])?;
                let inventory =
                    retained_web_inventory
                        .as_ref()
                        .ok_or(CliError::ArtifactLinkMismatch(
                            "web corpus result requires web inventory",
                        ))?;
                let inference =
                    retained_web_inference
                        .as_ref()
                        .ok_or(CliError::ArtifactLinkMismatch(
                            "web corpus result requires web inference",
                        ))?;
                let bytes = read_bounded_file(path, secureflow_web::MAX_CORPUS_RESULT_BYTES)?;
                let result = secureflow_web::parse_corpus_result(&bytes)?;
                if result.inventory_id != inventory.inventory_id
                    || result.inference_id != inference.inference_id
                {
                    return Err(CliError::ArtifactLinkMismatch("web corpus result"));
                }
                evidence.push(OrchestrationEvidence {
                    kind: OrchestrationEvidenceKind::WebCorpusResult,
                    sha256: sha256_bytes(&bytes),
                });
            }

            let plan = derive_plan(&run_manifest, manifest_sha256, evidence)?;
            let plan_id = plan.plan_id.clone();
            let next_action = plan.next_action;
            let claim_status = plan.claim_status;
            write_atomic(&output, &serde_json::to_vec_pretty(&plan)?)?;
            println!(
                "orchestration plan derived: output={} plan_id={} next_action={:?} claim_status={:?} network_execution=not-implemented validation_authority=human-only",
                output.display(),
                plan_id,
                next_action,
                claim_status,
            );
            Ok(())
        }
        Command::OrchestrationValidate { path } => {
            let bytes = read_bounded_file(&path, MAX_ORCHESTRATION_BYTES)?;
            let plan = parse_plan(&bytes)?;
            println!(
                "valid secureflow-orchestration-v1: {} next_action={:?} validation_authority=human-only",
                path.display(),
                plan.next_action,
            );
            Ok(())
        }
        Command::SecureReviewImport {
            review,
            manifest,
            secure_skill_root,
            secure_skill_revision,
            output,
        } => {
            ensure_output_distinct(&output, &[&review, &manifest])?;
            ensure_output_outside_tree(&output, &secure_skill_root)?;
            let (_, run_manifest) = load_manifest(&manifest)?;
            let payload = read_bounded(&review, MAX_REVIEW_BYTES)?;
            let source = load_source_provenance(&secure_skill_root, &secure_skill_revision)?;
            let envelope = import_review(
                &payload,
                ImportContext {
                    imported_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
                    linked_run_id: run_manifest.run_id,
                    target_sha256: run_manifest.target.root_sha256,
                },
                source,
            )?;
            let finding_count = envelope.review.findings.len();
            let non_finding_count = envelope.review.non_findings.len();
            let bytes = serde_json::to_vec_pretty(&envelope)?;
            write_atomic(&output, &bytes)?;
            println!(
                "contextual review imported: envelope={} candidates={} non_findings={} validation_authority=human-only import_id={}",
                output.display(),
                finding_count,
                non_finding_count,
                envelope.import_id,
            );
            Ok(())
        }
        Command::SecureReviewValidate { path } => {
            load_secure_review_envelope(&path)?;
            println!("valid secureflow-secure-review-v1: {}", path.display());
            Ok(())
        }
        Command::SecureReviewList { envelope, format } => {
            let envelope = load_secure_review_envelope(&envelope)?;
            match format {
                OutputFormat::Json => {
                    let output = serde_json::json!({
                        "contract_version": envelope.contract_version,
                        "import_id": envelope.import_id,
                        "linked_run_id": envelope.linked_run_id,
                        "semantics": envelope.semantics,
                        "count": envelope.review.findings.len(),
                        "findings": envelope.review.findings,
                        "non_findings": envelope.review.non_findings,
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                }
                OutputFormat::Text => print_secure_review_findings(&envelope),
            }
            Ok(())
        }
        Command::BenchmarkImport {
            result,
            run_manifest,
            suite,
            secure_bench_root,
            secure_bench_revision,
            study_kind,
            output,
        } => {
            ensure_output_distinct(&output, &[&result, &run_manifest, &suite])?;
            ensure_output_outside_tree(&output, &secure_bench_root)?;
            let result_bytes =
                bench_adapter::read_bounded(&result, bench_adapter::MAX_RESULT_BYTES)?;
            let run_bytes = bench_adapter::read_bounded(
                &run_manifest,
                bench_adapter::MAX_INPUT_ARTIFACT_BYTES,
            )?;
            let suite_bytes =
                bench_adapter::read_bounded(&suite, bench_adapter::MAX_INPUT_ARTIFACT_BYTES)?;
            let (source, result_schema) =
                bench_adapter::load_source_provenance(&secure_bench_root, &secure_bench_revision)?;
            let envelope = bench_adapter::import_benchmark(bench_adapter::BenchmarkImport {
                result: &result_bytes,
                run_manifest: &run_bytes,
                suite: &suite_bytes,
                result_schema: &result_schema,
                imported_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
                study_kind: study_kind.into(),
                source,
            })?;
            let bytes = serde_json::to_vec_pretty(&envelope)?;
            write_atomic(&output, &bytes)?;
            println!(
                "benchmark imported: envelope={} evaluation_only=true TP_expectations={} FN_expectations={} FP_safe_controls={} TN_safe_controls={} import_id={}",
                output.display(),
                envelope.result.confusion.true_positive_expectations,
                envelope.result.confusion.false_negative_expectations,
                envelope.result.confusion.false_positive_safe_controls,
                envelope.result.confusion.true_negative_safe_controls,
                envelope.import_id,
            );
            Ok(())
        }
        Command::BenchmarkValidate { path } => {
            load_benchmark_envelope(&path)?;
            println!("valid secureflow-benchmark-result-v1: {}", path.display());
            Ok(())
        }
        Command::BenchmarkSummary { envelope, format } => {
            let envelope = load_benchmark_envelope(&envelope)?;
            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&envelope)?);
                }
                OutputFormat::Text => print_benchmark_summary(&envelope),
            }
            Ok(())
        }
        Command::BenchmarkProtocolSeal { draft, output } => {
            ensure_output_distinct(&output, &[&draft])?;
            let bytes = read_bounded_file(&draft, bench_adapter::prospective::MAX_PROTOCOL_BYTES)?;
            let protocol = bench_adapter::prospective::seal_draft(&bytes, None)?;
            let protocol_id = protocol.protocol_id.clone();
            write_atomic(&output, &serde_json::to_vec_pretty(&protocol)?)?;
            println!(
                "prospective protocol sealed: output={} protocol_id={} holdout=true human_comparator_required=true negative_results_required=true claims=task-bounded-only",
                output.display(),
                protocol_id,
            );
            Ok(())
        }
        Command::BenchmarkProtocolPreflight {
            draft,
            corpus_manifest,
            provenance_manifest,
            license_manifest,
            environment_manifest,
            output,
        } => {
            ensure_output_distinct(
                &output,
                &[
                    &draft,
                    &corpus_manifest,
                    &provenance_manifest,
                    &license_manifest,
                    &environment_manifest,
                ],
            )?;
            let draft_bytes =
                read_bounded_file(&draft, bench_adapter::prospective::MAX_PROTOCOL_BYTES)?;
            let draft_value: bench_adapter::prospective::ProtocolDraft =
                serde_json::from_slice(&draft_bytes)?;
            let commitments = [
                (
                    "corpus.manifest_sha256",
                    &draft_value.corpus.manifest_sha256,
                    &corpus_manifest,
                ),
                (
                    "corpus.provenance_sha256",
                    &draft_value.corpus.provenance_sha256,
                    &provenance_manifest,
                ),
                (
                    "corpus.license_manifest_sha256",
                    &draft_value.corpus.license_manifest_sha256,
                    &license_manifest,
                ),
                (
                    "execution.environment_sha256",
                    &draft_value.execution.environment_sha256,
                    &environment_manifest,
                ),
            ];
            for (field, expected, path) in commitments {
                let bytes = read_bounded_file(path, MAX_PROSPECTIVE_ARTIFACT_BYTES)?;
                if sha256_bytes(&bytes) != *expected {
                    return Err(CliError::ProspectiveArtifactHashMismatch(field));
                }
            }
            let protocol = bench_adapter::prospective::seal_draft(&draft_bytes, None)?;
            let protocol_id = protocol.protocol_id.clone();
            write_atomic(&output, &serde_json::to_vec_pretty(&protocol)?)?;
            println!(
                "prospective protocol preflight complete: output={} protocol_id={} artifact_hashes_verified=true labels_opened=false human_comparator_required=true negative_results_required=true claims=task-bounded-only",
                output.display(),
                protocol_id,
            );
            Ok(())
        }
        Command::BenchmarkProtocolValidate { path } => {
            let bytes = read_bounded_file(&path, bench_adapter::prospective::MAX_PROTOCOL_BYTES)?;
            let protocol = bench_adapter::prospective::parse_protocol(&bytes)?;
            println!(
                "valid secureflow-prospective-protocol-v1: {} protocol_id={} cases={} claims=task-bounded-only",
                path.display(),
                protocol.protocol_id,
                protocol.draft.corpus.total_cases,
            );
            Ok(())
        }
        Command::AiPrepare {
            manifest,
            finding_id,
            enable_ai,
            consent_redacted_export,
            purpose,
            max_input_tokens,
            max_output_tokens,
            max_payload_bytes,
            output,
        } => {
            ensure_output_distinct(&output, &[&manifest])?;
            let (_, run_manifest) = load_manifest(&manifest)?;
            let request = ai::prepare_request(
                &run_manifest,
                &finding_id,
                ai::PrepareOptions {
                    enable_ai,
                    consent_redacted_export,
                    purpose: purpose.into(),
                    max_input_tokens,
                    max_output_tokens,
                    max_payload_bytes,
                    created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
                },
            )?;
            let bytes = serde_json::to_vec_pretty(&request)?;
            write_atomic(&output, &bytes)?;
            println!(
                "redacted AI request prepared locally: request={} model_family=luna payload_bytes={} max_input_tokens={} max_output_tokens={} transmitted=false validation_authority=human-only",
                output.display(),
                request.payload_bytes,
                request.budget.max_input_tokens,
                request.budget.max_output_tokens,
            );
            Ok(())
        }
        Command::AiValidateRequest { path } => {
            let bytes = read_bounded_file(&path, ai::MAX_DOCUMENT_BYTES as u64)?;
            ai::parse_request(&bytes)?;
            println!("valid secureflow-ai-request-v1: {}", path.display());
            Ok(())
        }
        Command::AiValidateResponse { path } => {
            let bytes = read_bounded_file(&path, ai::MAX_DOCUMENT_BYTES as u64)?;
            ai::parse_response(&bytes)?;
            println!("valid secureflow-ai-response-v1: {}", path.display());
            Ok(())
        }
        Command::AiApplyResponse {
            manifest,
            request,
            response,
            output,
        } => {
            ensure_output_distinct(&output, &[&manifest, &request, &response])?;
            let (_, mut run_manifest) = load_manifest(&manifest)?;
            let request_bytes = read_bounded_file(&request, ai::MAX_DOCUMENT_BYTES as u64)?;
            let response_bytes = read_bounded_file(&response, ai::MAX_DOCUMENT_BYTES as u64)?;
            let request = ai::parse_request(&request_bytes)?;
            let response = ai::parse_response(&response_bytes)?;
            let human_decision_before = run_manifest
                .findings
                .iter()
                .find(|finding| finding.finding_id == request.finding_id)
                .map(|finding| finding.human_review.decision);
            ai::apply_response(&mut run_manifest, &request, &response, &response_bytes)?;
            let human_decision_after = run_manifest
                .findings
                .iter()
                .find(|finding| finding.finding_id == request.finding_id)
                .map(|finding| finding.human_review.decision);
            if human_decision_before != human_decision_after {
                return Err(ai::AiError::HumanDecisionChanged.into());
            }
            let bytes = serde_json::to_vec_pretty(&run_manifest)?;
            write_atomic(&output, &bytes)?;
            println!(
                "advisory AI response recorded: manifest={} finding={} assessment={} input_tokens={} output_tokens={} human_decision_unchanged=true",
                output.display(),
                request.finding_id,
                ai_assessment_label(response.assessment),
                response.input_tokens,
                response.output_tokens,
            );
            Ok(())
        }
        Command::ReviewRun {
            manifest,
            finding_id,
            decision,
            reviewer,
            rationale,
            evidence_reference,
            output,
        } => {
            ensure_output_distinct(&output, &[&manifest])?;
            let (_, mut run_manifest) = load_manifest(&manifest)?;
            let reviewer = checked_review_field(reviewer.trim(), "reviewer", 200)?;
            let rationale = checked_review_field(rationale.trim(), "rationale", 3000)?;
            let evidence_reference = evidence_reference
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| checked_review_field(value, "evidence_reference", 300))
                .transpose()?;
            let finding = run_manifest
                .findings
                .iter_mut()
                .find(|finding| finding.finding_id == finding_id)
                .ok_or_else(|| CliError::FindingNotFound(finding_id.clone()))?;
            if finding.human_review.decision != HumanDecision::Pending {
                return Err(CliError::FindingAlreadyReviewed(finding_id));
            }
            finding.human_review.decision = decision.into();
            finding.human_review.reviewer = Some(reviewer);
            finding.human_review.reviewed_at = Some(OffsetDateTime::now_utc().format(&Rfc3339)?);
            finding.human_review.rationale = Some(rationale);
            finding.human_review.evidence_reference = evidence_reference;
            run_manifest.refresh_summary();
            let has_pending = run_manifest
                .findings
                .iter()
                .any(|finding| finding.human_review.decision == HumanDecision::Pending);
            run_manifest.phases.validation = if has_pending {
                PhaseStatus::Partial
            } else {
                PhaseStatus::Completed
            };
            run_manifest.validate()?;
            let manifest_bytes = serde_json::to_vec_pretty(&run_manifest)?;
            write_atomic(&output, &manifest_bytes)?;
            println!(
                "review recorded: manifest={} finding={} decision={:?} pending={}",
                output.display(),
                finding_id,
                decision,
                has_pending
            );
            Ok(())
        }
        Command::Scan {
            binary,
            target,
            authorized,
            authorization_reviewer,
            authorization_basis,
            authorization_reference,
            authorization_expires_at,
            target_revision_kind,
            target_revision,
            output,
            manifest_output,
            timeout_seconds,
            sandbox,
        } => {
            if !authorized {
                return Err(CliError::AuthorizationRequired);
            }
            if timeout_seconds == 0 || timeout_seconds > MAX_ENGINE_TIMEOUT_SECONDS {
                return Err(CliError::InvalidTimeout {
                    provided: timeout_seconds,
                    maximum: MAX_ENGINE_TIMEOUT_SECONDS,
                });
            }
            ensure_output_distinct(&output, &[&binary, &target, &manifest_output])?;
            ensure_output_distinct(&manifest_output, &[&binary, &target, &output])?;
            ensure_output_outside_tree(&output, &target)?;
            ensure_output_outside_tree(&manifest_output, &target)?;
            let authorization_reviewer =
                checked_review_field(authorization_reviewer.trim(), "authorization_reviewer", 200)?;
            let authorization_reference = authorization_reference
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| checked_review_field(value, "authorization_reference", 300))
                .transpose()?;
            if matches!(
                authorization_basis,
                ScanAuthorizationBasis::WrittenConsent
                    | ScanAuthorizationBasis::OrganizationPolicy
                    | ScanAuthorizationBasis::OtherDocumented
            ) && authorization_reference.is_none()
            {
                return Err(CliError::AuthorizationReferenceRequired(
                    scan_authorization_basis_label(authorization_basis),
                ));
            }
            let authorization_expires_at = authorization_expires_at
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let created = OffsetDateTime::now_utc();
            let authorization_expiration = authorization_expires_at
                .as_deref()
                .map(|value| {
                    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
                        CliError::Manifest(secureflow_model::ModelError::InvalidTimestamp(
                            "target.authorization.expires_at",
                        ))
                    })
                })
                .transpose()?;
            if authorization_expiration.is_some_and(|expires_at| expires_at <= created) {
                return Err(CliError::AuthorizationExpired);
            }
            let target_revision = target_revision
                .as_deref()
                .map(str::trim)
                .map(|value| checked_review_field(value, "target_revision", 200))
                .transpose()?;
            if target_revision_kind == Some(TargetRevisionKind::Git)
                && target_revision
                    .as_deref()
                    .is_some_and(|value| !valid_full_git_revision(value))
            {
                return Err(CliError::Manifest(
                    secureflow_model::ModelError::InvalidRevision,
                ));
            }
            let revision = target_revision_kind
                .zip(target_revision)
                .map(|(kind, value)| Revision {
                    kind: kind.into(),
                    value,
                });
            let mut config = EngineConfig::default_scan(binary, target);
            config.sandbox = sandbox.into();
            config.timeout = Duration::from_secs(timeout_seconds);
            config.max_cpu_seconds = timeout_seconds.saturating_add(1);
            let created_at = created.format(&Rfc3339)?;
            let target_hash =
                sha256_target(&config.target).map_err(|source| CliError::TargetHash {
                    path: config.target.clone(),
                    source,
                })?;
            if let Some(expires_at) = authorization_expiration {
                let remaining = Duration::try_from(expires_at - OffsetDateTime::now_utc())
                    .ok()
                    .and_then(|remaining| remaining.checked_sub(AUTHORIZATION_EXPIRY_MARGIN))
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or(CliError::AuthorizationExpired)?;
                config.timeout = config.timeout.min(remaining);
                config.max_cpu_seconds = config.timeout.as_secs().saturating_add(1);
            }
            let configuration_sha256 = config.configuration_sha256();
            let result = run(&config)?;
            let completed_target_hash =
                sha256_target(&config.target).map_err(|source| CliError::TargetHash {
                    path: config.target.clone(),
                    source,
                })?;
            if completed_target_hash != target_hash {
                return Err(CliError::TargetChangedDuringScan(config.target.clone()));
            }
            let completed = OffsetDateTime::now_utc();
            if authorization_expiration.is_some_and(|expires_at| expires_at <= completed) {
                return Err(CliError::AuthorizationExpired);
            }
            let completed_at = completed.format(&Rfc3339)?;
            let report = result.report_json()?;
            let mut findings = project_findings(&report)?;
            prioritize_findings(&mut findings);
            let duplicate_count = deduplicate_findings(&mut findings);
            let label = config
                .target
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "target".into());
            let manifest = RunManifest {
                contract_version: CONTRACT_VERSION.into(),
                run_id: format!(
                    "sf_run_{}_{:x}",
                    OffsetDateTime::now_utc().unix_timestamp_nanos(),
                    std::process::id()
                ),
                status: RunStatus::Completed,
                created_at,
                completed_at: Some(completed_at),
                target: Target {
                    label,
                    root_sha256: target_hash,
                    revision,
                    authorization: Authorization {
                        status: AuthorizationStatus::Authorized,
                        basis: authorization_basis.into(),
                        reviewer: authorization_reviewer,
                        reference: authorization_reference,
                        expires_at: authorization_expires_at,
                    },
                },
                engine: EngineProvenance {
                    name: "secure-engine".into(),
                    version: report
                        .get("engine_version")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown")
                        .into(),
                    binary_sha256: result.binary_sha256.clone(),
                    report_schema: ENGINE_REPORT_SCHEMA.into(),
                    report_sha256: result.report_sha256(),
                    sandbox_name: result.sandboxed.then(|| "bubblewrap".into()),
                    sandbox_binary_sha256: result.sandbox_binary_sha256.clone(),
                },
                configuration_sha256: Some(configuration_sha256.clone()),
                phases: Phases {
                    deterministic: PhaseStatus::Completed,
                    prioritization: PhaseStatus::Completed,
                    validation: PhaseStatus::Skipped,
                    evaluation: PhaseStatus::Skipped,
                },
                artifacts: Vec::new(),
                summary: Some(Summary {
                    candidate_count: findings.len() as u64,
                    duplicate_count: duplicate_count as u64,
                    validated_count: 0,
                    rejected_count: 0,
                    abstained_count: 0,
                    ai_calls: 0,
                    ai_input_tokens: 0,
                    ai_output_tokens: 0,
                }),
                findings,
                evaluation: Some(EvaluationReference {
                    harness: secureflow_model::EvaluationHarness::LocalFixture,
                    harness_version: None,
                    manifest_sha256: None,
                    result_sha256: None,
                    status: secureflow_model::EvaluationStatus::NotRun,
                }),
            };
            manifest.validate()?;
            write_atomic(&output, &result.stdout)?;
            let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
            write_atomic(&manifest_output, &manifest_bytes)?;
            println!(
                "run completed: report={} manifest={} candidates={} exit={} timed_out={} binary_sha256={} configuration_sha256={} sandboxed={} sandbox_binary_sha256={}",
                output.display(),
                manifest_output.display(),
                manifest.findings.len(),
                result.status,
                result.timed_out,
                result.binary_sha256,
                configuration_sha256,
                result.sandboxed,
                result.sandbox_binary_sha256.as_deref().unwrap_or("none"),
            );
            Ok(())
        }
    }
}

fn load_manifest(path: &PathBuf) -> Result<(Vec<u8>, RunManifest), CliError> {
    let bytes = read_bounded_file(path, MAX_MANIFEST_BYTES)?;
    let manifest: RunManifest = serde_json::from_slice(&bytes)?;
    manifest.validate()?;
    Ok((bytes, manifest))
}

fn ensure_catalog_database_outside_input(database: &Path, input: &PathBuf) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(input).map_err(|source| CliError::Read {
        path: input.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(CliError::CatalogInputSymlink(input.clone()));
    }
    if metadata.is_dir() {
        ensure_output_outside_tree(database, input)
    } else {
        ensure_output_distinct(database, &[input])
    }
}

fn collect_osv_files(input: &PathBuf) -> Result<Vec<PathBuf>, CliError> {
    let metadata = fs::symlink_metadata(input).map_err(|source| CliError::Read {
        path: input.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(CliError::CatalogInputSymlink(input.clone()));
    }
    let mut files = Vec::new();
    if metadata.is_file() {
        files.push(input.clone());
    } else if metadata.is_dir() {
        collect_osv_directory(input, 0, &mut files)?;
    } else {
        return Err(CliError::NotAFile(input.clone()));
    }
    if files.is_empty() {
        return Err(CliError::EmptyCatalogInput(input.clone()));
    }
    Ok(files)
}

fn collect_osv_directory(
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
) -> Result<(), CliError> {
    if depth > MAX_CATALOG_INPUT_DEPTH {
        return Err(CliError::CatalogInputTooDeep {
            path: directory.to_owned(),
            maximum: MAX_CATALOG_INPUT_DEPTH,
        });
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|source| CliError::Read {
            path: directory.to_owned(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| CliError::Read {
            path: directory.to_owned(),
            source,
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| CliError::Read {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(CliError::CatalogInputSymlink(path));
        }
        if file_type.is_dir() {
            collect_osv_directory(&path, depth + 1, files)?;
        } else if file_type.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            if files.len() >= MAX_IMPORT_RECORDS {
                return Err(CliError::CatalogInputTooLarge {
                    maximum: MAX_IMPORT_RECORDS,
                });
            }
            files.push(path);
        }
    }
    Ok(())
}

fn read_bounded_file(path: &PathBuf, maximum: u64) -> Result<Vec<u8>, CliError> {
    let metadata = fs::metadata(path).map_err(|source| CliError::Read {
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(CliError::NotAFile(path.clone()));
    }
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(CliError::InputTooLarge {
            path: path.clone(),
            bytes: metadata.len(),
            maximum,
        });
    }
    let bytes = fs::read(path).map_err(|source| CliError::Read {
        path: path.clone(),
        source,
    })?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(CliError::InputTooLarge {
            path: path.clone(),
            bytes: bytes.len() as u64,
            maximum,
        });
    }
    Ok(bytes)
}

fn load_secure_review_envelope(path: &Path) -> Result<SecureReviewEnvelope, CliError> {
    let bytes = read_bounded(path, MAX_REVIEW_BYTES)?;
    Ok(parse_envelope(&bytes)?)
}

fn load_benchmark_envelope(path: &Path) -> Result<bench_adapter::BenchmarkEnvelope, CliError> {
    let bytes = bench_adapter::read_bounded(path, bench_adapter::MAX_RESULT_BYTES)?;
    Ok(bench_adapter::parse_envelope(&bytes)?)
}

fn print_catalog_hits(
    hits: Vec<secureflow_knowledge::catalog::CatalogHit>,
    format: OutputFormat,
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "count": hits.len(),
                    "records": hits,
                    "validation_authority": "human-only"
                }))?
            );
        }
        OutputFormat::Text => {
            println!("source\trecord\twithdrawn\tcanonical\ttitle");
            for hit in hits {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    terminal_safe(&hit.source_name),
                    terminal_safe(&hit.source_record_id),
                    hit.withdrawn,
                    terminal_safe(&hit.canonical_id),
                    terminal_safe(&hit.title),
                );
            }
        }
    }
    Ok(())
}

fn print_findings(findings: &[&secureflow_model::Finding]) {
    println!("severity\tconfidence\tdecision\trule\tsource\tfinding_id\ttitle");
    for finding in findings {
        println!(
            "{}\t{}\t{}\t{}\t{}:{}\t{}\t{}",
            severity_label(finding.severity),
            confidence_label(finding.confidence),
            decision_label(finding.human_review.decision),
            terminal_safe(&finding.rule_id),
            terminal_safe(&finding.source_location.path),
            finding.source_location.start_line,
            finding.finding_id,
            terminal_safe(&finding.title),
        );
    }
}

fn render_markdown_report(manifest: &RunManifest, include_human_rationale: bool) -> String {
    let summary = manifest.summary.as_ref();
    let mut output = String::new();
    output.push_str("# SecureFlow local security analysis report\n\n");
    output.push_str(
        "> Candidates are not confirmed vulnerabilities. Only the recorded human decision is authoritative. A zero-candidate run is not proof of security.\n\n",
    );
    output.push_str("## Run and provenance\n\n");
    output.push_str(&format!("- Run: `{}`\n", markdown_code(&manifest.run_id)));
    output.push_str(&format!(
        "- Status: `{}`\n",
        run_status_label(manifest.status)
    ));
    output.push_str(&format!(
        "- Created: `{}`\n",
        markdown_code(&manifest.created_at)
    ));
    if let Some(completed_at) = &manifest.completed_at {
        output.push_str(&format!("- Completed: `{}`\n", markdown_code(completed_at)));
    }
    output.push_str(&format!(
        "- Target: {} (`{}`)\n",
        markdown_text(&manifest.target.label),
        markdown_code(&manifest.target.root_sha256)
    ));
    output.push_str(&format!(
        "- Authorization: `authorized` / `{}`\n",
        authorization_basis_label(manifest.target.authorization.basis)
    ));
    output.push_str(&format!(
        "- Engine: {} {}\n",
        markdown_text(&manifest.engine.name),
        markdown_text(&manifest.engine.version)
    ));
    output.push_str(&format!(
        "- Engine binary SHA-256: `{}`\n",
        markdown_code(&manifest.engine.binary_sha256)
    ));
    output.push_str(&format!(
        "- Raw report SHA-256: `{}`\n\n",
        markdown_code(&manifest.engine.report_sha256)
    ));

    output.push_str("## Accounting\n\n");
    output.push_str("| Candidates | Validated | Rejected | Abstained | Pending | AI calls | AI input tokens | AI output tokens |\n");
    output.push_str("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    let candidate_count = manifest.findings.len() as u64;
    let validated = summary.map_or(0, |value| value.validated_count);
    let rejected = summary.map_or(0, |value| value.rejected_count);
    let abstained = summary.map_or(0, |value| value.abstained_count);
    let pending = candidate_count.saturating_sub(validated + rejected + abstained);
    output.push_str(&format!(
        "| {candidate_count} | {validated} | {rejected} | {abstained} | {pending} | {} | {} | {} |\n\n",
        summary.map_or(0, |value| value.ai_calls),
        summary.map_or(0, |value| value.ai_input_tokens),
        summary.map_or(0, |value| value.ai_output_tokens),
    ));

    output.push_str("## Findings\n\n");
    if manifest.findings.is_empty() {
        output.push_str(
            "No candidates were emitted in this scoped run. This is not a security clearance; review coverage and residual risk separately.\n",
        );
        return output;
    }
    for finding in &manifest.findings {
        output.push_str(&format!(
            "### {} — {}\n\n",
            markdown_text(&finding.finding_id),
            markdown_text(&finding.title)
        ));
        output.push_str(&format!(
            "- Classification: **candidate, not confirmed vulnerability**\n- Rule: `{}`\n- Severity / confidence: `{}` / `{}`\n- Human decision: `{}`\n- Source: `{}`\n- Sink: `{}`\n- Invariant: {}\n",
            markdown_code(&finding.rule_id),
            severity_label(finding.severity),
            confidence_label(finding.confidence),
            decision_label(finding.human_review.decision),
            markdown_code(&location_label(&finding.source_location)),
            markdown_code(&location_label(&finding.sink_location)),
            markdown_text(&finding.invariant),
        ));
        output.push_str(&format!(
            "- AI advisory: `{}`",
            ai_status_label(finding.ai_validation.status)
        ));
        if let Some(assessment) = finding.ai_validation.assessment {
            output.push_str(&format!(" / `{}`", ai_assessment_label(assessment)));
        }
        output.push('\n');
        if include_human_rationale {
            if let Some(rationale) = &finding.human_review.rationale {
                output.push_str(&format!(
                    "- Human rationale: {}\n",
                    markdown_text(rationale)
                ));
            }
        } else if finding.human_review.rationale.is_some() {
            output.push_str("- Human rationale: omitted from this export\n");
        }
        output.push_str("\nEvidence path:\n\n");
        for step in &finding.evidence_path {
            output.push_str(&format!(
                "1. `{}` at `{}` — {}\n",
                evidence_kind_label(step.kind),
                markdown_code(&location_label(&step.location)),
                markdown_text(&step.description),
            ));
        }
        if !finding.limitations.is_empty() {
            output.push_str("\nLimitations:\n\n");
            for limitation in &finding.limitations {
                output.push_str(&format!("- {}\n", markdown_text(limitation)));
            }
        }
        output.push('\n');
    }
    output
}

fn run_status_label(value: RunStatus) -> &'static str {
    match value {
        RunStatus::Created => "created",
        RunStatus::Running => "running",
        RunStatus::Completed => "completed",
        RunStatus::Partial => "partial",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
    }
}

fn authorization_basis_label(value: AuthorizationBasis) -> &'static str {
    match value {
        AuthorizationBasis::RepositoryOwner => "repository-owner",
        AuthorizationBasis::WrittenConsent => "written-consent",
        AuthorizationBasis::OrganizationPolicy => "organization-policy",
        AuthorizationBasis::LocalProject => "local-project",
        AuthorizationBasis::OtherDocumented => "other-documented",
    }
}

fn scan_authorization_basis_label(value: ScanAuthorizationBasis) -> &'static str {
    match value {
        ScanAuthorizationBasis::RepositoryOwner => "repository-owner",
        ScanAuthorizationBasis::WrittenConsent => "written-consent",
        ScanAuthorizationBasis::OrganizationPolicy => "organization-policy",
        ScanAuthorizationBasis::LocalProject => "local-project",
        ScanAuthorizationBasis::OtherDocumented => "other-documented",
    }
}

fn ai_status_label(value: secureflow_model::AiValidationStatus) -> &'static str {
    use secureflow_model::AiValidationStatus;
    match value {
        AiValidationStatus::NotRequested => "not-requested",
        AiValidationStatus::Queued => "queued",
        AiValidationStatus::Completed => "completed",
        AiValidationStatus::Failed => "failed",
        AiValidationStatus::Skipped => "skipped",
    }
}

fn evidence_kind_label(value: secureflow_model::EvidenceKind) -> &'static str {
    use secureflow_model::EvidenceKind;
    match value {
        EvidenceKind::Source => "source",
        EvidenceKind::Transform => "transform",
        EvidenceKind::Guard => "guard",
        EvidenceKind::Sanitizer => "sanitizer",
        EvidenceKind::Authorization => "authorization",
        EvidenceKind::Sink => "sink",
        EvidenceKind::Barrier => "barrier",
        EvidenceKind::Unknown => "unknown",
    }
}

fn location_label(location: &secureflow_model::Location) -> String {
    format!(
        "{}:{}:{}",
        location.path, location.start_line, location.start_column
    )
}

fn markdown_text(value: &str) -> String {
    terminal_safe(value)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('|', "\\|")
        .replace('#', "\\#")
}

fn markdown_code(value: &str) -> String {
    terminal_safe(value).replace('`', "\\`")
}

fn print_knowledge_records(records: &[&KnowledgeRecord]) {
    println!(
        "severity\tconfidence\tdecision\trule\tsource\trecord_id\tduplicate_of\tfinding_id\ttitle"
    );
    for record in records {
        println!(
            "{}\t{}\t{}\t{}\t{}:{}\t{}\t{}\t{}\t{}",
            severity_label(record.severity()),
            confidence_label(record.confidence()),
            decision_label(record.decision()),
            terminal_safe(record.rule_id()),
            terminal_safe(&record.source_location().path),
            record.source_location().start_line,
            record.record_id(),
            record.duplicate_of_record_id().unwrap_or("-"),
            record.finding_id(),
            terminal_safe(record.title()),
        );
    }
}

fn print_secure_review_findings(envelope: &SecureReviewEnvelope) {
    println!(
        "# contextual candidates only; validation_authority=human-only; no_findings_mean_safe=false"
    );
    println!("severity\tconfidence\tupstream_status\tlocation\tid\ttitle");
    for finding in &envelope.review.findings {
        let line = finding
            .location
            .line
            .map_or_else(|| "?".to_owned(), |value| value.to_string());
        println!(
            "{}\t{}\t{}\t{}:{}\t{}\t{}",
            review_severity_label(finding.severity),
            review_confidence_label(finding.confidence),
            review_verification_label(finding.verification_status),
            terminal_safe(&finding.location.file),
            line,
            finding.id,
            terminal_safe(&finding.title),
        );
    }
}

fn print_benchmark_summary(envelope: &bench_adapter::BenchmarkEnvelope) {
    let result = &envelope.result;
    let confusion = &result.confusion;
    println!(
        "# evaluation only; ranking=false; superiority_claim=false; production_readiness_claim=false"
    );
    println!("study_kind\t{:?}", envelope.study_kind);
    println!(
        "suite\t{}\nbenchmark_run\t{}\ntool\t{} {}",
        terminal_safe(&result.suite_id),
        terminal_safe(&result.benchmark_run_id),
        terminal_safe(&result.tool.name),
        terminal_safe(&result.tool.version),
    );
    println!(
        "TP_expectations\t{}\nFN_expectations\t{}\nFP_safe_controls\t{}\nTN_safe_controls\t{}",
        confusion.true_positive_expectations,
        confusion.false_negative_expectations,
        confusion.false_positive_safe_controls,
        confusion.true_negative_safe_controls,
    );
    print_ratio("vulnerable_recall", &result.metrics.vulnerable_recall);
    print_ratio(
        "safe_control_false_positive_rate",
        &result.metrics.safe_control_false_positive_rate,
    );
    print_ratio(
        "safe_control_clean_coverage",
        &result.metrics.safe_control_clean_coverage,
    );
    println!(
        "# TP/FN unit=vulnerable-expectation; FP/TN unit=safe-control-case; operational failures never count as clean"
    );
}

fn print_ratio(name: &str, ratio: &bench_adapter::RatioMetric) {
    let rate = ratio.basis_points.map_or_else(
        || "undefined".to_owned(),
        |value| format!("{:.2}%", f64::from(value) / 100.0),
    );
    println!(
        "{}\t{}/{}\t{}",
        name, ratio.numerator, ratio.denominator, rate
    );
}

fn ai_assessment_label(value: secureflow_model::AiAssessment) -> &'static str {
    use secureflow_model::AiAssessment;
    match value {
        AiAssessment::Supports => "supports",
        AiAssessment::Insufficient => "insufficient",
        AiAssessment::Contradicts => "contradicts",
        AiAssessment::Uncertain => "uncertain",
    }
}

fn review_severity_label(value: secureflow_secure_adapter::ReviewSeverity) -> &'static str {
    use secureflow_secure_adapter::ReviewSeverity;
    match value {
        ReviewSeverity::Critical => "critical",
        ReviewSeverity::High => "high",
        ReviewSeverity::Medium => "medium",
        ReviewSeverity::Low => "low",
    }
}

fn review_confidence_label(value: secureflow_secure_adapter::ReviewConfidence) -> &'static str {
    use secureflow_secure_adapter::ReviewConfidence;
    match value {
        ReviewConfidence::High => "high",
        ReviewConfidence::Medium => "medium",
        ReviewConfidence::Low => "low",
    }
}

fn review_verification_label(value: secureflow_secure_adapter::VerificationStatus) -> &'static str {
    use secureflow_secure_adapter::VerificationStatus;
    match value {
        VerificationStatus::Verified => "verified",
        VerificationStatus::Unverified => "unverified",
        VerificationStatus::Fixed => "fixed",
        VerificationStatus::RetestFailed => "retest-failed",
        VerificationStatus::NotApplicable => "not-applicable",
    }
}

fn severity_label(value: Option<Severity>) -> &'static str {
    match value {
        Some(Severity::Critical) => "critical",
        Some(Severity::High) => "high",
        Some(Severity::Medium) => "medium",
        Some(Severity::Low) => "low",
        Some(Severity::Unknown) | None => "unknown",
    }
}

fn confidence_label(value: Confidence) -> &'static str {
    match value {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
        Confidence::Unknown => "unknown",
    }
}

fn decision_label(value: HumanDecision) -> &'static str {
    match value {
        HumanDecision::Pending => "pending",
        HumanDecision::Validated => "validated",
        HumanDecision::Rejected => "rejected",
        HumanDecision::Abstained => "abstained",
    }
}

fn terminal_safe(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        let directional_control = matches!(
            character,
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        );
        if character.is_control() || directional_control {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}

fn checked_review_field(value: &str, field: &'static str, max: usize) -> Result<String, CliError> {
    if value.is_empty() {
        return Err(CliError::EmptyReviewField(field));
    }
    if value.chars().count() > max {
        return Err(CliError::ReviewFieldTooLong { field, max });
    }
    Ok(value.to_owned())
}

fn valid_full_git_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn resolved_path(path: &Path) -> Result<PathBuf, CliError> {
    match fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|source| CliError::PathResolution {
                        path: path.to_path_buf(),
                        source,
                    })?
                    .join(path)
            };
            let mut cursor = absolute.as_path();
            let mut missing = Vec::new();
            let mut resolved = loop {
                match fs::canonicalize(cursor) {
                    Ok(value) => break value,
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                        let name = cursor.file_name().ok_or_else(|| CliError::PathResolution {
                            path: path.to_path_buf(),
                            source: std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "path does not have an existing ancestor",
                            ),
                        })?;
                        missing.push(name.to_os_string());
                        cursor = cursor.parent().ok_or_else(|| CliError::PathResolution {
                            path: path.to_path_buf(),
                            source: std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "path does not have an existing ancestor",
                            ),
                        })?;
                    }
                    Err(source) => {
                        return Err(CliError::PathResolution {
                            path: path.to_path_buf(),
                            source,
                        });
                    }
                }
            };
            for component in missing.into_iter().rev() {
                if component == "." {
                    continue;
                }
                if component == ".." {
                    resolved.pop();
                } else {
                    resolved.push(component);
                }
            }
            if resolved.as_os_str().is_empty() {
                return Err(CliError::PathResolution {
                    path: path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "resolved path is empty",
                    ),
                });
            }
            Ok(resolved)
        }
        Err(source) => Err(CliError::PathResolution {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn paths_alias(left: &Path, right: &Path) -> Result<bool, CliError> {
    if resolved_path(left)? == resolved_path(right)? {
        return Ok(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = |path: &Path| match fs::metadata(path) {
            Ok(value) => Ok(Some(value)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(CliError::PathResolution {
                path: path.to_path_buf(),
                source,
            }),
        };
        if let (Some(left), Some(right)) = (metadata(left)?, metadata(right)?) {
            return Ok(left.dev() == right.dev() && left.ino() == right.ino());
        }
    }

    Ok(false)
}

fn ensure_output_distinct(output: &Path, inputs: &[&Path]) -> Result<(), CliError> {
    for input in inputs {
        if paths_alias(output, input)? {
            return Err(CliError::OutputAliasesInput {
                output: output.to_path_buf(),
                input: input.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn ensure_output_outside_tree(output: &Path, root: &Path) -> Result<(), CliError> {
    let root = fs::canonicalize(root).map_err(|source| CliError::PathResolution {
        path: root.to_path_buf(),
        source,
    })?;
    let metadata = fs::metadata(&root).map_err(|source| CliError::PathResolution {
        path: root.clone(),
        source,
    })?;
    if metadata.is_dir() && resolved_path(output)?.starts_with(&root) {
        return Err(CliError::OutputInsideInputTree {
            output: output.to_path_buf(),
            root,
        });
    }
    Ok(())
}

fn write_atomic(path: &PathBuf, bytes: &[u8]) -> Result<(), CliError> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy())
        .unwrap_or_else(|| std::borrow::Cow::Borrowed("secureflow-output"));
    let nonce = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let mut temporary = None;
    for attempt in 0..100_u32 {
        let candidate = parent.join(format!(
            ".{name}.tmp-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(mut file) => {
                let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
                drop(file);
                if let Err(source) = write_result {
                    let _ = fs::remove_file(&candidate);
                    return Err(CliError::Write {
                        path: path.clone(),
                        source,
                    });
                }
                temporary = Some(candidate);
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(CliError::Write {
                    path: path.clone(),
                    source,
                });
            }
        }
    }
    let temporary = temporary.ok_or_else(|| CliError::Write {
        path: path.clone(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary output file",
        ),
    })?;
    if let Err(source) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(CliError::Write {
            path: path.clone(),
            source,
        });
    }
    Ok(())
}

fn write_atomic_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(CliError::Write {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "destination already exists",
            ),
        });
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy())
        .unwrap_or_else(|| std::borrow::Cow::Borrowed("secureflow-output"));
    let nonce = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let mut temporary = None;
    for attempt in 0..100_u32 {
        let candidate = parent.join(format!(
            ".{name}.new-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(mut file) => {
                let result = file.write_all(bytes).and_then(|()| file.sync_all());
                drop(file);
                if let Err(source) = result {
                    let _ = fs::remove_file(&candidate);
                    return Err(CliError::Write {
                        path: path.to_path_buf(),
                        source,
                    });
                }
                temporary = Some(candidate);
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(CliError::Write {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    let temporary = temporary.ok_or_else(|| CliError::Write {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary output file",
        ),
    })?;
    let publish = fs::hard_link(&temporary, path).map_err(|source| CliError::Write {
        path: path.to_path_buf(),
        source,
    });
    let _ = fs::remove_file(&temporary);
    publish
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_output_escapes_control_characters() {
        assert_eq!(terminal_safe("safe\n\u{202e}name"), "safe\\n\\u{202e}name");
    }
}
