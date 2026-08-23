//! Deterministic web inventory and assessment for explicitly authorized targets.
//!
//! SecureFlow Web v1 is local-only: it performs no network requests and never
//! executes code from the target. Automated observations remain candidates or
//! hardening guidance until a human records reproducible validation evidence.

mod assessment;
mod corpus;
mod inference;
mod inventory;
mod lab;
mod scope;

pub use assessment::{
    ASSESSMENT_VERSION, AccessIntent, AssessmentError, AssessmentEvidenceKind, AssessmentSemantics,
    AssessmentSummary, ControlExpectation, ControlState, CoverageRoute, EvidenceReference,
    HumanValidation, MAX_ASSESSMENT_BYTES, Observation, ObservationClass, ObservedControls,
    WebAssessment, assess_routes, parse_assessment, record_human_validation,
};
pub use corpus::{
    CORPUS_RESULT_VERSION, CORPUS_VERSION, CorpusCase, CorpusCaseResult, CorpusClaims,
    CorpusCounts, CorpusError, CorpusExpectation, CorpusSemanticInvariant, MAX_CORPUS_BYTES,
    MAX_CORPUS_RESULT_BYTES, WebCorpusResult, WebDevelopmentCorpus, evaluate_corpus, parse_corpus,
    parse_corpus_result,
};
pub use inference::{
    ApiCandidate, ApiCandidateKind, CandidateClassification, CandidateConfidence,
    CandidateDisposition, CandidateEvidence, CandidateOrigin, CandidatePresence, ConfidenceLevel,
    INFERENCE_VERSION, InferenceError, InferenceIssue, InferenceIssueKind, InferenceSemantics,
    InferenceStats, MAX_INFERENCE_BYTES, VulnerabilityStatus, WebInference, infer_local_apis,
    parse_inference,
};
pub use inventory::{
    AccessLevel, ApiPresence, EvidenceAnchor, EvidenceKind, EvidenceState, FieldSensitivity,
    Framework, HttpMethod, INVENTORY_VERSION, InventoryError, InventoryIssue, InventoryIssueKind,
    InventorySemantics, InventorySource, InventoryStats, MAX_INVENTORY_BYTES, MethodEvidence,
    ParameterLocation, ResponseField, RouteControls, RouteKind, RouteParameter, RouteRecord,
    SourceKind, SourceLocation, WebInventory, discover_nextjs, hash_repository_tree,
    parse_inventory,
};
pub use lab::{
    CASE_VERSION, CaseLicense, CaseSplit, LAB_RESULT_VERSION, LabCounts, LabError, LabMetric,
    LabMismatch, LabMismatchKind, LabSafety, MAX_CASE_BYTES, MAX_LAB_RESULT_BYTES,
    RouteExpectation, WebCase, WebLabResult, compare_inventory, lab_result_sarif, parse_case,
    parse_lab_result, seal_case,
};
pub use scope::{
    AuthorizationStatus, AuthorizedAsset, AuthorizedRepository, MAX_SCOPE_BYTES, NetworkExecution,
    SCOPE_VERSION, ScopeAuthorization, ScopeError, ScopeLimits, ScopePolicy, TargetKind, WebScheme,
    WebScope, WebScopeDraft, parse_scope, seal_scope,
};
