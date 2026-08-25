use secureflow_web::{
    AccessIntent, ApiCandidateKind, AssessmentEvidenceKind, AuthorizationStatus, AuthorizedAsset,
    AuthorizedRepository, CandidateDisposition, CandidateOrigin, ControlExpectation, ControlState,
    CoverageRoute, EvidenceReference, EvidenceState, HttpMethod, InventoryError, InventorySource,
    NetworkExecution, ObservedControls, PilotBlocker, PilotReadiness, ScopeAuthorization,
    ScopeLimits, ScopePolicy, SourceKind, TargetKind, WebScheme, WebScopeDraft, assess_routes,
    compare_inventory, discover_nextjs, evaluate_corpus, generate_api_risk_corpus,
    generate_variant_descriptors, hash_repository_tree, infer_local_apis, lab_result_sarif,
    mitiquete_pilot_draft, parse_api_risk_corpus, parse_assessment, parse_corpus,
    parse_corpus_result, parse_inference, parse_inventory, parse_lab_result,
    parse_observation_pilot, parse_scope, seal_case, seal_observation_pilot, seal_scope,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const CREATED_AT: &str = "2026-08-23T12:00:00Z";
const EXPIRES_AT: &str = "2027-08-23T12:00:00Z";

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/web-nextjs")
}

fn risk_corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/web-api-risk-corpus")
}

fn pilot_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/web-pilot-mitiquete")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::parse(CREATED_AT, &Rfc3339).expect("fixture time")
}

fn limits() -> ScopeLimits {
    ScopeLimits {
        max_files: 10_000,
        max_file_bytes: 1024 * 1024,
        max_total_bytes: 64 * 1024 * 1024,
        max_routes: 10_000,
        max_sources: 10_000,
        max_requests: 0,
        requests_per_minute: 0,
        max_concurrency: 0,
    }
}

fn scope_and_source(root: &Path) -> (secureflow_web::WebScope, InventorySource) {
    let limits = limits();
    let root_sha256 = hash_repository_tree(
        root,
        limits.max_files,
        limits.max_file_bytes,
        limits.max_total_bytes,
    )
    .expect("fixture tree hash");
    let draft = WebScopeDraft {
        authorization: ScopeAuthorization {
            status: AuthorizationStatus::Authorized,
            reference: "AUTH-SYNTHETIC-WEB-001".into(),
            reviewer: "fixture-reviewer".into(),
            expires_at: EXPIRES_AT.into(),
        },
        repositories: vec![AuthorizedRepository {
            label: "synthetic-nextjs".into(),
            root_sha256: root_sha256.clone(),
        }],
        assets: vec![AuthorizedAsset {
            kind: TargetKind::DnsName,
            value: "fixture.example.test".into(),
            include_subdomains: false,
            schemes: vec![WebScheme::Https],
            ports: vec![443],
        }],
        policy: ScopePolicy {
            passive_only: true,
            network_execution: NetworkExecution::Disabled,
            follow_redirects: false,
            third_party_scanning: false,
        },
        limits,
    };
    let scope = seal_scope(
        &serde_json::to_vec(&draft).expect("scope draft JSON"),
        Some(CREATED_AT.into()),
    )
    .expect("sealed scope");
    let source = InventorySource::new(
        SourceKind::Repository,
        "secureflow-synthetic-nextjs".into(),
        "fixture-v1".into(),
        root_sha256,
        "MIT OR Apache-2.0".into(),
    )
    .expect("valid source provenance");
    (scope, source)
}

fn validate_schema(name: &str, value: &Value) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .join(name);
    let schema: Value =
        serde_json::from_slice(&std::fs::read(path).expect("schema bytes")).expect("schema JSON");
    jsonschema::validator_for(&schema)
        .expect("schema compiles")
        .validate(value)
        .expect("artifact satisfies schema");
}

fn assessment_evidence() -> Vec<EvidenceReference> {
    vec![EvidenceReference {
        kind: AssessmentEvidenceKind::Code,
        reference: "app/api/admin/[tenantId]/users/[id]/route.ts:1".into(),
        sha256: "5".repeat(64),
        description: "synthetic route-to-query evidence".into(),
    }]
}

#[test]
fn local_nextjs_inventory_matches_expected_and_preserves_target() {
    let root = fixture_root();
    let (scope, source) = scope_and_source(&root);
    let before = source.sha256.clone();
    let inventory =
        discover_nextjs(&root, &scope, &source.sha256, source.clone(), now()).expect("inventory");
    let after = hash_repository_tree(
        &root,
        scope.draft.limits.max_files,
        scope.draft.limits.max_file_bytes,
        scope.draft.limits.max_total_bytes,
    )
    .expect("tree hash after inventory");
    assert_eq!(before, after, "inventory must not modify the target");
    assert!(!inventory.semantics.network_used);
    assert!(!inventory.semantics.target_code_executed);

    let actual = inventory
        .routes
        .iter()
        .map(|route| {
            json!({
                "route": route.route,
                "kind": route.kind,
                "methods": route.methods,
            })
        })
        .collect::<Vec<_>>();
    let expected: Value =
        serde_json::from_slice(&std::fs::read(root.join("expected.json")).expect("expected bytes"))
            .expect("expected JSON");
    assert_eq!(Value::Array(actual), expected["routes"]);

    let expected_bytes = std::fs::read(root.join("expected.json")).expect("expected bytes");
    let expected_value: Value = serde_json::from_slice(&expected_bytes).expect("case JSON");
    validate_schema("secureflow-web-case-v1.schema.json", &expected_value);
    let lab_result = compare_inventory(&inventory, &expected_bytes).expect("lab comparison");
    assert_eq!(lab_result.counts.matched_routes, 6);
    assert_eq!(lab_result.counts.missing_routes, 0);
    assert_eq!(lab_result.counts.unexpected_routes, 0);
    assert_eq!(
        lab_result.metrics.route_precision.basis_points,
        Some(10_000)
    );
    assert_eq!(lab_result.metrics.route_recall.basis_points, Some(10_000));
    assert_eq!(lab_result.metrics.route_f1.basis_points, Some(10_000));
    validate_schema(
        "secureflow-web-lab-result-v1.schema.json",
        &serde_json::to_value(&lab_result).expect("lab result value"),
    );
    assert!(
        lab_result_sarif(&lab_result).expect("SARIF")["runs"][0]["results"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(
        parse_lab_result(&serde_json::to_vec(&lab_result).expect("lab result JSON"))
            .expect("parsed lab result"),
        lab_result
    );

    let scope_value = serde_json::to_value(&scope).expect("scope value");
    let inventory_value = serde_json::to_value(&inventory).expect("inventory value");
    validate_schema("secureflow-web-scope-v1.schema.json", &scope_value);
    validate_schema("secureflow-web-inventory-v1.schema.json", &inventory_value);
    assert_eq!(
        parse_scope(&serde_json::to_vec(&scope).expect("scope JSON"), now()).expect("parsed scope"),
        scope
    );
    assert_eq!(
        parse_inventory(&serde_json::to_vec(&inventory).expect("inventory JSON"))
            .expect("parsed inventory"),
        inventory
    );

    let source_sha256 = source.sha256.clone();
    let inventory_again = discover_nextjs(
        &root,
        &scope,
        &source_sha256,
        source,
        OffsetDateTime::parse("2026-08-24T12:00:00Z", &Rfc3339).expect("second time"),
    )
    .expect("second inventory");
    assert_eq!(inventory.inventory_id, inventory_again.inventory_id);
}

#[test]
fn retained_api_risk_corpus_matches_generator_schema_and_scale_contract() {
    let root = risk_corpus_root();
    let license = std::fs::read(root.join("LICENSE")).expect("risk corpus license");
    let license_sha256 = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&license);
        let mut value = String::with_capacity(64);
        use std::fmt::Write as _;
        for byte in digest {
            write!(&mut value, "{byte:02x}").expect("hash formatting");
        }
        value
    };
    let retained_bytes = std::fs::read(root.join("corpus.json")).expect("retained risk corpus");
    let retained = parse_api_risk_corpus(&retained_bytes).expect("parsed risk corpus");
    let generated = generate_api_risk_corpus(&license_sha256).expect("generated risk corpus");
    assert_eq!(retained, generated);
    assert_eq!(retained.counts.canonical_pairs, 200);
    assert_eq!(retained.counts.risky_scenarios, 200);
    assert_eq!(retained.counts.safe_controls, 200);
    assert_eq!(retained.counts.total_scenarios, 400);
    assert!(!retained.partition.holdout_eligible);
    assert!(!retained.claims.independent_holdout);
    assert!(!retained.claims.human_superiority_claim_allowed);
    validate_schema(
        "secureflow-web-api-risk-corpus-v1.schema.json",
        &serde_json::to_value(&retained).expect("risk corpus value"),
    );
    assert_eq!(
        generate_variant_descriptors(&retained, 13)
            .expect("minimum variants")
            .len(),
        5_200
    );
}

#[test]
fn retained_mitiquete_pilot_is_exactly_scoped_and_blocked_without_network() {
    let root = pilot_fixture_root();
    let retained_bytes = std::fs::read(root.join("plan.json")).expect("retained pilot plan");
    let issued_at =
        OffsetDateTime::parse("2026-08-24T12:00:00Z", &Rfc3339).expect("pilot issue time");
    let retained = parse_observation_pilot(&retained_bytes, issued_at).expect("parsed pilot");
    let draft = mitiquete_pilot_draft(
        "codex-thread:01a02c99-9cb2-7c71-84b2-172cd2a7d498",
        "2026-08-24T12:00:00Z",
        "2026-09-24T12:00:00Z",
    )
    .expect("pilot draft");
    let generated = seal_observation_pilot(
        &serde_json::to_vec(&draft).expect("pilot draft JSON"),
        Some("2026-08-24T12:00:00Z".into()),
    )
    .expect("generated pilot");
    assert_eq!(retained, generated);
    assert_eq!(retained.target.apex_host, "mitiqueteonline.com");
    assert!(!retained.target.include_subdomains);
    assert_eq!(retained.readiness, PilotReadiness::Blocked);
    assert_eq!(
        retained.blockers,
        vec![
            PilotBlocker::OwnershipEvidenceUnverified,
            PilotBlocker::BoundedTransportMissing,
            PilotBlocker::StagingNotCompleted,
        ]
    );
    assert!(!retained.claims.network_executed);
    assert!(!retained.claims.production_execution_allowed);
    assert!(!retained.policy.send_credentials);
    assert!(!retained.policy.retain_response_body);
    assert!(!retained.policy.authentication_comparisons_enabled);
    validate_schema(
        "secureflow-web-observation-pilot-v1.schema.json",
        &serde_json::to_value(&retained).expect("pilot value"),
    );
}

#[test]
fn local_inference_finds_hidden_api_candidates_without_network_or_target_changes() {
    let root = fixture_root();
    let (scope, source) = scope_and_source(&root);
    let before = source.sha256.clone();
    let inventory = discover_nextjs(&root, &scope, &before, source, now()).expect("inventory");
    let inference =
        infer_local_apis(&root, &scope, &before, &inventory, now()).expect("local inference");
    let after = hash_repository_tree(
        &root,
        scope.draft.limits.max_files,
        scope.draft.limits.max_file_bytes,
        scope.draft.limits.max_total_bytes,
    )
    .expect("tree hash after inference");
    assert_eq!(before, after, "inference must not modify the target");
    assert!(!inference.semantics.network_used);
    assert!(!inference.semantics.target_code_executed);
    assert!(inference.semantics.target_preserved);
    assert!(!inference.semantics.obscurity_is_control);
    assert!(!inference.semantics.guesses_are_vulnerabilities);
    assert_eq!(inference.stats.candidates, 11);
    assert_eq!(inference.stats.correlated_local, 4);
    assert_eq!(inference.stats.needs_human_review, 5);
    assert_eq!(inference.stats.abstentions, 2);

    let by_route = |route: &str| {
        inference
            .candidates
            .iter()
            .find(|candidate| candidate.route.as_deref() == Some(route))
            .unwrap_or_else(|| panic!("missing candidate {route}"))
    };
    let health = by_route("/api/health");
    assert_eq!(health.presence.implemented, EvidenceState::Present);
    assert_eq!(health.presence.documented, EvidenceState::Present);
    assert_eq!(health.disposition, CandidateDisposition::CorrelatedLocal);
    assert!(
        health
            .evidence
            .iter()
            .any(|evidence| evidence.origin == CandidateOrigin::ClientCall)
    );
    assert!(
        health
            .evidence
            .iter()
            .any(|evidence| evidence.origin == CandidateOrigin::OpenApi)
    );

    let admin = by_route("/api/admin/{tenantId}/users/{id}");
    assert_eq!(admin.presence.implemented, EvidenceState::Present);
    assert!(
        admin
            .evidence
            .iter()
            .any(|evidence| evidence.origin == CandidateOrigin::ClientCall)
    );
    assert!(
        inference
            .candidates
            .iter()
            .all(|candidate| candidate.route.as_deref() != Some("/api/admin/acme/users/user-1")),
        "concrete client path should correlate to its implemented parameterized route"
    );

    for route in [
        "/api/forgotten",
        "/api/internal",
        "/api/documented-only",
        "/api/trpc/health",
        "/api/trpc/adminUser",
    ] {
        let candidate = by_route(route);
        assert_eq!(candidate.presence.implemented, EvidenceState::Unknown);
        assert_eq!(
            candidate.disposition,
            CandidateDisposition::NeedsHumanReview
        );
    }
    assert!(
        inference
            .candidates
            .iter()
            .any(
                |candidate| candidate.operation.as_deref() == Some("Query.user")
                    && candidate.disposition == CandidateDisposition::Abstained
            )
    );
    assert!(inference.candidates.iter().any(|candidate| candidate.kind
        == ApiCandidateKind::UnresolvedClientCall
        && candidate.route.is_none()
        && candidate.disposition == CandidateDisposition::Abstained));
    assert!(inference.candidates.iter().all(|candidate| {
        candidate
            .route
            .as_deref()
            .is_none_or(|route| !route.contains("third-party") && !route.contains("decoy"))
    }));

    let value = serde_json::to_value(&inference).expect("inference value");
    validate_schema("secureflow-web-inference-v1.schema.json", &value);
    assert_eq!(
        parse_inference(&serde_json::to_vec(&inference).expect("inference JSON"))
            .expect("parsed inference"),
        inference
    );
    let inference_again = infer_local_apis(
        &root,
        &scope,
        &before,
        &inventory,
        OffsetDateTime::parse("2026-08-24T12:00:00Z", &Rfc3339).expect("second time"),
    )
    .expect("second inference");
    assert_eq!(inference.inference_id, inference_again.inference_id);

    let corpus_bytes = std::fs::read(root.join("corpus.json")).expect("corpus bytes");
    let corpus = parse_corpus(&corpus_bytes).expect("valid development corpus");
    assert_eq!(corpus.cases.len(), 24);
    let corpus_result =
        evaluate_corpus(&inventory, &inference, &corpus_bytes).expect("corpus evaluation");
    assert_eq!(corpus_result.counts.total, 24);
    assert_eq!(corpus_result.counts.passed, 24);
    assert_eq!(corpus_result.counts.failed, 0);
    assert!(corpus_result.claims.development_only);
    assert!(!corpus_result.claims.independent_holdout);
    assert!(!corpus_result.claims.superiority_claim_allowed);
    validate_schema(
        "secureflow-web-development-corpus-v1.schema.json",
        &serde_json::to_value(&corpus).expect("corpus value"),
    );
    validate_schema(
        "secureflow-web-corpus-result-v1.schema.json",
        &serde_json::to_value(&corpus_result).expect("corpus result value"),
    );
    assert_eq!(
        parse_corpus_result(
            &serde_json::to_vec(&corpus_result).expect("corpus result serialization")
        )
        .expect("parsed corpus result"),
        corpus_result
    );
}

#[test]
fn assessment_separates_exposure_candidates_from_safe_public_control() {
    let root = fixture_root();
    let (scope, source) = scope_and_source(&root);
    let source_sha256 = source.sha256.clone();
    let inventory =
        discover_nextjs(&root, &scope, &source_sha256, source, now()).expect("inventory");
    let admin = CoverageRoute {
        route_key: "GET /api/admin/{tenantId}/users/{id}".into(),
        method: HttpMethod::Get,
        route: "/api/admin/{tenantId}/users/{id}".into(),
        implemented: true,
        documented: false,
        observed: true,
        access_intent: AccessIntent::Privileged,
        expected: ControlExpectation {
            authentication_required: true,
            authorization_required: true,
            owner_scope_required: false,
            tenant_scope_required: true,
            restricted_cors_required: true,
            private_cache_required: true,
            sanitized_errors_required: true,
        },
        observed_controls: ObservedControls {
            authentication: ControlState::Present,
            authorization: ControlState::Inconsistent,
            owner_scope: ControlState::NotApplicable,
            tenant_scope: ControlState::Missing,
            restricted_cors: ControlState::Missing,
            private_cache: ControlState::Missing,
            sanitized_errors: ControlState::Missing,
        },
        allowed_response_fields: vec!["id".into()],
        response_allowlist_declared: true,
        observed_response_fields: vec!["email".into(), "id".into(), "tenantId".into()],
        evidence: assessment_evidence(),
    };
    let health = CoverageRoute {
        route_key: "GET /api/health".into(),
        method: HttpMethod::Get,
        route: "/api/health".into(),
        implemented: true,
        documented: true,
        observed: true,
        access_intent: AccessIntent::Public,
        expected: ControlExpectation {
            authentication_required: false,
            authorization_required: false,
            owner_scope_required: false,
            tenant_scope_required: false,
            restricted_cors_required: false,
            private_cache_required: false,
            sanitized_errors_required: false,
        },
        observed_controls: ObservedControls {
            authentication: ControlState::NotApplicable,
            authorization: ControlState::NotApplicable,
            owner_scope: ControlState::NotApplicable,
            tenant_scope: ControlState::NotApplicable,
            restricted_cors: ControlState::NotApplicable,
            private_cache: ControlState::NotApplicable,
            sanitized_errors: ControlState::Present,
        },
        allowed_response_fields: vec!["status".into()],
        response_allowlist_declared: true,
        observed_response_fields: vec!["status".into()],
        evidence: vec![EvidenceReference {
            kind: AssessmentEvidenceKind::Code,
            reference: "app/api/health/route.ts:1".into(),
            sha256: "6".repeat(64),
            description: "intentional public health control".into(),
        }],
    };
    let assessment = assess_routes(
        scope.scope_id,
        vec![inventory.inventory_id],
        vec![admin, health],
        Some(CREATED_AT.into()),
    )
    .expect("assessment");
    assert_eq!(assessment.summary.candidates, 6);
    assert_eq!(assessment.summary.hardening, 1);
    assert_eq!(assessment.summary.human_validated_vulnerabilities, 0);
    assert!(
        assessment
            .observations
            .iter()
            .all(|item| item.route != "/api/health")
    );
    let value = serde_json::to_value(&assessment).expect("assessment value");
    validate_schema("secureflow-web-assessment-v1.schema.json", &value);
    assert_eq!(
        parse_assessment(&serde_json::to_vec(&assessment).expect("assessment JSON"))
            .expect("parsed assessment"),
        assessment
    );
}

#[test]
fn scope_guard_rejects_expiry_and_wrong_repository() {
    let root = fixture_root();
    let (scope, mut source) = scope_and_source(&root);
    let expired_now = OffsetDateTime::parse(EXPIRES_AT, &Rfc3339).expect("expiry");
    assert!(
        parse_scope(
            &serde_json::to_vec(&scope).expect("scope JSON"),
            expired_now
        )
        .is_err()
    );
    source.sha256 = "9".repeat(64);
    let source_sha256 = source.sha256.clone();
    assert!(matches!(
        discover_nextjs(&root, &scope, &source_sha256, source, now()),
        Err(InventoryError::UnauthorizedRepository)
    ));
}

#[test]
fn lab_runner_reports_missing_routes_in_json_and_sarif() {
    let root = fixture_root();
    let (scope, source) = scope_and_source(&root);
    let source_sha256 = source.sha256.clone();
    let inventory =
        discover_nextjs(&root, &scope, &source_sha256, source, now()).expect("inventory");
    let expected: Value =
        serde_json::from_slice(&std::fs::read(root.join("expected.json")).expect("expected bytes"))
            .expect("expected JSON");
    let mut expected: secureflow_web::WebCase =
        serde_json::from_value(expected).expect("typed expected case");
    expected.routes.push(secureflow_web::RouteExpectation {
        route: Some("/zzz-missing".into()),
        kind: secureflow_web::RouteKind::ApiRoute,
        methods: vec![HttpMethod::Get],
    });
    expected.routes.sort();
    let expected = seal_case(expected).expect("re-sealed modified case");
    let result = compare_inventory(
        &inventory,
        &serde_json::to_vec(&expected).expect("modified case JSON"),
    )
    .expect("comparison");
    assert_eq!(result.counts.missing_routes, 1);
    assert_eq!(result.counts.unexpected_routes, 0);
    assert!(
        result
            .metrics
            .route_recall
            .basis_points
            .is_some_and(|value| value < 10_000)
    );
    let sarif = lab_result_sarif(&result).expect("SARIF");
    assert_eq!(
        sarif["runs"][0]["results"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "SFWEBLAB001");
}

#[test]
fn lab_binary_writes_json_and_sarif_without_overwrite() {
    let root = fixture_root();
    let (scope, source) = scope_and_source(&root);
    let source_sha256 = source.sha256.clone();
    let inventory =
        discover_nextjs(&root, &scope, &source_sha256, source, now()).expect("inventory");
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let output_root = std::env::temp_dir().join(format!(
        "secureflow-web-lab-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&output_root).expect("temporary output directory");
    let inventory_path = output_root.join("inventory.json");
    let result_path = output_root.join("result.json");
    let sarif_path = output_root.join("result.sarif");
    std::fs::write(
        &inventory_path,
        serde_json::to_vec_pretty(&inventory).expect("inventory JSON"),
    )
    .expect("inventory input");
    let binary = env!("CARGO_BIN_EXE_secureflow-web-lab");
    let output = std::process::Command::new(binary)
        .arg(&inventory_path)
        .arg(root.join("expected.json"))
        .arg(&result_path)
        .arg(&sarif_path)
        .output()
        .expect("lab binary");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&std::fs::read(&result_path).expect("result bytes"))
        .expect("result JSON");
    validate_schema("secureflow-web-lab-result-v1.schema.json", &result);
    let sarif: Value = serde_json::from_slice(&std::fs::read(&sarif_path).expect("SARIF bytes"))
        .expect("SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    #[cfg(unix)]
    for path in [&result_path, &sarif_path] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path)
                .expect("output metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let second = std::process::Command::new(binary)
        .arg(&inventory_path)
        .arg(root.join("expected.json"))
        .arg(&result_path)
        .arg(&sarif_path)
        .output()
        .expect("second lab binary");
    assert!(!second.status.success(), "outputs must not be overwritten");
    std::fs::remove_dir_all(&output_root).expect("remove exact temporary output directory");
}

#[test]
fn inference_binary_writes_outside_target_and_rejects_overwrite_or_target_mutation() {
    let root = fixture_root();
    let (scope, source) = scope_and_source(&root);
    let source_sha256 = source.sha256.clone();
    let inventory =
        discover_nextjs(&root, &scope, &source_sha256, source, now()).expect("inventory");
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let output_root = std::env::temp_dir().join(format!(
        "secureflow-web-infer-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&output_root).expect("temporary output directory");
    let scope_path = output_root.join("scope.json");
    let inventory_path = output_root.join("inventory.json");
    let inference_path = output_root.join("inference.json");
    std::fs::write(
        &scope_path,
        serde_json::to_vec_pretty(&scope).expect("scope JSON"),
    )
    .expect("scope input");
    std::fs::write(
        &inventory_path,
        serde_json::to_vec_pretty(&inventory).expect("inventory JSON"),
    )
    .expect("inventory input");
    let binary = env!("CARGO_BIN_EXE_secureflow-web-infer");
    let output = std::process::Command::new(binary)
        .arg(&root)
        .arg(&scope_path)
        .arg(&inventory_path)
        .arg(&inference_path)
        .output()
        .expect("inference binary");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inference: Value =
        serde_json::from_slice(&std::fs::read(&inference_path).expect("inference bytes"))
            .expect("inference JSON");
    validate_schema("secureflow-web-inference-v1.schema.json", &inference);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&inference_path)
                .expect("inference metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let second = std::process::Command::new(binary)
        .arg(&root)
        .arg(&scope_path)
        .arg(&inventory_path)
        .arg(&inference_path)
        .output()
        .expect("second inference binary");
    assert!(!second.status.success(), "output must not be overwritten");

    let forbidden_output = root.join("forbidden-inference.json");
    assert!(!forbidden_output.exists());
    let forbidden = std::process::Command::new(binary)
        .arg(&root)
        .arg(&scope_path)
        .arg(&inventory_path)
        .arg(&forbidden_output)
        .output()
        .expect("target output attempt");
    assert!(
        !forbidden.status.success(),
        "target mutation must be rejected"
    );
    assert!(!forbidden_output.exists());
    std::fs::remove_dir_all(&output_root).expect("remove exact temporary output directory");
}

#[test]
fn risk_corpus_and_pilot_binaries_validate_outputs_and_reject_overwrite() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let output_root = std::env::temp_dir().join(format!(
        "secureflow-web-generated-artifacts-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&output_root).expect("temporary output directory");

    let corpus_path = output_root.join("corpus.json");
    let corpus_binary = env!("CARGO_BIN_EXE_secureflow-web-risk-corpus");
    let corpus_output = std::process::Command::new(corpus_binary)
        .arg(risk_corpus_root().join("LICENSE"))
        .arg(&corpus_path)
        .output()
        .expect("risk corpus binary");
    assert!(
        corpus_output.status.success(),
        "{}",
        String::from_utf8_lossy(&corpus_output.stderr)
    );
    let corpus_value: Value =
        serde_json::from_slice(&std::fs::read(&corpus_path).expect("generated corpus bytes"))
            .expect("generated corpus JSON");
    validate_schema(
        "secureflow-web-api-risk-corpus-v1.schema.json",
        &corpus_value,
    );
    let corpus_second = std::process::Command::new(corpus_binary)
        .arg(risk_corpus_root().join("LICENSE"))
        .arg(&corpus_path)
        .output()
        .expect("second risk corpus binary");
    assert!(
        !corpus_second.status.success(),
        "corpus must not be overwritten"
    );

    let pilot_path = output_root.join("pilot.json");
    let pilot_binary = env!("CARGO_BIN_EXE_secureflow-web-pilot-plan");
    let pilot_output = std::process::Command::new(pilot_binary)
        .arg("test-owner-authorization")
        .arg("2026-08-24T12:00:00Z")
        .arg("2026-09-24T12:00:00Z")
        .arg(&pilot_path)
        .output()
        .expect("pilot plan binary");
    assert!(
        pilot_output.status.success(),
        "{}",
        String::from_utf8_lossy(&pilot_output.stderr)
    );
    let pilot_value: Value =
        serde_json::from_slice(&std::fs::read(&pilot_path).expect("pilot bytes"))
            .expect("pilot JSON");
    validate_schema(
        "secureflow-web-observation-pilot-v1.schema.json",
        &pilot_value,
    );
    assert_eq!(pilot_value["readiness"], "blocked");
    assert_eq!(pilot_value["claims"]["network_executed"], false);
    let pilot_second = std::process::Command::new(pilot_binary)
        .arg("test-owner-authorization")
        .arg("2026-08-24T12:00:00Z")
        .arg("2026-09-24T12:00:00Z")
        .arg(&pilot_path)
        .output()
        .expect("second pilot binary");
    assert!(
        !pilot_second.status.success(),
        "pilot must not be overwritten"
    );

    #[cfg(unix)]
    for path in [&corpus_path, &pilot_path] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path)
                .expect("generated artifact metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    std::fs::remove_dir_all(&output_root).expect("remove exact temporary output directory");
}
