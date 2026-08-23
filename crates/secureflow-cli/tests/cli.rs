use std::path::PathBuf;
use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_secureflow")
}

fn validate_with_schema(schema_name: &str, instance: &serde_json::Value) {
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .join(schema_name);
    let schema: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&schema_path).expect("schema should be readable"))
            .expect("schema should be JSON");
    let validator = jsonschema::validator_for(&schema).expect("schema should compile");
    validator
        .validate(instance)
        .expect("instance should satisfy its normative schema");
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/minimal-run.json")
}

fn knowledge_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/minimal-knowledge.jsonl")
}

fn osv_source_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/osv-source")
}

fn secure_review_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/minimal-secure-review.json")
}

fn secure_skill_source_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/secure-skill-source")
}

fn bench_result_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/minimal-bench-result.json")
}

fn bench_run_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/minimal-bench-run.json")
}

fn bench_suite_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/minimal-bench-suite.toml")
}

fn secure_bench_source_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/secure-bench-source")
}

fn finding_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/minimal-run-with-finding.json")
}

fn prospective_protocol_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/prospective-protocol-draft.json")
}

#[test]
fn validates_the_canonical_fixture() {
    let output = Command::new(binary())
        .arg("validate-run")
        .arg(fixture())
        .output()
        .expect("CLI should start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("valid secureflow-run-v1"));
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture()).expect("fixture should be readable"))
            .expect("fixture should be JSON");
    validate_with_schema("secureflow-run-v1.schema.json", &value);
}

#[test]
fn lists_empty_fixture_as_machine_readable_json() {
    let output = Command::new(binary())
        .arg("list-findings")
        .arg(fixture())
        .args(["--format", "json"])
        .output()
        .expect("CLI should start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["count"], 0);
    assert_eq!(value["findings"], serde_json::json!([]));
}

#[test]
fn show_finding_fails_closed_for_unknown_id() {
    let output = Command::new(binary())
        .arg("show-finding")
        .arg(fixture())
        .arg("sf_finding_0000000000000000")
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("finding not found"));
}

#[test]
fn human_can_abstain_without_mutating_the_original_manifest() {
    let output_path = std::env::temp_dir().join(format!(
        "secureflow-cli-abstained-review-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&output_path);
    let original = std::fs::read(finding_fixture()).expect("fixture should be readable");
    let output = Command::new(binary())
        .arg("review-run")
        .args(["--manifest"])
        .arg(finding_fixture())
        .args(["--finding-id", "sf_finding_fixture_1234567890abcdef"])
        .args(["--decision", "abstained"])
        .args(["--reviewer", "Daniel"])
        .args(["--rationale", "La evidencia disponible no permite decidir."])
        .args(["--output"])
        .arg(&output_path)
        .output()
        .expect("CLI should start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(finding_fixture()).expect("original fixture should remain readable"),
        original
    );
    let reviewed: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&output_path).expect("derived manifest should be readable"),
    )
    .expect("derived manifest should be JSON");
    assert_eq!(
        reviewed["findings"][0]["human_review"]["decision"],
        "abstained"
    );
    assert_eq!(reviewed["summary"]["abstained_count"], 1);
    assert_eq!(reviewed["phases"]["validation"], "completed");
    validate_with_schema("secureflow-run-v1.schema.json", &reviewed);
    std::fs::remove_file(output_path).expect("temporary output should be removable");
}

#[test]
fn exports_a_markdown_report_that_preserves_candidate_semantics() {
    let output_path =
        std::env::temp_dir().join(format!("secureflow-cli-report-{}.md", std::process::id()));
    let _ = std::fs::remove_file(&output_path);
    let output = Command::new(binary())
        .arg("export-report")
        .args(["--manifest"])
        .arg(finding_fixture())
        .args(["--output"])
        .arg(&output_path)
        .output()
        .expect("CLI should start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = std::fs::read_to_string(&output_path).expect("report should be readable");
    assert!(report.contains("candidate, not confirmed vulnerability"));
    assert!(report.contains("Only the recorded human decision is authoritative"));
    assert!(report.contains("Potential command injection"));
    assert!(report.contains("This evidence description must not enter the AI payload"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&output_path)
            .expect("report metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    std::fs::remove_file(&output_path).expect("temporary report should be removable");
}

#[test]
fn queries_validated_knowledge_as_json() {
    let output = Command::new(binary())
        .arg("knowledge-list")
        .arg(knowledge_fixture())
        .args(["--decision", "validated", "--format", "json"])
        .output()
        .expect("CLI should start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["count"], 1);
    assert_eq!(value["records"][0]["decision"], "validated");
}

#[test]
fn prints_the_knowledge_schema() {
    let output = Command::new(binary())
        .arg("knowledge-schema")
        .output()
        .expect("CLI should start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["title"], "SecureFlow Knowledge Record v2");

    let legacy = Command::new(binary())
        .arg("knowledge-schema")
        .args(["--version", "v1"])
        .output()
        .expect("CLI should start");
    assert!(legacy.status.success());
    let legacy_value: serde_json::Value =
        serde_json::from_slice(&legacy.stdout).expect("legacy schema should be JSON");
    assert_eq!(legacy_value["title"], "SecureFlow Knowledge Record v1");
}

#[test]
fn imports_reviewed_findings_as_traceable_v2_knowledge() {
    let base = std::env::temp_dir().join(format!(
        "secureflow-cli-knowledge-v2-{}",
        std::process::id()
    ));
    let reviewed_path = base.with_extension("reviewed.json");
    let ledger_root = base.with_extension("ledger-root");
    let ledger_path = ledger_root.join("nested/knowledge.jsonl");
    let _ = std::fs::remove_file(&reviewed_path);
    let _ = std::fs::remove_dir_all(&ledger_root);

    let review = Command::new(binary())
        .arg("review-run")
        .args(["--manifest"])
        .arg(finding_fixture())
        .args([
            "--finding-id",
            "sf_finding_fixture_1234567890abcdef",
            "--decision",
            "abstained",
            "--reviewer",
            "fixture-human",
            "--rationale",
            "Insufficient runtime evidence",
            "--output",
        ])
        .arg(&reviewed_path)
        .output()
        .expect("review command should start");
    assert!(
        review.status.success(),
        "{}",
        String::from_utf8_lossy(&review.stderr)
    );

    let import = Command::new(binary())
        .arg("knowledge-import")
        .args(["--manifest"])
        .arg(&reviewed_path)
        .args(["--ledger"])
        .arg(&ledger_path)
        .args(["--source-license-status", "unknown"])
        .output()
        .expect("knowledge import should start");
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    assert!(String::from_utf8_lossy(&import.stdout).contains("duplicate_observations_linked=0"));

    let line = std::fs::read_to_string(&ledger_path).expect("ledger should exist");
    let record: serde_json::Value =
        serde_json::from_str(line.trim()).expect("record should be JSON");
    assert_eq!(record["record_version"], "secureflow-knowledge-record-v2");
    assert_eq!(record["source_license"]["status"], "unknown");
    assert_eq!(record["source_license"]["assertion"], "operator-declared");
    assert!(
        record["observation_fingerprint"]
            .as_str()
            .expect("fingerprint string")
            .starts_with("sf_obs_")
    );
    validate_with_schema("secureflow-knowledge-record-v2.schema.json", &record);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ledger_mode = std::fs::metadata(&ledger_path)
            .expect("ledger metadata")
            .permissions()
            .mode()
            & 0o777;
        let directory_mode = std::fs::metadata(ledger_path.parent().expect("ledger parent"))
            .expect("ledger directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(ledger_mode, 0o600);
        assert_eq!(directory_mode, 0o700);
    }

    std::fs::remove_file(reviewed_path).expect("temporary manifest cleanup");
    std::fs::remove_dir_all(ledger_root).expect("temporary ledger cleanup");
}

#[test]
fn imports_and_queries_a_deduplicated_local_osv_catalog() {
    let root = std::env::temp_dir().join(format!("secureflow-cli-catalog-{}", std::process::id()));
    let database = root.join("catalog.sqlite3");
    let _ = std::fs::remove_dir_all(&root);
    let source = osv_source_fixture();
    let original = std::fs::read(source.join("advisories/GHSA-aaaa-bbbb-cccc.json"))
        .expect("fixture should be readable");

    let import = Command::new(binary())
        .arg("catalog-import-osv")
        .args(["--database"])
        .arg(&database)
        .args(["--input"])
        .arg(source.join("advisories"))
        .args(["--source-name", "fixture-osv"])
        .args(["--source-license-expression", "CC-BY-4.0"])
        .args(["--source-license-evidence"])
        .arg(source.join("LICENSE"))
        .args(["--source-locator", "https://example.invalid/osv-fixture"])
        .output()
        .expect("catalog import should start");
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    assert!(String::from_utf8_lossy(&import.stdout).contains("seen=2"));
    assert!(String::from_utf8_lossy(&import.stdout).contains("total_canonical_vulnerabilities=1"));

    let stats = Command::new(binary())
        .arg("catalog-stats")
        .arg(&database)
        .output()
        .expect("catalog stats should start");
    assert!(
        stats.status.success(),
        "{}",
        String::from_utf8_lossy(&stats.stderr)
    );
    let stats: serde_json::Value =
        serde_json::from_slice(&stats.stdout).expect("stats should be JSON");
    assert_eq!(stats["source_records"], 2);
    assert_eq!(stats["canonical_vulnerabilities"], 1);
    assert_eq!(stats["source_record_revisions"], 2);
    assert_eq!(stats["search_index_status"], "ready");

    let check = Command::new(binary())
        .arg("catalog-check")
        .arg(&database)
        .output()
        .expect("catalog check should start");
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    let check: serde_json::Value =
        serde_json::from_slice(&check.stdout).expect("check should be JSON");
    assert_eq!(check["quick_check"], "ok");
    assert_eq!(check["foreign_key_violations"], 0);

    for arguments in [
        vec![
            "catalog-lookup",
            "--database",
            database.to_str().expect("UTF-8 path"),
            "CVE-2026-0001",
            "--format",
            "json",
        ],
        vec![
            "catalog-search",
            "--database",
            database.to_str().expect("UTF-8 path"),
            "command injection",
            "--format",
            "json",
        ],
        vec![
            "catalog-package",
            "--database",
            database.to_str().expect("UTF-8 path"),
            "crates.io",
            "secureflow-fixture",
            "--format",
            "json",
        ],
    ] {
        let output = Command::new(binary())
            .args(arguments)
            .output()
            .expect("catalog query should start");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("query should be JSON");
        assert_eq!(value["count"], 2);
        assert_eq!(value["validation_authority"], "human-only");
    }

    assert_eq!(
        std::fs::read(source.join("advisories/GHSA-aaaa-bbbb-cccc.json"))
            .expect("fixture should remain readable"),
        original
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&database)
                .expect("database metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let backup = root.join("catalog.backup.sqlite3");
    let backup_manifest = root.join("catalog.backup.json");
    let restored = root.join("catalog.restored.sqlite3");
    let restored_manifest = root.join("catalog.restored.json");
    let backup_output = Command::new(binary())
        .arg("catalog-backup")
        .args(["--database"])
        .arg(&database)
        .args(["--output"])
        .arg(&backup)
        .args(["--manifest-output"])
        .arg(&backup_manifest)
        .output()
        .expect("catalog backup should start");
    assert!(
        backup_output.status.success(),
        "{}",
        String::from_utf8_lossy(&backup_output.stderr)
    );
    let verify_output = Command::new(binary())
        .arg("catalog-backup-verify")
        .args(["--backup"])
        .arg(&backup)
        .args(["--manifest"])
        .arg(&backup_manifest)
        .output()
        .expect("catalog backup verification should start");
    assert!(verify_output.status.success());
    let restore_output = Command::new(binary())
        .arg("catalog-restore")
        .args(["--backup"])
        .arg(&backup)
        .args(["--manifest"])
        .arg(&backup_manifest)
        .args(["--output"])
        .arg(&restored)
        .args(["--manifest-output"])
        .arg(&restored_manifest)
        .output()
        .expect("catalog restore should start");
    assert!(restore_output.status.success());
    let restored_stats = Command::new(binary())
        .arg("catalog-stats")
        .arg(&restored)
        .output()
        .expect("restored stats should start");
    let restored_stats: serde_json::Value =
        serde_json::from_slice(&restored_stats.stdout).expect("restored stats JSON");
    assert_eq!(restored_stats["source_records"], 2);
    assert_eq!(restored_stats["canonical_vulnerabilities"], 1);
    std::fs::remove_dir_all(root).expect("temporary catalog cleanup");
}

#[test]
fn prints_new_phase_two_schemas_and_seals_a_prospective_protocol() {
    for (command, schema_name) in [
        (
            "correlation-schema",
            "secureflow-correlation-v2.schema.json",
        ),
        (
            "orchestration-schema",
            "secureflow-orchestration-v1.schema.json",
        ),
        (
            "prospective-protocol-schema",
            "secureflow-prospective-protocol-v1.schema.json",
        ),
        (
            "advisory-delta-schema",
            "secureflow-advisory-delta-v1.schema.json",
        ),
    ] {
        let output = Command::new(binary())
            .arg(command)
            .output()
            .expect("schema command should start");
        assert!(output.status.success());
        let schema: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("schema JSON");
        jsonschema::validator_for(&schema).expect("schema should compile");
        assert!(
            schema["$id"]
                .as_str()
                .is_some_and(|value| value.ends_with(schema_name))
        );
    }

    let legacy_correlation_schema = Command::new(binary())
        .arg("correlation-schema")
        .args(["--version", "v1"])
        .output()
        .expect("legacy correlation schema command should start");
    assert!(legacy_correlation_schema.status.success());
    let legacy_correlation_schema: serde_json::Value =
        serde_json::from_slice(&legacy_correlation_schema.stdout).expect("legacy schema JSON");
    assert!(
        legacy_correlation_schema["$id"]
            .as_str()
            .is_some_and(|value| value.ends_with("secureflow-correlation-v1.schema.json"))
    );

    let output_path = std::env::temp_dir().join(format!(
        "secureflow-prospective-protocol-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&output_path);
    let sealed = Command::new(binary())
        .arg("benchmark-protocol-seal")
        .args(["--draft"])
        .arg(prospective_protocol_fixture())
        .args(["--output"])
        .arg(&output_path)
        .output()
        .expect("protocol seal should start");
    assert!(
        sealed.status.success(),
        "{}",
        String::from_utf8_lossy(&sealed.stderr)
    );
    let protocol: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output_path).expect("sealed protocol should exist"))
            .expect("sealed protocol JSON");
    validate_with_schema("secureflow-prospective-protocol-v1.schema.json", &protocol);
    let validated = Command::new(binary())
        .arg("benchmark-protocol-validate")
        .arg(&output_path)
        .output()
        .expect("protocol validation should start");
    assert!(validated.status.success());
    std::fs::remove_file(output_path).expect("protocol cleanup");
}

#[test]
fn prepares_and_validates_a_fail_closed_advisory_delta() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "secureflow-cli-delta-{}-{nonce}",
        std::process::id()
    ));
    let payloads = root.join("payloads");
    let output = root.join("prepared");
    std::fs::create_dir_all(&payloads).expect("payload directory");
    std::fs::write(
        root.join("modified_id.csv"),
        b"2026-08-23T12:00:00Z,GHSA-aaaa-bbbb-cccc\n",
    )
    .expect("index");
    std::fs::write(root.join("license.txt"), b"CC-BY-4.0 evidence").expect("license");
    std::fs::write(
        payloads.join("GHSA-aaaa-bbbb-cccc.json"),
        serde_json::to_vec(&serde_json::json!({
            "id": "GHSA-aaaa-bbbb-cccc",
            "modified": "2026-08-23T12:00:00Z",
            "withdrawn": "2026-08-23T12:00:00Z",
            "summary": "CLI delta fixture",
            "affected": [{
                "package": {"ecosystem": "crates.io", "name": "fixture"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
            }]
        }))
        .expect("payload JSON"),
    )
    .expect("payload");

    let prepared = Command::new(binary())
        .arg("delta-prepare-osv")
        .args(["--modified-index"])
        .arg(root.join("modified_id.csv"))
        .args(["--records"])
        .arg(&payloads)
        .args(["--output"])
        .arg(&output)
        .args([
            "--index-locator",
            "https://storage.googleapis.com/osv-vulnerabilities/crates.io/modified_id.csv",
            "--index-revision",
            "etag-fixture",
            "--expected-ecosystem",
            "crates.io",
            "--acquired-at",
            "2026-08-23T13:00:00Z",
            "--after-modified",
            "2026-08-23T00:00:00Z",
            "--base-snapshot-id",
            &format!("sf_snapshot_{}", "1".repeat(64)),
            "--github-license-evidence",
        ])
        .arg(root.join("license.txt"))
        .output()
        .expect("delta preparation should start");
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let manifest_path = output.join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("prepared manifest"))
            .expect("manifest JSON");
    validate_with_schema("secureflow-advisory-delta-v1.schema.json", &manifest);
    assert_eq!(manifest["semantics"]["absence_deactivates_record"], false);
    assert_eq!(manifest["accounting"]["withdrawn_records"], 1);

    let validated = Command::new(binary())
        .arg("delta-validate")
        .arg(&manifest_path)
        .output()
        .expect("delta validation should start");
    assert!(
        validated.status.success(),
        "{}",
        String::from_utf8_lossy(&validated.stderr)
    );
    let missing_catalog = root.join("missing-catalog.sqlite3");
    let rejected_import = Command::new(binary())
        .arg("catalog-import-delta")
        .args(["--database"])
        .arg(&missing_catalog)
        .args(["--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("delta import should start");
    assert!(!rejected_import.status.success());
    assert!(!missing_catalog.exists());
    std::fs::remove_dir_all(root).expect("delta cleanup");
}

#[test]
fn prospective_preflight_binds_real_artifacts_without_opening_labels() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "secureflow-cli-prospective-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("study directory");
    let known_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let artifacts = [
        root.join("corpus.json"),
        root.join("provenance.json"),
        root.join("licenses.json"),
        root.join("environment.json"),
    ];
    for artifact in &artifacts {
        std::fs::write(artifact, b"abc").expect("commitment artifact");
    }
    let mut draft: serde_json::Value = serde_json::from_slice(
        &std::fs::read(prospective_protocol_fixture()).expect("protocol fixture"),
    )
    .expect("protocol JSON");
    draft["corpus"]["manifest_sha256"] = known_hash.into();
    draft["corpus"]["provenance_sha256"] = known_hash.into();
    draft["corpus"]["license_manifest_sha256"] = known_hash.into();
    draft["execution"]["environment_sha256"] = known_hash.into();
    let draft_path = root.join("draft.json");
    std::fs::write(
        &draft_path,
        serde_json::to_vec_pretty(&draft).expect("draft bytes"),
    )
    .expect("draft");
    let output = root.join("sealed.json");
    let preflight = Command::new(binary())
        .arg("benchmark-protocol-preflight")
        .args(["--draft"])
        .arg(&draft_path)
        .args(["--corpus-manifest"])
        .arg(&artifacts[0])
        .args(["--provenance-manifest"])
        .arg(&artifacts[1])
        .args(["--license-manifest"])
        .arg(&artifacts[2])
        .args(["--environment-manifest"])
        .arg(&artifacts[3])
        .args(["--output"])
        .arg(&output)
        .output()
        .expect("preflight should start");
    assert!(
        preflight.status.success(),
        "{}",
        String::from_utf8_lossy(&preflight.stderr)
    );
    assert!(String::from_utf8_lossy(&preflight.stdout).contains("labels_opened=false"));
    let protocol: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output).expect("sealed protocol"))
            .expect("sealed JSON");
    validate_with_schema("secureflow-prospective-protocol-v1.schema.json", &protocol);

    std::fs::write(&artifacts[3], b"tampered").expect("tamper environment");
    let rejected = Command::new(binary())
        .arg("benchmark-protocol-preflight")
        .args(["--draft"])
        .arg(&draft_path)
        .args(["--corpus-manifest"])
        .arg(&artifacts[0])
        .args(["--provenance-manifest"])
        .arg(&artifacts[1])
        .args(["--license-manifest"])
        .arg(&artifacts[2])
        .args(["--environment-manifest"])
        .arg(&artifacts[3])
        .args(["--output"])
        .arg(root.join("must-not-exist.json"))
        .output()
        .expect("tampered preflight should start");
    assert!(!rejected.status.success());
    assert!(!root.join("must-not-exist.json").exists());
    std::fs::remove_dir_all(root).expect("study cleanup");
}

#[test]
fn prints_the_secure_review_schema() {
    let output = Command::new(binary())
        .arg("secure-review-schema")
        .output()
        .expect("CLI should start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(
        value["title"],
        "SecureFlow Secure Skill Contextual Review v1"
    );
}

#[test]
fn imports_and_lists_secure_skill_findings_as_contextual_candidates() {
    let output_path = std::env::temp_dir().join(format!(
        "secureflow-cli-secure-review-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&output_path);

    let import = Command::new(binary())
        .arg("secure-review-import")
        .args(["--review"])
        .arg(secure_review_fixture())
        .args(["--manifest"])
        .arg(fixture())
        .args(["--secure-skill-root"])
        .arg(secure_skill_source_fixture())
        .args([
            "--secure-skill-revision",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .args(["--output"])
        .arg(&output_path)
        .output()
        .expect("CLI should start");
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    assert!(String::from_utf8_lossy(&import.stdout).contains("validation_authority=human-only"));
    let imported: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output_path).expect("envelope should be readable"))
            .expect("envelope should be JSON");
    validate_with_schema("secureflow-secure-review-v1.schema.json", &imported);

    let validate = Command::new(binary())
        .arg("secure-review-validate")
        .arg(&output_path)
        .output()
        .expect("CLI should start");
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );

    let list = Command::new(binary())
        .arg("secure-review-list")
        .arg(&output_path)
        .args(["--format", "json"])
        .output()
        .expect("CLI should start");
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&list.stdout).expect("stdout should be JSON");
    assert_eq!(value["count"], 1);
    assert_eq!(value["semantics"]["validation_authority"], "human-only");
    assert_eq!(
        value["semantics"]["imported_findings_are"],
        "contextual-candidates"
    );
    assert_eq!(value["semantics"]["no_findings_mean_safe"], false);

    std::fs::remove_file(&output_path).expect("temporary fixture output should be removable");
}

#[test]
fn prints_the_benchmark_schema() {
    let output = Command::new(binary())
        .arg("benchmark-schema")
        .output()
        .expect("CLI should start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    assert_eq!(value["title"], "SecureFlow Benchmark Result v1");
}

#[test]
fn imports_verified_benchmark_artifacts_without_enabling_marketing_claims() {
    let output_path = std::env::temp_dir().join(format!(
        "secureflow-cli-benchmark-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&output_path);
    let import = Command::new(binary())
        .arg("benchmark-import")
        .args(["--result"])
        .arg(bench_result_fixture())
        .args(["--run-manifest"])
        .arg(bench_run_fixture())
        .args(["--suite"])
        .arg(bench_suite_fixture())
        .args(["--secure-bench-root"])
        .arg(secure_bench_source_fixture())
        .args([
            "--secure-bench-revision",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .args(["--study-kind", "historical-public-diagnostic"])
        .args(["--output"])
        .arg(&output_path)
        .output()
        .expect("CLI should start");
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    let imported: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output_path).expect("envelope should be readable"))
            .expect("envelope should be JSON");
    validate_with_schema("secureflow-benchmark-result-v1.schema.json", &imported);

    let summary = Command::new(binary())
        .arg("benchmark-summary")
        .arg(&output_path)
        .args(["--format", "json"])
        .output()
        .expect("CLI should start");
    assert!(
        summary.status.success(),
        "{}",
        String::from_utf8_lossy(&summary.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&summary.stdout).expect("stdout should be JSON");
    assert_eq!(
        value["result"]["confusion"]["true_positive_expectations"],
        1
    );
    assert_eq!(
        value["result"]["confusion"]["false_negative_expectations"],
        1
    );
    assert_eq!(value["claims"]["evaluation_only"], true);
    assert_eq!(value["claims"]["ranking_allowed"], false);
    assert_eq!(value["claims"]["superiority_claim_allowed"], false);

    std::fs::remove_file(&output_path).expect("temporary fixture output should be removable");
}

#[test]
fn benchmark_import_rejects_a_suite_fingerprint_mismatch() {
    let output_path = std::env::temp_dir().join(format!(
        "secureflow-cli-benchmark-mismatch-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&output_path);
    let output = Command::new(binary())
        .arg("benchmark-import")
        .args(["--result"])
        .arg(bench_result_fixture())
        .args(["--run-manifest"])
        .arg(bench_run_fixture())
        .args(["--suite"])
        .arg(bench_run_fixture())
        .args(["--secure-bench-root"])
        .arg(secure_bench_source_fixture())
        .args([
            "--secure-bench-revision",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .args(["--study-kind", "historical-public-diagnostic"])
        .args(["--output"])
        .arg(&output_path)
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("suite"));
    assert!(!output_path.exists());
}

#[test]
fn prints_the_ai_contract_schemas() {
    for (command, title) in [
        ("ai-request-schema", "SecureFlow Redacted AI Request v1"),
        ("ai-response-schema", "SecureFlow Advisory AI Response v1"),
    ] {
        let output = Command::new(binary())
            .arg(command)
            .output()
            .expect("CLI should start");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
        assert_eq!(value["title"], title);
    }
}

#[test]
fn ai_preparation_is_disabled_without_explicit_enablement() {
    let output_path = std::env::temp_dir().join(format!(
        "secureflow-cli-ai-disabled-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&output_path);
    let output = Command::new(binary())
        .arg("ai-prepare")
        .args(["--manifest"])
        .arg(finding_fixture())
        .args(["--finding-id", "sf_finding_fixture_1234567890abcdef"])
        .arg("--consent-redacted-export")
        .args(["--output"])
        .arg(&output_path)
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("AI is disabled"));
    assert!(!output_path.exists());
}

#[test]
fn prepares_and_applies_a_budgeted_advisory_response_without_human_validation() {
    let temporary = std::env::temp_dir();
    let request_path = temporary.join(format!(
        "secureflow-cli-ai-request-{}.json",
        std::process::id()
    ));
    let response_path = temporary.join(format!(
        "secureflow-cli-ai-response-{}.json",
        std::process::id()
    ));
    let manifest_path = temporary.join(format!(
        "secureflow-cli-ai-manifest-{}.json",
        std::process::id()
    ));
    for path in [&request_path, &response_path, &manifest_path] {
        let _ = std::fs::remove_file(path);
    }

    let prepare = Command::new(binary())
        .arg("ai-prepare")
        .args(["--manifest"])
        .arg(finding_fixture())
        .args(["--finding-id", "sf_finding_fixture_1234567890abcdef"])
        .args(["--enable-ai", "--consent-redacted-export"])
        .args(["--output"])
        .arg(&request_path)
        .output()
        .expect("CLI should start");
    assert!(
        prepare.status.success(),
        "{}",
        String::from_utf8_lossy(&prepare.stderr)
    );
    assert!(String::from_utf8_lossy(&prepare.stdout).contains("transmitted=false"));
    let request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&request_path).expect("request should be readable"))
            .expect("request should be JSON");
    assert_eq!(request["model_family"], "luna");
    assert_eq!(request["authority"]["validation_authority"], "human-only");
    assert!(!request.to_string().contains("This evidence description"));
    validate_with_schema("secureflow-ai-request-v1.schema.json", &request);

    let response = serde_json::json!({
        "contract_version": "secureflow-ai-response-v1",
        "request_id": request["request_id"],
        "responded_at": "2026-08-23T13:01:00Z",
        "provider": "openai",
        "model_family": "luna",
        "prompt_version": "secureflow-ai-triage-v1",
        "request_payload_sha256": request["payload_sha256"],
        "assessment": "uncertain",
        "analysis_summary": "The minimized evidence requires human application context.",
        "input_tokens": 500,
        "output_tokens": 100,
        "limitations": ["requires-human-context"],
        "validation_authority": "human-only"
    });
    validate_with_schema("secureflow-ai-response-v1.schema.json", &response);
    std::fs::write(
        &response_path,
        serde_json::to_vec_pretty(&response).expect("response should serialize"),
    )
    .expect("response fixture should be writable");

    let apply = Command::new(binary())
        .arg("ai-apply-response")
        .args(["--manifest"])
        .arg(finding_fixture())
        .args(["--request"])
        .arg(&request_path)
        .args(["--response"])
        .arg(&response_path)
        .args(["--output"])
        .arg(&manifest_path)
        .output()
        .expect("CLI should start");
    assert!(
        apply.status.success(),
        "{}",
        String::from_utf8_lossy(&apply.stderr)
    );
    assert!(String::from_utf8_lossy(&apply.stdout).contains("human_decision_unchanged=true"));
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&manifest_path).expect("manifest should be readable"),
    )
    .expect("manifest should be JSON");
    assert_eq!(
        manifest["findings"][0]["human_review"]["decision"],
        "pending"
    );
    assert_eq!(
        manifest["findings"][0]["ai_validation"]["status"],
        "completed"
    );
    assert_eq!(
        manifest["findings"][0]["ai_validation"]["assessment"],
        "uncertain"
    );
    assert_eq!(manifest["summary"]["ai_calls"], 1);
    assert_eq!(manifest["summary"]["ai_input_tokens"], 500);
    validate_with_schema("secureflow-run-v1.schema.json", &manifest);

    for path in [&request_path, &response_path, &manifest_path] {
        std::fs::remove_file(path).expect("temporary output should be removable");
    }
}

#[test]
fn validate_run_rejects_unknown_contract_fields() {
    let path = std::env::temp_dir().join(format!(
        "secureflow-cli-unknown-field-{}.json",
        std::process::id()
    ));
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture()).expect("fixture should be readable"))
            .expect("fixture should be JSON");
    value
        .as_object_mut()
        .expect("manifest object")
        .insert("unexpected".into(), serde_json::Value::Bool(true));
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&value).expect("fixture should serialize"),
    )
    .expect("temporary fixture should be writable");

    let output = Command::new(binary())
        .arg("validate-run")
        .arg(&path)
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field"));
    std::fs::remove_file(path).expect("temporary fixture should be removable");
}

#[test]
fn derived_output_cannot_overwrite_its_manifest_input() {
    let path = std::env::temp_dir().join(format!(
        "secureflow-cli-alias-input-{}.json",
        std::process::id()
    ));
    let original = std::fs::read(finding_fixture()).expect("fixture should be readable");
    std::fs::write(&path, &original).expect("temporary fixture should be writable");

    let output = Command::new(binary())
        .arg("export-report")
        .args(["--manifest"])
        .arg(&path)
        .args(["--output"])
        .arg(&path)
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("aliases protected input"));
    assert_eq!(
        std::fs::read(&path).expect("input should remain readable"),
        original
    );
    std::fs::remove_file(path).expect("temporary fixture should be removable");
}

#[test]
fn scan_rejects_outputs_inside_the_authorized_target() {
    let root = std::env::temp_dir().join(format!(
        "secureflow-cli-protected-target-{}",
        std::process::id()
    ));
    let manifest = std::env::temp_dir().join(format!(
        "secureflow-cli-protected-manifest-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_file(&manifest);
    std::fs::create_dir(&root).expect("temporary target should be created");
    std::fs::write(root.join("source.ts"), "export const value = 1;\n")
        .expect("temporary target should be writable");

    let output = Command::new(binary())
        .arg("scan")
        .args(["--binary", "/bin/false"])
        .arg(&root)
        .arg("--authorized")
        .args(["--authorization-reviewer", "test-runner"])
        .args(["--output"])
        .arg(root.join("report.json"))
        .args(["--manifest-output"])
        .arg(&manifest)
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("inside protected input tree"));
    assert!(!root.join("report.json").exists());
    assert!(!manifest.exists());
    std::fs::remove_dir_all(root).expect("temporary target should be removable");
}

#[cfg(unix)]
#[test]
fn scan_fails_closed_when_the_target_changes_during_execution() {
    use std::os::unix::fs::PermissionsExt;

    let suffix = std::process::id();
    let root = std::env::temp_dir().join(format!("secureflow-cli-changing-target-{suffix}"));
    let engine = std::env::temp_dir().join(format!("secureflow-cli-changing-engine-{suffix}.sh"));
    let report = std::env::temp_dir().join(format!("secureflow-cli-changing-report-{suffix}.json"));
    let manifest =
        std::env::temp_dir().join(format!("secureflow-cli-changing-manifest-{suffix}.json"));
    let _ = std::fs::remove_dir_all(&root);
    for path in [&engine, &report, &manifest] {
        let _ = std::fs::remove_file(path);
    }
    std::fs::create_dir(&root).expect("temporary target should be created");
    std::fs::write(root.join("source.ts"), "export const value = 1;\n")
        .expect("temporary target should be writable");
    std::fs::write(
        &engine,
        "#!/bin/sh\nfor target do :; done\nprintf '\\n// changed during scan\\n' >> \"$target/source.ts\"\nprintf '%s\\n' '{\"schema_version\":\"secure-json-v1\",\"findings\":[]}'\n",
    )
    .expect("temporary engine should be writable");
    let mut permissions = std::fs::metadata(&engine)
        .expect("temporary engine metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&engine, permissions).expect("temporary engine should be executable");

    let output = Command::new(binary())
        .arg("scan")
        .args(["--binary"])
        .arg(&engine)
        .arg(&root)
        .arg("--authorized")
        .args(["--authorization-reviewer", "test-runner"])
        .args(["--sandbox", "disabled"])
        .args(["--output"])
        .arg(&report)
        .args(["--manifest-output"])
        .arg(&manifest)
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("target changed"));
    assert!(!report.exists());
    assert!(!manifest.exists());

    std::fs::remove_dir_all(root).expect("temporary target should be removable");
    std::fs::remove_file(engine).expect("temporary engine should be removable");
}

#[cfg(unix)]
#[test]
fn scan_records_explicit_authorization_and_target_revision() {
    use std::os::unix::fs::PermissionsExt;

    let suffix = std::process::id();
    let root = std::env::temp_dir().join(format!("secureflow-cli-scoped-target-{suffix}"));
    let engine = std::env::temp_dir().join(format!("secureflow-cli-scoped-engine-{suffix}.sh"));
    let report = std::env::temp_dir().join(format!("secureflow-cli-scoped-report-{suffix}.json"));
    let manifest =
        std::env::temp_dir().join(format!("secureflow-cli-scoped-manifest-{suffix}.json"));
    let _ = std::fs::remove_dir_all(&root);
    for path in [&engine, &report, &manifest] {
        let _ = std::fs::remove_file(path);
    }
    std::fs::create_dir(&root).expect("temporary target should be created");
    std::fs::write(root.join("source.ts"), "export const value = 1;\n")
        .expect("temporary target should be writable");
    std::fs::write(
        &engine,
        "#!/bin/sh\nprintf '%s\\n' '{\"schema_version\":\"secure-json-v1\",\"engine_version\":\"test\",\"findings\":[]}'\n",
    )
    .expect("temporary engine should be writable");
    let mut permissions = std::fs::metadata(&engine)
        .expect("temporary engine metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&engine, permissions).expect("temporary engine should be executable");

    let revision = "0123456789abcdef0123456789abcdef01234567";
    let output = Command::new(binary())
        .arg("scan")
        .args(["--binary"])
        .arg(&engine)
        .arg(&root)
        .arg("--authorized")
        .args(["--authorization-reviewer", "Daniel"])
        .args(["--authorization-basis", "written-consent"])
        .args(["--authorization-reference", "scope-ticket-123"])
        .args(["--authorization-expires-at", "2099-01-01T00:00:00Z"])
        .args(["--target-revision-kind", "git"])
        .args(["--target-revision", revision])
        .args(["--output"])
        .arg(&report)
        .args(["--manifest-output"])
        .arg(&manifest)
        .output()
        .expect("CLI should start");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).expect("manifest should be readable"))
            .expect("manifest should be JSON");
    assert_eq!(value["target"]["authorization"]["reviewer"], "Daniel");
    assert_eq!(value["target"]["authorization"]["basis"], "written-consent");
    assert_eq!(
        value["target"]["authorization"]["reference"],
        "scope-ticket-123"
    );
    assert_eq!(value["target"]["revision"]["kind"], "git");
    assert_eq!(value["target"]["revision"]["value"], revision);
    assert_ne!(value["created_at"], value["completed_at"]);
    validate_with_schema("secureflow-run-v1.schema.json", &value);

    std::fs::remove_dir_all(root).expect("temporary target should be removable");
    for path in [&engine, &report, &manifest] {
        std::fs::remove_file(path).expect("temporary artifact should be removable");
    }
}

#[test]
fn documented_authorization_bases_require_a_reference() {
    let report = std::env::temp_dir().join(format!(
        "secureflow-cli-auth-reference-report-{}.json",
        std::process::id()
    ));
    let manifest = std::env::temp_dir().join(format!(
        "secureflow-cli-auth-reference-manifest-{}.json",
        std::process::id()
    ));
    for path in [&report, &manifest] {
        let _ = std::fs::remove_file(path);
    }
    let output = Command::new(binary())
        .arg("scan")
        .args(["--binary", "/bin/false"])
        .arg(fixture())
        .arg("--authorized")
        .args(["--authorization-reviewer", "test-runner"])
        .args(["--authorization-basis", "written-consent"])
        .args(["--output"])
        .arg(&report)
        .args(["--manifest-output"])
        .arg(&manifest)
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("reference is required"));
    assert!(!report.exists());
    assert!(!manifest.exists());
}

#[test]
fn expired_authorization_fails_before_engine_execution() {
    let report = std::env::temp_dir().join(format!(
        "secureflow-cli-expired-auth-report-{}.json",
        std::process::id()
    ));
    let manifest = std::env::temp_dir().join(format!(
        "secureflow-cli-expired-auth-manifest-{}.json",
        std::process::id()
    ));
    for path in [&report, &manifest] {
        let _ = std::fs::remove_file(path);
    }
    let output = Command::new(binary())
        .arg("scan")
        .args(["--binary", "/bin/false"])
        .arg(fixture())
        .arg("--authorized")
        .args(["--authorization-reviewer", "test-runner"])
        .args(["--authorization-expires-at", "2000-01-01T00:00:00Z"])
        .args(["--output"])
        .arg(&report)
        .args(["--manifest-output"])
        .arg(&manifest)
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("authorization expired"));
    assert!(!report.exists());
    assert!(!manifest.exists());
}

#[test]
fn invalid_timeout_fails_before_engine_execution() {
    let report = std::env::temp_dir().join(format!(
        "secureflow-cli-invalid-timeout-report-{}.json",
        std::process::id()
    ));
    let manifest = std::env::temp_dir().join(format!(
        "secureflow-cli-invalid-timeout-manifest-{}.json",
        std::process::id()
    ));
    for path in [&report, &manifest] {
        let _ = std::fs::remove_file(path);
    }
    let output = Command::new(binary())
        .arg("scan")
        .args(["--binary", "/bin/false"])
        .arg(fixture())
        .arg("--authorized")
        .args(["--authorization-reviewer", "test-runner"])
        .args(["--timeout-seconds", "0"])
        .args(["--output"])
        .arg(&report)
        .args(["--manifest-output"])
        .arg(&manifest)
        .output()
        .expect("CLI should start");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid timeout"));
    assert!(!report.exists());
    assert!(!manifest.exists());
}
