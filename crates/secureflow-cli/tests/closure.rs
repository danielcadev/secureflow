use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secureflow"))
        .args(args)
        .output()
        .unwrap()
}
fn passed(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=Closure Test",
            "-c",
            "user.email=closure@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn closure_checks_real_patch_inventory_evidence_and_candidate_semantics() {
    let root = std::env::temp_dir().join(format!(
        "secureflow-closure-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let _scratch = Scratch(root.clone());
    let repo = root.join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "--template="]);
    fs::create_dir(repo.join("src")).unwrap();
    fs::write(repo.join("src/auth.rs"), "before\n").unwrap();
    git(&repo, &["add", "src/auth.rs"]);
    git(&repo, &["commit", "-m", "fixture"]);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    fs::write(repo.join("src/auth.rs"), "after\n").unwrap();
    let evidence = root.join("evidence");
    fs::create_dir(&evidence).unwrap();
    fs::write(evidence.join("review.txt"), "fixture source review\n").unwrap();
    fs::write(evidence.join("test.txt"), "fixture regression evidence\n").unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/minimal-run-with-finding.json");
    let original = root.join("original.json");
    passed(cli(&[
        "case-create",
        "--run-manifest",
        fixture.to_str().unwrap(),
        "--output",
        original.to_str().unwrap(),
    ]));
    let case: Value = serde_json::from_slice(&fs::read(&original).unwrap()).unwrap();
    let id = case["candidates"][0]["candidate_id"].as_str().unwrap();
    let decided = root.join("decided.json");
    passed(cli(&[
        "case-decide",
        "--case",
        original.to_str().unwrap(),
        "--candidate-id",
        id,
        "--decision",
        "validated",
        "--reviewer",
        "fixture human",
        "--rationale",
        "Explicit synthetic disposition",
        "--output",
        decided.to_str().unwrap(),
    ]));
    let case_bytes = fs::read(&decided).unwrap();
    let case: Value = serde_json::from_slice(&case_bytes).unwrap();
    let draft = root.join("draft.json");
    let authorized = root.join("authorized.json");
    let hash = secureflow_case::digest;
    write_json(
        &draft,
        &json!({"contract_version": "secureflow-remediation-handoff-v1",
        "handoff_id": "sf_handoff_0000000000000000", "created_at": "2026-09-18T00:00:00Z", "status": "draft",
        "cases": [{"case_id": case["case_id"], "case_sha256": hash(&case_bytes),
            "target_root_sha256": case["target"]["root_sha256"], "revision": case["target"]["revision"], "candidate_ids": [id]}],
        "scope": {"allowed_paths": ["src"], "prohibited_actions": ["merge", "deploy"], "merge_authorized": false, "deploy_authorized": false}}),
    );
    passed(cli(&[
        "remediation-authorize",
        "--draft",
        draft.to_str().unwrap(),
        "--case",
        decided.to_str().unwrap(),
        "--reviewer",
        "fixture human",
        "--rationale",
        "Explicit synthetic authorization",
        "--output",
        authorized.to_str().unwrap(),
    ]));
    let source = json!({"path": "review.txt", "sha256": hash(&fs::read(evidence.join("review.txt")).unwrap()), "kind": "source_review"});
    let test = json!({"path": "test.txt", "sha256": hash(&fs::read(evidence.join("test.txt")).unwrap()), "kind": "regression_test"});
    let mut report = json!({"contract_version": "secureflow-remediation-closure-v1", "base_commit": head,
        "cases": [{"case_id": case["case_id"], "case_sha256": hash(&case_bytes), "outcomes": [{
            "candidate_id": id, "outcome": "fixed", "rationale": "Synthetic regression and source evidence",
            "evidence": [source, test.clone()], "changed_paths": ["src/auth.rs"]}]}],
        "files": [{"path": "src/auth.rs", "mode": "100644", "sha256": hash(&fs::read(repo.join("src/auth.rs")).unwrap())}],
        "checks": [{"name": "regression", "passed": true, "evidence": test}]});
    let report_path = root.join("closure.json");
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/secureflow-remediation-closure-v1.schema.json"
    ))
    .unwrap();
    jsonschema::validator_for(&schema)
        .unwrap()
        .validate(&report)
        .unwrap();
    write_json(&report_path, &report);
    let args = [
        "remediation-check",
        "--report",
        report_path.to_str().unwrap(),
        "--case",
        decided.to_str().unwrap(),
        "--handoff",
        authorized.to_str().unwrap(),
        "--repository",
        repo.to_str().unwrap(),
        "--evidence-root",
        evidence.to_str().unwrap(),
    ];
    let output = cli(&args);
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["ready_for_review"], true);
    passed(output);

    fs::write(repo.join("src/unrelated.rs"), "unrelated work\n").unwrap();
    let output = cli(&args);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("inventory"));
    fs::remove_file(repo.join("src/unrelated.rs")).unwrap();
    git(&repo, &["add", "src/auth.rs"]);
    passed(cli(&args)); // Staged and unstaged changes have the same exact inventory.

    fs::write(repo.join("src/auth.rs"), "changed after verification\n").unwrap();
    let output = cli(&args);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("patch content changed"));
    fs::write(repo.join("src/auth.rs"), "after\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::set_permissions(repo.join("src/auth.rs"), fs::Permissions::from_mode(0o755)).unwrap();
        let output = cli(&args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("mode changed"));
        fs::set_permissions(repo.join("src/auth.rs"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(repo.join("src/auth.rs")).unwrap();
        symlink(evidence.join("test.txt"), repo.join("src/auth.rs")).unwrap();
        let output = cli(&args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("regular files"));
        fs::remove_file(repo.join("src/auth.rs")).unwrap();
        fs::write(repo.join("src/auth.rs"), "after\n").unwrap();
    }

    fs::write(evidence.join("test.txt"), "substitution\n").unwrap();
    let output = cli(&args);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("evidence changed"));
    fs::write(evidence.join("test.txt"), "fixture regression evidence\n").unwrap();

    report["checks"][0]["passed"] = json!(false);
    write_json(&report_path, &report);
    let output = cli(&args);
    assert!(!output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["ready_for_review"],
        false
    );

    report["cases"][0]["outcomes"][0]["outcome"] = json!("no_change");
    report["cases"][0]["outcomes"][0]["changed_paths"] = json!([]);
    report["files"] = json!([]);
    write_json(&report_path, &report);
    let output = cli(&args);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no_change requires"));
    assert_eq!(
        fs::read(&decided).unwrap(),
        case_bytes,
        "verification never rewrites verdicts"
    );
}
