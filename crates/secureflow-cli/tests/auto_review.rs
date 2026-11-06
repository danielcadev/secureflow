//! Synthetic orchestration tests; fixtures do not execute application code.
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_secureflow")
}

struct Fixture {
    root: PathBuf,
    target: PathBuf,
    engine: PathBuf,
    plan: PathBuf,
    output: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "secureflow-auto-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let target = root.join("target-a");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("input.ts"), "export const synthetic = true;\n").unwrap();
        let instance = Self {
            engine: root.join("engine.sh"),
            plan: root.join("plan.json"),
            output: root.join("run"),
            root,
            target,
        };
        instance.engine_script("");
        instance
    }
    fn engine_script(&self, prefix: &str) {
        let mut report: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/codesupply-ready/engine-report.json"
        ))
        .unwrap();
        report["graph"] =
            json!({"scope":"full","nodes":[],"edges":[],"total_nodes":0,"total_edges":0});
        report["scan"] = json!({"complete":true});
        report["analysis"] = json!({"truncated":false});
        let script = format!(
            "#!/bin/sh\nset -eu\n{prefix}\nprintf '%s\\n' '{}'\n",
            serde_json::to_string(&report)
                .unwrap()
                .replace('\'', "'\\''")
        );
        fs::write(&self.engine, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.engine, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    fn prepare_command(&self) -> Command {
        let mut cmd = Command::new(binary());
        cmd.args(["review-plan", "--binary"])
            .arg(&self.engine)
            .arg("--target")
            .arg(&self.target)
            .args([
                "--authorization-reviewer",
                "Test operator",
                "--authorization-reference",
                "Synthetic local test only",
                "--timeout-seconds",
                "5",
                "--total-budget-seconds",
                "30",
                "--output-directory",
            ])
            .arg(&self.output)
            .arg("--plan-output")
            .arg(&self.plan);
        cmd
    }
    fn prepare(&self) -> String {
        let output = self.prepare_command().arg("--authorized").output().unwrap();
        assert_ok(&output);
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        result["plan_sha256"].as_str().unwrap().into()
    }
    fn execute(&self, hash: &str) -> Output {
        Command::new(binary())
            .arg("review-execute")
            .arg("--plan")
            .arg(&self.plan)
            .args(["--plan-sha256", hash])
            .output()
            .unwrap()
    }
    fn status(&self, hash: &str) -> Output {
        Command::new(binary())
            .arg("review-status")
            .arg("--directory")
            .arg(&self.output)
            .args(["--plan-sha256", hash])
            .output()
            .unwrap()
    }
    fn alter_plan(&self, edit: impl FnOnce(&mut Value)) -> String {
        let mut value: Value = serde_json::from_slice(&fs::read(&self.plan).unwrap()).unwrap();
        edit(&mut value);
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        fs::write(&self.plan, &bytes).unwrap();
        secureflow_case::digest(&bytes)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn assert_ok(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn schema(name: &str, value: &Value) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .join(name);
    let document: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    jsonschema::validator_for(&document)
        .unwrap()
        .validate(value)
        .unwrap();
}
fn failed(output: &Output, expected: &str) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sandbox() -> bool {
    let available = Command::new("/usr/bin/bwrap")
        .args([
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--clearenv",
            "--",
            "/bin/true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !available {
        assert!(
            std::env::var_os("SECUREFLOW_REQUIRE_SANDBOX_TESTS").is_none(),
            "required Bubblewrap test environment unavailable"
        );
        eprintln!(
            "Bubblewrap unavailable; positive runtime case not exercised (no isolation downgrade)"
        );
    }
    available
}

#[test]
fn plan_requires_authorization_and_preserves_inputs() {
    let f = Fixture::new();
    failed(&f.prepare_command().output().unwrap(), "authorization");
    assert!(!f.plan.exists());
    assert!(!f.output.exists());
    let before = fs::read(f.target.join("input.ts")).unwrap();
    let hash = f.prepare();
    assert_eq!(hash.len(), 64);
    schema(
        "secureflow-auto-review-plan-v1.schema.json",
        &serde_json::from_slice(&fs::read(&f.plan).unwrap()).unwrap(),
    );
    assert!(!f.output.exists());
    assert_eq!(before, fs::read(f.target.join("input.ts")).unwrap());
    failed(
        &f.prepare_command().arg("--authorized").output().unwrap(),
        "already exists",
    );
}

#[test]
fn target_and_binary_changes_fail_before_run_creation() {
    for mutate_binary in [false, true] {
        let f = Fixture::new();
        let hash = f.prepare();
        if mutate_binary {
            fs::write(&f.engine, "#!/bin/sh\nexit 0\n").unwrap();
        } else {
            fs::write(f.target.join("input.ts"), "changed").unwrap();
        }
        failed(&f.execute(&hash), "changed since authorization");
        assert!(!f.output.exists());
    }
}

#[test]
fn tampered_expired_or_expanded_plans_cannot_execute() {
    let f = Fixture::new();
    let original = f.prepare();
    let hash = f.alter_plan(|v| v["permissions"]["network"] = json!(true));
    failed(&f.execute(&original), "plan hash mismatch");
    failed(&f.execute(&hash), "permissions");
    let hash = f.alter_plan(|v| {
        v["permissions"]["network"] = json!(false);
        v["created_at"] = json!("2000-01-01T00:00:00Z");
        v["authorization"]["expires_at"] = json!("2000-01-01T01:00:00Z");
    });
    failed(&f.execute(&hash), "expired");
    assert!(!f.output.exists());
    let hash = f.alter_plan(|v| v["unexpected_authority"] = json!(true));
    failed(&f.execute(&hash), "unknown field");
}

#[test]
fn overlapping_targets_and_output_within_target_are_rejected() {
    let f = Fixture::new();
    let output = f
        .prepare_command()
        .arg("--authorized")
        .arg("--target")
        .arg(&f.target)
        .output()
        .unwrap();
    failed(&output, "overlapping");
    assert!(!f.plan.exists());
    // An explicit plan mutation also exercises the loader boundary.
    let hash = f.prepare();
    let bad = f.alter_plan(|v| v["output_directory"] = json!(f.target.join("nested")));
    assert_ne!(hash, bad);
    failed(&f.execute(&bad), "overlapping");
}

#[test]
fn identical_component_snapshots_are_rejected_before_panel_identity_collision() {
    let f = Fixture::new();
    let second = f.root.join("target-b");
    fs::create_dir(&second).unwrap();
    fs::copy(f.target.join("input.ts"), second.join("input.ts")).unwrap();
    let output = f
        .prepare_command()
        .arg("--authorized")
        .arg("--target")
        .arg(&second)
        .output()
        .unwrap();
    failed(&output, "duplicate case identity");
    assert!(!f.plan.exists());
    assert!(!f.output.exists());

    f.prepare();
    let hash = f.alter_plan(|plan| {
        let mut duplicate = plan["targets"][0].clone();
        duplicate["path"] = json!(second);
        plan["targets"].as_array_mut().unwrap().push(duplicate);
    });
    failed(&f.execute(&hash), "duplicate case identity");
    assert!(!f.output.exists());
}

#[test]
fn successful_bundle_has_pending_cases_and_rejects_replay_or_tampering() {
    if !sandbox() {
        return;
    }
    let f = Fixture::new();
    let hash = f.prepare();
    let output = f.execute(&hash);
    assert_ok(&output);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "ready-for-review");
    assert_eq!(value["human_decisions"], 0);
    assert_eq!(value["ai_calls"], 0);
    assert_eq!(value["contextual_investigation"], "not-performed-by-runner");
    assert_eq!(value["candidate_count"], 1);
    schema(
        "secureflow-auto-review-result-v1.schema.json",
        &serde_json::from_slice(&fs::read(f.output.join("result.json")).unwrap()).unwrap(),
    );
    let case_path = f.output.join("component-00/security-case.json");
    let original = fs::read(&case_path).unwrap();
    let case: Value = serde_json::from_slice(&original).unwrap();
    assert!(case["decisions"].as_array().unwrap().is_empty());
    assert!(
        case["staged_recommendations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_ok(&f.status(&hash));
    failed(&f.execute(&hash), "already exists");
    assert_eq!(original, fs::read(&case_path).unwrap());
    fs::write(&case_path, b"{}").unwrap();
    failed(&f.status(&hash), "artifact hash mismatch");
}

#[test]
fn a_failed_second_component_retains_first_but_is_not_ready() {
    if !sandbox() {
        return;
    }
    let f = Fixture::new();
    let second = f.root.join("target-b");
    fs::create_dir(&second).unwrap();
    fs::write(second.join("different.ts"), "fixture").unwrap();
    f.engine_script("for value do last=$value; done\ncase \"$last\" in */target-b) echo 'synthetic failure' >&2; exit 134;; esac");
    let prepared = f
        .prepare_command()
        .arg("--authorized")
        .arg("--target")
        .arg(second)
        .output()
        .unwrap();
    assert_ok(&prepared);
    let v: Value = serde_json::from_slice(&prepared.stdout).unwrap();
    let hash = v["plan_sha256"].as_str().unwrap();
    failed(&f.execute(hash), "134");
    let output = f.status(hash);
    assert_ok(&output);
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["status"], "failed");
    assert_eq!(v["ready_for_review"], false);
    assert_eq!(v["components_requested"], 2);
    assert_eq!(v["components_completed"], 1);
    assert!(!f.output.join("component-01/security-case.json").exists());
}

#[test]
fn malformed_or_truncated_engine_never_creates_a_case() {
    if !sandbox() {
        return;
    }
    for prefix in [
        "echo '{}' ; exit 0",
        "printf '%s\\n' '{\"schema_version\":\"secure-json-v1\",\"document_type\":\"scan-report\",\"engine_version\":\"test\",\"findings\":[],\"analysis\":{\"truncated\":true},\"graph\":{\"scope\":\"full\",\"nodes\":[],\"edges\":[],\"total_nodes\":0,\"total_edges\":0}}'; exit 0",
    ] {
        let f = Fixture::new();
        f.engine_script(prefix);
        let hash = f.prepare();
        assert!(!f.execute(&hash).status.success());
        assert!(!f.output.join("component-00/security-case.json").exists());
        let output = f.status(&hash);
        assert_ok(&output);
        let v: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(v["status"], "failed");
        assert_eq!(v["components_completed"], 0);
    }
}

#[test]
fn interrupted_directory_is_never_reported_as_ready() {
    let f = Fixture::new();
    let hash = f.prepare();
    fs::create_dir(&f.output).unwrap();
    fs::copy(&f.plan, f.output.join("plan.json")).unwrap();
    let output = f.status(&hash);
    assert_ok(&output);
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["status"], "incomplete-or-running");
    assert_eq!(v["ready_for_review"], false);
}

fn mcp(plan: Option<(&Path, &str)>, requests: &[Value]) -> Vec<Value> {
    let mut command = Command::new(binary());
    command.arg("mcp");
    if let Some((path, hash)) = plan {
        command
            .arg("--review-plan")
            .arg(path)
            .args(["--review-plan-sha256", hash]);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for request in requests {
        writeln!(child.stdin.as_mut().unwrap(), "{request}").unwrap();
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert_ok(&output);
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("stdout must contain only JSON-RPC"))
        .collect()
}

#[test]
fn default_mcp_cannot_start_runs_and_grants_reject_scope_overrides() {
    let f = Fixture::new();
    let hash = f.prepare();
    let requests = [
        json!({"id":1,"jsonrpc":"2.0","method":"tools/list"}),
        json!({"id":2,"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_authorized_review","arguments":{}}}),
    ];
    let responses = mcp(None, &requests);
    assert_eq!(responses[0]["result"]["tools"].as_array().unwrap().len(), 5);
    assert!(
        responses[1]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("disabled")
    );
    let requests = [
        requests[0].clone(),
        json!({"id":2,"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_authorized_review","arguments":{"target":"/","sandbox":"disabled"}}}),
    ];
    let responses = mcp(Some((&f.plan, &hash)), &requests);
    assert_eq!(responses[0]["result"]["tools"].as_array().unwrap().len(), 8);
    assert!(
        responses[1]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot override")
    );
    assert!(!f.output.exists());
}

#[test]
fn authorized_mcp_runs_and_inspects_exact_source_sink_evidence() {
    if !sandbox() {
        return;
    }
    let f = Fixture::new();
    let hash = f.prepare();
    let run = json!({"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_authorized_review","arguments":{}}});
    let responses = mcp(Some((&f.plan, &hash)), &[run]);
    let summary: Value = serde_json::from_str(
        responses[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(summary["status"], "ready-for-review");
    let case: Value = serde_json::from_slice(
        &fs::read(f.output.join("component-00/security-case.json")).unwrap(),
    )
    .unwrap();
    let request = json!({"id":2,"jsonrpc":"2.0","method":"tools/call","params":{"name":"investigate_review_candidate","arguments":{"component":0,"candidate_id":case["candidates"][0]["candidate_id"]}}});
    let responses = mcp(Some((&f.plan, &hash)), &[request]);
    let item: Value = serde_json::from_str(
        responses[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(item["finding"]["rule_id"], "SYNTHETIC-001");
    assert_eq!(item["finding"]["human_review"]["decision"], "pending");
    assert!(item["finding"]["source_location"].is_object());
    assert_eq!(item["final_authority"], "human-only");
}

#[test]
fn process_timeout_records_failure_and_never_retries_without_sandbox() {
    if !sandbox() {
        return;
    }
    let f = Fixture::new();
    f.engine_script("sleep 3");
    f.prepare();
    let hash = f.alter_plan(|value| value["timeout_seconds"] = json!(1));
    let output = f.execute(&hash);
    assert!(!output.status.success());
    let status = f.status(&hash);
    assert_ok(&status);
    let value: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["components_completed"], 0);
    assert!(!f.output.join("component-00/security-case.json").exists());
}

#[cfg(unix)]
#[test]
fn redirected_inputs_and_receipt_artifacts_are_rejected() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let hash = f.prepare();
    let replacement = f.root.join("replacement");
    fs::rename(&f.target, &replacement).unwrap();
    symlink(&replacement, &f.target).unwrap();
    failed(&f.execute(&hash), "symlink");
    assert!(!f.output.exists());
    if !sandbox() {
        return;
    }
    let f = Fixture::new();
    let hash = f.prepare();
    assert_ok(&f.execute(&hash));
    let original = f.output.join("component-00/security-case.json");
    let moved = f.root.join("copied-case.json");
    fs::rename(&original, &moved).unwrap();
    symlink(&moved, &original).unwrap();
    failed(&f.status(&hash), "symlink");
}

#[test]
fn all_explicit_components_produce_separate_undecided_cases() {
    if !sandbox() {
        return;
    }
    let f = Fixture::new();
    let second = f.root.join("target-b");
    fs::create_dir(&second).unwrap();
    fs::write(second.join("other.ts"), "fixture-b").unwrap();
    let prepared = f
        .prepare_command()
        .arg("--authorized")
        .arg("--target")
        .arg(&second)
        .output()
        .unwrap();
    assert_ok(&prepared);
    let prepared: Value = serde_json::from_slice(&prepared.stdout).unwrap();
    let output = f.execute(prepared["plan_sha256"].as_str().unwrap());
    assert_ok(&output);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["components_completed"], 2);
    assert_eq!(result["candidate_count"], 2);
    assert_eq!(result["human_decisions"], 0);
    assert!(f.output.join("component-00/security-case.json").is_file());
    assert!(f.output.join("component-01/security-case.json").is_file());
}

#[test]
fn mcp_operational_failure_is_a_tool_error_and_preserves_inspectable_status() {
    if !sandbox() {
        return;
    }
    let f = Fixture::new();
    f.engine_script("exit 134");
    let hash = f.prepare();
    let requests = [
        json!({"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_authorized_review","arguments":{}}}),
        json!({"id":2,"jsonrpc":"2.0","method":"tools/call","params":{"name":"authorized_review_status","arguments":{}}}),
    ];
    let responses = mcp(Some((&f.plan, &hash)), &requests);
    assert_eq!(responses[0]["result"]["isError"], true);
    assert!(responses[0].get("error").is_none());
    let status: Value = serde_json::from_str(
        responses[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status["status"], "failed");
}

#[test]
fn historical_status_survives_but_live_investigation_rejects_target_drift() {
    if !sandbox() {
        return;
    }
    let f = Fixture::new();
    let hash = f.prepare();
    assert_ok(&f.execute(&hash));
    let case: Value = serde_json::from_slice(
        &fs::read(f.output.join("component-00/security-case.json")).unwrap(),
    )
    .unwrap();
    fs::write(f.target.join("input.ts"), "new source revision").unwrap();
    assert_ok(&f.status(&hash));
    let request = json!({"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"name":"investigate_review_candidate","arguments":{"component":0,"candidate_id":case["candidates"][0]["candidate_id"]}}});
    let response = mcp(Some((&f.plan, &hash)), &[request]);
    assert_eq!(response[0]["result"]["isError"], true);
    assert!(
        response[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("live target changed")
    );
}
