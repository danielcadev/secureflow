use std::{fs, path::PathBuf, process::Command};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn trusted_cli_schemas_and_required_flags() {
    let binary = env!("CARGO_BIN_EXE_secureflow");
    for kind in ["target", "trust-policy", "trust-state", "trust-receipt"] {
        let output = Command::new(binary)
            .arg(format!("catalog-{kind}-schema"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let expected: serde_json::Value = serde_json::from_slice(
            &fs::read(root().join(format!("schemas/secureflow-catalog-{kind}-v1.schema.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(actual, expected);
    }
    for command in [
        "catalog-trust-init",
        "catalog-trusted-install",
        "catalog-trusted-inspect",
    ] {
        let output = Command::new(binary).arg(command).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    let output = Command::new(binary)
        .args([
            "catalog-trust-import",
            "--trust-store",
            "/secureflow-absent-trust-fixture",
            "--metadata-dir",
            "/secureflow-absent-metadata",
            "--publisher",
            "synthetic",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["acceptance"], "rejected");
    assert_eq!(error["validation_authority"], "human-only");
    assert!(error["error_code"].as_str().unwrap().starts_with("TRUST_"));
}

#[test]
#[cfg(target_os = "linux")]
fn trusted_cli_hermetic_lifecycle_and_evidence_tampering() {
    let binary = env!("CARGO_BIN_EXE_secureflow");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let output = std::env::temp_dir().join(format!(
        "secureflow-trusted-cli-{}-{nonce}",
        std::process::id()
    ));
    let result = Command::new("python3")
        .arg(root().join("scripts/demo-trusted-catalog.py"))
        .arg("--binary")
        .arg(binary)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "retained at {}: {}",
        output.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    let verify = || {
        Command::new("python3")
            .arg(root().join("scripts/verify-trusted-catalog-demo.py"))
            .arg("--binary")
            .arg(binary)
            .arg("--demo")
            .arg(&output)
            .output()
            .unwrap()
    };
    let result = verify();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let receipt_path = output.join("demo-receipt.json");
    let original = fs::read(&receipt_path).unwrap();
    for field in [
        "binary_sha256",
        "fixture_manifest_sha256",
        "engine_invocations",
    ] {
        let mut receipt: serde_json::Value = serde_json::from_slice(&original).unwrap();
        receipt[field] = if field == "engine_invocations" {
            1.into()
        } else {
            "0".repeat(64).into()
        };
        fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(!verify().status.success(), "must reject altered {field}");
    }
    fs::write(&receipt_path, original).unwrap();
    fs::write(output.join("current.sqlite3"), b"substituted bytes").unwrap();
    assert!(!verify().status.success());
    fs::remove_dir_all(output).unwrap();
}
