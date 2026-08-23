//! Safe process boundary for an explicitly supplied Secure Engine binary.
//!
//! This first slice avoids a shell, clears the child environment, bounds the
//! direct process duration, retained output and Linux resources. On Unix the
//! child receives a dedicated process group so timeout cleanup includes its
//! descendants. Linux callers can require Bubblewrap for a read-only host
//! filesystem and a private network namespace; failure to start then fails
//! closed rather than silently falling back.

use secureflow_model::{
    AiValidation, Confidence, EvidenceKind, EvidenceStep, Finding, HumanDecision, HumanReview,
    Location, Severity, TaxonomyCoordinates,
};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const SECURE_JSON_SCHEMA: &str = "secure-json-v1";
pub const TARGET_FINGERPRINT_SCHEME: &str = "secureflow-target-sha256-v2";
pub const DEFAULT_MAX_TARGET_FILES: u64 = 250_000;
pub const DEFAULT_MAX_TARGET_ENTRIES: u64 = 500_000;
pub const DEFAULT_MAX_TARGET_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_TARGET_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_TARGET_DEPTH: usize = 256;
pub const MAX_ENGINE_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ENGINE_TIMEOUT_SECONDS: u64 = 3600;
#[cfg(target_os = "linux")]
pub const BUBBLEWRAP_PATH: &str = "/usr/bin/bwrap";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxMode {
    Disabled,
    RequiredLinuxBubblewrap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetHashLimits {
    pub max_files: u64,
    pub max_entries: u64,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_depth: usize,
}

impl Default for TargetHashLimits {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_TARGET_FILES,
            max_entries: DEFAULT_MAX_TARGET_ENTRIES,
            max_total_bytes: DEFAULT_MAX_TARGET_BYTES,
            max_file_bytes: DEFAULT_MAX_TARGET_FILE_BYTES,
            max_depth: DEFAULT_MAX_TARGET_DEPTH,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub binary: PathBuf,
    pub target: PathBuf,
    pub arguments: Vec<String>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub max_memory_bytes: u64,
    pub max_cpu_seconds: u64,
    pub max_open_files: u64,
    pub sandbox: SandboxMode,
}

impl EngineConfig {
    pub fn default_scan(binary: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            target: target.into(),
            arguments: vec![
                "scan".into(),
                "--format".into(),
                SECURE_JSON_SCHEMA.into(),
                "--no-cache".into(),
                "--quiet".into(),
            ],
            timeout: Duration::from_secs(120),
            max_output_bytes: 32 * 1024 * 1024,
            max_memory_bytes: 2 * 1024 * 1024 * 1024,
            max_cpu_seconds: 121,
            max_open_files: 256,
            sandbox: SandboxMode::Disabled,
        }
    }

    pub fn configuration_sha256(&self) -> String {
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "secureflow-engine-config-v1");
        for argument in &self.arguments {
            hash_field(&mut hasher, argument);
        }
        hash_field(&mut hasher, &self.timeout.as_millis().to_string());
        hash_field(&mut hasher, &self.max_output_bytes.to_string());
        hash_field(&mut hasher, &self.max_memory_bytes.to_string());
        hash_field(&mut hasher, &self.max_cpu_seconds.to_string());
        hash_field(&mut hasher, &self.max_open_files.to_string());
        hash_field(
            &mut hasher,
            match self.sandbox {
                SandboxMode::Disabled => "sandbox-disabled",
                SandboxMode::RequiredLinuxBubblewrap => "sandbox-required-linux-bubblewrap-v1",
            },
        );
        hex_digest(hasher.finalize().as_slice())
    }
}

#[derive(Debug)]
pub struct EngineOutput {
    pub status: ExitStatus,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub binary_sha256: String,
    pub argv: Vec<String>,
    pub sandboxed: bool,
    pub sandbox_binary_sha256: Option<String>,
}

impl EngineOutput {
    pub fn report_json(&self) -> Result<serde_json::Value, AdapterError> {
        if self.timed_out {
            return Err(AdapterError::TimedOut);
        }
        if !matches!(self.status.code(), Some(0 | 1)) || self.stdout.is_empty() {
            return Err(AdapterError::ProcessFailed(self.status.to_string()));
        }
        validate_secure_json_report(&self.stdout)
    }

    pub fn report_sha256(&self) -> String {
        sha256_bytes(&self.stdout)
    }
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("could not hash engine binary: {0}")]
    BinaryHash(#[source] io::Error),
    #[error("engine binary is not a regular file: {0}")]
    BinaryNotRegular(PathBuf),
    #[error("engine binary size is outside limits: {bytes} bytes (maximum {maximum})")]
    BinarySize { bytes: u64, maximum: u64 },
    #[error("engine binary changed while the scan was running")]
    BinaryChangedDuringRun,
    #[error("could not start engine: {0}")]
    Spawn(#[source] io::Error),
    #[error("engine configuration is invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("engine process failed: {0}")]
    ProcessFailed(String),
    #[error("engine process timed out")]
    TimedOut,
    #[error("engine output exceeded configured limit")]
    OutputLimit,
    #[error("engine output reader failed: {0}")]
    OutputRead(#[source] io::Error),
    #[error("engine output reader panicked")]
    OutputReaderPanicked,
    #[error("engine report is not valid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("engine report does not declare secure-json-v1")]
    WrongSchema,
    #[error("required Linux Bubblewrap sandbox is unavailable: {0}")]
    SandboxUnavailable(String),
    #[error("invalid finding at index {index}: {message}")]
    InvalidFinding { index: usize, message: String },
}

pub fn run(config: &EngineConfig) -> Result<EngineOutput, AdapterError> {
    validate_config(config)?;
    let resolved_binary = resolve_engine_binary(&config.binary)?;
    let binary_sha256 = hash_engine_binary(&resolved_binary)?;
    let mut argv = config.arguments.clone();
    argv.push(config.target.display().to_string());

    let (mut command, sandbox_binary_sha256) = command_for(config, &resolved_binary, &argv)?;
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_isolation(&mut command, config);
    let mut child = command.spawn().map_err(AdapterError::Spawn)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(AdapterError::OutputReaderPanicked)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(AdapterError::OutputReaderPanicked)?;
    let max_output = config.max_output_bytes;
    let stdout_thread = thread::spawn(move || read_bounded(stdout, max_output));
    let stderr_thread = thread::spawn(move || read_bounded(stderr, max_output));

    let deadline =
        Instant::now()
            .checked_add(config.timeout)
            .ok_or(AdapterError::InvalidConfig(
                "timeout exceeds platform limits",
            ))?;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(AdapterError::Spawn)? {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break terminate_process_tree(&mut child).map_err(AdapterError::Spawn)?;
        }
        thread::sleep(Duration::from_millis(10));
    };

    let stdout = join_output(stdout_thread)?;
    let stderr = join_output(stderr_thread)?;
    let completed_binary_sha256 = hash_engine_binary(&resolved_binary)?;
    if completed_binary_sha256 != binary_sha256 {
        return Err(AdapterError::BinaryChangedDuringRun);
    }
    if stdout.len() > max_output || stderr.len() > max_output {
        return Err(AdapterError::OutputLimit);
    }

    Ok(EngineOutput {
        status,
        timed_out,
        stdout,
        stderr,
        binary_sha256,
        argv,
        sandboxed: config.sandbox == SandboxMode::RequiredLinuxBubblewrap,
        sandbox_binary_sha256,
    })
}

fn command_for(
    config: &EngineConfig,
    resolved_binary: &Path,
    argv: &[String],
) -> Result<(Command, Option<String>), AdapterError> {
    match config.sandbox {
        SandboxMode::Disabled => {
            let mut command = Command::new(resolved_binary);
            command.args(argv);
            Ok((command, None))
        }
        SandboxMode::RequiredLinuxBubblewrap => {
            #[cfg(target_os = "linux")]
            {
                let sandbox = Path::new(BUBBLEWRAP_PATH);
                let sandbox_sha256 = hash_engine_binary(sandbox)
                    .map_err(|error| AdapterError::SandboxUnavailable(error.to_string()))?;
                let mut command = Command::new(sandbox);
                command.args([
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
                ]);
                command.arg(resolved_binary).args(argv);
                Ok((command, Some(sandbox_sha256)))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (resolved_binary, argv);
                Err(AdapterError::SandboxUnavailable(
                    "Bubblewrap sandbox is supported only on Linux".into(),
                ))
            }
        }
    }
}

fn resolve_engine_binary(path: &Path) -> Result<PathBuf, AdapterError> {
    let resolved = std::fs::canonicalize(path).map_err(AdapterError::BinaryHash)?;
    validate_engine_binary(&resolved)?;
    Ok(resolved)
}

fn validate_engine_binary(path: &Path) -> Result<std::fs::Metadata, AdapterError> {
    let metadata = std::fs::symlink_metadata(path).map_err(AdapterError::BinaryHash)?;
    if !metadata.is_file() {
        return Err(AdapterError::BinaryNotRegular(path.to_path_buf()));
    }
    if metadata.len() == 0 || metadata.len() > MAX_ENGINE_BINARY_BYTES {
        return Err(AdapterError::BinarySize {
            bytes: metadata.len(),
            maximum: MAX_ENGINE_BINARY_BYTES,
        });
    }
    Ok(metadata)
}

fn hash_engine_binary(path: &Path) -> Result<String, AdapterError> {
    let metadata = validate_engine_binary(path)?;
    let mut hasher = Sha256::new();
    hash_target_file(&mut hasher, path, metadata.len()).map_err(AdapterError::BinaryHash)?;
    Ok(hex_digest(hasher.finalize().as_slice()))
}

fn validate_config(config: &EngineConfig) -> Result<(), AdapterError> {
    if config.timeout.is_zero() {
        return Err(AdapterError::InvalidConfig("timeout must be positive"));
    }
    if config.timeout > Duration::from_secs(MAX_ENGINE_TIMEOUT_SECONDS) {
        return Err(AdapterError::InvalidConfig("timeout exceeds one hour"));
    }
    if config.target.to_str().is_none() {
        return Err(AdapterError::InvalidConfig(
            "target path must be valid UTF-8",
        ));
    }
    if config.max_output_bytes == 0 {
        return Err(AdapterError::InvalidConfig(
            "max_output_bytes must be positive",
        ));
    }
    if config.max_memory_bytes < 64 * 1024 * 1024 {
        return Err(AdapterError::InvalidConfig(
            "max_memory_bytes must be at least 64 MiB",
        ));
    }
    if config.max_cpu_seconds == 0 {
        return Err(AdapterError::InvalidConfig(
            "max_cpu_seconds must be positive",
        ));
    }
    if config.max_open_files < 16 {
        return Err(AdapterError::InvalidConfig(
            "max_open_files must be at least 16",
        ));
    }
    Ok(())
}

fn configure_isolation(command: &mut Command, config: &EngineConfig) {
    #[cfg(unix)]
    command.process_group(0);

    #[cfg(target_os = "linux")]
    {
        let memory = config.max_memory_bytes;
        let cpu = config.max_cpu_seconds;
        let open_files = config.max_open_files;
        // SAFETY: pre_exec is restricted to async-signal-safe setrlimit calls.
        // Captured values are plain integers and no allocation occurs in the
        // child closure before exec.
        unsafe {
            command.pre_exec(move || {
                set_limit(libc::RLIMIT_AS, memory)?;
                set_limit(libc::RLIMIT_CPU, cpu)?;
                set_limit(libc::RLIMIT_NOFILE, open_files)?;
                set_limit(libc::RLIMIT_CORE, 0)?;
                Ok(())
            });
        }
    }
}

#[cfg(target_os = "linux")]
fn set_limit(resource: libc::__rlimit_resource_t, value: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: `limit` is initialized and `resource` is selected from fixed
    // RLIMIT constants in configure_isolation.
    if unsafe { libc::setrlimit(resource, &limit) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn terminate_process_tree(child: &mut Child) -> io::Result<ExitStatus> {
    let pid = i32::try_from(child.id())
        .map_err(|_| io::Error::other("child pid is outside the supported range"))?;
    // SAFETY: the child was placed in a dedicated process group whose ID is
    // its PID before exec. A negative PID targets only that group.
    let killed = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if killed != 0 {
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::ESRCH) {
            child.kill()?;
        }
    }
    child.wait()
}

#[cfg(not(unix))]
fn terminate_process_tree(child: &mut Child) -> io::Result<ExitStatus> {
    child.kill()?;
    child.wait()
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    Ok(hex_digest(&digest))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex_digest(&digest)
}

pub fn sha256_target(path: &Path) -> io::Result<String> {
    sha256_target_with_limits(path, TargetHashLimits::default())
}

pub fn sha256_target_with_limits(path: &Path, limits: TargetHashLimits) -> io::Result<String> {
    if limits.max_files == 0
        || limits.max_entries == 0
        || limits.max_total_bytes == 0
        || limits.max_file_bytes == 0
        || limits.max_depth == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target fingerprint limits must be positive",
        ));
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target symlinks are not accepted",
        ));
    }
    if metadata.is_file() {
        validate_target_file_size(metadata.len(), limits, 0)?;
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, TARGET_FINGERPRINT_SCHEME);
        hash_field(&mut hasher, "file");
        hasher.update(metadata.len().to_be_bytes());
        hash_target_file(&mut hasher, path, metadata.len())?;
        return Ok(hex_digest(hasher.finalize().as_slice()));
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target must be a regular file or directory",
        ));
    }

    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    let mut visited_entries = 0_u64;
    collect_regular_files(
        path,
        path,
        0,
        limits,
        &mut visited_entries,
        &mut total_bytes,
        &mut files,
    )?;
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let mut hasher = Sha256::new();
    hash_field(&mut hasher, TARGET_FINGERPRINT_SCHEME);
    hash_field(&mut hasher, "directory");
    hasher.update((files.len() as u64).to_be_bytes());
    hasher.update(total_bytes.to_be_bytes());
    for (relative, file, expected_bytes) in files {
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(expected_bytes.to_be_bytes());
        hash_target_file(&mut hasher, &file, expected_bytes)?;
    }
    Ok(hex_digest(hasher.finalize().as_slice()))
}

fn hash_target_file(hasher: &mut Sha256, path: &Path, expected_bytes: u64) -> io::Result<()> {
    let mut input = std::fs::File::open(path)?;
    let mut buffer = [0_u8; 8192];
    let mut actual_bytes = 0_u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        actual_bytes = actual_bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target size overflow"))?;
        if actual_bytes > expected_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("target file grew while hashing: {}", path.display()),
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if actual_bytes != expected_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("target file changed size while hashing: {}", path.display()),
        ));
    }
    Ok(())
}

fn validate_target_file_size(
    file_bytes: u64,
    limits: TargetHashLimits,
    accumulated_bytes: u64,
) -> io::Result<u64> {
    if file_bytes > limits.max_file_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "target file exceeds fingerprint limit: {file_bytes} bytes (maximum {})",
                limits.max_file_bytes
            ),
        ));
    }
    let total = accumulated_bytes
        .checked_add(file_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target size overflow"))?;
    if total > limits.max_total_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "target exceeds fingerprint limit: {total} bytes (maximum {})",
                limits.max_total_bytes
            ),
        ));
    }
    Ok(total)
}

pub fn project_findings(report: &serde_json::Value) -> Result<Vec<Finding>, AdapterError> {
    let findings = report
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid_finding(0, "report findings must be an array"))?;
    findings
        .iter()
        .enumerate()
        .map(|(index, finding)| project_finding(index, finding))
        .collect()
}

fn project_finding(index: usize, value: &serde_json::Value) -> Result<Finding, AdapterError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_finding(index, "finding must be an object"))?;
    let title = required_string(object, "title", index)?;
    let rule_id = required_string(object, "rule_id", index)?;
    let invariant = required_string(object, "invariant", index)?;
    let source_location = project_location(object.get("source"), index, "source")?;
    let sink_location = project_location(object.get("sink"), index, "sink")?;
    let engine_id = object
        .get("fingerprint")
        .or_else(|| object.get("finding_id"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_finding(index, "finding needs fingerprint or finding_id"))?;
    let evidence_path = project_evidence_path(object.get("evidence_path"), index)?;
    let taxonomy = project_taxonomy(object.get("taxonomy"), index)?;

    Ok(Finding {
        finding_id: format!("sf_finding_{engine_id}"),
        engine_fingerprint: Some(engine_id.into()),
        title: title.into(),
        rule_id: rule_id.into(),
        taxonomy,
        severity: Some(parse_severity(object.get("severity"))),
        confidence: parse_confidence(object.get("confidence")),
        source_location,
        sink_location,
        invariant: invariant.into(),
        evidence_path,
        limitations: string_array(object.get("limitations"), index, "limitations")?,
        human_review: HumanReview {
            decision: HumanDecision::Pending,
            reviewer: None,
            reviewed_at: None,
            rationale: None,
            evidence_reference: None,
        },
        ai_validation: AiValidation {
            status: secureflow_model::AiValidationStatus::NotRequested,
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
    })
}

fn project_taxonomy(
    value: Option<&serde_json::Value>,
    index: usize,
) -> Result<Option<TaxonomyCoordinates>, AdapterError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid_finding(index, "taxonomy must be an object"))?;
    Ok(Some(TaxonomyCoordinates {
        version: required_string(object, "taxonomy_version", index)?.into(),
        category_id: required_string(object, "category_id", index)?.into(),
        invariant_id: required_string(object, "invariant_id", index)?.into(),
    }))
}

fn project_location(
    value: Option<&serde_json::Value>,
    index: usize,
    field: &str,
) -> Result<Location, AdapterError> {
    let object = value
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_finding(index, format!("{field} must be an object")))?;
    let path = required_string(object, "path", index)?;
    let span = object
        .get("span")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_finding(index, format!("{field}.span must be an object")))?;
    Ok(Location {
        path: path.into(),
        start_line: number(span, "start_line", index)?,
        start_column: number(span, "start_column", index)?,
        end_line: Some(number(span, "end_line", index)?),
        end_column: Some(number(span, "end_column", index)?),
    })
}

fn project_evidence_path(
    value: Option<&serde_json::Value>,
    index: usize,
) -> Result<Vec<EvidenceStep>, AdapterError> {
    let values = value
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid_finding(index, "evidence_path must be an array"))?;
    if values.is_empty() {
        return Err(invalid_finding(index, "evidence_path cannot be empty"));
    }
    values
        .iter()
        .map(|step| {
            let object = step
                .as_object()
                .ok_or_else(|| invalid_finding(index, "evidence step must be an object"))?;
            let location = project_location(object.get("location"), index, "evidence location")?;
            let kind = object
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .map(parse_evidence_kind)
                .unwrap_or(EvidenceKind::Unknown);
            Ok(EvidenceStep {
                kind,
                location,
                description: format!("Secure Engine {kind:?} evidence"),
            })
        })
        .collect()
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    index: usize,
) -> Result<&'a str, AdapterError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_finding(index, format!("{key} must be a non-empty string")))
}

fn number(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    index: usize,
) -> Result<u32, AdapterError> {
    let value = object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid_finding(index, format!("{key} must be an integer")))?;
    u32::try_from(value).map_err(|_| invalid_finding(index, format!("{key} is too large")))
}

fn string_array(
    value: Option<&serde_json::Value>,
    index: usize,
    field: &str,
) -> Result<Vec<String>, AdapterError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| invalid_finding(index, format!("{field} must be an array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid_finding(index, format!("{field} must contain strings")))
        })
        .collect()
}

fn parse_severity(value: Option<&serde_json::Value>) -> Severity {
    match value.and_then(serde_json::Value::as_str) {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn parse_confidence(value: Option<&serde_json::Value>) -> Confidence {
    match value.and_then(serde_json::Value::as_str) {
        Some("high") => Confidence::High,
        Some("medium") => Confidence::Medium,
        Some("low") => Confidence::Low,
        _ => Confidence::Unknown,
    }
}

fn parse_evidence_kind(value: &str) -> EvidenceKind {
    match value {
        "source" => EvidenceKind::Source,
        "transform" => EvidenceKind::Transform,
        "guard" => EvidenceKind::Guard,
        "sanitizer" => EvidenceKind::Sanitizer,
        "authorization" => EvidenceKind::Authorization,
        "sink" => EvidenceKind::Sink,
        "barrier" => EvidenceKind::Barrier,
        _ => EvidenceKind::Unknown,
    }
}

fn invalid_finding(index: usize, message: impl Into<String>) -> AdapterError {
    AdapterError::InvalidFinding {
        index,
        message: message.into(),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn collect_regular_files(
    root: &Path,
    current: &Path,
    depth: usize,
    limits: TargetHashLimits,
    visited_entries: &mut u64,
    total_bytes: &mut u64,
    files: &mut Vec<(String, PathBuf, u64)>,
) -> io::Result<()> {
    if depth > limits.max_depth {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "target directory depth exceeds fingerprint limit: {depth} (maximum {})",
                limits.max_depth
            ),
        ));
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        *visited_entries = visited_entries
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target entry overflow"))?;
        if *visited_entries > limits.max_entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "target entry count exceeds fingerprint limit: maximum {}",
                    limits.max_entries
                ),
            ));
        }
        entries.push(entry);
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("symlink found in target: {}", path.display()),
            ));
        }
        if metadata.is_dir() {
            collect_regular_files(
                root,
                &path,
                depth.saturating_add(1),
                limits,
                visited_entries,
                total_bytes,
                files,
            )?;
        } else if metadata.is_file() {
            if files.len() as u64 >= limits.max_files {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "target file count exceeds fingerprint limit: maximum {}",
                        limits.max_files
                    ),
                ));
            }
            *total_bytes = validate_target_file_size(metadata.len(), limits, *total_bytes)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "target path escaped root")
                })?
                .to_str()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("target path is not valid UTF-8: {}", path.display()),
                    )
                })?
                .replace(std::path::MAIN_SEPARATOR, "/");
            files.push((relative, path, metadata.len()));
        }
    }
    Ok(())
}

pub fn validate_secure_json_report(bytes: &[u8]) -> Result<serde_json::Value, AdapterError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(AdapterError::InvalidJson)?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        != Some(SECURE_JSON_SCHEMA)
    {
        return Err(AdapterError::WrongSchema);
    }
    Ok(value)
}

fn read_bounded<R: Read>(mut reader: R, max_output: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > max_output {
            return Ok(vec![0; max_output.saturating_add(1)]);
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn join_output(handle: thread::JoinHandle<io::Result<Vec<u8>>>) -> Result<Vec<u8>, AdapterError> {
    handle
        .join()
        .map_err(|_| AdapterError::OutputReaderPanicked)?
        .map_err(AdapterError::OutputRead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_secure_json_v1() {
        let report = br#"{"schema_version":"secure-json-v1"}"#;
        assert!(validate_secure_json_report(report).is_ok());
        assert!(matches!(
            validate_secure_json_report(br#"{"schema_version":"sarif"}"#),
            Err(AdapterError::WrongSchema)
        ));
    }

    #[test]
    fn default_invocation_is_explicit_and_shell_free() {
        let config = EngineConfig::default_scan("/bin/secure", "/tmp/fixture");
        assert_eq!(
            config.arguments,
            [
                "scan",
                "--format",
                "secure-json-v1",
                "--no-cache",
                "--quiet"
            ]
        );
        assert_eq!(config.target, PathBuf::from("/tmp/fixture"));
        assert_eq!(config.max_memory_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(config.max_cpu_seconds, 121);
        assert_eq!(config.max_open_files, 256);
        assert_eq!(config.configuration_sha256().len(), 64);
    }

    #[test]
    fn configuration_hash_binds_resource_limits() {
        let first = EngineConfig::default_scan("/bin/secure", "/tmp/fixture");
        let mut second = first.clone();
        second.max_memory_bytes += 1;
        assert_ne!(first.configuration_sha256(), second.configuration_sha256());
        second = first.clone();
        second.sandbox = SandboxMode::RequiredLinuxBubblewrap;
        assert_ne!(first.configuration_sha256(), second.configuration_sha256());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn required_bubblewrap_is_read_only_and_uses_a_private_network_namespace() {
        let target = std::env::temp_dir().join(format!(
            "secureflow-sandbox-target-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("current time")
                .as_nanos()
        ));
        std::fs::create_dir(&target).expect("sandbox target");
        let parent_network_namespace = std::fs::read_link("/proc/self/ns/net")
            .expect("parent network namespace")
            .to_string_lossy()
            .into_owned();
        let mut config = EngineConfig::default_scan("/bin/sh", &target);
        config.arguments = vec![
            "-c".into(),
            "touch \"$0/sandbox-write\" 2>/dev/null; readlink /proc/self/ns/net >&2; printf '%s\\n' '{\"schema_version\":\"secure-json-v1\",\"findings\":[]}'".into(),
        ];
        config.sandbox = SandboxMode::RequiredLinuxBubblewrap;
        let output = run(&config).expect("sandboxed execution");
        output.report_json().expect("valid sandboxed report");
        assert!(output.sandboxed);
        assert!(output.sandbox_binary_sha256.is_some());
        assert!(!target.join("sandbox-write").exists());
        assert_ne!(
            String::from_utf8_lossy(&output.stderr).trim(),
            parent_network_namespace
        );
        std::fs::remove_dir(target).expect("sandbox target cleanup");
    }

    #[test]
    fn rejects_unbounded_timeout_and_engine_binary_size() {
        let mut config = EngineConfig::default_scan("/bin/secure", "/tmp/fixture");
        config.timeout = Duration::from_secs(MAX_ENGINE_TIMEOUT_SECONDS + 1);
        assert!(matches!(
            validate_config(&config),
            Err(AdapterError::InvalidConfig("timeout exceeds one hour"))
        ));

        let path = std::env::temp_dir().join(format!(
            "secureflow-oversized-engine-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let file = std::fs::File::create(&path).expect("temporary binary");
        file.set_len(MAX_ENGINE_BINARY_BYTES + 1)
            .expect("sparse oversized binary");
        drop(file);
        assert!(matches!(
            resolve_engine_binary(&path),
            Err(AdapterError::BinarySize { .. })
        ));
        std::fs::remove_file(path).expect("temporary binary should be removable");
    }

    #[test]
    fn rejects_a_directory_as_the_engine_binary() {
        let directory = std::env::current_dir().expect("current directory");
        assert!(matches!(
            resolve_engine_binary(&directory),
            Err(AdapterError::BinaryNotRegular(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_descendants_that_hold_output_pipes() {
        let mut config = EngineConfig::default_scan("/bin/sh", "/tmp/ignored");
        config.arguments = vec!["-c".into(), "sleep 30 & wait".into()];
        config.timeout = Duration::from_millis(50);
        config.max_cpu_seconds = 1;
        let started = Instant::now();
        let output = run(&config).expect("timeout should return a bounded result");
        assert!(output.timed_out);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "descendant kept an output pipe open after timeout"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_binary_that_changes_during_execution() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "secureflow-changing-engine-{}.sh",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf '\\n# changed during execution\\n' >> \"$0\"\nprintf '%s\\n' '{\"schema_version\":\"secure-json-v1\",\"findings\":[]}'\n",
        )
        .expect("temporary engine should be writable");
        let mut permissions = std::fs::metadata(&path)
            .expect("temporary engine metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions)
            .expect("temporary engine should be executable");

        let mut config = EngineConfig::default_scan(&path, "/tmp/ignored");
        config.timeout = Duration::from_secs(2);
        config.max_cpu_seconds = 2;
        assert!(matches!(
            run(&config),
            Err(AdapterError::BinaryChangedDuringRun)
        ));
        std::fs::remove_file(path).expect("temporary engine should be removable");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_operational_failure_even_when_stdout_contains_json() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "secureflow-failing-engine-{}.sh",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf '%s\\n' '{\"schema_version\":\"secure-json-v1\",\"findings\":[]}'\nexit 2\n",
        )
        .expect("temporary engine should be writable");
        let mut permissions = std::fs::metadata(&path)
            .expect("temporary engine metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions)
            .expect("temporary engine should be executable");

        let config = EngineConfig::default_scan(&path, "/tmp/ignored");
        let output = run(&config).expect("process boundary should retain the result");
        assert!(matches!(
            output.report_json(),
            Err(AdapterError::ProcessFailed(_))
        ));
        std::fs::remove_file(path).expect("temporary engine should be removable");
    }

    #[test]
    fn target_fingerprint_is_unambiguous_and_bounded() {
        let base = std::env::temp_dir().join(format!(
            "secureflow-target-fingerprint-{}",
            std::process::id()
        ));
        let first = base.join("first");
        let second = base.join("second");
        let third = base.join("third");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&first).expect("first target directory");
        std::fs::create_dir_all(&second).expect("second target directory");
        std::fs::create_dir_all(third.join("one")).expect("third target directory one");
        std::fs::create_dir_all(third.join("two")).expect("third target directory two");
        std::fs::write(first.join("a"), b"x\0b\0y").expect("first target file");
        std::fs::write(second.join("a"), b"x").expect("second target file a");
        std::fs::write(second.join("b"), b"y").expect("second target file b");

        assert_ne!(
            sha256_target(&first).expect("first fingerprint"),
            sha256_target(&second).expect("second fingerprint")
        );
        let limits = TargetHashLimits {
            max_files: 1,
            max_entries: 2,
            max_total_bytes: 1024,
            max_file_bytes: 1024,
            max_depth: 8,
        };
        assert!(sha256_target_with_limits(&second, limits).is_err());
        let entry_limits = TargetHashLimits {
            max_files: 10,
            max_entries: 1,
            max_total_bytes: 1024,
            max_file_bytes: 1024,
            max_depth: 8,
        };
        assert!(sha256_target_with_limits(&third, entry_limits).is_err());
        std::fs::remove_dir_all(base).expect("temporary targets should be removable");
    }

    #[test]
    fn projects_a_finding_without_copying_source_text() {
        let report = serde_json::json!({
            "schema_version": "secure-json-v1",
            "findings": [{
                "fingerprint": "a".repeat(64),
                "title": "Tainted value reaches sink",
                "rule_id": "SE1001",
                "severity": "high",
                "confidence": "high",
                "invariant": "Untrusted values must not reach command execution",
                "source": {
                    "path": "src/main.ts",
                    "span": {
                        "start_line": 2, "start_column": 1,
                        "end_line": 2, "end_column": 8
                    }
                },
                "sink": {
                    "path": "src/main.ts",
                    "span": {
                        "start_line": 8, "start_column": 1,
                        "end_line": 8, "end_column": 12
                    }
                },
                "evidence_path": [{
                    "kind": "source",
                    "location": {
                        "path": "src/main.ts",
                        "span": {
                            "start_line": 2, "start_column": 1,
                            "end_line": 2, "end_column": 8
                        }
                    }
                }, {
                    "kind": "sink",
                    "location": {
                        "path": "src/main.ts",
                        "span": {
                            "start_line": 8, "start_column": 1,
                            "end_line": 8, "end_column": 12
                        }
                    }
                }]
            }]
        });
        let findings = project_findings(&report).expect("fixture should project");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].finding_id,
            format!("sf_finding_{}", "a".repeat(64))
        );
        assert_eq!(findings[0].human_review.decision, HumanDecision::Pending);
    }

    #[test]
    fn hashes_bytes_with_lowercase_sha256() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
