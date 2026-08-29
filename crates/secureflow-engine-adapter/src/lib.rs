//! Safe process boundary for an explicitly supplied Secure Engine binary.
//!
//! This first slice avoids a shell, clears the child environment, bounds the
//! direct process duration, retained output and Linux resources. On Unix the
//! child receives a dedicated process group so timeout cleanup includes its
//! descendants. Linux callers can require Bubblewrap for a read-only host
//! filesystem and a private network namespace; failure to start then fails
//! closed rather than silently falling back.

use secureflow_model::{
    AiValidation, Confidence, ENGINE_CALIBRATION_TAXONOMY, ENGINE_EVIDENCE_STATE_TAXONOMY,
    EngineAnalysisAbstention, EngineEvidenceCalibration, EngineEvidenceDisposition,
    EngineEvidenceResolution, EngineEvidenceState, EngineEvidenceStateKind,
    EngineFilesystemIdentity, EngineGraphScope, EngineGraphSummary, EngineSecurityControlEvidence,
    EngineSecurityControlKind, EvidenceKind, EvidenceStep, Finding, HumanDecision, HumanReview,
    Location, Severity, TaxonomyCoordinates,
};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const SECURE_JSON_SCHEMA: &str = "secure-json-v1";
pub const TARGET_FINGERPRINT_SCHEME: &str = "secureflow-target-sha256-v3";
pub const DEFAULT_ENGINE_EXCLUDES: &[&str] = &["node_modules/**", "**/node_modules/**"];
pub const DEFAULT_MAX_TARGET_FILES: u64 = 250_000;
pub const DEFAULT_MAX_TARGET_ENTRIES: u64 = 500_000;
pub const DEFAULT_MAX_TARGET_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_TARGET_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_TARGET_DEPTH: usize = 256;
pub const MAX_ENGINE_BINARY_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ENGINE_TIMEOUT_SECONDS: u64 = 3600;
pub const FULL_GRAPH_MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
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
    /// Aggregate retained-output budget for stdout and stderr combined.
    pub max_output_bytes: usize,
    /// Require a complete graph, negotiating once when a compatible Engine
    /// explicitly returns a compact graph to the portable first invocation.
    pub require_full_graph: bool,
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
                "--exclude".into(),
                DEFAULT_ENGINE_EXCLUDES[0].into(),
                "--exclude".into(),
                DEFAULT_ENGINE_EXCLUDES[1].into(),
            ],
            timeout: Duration::from_secs(120),
            max_output_bytes: 32 * 1024 * 1024,
            require_full_graph: false,
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
        hash_field(
            &mut hasher,
            if self.require_full_graph {
                "full-engine-graph-required-v1"
            } else {
                "engine-default-graph-v1"
            },
        );
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

    /// Requires a complete graph in the received Engine report and raises the
    /// aggregate retained-output budget. Capability negotiation starts with
    /// the portable RC2 invocation and retries only when an Engine explicitly
    /// identifies its first response as a compact finding-evidence graph.
    pub fn request_full_graph(&mut self) {
        self.require_full_graph = true;
        self.max_output_bytes = self.max_output_bytes.max(FULL_GRAPH_MAX_OUTPUT_BYTES);
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
    require_full_graph: bool,
}

impl EngineOutput {
    pub fn import_report(&self) -> Result<ImportedEngineReport, AdapterError> {
        if self.timed_out {
            return Err(AdapterError::TimedOut);
        }
        if !matches!(self.status.code(), Some(0 | 1)) || self.stdout.is_empty() {
            return Err(AdapterError::ProcessFailed(self.status.to_string()));
        }
        let report = import_secure_json_report(&self.stdout)?;
        if self.require_full_graph
            && report
                .graph
                .as_ref()
                .is_none_or(|graph| graph.scope != EngineGraphScope::Full)
        {
            return Err(AdapterError::RequiredFullGraphUnavailable);
        }
        Ok(report)
    }

    pub fn report_json(&self) -> Result<serde_json::Value, AdapterError> {
        self.import_report().map(|report| report.document)
    }

    pub fn report_sha256(&self) -> String {
        sha256_bytes(&self.stdout)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedEngineReport {
    pub document: serde_json::Value,
    pub engine_version: String,
    pub report_fingerprint: String,
    pub graph: Option<EngineGraphSummary>,
    pub findings: Vec<Finding>,
    pub abstentions: Vec<EngineAnalysisAbstention>,
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
    #[error("engine did not return the required complete evidence graph")]
    RequiredFullGraphUnavailable,
    #[error("engine report is not valid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("engine report does not declare secure-json-v1")]
    WrongSchema,
    #[error("engine report is incompatible: {0}")]
    IncompatibleReport(&'static str),
    #[error("required Linux Bubblewrap sandbox is unavailable: {0}")]
    SandboxUnavailable(String),
    #[error("invalid finding at index {index}: {message}")]
    InvalidFinding { index: usize, message: String },
}

pub fn run(config: &EngineConfig) -> Result<EngineOutput, AdapterError> {
    validate_config(config)?;
    let resolved_binary = resolve_engine_binary(&config.binary)?;
    let mut argv = config.arguments.clone();
    argv.push(config.target.display().to_string());
    let started = Instant::now();
    let first = run_with_argv(config, &resolved_binary, argv)?;
    if !config.require_full_graph || !explicitly_compact_graph(&first) {
        return Ok(first);
    }

    let remaining = config
        .timeout
        .checked_sub(started.elapsed())
        .ok_or(AdapterError::TimedOut)?;
    if remaining.is_zero() {
        return Err(AdapterError::TimedOut);
    }
    let mut retry_config = config.clone();
    retry_config.timeout = remaining;
    retry_config.max_cpu_seconds = retry_config
        .max_cpu_seconds
        .min(remaining.as_secs().saturating_add(1));
    let mut retry_argv = config.arguments.clone();
    retry_argv.extend([
        "--full-graph".into(),
        "--max-output-bytes".into(),
        FULL_GRAPH_MAX_OUTPUT_BYTES.to_string(),
    ]);
    retry_argv.push(config.target.display().to_string());
    let retried = run_with_argv(&retry_config, &resolved_binary, retry_argv)?;
    if retried.binary_sha256 != first.binary_sha256 {
        return Err(AdapterError::BinaryChangedDuringRun);
    }
    Ok(retried)
}

fn explicitly_compact_graph(output: &EngineOutput) -> bool {
    if output.timed_out || !matches!(output.status.code(), Some(0 | 1)) || output.stdout.is_empty()
    {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .ok()
        .and_then(|document| {
            document
                .get("graph")?
                .get("scope")?
                .as_str()
                .map(|scope| scope == "finding-evidence")
        })
        .unwrap_or(false)
}

fn run_with_argv(
    config: &EngineConfig,
    resolved_binary: &Path,
    argv: Vec<String>,
) -> Result<EngineOutput, AdapterError> {
    let binary_sha256 = hash_engine_binary(resolved_binary)?;

    let (mut command, sandbox_binary_sha256) = command_for(config, resolved_binary, &argv)?;
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
    let remaining_output = Arc::new(AtomicUsize::new(config.max_output_bytes));
    let stdout_budget = Arc::clone(&remaining_output);
    let stderr_budget = Arc::clone(&remaining_output);
    let stdout_thread = thread::spawn(move || read_bounded(stdout, stdout_budget));
    let stderr_thread = thread::spawn(move || read_bounded(stderr, stderr_budget));

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
    let completed_binary_sha256 = hash_engine_binary(resolved_binary)?;
    if completed_binary_sha256 != binary_sha256 {
        return Err(AdapterError::BinaryChangedDuringRun);
    }
    let (stdout, stderr) = match (stdout, stderr) {
        (BoundedRead::Complete(stdout), BoundedRead::Complete(stderr)) => (stdout, stderr),
        _ => return Err(AdapterError::OutputLimit),
    };
    if stdout.len().saturating_add(stderr.len()) > config.max_output_bytes {
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
        require_full_graph: config.require_full_graph,
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

fn project_graph(report: &serde_json::Value) -> Result<Option<EngineGraphSummary>, AdapterError> {
    let Some(graph) = report.get("graph") else {
        return Ok(None);
    };
    let object = graph
        .as_object()
        .ok_or(AdapterError::IncompatibleReport("graph must be an object"))?;
    let nodes = object
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .ok_or(AdapterError::IncompatibleReport(
            "graph.nodes must be an array",
        ))?;
    let edges = object
        .get("edges")
        .and_then(serde_json::Value::as_array)
        .ok_or(AdapterError::IncompatibleReport(
            "graph.edges must be an array",
        ))?;
    let nodes = u64::try_from(nodes.len())
        .map_err(|_| AdapterError::IncompatibleReport("graph node count is too large"))?;
    let edges = u64::try_from(edges.len())
        .map_err(|_| AdapterError::IncompatibleReport("graph edge count is too large"))?;
    let scope = match object
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("full")
    {
        "full" => EngineGraphScope::Full,
        "finding-evidence" => EngineGraphScope::FindingEvidence,
        _ => {
            return Err(AdapterError::IncompatibleReport(
                "graph.scope is unsupported",
            ));
        }
    };
    let total_nodes = optional_graph_count(object, "total_nodes")?.unwrap_or(nodes);
    let total_edges = optional_graph_count(object, "total_edges")?.unwrap_or(edges);
    if total_nodes < nodes || total_edges < edges {
        return Err(AdapterError::IncompatibleReport(
            "graph totals cannot be smaller than serialized counts",
        ));
    }
    if scope == EngineGraphScope::Full && (total_nodes != nodes || total_edges != edges) {
        return Err(AdapterError::IncompatibleReport(
            "a full graph must serialize all reported nodes and edges",
        ));
    }
    Ok(Some(EngineGraphSummary {
        scope,
        nodes,
        edges,
        total_nodes,
        total_edges,
    }))
}

fn optional_graph_count(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &'static str,
) -> Result<Option<u64>, AdapterError> {
    object
        .get(key)
        .map(|value| {
            value.as_u64().ok_or(AdapterError::IncompatibleReport(
                "graph totals must be non-negative integers",
            ))
        })
        .transpose()
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
    let engine_id = required_string(object, "fingerprint", index)?;
    if !is_lower_sha256(engine_id) {
        return Err(invalid_finding(
            index,
            "fingerprint must be a lowercase SHA-256",
        ));
    }
    let engine_finding_id = required_string(object, "finding_id", index)?;
    let engine_verification_state = required_string(object, "verification_state", index)?;
    let engine_evidence_state = project_evidence_state(
        object.get("evidence_state"),
        engine_verification_state,
        index,
    )?;
    let engine_calibration = project_calibration(object.get("calibration"), index)?;
    if engine_calibration.as_ref().is_some_and(|calibration| {
        calibration.disposition == EngineEvidenceDisposition::ExplicitAbstention
    }) {
        return Err(invalid_finding(
            index,
            "explicit abstention cannot be imported from the findings collection",
        ));
    }
    let evidence_path = project_evidence_path(object.get("evidence_path"), index)?;
    let taxonomy = project_taxonomy(object.get("taxonomy"), index)?;

    Ok(Finding {
        finding_id: format!("sf_finding_{engine_id}"),
        engine_fingerprint: Some(engine_id.into()),
        engine_finding_id: Some(engine_finding_id.into()),
        engine_verification_state: Some(engine_verification_state.into()),
        engine_evidence_state,
        engine_calibration,
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

fn project_calibration(
    value: Option<&serde_json::Value>,
    index: usize,
) -> Result<Option<EngineEvidenceCalibration>, AdapterError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid_finding(index, "calibration must be an object"))?;
    let taxonomy_version = required_string(object, "taxonomy_version", index)?;
    if taxonomy_version != ENGINE_CALIBRATION_TAXONOMY {
        return Err(invalid_finding(
            index,
            "calibration taxonomy is unsupported",
        ));
    }
    let control = object
        .get("security_control")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_finding(index, "calibration.security_control must be an object"))?;
    Ok(Some(EngineEvidenceCalibration {
        taxonomy_version: taxonomy_version.into(),
        disposition: parse_disposition(required_string(object, "disposition", index)?, index)?,
        reachability: parse_resolution(required_string(object, "reachability", index)?, index)?,
        attacker_control: parse_resolution(
            required_string(object, "attacker_control", index)?,
            index,
        )?,
        actor_identity: parse_resolution(required_string(object, "actor_identity", index)?, index)?,
        trust_boundary: parse_resolution(required_string(object, "trust_boundary", index)?, index)?,
        security_control: EngineSecurityControlEvidence {
            kind: parse_control_kind(required_string(control, "kind", index)?, index)?,
            scope_binding: parse_resolution(
                required_string(control, "scope_binding", index)?,
                index,
            )?,
            value_binding: parse_resolution(
                required_string(control, "value_binding", index)?,
                index,
            )?,
            time_binding: parse_resolution(
                required_string(control, "time_binding", index)?,
                index,
            )?,
        },
        filesystem_identity: parse_filesystem_identity(
            required_string(object, "filesystem_identity", index)?,
            index,
        )?,
        observable_impact: parse_resolution(
            required_string(object, "observable_impact", index)?,
            index,
        )?,
        reason: optional_string(object.get("reason"), index, "calibration.reason")?,
    }))
}

fn parse_disposition(value: &str, index: usize) -> Result<EngineEvidenceDisposition, AdapterError> {
    match value {
        "security-path" => Ok(EngineEvidenceDisposition::SecurityPath),
        "bounded-hardening" => Ok(EngineEvidenceDisposition::BoundedHardening),
        "explicit-abstention" => Ok(EngineEvidenceDisposition::ExplicitAbstention),
        _ => Err(invalid_finding(
            index,
            "calibration disposition is unsupported",
        )),
    }
}

fn parse_resolution(value: &str, index: usize) -> Result<EngineEvidenceResolution, AdapterError> {
    match value {
        "proven" => Ok(EngineEvidenceResolution::Proven),
        "unresolved" => Ok(EngineEvidenceResolution::Unresolved),
        "equivalent-capability" => Ok(EngineEvidenceResolution::EquivalentCapability),
        "not-applicable" => Ok(EngineEvidenceResolution::NotApplicable),
        _ => Err(invalid_finding(
            index,
            "calibration resolution is unsupported",
        )),
    }
}

fn parse_control_kind(
    value: &str,
    index: usize,
) -> Result<EngineSecurityControlKind, AdapterError> {
    match value {
        "none" => Ok(EngineSecurityControlKind::None),
        "lexical-containment" => Ok(EngineSecurityControlKind::LexicalContainment),
        "canonical-containment" => Ok(EngineSecurityControlKind::CanonicalContainment),
        "opened-object-identity" => Ok(EngineSecurityControlKind::OpenedObjectIdentity),
        "identity-revalidation" => Ok(EngineSecurityControlKind::IdentityRevalidation),
        "authorization" => Ok(EngineSecurityControlKind::Authorization),
        "destination-policy" => Ok(EngineSecurityControlKind::DestinationPolicy),
        "workspace-trust" => Ok(EngineSecurityControlKind::WorkspaceTrust),
        "unknown" => Ok(EngineSecurityControlKind::Unknown),
        _ => Err(invalid_finding(
            index,
            "security control kind is unsupported",
        )),
    }
}

fn parse_filesystem_identity(
    value: &str,
    index: usize,
) -> Result<EngineFilesystemIdentity, AdapterError> {
    match value {
        "not-applicable" => Ok(EngineFilesystemIdentity::NotApplicable),
        "lexical-path" => Ok(EngineFilesystemIdentity::LexicalPath),
        "canonical-target" => Ok(EngineFilesystemIdentity::CanonicalTarget),
        "opened-object" => Ok(EngineFilesystemIdentity::OpenedObject),
        "revalidated-object" => Ok(EngineFilesystemIdentity::RevalidatedObject),
        "unresolved" => Ok(EngineFilesystemIdentity::Unresolved),
        _ => Err(invalid_finding(index, "filesystem identity is unsupported")),
    }
}

fn project_evidence_state(
    value: Option<&serde_json::Value>,
    verification_state: &str,
    index: usize,
) -> Result<Option<EngineEvidenceState>, AdapterError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid_finding(index, "evidence_state must be an object"))?;
    let taxonomy_version = required_string(object, "taxonomy_version", index)?;
    if taxonomy_version != ENGINE_EVIDENCE_STATE_TAXONOMY {
        return Err(invalid_finding(
            index,
            "evidence_state taxonomy is unsupported",
        ));
    }
    let state_value = required_string(object, "state", index)?;
    let state = match state_value {
        "syntactic-lead" => EngineEvidenceStateKind::SyntacticLead,
        "semantic-path" => EngineEvidenceStateKind::SemanticPath,
        "guard-aware-lead" => EngineEvidenceStateKind::GuardAwareLead,
        "manually-validated" => EngineEvidenceStateKind::ManuallyValidated,
        _ => {
            return Err(invalid_finding(
                index,
                "evidence_state state is unsupported",
            ));
        }
    };
    if state_value != verification_state {
        return Err(invalid_finding(
            index,
            "verification_state and evidence_state.state must agree",
        ));
    }
    Ok(Some(EngineEvidenceState {
        taxonomy_version: taxonomy_version.into(),
        state,
    }))
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
    if !is_portable_relative_path(path) {
        return Err(invalid_finding(
            index,
            format!("{field}.path must be a portable relative path"),
        ));
    }
    let span = object
        .get("span")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid_finding(index, format!("{field}.span must be an object")))?;
    let start_byte = optional_number(span, "start_byte", index)?;
    let end_byte = optional_number(span, "end_byte", index)?;
    if start_byte.is_some() != end_byte.is_some()
        || start_byte
            .zip(end_byte)
            .is_some_and(|(start, end)| end < start)
    {
        return Err(invalid_finding(
            index,
            format!("{field}.span byte offsets are inconsistent"),
        ));
    }
    Ok(Location {
        path: path.into(),
        start_byte,
        end_byte,
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

fn optional_string(
    value: Option<&serde_json::Value>,
    index: usize,
    field: &str,
) -> Result<Option<String>, AdapterError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 200)
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| {
                invalid_finding(index, format!("{field} must be a non-empty bounded string"))
            }),
    }
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

fn optional_number(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    index: usize,
) -> Result<Option<u64>, AdapterError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| invalid_finding(index, format!("{key} must be an integer")))
        })
        .transpose()
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

fn project_abstentions(
    report: &serde_json::Value,
) -> Result<Vec<EngineAnalysisAbstention>, AdapterError> {
    let Some(value) = report.get("abstentions") else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or(AdapterError::IncompatibleReport(
        "abstentions must be an array",
    ))?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid_finding(index, "abstention must be an object"))?;
            let abstention_id = required_string(object, "abstention_id", index)?;
            if !abstention_id.strip_prefix("ab_").is_some_and(|suffix| {
                suffix.len() == 24
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }) {
                return Err(invalid_finding(index, "abstention_id is invalid"));
            }
            let fingerprint = required_string(object, "fingerprint", index)?;
            if !is_lower_sha256(fingerprint) {
                return Err(invalid_finding(index, "abstention fingerprint is invalid"));
            }
            let calibration = project_calibration(object.get("calibration"), index)?
                .ok_or_else(|| invalid_finding(index, "abstention calibration is required"))?;
            if calibration.disposition != EngineEvidenceDisposition::ExplicitAbstention {
                return Err(invalid_finding(
                    index,
                    "abstention calibration disposition must be explicit-abstention",
                ));
            }
            Ok(EngineAnalysisAbstention {
                abstention_id: abstention_id.into(),
                rule_id: required_string(object, "rule_id", index)?.into(),
                reason: required_string(object, "reason", index)?.into(),
                source_location: project_location(object.get("source"), index, "source")?,
                sink_location: project_location(object.get("sink"), index, "sink")?,
                evidence_path: project_evidence_path(object.get("evidence_path"), index)?,
                calibration,
                limitations: string_array(object.get("limitations"), index, "limitations")?,
                fingerprint: fingerprint.into(),
            })
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
        "receiver" => EvidenceKind::Receiver,
        "transform" => EvidenceKind::Transform,
        "guard" => EvidenceKind::Guard,
        "sanitizer" => EvidenceKind::Sanitizer,
        "authorization" => EvidenceKind::Authorization,
        "sink" => EvidenceKind::Sink,
        "barrier" => EvidenceKind::Barrier,
        _ => EvidenceKind::Unknown,
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_portable_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        && !value
            .split('/')
            .any(|component| component.is_empty() || component == "..")
        && !(value.len() >= 2
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes()[1] == b':')
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
        let name = entry.file_name();
        if name == ".git" || name == "node_modules" {
            continue;
        }
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

pub fn import_secure_json_report(bytes: &[u8]) -> Result<ImportedEngineReport, AdapterError> {
    let document: serde_json::Value =
        serde_json::from_slice(bytes).map_err(AdapterError::InvalidJson)?;
    if document
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        != Some(SECURE_JSON_SCHEMA)
    {
        return Err(AdapterError::WrongSchema);
    }
    let object = document
        .as_object()
        .ok_or(AdapterError::IncompatibleReport(
            "report root must be an object",
        ))?;
    if object
        .get("document_type")
        .and_then(serde_json::Value::as_str)
        != Some("scan-report")
    {
        return Err(AdapterError::IncompatibleReport(
            "document_type must be scan-report",
        ));
    }
    let engine_version = object
        .get("engine_version")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 100)
        .ok_or(AdapterError::IncompatibleReport(
            "engine_version must be a non-empty bounded string",
        ))?
        .to_owned();
    let report_fingerprint = object
        .get("report_fingerprint")
        .and_then(serde_json::Value::as_str)
        .filter(|value| is_lower_sha256(value))
        .ok_or(AdapterError::IncompatibleReport(
            "report_fingerprint must be a lowercase SHA-256",
        ))?
        .to_owned();
    let graph = project_graph(&document)?;
    let findings = project_findings(&document)?;
    let abstentions = project_abstentions(&document)?;
    Ok(ImportedEngineReport {
        document,
        engine_version,
        report_fingerprint,
        graph,
        findings,
        abstentions,
    })
}

pub fn validate_secure_json_report(bytes: &[u8]) -> Result<serde_json::Value, AdapterError> {
    import_secure_json_report(bytes).map(|report| report.document)
}

enum BoundedRead {
    Complete(Vec<u8>),
    LimitExceeded,
}

fn read_bounded<R: Read>(mut reader: R, remaining: Arc<AtomicUsize>) -> io::Result<BoundedRead> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut limit_exceeded = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(if limit_exceeded {
                BoundedRead::LimitExceeded
            } else {
                BoundedRead::Complete(output)
            });
        }
        if limit_exceeded
            || remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |available| {
                    available.checked_sub(read)
                })
                .is_err()
        {
            // Continue draining after a limit breach so an untrusted child
            // cannot block forever on a full pipe.
            limit_exceeded = true;
            continue;
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn join_output(
    handle: thread::JoinHandle<io::Result<BoundedRead>>,
) -> Result<BoundedRead, AdapterError> {
    handle
        .join()
        .map_err(|_| AdapterError::OutputReaderPanicked)?
        .map_err(AdapterError::OutputRead)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_REPORT: &str = concat!(
        "{\"schema_version\":\"secure-json-v1\",",
        "\"engine_version\":\"test-engine\",",
        "\"document_type\":\"scan-report\",",
        "\"findings\":[],",
        "\"graph\":{\"scope\":\"finding-evidence\",\"nodes\":[],\"edges\":[],",
        "\"total_nodes\":0,\"total_edges\":0},",
        "\"report_fingerprint\":",
        "\"0000000000000000000000000000000000000000000000000000000000000000\"}"
    );

    #[test]
    fn accepts_only_secure_json_v1() {
        assert!(validate_secure_json_report(EMPTY_REPORT.as_bytes()).is_ok());
        let mut legacy_graph: serde_json::Value =
            serde_json::from_str(EMPTY_REPORT).expect("empty fixture");
        legacy_graph["graph"]
            .as_object_mut()
            .expect("graph object")
            .remove("scope");
        legacy_graph["graph"]
            .as_object_mut()
            .expect("graph object")
            .remove("total_nodes");
        legacy_graph["graph"]
            .as_object_mut()
            .expect("graph object")
            .remove("total_edges");
        assert_eq!(
            import_secure_json_report(&serde_json::to_vec(&legacy_graph).expect("fixture bytes"))
                .expect("legacy graph should import")
                .graph
                .expect("graph summary")
                .scope,
            EngineGraphScope::Full
        );
        let wrong_schema = EMPTY_REPORT.replace("secure-json-v1", "sarif");
        assert!(matches!(
            validate_secure_json_report(wrong_schema.as_bytes()),
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
                "--quiet",
                "--exclude",
                "node_modules/**",
                "--exclude",
                "**/node_modules/**"
            ]
        );
        assert_eq!(config.target, PathBuf::from("/tmp/fixture"));
        assert_eq!(config.max_memory_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(config.max_cpu_seconds, 121);
        assert_eq!(config.max_open_files, 256);
        assert_eq!(config.configuration_sha256().len(), 64);
    }

    #[test]
    fn full_graph_requirement_is_explicit_and_raises_the_aggregate_output_limit() {
        let mut config = EngineConfig::default_scan("/bin/secure", "/tmp/fixture");
        let compact_hash = config.configuration_sha256();
        assert!(!config.require_full_graph);

        config.request_full_graph();
        config.request_full_graph();

        assert!(config.require_full_graph);
        assert!(!config.arguments.iter().any(|value| value == "--full-graph"));
        assert_eq!(config.max_output_bytes, FULL_GRAPH_MAX_OUTPUT_BYTES);
        assert_ne!(config.configuration_sha256(), compact_hash);
    }

    #[cfg(unix)]
    #[test]
    fn full_graph_requirement_is_enforced_by_the_adapter_boundary() {
        let mut config = EngineConfig::default_scan("/bin/sh", "/tmp/ignored");
        config.arguments = vec!["-c".into(), format!("printf '%s\\n' '{}'", EMPTY_REPORT)];
        config.request_full_graph();

        let output = run(&config).expect("process execution should complete");
        assert!(
            output
                .argv
                .iter()
                .any(|argument| argument == "--full-graph")
        );
        assert!(matches!(
            output.import_report(),
            Err(AdapterError::RequiredFullGraphUnavailable)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_full_graph_contract_does_not_trigger_capability_retry() {
        let mut legacy: serde_json::Value =
            serde_json::from_str(EMPTY_REPORT).expect("empty fixture");
        legacy["graph"]
            .as_object_mut()
            .expect("graph object")
            .remove("scope");
        let serialized = serde_json::to_string(&legacy).expect("legacy fixture");
        let mut config = EngineConfig::default_scan("/bin/sh", "/tmp/ignored");
        config.arguments = vec!["-c".into(), format!("printf '%s\\n' '{serialized}'")];
        config.request_full_graph();

        let output = run(&config).expect("legacy execution should complete");
        assert!(
            !output
                .argv
                .iter()
                .any(|argument| argument == "--full-graph")
        );
        assert_eq!(
            output
                .import_report()
                .expect("legacy report should import")
                .graph
                .expect("graph")
                .scope,
            EngineGraphScope::Full
        );
    }

    #[cfg(unix)]
    #[test]
    fn compact_graph_negotiates_one_bounded_full_graph_retry() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "secureflow-negotiating-engine-{}.sh",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let full_report = EMPTY_REPORT.replace("finding-evidence", "full");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nfor argument in \"$@\"; do\n  if test \"$argument\" = --full-graph; then\n    printf '%s\\n' '{full_report}'\n    exit 0\n  fi\ndone\nprintf '%s\\n' '{EMPTY_REPORT}'\n"
            ),
        )
        .expect("temporary engine should be writable");
        let mut permissions = std::fs::metadata(&path)
            .expect("temporary engine metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions)
            .expect("temporary engine should be executable");

        let mut config = EngineConfig::default_scan(&path, "/tmp/ignored");
        config.request_full_graph();
        let output = run(&config).expect("capability negotiation should complete");
        assert!(
            output
                .argv
                .iter()
                .any(|argument| argument == "--full-graph")
        );
        assert_eq!(
            output
                .import_report()
                .expect("negotiated full report should import")
                .graph
                .expect("graph")
                .scope,
            EngineGraphScope::Full
        );
        std::fs::remove_file(path).expect("temporary engine should be removable");
    }

    #[test]
    fn output_budget_is_shared_across_streams() {
        let budget = Arc::new(AtomicUsize::new(6));
        assert!(matches!(
            read_bounded(std::io::Cursor::new(b"abcd"), Arc::clone(&budget))
                .expect("stdout should be readable"),
            BoundedRead::Complete(_)
        ));
        assert!(matches!(
            read_bounded(std::io::Cursor::new(b"efgh"), budget).expect("stderr should be readable"),
            BoundedRead::LimitExceeded
        ));
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
        let bubblewrap_available = Command::new(BUBBLEWRAP_PATH)
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
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !bubblewrap_available {
            eprintln!("skipping Bubblewrap runtime test: user namespaces are unavailable");
            return;
        }
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
            format!(
                "touch \"$0/sandbox-write\" 2>/dev/null; readlink /proc/self/ns/net >&2; printf '%s\\n' '{}'",
                EMPTY_REPORT
            ),
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

    #[cfg(unix)]
    #[test]
    fn accepts_exit_one_as_findings_and_clears_the_child_environment() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "secureflow-findings-engine-{}.sh",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ntest -z \"$HOME\" || exit 2\nprintf '%s\\n' '{}'\nexit 1\n",
                EMPTY_REPORT
            ),
        )
        .expect("temporary engine should be writable");
        let mut permissions = std::fs::metadata(&path)
            .expect("temporary engine metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions)
            .expect("temporary engine should be executable");

        let config = EngineConfig::default_scan(&path, "/tmp/ignored");
        let output = run(&config).expect("process boundary should retain exit one");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.import_report().is_ok());
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
    fn target_fingerprint_excludes_root_and_nested_node_modules() {
        let root = std::env::temp_dir().join(format!(
            "secureflow-target-node-modules-exclusion-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("node_modules/root-dependency"))
            .expect("root dependency directory");
        std::fs::create_dir_all(root.join("packages/app/node_modules/nested-dependency"))
            .expect("nested dependency directory");
        std::fs::create_dir_all(root.join("packages/app/src")).expect("source directory");
        std::fs::write(root.join("source.ts"), b"export const root = true;\n")
            .expect("root source");
        std::fs::write(
            root.join("packages/app/src/index.ts"),
            b"export const nested = true;\n",
        )
        .expect("nested source");
        std::fs::write(
            root.join("node_modules/root-dependency/index.js"),
            b"module.exports = 1;\n",
        )
        .expect("root dependency");
        std::fs::write(
            root.join("packages/app/node_modules/nested-dependency/index.js"),
            b"module.exports = 1;\n",
        )
        .expect("nested dependency");

        let baseline = sha256_target(&root).expect("baseline fingerprint");
        std::fs::write(
            root.join("node_modules/root-dependency/index.js"),
            b"module.exports = 2;\n",
        )
        .expect("changed root dependency");
        std::fs::write(
            root.join("packages/app/node_modules/nested-dependency/index.js"),
            b"module.exports = 2;\n",
        )
        .expect("changed nested dependency");
        assert_eq!(
            sha256_target(&root).expect("dependency-only fingerprint"),
            baseline
        );

        std::fs::write(root.join("source.ts"), b"export const root = false;\n")
            .expect("changed source");
        assert_ne!(
            sha256_target(&root).expect("source-change fingerprint"),
            baseline
        );
        std::fs::remove_dir_all(root).expect("temporary target should be removable");
    }

    #[test]
    fn imports_compact_contract_deterministically_without_copying_unknown_engine_fields() {
        let report = serde_json::json!({
            "schema_version": "secure-json-v1",
            "engine_version": "0.1.10",
            "document_type": "scan-report",
            "repository": {"root": "/home/operator/private-target"},
            "findings": [{
                "finding_id": "fd_fixture_listener",
                "fingerprint": "a".repeat(64),
                "title": "Potential non-loopback Node listener requires validation",
                "rule_id": "SE1011",
                "severity": "low",
                "confidence": "medium",
                "invariant": "A listener should use an explicit loopback host",
                "verification_state": "syntactic-lead",
                "evidence_state": {
                    "taxonomy_version": "secure-evidence-state-v1",
                    "state": "syntactic-lead"
                },
                "calibration": {
                    "taxonomy_version": "secure-evidence-calibration-v1",
                    "disposition": "security-path",
                    "reachability": "proven",
                    "attacker_control": "proven",
                    "actor_identity": "unresolved",
                    "trust_boundary": "unresolved",
                    "security_control": {
                        "kind": "unknown",
                        "scope_binding": "unresolved",
                        "value_binding": "unresolved",
                        "time_binding": "unresolved"
                    },
                    "filesystem_identity": "not-applicable",
                    "observable_impact": "unresolved"
                },
                "source": {
                    "path": "src/main.ts",
                    "span": {
                        "start_byte": 10, "end_byte": 20,
                        "start_line": 2, "start_column": 1,
                        "end_line": 2, "end_column": 8
                    }
                },
                "sink": {
                    "path": "src/main.ts",
                    "span": {
                        "start_byte": 50, "end_byte": 60,
                        "start_line": 8, "start_column": 1,
                        "end_line": 8, "end_column": 12
                    }
                },
                "evidence_path": [{
                    "kind": "receiver",
                    "semantic": {"identity": "DO_NOT_COPY_SECRET_TOKEN"},
                    "location": {
                        "path": "src/main.ts",
                        "span": {
                            "start_byte": 10, "end_byte": 20,
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
                }],
                "limitations": ["Static reachability and firewall behavior require validation"],
                "source_excerpt": "DO_NOT_COPY_SECRET_TOKEN"
            }],
            "abstentions": [{
                "abstention_id": "ab_0123456789abcdef01234567",
                "rule_id": "SE1003",
                "reason": "filesystem-object-identity-unresolved",
                "source": {
                    "path": "src/path.ts",
                    "span": {"start_byte": 1, "end_byte": 2, "start_line": 1, "start_column": 1, "end_line": 1, "end_column": 2}
                },
                "sink": {
                    "path": "src/path.ts",
                    "span": {"start_byte": 3, "end_byte": 4, "start_line": 2, "start_column": 1, "end_line": 2, "end_column": 2}
                },
                "evidence_path": [{
                    "kind": "source",
                    "location": {
                        "path": "src/path.ts",
                        "span": {"start_byte": 1, "end_byte": 2, "start_line": 1, "start_column": 1, "end_line": 1, "end_column": 2}
                    }
                }, {
                    "kind": "sink",
                    "location": {
                        "path": "src/path.ts",
                        "span": {"start_byte": 3, "end_byte": 4, "start_line": 2, "start_column": 1, "end_line": 2, "end_column": 2}
                    }
                }],
                "calibration": {
                    "taxonomy_version": "secure-evidence-calibration-v1",
                    "disposition": "explicit-abstention",
                    "reachability": "proven",
                    "attacker_control": "proven",
                    "actor_identity": "unresolved",
                    "trust_boundary": "unresolved",
                    "security_control": {
                        "kind": "lexical-containment",
                        "scope_binding": "proven",
                        "value_binding": "proven",
                        "time_binding": "unresolved"
                    },
                    "filesystem_identity": "lexical-path",
                    "observable_impact": "unresolved",
                    "reason": "filesystem-object-identity-unresolved"
                },
                "limitations": ["Object identity requires runtime validation"],
                "fingerprint": "c".repeat(64)
            }],
            "graph": {
                "scope": "finding-evidence",
                "nodes": [{}, {}],
                "edges": [{}],
                "total_nodes": 47293,
                "total_edges": 83344
            },
            "report_fingerprint": "b".repeat(64)
        });
        let bytes = serde_json::to_vec(&report).expect("fixture should serialize");
        let imported = import_secure_json_report(&bytes).expect("fixture should import");
        let repeated = import_secure_json_report(&bytes).expect("fixture should import again");
        assert_eq!(imported, repeated);
        assert_eq!(imported.engine_version, "0.1.10");
        assert_eq!(imported.report_fingerprint, "b".repeat(64));
        assert_eq!(
            imported.graph,
            Some(EngineGraphSummary {
                scope: EngineGraphScope::FindingEvidence,
                nodes: 2,
                edges: 1,
                total_nodes: 47293,
                total_edges: 83344,
            })
        );
        assert_eq!(imported.findings.len(), 1);
        let finding = &imported.findings[0];
        assert_eq!(finding.finding_id, format!("sf_finding_{}", "a".repeat(64)));
        assert_eq!(
            finding.engine_finding_id.as_deref(),
            Some("fd_fixture_listener")
        );
        assert_eq!(
            finding.engine_verification_state.as_deref(),
            Some("syntactic-lead")
        );
        assert_eq!(
            finding
                .engine_evidence_state
                .as_ref()
                .map(|state| state.state),
            Some(EngineEvidenceStateKind::SyntacticLead)
        );
        assert_eq!(finding.source_location.path, "src/main.ts");
        assert_eq!(finding.source_location.start_byte, Some(10));
        assert_eq!(finding.source_location.end_byte, Some(20));
        assert_eq!(finding.source_location.start_line, 2);
        assert_eq!(finding.sink_location.start_byte, Some(50));
        assert_eq!(finding.sink_location.end_byte, Some(60));
        assert_eq!(finding.sink_location.start_line, 8);
        assert_eq!(finding.evidence_path[0].kind, EvidenceKind::Receiver);
        assert_eq!(
            finding.limitations,
            ["Static reachability and firewall behavior require validation"]
        );
        assert_eq!(finding.human_review.decision, HumanDecision::Pending);
        assert_eq!(
            finding
                .engine_calibration
                .as_ref()
                .map(|calibration| calibration.disposition),
            Some(EngineEvidenceDisposition::SecurityPath)
        );
        assert_eq!(imported.abstentions.len(), 1);
        assert_eq!(
            imported.abstentions[0].calibration.disposition,
            EngineEvidenceDisposition::ExplicitAbstention
        );
        let normalized = serde_json::to_string(&imported.findings)
            .expect("normalized findings should serialize");
        assert!(!normalized.contains("DO_NOT_COPY_SECRET_TOKEN"));
        assert!(!normalized.contains("/home/operator/private-target"));

        let mut disguised_abstention = report;
        disguised_abstention["findings"][0]["calibration"]["disposition"] =
            serde_json::Value::String("explicit-abstention".into());
        disguised_abstention["findings"][0]["calibration"]["reason"] =
            serde_json::Value::String("attacker-control-unresolved".into());
        assert!(matches!(
            import_secure_json_report(
                &serde_json::to_vec(&disguised_abstention).expect("fixture bytes")
            ),
            Err(AdapterError::InvalidFinding { .. })
        ));
    }

    #[test]
    fn rejects_malformed_or_incompatible_contract_metadata_without_echoing_paths() {
        let mut missing_fingerprint: serde_json::Value =
            serde_json::from_str(EMPTY_REPORT).expect("empty fixture");
        missing_fingerprint
            .as_object_mut()
            .expect("report object")
            .remove("report_fingerprint");
        assert!(matches!(
            import_secure_json_report(
                &serde_json::to_vec(&missing_fingerprint).expect("fixture bytes")
            ),
            Err(AdapterError::IncompatibleReport(_))
        ));

        let mut inconsistent_graph: serde_json::Value =
            serde_json::from_str(EMPTY_REPORT).expect("empty fixture");
        inconsistent_graph["graph"]["nodes"] = serde_json::json!([{}]);
        assert!(matches!(
            import_secure_json_report(
                &serde_json::to_vec(&inconsistent_graph).expect("fixture bytes")
            ),
            Err(AdapterError::IncompatibleReport(_))
        ));

        let mut unknown_graph_scope: serde_json::Value =
            serde_json::from_str(EMPTY_REPORT).expect("empty fixture");
        unknown_graph_scope["graph"]["scope"] = serde_json::json!("future-scope");
        assert!(matches!(
            import_secure_json_report(
                &serde_json::to_vec(&unknown_graph_scope).expect("fixture bytes")
            ),
            Err(AdapterError::IncompatibleReport(_))
        ));

        let mut wrong_document: serde_json::Value =
            serde_json::from_str(EMPTY_REPORT).expect("empty fixture");
        wrong_document["document_type"] = serde_json::json!("doctor-report");
        assert!(matches!(
            import_secure_json_report(&serde_json::to_vec(&wrong_document).expect("fixture bytes")),
            Err(AdapterError::IncompatibleReport(_))
        ));

        let absolute_path_report = serde_json::json!({
            "schema_version": "secure-json-v1",
            "engine_version": "test-engine",
            "document_type": "scan-report",
            "report_fingerprint": "c".repeat(64),
            "findings": [{
                "finding_id": "fd_absolute_path",
                "fingerprint": "d".repeat(64),
                "title": "candidate",
                "rule_id": "SE1001",
                "invariant": "invariant",
                "verification_state": "semantic-path",
                "source": {"path": "/home/operator/private.ts", "span": {
                    "start_line": 1, "start_column": 1, "end_line": 1, "end_column": 2
                }},
                "sink": {"path": "src/sink.ts", "span": {
                    "start_line": 2, "start_column": 1, "end_line": 2, "end_column": 2
                }},
                "evidence_path": [{"kind": "source", "location": {
                    "path": "src/source.ts", "span": {
                        "start_line": 1, "start_column": 1, "end_line": 1, "end_column": 2
                    }
                }}]
            }]
        });
        let error = import_secure_json_report(
            &serde_json::to_vec(&absolute_path_report).expect("fixture bytes"),
        )
        .expect_err("absolute paths must fail");
        assert!(!error.to_string().contains("/home/operator/private.ts"));

        let mut mismatched_state = absolute_path_report;
        mismatched_state["findings"][0]["source"]["path"] = serde_json::json!("src/source.ts");
        mismatched_state["findings"][0]["evidence_state"] = serde_json::json!({
            "taxonomy_version": "secure-evidence-state-v1",
            "state": "syntactic-lead"
        });
        assert!(matches!(
            import_secure_json_report(
                &serde_json::to_vec(&mismatched_state).expect("fixture bytes")
            ),
            Err(AdapterError::InvalidFinding { .. })
        ));
    }

    #[test]
    fn hashes_bytes_with_lowercase_sha256() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
