//! Separate CLI family: legacy bundle flags and JSON retain their meanings.
use clap::Args;
use secureflow_knowledge::catalog_trust::{self as trust, Clock, Scope, Session};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct Time {
    #[arg(long, requires = "time_reference")]
    verification_time: Option<String>,
    #[arg(long, requires = "verification_time")]
    time_reference: Option<String>,
}
impl Time {
    fn clock(self) -> trust::Result<Clock> {
        Clock::capture(self.verification_time, self.time_reference)
    }
}
#[derive(Debug, Args)]
pub struct Init {
    #[arg(long)]
    trust_store: PathBuf,
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    expected_root_sha256: String,
    #[arg(long)]
    publisher: String,
    #[arg(long)]
    catalog: String,
    #[arg(long)]
    channel: String,
    #[arg(long = "profile", required = true)]
    profiles: Vec<String>,
    /// Explicit zero records no prior release history.
    #[arg(long)]
    minimum_sequence: u64,
    /// Optional independently authenticated first manifest; requires one profile.
    #[arg(long)]
    bootstrap_manifest_sha256: Option<String>,
    #[arg(long)]
    operator: String,
    #[arg(long)]
    authorization_reference: String,
    #[command(flatten)]
    time: Time,
}
#[derive(Debug, Args)]
pub struct Import {
    #[arg(long)]
    trust_store: PathBuf,
    #[arg(long)]
    metadata_dir: PathBuf,
    #[arg(long)]
    publisher: String,
    /// Import revocations without requiring catalog metadata or payload.
    #[arg(long)]
    root_only: bool,
    #[command(flatten)]
    time: Time,
}
#[derive(Debug, Args)]
pub struct Verify {
    #[arg(long)]
    trust_store: PathBuf,
    #[arg(long)]
    metadata_dir: PathBuf,
    #[arg(long)]
    publisher: String,
    #[arg(long)]
    catalog: String,
    #[arg(long)]
    channel: String,
    #[arg(long)]
    required_profile: String,
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    bundle: PathBuf,
    #[command(flatten)]
    time: Time,
}
#[derive(Debug, Args)]
pub struct Install {
    #[command(flatten)]
    input: Verify,
    #[arg(long)]
    output: PathBuf,
}
#[derive(Debug, Args)]
pub struct Inspect {
    #[command(flatten)]
    input: Verify,
    /// Report historical evidence and policy failures; never reserve acceptance.
    #[arg(long, required = true)]
    historical: bool,
}
#[derive(Debug, Args)]
pub struct Status {
    #[arg(long)]
    trust_store: PathBuf,
    #[arg(long)]
    receipt: PathBuf,
    #[command(flatten)]
    time: Time,
}
#[derive(Debug, Args)]
pub struct Prepare {
    #[arg(long)]
    signed_input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, requires = "bundle")]
    manifest: Option<PathBuf>,
    #[arg(long, requires = "manifest")]
    bundle: Option<PathBuf>,
}
#[derive(Debug, Args)]
pub struct Sign {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    key_id: String,
    /// Raw 64-byte signature from the external offline custodian.
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    output: PathBuf,
}
#[derive(Debug, Args)]
pub struct Assemble {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    previous_root: Option<PathBuf>,
    #[arg(long = "signature", required = true)]
    signatures: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
}
fn print(v: serde_json::Value) -> trust::Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&v).map_err(|e| trust::TrustError {
            code: "TRUST_FORMAT",
            message: e.to_string()
        })?
    );
    Ok(())
}
pub fn init(a: Init) -> trust::Result<()> {
    print(trust::enroll(
        &a.trust_store,
        &a.root,
        trust::Enrollment {
            publisher: a.publisher,
            catalog: a.catalog,
            channel: a.channel,
            profiles: a.profiles,
            minimum_sequence: a.minimum_sequence,
            bootstrap_manifest_sha256: a.bootstrap_manifest_sha256,
            operator: a.operator,
            authorization_reference: a.authorization_reference,
            expected_root_sha256: a.expected_root_sha256,
            clock: a.time.clock()?,
        },
    )?)
}
pub fn import(a: Import) -> trust::Result<()> {
    print(
        Session::open(&a.trust_store, a.time.clock()?, true)?.import(
            &a.metadata_dir,
            &a.publisher,
            a.root_only,
        )?,
    )
}
fn scope(a: &Verify) -> Scope {
    Scope {
        publisher_id: a.publisher.clone(),
        catalog_id: a.catalog.clone(),
        channel: a.channel.clone(),
        profile: a.required_profile.clone(),
    }
}
pub fn verify(a: Verify) -> trust::Result<()> {
    let scope = scope(&a);
    let receipt = Session::open(&a.trust_store, a.time.clock()?, false)?.verify(
        &a.metadata_dir,
        &scope,
        &a.manifest,
        &a.bundle,
    )?;
    print(
        serde_json::to_value(receipt).map_err(|e| trust::TrustError {
            code: "TRUST_FORMAT",
            message: e.to_string(),
        })?,
    )
}
pub fn install(a: Install) -> trust::Result<()> {
    let scope = scope(&a.input);
    let a_input = a.input;
    let receipt = Session::open(&a_input.trust_store, a_input.time.clock()?, true)?.install(
        &a_input.metadata_dir,
        &scope,
        &a_input.manifest,
        &a_input.bundle,
        &a.output,
    )?;
    print(
        serde_json::to_value(receipt).map_err(|e| trust::TrustError {
            code: "TRUST_FORMAT",
            message: e.to_string(),
        })?,
    )
}
pub fn inspect(a: Inspect) -> trust::Result<()> {
    let scope = scope(&a.input);
    let a = a.input;
    print(trust::inspect_historical(
        &a.trust_store,
        a.time.clock()?,
        &a.metadata_dir,
        &scope,
        &a.manifest,
        &a.bundle,
    )?)
}
pub fn status(a: Status) -> trust::Result<()> {
    print(Session::open(&a.trust_store, a.time.clock()?, false)?.status(&a.receipt)?)
}
pub fn prepare(a: Prepare) -> trust::Result<()> {
    print(trust::producer::prepare(
        &a.signed_input,
        &a.output,
        a.manifest.as_deref(),
        a.bundle.as_deref(),
    )?)
}
pub fn sign(a: Sign) -> trust::Result<()> {
    print(trust::producer::sign(
        &a.request,
        &a.root,
        &a.key_id,
        &a.signature,
        &a.output,
    )?)
}
pub fn assemble(a: Assemble) -> trust::Result<()> {
    print(trust::producer::assemble(
        &a.request,
        &a.root,
        a.previous_root.as_deref(),
        &a.signatures,
        &a.output,
    )?)
}
