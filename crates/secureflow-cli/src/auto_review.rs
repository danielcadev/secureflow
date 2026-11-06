//! Operator-scoped, local-only automatic analysis. No agent or human verdicts are fabricated.
use super::*;
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Instant;

const PLAN_VERSION: &str = "secureflow-auto-review-plan-v1";
const RESULT_VERSION: &str = "secureflow-auto-review-result-v1";
const MAX_COMPONENTS: usize = 16;
const MAX_PLAN_BYTES: u64 = 64 * 1024;

#[derive(Debug, Args)]
pub(crate) struct PrepareArgs {
    #[arg(long)]
    binary: PathBuf,
    /// Explicit component roots; no automatic scope expansion or symlink exclusions.
    #[arg(long, required = true)]
    target: Vec<PathBuf>,
    #[arg(long)]
    authorized: bool,
    #[arg(long)]
    authorization_reviewer: String,
    #[arg(long, value_enum, default_value_t = ScanAuthorizationBasis::LocalProject)]
    authorization_basis: ScanAuthorizationBasis,
    #[arg(long)]
    authorization_reference: String,
    /// Lifetime of this exact input snapshot and Engine grant (maximum 24 hours).
    #[arg(long, default_value_t = 3600)]
    expires_after_seconds: u64,
    #[arg(long, default_value_t = 120)]
    timeout_seconds: u64,
    /// Cooperative whole-run wall budget; each Engine process uses the remaining budget.
    #[arg(long, default_value_t = 600)]
    total_budget_seconds: u64,
    /// A new directory under an existing trusted parent, outside every target.
    #[arg(long)]
    output_directory: PathBuf,
    /// New plan file, outside the target trees and output directory.
    #[arg(long)]
    plan_output: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct ExecuteArgs {
    #[arg(long)]
    pub(crate) plan: PathBuf,
    /// Pin the exact operator-approved plan bytes; not a digital signature.
    #[arg(long)]
    pub(crate) plan_sha256: String,
}

#[derive(Debug, Args)]
pub(crate) struct StatusArgs {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    plan_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Permissions {
    sandbox: String,
    network: bool,
    target_execution: bool,
    ai_transport: bool,
    human_decisions: bool,
    autonomous_patching: bool,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            sandbox: "required".into(),
            network: false,
            target_execution: false,
            ai_transport: false,
            human_decisions: false,
            autonomous_patching: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PinnedTarget {
    path: PathBuf,
    root_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    contract_version: String,
    created_at: String,
    binary: PathBuf,
    binary_sha256: String,
    targets: Vec<PinnedTarget>,
    authorization: CaseAuthorization,
    permissions: Permissions,
    timeout_seconds: u64,
    total_budget_seconds: u64,
    output_directory: PathBuf,
}

/// A process-start capability, absent from the default MCP server.
pub(crate) struct Grant {
    path: PathBuf,
    bytes: Vec<u8>,
    sha256: String,
    plan: Plan,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ComponentReceipt {
    index: usize,
    report_sha256: String,
    manifest_sha256: String,
    case_sha256: String,
    candidate_count: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResultReceipt {
    contract_version: String,
    plan_sha256: String,
    started_at: String,
    finished_at: String,
    status: String,
    components: Vec<ComponentReceipt>,
    error: Option<String>,
}

fn error(message: impl Into<String>) -> CliError {
    CliError::AutoReview(message.into())
}

fn hash_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn clean_path(path: &Path) -> Result<(), CliError> {
    if !path.is_absolute()
        || path
            .to_str()
            .is_none_or(|text| text.chars().any(char::is_control))
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(error(
            "paths must be absolute, UTF-8, and free of parent traversal/control characters",
        ));
    }
    Ok(())
}

fn canonical(path: &Path) -> Result<PathBuf, CliError> {
    let resolved = fs::canonicalize(path)
        .map_err(|e| error(format!("cannot resolve {}: {e}", path.display())))?;
    clean_path(&resolved)?;
    Ok(resolved)
}

fn existing_exact(path: &Path) -> Result<(), CliError> {
    clean_path(path)?;
    if canonical(path)? != path {
        return Err(error("a pinned path was redirected by a symlink"));
    }
    Ok(())
}

fn new_path(path: &Path) -> Result<PathBuf, CliError> {
    let resolved = resolved_path(path)?;
    clean_path(&resolved)?;
    let parent = resolved
        .parent()
        .ok_or_else(|| error("output has no parent"))?;
    existing_exact(parent)?;
    if !parent.is_dir() {
        return Err(error("output parent must be an existing directory"));
    }
    ensure_output_absent(&resolved)?;
    Ok(resolved)
}

fn file_hash(path: &Path, maximum: u64) -> Result<String, CliError> {
    existing_exact(path)?;
    let metadata = fs::metadata(path).map_err(|e| error(e.to_string()))?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(error(format!(
            "not a bounded regular file: {}",
            path.display()
        )));
    }
    secureflow_engine_adapter::sha256_file(path).map_err(|e| error(e.to_string()))
}

fn target_hash(path: &Path) -> Result<String, CliError> {
    existing_exact(path)?;
    if !path.is_dir() {
        return Err(error("automatic review targets must be directories"));
    }
    sha256_target(path)
        .map_err(|e| error(format!("cannot fingerprint target {}: {e}", path.display())))
}

fn validate_plan(plan: &Plan) -> Result<(), CliError> {
    ScanAuthorizationBasis::from_str(&plan.authorization.basis, false).map_err(error)?;
    if plan.contract_version != PLAN_VERSION
        || plan.permissions != Permissions::default()
        || plan.targets.is_empty()
        || plan.targets.len() > MAX_COMPONENTS
        || !hash_text(&plan.binary_sha256)
        || !(1..=3600).contains(&plan.timeout_seconds)
        || !(1..=3600).contains(&plan.total_budget_seconds)
    {
        return Err(error(
            "invalid automatic-review contract, permissions, bounds, or Engine hash",
        ));
    }
    clean_path(&plan.binary)?;
    clean_path(&plan.output_directory)?;
    if plan.binary.starts_with(&plan.output_directory) {
        return Err(error("Engine cannot be inside output directory"));
    }
    let created = OffsetDateTime::parse(&plan.created_at, &Rfc3339)
        .map_err(|_| error("invalid creation time"))?;
    let expires = expires_at(plan)?;
    if expires <= created || (expires - created).whole_seconds() > 86400 {
        return Err(error("plan lifetime must be at most 24 hours"));
    }
    if plan
        .authorization
        .reference
        .as_deref()
        .is_none_or(|reference| reference.trim().is_empty())
    {
        return Err(error("an explicit authorization reference is required"));
    }
    for (index, target) in plan.targets.iter().enumerate() {
        clean_path(&target.path)?;
        if !hash_text(&target.root_sha256)
            || plan.binary.starts_with(&target.path)
            || plan.output_directory.starts_with(&target.path)
            || target.path.starts_with(&plan.output_directory)
            || plan.targets[..index].iter().any(|prior| {
                prior.path.starts_with(&target.path) || target.path.starts_with(&prior.path)
            })
        {
            return Err(error(
                "invalid target hash or overlapping target/output roots",
            ));
        }
        if plan.targets[..index].iter().any(|prior| {
            SecurityCase::case_id_for(&prior.root_sha256)
                == SecurityCase::case_id_for(&target.root_sha256)
        }) {
            return Err(error(
                "duplicate case identity across components; review identical snapshots in separate plans",
            ));
        }
        // Reuse the authoritative Case validator for authorization and snapshot identity.
        let case = SecurityCase {
            contract_version: CASE_CONTRACT_VERSION.into(),
            case_id: SecurityCase::case_id_for(&target.root_sha256),
            created_at: plan.created_at.clone(),
            target: case_target(plan, target),
            sources: vec![],
            evidence: vec![],
            candidates: vec![],
            staged_recommendations: vec![],
            decisions: vec![],
        };
        case.validate()?;
    }
    Ok(())
}

fn case_target(plan: &Plan, target: &PinnedTarget) -> CaseTarget {
    CaseTarget {
        label: target
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("target")
            .into(),
        root_sha256: target.root_sha256.clone(),
        revision: Some(CaseRevision {
            kind: "snapshot".into(),
            value: format!("sha256:{}", target.root_sha256),
        }),
        authorization: plan.authorization.clone(),
    }
}

fn expires_at(plan: &Plan) -> Result<OffsetDateTime, CliError> {
    OffsetDateTime::parse(
        plan.authorization
            .expires_at
            .as_deref()
            .ok_or_else(|| error("plan must expire"))?,
        &Rfc3339,
    )
    .map_err(|_| error("invalid authorization expiration"))
}

fn ensure_live(plan: &Plan) -> Result<(), CliError> {
    let now = OffsetDateTime::now_utc();
    if expires_at(plan)? <= now {
        return Err(error("automatic-review authorization expired"));
    }
    if OffsetDateTime::parse(&plan.created_at, &Rfc3339)
        .map_err(|_| error("invalid creation time"))?
        > now
    {
        return Err(error("automatic-review authorization is not yet valid"));
    }
    Ok(())
}

pub(crate) fn prepare(args: PrepareArgs) -> Result<(), CliError> {
    if !args.authorized {
        return Err(CliError::AuthorizationRequired);
    }
    if args.target.is_empty()
        || args.target.len() > MAX_COMPONENTS
        || !(1..=86400).contains(&args.expires_after_seconds)
    {
        return Err(error(
            "select 1–16 targets and an expiration of 1–86400 seconds",
        ));
    }
    let created = OffsetDateTime::now_utc();
    let binary = canonical(&args.binary)?;
    let output_directory = new_path(&args.output_directory)?;
    let plan_output = new_path(&args.plan_output)?;
    let targets = args
        .target
        .iter()
        .map(|path| {
            let path = canonical(path)?;
            Ok(PinnedTarget {
                root_sha256: target_hash(&path)?,
                path,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let plan = Plan {
        contract_version: PLAN_VERSION.into(),
        created_at: created.format(&Rfc3339)?,
        binary_sha256: file_hash(&binary, secureflow_engine_adapter::MAX_ENGINE_BINARY_BYTES)?,
        binary,
        targets,
        output_directory,
        authorization: CaseAuthorization {
            status: "authorized".into(),
            basis: scan_authorization_basis_label(args.authorization_basis).into(),
            reviewer: checked_review_field(
                args.authorization_reviewer.trim(),
                "authorization_reviewer",
                200,
            )?,
            reference: Some(checked_review_field(
                args.authorization_reference.trim(),
                "authorization_reference",
                300,
            )?),
            expires_at: Some(
                (created + time::Duration::seconds(args.expires_after_seconds as i64))
                    .format(&Rfc3339)?,
            ),
        },
        permissions: Permissions::default(),
        timeout_seconds: args.timeout_seconds,
        total_budget_seconds: args.total_budget_seconds,
    };
    validate_plan(&plan)?;
    ensure_live(&plan)?;
    if plan_output.starts_with(&plan.output_directory)
        || plan
            .targets
            .iter()
            .any(|t| plan_output.starts_with(&t.path))
    {
        return Err(error(
            "retain the plan outside every target and output directory",
        ));
    }
    let bytes = serde_json::to_vec_pretty(&plan)?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        return Err(error("plan exceeds 64 KiB"));
    }
    write_atomic_new(&plan_output, &bytes)?;
    println!(
        "{}",
        json!({"plan_path":plan_output,"plan_sha256":case_digest(&bytes),"targets":plan.targets.len(),"output_directory":plan.output_directory,"execution":"not-started","final_authority":"human-only"})
    );
    Ok(())
}

impl Grant {
    pub(crate) fn load(path: &Path, expected: &str) -> Result<Self, CliError> {
        let path = canonical(path)?;
        let bytes = read_bounded_file(&path, MAX_PLAN_BYTES)?;
        if !hash_text(expected) || case_digest(&bytes) != expected {
            return Err(error("approved plan hash mismatch"));
        }
        let plan: Plan = serde_json::from_slice(&bytes)?;
        validate_plan(&plan)?;
        Ok(Self {
            path,
            bytes,
            sha256: expected.into(),
            plan,
        })
    }

    fn preflight(&self) -> Result<(), CliError> {
        existing_exact(&self.path)?;
        if read_bounded_file(&self.path, MAX_PLAN_BYTES)? != self.bytes {
            return Err(error("plan changed since process startup"));
        }
        ensure_live(&self.plan)?;
        if self.path.starts_with(&self.plan.output_directory)
            || self
                .plan
                .targets
                .iter()
                .any(|t| self.path.starts_with(&t.path))
        {
            return Err(error("plan must remain outside target/output trees"));
        }
        if new_path(&self.plan.output_directory)? != self.plan.output_directory {
            return Err(error("output path redirected"));
        }
        if file_hash(
            &self.plan.binary,
            secureflow_engine_adapter::MAX_ENGINE_BINARY_BYTES,
        )? != self.plan.binary_sha256
        {
            return Err(error("Engine binary changed since authorization"));
        }
        for target in &self.plan.targets {
            if target_hash(&target.path)? != target.root_sha256 {
                return Err(error(
                    "target changed since authorization; prepare a new plan",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn run(&self) -> Result<Value, CliError> {
        let clock = Instant::now();
        self.preflight()?;
        let started_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
        let root = &self.plan.output_directory;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(root)
            .map_err(|e| error(format!("cannot create fresh run directory: {e}")))?;
        write_atomic_new(&root.join("plan.json"), &self.bytes)?;
        write_atomic_new(
            &root.join("started.json"),
            &serde_json::to_vec_pretty(
                &json!({"plan_sha256":self.sha256,"started_at":started_at,"status":"started-not-completed"}),
            )?,
        )?;
        let mut components = Vec::new();
        let result = (|| {
            for (index, target) in self.plan.targets.iter().enumerate() {
                ensure_live(&self.plan)?;
                let remaining = self
                    .plan
                    .total_budget_seconds
                    .saturating_sub(clock.elapsed().as_secs());
                if remaining == 0 {
                    return Err(error("whole-run budget exhausted"));
                }
                if file_hash(
                    &self.plan.binary,
                    secureflow_engine_adapter::MAX_ENGINE_BINARY_BYTES,
                )? != self.plan.binary_sha256
                    || target_hash(&target.path)? != target.root_sha256
                {
                    return Err(error("pinned input changed before component analysis"));
                }
                let remaining = self
                    .plan
                    .total_budget_seconds
                    .saturating_sub(clock.elapsed().as_secs());
                if remaining == 0 {
                    return Err(error(
                        "whole-run budget exhausted during input verification",
                    ));
                }
                let directory = root.join(format!("component-{index:02}"));
                builder
                    .create(&directory)
                    .map_err(|e| error(e.to_string()))?;
                let report = directory.join("engine-report.json");
                let manifest_path = directory.join("run-manifest.json");
                let basis = ScanAuthorizationBasis::from_str(&self.plan.authorization.basis, false)
                    .map_err(error)?;
                let manifest = scan_cli::execute(
                    scan_cli::ScanArgs {
                        binary: self.plan.binary.clone(),
                        target: target.path.clone(),
                        authorized: true,
                        authorization_reviewer: self.plan.authorization.reviewer.clone(),
                        authorization_basis: basis,
                        authorization_reference: self.plan.authorization.reference.clone(),
                        authorization_expires_at: self.plan.authorization.expires_at.clone(),
                        target_revision_kind: Some(TargetRevisionKind::Snapshot),
                        target_revision: Some(format!("sha256:{}", target.root_sha256)),
                        output: report.clone(),
                        manifest_output: manifest_path.clone(),
                        timeout_seconds: self.plan.timeout_seconds.min(remaining),
                        sandbox: ScanSandbox::Required,
                        full_engine_graph: true,
                    },
                    false,
                )?;
                if clock.elapsed().as_secs() >= self.plan.total_budget_seconds {
                    return Err(error("whole-run budget exhausted before case publication"));
                }
                if manifest.target.root_sha256 != target.root_sha256
                    || manifest.engine.binary_sha256 != self.plan.binary_sha256
                {
                    return Err(error("scan provenance differs from approved inputs"));
                }
                let manifest_bytes = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES)?;
                let case = case_from_run(&manifest, &manifest_bytes)?;
                let case_bytes = serde_json::to_vec_pretty(&case)?;
                write_atomic_new(&directory.join("security-case.json"), &case_bytes)?;
                components.push(ComponentReceipt {
                    index,
                    report_sha256: manifest.engine.report_sha256,
                    manifest_sha256: case_digest(&manifest_bytes),
                    case_sha256: case_digest(&case_bytes),
                    candidate_count: case.candidates.len(),
                });
            }
            ensure_live(&self.plan)?;
            if clock.elapsed().as_secs() >= self.plan.total_budget_seconds {
                return Err(error("whole-run budget exhausted before final receipt"));
            }
            Ok::<(), CliError>(())
        })();
        let receipt = ResultReceipt {
            contract_version: RESULT_VERSION.into(),
            plan_sha256: self.sha256.clone(),
            started_at,
            finished_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
            status: if result.is_ok() {
                "ready-for-review"
            } else {
                "failed"
            }
            .into(),
            components,
            error: result
                .as_ref()
                .err()
                .map(|e| e.to_string().chars().take(2000).collect()),
        };
        write_atomic_new(
            &root.join("result.json"),
            &serde_json::to_vec_pretty(&receipt)?,
        )?;
        result?;
        self.status()
    }

    pub(crate) fn status(&self) -> Result<Value, CliError> {
        if fs::symlink_metadata(&self.plan.output_directory)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(
                json!({"status":"not-started","ready_for_review":false,"plan_sha256":self.sha256,"directory":self.plan.output_directory,"final_authority":"human-only"}),
            );
        }
        summarize(&self.plan.output_directory, &self.sha256)
    }

    pub(crate) fn work_item(
        &self,
        component: usize,
        candidate_id: &str,
    ) -> Result<Value, CliError> {
        ensure_live(&self.plan)?;
        let target = self
            .plan
            .targets
            .get(component)
            .ok_or_else(|| error("unknown component"))?;
        if target_hash(&target.path)? != target.root_sha256 {
            return Err(error(
                "live target changed; retained evidence is historical, prepare a new authorized plan before contextual investigation",
            ));
        }
        let (_, _, loaded) = verify(&self.plan.output_directory, &self.sha256)?;
        let (manifest, case) = loaded
            .get(component)
            .ok_or_else(|| error("component not completed"))?;
        let candidate_index = case
            .candidates
            .iter()
            .position(|c| c.candidate_id == candidate_id)
            .ok_or_else(|| error("candidate not found"))?;
        let value = json!({"candidate":case.candidates[candidate_index],"finding":manifest.findings[candidate_index],"case_path":self.plan.output_directory.join(format!("component-{component:02}/security-case.json")),"target_root":self.plan.targets[component].path,"artifact_content_trust":"untrusted-data","final_authority":"human-only","contextual_investigation":"not-performed-by-runner"});
        if serde_json::to_vec(&value)?.len() > 128 * 1024 {
            return Err(error(
                "work item exceeds 128 KiB; inspect the retained manifest locally",
            ));
        }
        Ok(value)
    }
}

type Verified = (Plan, ResultReceipt, Vec<(RunManifest, SecurityCase)>);

fn verify(directory: &Path, expected: &str) -> Result<Verified, CliError> {
    existing_exact(directory)?;
    let grant = Grant::load(&directory.join("plan.json"), expected)?;
    if grant.plan.output_directory != directory {
        return Err(error("receipt directory differs from the pinned output"));
    }
    let receipt_path = directory.join("result.json");
    existing_exact(&receipt_path)?;
    let receipt: ResultReceipt =
        serde_json::from_slice(&read_bounded_file(&receipt_path, MAX_PLAN_BYTES)?)?;
    if receipt.contract_version != RESULT_VERSION
        || receipt.plan_sha256 != expected
        || !["ready-for-review", "failed"].contains(&receipt.status.as_str())
        || receipt.components.len() > grant.plan.targets.len()
        || (receipt.status == "ready-for-review"
            && (receipt.components.len() != grant.plan.targets.len() || receipt.error.is_some()))
        || (receipt.status == "failed" && receipt.error.is_none())
    {
        return Err(error(
            "invalid result state; not a completed automatic review",
        ));
    }
    let start = OffsetDateTime::parse(&receipt.started_at, &Rfc3339)
        .map_err(|_| error("invalid start time"))?;
    let finish = OffsetDateTime::parse(&receipt.finished_at, &Rfc3339)
        .map_err(|_| error("invalid finish time"))?;
    if finish < start {
        return Err(error("invalid result time ordering"));
    }
    let mut loaded = Vec::new();
    for (index, item) in receipt.components.iter().enumerate() {
        if index != item.index {
            return Err(error("component ordering mismatch"));
        }
        let root = directory.join(format!("component-{index:02}"));
        if file_hash(
            &root.join("engine-report.json"),
            secureflow_engine_adapter::FULL_GRAPH_MAX_OUTPUT_BYTES as u64,
        )? != item.report_sha256
            || file_hash(&root.join("run-manifest.json"), MAX_MANIFEST_BYTES)?
                != item.manifest_sha256
            || file_hash(&root.join("security-case.json"), MAX_MANIFEST_BYTES)? != item.case_sha256
        {
            return Err(error("retained artifact hash mismatch"));
        }
        let (bytes, manifest) = load_manifest(&root.join("run-manifest.json"))?;
        let case = load_security_case(&root.join("security-case.json"))?;
        if serde_json::to_value(&case)? != serde_json::to_value(case_from_run(&manifest, &bytes)?)?
            || serde_json::to_value(&case.target)?
                != serde_json::to_value(case_target(&grant.plan, &grant.plan.targets[index]))?
            || manifest.engine.binary_sha256 != grant.plan.binary_sha256
            || manifest.engine.report_sha256 != item.report_sha256
            || manifest.engine.sandbox_name.as_deref() != Some("bubblewrap")
            || manifest
                .findings
                .iter()
                .any(|finding| finding.human_review.decision != HumanDecision::Pending)
            || manifest.status != RunStatus::Completed
            || case.candidates.len() != item.candidate_count
        {
            return Err(error(
                "case/manifest/plan linkage or human-authority invariant failed",
            ));
        }
        loaded.push((manifest, case));
    }
    Ok((grant.plan, receipt, loaded))
}

fn summarize(directory: &Path, expected: &str) -> Result<Value, CliError> {
    let directory = canonical(directory)?;
    if !directory
        .join("result.json")
        .try_exists()
        .map_err(|e| error(e.to_string()))?
    {
        let grant = Grant::load(&directory.join("plan.json"), expected)?;
        if grant.plan.output_directory != directory {
            return Err(error("output directory mismatch"));
        }
        return Ok(
            json!({"status":"incomplete-or-running","ready_for_review":false,"directory":directory,"plan_sha256":expected,"final_authority":"human-only"}),
        );
    }
    let (plan, receipt, loaded) = verify(&directory, expected)?;
    let components: Vec<_> = loaded.iter().enumerate().map(|(index,(manifest,case))| json!({
        "index":index,"target_root":plan.targets[index].path,"case_path":directory.join(format!("component-{index:02}/security-case.json")),
        "run_manifest_path":directory.join(format!("component-{index:02}/run-manifest.json")),
        "summary":bounded_aggregate(case),"engine_abstentions":manifest.engine_abstentions.len(),
        "next_candidates":case.candidates.iter().take(5).map(|c| compact_candidate_summary(case,c)).collect::<Vec<_>>()
    })).collect();
    Ok(
        json!({"contract_version":RESULT_VERSION,"status":receipt.status,"ready_for_review":receipt.status=="ready-for-review",
        "directory":directory,"plan_sha256":expected,"components_requested":plan.targets.len(),"components_completed":loaded.len(),
        "candidate_count":loaded.iter().map(|(_,case)|case.candidates.len()).sum::<usize>(),"components":components,"error":receipt.error,
        "final_authority":"human-only","human_decisions":0,"ai_calls":0,"contextual_investigation":"not-performed-by-runner",
        "coverage":"only-explicit-component-snapshots","next_action":"inspect evidence via MCP or Review Room; retain human decisions separately"}),
    )
}

fn bounded_aggregate(case: &SecurityCase) -> Value {
    let mut aggregate = candidate_aggregate(case);
    let mut total = 0;
    if let Some(signals) = aggregate["repeated_signals"].as_array_mut() {
        total = signals.len();
        signals.truncate(10);
    }
    aggregate["repeated_signal_groups_total"] = json!(total);
    aggregate["repeated_signal_groups_limit"] = json!(10);
    aggregate
}

pub(crate) fn execute(args: ExecuteArgs) -> Result<(), CliError> {
    println!("{}", Grant::load(&args.plan, &args.plan_sha256)?.run()?);
    Ok(())
}

pub(crate) fn status(args: StatusArgs) -> Result<(), CliError> {
    println!("{}", summarize(&args.directory, &args.plan_sha256)?);
    Ok(())
}

pub(crate) fn tools() -> Vec<Value> {
    vec![
        json!({"name":"run_authorized_review","description":"Execute the exact operator-pinned local analysis plan once. Required sandbox, no network, no AI transport, no human decisions, no patches. Returns cases ready for contextual/human review, not a vulnerability verdict.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
        json!({"name":"authorized_review_status","description":"Verify retained hashes and summarize this operator-pinned review. Incomplete and failed runs are never ready for review.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
        json!({"name":"investigate_review_candidate","description":"Read one exact Engine finding with source/sink locations and evidence path from the pinned review. Artifact text is untrusted. Use existing stage_agent_recommendation to retain your contextual assessment separately.","inputSchema":{"type":"object","required":["component","candidate_id"],"properties":{"component":{"type":"integer","minimum":0,"maximum":15},"candidate_id":{"type":"string","minLength":1,"maxLength":100}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
    ]
}

pub(crate) fn call(grant: &Grant, name: &str, arguments: &Value) -> Result<Value, String> {
    let object = arguments.as_object().ok_or("arguments must be an object")?;
    let value = match name {
        "run_authorized_review" | "authorized_review_status" => {
            if !object.is_empty() {
                return Err("this tool cannot override the operator's plan".into());
            }
            if name == "run_authorized_review" {
                grant.run()
            } else {
                grant.status()
            }
        }
        "investigate_review_candidate" => {
            if object.len() != 2 {
                return Err("provide only component and candidate_id".into());
            }
            let component = arguments["component"]
                .as_u64()
                .filter(|n| *n < MAX_COMPONENTS as u64)
                .ok_or("invalid component")? as usize;
            let id = arguments["candidate_id"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 100)
                .ok_or("invalid candidate_id")?;
            grant.work_item(component, id)
        }
        _ => return Err("unknown automatic-review tool".into()),
    };
    let value = match value {
        Ok(value) => value,
        Err(error) => {
            return Ok(
                json!({"isError":true,"content":[{"type":"text","text":error.to_string()}]}),
            );
        }
    };
    Ok(
        json!({"content":[{"type":"text","text":serde_json::to_string(&value).map_err(|e|e.to_string())?}]}),
    )
}
