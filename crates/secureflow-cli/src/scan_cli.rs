//! Shared scan entrypoint; automated callers retain the same adapter gates.
use super::*;

#[derive(Debug, clap::Args)]
pub(crate) struct ScanArgs {
    /// Engine binary path.
    #[arg(long)]
    pub(crate) binary: PathBuf,
    /// Authorized repository or fixture path.
    pub(crate) target: PathBuf,
    /// Require an explicit authorization acknowledgement.
    #[arg(long)]
    pub(crate) authorized: bool,
    /// Human identity asserting that this target is in scope.
    #[arg(long)]
    pub(crate) authorization_reviewer: String,
    /// Documented basis for authorization.
    #[arg(long, value_enum, default_value_t = ScanAuthorizationBasis::LocalProject)]
    pub(crate) authorization_basis: ScanAuthorizationBasis,
    /// Local ticket, policy, agreement or other scope reference.
    #[arg(long)]
    pub(crate) authorization_reference: Option<String>,
    /// Optional RFC3339 expiration for the authorization.
    #[arg(long)]
    pub(crate) authorization_expires_at: Option<String>,
    /// Kind of explicitly recorded target revision.
    #[arg(long, value_enum, requires = "target_revision")]
    pub(crate) target_revision_kind: Option<TargetRevisionKind>,
    /// Commit, snapshot or working-tree identifier supplied by the operator.
    #[arg(long, requires = "target_revision_kind")]
    pub(crate) target_revision: Option<String>,
    /// Raw secure-json-v1 output path.
    #[arg(long)]
    pub(crate) output: PathBuf,
    /// secureflow-run-v2 manifest output path.
    #[arg(long)]
    pub(crate) manifest_output: PathBuf,
    /// Process timeout in seconds.
    #[arg(long, default_value_t = 120)]
    pub(crate) timeout_seconds: u64,
    /// Linux process isolation policy. Required is the secure default.
    #[arg(long, value_enum, default_value_t = ScanSandbox::Required)]
    pub(crate) sandbox: ScanSandbox,
    /// Require the Engine to return a complete evidence graph.
    #[arg(long)]
    pub(crate) full_engine_graph: bool,
}

pub(crate) fn execute(args: ScanArgs, announce: bool) -> Result<RunManifest, CliError> {
    let ScanArgs {
        binary,
        target,
        authorized,
        authorization_reviewer,
        authorization_basis,
        authorization_reference,
        authorization_expires_at,
        target_revision_kind,
        target_revision,
        output,
        manifest_output,
        timeout_seconds,
        sandbox,
        full_engine_graph,
    } = args;
    if !authorized {
        return Err(CliError::AuthorizationRequired);
    }
    if timeout_seconds == 0 || timeout_seconds > MAX_ENGINE_TIMEOUT_SECONDS {
        return Err(CliError::InvalidTimeout {
            provided: timeout_seconds,
            maximum: MAX_ENGINE_TIMEOUT_SECONDS,
        });
    }
    ensure_output_distinct(&output, &[&binary, &target, &manifest_output])?;
    ensure_output_distinct(&manifest_output, &[&binary, &target, &output])?;
    ensure_output_outside_tree(&output, &target)?;
    ensure_output_outside_tree(&manifest_output, &target)?;
    let authorization_reviewer =
        checked_review_field(authorization_reviewer.trim(), "authorization_reviewer", 200)?;
    let authorization_reference = authorization_reference
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| checked_review_field(value, "authorization_reference", 300))
        .transpose()?;
    if matches!(
        authorization_basis,
        ScanAuthorizationBasis::WrittenConsent
            | ScanAuthorizationBasis::OrganizationPolicy
            | ScanAuthorizationBasis::OtherDocumented
    ) && authorization_reference.is_none()
    {
        return Err(CliError::AuthorizationReferenceRequired(
            scan_authorization_basis_label(authorization_basis),
        ));
    }
    let authorization_expires_at = authorization_expires_at
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let created = OffsetDateTime::now_utc();
    let authorization_expiration = authorization_expires_at
        .as_deref()
        .map(|value| {
            OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
                CliError::Manifest(secureflow_model::ModelError::InvalidTimestamp(
                    "target.authorization.expires_at",
                ))
            })
        })
        .transpose()?;
    if authorization_expiration.is_some_and(|expires_at| expires_at <= created) {
        return Err(CliError::AuthorizationExpired);
    }
    let target_revision = target_revision
        .as_deref()
        .map(str::trim)
        .map(|value| checked_review_field(value, "target_revision", 200))
        .transpose()?;
    if target_revision_kind == Some(TargetRevisionKind::Git)
        && target_revision
            .as_deref()
            .is_some_and(|value| !valid_full_git_revision(value))
    {
        return Err(CliError::Manifest(
            secureflow_model::ModelError::InvalidRevision,
        ));
    }
    let revision = target_revision_kind
        .zip(target_revision)
        .map(|(kind, value)| Revision {
            kind: kind.into(),
            value,
        });
    let mut config = EngineConfig::default_scan(binary, target);
    config.sandbox = sandbox.into();
    config.timeout = Duration::from_secs(timeout_seconds);
    config.max_cpu_seconds = timeout_seconds.saturating_add(1);
    if full_engine_graph {
        config.request_full_graph();
    }
    let created_at = created.format(&Rfc3339)?;
    let target_hash = sha256_target(&config.target).map_err(|source| CliError::TargetHash {
        path: config.target.clone(),
        source,
    })?;
    if let Some(expires_at) = authorization_expiration {
        let remaining = Duration::try_from(expires_at - OffsetDateTime::now_utc())
            .ok()
            .and_then(|remaining| remaining.checked_sub(AUTHORIZATION_EXPIRY_MARGIN))
            .filter(|remaining| !remaining.is_zero())
            .ok_or(CliError::AuthorizationExpired)?;
        config.timeout = config.timeout.min(remaining);
        config.max_cpu_seconds = config.timeout.as_secs().saturating_add(1);
    }
    let configuration_sha256 = config.configuration_sha256();
    let result = run(&config)?;
    let completed_target_hash =
        sha256_target(&config.target).map_err(|source| CliError::TargetHash {
            path: config.target.clone(),
            source,
        })?;
    if completed_target_hash != target_hash {
        return Err(CliError::TargetChangedDuringScan(config.target.clone()));
    }
    let completed = OffsetDateTime::now_utc();
    if authorization_expiration.is_some_and(|expires_at| expires_at <= completed) {
        return Err(CliError::AuthorizationExpired);
    }
    let completed_at = completed.format(&Rfc3339)?;
    let imported_report = result.import_report()?;
    let mut findings = imported_report.findings;
    let engine_abstentions = imported_report.abstentions;
    prioritize_findings(&mut findings);
    let duplicate_count = deduplicate_findings(&mut findings);
    let label = config
        .target
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "target".into());
    let manifest = RunManifest {
        contract_version: CONTRACT_VERSION.into(),
        run_id: format!(
            "sf_run_{}_{:x}",
            OffsetDateTime::now_utc().unix_timestamp_nanos(),
            std::process::id()
        ),
        status: RunStatus::Completed,
        created_at,
        completed_at: Some(completed_at),
        target: Target {
            label,
            root_sha256: target_hash,
            revision,
            authorization: Authorization {
                status: AuthorizationStatus::Authorized,
                basis: authorization_basis.into(),
                reviewer: authorization_reviewer,
                reference: authorization_reference,
                expires_at: authorization_expires_at,
            },
        },
        engine: EngineProvenance {
            name: "secure-engine".into(),
            version: imported_report.engine_version,
            binary_sha256: result.binary_sha256.clone(),
            report_schema: ENGINE_REPORT_SCHEMA.into(),
            report_sha256: result.report_sha256(),
            report_fingerprint: Some(imported_report.report_fingerprint),
            graph: imported_report.graph,
            sandbox_name: result.sandboxed.then(|| "bubblewrap".into()),
            sandbox_binary_sha256: result.sandbox_binary_sha256.clone(),
        },
        configuration_sha256: Some(configuration_sha256.clone()),
        phases: Phases {
            deterministic: PhaseStatus::Completed,
            prioritization: PhaseStatus::Completed,
            validation: PhaseStatus::Skipped,
            evaluation: PhaseStatus::Skipped,
        },
        artifacts: Vec::new(),
        summary: Some(Summary {
            candidate_count: findings.len() as u64,
            duplicate_count: duplicate_count as u64,
            validated_count: 0,
            rejected_count: 0,
            abstained_count: 0,
            ai_calls: 0,
            ai_input_tokens: 0,
            ai_output_tokens: 0,
        }),
        findings,
        engine_abstentions,
        evaluation: Some(EvaluationReference {
            harness: secureflow_model::EvaluationHarness::LocalFixture,
            harness_version: None,
            manifest_sha256: None,
            result_sha256: None,
            status: secureflow_model::EvaluationStatus::NotRun,
        }),
    };
    manifest.validate()?;
    write_atomic(&output, &result.stdout)?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    write_atomic(&manifest_output, &manifest_bytes)?;
    if announce {
        println!(
            "run completed: report={} manifest={} candidates={} engine_abstentions={} exit={} timed_out={} binary_sha256={} configuration_sha256={} sandboxed={} sandbox_binary_sha256={}",
            output.display(),
            manifest_output.display(),
            manifest.findings.len(),
            manifest.engine_abstentions.len(),
            result.status,
            result.timed_out,
            result.binary_sha256,
            configuration_sha256,
            result.sandboxed,
            result.sandbox_binary_sha256.as_deref().unwrap_or("none"),
        );
    }
    Ok(manifest)
}
