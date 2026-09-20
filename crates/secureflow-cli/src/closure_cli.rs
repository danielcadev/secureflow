//! Read-only closure verification against an uncommitted, isolated checkout.
use crate::{CliError, MAX_MANIFEST_BYTES, read_bounded_file};
use clap::Args;
use secureflow_case::closure::{ClosureReport, relative_path};
use secureflow_case::remediation::RemediationHandoff;
use secureflow_case::{SecurityCase, digest};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Args)]
pub struct CheckArgs {
    #[arg(long)]
    report: PathBuf,
    #[arg(long, required = true)]
    case: Vec<PathBuf>,
    #[arg(long)]
    handoff: Option<PathBuf>,
    #[arg(long)]
    repository: PathBuf,
    /// Directory containing retained review and test evidence; no scripts are executed.
    #[arg(long)]
    evidence_root: PathBuf,
}

fn error(message: impl Into<String>) -> CliError {
    CliError::Closure(message.into())
}

fn git(repository: &Path, args: &[&str]) -> Result<Vec<u8>, CliError> {
    let output = Command::new("git")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(repository)
        .args(args)
        .output()
        .map_err(|e| error(format!("could not inspect repository: {e}")))?;
    if !output.status.success() {
        return Err(error("Git repository inspection failed"));
    }
    Ok(output.stdout)
}

fn file_hash(root: &Path, relative: &str) -> Result<Option<String>, CliError> {
    if !relative_path(relative) {
        return Err(error("invalid relative artifact path"));
    }
    let mut path = root.to_path_buf();
    let parts: Vec<_> = relative.split('/').collect();
    for (index, component) in parts.iter().enumerate() {
        path.push(component);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(error(format!("cannot inspect {relative}: {e}"))),
        };
        if metadata.file_type().is_symlink()
            || (index + 1 < parts.len() && !metadata.is_dir())
            || (index + 1 == parts.len() && !metadata.is_file())
        {
            return Err(error(format!(
                "artifact must use regular files and private directory ancestors: {relative}"
            )));
        }
    }
    Ok(Some(digest(&read_bounded_file(&path, MAX_MANIFEST_BYTES)?)))
}

pub fn check(args: CheckArgs) -> Result<(), CliError> {
    let report: ClosureReport =
        serde_json::from_slice(&read_bounded_file(&args.report, MAX_MANIFEST_BYTES)?)?;
    let mut loaded = Vec::new();
    for path in &args.case {
        let bytes = read_bounded_file(path, MAX_MANIFEST_BYTES)?;
        let parsed = SecurityCase::parse(&bytes)?;
        loaded.push((bytes, parsed));
    }
    let borrowed: Vec<_> = loaded.iter().map(|(b, c)| (b.as_slice(), c)).collect();
    let handoff = args
        .handoff
        .as_ref()
        .map(|path| {
            Ok::<_, CliError>(RemediationHandoff::parse(&read_bounded_file(
                path,
                MAX_MANIFEST_BYTES,
            )?)?)
        })
        .transpose()?;
    let summary = report.reconcile(&borrowed, handoff.as_ref())?;
    let repository = args
        .repository
        .canonicalize()
        .map_err(|e| error(e.to_string()))?;
    let evidence_root = args
        .evidence_root
        .canonicalize()
        .map_err(|e| error(e.to_string()))?;
    if evidence_root.starts_with(&repository) || !evidence_root.is_dir() {
        return Err(error(
            "retain closure evidence in a directory outside the repository",
        ));
    }
    let top = git(&repository, &["rev-parse", "--show-toplevel"])?;
    let top = std::str::from_utf8(&top)
        .map_err(|_| error("repository path is not UTF-8"))?
        .trim_end();
    if Path::new(top) != repository {
        return Err(error("--repository must be the checkout root"));
    }
    let head = git(&repository, &["rev-parse", "HEAD"])?;
    if head != format!("{}\n", report.base_commit).as_bytes() {
        return Err(error(
            "checkout HEAD differs from closure base_commit; verify before committing",
        ));
    }
    if !git(&repository, &["ls-files", "--unmerged", "-z"])?.is_empty() {
        return Err(error("checkout has unresolved conflicts"));
    }
    let mut names = git(
        &repository,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "--no-renames",
            "-z",
            "HEAD",
            "--",
        ],
    )?;
    names.extend(git(
        &repository,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?);
    let mut actual = BTreeSet::new();
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        actual.insert(
            std::str::from_utf8(name)
                .map_err(|_| error("changed filename is not UTF-8"))?
                .to_owned(),
        );
    }
    let expected: BTreeSet<_> = report.files.iter().map(|file| file.path.clone()).collect();
    if actual != expected {
        return Err(error(
            "changed file inventory differs from closure report; isolate unrelated tracked and untracked changes",
        ));
    }
    for file in &report.files {
        if file_hash(&repository, &file.path)? != file.sha256 {
            return Err(error(format!("patch content changed: {}", file.path)));
        }
        #[cfg(unix)]
        if file.sha256.is_some() {
            use std::os::unix::fs::PermissionsExt;
            let metadata =
                fs::metadata(repository.join(&file.path)).map_err(|e| error(e.to_string()))?;
            let mode = if metadata.permissions().mode() & 0o111 == 0 {
                "100644"
            } else {
                "100755"
            };
            if mode != file.mode {
                return Err(error("patch file mode changed"));
            }
        }
        #[cfg(not(unix))]
        return Err(error(
            "closure file-mode verification currently requires Unix",
        ));
        // Byte hashes do not capture mode changes; reject symlinks/gitlinks even when deleted.
        let tree = git(&repository, &["ls-tree", "HEAD", "--", &file.path])?;
        if tree.starts_with(b"120000 ") || tree.starts_with(b"160000 ") {
            return Err(error(
                "closure does not accept symlink or submodule patches",
            ));
        }
    }
    for artifact in report
        .cases
        .iter()
        .flat_map(|case| &case.outcomes)
        .flat_map(|outcome| &outcome.evidence)
        .chain(report.checks.iter().map(|check| &check.evidence))
    {
        if file_hash(&evidence_root, &artifact.path)?.as_deref() != Some(&artifact.sha256) {
            return Err(error(format!(
                "retained evidence changed or is missing: {}",
                artifact.path
            )));
        }
    }
    println!("{}", serde_json::to_string_pretty(&summary)?);
    if !summary.ready_for_review {
        return Err(error(
            "closure remains incomplete: pending/blocked candidates or missing/failed checks",
        ));
    }
    Ok(())
}
