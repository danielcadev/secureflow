use secureflow_web::{
    MAX_INVENTORY_BYTES, MAX_SCOPE_BYTES, hash_repository_tree, infer_local_apis, parse_inventory,
    parse_scope,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use time::OffsetDateTime;

fn main() {
    if let Err(error) = run() {
        eprintln!("secureflow-web-infer: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4 {
        return Err(
            "usage: secureflow-web-infer <authorized-root> <scope.json> <inventory.json> <inference.json>"
                .into(),
        );
    }
    let root = Path::new(&arguments[0]);
    let output = Path::new(&arguments[3]);
    require_output_outside_target(root, output)?;
    let scope_bytes = read_bounded(Path::new(&arguments[1]), MAX_SCOPE_BYTES)?;
    let inventory_bytes = read_bounded(Path::new(&arguments[2]), MAX_INVENTORY_BYTES)?;
    let now = OffsetDateTime::now_utc();
    let scope = parse_scope(&scope_bytes, now)?;
    let inventory = parse_inventory(&inventory_bytes)?;
    let root_sha256 = hash_repository_tree(
        root,
        scope.draft.limits.max_files,
        scope.draft.limits.max_file_bytes,
        scope.draft.limits.max_total_bytes,
    )?;
    let inference = infer_local_apis(root, &scope, &root_sha256, &inventory, now)?;
    let bytes = serde_json::to_vec_pretty(&inference)?;
    write_new(output, &bytes)?;
    println!(
        "web inference complete: candidates={} correlated={} review={} abstentions={} output={}",
        inference.stats.candidates,
        inference.stats.correlated_local,
        inference.stats.needs_human_review,
        inference.stats.abstentions,
        output.display()
    );
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(format!("input is not a bounded regular file: {}", path.display()).into());
    }
    let input = File::open(path)?;
    let capacity = usize::try_from(metadata.len())?;
    let mut bytes = Vec::with_capacity(capacity);
    input
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(format!("input exceeds byte limit: {}", path.display()).into());
    }
    Ok(bytes)
}

fn require_output_outside_target(
    root: &Path,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = fs::canonicalize(root)?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)?;
    if parent.starts_with(&root) {
        return Err("inference output must be outside the authorized target root".into());
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(path)?;
    output.write_all(bytes)?;
    output.sync_all()
}
