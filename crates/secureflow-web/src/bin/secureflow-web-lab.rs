use secureflow_web::{
    MAX_CASE_BYTES, MAX_INVENTORY_BYTES, compare_inventory, lab_result_sarif, parse_inventory,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("secureflow-web-lab: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4 {
        return Err(
            "usage: secureflow-web-lab <inventory.json> <expected.json> <result.json> <result.sarif>"
                .into(),
        );
    }
    if arguments[2] == arguments[3] {
        return Err("result and SARIF outputs must be distinct".into());
    }
    let inventory_bytes = read_bounded(Path::new(&arguments[0]), MAX_INVENTORY_BYTES)?;
    let expected_bytes = read_bounded(Path::new(&arguments[1]), MAX_CASE_BYTES)?;
    let inventory = parse_inventory(&inventory_bytes)?;
    let result = compare_inventory(&inventory, &expected_bytes)?;
    let result_bytes = serde_json::to_vec_pretty(&result)?;
    let sarif_bytes = serde_json::to_vec_pretty(&lab_result_sarif(&result)?)?;
    write_new(Path::new(&arguments[2]), &result_bytes)?;
    write_new(Path::new(&arguments[3]), &sarif_bytes)?;
    println!(
        "web lab complete: matched={} missing={} unexpected={} result={} sarif={}",
        result.counts.matched_routes,
        result.counts.missing_routes,
        result.counts.unexpected_routes,
        Path::new(&arguments[2]).display(),
        Path::new(&arguments[3]).display()
    );
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
