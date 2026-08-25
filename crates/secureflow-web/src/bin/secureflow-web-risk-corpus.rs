use secureflow_web::{generate_api_risk_corpus, parse_api_risk_corpus};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const MAX_LICENSE_BYTES: u64 = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("secureflow-web-risk-corpus: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 {
        return Err(
            "usage: secureflow-web-risk-corpus <synthetic-license-file> <corpus.json>".into(),
        );
    }
    let license_path = Path::new(&arguments[0]);
    let metadata = fs::symlink_metadata(license_path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_LICENSE_BYTES
    {
        return Err("license input must be a bounded regular file".into());
    }
    let license = fs::read(license_path)?;
    let license_sha256 = sha256_hex(&license);
    let corpus = generate_api_risk_corpus(&license_sha256)?;
    let bytes = serde_json::to_vec_pretty(&corpus)?;
    parse_api_risk_corpus(&bytes)?;
    let output_path = Path::new(&arguments[1]);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(output_path)?;
    output.write_all(&bytes)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    println!(
        "API risk corpus generated: pairs={} risky={} safe={} output={}",
        corpus.counts.canonical_pairs,
        corpus.counts.risky_scenarios,
        corpus.counts.safe_controls,
        output_path.display()
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
