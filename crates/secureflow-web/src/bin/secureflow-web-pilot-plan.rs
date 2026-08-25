use secureflow_web::{mitiquete_pilot_draft, parse_observation_pilot, seal_observation_pilot};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn main() {
    if let Err(error) = run() {
        eprintln!("secureflow-web-pilot-plan: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4 {
        return Err(
            "usage: secureflow-web-pilot-plan <authorization-reference> <issued-at-rfc3339> <expires-at-rfc3339> <pilot.json>"
                .into(),
        );
    }
    let reference = arguments[0]
        .to_str()
        .ok_or("authorization reference must be UTF-8")?;
    let issued_at = arguments[1].to_str().ok_or("issued-at must be UTF-8")?;
    let expires_at = arguments[2].to_str().ok_or("expires-at must be UTF-8")?;
    let draft = mitiquete_pilot_draft(reference, issued_at, expires_at)?;
    let draft_bytes = serde_json::to_vec(&draft)?;
    let pilot = seal_observation_pilot(&draft_bytes, Some(issued_at.into()))?;
    let bytes = serde_json::to_vec_pretty(&pilot)?;
    let issued = OffsetDateTime::parse(issued_at, &Rfc3339)?;
    parse_observation_pilot(&bytes, issued)?;
    let output_path = Path::new(&arguments[3]);
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
        "Mitiquete pilot prepared: readiness={:?} blockers={} network_executed=false output={}",
        pilot.readiness,
        pilot.blockers.len(),
        output_path.display()
    );
    Ok(())
}
