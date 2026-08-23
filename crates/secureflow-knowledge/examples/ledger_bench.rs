use secureflow_knowledge::{
    KnowledgeRecordV1, KnowledgeRecordV2, RECORD_VERSION, SourceLicense, SourceLicenseStatus,
    read_ledger,
};
use std::error::Error;
use std::time::Instant;

fn main() -> Result<(), Box<dyn Error>> {
    let mut iterations = 5_usize;
    let mut sizes = Vec::new();
    let mut record_version = String::from("v2");
    let mut arguments = std::env::args().skip(1);
    while let Some(value) = arguments.next() {
        if value == "--iterations" {
            iterations = arguments
                .next()
                .ok_or("--iterations requires a positive integer")?
                .parse()?;
        } else if value == "--record-version" {
            record_version = arguments
                .next()
                .ok_or("--record-version requires v1 or v2")?;
        } else {
            sizes.push(value.parse::<usize>()?);
        }
    }
    if iterations == 0 {
        return Err("iterations must be positive".into());
    }
    let sizes = if sizes.is_empty() {
        vec![100, 1_000, 10_000]
    } else {
        sizes
    };
    let template: KnowledgeRecordV1 = serde_json::from_str(include_str!(
        "../../../tests/fixtures/minimal-knowledge.jsonl"
    ))?;
    if !matches!(record_version.as_str(), "v1" | "v2") {
        return Err("--record-version must be v1 or v2".into());
    }

    println!(
        "record_version,records,bytes,iterations,load_validate_median_ms,load_validate_max_ms,filter_median_us,matches"
    );
    for count in sizes {
        if count == 0 {
            return Err("record counts must be positive".into());
        }
        let mut bytes = Vec::new();
        for index in 0..count {
            let record_id = format!("sf_kb_{:064x}", index + 1);
            let finding_id = format!("sf_finding_{:064x}", index + 1);
            let rule_id = if index % 2 == 0 {
                "SE1001".into()
            } else {
                "SE1006".into()
            };
            if record_version == "v1" {
                let mut record = template.clone();
                record.record_id = record_id;
                record.finding_id = finding_id;
                record.rule_id = rule_id;
                serde_json::to_writer(&mut bytes, &record)?;
            } else {
                let record = KnowledgeRecordV2 {
                    record_version: RECORD_VERSION.into(),
                    record_id,
                    observation_fingerprint: format!("sf_obs_{:064x}", index + 1),
                    duplicate_of_record_id: None,
                    manifest_sha256: template.manifest_sha256.clone(),
                    manifest_created_at: template.manifest_created_at.clone(),
                    target_sha256: template.target_sha256.clone(),
                    target_revision: None,
                    source_license: SourceLicense::operator_declared(
                        SourceLicenseStatus::Unknown,
                        None,
                        None,
                    )?,
                    engine_name: template.engine_name.clone(),
                    engine_version: template.engine_version.clone(),
                    engine_binary_sha256: template.engine_binary_sha256.clone(),
                    finding_id,
                    engine_fingerprint: template.engine_fingerprint.clone(),
                    title: template.title.clone(),
                    rule_id,
                    taxonomy: template.taxonomy.clone(),
                    severity: template.severity,
                    confidence: template.confidence,
                    source_location: template.source_location.clone(),
                    sink_location: template.sink_location.clone(),
                    invariant: template.invariant.clone(),
                    evidence_path: template.evidence_path.clone(),
                    decision: template.decision,
                    reviewer: template.reviewer.clone(),
                    reviewed_at: template.reviewed_at.clone(),
                    rationale_sha256: template.rationale_sha256.clone(),
                    evidence_reference_sha256: template.evidence_reference_sha256.clone(),
                };
                serde_json::to_writer(&mut bytes, &record)?;
            }
            bytes.push(b'\n');
        }
        let path = std::env::temp_dir().join(format!(
            "secureflow-ledger-bench-{}-{count}.jsonl",
            std::process::id()
        ));
        if path.exists() {
            return Err(format!("temporary benchmark path already exists: {}", path.display()).into());
        }
        std::fs::write(&path, &bytes)?;
        let mut load_samples = Vec::with_capacity(iterations);
        let mut filter_samples = Vec::with_capacity(iterations);
        let mut matches = 0;
        for _ in 0..iterations {
            let load_started = Instant::now();
            let records = read_ledger(&path)?;
            load_samples.push(load_started.elapsed().as_secs_f64() * 1_000.0);
            let filter_started = Instant::now();
            matches = records
                .iter()
                .filter(|record| record.rule_id() == "SE1006")
                .count();
            filter_samples.push(filter_started.elapsed().as_secs_f64() * 1_000_000.0);
        }
        std::fs::remove_file(&path)?;
        load_samples.sort_by(f64::total_cmp);
        filter_samples.sort_by(f64::total_cmp);
        println!(
            "{record_version},{count},{},{iterations},{:.3},{:.3},{:.3},{matches}",
            bytes.len(),
            median(&load_samples),
            load_samples[load_samples.len() - 1],
            median(&filter_samples),
        );
    }
    Ok(())
}

fn median(samples: &[f64]) -> f64 {
    let middle = samples.len() / 2;
    if samples.len() % 2 == 0 {
        (samples[middle - 1] + samples[middle]) / 2.0
    } else {
        samples[middle]
    }
}
