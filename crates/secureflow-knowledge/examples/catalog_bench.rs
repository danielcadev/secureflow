use secureflow_knowledge::catalog::{Catalog, CatalogSource};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Instant;
use time::OffsetDateTime;

const BATCH_RECORDS: usize = 50_000;

fn main() -> Result<(), Box<dyn Error>> {
    let mut iterations = 5_usize;
    let mut sizes = Vec::new();
    let mut benchmark_root = std::env::temp_dir();
    let mut arguments = std::env::args().skip(1);
    while let Some(value) = arguments.next() {
        if value == "--iterations" {
            iterations = arguments
                .next()
                .ok_or("--iterations requires a positive integer")?
                .parse()?;
        } else if value == "--root" {
            benchmark_root = PathBuf::from(
                arguments
                    .next()
                    .ok_or("--root requires a local directory path")?,
            );
        } else {
            sizes.push(value.parse::<usize>()?);
        }
    }
    if iterations == 0 {
        return Err("iterations must be positive".into());
    }
    let sizes = if sizes.is_empty() {
        vec![100_000, 500_000, 1_000_000]
    } else {
        sizes
    };
    println!(
        "source_records,canonical_vulnerabilities,database_bytes,raw_revision_bytes,normalize_ms,index_build_ms,total_ingest_ms,records_per_second,lookup_median_us,fts_median_us,package_median_us,expected_canonical_vulnerabilities,exact_alias_reduction,dedup_gate_passed,quick_check,foreign_key_violations,search_index_status,integrity_gate_passed"
    );
    for count in sizes {
        if count == 0 || count > 1_000_000 {
            return Err("record counts must be between 1 and 1,000,000".into());
        }
        run_size(count, iterations, &benchmark_root)?;
    }
    Ok(())
}

fn run_size(count: usize, iterations: usize, benchmark_root: &Path) -> Result<(), Box<dyn Error>> {
    let root = benchmark_root.join(format!(
        "secureflow-catalog-bench-{}-{}-{count}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    let path = root.join("catalog.sqlite3");
    let mut catalog = Catalog::open_or_create(&path)?;
    let source = CatalogSource {
        name: "secureflow-synthetic-osv".into(),
        license_expression: "CC0-1.0".into(),
        license_evidence_sha256: "a".repeat(64),
        locator: "urn:secureflow:synthetic-catalog-benchmark:v1".into(),
    };
    let started = Instant::now();
    let mut batch = Vec::with_capacity(BATCH_RECORDS);
    for index in 0..count {
        batch.push(synthetic_record(index)?);
        if batch.len() == BATCH_RECORDS {
            catalog.import_osv_batch_deferred_search(&source, batch.drain(..))?;
        }
    }
    if !batch.is_empty() {
        catalog.import_osv_batch_deferred_search(&source, batch.drain(..))?;
    }
    let normalize_seconds = started.elapsed().as_secs_f64();
    let index_started = Instant::now();
    catalog.rebuild_search_index()?;
    let index_seconds = index_started.elapsed().as_secs_f64();
    let ingest_seconds = normalize_seconds + index_seconds;
    let stats = catalog.stats()?;
    let integrity = catalog.check_integrity()?;
    let expected_canonical_vulnerabilities = expected_canonical_count(count);
    let dedup_gate_passed =
        stats.canonical_vulnerabilities == u64::try_from(expected_canonical_vulnerabilities)?;
    let exact_alias_reduction = stats
        .source_records
        .saturating_sub(stats.canonical_vulnerabilities);
    let integrity_gate_passed = integrity.quick_check == "ok"
        && integrity.foreign_key_violations == 0
        && integrity.search_index_status == "ready";
    let lookup_id = duplicate_cve_id(count.saturating_sub(1));
    let last_index = count.saturating_sub(1);
    let crates_index = last_index - (last_index % 3);
    let package_name = format!("fixture-package-{}", crates_index % 4_096);
    let mut lookup_samples = Vec::with_capacity(iterations);
    let mut fts_samples = Vec::with_capacity(iterations);
    let mut package_samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let query_started = Instant::now();
        let _ = catalog.lookup_identifier(&lookup_id, 20)?;
        lookup_samples.push(query_started.elapsed().as_secs_f64() * 1_000_000.0);

        let query_started = Instant::now();
        let _ = catalog.search_text("command injection", 20)?;
        fts_samples.push(query_started.elapsed().as_secs_f64() * 1_000_000.0);

        let query_started = Instant::now();
        let _ = catalog.search_package("crates.io", &package_name, 20)?;
        package_samples.push(query_started.elapsed().as_secs_f64() * 1_000_000.0);
    }
    lookup_samples.sort_by(f64::total_cmp);
    fts_samples.sort_by(f64::total_cmp);
    package_samples.sort_by(f64::total_cmp);
    println!(
        "{},{},{},{},{:.3},{:.3},{:.3},{:.1},{:.3},{:.3},{:.3},{},{},{},{},{},{},{}",
        stats.source_records,
        stats.canonical_vulnerabilities,
        stats.database_bytes,
        stats.raw_revision_bytes,
        normalize_seconds * 1_000.0,
        index_seconds * 1_000.0,
        ingest_seconds * 1_000.0,
        count as f64 / ingest_seconds,
        median(&lookup_samples),
        median(&fts_samples),
        median(&package_samples),
        expected_canonical_vulnerabilities,
        exact_alias_reduction,
        dedup_gate_passed,
        integrity.quick_check,
        integrity.foreign_key_violations,
        integrity.search_index_status,
        integrity_gate_passed,
    );
    drop(catalog);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

fn synthetic_record(index: usize) -> Result<Vec<u8>, serde_json::Error> {
    let (id, aliases) = if index % 10 == 9 {
        (
            format!("GHSA-SYNTH-{index:09}"),
            vec![duplicate_cve_id(index)],
        )
    } else {
        (duplicate_cve_id(index), Vec::new())
    };
    let ecosystem = match index % 3 {
        0 => "crates.io",
        1 => "npm",
        _ => "GitHub Actions",
    };
    serde_json::to_vec(&serde_json::json!({
        "schema_version": "1.7.0",
        "id": id,
        "modified": "2026-08-23T00:00:00Z",
        "aliases": aliases,
        "summary": format!("Synthetic command injection advisory {index}"),
        "details": "Deterministic generated benchmark record; not a real vulnerability.",
        "affected": [{
            "package": {
                "ecosystem": ecosystem,
                "name": format!("fixture-package-{}", index % 4_096)
            },
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]
            }]
        }]
    }))
}

fn duplicate_cve_id(index: usize) -> String {
    let canonical_index = if index % 10 == 9 { index - 1 } else { index };
    format!("CVE-2099-{canonical_index:09}")
}

fn expected_canonical_count(source_records: usize) -> usize {
    source_records - source_records / 10
}

fn median(samples: &[f64]) -> f64 {
    let middle = samples.len() / 2;
    if samples.len().is_multiple_of(2) {
        (samples[middle - 1] + samples[middle]) / 2.0
    } else {
        samples[middle]
    }
}

#[cfg(test)]
mod tests {
    use super::expected_canonical_count;

    #[test]
    fn expected_canonical_count_matches_every_tenth_alias() {
        assert_eq!(expected_canonical_count(9), 9);
        assert_eq!(expected_canonical_count(10), 9);
        assert_eq!(expected_canonical_count(50_000), 45_000);
        assert_eq!(expected_canonical_count(100_000), 90_000);
    }
}
