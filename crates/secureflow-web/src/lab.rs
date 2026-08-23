use crate::inventory::{HttpMethod, RouteKind, WebInventory};
use crate::scope::{sha256_hex, valid_sha256, valid_text};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use thiserror::Error;

pub const CASE_VERSION: &str = "secureflow-web-case-v1";
pub const LAB_RESULT_VERSION: &str = "secureflow-web-lab-result-v1";
pub const MAX_CASE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_LAB_RESULT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebCase {
    pub contract_version: String,
    pub case_id: String,
    pub lineage_group: String,
    pub split: CaseSplit,
    pub license: CaseLicense,
    pub routes: Vec<RouteExpectation>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseSplit {
    Development,
    Validation,
    Holdout,
    PostOpen,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLicense {
    pub spdx: String,
    pub provenance: String,
    pub license_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteExpectation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    pub kind: RouteKind,
    pub methods: Vec<HttpMethod>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebLabResult {
    pub contract_version: String,
    pub run_id: String,
    pub case_id: String,
    pub inventory_id: String,
    pub expected_sha256: String,
    pub counts: LabCounts,
    pub metrics: LabMetrics,
    pub mismatches: Vec<LabMismatch>,
    pub safety: LabSafety,
    pub claims: LabClaims,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabCounts {
    pub expected_routes: u64,
    pub reported_routes: u64,
    pub matched_routes: u64,
    pub missing_routes: u64,
    pub unexpected_routes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabMetrics {
    pub route_precision: LabMetric,
    pub route_recall: LabMetric,
    pub route_f1: LabMetric,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabMetric {
    pub numerator: u64,
    pub denominator: u64,
    pub basis_points: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabMismatch {
    pub kind: LabMismatchKind,
    pub route: RouteExpectation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LabMismatchKind {
    MissingExpected,
    UnexpectedActual,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabSafety {
    pub network_used: bool,
    pub target_code_executed: bool,
    pub target_preserved: bool,
    pub failures_are_clean: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabClaims {
    pub evaluation_only: bool,
    pub superiority_claim_allowed: bool,
    pub production_safety_claim_allowed: bool,
}

#[derive(Debug, Error)]
pub enum LabError {
    #[error("invalid web lab field: {0}")]
    InvalidField(&'static str),
    #[error("invalid web lab JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn parse_case(bytes: &[u8]) -> Result<WebCase, LabError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CASE_BYTES {
        return Err(LabError::InvalidField("case document size"));
    }
    let case: WebCase = serde_json::from_slice(bytes)?;
    case.validate()?;
    Ok(case)
}

pub fn seal_case(mut case: WebCase) -> Result<WebCase, LabError> {
    case.case_id = expected_case_id(&case);
    case.validate()?;
    Ok(case)
}

pub fn compare_inventory(
    inventory: &WebInventory,
    expected_bytes: &[u8],
) -> Result<WebLabResult, LabError> {
    inventory
        .validate()
        .map_err(|_| LabError::InvalidField("inventory"))?;
    let case = parse_case(expected_bytes)?;
    let expected = case.routes.iter().cloned().collect::<BTreeSet<_>>();
    let actual = inventory
        .routes
        .iter()
        .map(|route| RouteExpectation {
            route: route.route.clone(),
            kind: route.kind,
            methods: route.methods.clone(),
        })
        .collect::<BTreeSet<_>>();
    let matched = expected.intersection(&actual).count() as u64;
    let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
    let unexpected = actual.difference(&expected).cloned().collect::<Vec<_>>();
    let mut mismatches = missing
        .into_iter()
        .map(|route| LabMismatch {
            kind: LabMismatchKind::MissingExpected,
            route,
        })
        .chain(unexpected.into_iter().map(|route| LabMismatch {
            kind: LabMismatchKind::UnexpectedActual,
            route,
        }))
        .collect::<Vec<_>>();
    mismatches.sort();
    let counts = LabCounts {
        expected_routes: expected.len() as u64,
        reported_routes: actual.len() as u64,
        matched_routes: matched,
        missing_routes: expected.len() as u64 - matched,
        unexpected_routes: actual.len() as u64 - matched,
    };
    let metrics = LabMetrics {
        route_precision: ratio(matched, actual.len() as u64),
        route_recall: ratio(matched, expected.len() as u64),
        route_f1: ratio(
            matched.saturating_mul(2),
            matched
                .saturating_mul(2)
                .saturating_add(counts.missing_routes)
                .saturating_add(counts.unexpected_routes),
        ),
    };
    let expected_sha256 = sha256_hex(expected_bytes);
    let mut result = WebLabResult {
        contract_version: LAB_RESULT_VERSION.into(),
        run_id: String::new(),
        case_id: case.case_id,
        inventory_id: inventory.inventory_id.clone(),
        expected_sha256,
        counts,
        metrics,
        mismatches,
        safety: LabSafety {
            network_used: inventory.semantics.network_used,
            target_code_executed: inventory.semantics.target_code_executed,
            target_preserved: true,
            failures_are_clean: false,
        },
        claims: LabClaims {
            evaluation_only: true,
            superiority_claim_allowed: false,
            production_safety_claim_allowed: false,
        },
    };
    result.run_id = expected_run_id(&result);
    result.validate()?;
    Ok(result)
}

pub fn parse_lab_result(bytes: &[u8]) -> Result<WebLabResult, LabError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_LAB_RESULT_BYTES {
        return Err(LabError::InvalidField("result document size"));
    }
    let result: WebLabResult = serde_json::from_slice(bytes)?;
    result.validate()?;
    Ok(result)
}

pub fn lab_result_sarif(result: &WebLabResult) -> Result<Value, LabError> {
    result.validate()?;
    let results = result
        .mismatches
        .iter()
        .map(|mismatch| {
            let (rule_id, level, verb) = match mismatch.kind {
                LabMismatchKind::MissingExpected => ("SFWEBLAB001", "error", "missing"),
                LabMismatchKind::UnexpectedActual => ("SFWEBLAB002", "warning", "unexpected"),
            };
            let route = mismatch.route.route.as_deref().unwrap_or("<non-route-entry>");
            json!({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": format!("{verb} {:?} entry at {route} with methods {:?}", mismatch.route.kind, mismatch.route.methods)
                },
                "locations": [{
                    "logicalLocations": [{
                        "fullyQualifiedName": format!("{:?} {route}", mismatch.route.methods)
                    }]
                }]
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secureflow-web-lab",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": [
                        {"id": "SFWEBLAB001", "name": "MissingExpectedRoute"},
                        {"id": "SFWEBLAB002", "name": "UnexpectedActualRoute"}
                    ]
                }
            },
            "results": results,
            "properties": {
                "run_id": result.run_id,
                "case_id": result.case_id,
                "inventory_id": result.inventory_id
            }
        }]
    }))
}

impl WebCase {
    fn validate(&self) -> Result<(), LabError> {
        if self.contract_version != CASE_VERSION
            || !valid_identifier(&self.case_id, "sf_web_case_")
            || self.case_id != expected_case_id(self)
            || !valid_text(&self.lineage_group, 200)
            || !valid_text(&self.license.spdx, 100)
            || !valid_text(&self.license.provenance, 500)
            || !valid_sha256(&self.license.license_sha256)
            || self.routes.is_empty()
            || self.routes.len() > 2_000_000
            || !self.routes.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(LabError::InvalidField("case"));
        }
        for route in &self.routes {
            validate_route(route)?;
        }
        Ok(())
    }
}

impl WebLabResult {
    fn validate(&self) -> Result<(), LabError> {
        if self.contract_version != LAB_RESULT_VERSION
            || !valid_identifier(&self.run_id, "sf_web_lab_")
            || self.run_id != expected_run_id(self)
            || !valid_identifier(&self.case_id, "sf_web_case_")
            || !valid_identifier(&self.inventory_id, "sf_web_inventory_")
            || !valid_sha256(&self.expected_sha256)
            || self.counts.matched_routes + self.counts.missing_routes
                != self.counts.expected_routes
            || self.counts.matched_routes + self.counts.unexpected_routes
                != self.counts.reported_routes
            || self.mismatches.len() as u64
                != self.counts.missing_routes + self.counts.unexpected_routes
            || self.safety.network_used
            || self.safety.target_code_executed
            || !self.safety.target_preserved
            || self.safety.failures_are_clean
            || !self.claims.evaluation_only
            || self.claims.superiority_claim_allowed
            || self.claims.production_safety_claim_allowed
        {
            return Err(LabError::InvalidField("result"));
        }
        validate_metric(&self.metrics.route_precision)?;
        validate_metric(&self.metrics.route_recall)?;
        validate_metric(&self.metrics.route_f1)?;
        for mismatch in &self.mismatches {
            validate_route(&mismatch.route)?;
        }
        if !self.mismatches.windows(2).all(|pair| pair[0] < pair[1])
            || self
                .mismatches
                .iter()
                .filter(|item| item.kind == LabMismatchKind::MissingExpected)
                .count() as u64
                != self.counts.missing_routes
            || self
                .mismatches
                .iter()
                .filter(|item| item.kind == LabMismatchKind::UnexpectedActual)
                .count() as u64
                != self.counts.unexpected_routes
            || self.metrics.route_precision
                != ratio(self.counts.matched_routes, self.counts.reported_routes)
            || self.metrics.route_recall
                != ratio(self.counts.matched_routes, self.counts.expected_routes)
            || self.metrics.route_f1
                != ratio(
                    self.counts.matched_routes.saturating_mul(2),
                    self.counts
                        .matched_routes
                        .saturating_mul(2)
                        .saturating_add(self.counts.missing_routes)
                        .saturating_add(self.counts.unexpected_routes),
                )
        {
            return Err(LabError::InvalidField("result derivation"));
        }
        Ok(())
    }
}

fn validate_route(route: &RouteExpectation) -> Result<(), LabError> {
    if route.methods.len() > 7 || !route.methods.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(LabError::InvalidField("case route methods"));
    }
    if let Some(path) = &route.route
        && (!path.starts_with('/') || path.len() > 2_000 || path.contains(".."))
    {
        return Err(LabError::InvalidField("case route path"));
    }
    if matches!(route.kind, RouteKind::ApiRoute | RouteKind::PageRoute) != route.route.is_some() {
        return Err(LabError::InvalidField("case route applicability"));
    }
    Ok(())
}

fn ratio(numerator: u64, denominator: u64) -> LabMetric {
    LabMetric {
        numerator,
        denominator,
        basis_points: (denominator != 0).then(|| {
            numerator
                .saturating_mul(10_000)
                .checked_div(denominator)
                .unwrap_or(0)
        }),
    }
}

fn validate_metric(metric: &LabMetric) -> Result<(), LabError> {
    if metric.numerator > metric.denominator
        || metric.basis_points
            != (metric.denominator != 0).then(|| {
                metric
                    .numerator
                    .saturating_mul(10_000)
                    .checked_div(metric.denominator)
                    .unwrap_or(0)
            })
    {
        return Err(LabError::InvalidField("metric"));
    }
    Ok(())
}

fn expected_case_id(case: &WebCase) -> String {
    let mut stable = case.clone();
    stable.case_id.clear();
    format!(
        "sf_web_case_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("case serialization"))
    )
}

fn expected_run_id(result: &WebLabResult) -> String {
    let mut stable = result.clone();
    stable.run_id.clear();
    format!(
        "sf_web_lab_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("lab result serialization"))
    )
}

fn valid_identifier(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_identity_changes_with_labels() {
        let case = WebCase {
            contract_version: CASE_VERSION.into(),
            case_id: String::new(),
            lineage_group: "synthetic".into(),
            split: CaseSplit::Development,
            license: CaseLicense {
                spdx: "MIT".into(),
                provenance: "synthetic test".into(),
                license_sha256: "1".repeat(64),
            },
            routes: vec![RouteExpectation {
                route: Some("/api/health".into()),
                kind: RouteKind::ApiRoute,
                methods: vec![HttpMethod::Get],
            }],
        };
        let mut sealed = seal_case(case).expect("sealed case");
        sealed.lineage_group = "tampered".into();
        assert!(matches!(
            sealed.validate(),
            Err(LabError::InvalidField("case"))
        ));
    }

    #[test]
    fn rehashed_result_cannot_claim_metrics_inconsistent_with_counts() {
        let mut result = WebLabResult {
            contract_version: LAB_RESULT_VERSION.into(),
            run_id: String::new(),
            case_id: format!("sf_web_case_{}", "1".repeat(64)),
            inventory_id: format!("sf_web_inventory_{}", "2".repeat(64)),
            expected_sha256: "3".repeat(64),
            counts: LabCounts {
                expected_routes: 1,
                reported_routes: 1,
                matched_routes: 1,
                missing_routes: 0,
                unexpected_routes: 0,
            },
            metrics: LabMetrics {
                route_precision: ratio(1, 1),
                route_recall: ratio(1, 1),
                route_f1: ratio(2, 2),
            },
            mismatches: vec![],
            safety: LabSafety {
                network_used: false,
                target_code_executed: false,
                target_preserved: true,
                failures_are_clean: false,
            },
            claims: LabClaims {
                evaluation_only: true,
                superiority_claim_allowed: false,
                production_safety_claim_allowed: false,
            },
        };
        result.run_id = expected_run_id(&result);
        assert!(result.validate().is_ok());
        result.metrics.route_recall = ratio(0, 1);
        result.run_id = expected_run_id(&result);
        assert!(matches!(
            result.validate(),
            Err(LabError::InvalidField("result derivation"))
        ));
    }
}
