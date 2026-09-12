use super::{Result, error, parse_time, require, wire};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub publisher_id: String,
    pub catalog_id: String,
    pub channel: String,
    pub profile: String,
}
impl Scope {
    pub fn validate(&self) -> Result<()> {
        require(
            [&self.publisher_id, &self.catalog_id, &self.channel]
                .iter()
                .all(|s| wire::identifier(s))
                && ["core", "malicious", "full"].contains(&self.profile.as_str()),
            "TRUST_SCOPE",
            "invalid scope",
        )
    }
    pub fn target(&self) -> String {
        format!(
            "catalogs/{}/{}/{}.manifest.json",
            self.catalog_id, self.channel, self.profile
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub contract_version: String,
    pub publisher_id: String,
    pub catalog_id: String,
    pub channel: String,
    pub profile: String,
    pub profile_policy_version: String,
    pub bundle_id: String,
    pub release_sequence: u64,
    pub manifest_contract_version: String,
    pub validation_authority: String,
}
impl Target {
    pub fn scope(&self) -> Scope {
        Scope {
            publisher_id: self.publisher_id.clone(),
            catalog_id: self.catalog_id.clone(),
            channel: self.channel.clone(),
            profile: self.profile.clone(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        super::validate_schema(
            "target",
            &serde_json::to_value(self).map_err(|e| error("TRUST_FORMAT", e))?,
        )?;
        self.scope().validate()?;
        require(
            self.contract_version == "secureflow-catalog-target-v1"
                && self.profile_policy_version == "secureflow-catalog-profile-policy-v2"
                && self.manifest_contract_version == "secureflow-catalog-bundle-v1"
                && self.validation_authority == "external-records-require-human-validation"
                && self.release_sequence > 0
                && self.release_sequence <= wire::MAX_SEQUENCE
                && self.bundle_id.starts_with("sf_catalog_bundle_")
                && self.bundle_id.len() == 82,
            "TRUST_SCOPE",
            "invalid target contract",
        )?;
        wire::hex::<32>(&self.bundle_id[18..])?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Clock {
    pub verification_time: String,
    pub time_source: String,
    pub time_reference: String,
}
impl Clock {
    pub fn validate(&self) -> Result<()> {
        parse_time(&self.verification_time)?;
        require(
            ["operator-attested", "operator-trusted-system-clock"]
                .contains(&self.time_source.as_str())
                && !self.time_reference.trim().is_empty()
                && self.time_reference.len() <= 1024,
            "TRUST_CLOCK",
            "explicit bounded clock source/reference required",
        )
    }
    pub fn capture(time: Option<String>, reference: Option<String>) -> Result<Self> {
        match (time, reference) {
            (Some(t), Some(r)) => {
                parse_time(&t)?;
                require(
                    !r.trim().is_empty() && r.len() <= 1024,
                    "TRUST_CLOCK",
                    "time reference required and bounded",
                )?;
                Ok(Self {
                    verification_time: t,
                    time_source: "operator-attested".into(),
                    time_reference: r,
                })
            }
            (None, None) => Ok(Self {
                verification_time: time::OffsetDateTime::now_utc()
                    .replace_nanosecond(0)
                    .map_err(|e| error("TRUST_CLOCK", e))?
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| error("TRUST_CLOCK", e))?,
                time_source: "operator-trusted-system-clock".into(),
                time_reference: "local operating system clock".into(),
            }),
            _ => Err(error(
                "TRUST_CLOCK",
                "verification-time and time-reference must be supplied together",
            )),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub contract_version: String,
    pub publisher_id: String,
    pub publisher_label: String,
    pub catalog_id: String,
    pub channel: String,
    pub profiles: Vec<String>,
    pub initial_root_sha256: String,
    pub minimum_root_version: u64,
    pub minimum_sequence: u64,
    pub bootstrap_manifest_sha256: Option<String>,
    pub minimum_thresholds: BTreeMap<String, u64>,
    pub maximum_horizon_days: BTreeMap<String, u64>,
    pub operator: String,
    pub authorization_reference: String,
    pub enrolled_at: Clock,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        super::validate_schema(
            "policy",
            &serde_json::to_value(self).map_err(|e| error("TRUST_FORMAT", e))?,
        )?;
        require(
            self.contract_version == "secureflow-catalog-trust-policy-v1"
                && !self.operator.trim().is_empty()
                && self.operator.len() <= 256
                && !self.authorization_reference.trim().is_empty()
                && self.authorization_reference.len() <= 1024
                && !self.publisher_label.trim().is_empty()
                && self.publisher_label.len() <= 256
                && self.minimum_sequence <= wire::MAX_SEQUENCE
                && self.minimum_root_version > 0
                && self.minimum_root_version <= u32::MAX as u64,
            "TRUST_BOOTSTRAP",
            "invalid explicit bootstrap policy",
        )?;
        wire::hex::<32>(&self.initial_root_sha256)?;
        if let Some(pin) = &self.bootstrap_manifest_sha256 {
            wire::hex::<32>(pin)?;
            require(
                self.profiles.len() == 1,
                "TRUST_BOOTSTRAP",
                "first-manifest pin requires exactly one profile",
            )?;
        }
        self.enrolled_at.validate()?;
        require(
            !self.profiles.is_empty() && self.profiles.len() <= 3,
            "TRUST_SCOPE",
            "one to three profiles required",
        )?;
        let unique: std::collections::BTreeSet<_> = self.profiles.iter().collect();
        require(
            unique.len() == self.profiles.len(),
            "TRUST_SCOPE",
            "duplicate profile",
        )?;
        for profile in &self.profiles {
            self.scope(profile).validate()?;
        }
        require(
            self.minimum_thresholds == thresholds() && self.maximum_horizon_days == horizons(),
            "TRUST_BOOTSTRAP",
            "unsupported local policy minima/horizons",
        )
    }
    pub fn scope(&self, profile: &str) -> Scope {
        Scope {
            publisher_id: self.publisher_id.clone(),
            catalog_id: self.catalog_id.clone(),
            channel: self.channel.clone(),
            profile: profile.into(),
        }
    }
    pub fn allows(&self, scope: &Scope) -> Result<()> {
        scope.validate()?;
        require(
            self.profiles.contains(&scope.profile) && self.scope(&scope.profile) == *scope,
            "TRUST_SCOPE",
            "scope differs from enrollment",
        )
    }
}
pub fn thresholds() -> BTreeMap<String, u64> {
    [
        ("root", 2),
        ("targets", 2),
        ("snapshot", 1),
        ("timestamp", 1),
    ]
    .map(|(k, v)| (k.into(), v))
    .into()
}
pub fn horizons() -> BTreeMap<String, u64> {
    [
        ("root", 366),
        ("targets", 30),
        ("snapshot", 30),
        ("timestamp", 7),
    ]
    .map(|(k, v)| (k.into(), v))
    .into()
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleEvidence {
    pub version: u64,
    pub raw_sha256: String,
    pub signed_sha256: String,
    pub expires: String,
    pub accepted_signer_ids: Vec<String>,
    pub threshold: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub contract_version: String,
    pub operation: String,
    pub installation: String,
    pub transaction_id: Option<String>,
    pub output: Option<String>,
    pub integrity: String,
    pub publisher_authenticity: String,
    pub freshness: String,
    pub rollback: String,
    pub scope: Scope,
    pub release_sequence: u64,
    pub initial_root_sha256: String,
    pub current_root_sha256: String,
    pub metadata: BTreeMap<String, RoleEvidence>,
    pub manifest_sha256: String,
    pub manifest_bytes: u64,
    pub database_sha256: String,
    pub database_bytes: u64,
    pub policy_sha256: String,
    pub clock: Clock,
    pub earliest_expiry: String,
    pub state_generation: u64,
    pub reserves_acceptance: bool,
    pub validation_authority: String,
    pub limitations: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub sequence: u64,
    pub manifest_sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRecord {
    pub raw: String,
    pub evidence: RoleEvidence,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub receipt: Receipt,
    pub descriptor: crate::catalog_bundle::CatalogDatabaseDescriptor,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub contract_version: String,
    pub policy: Policy,
    pub policy_sha256: String,
    pub roots: Vec<String>,
    pub roles: BTreeMap<String, RoleRecord>,
    pub floors: BTreeMap<String, Floor>,
    pub maximum_verification_time: String,
    pub generation: u64,
    pub pending: Option<Pending>,
    pub completed: BTreeMap<String, Receipt>,
}
