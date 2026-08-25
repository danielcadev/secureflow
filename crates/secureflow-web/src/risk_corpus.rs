use crate::inventory::{HttpMethod, ParameterLocation};
use crate::lab::{CaseLicense, CaseSplit};
use crate::scope::{sha256_hex, valid_sha256, valid_text};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const API_RISK_CORPUS_VERSION: &str = "secureflow-web-api-risk-corpus-v1";
pub const API_RISK_GENERATOR_VERSION: &str = "secureflow-web-api-risk-generator-v1";
pub const MAX_API_RISK_CORPUS_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_VARIANTS_PER_SCENARIO: u16 = 50;
const EXPECTED_FAMILIES: usize = 20;
const EXPECTED_PROFILES: usize = 10;
const EXPECTED_PAIRS: usize = EXPECTED_FAMILIES * EXPECTED_PROFILES;
const EXPECTED_CASES: usize = EXPECTED_PAIRS * 2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebApiRiskCorpus {
    pub contract_version: String,
    pub corpus_id: String,
    pub name: String,
    pub split: CaseSplit,
    pub partition: CorpusPartition,
    pub license: CaseLicense,
    pub generator: CorpusGenerator,
    pub counts: RiskCorpusCounts,
    pub cases: Vec<ApiRiskScenario>,
    pub claims: RiskCorpusClaims,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusPartition {
    pub lineage_group: String,
    pub known_to_developers: bool,
    pub holdout_eligible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusGenerator {
    pub version: String,
    pub seed: String,
    pub family_count: u16,
    pub profile_count: u16,
    pub pairing_strategy: String,
    pub variant_plan: VariantPlan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VariantPlan {
    pub materialization: String,
    pub identity_algorithm: String,
    pub maximum_variants_per_scenario: u16,
    pub minimum_supported_total: u64,
    pub maximum_supported_total: u64,
    pub dimensions: Vec<String>,
    pub deduplication_key: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskCorpusCounts {
    pub canonical_pairs: u64,
    pub risky_scenarios: u64,
    pub safe_controls: u64,
    pub total_scenarios: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskCorpusClaims {
    pub development_only: bool,
    pub independent_holdout: bool,
    pub human_superiority_claim_allowed: bool,
    pub production_safety_claim_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRiskScenario {
    pub scenario_id: String,
    pub scenario_fingerprint: String,
    pub title: String,
    pub description: String,
    pub family: RiskFamily,
    pub framework: RiskScenarioFramework,
    pub runtime: String,
    pub surface: RiskSurface,
    pub method: HttpMethod,
    pub route: String,
    pub actor: ActorKind,
    pub authentication: ActorAuthentication,
    pub role: ActorRole,
    pub tenant_relation: TenantRelation,
    pub parameters: Vec<RiskScenarioParameter>,
    pub expected_controls: Vec<ExpectedControl>,
    pub response: RiskScenarioResponse,
    pub evidence: Vec<RiskScenarioEvidence>,
    pub provenance: RiskScenarioProvenance,
    pub pairing: RiskPairing,
    pub ground_truth: GroundTruth,
    pub automated_output_ceiling: AutomatedOutputCeiling,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskFamily {
    MissingAuthentication,
    RoleAuthorization,
    BolaOwnerScope,
    TenantIsolation,
    ExcessiveResponseData,
    MassAssignment,
    CorsPolicy,
    PrivateCachePolicy,
    VerboseErrorDisclosure,
    WebhookSignature,
    WebhookReplay,
    UploadConstraints,
    PathTraversal,
    SsrfDestination,
    AbuseRateLimit,
    FailOpenDependency,
    HiddenAdminExposure,
    InternalEndpointExposure,
    ServerActionAuthorization,
    MiddlewareCoverage,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskScenarioFramework {
    NextAppRouter,
    NextPagesRouter,
    NextServerAction,
    Express,
    Fastify,
    NestJs,
    Django,
    Axum,
    GraphQl,
    Trpc,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskSurface {
    RouteHandler,
    ApiHandler,
    ServerAction,
    MiddlewareProtectedRoute,
    RestHandler,
    GraphQlOperation,
    TrpcProcedure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorKind {
    AnonymousExternal,
    AuthenticatedUser,
    TenantMember,
    TenantAdministrator,
    WebhookSender,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorAuthentication {
    None,
    ValidSession,
    ValidApiToken,
    InvalidOrMissingSignature,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActorRole {
    None,
    User,
    Member,
    TenantAdmin,
    ExternalService,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TenantRelation {
    NotApplicable,
    OwnTenant,
    CrossTenant,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskScenarioParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub attacker_controlled: bool,
    pub sensitivity: ScenarioParameterSensitivity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioParameterSensitivity {
    Public,
    ObjectIdentifier,
    TenantIdentifier,
    AuthorizationMetadata,
    FilePath,
    DestinationUrl,
    Signature,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedControl {
    Authentication,
    RoleAuthorization,
    OwnerScope,
    TenantScope,
    ResponseFieldAllowlist,
    InputFieldAllowlist,
    RestrictedCors,
    PrivateNoStoreCache,
    SanitizedErrors,
    WebhookSignatureVerification,
    WebhookReplayProtection,
    UploadTypeAndSizeLimits,
    CanonicalPathConfinement,
    DestinationAllowlist,
    RateLimitAndQuota,
    FailClosedDependency,
    ExplicitAdminAuthorization,
    InternalRouteNonExposure,
    ServerActionAuthorization,
    MiddlewareMatcherCoverage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskScenarioResponse {
    pub expected_decision: ExpectedDecision,
    pub fixture_decision: FixtureDecision,
    pub expected_status: u16,
    pub fixture_status: u16,
    pub expected_fields: Vec<String>,
    pub fixture_fields: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedDecision {
    AllowMinimal,
    Deny,
    Reject,
    RestrictMetadata,
    StorePrivately,
    Sanitize,
    Throttle,
    FailClosed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureDecision {
    MatchesExpected,
    AllowsUnexpectedly,
    ExposesExcessData,
    AcceptsPolicyFields,
    EmitsUnsafeMetadata,
    StoresPublicly,
    EmitsVerboseError,
    AcceptsUnverifiedEvent,
    AcceptsReplay,
    AcceptsUnsafeUpload,
    EscapesConfinement,
    FetchesUntrustedDestination,
    OmitsThrottle,
    FailsOpen,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskScenarioEvidence {
    pub kind: ScenarioEvidenceKind,
    pub reference: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioEvidenceKind {
    SyntheticSpecification,
    ExpectedControl,
    ExpectedDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskScenarioProvenance {
    pub origin: SyntheticOrigin,
    pub license_spdx: String,
    pub generator_version: String,
    pub template_id: String,
    pub profile_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyntheticOrigin {
    SecureFlowSynthetic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskPairing {
    pub pair_id: String,
    pub counterpart_scenario_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroundTruth {
    RiskySynthetic,
    SafeControl,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutomatedOutputCeiling {
    CandidateOrHardening,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VariantDescriptor {
    pub variant_id: String,
    pub canonical_scenario_id: String,
    pub canonical_fingerprint: String,
    pub variant_index: u16,
    pub route: String,
    pub parameter_aliases: Vec<VariantAlias>,
    pub response_field_aliases: Vec<VariantAlias>,
    pub lineage_fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VariantAlias {
    pub canonical: String,
    pub variant: String,
}

#[derive(Debug, Error)]
pub enum ApiRiskCorpusError {
    #[error("invalid API risk corpus field: {0}")]
    InvalidField(&'static str),
    #[error("invalid API risk corpus JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Copy)]
struct ProfileDefinition {
    id: &'static str,
    framework: RiskScenarioFramework,
    runtime: &'static str,
    surface: RiskSurface,
}

pub fn generate_api_risk_corpus(
    license_sha256: &str,
) -> Result<WebApiRiskCorpus, ApiRiskCorpusError> {
    if !valid_sha256(license_sha256) {
        return Err(ApiRiskCorpusError::InvalidField("license hash"));
    }
    let profiles = profiles();
    let families = families();
    let mut cases = Vec::with_capacity(EXPECTED_CASES);
    for (profile_index, profile) in profiles.iter().enumerate() {
        for (family_index, family) in families.iter().copied().enumerate() {
            let pair_number = profile_index * EXPECTED_FAMILIES + family_index + 1;
            let pair_id = format!("WEBRISK-PAIR-{pair_number:04}");
            let risk_id = format!("WEBRISK-{pair_number:04}-RISK");
            let safe_id = format!("WEBRISK-{pair_number:04}-SAFE");
            cases.push(build_scenario(
                &risk_id,
                &safe_id,
                &pair_id,
                family,
                profile,
                GroundTruth::RiskySynthetic,
            ));
            cases.push(build_scenario(
                &safe_id,
                &risk_id,
                &pair_id,
                family,
                profile,
                GroundTruth::SafeControl,
            ));
        }
    }
    cases.sort_by(|left, right| left.scenario_id.cmp(&right.scenario_id));
    let mut corpus = WebApiRiskCorpus {
        contract_version: API_RISK_CORPUS_VERSION.into(),
        corpus_id: String::new(),
        name: "SecureFlow Web synthetic paired API risk corpus v1".into(),
        split: CaseSplit::Development,
        partition: CorpusPartition {
            lineage_group: "secureflow-web-api-risk-development-v1".into(),
            known_to_developers: true,
            holdout_eligible: false,
        },
        license: CaseLicense {
            spdx: "MIT OR Apache-2.0".into(),
            provenance:
                "SecureFlow-generated synthetic scenarios; no private or third-party API data"
                    .into(),
            license_sha256: license_sha256.into(),
        },
        generator: CorpusGenerator {
            version: API_RISK_GENERATOR_VERSION.into(),
            seed: "secureflow-web-risk-corpus-v1-fixed-seed".into(),
            family_count: EXPECTED_FAMILIES as u16,
            profile_count: EXPECTED_PROFILES as u16,
            pairing_strategy: "one risky scenario and one safe control per family/profile pair"
                .into(),
            variant_plan: VariantPlan {
                materialization: "on-demand; canonical cases only are retained".into(),
                identity_algorithm: "sha256(canonical fingerprint, variant index, aliases)".into(),
                maximum_variants_per_scenario: MAX_VARIANTS_PER_SCENARIO,
                minimum_supported_total: EXPECTED_CASES as u64 * 13,
                maximum_supported_total: EXPECTED_CASES as u64
                    * u64::from(MAX_VARIANTS_PER_SCENARIO),
                dimensions: vec![
                    "route suffix".into(),
                    "parameter aliases".into(),
                    "response field aliases".into(),
                ],
                deduplication_key: vec![
                    "canonical scenario fingerprint".into(),
                    "variant index".into(),
                    "generated alias fingerprint".into(),
                ],
            },
        },
        counts: RiskCorpusCounts {
            canonical_pairs: EXPECTED_PAIRS as u64,
            risky_scenarios: EXPECTED_PAIRS as u64,
            safe_controls: EXPECTED_PAIRS as u64,
            total_scenarios: EXPECTED_CASES as u64,
        },
        cases,
        claims: RiskCorpusClaims {
            development_only: true,
            independent_holdout: false,
            human_superiority_claim_allowed: false,
            production_safety_claim_allowed: false,
        },
    };
    corpus.corpus_id = expected_corpus_id(&corpus);
    corpus.validate()?;
    Ok(corpus)
}

pub fn parse_api_risk_corpus(bytes: &[u8]) -> Result<WebApiRiskCorpus, ApiRiskCorpusError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_API_RISK_CORPUS_BYTES {
        return Err(ApiRiskCorpusError::InvalidField("document size"));
    }
    let corpus: WebApiRiskCorpus = serde_json::from_slice(bytes)?;
    corpus.validate()?;
    Ok(corpus)
}

pub fn generate_variant_descriptors(
    corpus: &WebApiRiskCorpus,
    variants_per_scenario: u16,
) -> Result<Vec<VariantDescriptor>, ApiRiskCorpusError> {
    corpus.validate()?;
    if variants_per_scenario == 0 || variants_per_scenario > MAX_VARIANTS_PER_SCENARIO {
        return Err(ApiRiskCorpusError::InvalidField("variants per scenario"));
    }
    let expected = corpus
        .cases
        .len()
        .checked_mul(usize::from(variants_per_scenario))
        .ok_or(ApiRiskCorpusError::InvalidField("variant count"))?;
    let mut variants = Vec::with_capacity(expected);
    for scenario in &corpus.cases {
        for variant_index in 0..variants_per_scenario {
            let route = variant_route(&scenario.route, variant_index);
            let parameter_aliases = aliases(
                scenario
                    .parameters
                    .iter()
                    .map(|parameter| parameter.name.as_str()),
                "parameter",
                variant_index,
            );
            let response_field_aliases = aliases(
                scenario.response.fixture_fields.iter().map(String::as_str),
                "field",
                variant_index,
            );
            let lineage_fingerprint = sha256_hex(
                format!(
                    "{}\0{}\0{}",
                    scenario.scenario_fingerprint, variant_index, route
                )
                .as_bytes(),
            );
            let mut variant = VariantDescriptor {
                variant_id: String::new(),
                canonical_scenario_id: scenario.scenario_id.clone(),
                canonical_fingerprint: scenario.scenario_fingerprint.clone(),
                variant_index,
                route,
                parameter_aliases,
                response_field_aliases,
                lineage_fingerprint,
            };
            variant.variant_id = expected_variant_id(&variant);
            validate_variant(&variant)?;
            variants.push(variant);
        }
    }
    let unique = variants
        .iter()
        .map(|variant| variant.variant_id.as_str())
        .collect::<BTreeSet<_>>();
    if variants.len() != expected || unique.len() != expected {
        return Err(ApiRiskCorpusError::InvalidField("duplicate variants"));
    }
    Ok(variants)
}

impl WebApiRiskCorpus {
    pub fn validate(&self) -> Result<(), ApiRiskCorpusError> {
        if self.contract_version != API_RISK_CORPUS_VERSION
            || !valid_prefixed_hash(&self.corpus_id, "sf_web_api_risk_corpus_")
            || self.corpus_id != expected_corpus_id(self)
            || !valid_text(&self.name, 200)
            || self.split != CaseSplit::Development
            || !valid_text(&self.partition.lineage_group, 200)
            || !self.partition.known_to_developers
            || self.partition.holdout_eligible
            || !valid_text(&self.license.spdx, 100)
            || !valid_text(&self.license.provenance, 500)
            || !valid_sha256(&self.license.license_sha256)
            || self.generator.version != API_RISK_GENERATOR_VERSION
            || !valid_text(&self.generator.seed, 200)
            || self.generator.family_count != EXPECTED_FAMILIES as u16
            || self.generator.profile_count != EXPECTED_PROFILES as u16
            || !valid_text(&self.generator.pairing_strategy, 300)
            || self.generator.variant_plan.maximum_variants_per_scenario
                != MAX_VARIANTS_PER_SCENARIO
            || self.generator.variant_plan.minimum_supported_total != 5_200
            || self.generator.variant_plan.maximum_supported_total != 20_000
            || self.cases.len() != EXPECTED_CASES
            || self.counts.canonical_pairs != EXPECTED_PAIRS as u64
            || self.counts.risky_scenarios != EXPECTED_PAIRS as u64
            || self.counts.safe_controls != EXPECTED_PAIRS as u64
            || self.counts.total_scenarios != EXPECTED_CASES as u64
            || !self
                .cases
                .windows(2)
                .all(|pair| pair[0].scenario_id < pair[1].scenario_id)
            || !self.claims.development_only
            || self.claims.independent_holdout
            || self.claims.human_superiority_claim_allowed
            || self.claims.production_safety_claim_allowed
        {
            return Err(ApiRiskCorpusError::InvalidField("corpus"));
        }
        let scenario_ids = self
            .cases
            .iter()
            .map(|scenario| scenario.scenario_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut pairs = BTreeMap::<&str, Vec<&ApiRiskScenario>>::new();
        let mut family_counts = BTreeMap::<RiskFamily, usize>::new();
        let mut framework_counts = BTreeMap::<RiskScenarioFramework, usize>::new();
        for scenario in &self.cases {
            validate_scenario(scenario, &self.license)?;
            if !scenario_ids.contains(scenario.pairing.counterpart_scenario_id.as_str()) {
                return Err(ApiRiskCorpusError::InvalidField("pair counterpart"));
            }
            pairs
                .entry(&scenario.pairing.pair_id)
                .or_default()
                .push(scenario);
            *family_counts.entry(scenario.family).or_default() += 1;
            *framework_counts.entry(scenario.framework).or_default() += 1;
        }
        if pairs.len() != EXPECTED_PAIRS
            || family_counts.len() != EXPECTED_FAMILIES
            || framework_counts.len() != EXPECTED_PROFILES
            || family_counts
                .values()
                .any(|count| *count != EXPECTED_PROFILES * 2)
            || framework_counts
                .values()
                .any(|count| *count != EXPECTED_FAMILIES * 2)
        {
            return Err(ApiRiskCorpusError::InvalidField("coverage balance"));
        }
        for scenarios in pairs.values() {
            if scenarios.len() != 2
                || scenarios[0].pairing.counterpart_scenario_id != scenarios[1].scenario_id
                || scenarios[1].pairing.counterpart_scenario_id != scenarios[0].scenario_id
                || scenarios[0].ground_truth == scenarios[1].ground_truth
                || scenarios[0].family != scenarios[1].family
                || scenarios[0].framework != scenarios[1].framework
                || scenarios[0].route != scenarios[1].route
                || scenarios[0].method != scenarios[1].method
                || scenarios[0].actor != scenarios[1].actor
                || scenarios[0].authentication != scenarios[1].authentication
                || scenarios[0].role != scenarios[1].role
                || scenarios[0].tenant_relation != scenarios[1].tenant_relation
                || scenarios[0].parameters != scenarios[1].parameters
                || scenarios[0].expected_controls != scenarios[1].expected_controls
                || scenarios[0].response.expected_decision
                    != scenarios[1].response.expected_decision
                || scenarios[0].response.expected_status != scenarios[1].response.expected_status
                || scenarios[0].response.expected_fields != scenarios[1].response.expected_fields
                || scenarios[0].provenance != scenarios[1].provenance
            {
                return Err(ApiRiskCorpusError::InvalidField("pair integrity"));
            }
        }
        Ok(())
    }
}

fn build_scenario(
    scenario_id: &str,
    counterpart_id: &str,
    pair_id: &str,
    family: RiskFamily,
    profile: &ProfileDefinition,
    ground_truth: GroundTruth,
) -> ApiRiskScenario {
    let expected_controls = controls_for(family);
    let (actor, authentication, role, tenant_relation) = actor_for(family);
    let expected_decision = expected_decision_for(family);
    let expected_status = expected_status_for(expected_decision);
    let fixture_decision = if ground_truth == GroundTruth::SafeControl {
        FixtureDecision::MatchesExpected
    } else {
        broken_decision_for(family)
    };
    let fixture_status = if ground_truth == GroundTruth::SafeControl {
        expected_status
    } else {
        risky_status_for(family)
    };
    let expected_fields = expected_fields_for(family);
    let fixture_fields = if ground_truth == GroundTruth::SafeControl {
        expected_fields.clone()
    } else {
        risky_fields_for(family, &expected_fields)
    };
    let family_name = enum_name(family);
    let profile_name = profile.id;
    let route = route_for(family, profile);
    let mut scenario = ApiRiskScenario {
        scenario_id: scenario_id.into(),
        scenario_fingerprint: String::new(),
        title: format!(
            "{} {} scenario for {}",
            if ground_truth == GroundTruth::RiskySynthetic {
                "Risky"
            } else {
                "Safe"
            },
            family_name,
            profile_name
        ),
        description: format!(
            "Synthetic {} case for {} on the {} profile; it is evaluation data, not a real vulnerability.",
            family_name, profile_name, profile.runtime
        ),
        family,
        framework: profile.framework,
        runtime: profile.runtime.into(),
        surface: profile.surface,
        method: method_for(family, profile.framework),
        route,
        actor,
        authentication,
        role,
        tenant_relation,
        parameters: parameters_for(family),
        expected_controls,
        response: RiskScenarioResponse {
            expected_decision,
            fixture_decision,
            expected_status,
            fixture_status,
            expected_fields,
            fixture_fields,
        },
        evidence: vec![
            RiskScenarioEvidence {
                kind: ScenarioEvidenceKind::SyntheticSpecification,
                reference: format!("template:{family_name}/profile:{profile_name}"),
                description: "Deterministic synthetic scenario generated from a reviewed family/profile recipe"
                    .into(),
            },
            RiskScenarioEvidence {
                kind: ScenarioEvidenceKind::ExpectedControl,
                reference: format!("control:{:?}", controls_for(family)[0]),
                description: "The paired cases share the same required security invariant".into(),
            },
        ],
        provenance: RiskScenarioProvenance {
            origin: SyntheticOrigin::SecureFlowSynthetic,
            license_spdx: "MIT OR Apache-2.0".into(),
            generator_version: API_RISK_GENERATOR_VERSION.into(),
            template_id: format!("WEB-TEMPLATE-{family_name}"),
            profile_id: format!("WEB-PROFILE-{profile_name}"),
        },
        pairing: RiskPairing {
            pair_id: pair_id.into(),
            counterpart_scenario_id: counterpart_id.into(),
        },
        ground_truth,
        automated_output_ceiling: AutomatedOutputCeiling::CandidateOrHardening,
    };
    scenario.scenario_fingerprint = expected_scenario_fingerprint(&scenario);
    scenario
}

fn profiles() -> [ProfileDefinition; EXPECTED_PROFILES] {
    [
        ProfileDefinition {
            id: "NEXT-APP",
            framework: RiskScenarioFramework::NextAppRouter,
            runtime: "Node.js/Next.js App Router",
            surface: RiskSurface::RouteHandler,
        },
        ProfileDefinition {
            id: "NEXT-PAGES",
            framework: RiskScenarioFramework::NextPagesRouter,
            runtime: "Node.js/Next.js Pages Router",
            surface: RiskSurface::ApiHandler,
        },
        ProfileDefinition {
            id: "NEXT-ACTION",
            framework: RiskScenarioFramework::NextServerAction,
            runtime: "Node.js/Next.js Server Actions",
            surface: RiskSurface::ServerAction,
        },
        ProfileDefinition {
            id: "EXPRESS",
            framework: RiskScenarioFramework::Express,
            runtime: "Node.js/Express",
            surface: RiskSurface::RestHandler,
        },
        ProfileDefinition {
            id: "FASTIFY",
            framework: RiskScenarioFramework::Fastify,
            runtime: "Node.js/Fastify",
            surface: RiskSurface::RestHandler,
        },
        ProfileDefinition {
            id: "NESTJS",
            framework: RiskScenarioFramework::NestJs,
            runtime: "Node.js/NestJS",
            surface: RiskSurface::RestHandler,
        },
        ProfileDefinition {
            id: "DJANGO",
            framework: RiskScenarioFramework::Django,
            runtime: "Python/Django",
            surface: RiskSurface::RestHandler,
        },
        ProfileDefinition {
            id: "AXUM",
            framework: RiskScenarioFramework::Axum,
            runtime: "Rust/Axum",
            surface: RiskSurface::RestHandler,
        },
        ProfileDefinition {
            id: "GRAPHQL",
            framework: RiskScenarioFramework::GraphQl,
            runtime: "GraphQL",
            surface: RiskSurface::GraphQlOperation,
        },
        ProfileDefinition {
            id: "TRPC",
            framework: RiskScenarioFramework::Trpc,
            runtime: "Node.js/tRPC",
            surface: RiskSurface::TrpcProcedure,
        },
    ]
}

fn families() -> [RiskFamily; EXPECTED_FAMILIES] {
    [
        RiskFamily::MissingAuthentication,
        RiskFamily::RoleAuthorization,
        RiskFamily::BolaOwnerScope,
        RiskFamily::TenantIsolation,
        RiskFamily::ExcessiveResponseData,
        RiskFamily::MassAssignment,
        RiskFamily::CorsPolicy,
        RiskFamily::PrivateCachePolicy,
        RiskFamily::VerboseErrorDisclosure,
        RiskFamily::WebhookSignature,
        RiskFamily::WebhookReplay,
        RiskFamily::UploadConstraints,
        RiskFamily::PathTraversal,
        RiskFamily::SsrfDestination,
        RiskFamily::AbuseRateLimit,
        RiskFamily::FailOpenDependency,
        RiskFamily::HiddenAdminExposure,
        RiskFamily::InternalEndpointExposure,
        RiskFamily::ServerActionAuthorization,
        RiskFamily::MiddlewareCoverage,
    ]
}

fn controls_for(family: RiskFamily) -> Vec<ExpectedControl> {
    let controls = match family {
        RiskFamily::MissingAuthentication => vec![ExpectedControl::Authentication],
        RiskFamily::RoleAuthorization => vec![ExpectedControl::RoleAuthorization],
        RiskFamily::BolaOwnerScope => vec![ExpectedControl::OwnerScope],
        RiskFamily::TenantIsolation => vec![ExpectedControl::TenantScope],
        RiskFamily::ExcessiveResponseData => vec![ExpectedControl::ResponseFieldAllowlist],
        RiskFamily::MassAssignment => vec![ExpectedControl::InputFieldAllowlist],
        RiskFamily::CorsPolicy => vec![ExpectedControl::RestrictedCors],
        RiskFamily::PrivateCachePolicy => vec![ExpectedControl::PrivateNoStoreCache],
        RiskFamily::VerboseErrorDisclosure => vec![ExpectedControl::SanitizedErrors],
        RiskFamily::WebhookSignature => vec![ExpectedControl::WebhookSignatureVerification],
        RiskFamily::WebhookReplay => vec![ExpectedControl::WebhookReplayProtection],
        RiskFamily::UploadConstraints => vec![ExpectedControl::UploadTypeAndSizeLimits],
        RiskFamily::PathTraversal => vec![ExpectedControl::CanonicalPathConfinement],
        RiskFamily::SsrfDestination => vec![ExpectedControl::DestinationAllowlist],
        RiskFamily::AbuseRateLimit => vec![ExpectedControl::RateLimitAndQuota],
        RiskFamily::FailOpenDependency => vec![ExpectedControl::FailClosedDependency],
        RiskFamily::HiddenAdminExposure => vec![ExpectedControl::ExplicitAdminAuthorization],
        RiskFamily::InternalEndpointExposure => vec![ExpectedControl::InternalRouteNonExposure],
        RiskFamily::ServerActionAuthorization => {
            vec![
                ExpectedControl::Authentication,
                ExpectedControl::ServerActionAuthorization,
            ]
        }
        RiskFamily::MiddlewareCoverage => {
            vec![
                ExpectedControl::Authentication,
                ExpectedControl::MiddlewareMatcherCoverage,
            ]
        }
    };
    let mut controls = controls;
    controls.sort();
    controls
}

fn actor_for(family: RiskFamily) -> (ActorKind, ActorAuthentication, ActorRole, TenantRelation) {
    match family {
        RiskFamily::MissingAuthentication
        | RiskFamily::CorsPolicy
        | RiskFamily::PrivateCachePolicy
        | RiskFamily::VerboseErrorDisclosure
        | RiskFamily::UploadConstraints
        | RiskFamily::PathTraversal
        | RiskFamily::SsrfDestination
        | RiskFamily::AbuseRateLimit
        | RiskFamily::FailOpenDependency
        | RiskFamily::HiddenAdminExposure
        | RiskFamily::InternalEndpointExposure
        | RiskFamily::MiddlewareCoverage => (
            ActorKind::AnonymousExternal,
            ActorAuthentication::None,
            ActorRole::None,
            TenantRelation::NotApplicable,
        ),
        RiskFamily::RoleAuthorization | RiskFamily::ServerActionAuthorization => (
            ActorKind::AuthenticatedUser,
            ActorAuthentication::ValidSession,
            ActorRole::User,
            TenantRelation::OwnTenant,
        ),
        RiskFamily::BolaOwnerScope | RiskFamily::MassAssignment => (
            ActorKind::AuthenticatedUser,
            ActorAuthentication::ValidSession,
            ActorRole::User,
            TenantRelation::OwnTenant,
        ),
        RiskFamily::TenantIsolation | RiskFamily::ExcessiveResponseData => (
            ActorKind::TenantMember,
            ActorAuthentication::ValidApiToken,
            ActorRole::Member,
            TenantRelation::CrossTenant,
        ),
        RiskFamily::WebhookSignature | RiskFamily::WebhookReplay => (
            ActorKind::WebhookSender,
            ActorAuthentication::InvalidOrMissingSignature,
            ActorRole::ExternalService,
            TenantRelation::NotApplicable,
        ),
    }
}

fn parameters_for(family: RiskFamily) -> Vec<RiskScenarioParameter> {
    let (name, location, sensitivity) = match family {
        RiskFamily::TenantIsolation => (
            "tenantId",
            ParameterLocation::Path,
            ScenarioParameterSensitivity::TenantIdentifier,
        ),
        RiskFamily::BolaOwnerScope => (
            "objectId",
            ParameterLocation::Path,
            ScenarioParameterSensitivity::ObjectIdentifier,
        ),
        RiskFamily::MassAssignment => (
            "role",
            ParameterLocation::Body,
            ScenarioParameterSensitivity::AuthorizationMetadata,
        ),
        RiskFamily::PathTraversal => (
            "path",
            ParameterLocation::Query,
            ScenarioParameterSensitivity::FilePath,
        ),
        RiskFamily::SsrfDestination => (
            "url",
            ParameterLocation::Body,
            ScenarioParameterSensitivity::DestinationUrl,
        ),
        RiskFamily::WebhookSignature => (
            "signature",
            ParameterLocation::Header,
            ScenarioParameterSensitivity::Signature,
        ),
        _ => (
            "input",
            ParameterLocation::Body,
            ScenarioParameterSensitivity::Unknown,
        ),
    };
    vec![RiskScenarioParameter {
        name: name.into(),
        location,
        attacker_controlled: true,
        sensitivity,
    }]
}

fn expected_decision_for(family: RiskFamily) -> ExpectedDecision {
    match family {
        RiskFamily::ExcessiveResponseData => ExpectedDecision::AllowMinimal,
        RiskFamily::CorsPolicy => ExpectedDecision::RestrictMetadata,
        RiskFamily::PrivateCachePolicy => ExpectedDecision::StorePrivately,
        RiskFamily::VerboseErrorDisclosure => ExpectedDecision::Sanitize,
        RiskFamily::AbuseRateLimit => ExpectedDecision::Throttle,
        RiskFamily::FailOpenDependency => ExpectedDecision::FailClosed,
        RiskFamily::MassAssignment
        | RiskFamily::WebhookSignature
        | RiskFamily::WebhookReplay
        | RiskFamily::UploadConstraints
        | RiskFamily::PathTraversal
        | RiskFamily::SsrfDestination => ExpectedDecision::Reject,
        _ => ExpectedDecision::Deny,
    }
}

fn broken_decision_for(family: RiskFamily) -> FixtureDecision {
    match family {
        RiskFamily::ExcessiveResponseData => FixtureDecision::ExposesExcessData,
        RiskFamily::MassAssignment => FixtureDecision::AcceptsPolicyFields,
        RiskFamily::CorsPolicy => FixtureDecision::EmitsUnsafeMetadata,
        RiskFamily::PrivateCachePolicy => FixtureDecision::StoresPublicly,
        RiskFamily::VerboseErrorDisclosure => FixtureDecision::EmitsVerboseError,
        RiskFamily::WebhookSignature => FixtureDecision::AcceptsUnverifiedEvent,
        RiskFamily::WebhookReplay => FixtureDecision::AcceptsReplay,
        RiskFamily::UploadConstraints => FixtureDecision::AcceptsUnsafeUpload,
        RiskFamily::PathTraversal => FixtureDecision::EscapesConfinement,
        RiskFamily::SsrfDestination => FixtureDecision::FetchesUntrustedDestination,
        RiskFamily::AbuseRateLimit => FixtureDecision::OmitsThrottle,
        RiskFamily::FailOpenDependency => FixtureDecision::FailsOpen,
        _ => FixtureDecision::AllowsUnexpectedly,
    }
}

fn method_for(family: RiskFamily, framework: RiskScenarioFramework) -> HttpMethod {
    if matches!(
        framework,
        RiskScenarioFramework::GraphQl | RiskScenarioFramework::Trpc
    ) || matches!(
        family,
        RiskFamily::MassAssignment
            | RiskFamily::WebhookSignature
            | RiskFamily::WebhookReplay
            | RiskFamily::UploadConstraints
            | RiskFamily::SsrfDestination
            | RiskFamily::ServerActionAuthorization
    ) {
        HttpMethod::Post
    } else {
        HttpMethod::Get
    }
}

fn route_for(family: RiskFamily, profile: &ProfileDefinition) -> String {
    let family_slug = enum_name(family).to_ascii_lowercase().replace('_', "-");
    match profile.framework {
        RiskScenarioFramework::GraphQl => "/graphql".into(),
        RiskScenarioFramework::Trpc => format!("/api/trpc/{family_slug}"),
        RiskScenarioFramework::NextServerAction => format!("/_actions/{family_slug}"),
        _ => format!(
            "/api/{}/{family_slug}/{{objectId}}",
            profile.id.to_ascii_lowercase()
        ),
    }
}

fn expected_status_for(decision: ExpectedDecision) -> u16 {
    match decision {
        ExpectedDecision::Deny => 403,
        ExpectedDecision::Reject => 400,
        ExpectedDecision::Throttle => 429,
        ExpectedDecision::FailClosed => 503,
        ExpectedDecision::AllowMinimal
        | ExpectedDecision::RestrictMetadata
        | ExpectedDecision::StorePrivately
        | ExpectedDecision::Sanitize => 200,
    }
}

fn risky_status_for(family: RiskFamily) -> u16 {
    if family == RiskFamily::VerboseErrorDisclosure {
        500
    } else {
        200
    }
}

fn expected_fields_for(family: RiskFamily) -> Vec<String> {
    match family {
        RiskFamily::ExcessiveResponseData => vec!["id".into(), "displayName".into()],
        RiskFamily::VerboseErrorDisclosure => vec!["errorCode".into()],
        _ => vec!["decision".into()],
    }
}

fn risky_fields_for(family: RiskFamily, expected: &[String]) -> Vec<String> {
    let mut fields = expected.to_vec();
    match family {
        RiskFamily::ExcessiveResponseData => {
            fields.extend(["email".into(), "tenantId".into(), "passwordHash".into()]);
        }
        RiskFamily::VerboseErrorDisclosure => {
            fields.extend(["stack".into(), "databaseError".into()]);
        }
        _ => {}
    }
    fields.sort();
    fields.dedup();
    fields
}

fn enum_name(family: RiskFamily) -> &'static str {
    match family {
        RiskFamily::MissingAuthentication => "MISSING_AUTHENTICATION",
        RiskFamily::RoleAuthorization => "ROLE_AUTHORIZATION",
        RiskFamily::BolaOwnerScope => "BOLA_OWNER_SCOPE",
        RiskFamily::TenantIsolation => "TENANT_ISOLATION",
        RiskFamily::ExcessiveResponseData => "EXCESSIVE_RESPONSE_DATA",
        RiskFamily::MassAssignment => "MASS_ASSIGNMENT",
        RiskFamily::CorsPolicy => "CORS_POLICY",
        RiskFamily::PrivateCachePolicy => "PRIVATE_CACHE_POLICY",
        RiskFamily::VerboseErrorDisclosure => "VERBOSE_ERROR_DISCLOSURE",
        RiskFamily::WebhookSignature => "WEBHOOK_SIGNATURE",
        RiskFamily::WebhookReplay => "WEBHOOK_REPLAY",
        RiskFamily::UploadConstraints => "UPLOAD_CONSTRAINTS",
        RiskFamily::PathTraversal => "PATH_TRAVERSAL",
        RiskFamily::SsrfDestination => "SSRF_DESTINATION",
        RiskFamily::AbuseRateLimit => "ABUSE_RATE_LIMIT",
        RiskFamily::FailOpenDependency => "FAIL_OPEN_DEPENDENCY",
        RiskFamily::HiddenAdminExposure => "HIDDEN_ADMIN_EXPOSURE",
        RiskFamily::InternalEndpointExposure => "INTERNAL_ENDPOINT_EXPOSURE",
        RiskFamily::ServerActionAuthorization => "SERVER_ACTION_AUTHORIZATION",
        RiskFamily::MiddlewareCoverage => "MIDDLEWARE_COVERAGE",
    }
}

fn aliases<'a>(
    names: impl IntoIterator<Item = &'a str>,
    prefix: &str,
    variant_index: u16,
) -> Vec<VariantAlias> {
    let mut aliases = names
        .into_iter()
        .enumerate()
        .map(|(position, name)| VariantAlias {
            canonical: name.into(),
            variant: format!("{prefix}_{variant_index:02}_{position:02}"),
        })
        .collect::<Vec<_>>();
    aliases.sort();
    aliases
}

fn variant_route(route: &str, variant_index: u16) -> String {
    format!("{}/variant-{variant_index:02}", route.trim_end_matches('/'))
}

fn validate_scenario(
    scenario: &ApiRiskScenario,
    license: &CaseLicense,
) -> Result<(), ApiRiskCorpusError> {
    if !valid_scenario_id(&scenario.scenario_id)
        || !valid_sha256(&scenario.scenario_fingerprint)
        || scenario.scenario_fingerprint != expected_scenario_fingerprint(scenario)
        || !valid_text(&scenario.title, 300)
        || !valid_text(&scenario.description, 1_000)
        || !valid_text(&scenario.runtime, 200)
        || !valid_route(&scenario.route)
        || scenario.parameters.is_empty()
        || scenario.parameters.len() > 20
        || scenario.expected_controls.is_empty()
        || !scenario
            .expected_controls
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || scenario.evidence.is_empty()
        || scenario.evidence.len() > 20
        || scenario.pairing.counterpart_scenario_id == scenario.scenario_id
        || !valid_pair_id(&scenario.pairing.pair_id)
        || !valid_scenario_id(&scenario.pairing.counterpart_scenario_id)
        || scenario.provenance.license_spdx != license.spdx
        || scenario.provenance.generator_version != API_RISK_GENERATOR_VERSION
        || !valid_text(&scenario.provenance.template_id, 200)
        || !valid_text(&scenario.provenance.profile_id, 200)
    {
        return Err(ApiRiskCorpusError::InvalidField("scenario"));
    }
    for parameter in &scenario.parameters {
        if !valid_text(&parameter.name, 200) {
            return Err(ApiRiskCorpusError::InvalidField("scenario parameter"));
        }
    }
    for evidence in &scenario.evidence {
        if !valid_text(&evidence.reference, 500) || !valid_text(&evidence.description, 1_000) {
            return Err(ApiRiskCorpusError::InvalidField("scenario evidence"));
        }
    }
    validate_response(&scenario.response, scenario.ground_truth)?;
    Ok(())
}

fn validate_response(
    response: &RiskScenarioResponse,
    ground_truth: GroundTruth,
) -> Result<(), ApiRiskCorpusError> {
    if !(100..=599).contains(&response.expected_status)
        || !(100..=599).contains(&response.fixture_status)
        || response.expected_fields.len() > 100
        || response.fixture_fields.len() > 100
        || response
            .expected_fields
            .iter()
            .chain(&response.fixture_fields)
            .any(|field| !valid_text(field, 200))
        || ground_truth == GroundTruth::SafeControl
            && (response.fixture_decision != FixtureDecision::MatchesExpected
                || response.expected_status != response.fixture_status
                || response.expected_fields != response.fixture_fields)
        || ground_truth == GroundTruth::RiskySynthetic
            && response.fixture_decision == FixtureDecision::MatchesExpected
    {
        return Err(ApiRiskCorpusError::InvalidField("scenario response"));
    }
    Ok(())
}

fn validate_variant(variant: &VariantDescriptor) -> Result<(), ApiRiskCorpusError> {
    if !valid_prefixed_hash(&variant.variant_id, "sf_web_api_variant_")
        || variant.variant_id != expected_variant_id(variant)
        || !valid_scenario_id(&variant.canonical_scenario_id)
        || !valid_sha256(&variant.canonical_fingerprint)
        || variant.variant_index >= MAX_VARIANTS_PER_SCENARIO
        || !valid_route(&variant.route)
        || !valid_sha256(&variant.lineage_fingerprint)
        || !variant
            .parameter_aliases
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || !variant
            .response_field_aliases
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(ApiRiskCorpusError::InvalidField("variant"));
    }
    for alias in variant
        .parameter_aliases
        .iter()
        .chain(&variant.response_field_aliases)
    {
        if !valid_text(&alias.canonical, 200) || !valid_text(&alias.variant, 200) {
            return Err(ApiRiskCorpusError::InvalidField("variant alias"));
        }
    }
    Ok(())
}

fn expected_scenario_fingerprint(scenario: &ApiRiskScenario) -> String {
    let mut stable = scenario.clone();
    stable.scenario_fingerprint.clear();
    sha256_hex(&serde_json::to_vec(&stable).expect("risk scenario serialization"))
}

fn expected_corpus_id(corpus: &WebApiRiskCorpus) -> String {
    let mut stable = corpus.clone();
    stable.corpus_id.clear();
    format!(
        "sf_web_api_risk_corpus_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("risk corpus serialization"))
    )
}

fn expected_variant_id(variant: &VariantDescriptor) -> String {
    let mut stable = variant.clone();
    stable.variant_id.clear();
    format!(
        "sf_web_api_variant_{}",
        sha256_hex(&serde_json::to_vec(&stable).expect("risk variant serialization"))
    )
}

fn valid_route(route: &str) -> bool {
    route.starts_with('/')
        && !route.starts_with("//")
        && route.len() <= 2_000
        && !route.contains('\\')
        && !route.contains('\0')
        && !route
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
}

fn valid_scenario_id(value: &str) -> bool {
    (16..=80).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_pair_id(value: &str) -> bool {
    value.starts_with("WEBRISK-PAIR-")
        && (16..=80).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_prefixed_hash(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LICENSE_SHA256: &str = "8a59c035575dcb171fc2e90e0c92380d3c2ed1a0612e9577a420119c9ae322a5";

    #[test]
    fn generator_produces_two_hundred_balanced_pairs() {
        let corpus = generate_api_risk_corpus(LICENSE_SHA256).expect("risk corpus");
        assert_eq!(corpus.counts.canonical_pairs, 200);
        assert_eq!(corpus.counts.risky_scenarios, 200);
        assert_eq!(corpus.counts.safe_controls, 200);
        assert_eq!(corpus.counts.total_scenarios, 400);
        assert!(!corpus.claims.independent_holdout);
        assert!(!corpus.claims.human_superiority_claim_allowed);
    }

    #[test]
    fn variants_scale_without_duplicate_materialized_fixtures() {
        let corpus = generate_api_risk_corpus(LICENSE_SHA256).expect("risk corpus");
        let minimum = generate_variant_descriptors(&corpus, 13).expect("5,200 variants");
        let maximum = generate_variant_descriptors(&corpus, 50).expect("20,000 variants");
        assert_eq!(minimum.len(), 5_200);
        assert_eq!(maximum.len(), 20_000);
        assert_ne!(minimum[0].variant_id, minimum[1].variant_id);
        assert!(generate_variant_descriptors(&corpus, 51).is_err());
    }
}
