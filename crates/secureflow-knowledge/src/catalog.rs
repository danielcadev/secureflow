//! Indexed local catalog for public vulnerability advisories.
//!
//! The catalog is intentionally separate from the append-only human-decision
//! ledger. Source records remain attributable to their home database while
//! exact aliases may connect several source records to one internal canonical
//! entity. Upstream and related identifiers never trigger a merge.

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Params, Transaction, TransactionBehavior, params,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const CATALOG_SCHEMA_VERSION: u32 = 3;
pub const CATALOG_APPLICATION_ID: u32 = 0x5346_4b42;
pub const MAX_OSV_RECORD_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_IMPORT_RECORDS: usize = 1_100_000;
pub const MAX_QUERY_RESULTS: usize = 1_000;

const MAX_IDENTIFIERS_PER_RECORD: usize = 1_024;
const MAX_AFFECTED_PER_RECORD: usize = 4_096;
const MAX_REFERENCES_PER_RECORD: usize = 4_096;
const MAX_VERSIONS_PER_AFFECTED: usize = 100_000;
const MAX_CANONICAL_REBUILD_RECORDS: usize = 1_100_000;
const MAX_CANONICAL_REBUILD_RELATIONSHIPS: usize = 5_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogSource {
    pub name: String,
    pub license_expression: String,
    pub license_evidence_sha256: String,
    pub locator: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CatalogImportResult {
    pub records_seen: usize,
    pub records_inserted: usize,
    pub records_updated: usize,
    pub records_unchanged: usize,
    pub duplicate_records_linked: usize,
    pub canonical_groups_merged: usize,
    pub records_deactivated: usize,
}

impl CatalogImportResult {
    pub fn merge(&mut self, other: Self) {
        self.records_seen += other.records_seen;
        self.records_inserted += other.records_inserted;
        self.records_updated += other.records_updated;
        self.records_unchanged += other.records_unchanged;
        self.duplicate_records_linked += other.duplicate_records_linked;
        self.canonical_groups_merged += other.canonical_groups_merged;
        self.records_deactivated += other.records_deactivated;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CatalogStats {
    pub schema_version: u32,
    pub sources: u64,
    pub canonical_vulnerabilities: u64,
    pub active_canonical_vulnerabilities: u64,
    pub source_records: u64,
    pub active_source_records: u64,
    pub inactive_source_records: u64,
    pub source_record_revisions: u64,
    pub snapshots: u64,
    #[serde(default)]
    pub deltas: u64,
    #[serde(default)]
    pub complete_deltas: u64,
    pub identifiers: u64,
    pub relationships: u64,
    pub affected_packages: u64,
    pub references: u64,
    pub raw_revision_bytes: u64,
    pub database_bytes: u64,
    pub search_index_status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CatalogHit {
    pub canonical_id: String,
    pub source_name: String,
    pub source_record_id: String,
    pub title: String,
    pub modified_at: String,
    pub withdrawn: bool,
    pub score: Option<f64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionEvaluationStatus {
    NotEvaluated,
    Affected,
    NotAffected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionEvaluationBasis {
    NotRequested,
    ExactEnumeratedVersion,
    OsvSemverRange,
    SupportedDataExcludesVersion,
    UnsupportedOrInvalidData,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionEvaluationIssue {
    InvalidQuerySemver,
    InvalidStoredJson,
    InvalidSemverEvents,
    MissingVersionData,
    UnsupportedRangeType,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VersionAssessment {
    pub status: VersionEvaluationStatus,
    pub basis: VersionEvaluationBasis,
    pub evaluated_version: Option<String>,
    pub matched_value: Option<String>,
    pub affected_data_sha256: Vec<String>,
    pub issues: Vec<VersionEvaluationIssue>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CatalogVersionHit {
    pub advisory: CatalogHit,
    pub version_assessment: VersionAssessment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CatalogIntegrity {
    pub quick_check: String,
    pub foreign_key_violations: u64,
    pub search_index_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalRebuildResult {
    pub rebuild_id: String,
    pub active_records: u64,
    pub exact_relationships: u64,
    pub old_components: u64,
    pub new_components: u64,
    pub split_components: u64,
    pub merged_components: u64,
    pub unambiguous_redirects: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CatalogProvenance {
    pub schema_version: u32,
    pub complete_snapshot_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub complete_delta_ids: Vec<String>,
    pub canonicalization: String,
    pub last_canonical_rebuild_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogSnapshot {
    pub snapshot_id: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
    pub artifact_revision: String,
    pub expected_ecosystem: String,
    pub acquired_at: String,
    pub accepted_records: u64,
    pub quarantined_records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogDelta {
    pub delta_id: String,
    pub manifest_sha256: String,
    pub index_sha256: String,
    pub index_revision: String,
    pub expected_ecosystem: String,
    pub acquired_at: String,
    pub after_modified: String,
    pub through_modified: String,
    pub base_snapshot_id: String,
    pub previous_delta_id: Option<String>,
    pub accepted_records: u64,
    pub quarantined_records: u64,
    pub withdrawn_records: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OsvRecord {
    #[serde(default)]
    pub schema_version: Option<String>,
    pub id: String,
    pub modified: String,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub withdrawn: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub upstream: Vec<String>,
    #[serde(default)]
    pub related: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub ranges: Vec<serde_json::Value>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
    #[serde(default)]
    pub purl: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OsvReference {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    pub url: String,
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("catalog path is invalid: {0}")]
    InvalidPath(&'static str),
    #[error("catalog filesystem operation failed for {path}: {source}")]
    Filesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("catalog SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("catalog schema mismatch: expected {expected}, observed {observed}")]
    SchemaMismatch { expected: u32, observed: i64 },
    #[error("catalog application id mismatch: observed {0}")]
    ApplicationIdMismatch(i64),
    #[error("OSV record exceeds {maximum} bytes: {bytes}")]
    RecordTooLarge { bytes: u64, maximum: u64 },
    #[error("OSV record is invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("OSV record field is invalid: {0}")]
    InvalidRecord(&'static str),
    #[error("catalog source definition conflicts with the registered source: {0}")]
    SourceConflict(String),
    #[error("import contains more than {0} records")]
    ImportTooLarge(usize),
    #[error("catalog query is invalid: {0}")]
    InvalidQuery(&'static str),
    #[error("catalog WAL checkpoint remained busy with {remaining_frames} frames")]
    CheckpointBusy { remaining_frames: i64 },
    #[error("catalog snapshot metadata conflicts with an existing snapshot: {0}")]
    SnapshotConflict(String),
    #[error("catalog snapshot is not registered: {0}")]
    SnapshotNotRegistered(String),
    #[error("catalog snapshot would roll source {source_name} back from {latest} to {attempted}")]
    SnapshotRollback {
        source_name: String,
        latest: String,
        attempted: String,
    },
    #[error("catalog snapshot is incomplete: {0}")]
    SnapshotIncomplete(String),
    #[error("catalog delta metadata conflicts with an existing delta: {0}")]
    DeltaConflict(String),
    #[error("catalog delta is not registered: {0}")]
    DeltaNotRegistered(String),
    #[error(
        "catalog delta chain would roll back or fork {ecosystem}: latest={latest}, attempted={attempted}"
    )]
    DeltaRollback {
        ecosystem: String,
        latest: String,
        attempted: String,
    },
    #[error("catalog delta is incomplete: {0}")]
    DeltaIncomplete(String),
    #[error(
        "catalog has {0} delta(s) still preparing; resume the exact manifest or restore a verified backup before reading or starting unrelated work"
    )]
    DeltaPreparing(u64),
    #[error("catalog delta contains {0} quarantined records and cannot advance the cursor")]
    DeltaHasQuarantine(u64),
    #[error(
        "catalog delta record would roll back {source_name}/{record_id}: current={current}, attempted={attempted}"
    )]
    DeltaRecordRollback {
        source_name: String,
        record_id: String,
        current: String,
        attempted: String,
    },
    #[error("canonical rebuild exceeds {kind} limit of {maximum}")]
    CanonicalRebuildTooLarge { kind: &'static str, maximum: usize },
}

pub struct Catalog {
    connection: Connection,
    path: PathBuf,
}

struct DisjointSet {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl DisjointSet {
    fn new(length: usize) -> Self {
        Self {
            parent: (0..length).collect(),
            rank: vec![0; length],
        }
    }

    fn find(&mut self, value: usize) -> usize {
        let parent = self.parent[value];
        if parent != value {
            self.parent[value] = self.find(parent);
        }
        self.parent[value]
    }

    fn union(&mut self, left: usize, right: usize) {
        let mut left_root = self.find(left);
        let mut right_root = self.find(right);
        if left_root == right_root {
            return;
        }
        if self.rank[left_root] < self.rank[right_root] {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.parent[right_root] = left_root;
        if self.rank[left_root] == self.rank[right_root] {
            self.rank[left_root] = self.rank[left_root].saturating_add(1);
        }
    }
}

impl Catalog {
    /// Create a consistent SQLite online backup at a new path.
    ///
    /// The destination is published atomically through a same-directory hard
    /// link and is never overwritten. A failed or interrupted backup leaves no
    /// destination that can be mistaken for complete.
    pub fn backup_to(&self, output: &Path) -> Result<(), CatalogError> {
        ensure_no_preparing_delta(&self.connection)?;
        if prepare_catalog_path(output, true)? {
            return Err(CatalogError::InvalidPath(
                "backup destination already exists",
            ));
        }
        let parent = output.parent().ok_or(CatalogError::InvalidPath(
            "backup destination must have a parent directory",
        ))?;
        let name = output
            .file_name()
            .ok_or(CatalogError::InvalidPath(
                "backup destination must name a file",
            ))?
            .to_string_lossy();
        let nonce = OffsetDateTime::now_utc().unix_timestamp_nanos();
        let temporary = (0..100_u32)
            .find_map(|attempt| {
                let candidate = parent.join(format!(
                    ".{name}.backup-{}-{nonce}-{attempt}",
                    std::process::id()
                ));
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                match options.open(&candidate) {
                    Ok(file) => {
                        drop(file);
                        Some(Ok(candidate))
                    }
                    Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(source) => Some(Err(CatalogError::Filesystem {
                        path: candidate,
                        source,
                    })),
                }
            })
            .transpose()?
            .ok_or(CatalogError::InvalidPath(
                "could not allocate temporary backup file",
            ))?;

        let result = (|| {
            let mut destination = Connection::open_with_flags(
                &temporary,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            {
                let backup = rusqlite::backup::Backup::new(&self.connection, &mut destination)?;
                backup.run_to_completion(256, std::time::Duration::from_millis(5), None)?;
            }
            destination.close().map_err(|(_, error)| error)?;
            secure_file_permissions(&temporary)?;
            let file = fs::OpenOptions::new()
                .read(true)
                .open(&temporary)
                .map_err(|source| CatalogError::Filesystem {
                    path: temporary.clone(),
                    source,
                })?;
            file.sync_all().map_err(|source| CatalogError::Filesystem {
                path: temporary.clone(),
                source,
            })?;
            let verification = Catalog::open_existing(&temporary)?;
            ensure_no_preparing_delta(&verification.connection)?;
            let integrity = verification.check_integrity()?;
            if integrity.quick_check != "ok" || integrity.foreign_key_violations != 0 {
                return Err(CatalogError::InvalidPath(
                    "backup integrity verification failed",
                ));
            }
            drop(verification);
            fs::hard_link(&temporary, output).map_err(|source| CatalogError::Filesystem {
                path: output.to_owned(),
                source,
            })?;
            secure_file_permissions(output)?;
            Ok(())
        })();
        let _ = fs::remove_file(&temporary);
        result
    }

    pub fn open_or_create(path: &Path) -> Result<Self, CatalogError> {
        let existed = prepare_catalog_path(path, true)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        if existed {
            configure_connection(&connection, true)?;
            verify_application_id(&connection)?;
            let version = schema_version(&connection)?;
            configure_connection(&connection, false)?;
            migrate_catalog(&connection, version)?;
        } else {
            configure_connection(&connection, false)?;
            initialize_schema(&connection)?;
        }
        verify_schema(&connection)?;
        secure_file_permissions(path)?;
        Ok(Self {
            connection,
            path: path.to_owned(),
        })
    }

    pub fn open_existing(path: &Path) -> Result<Self, CatalogError> {
        prepare_catalog_path(path, false)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, true)?;
        verify_read_schema(&connection)?;
        Ok(Self {
            connection,
            path: path.to_owned(),
        })
    }

    pub fn open_existing_writable(path: &Path) -> Result<Self, CatalogError> {
        prepare_catalog_path(path, false)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, true)?;
        verify_application_id(&connection)?;
        let version = schema_version(&connection)?;
        configure_connection(&connection, false)?;
        migrate_catalog(&connection, version)?;
        verify_schema(&connection)?;
        secure_file_permissions(path)?;
        Ok(Self {
            connection,
            path: path.to_owned(),
        })
    }

    pub fn import_osv_record(
        &mut self,
        source: &CatalogSource,
        bytes: &[u8],
    ) -> Result<CatalogImportResult, CatalogError> {
        self.import_osv_batch(source, std::iter::once(bytes))
    }

    pub fn import_osv_batch<I, B>(
        &mut self,
        source: &CatalogSource,
        records: I,
    ) -> Result<CatalogImportResult, CatalogError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        self.import_osv_batch_internal(source, None, None, records, true)
    }

    /// Imports records without maintaining FTS row by row. The caller must
    /// invoke [`Catalog::rebuild_search_index`] after the final batch.
    pub fn import_osv_batch_deferred_search<I, B>(
        &mut self,
        source: &CatalogSource,
        records: I,
    ) -> Result<CatalogImportResult, CatalogError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        self.import_osv_batch_internal(source, None, None, records, false)
    }

    pub fn register_snapshot(&mut self, snapshot: &CatalogSnapshot) -> Result<(), CatalogError> {
        ensure_no_preparing_delta(&self.connection)?;
        validate_snapshot_descriptor(snapshot)?;
        let imported_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("snapshot.imported_at"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = query_row_optional_cached(
            &transaction,
            "SELECT manifest_sha256, artifact_sha256, artifact_revision,
                    expected_ecosystem, acquired_at, accepted_records,
                    quarantined_records
             FROM advisory_snapshots WHERE snapshot_id = ?1",
            [&snapshot.snapshot_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )?;
        if let Some(existing) = existing {
            let expected = (
                snapshot.manifest_sha256.clone(),
                snapshot.artifact_sha256.clone(),
                snapshot.artifact_revision.clone(),
                snapshot.expected_ecosystem.clone(),
                snapshot.acquired_at.clone(),
                i64::try_from(snapshot.accepted_records)
                    .map_err(|_| CatalogError::InvalidRecord("snapshot.accepted_records"))?,
                i64::try_from(snapshot.quarantined_records)
                    .map_err(|_| CatalogError::InvalidRecord("snapshot.quarantined_records"))?,
            );
            if existing != expected {
                return Err(CatalogError::SnapshotConflict(snapshot.snapshot_id.clone()));
            }
        } else {
            execute_cached(
                &transaction,
                "INSERT INTO advisory_snapshots(
                     snapshot_id, manifest_sha256, artifact_sha256,
                     artifact_revision, expected_ecosystem, acquired_at,
                     accepted_records, quarantined_records, status, imported_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'preparing', ?9)",
                params![
                    snapshot.snapshot_id,
                    snapshot.manifest_sha256,
                    snapshot.artifact_sha256,
                    snapshot.artifact_revision,
                    snapshot.expected_ecosystem,
                    snapshot.acquired_at,
                    snapshot.accepted_records as i64,
                    snapshot.quarantined_records as i64,
                    imported_at,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn register_delta(&mut self, delta: &CatalogDelta) -> Result<(), CatalogError> {
        validate_delta_descriptor(delta)?;
        if delta.quarantined_records != 0 {
            return Err(CatalogError::DeltaHasQuarantine(delta.quarantined_records));
        }
        let imported_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("delta.imported_at"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = query_row_optional_cached(
            &transaction,
            "SELECT manifest_sha256, index_sha256, index_revision,
                    expected_ecosystem, acquired_at, after_modified,
                    through_modified, base_snapshot_id, previous_delta_id,
                    accepted_records, quarantined_records, withdrawn_records
             FROM advisory_deltas WHERE delta_id = ?1",
            [&delta.delta_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )?;
        if let Some(existing) = existing {
            let expected = (
                delta.manifest_sha256.clone(),
                delta.index_sha256.clone(),
                delta.index_revision.clone(),
                delta.expected_ecosystem.clone(),
                delta.acquired_at.clone(),
                delta.after_modified.clone(),
                delta.through_modified.clone(),
                delta.base_snapshot_id.clone(),
                delta.previous_delta_id.clone(),
                i64::try_from(delta.accepted_records)
                    .map_err(|_| CatalogError::InvalidRecord("delta.accepted_records"))?,
                i64::try_from(delta.quarantined_records)
                    .map_err(|_| CatalogError::InvalidRecord("delta.quarantined_records"))?,
                i64::try_from(delta.withdrawn_records)
                    .map_err(|_| CatalogError::InvalidRecord("delta.withdrawn_records"))?,
            );
            if existing != expected {
                return Err(CatalogError::DeltaConflict(delta.delta_id.clone()));
            }
        } else {
            execute_cached(
                &transaction,
                "INSERT INTO advisory_deltas(
                     delta_id, manifest_sha256, index_sha256, index_revision,
                     expected_ecosystem, acquired_at, after_modified,
                     through_modified, base_snapshot_id, previous_delta_id,
                     accepted_records, quarantined_records, withdrawn_records,
                     status, imported_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                           ?12, ?13, 'preparing', ?14)",
                params![
                    delta.delta_id,
                    delta.manifest_sha256,
                    delta.index_sha256,
                    delta.index_revision,
                    delta.expected_ecosystem,
                    delta.acquired_at,
                    delta.after_modified,
                    delta.through_modified,
                    delta.base_snapshot_id,
                    delta.previous_delta_id,
                    delta.accepted_records as i64,
                    delta.quarantined_records as i64,
                    delta.withdrawn_records as i64,
                    imported_at,
                ],
            )?;
        }
        ensure_delta_order(&transaction, &delta.delta_id)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn import_osv_snapshot_batch_deferred_search<I, B>(
        &mut self,
        source: &CatalogSource,
        snapshot_id: &str,
        records: I,
    ) -> Result<CatalogImportResult, CatalogError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        self.import_osv_batch_internal(source, Some(snapshot_id), None, records, false)
    }

    pub fn import_osv_delta_batch_deferred_search<I, B>(
        &mut self,
        source: &CatalogSource,
        delta_id: &str,
        records: I,
    ) -> Result<CatalogImportResult, CatalogError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        self.import_osv_batch_internal(source, None, Some(delta_id), records, false)
    }

    /// Applies a bounded incremental delta while keeping FTS consistent in the
    /// same transaction. This avoids rebuilding the complete search index for
    /// a small modified set.
    pub fn import_osv_delta_batch<I, B>(
        &mut self,
        source: &CatalogSource,
        delta_id: &str,
        records: I,
    ) -> Result<CatalogImportResult, CatalogError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        self.import_osv_batch_internal(source, None, Some(delta_id), records, true)
    }

    fn import_osv_batch_internal<I, B>(
        &mut self,
        source: &CatalogSource,
        snapshot_id: Option<&str>,
        delta_id: Option<&str>,
        records: I,
        update_search_index: bool,
    ) -> Result<CatalogImportResult, CatalogError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        validate_source(source)?;
        if snapshot_id.is_some() && delta_id.is_some() {
            return Err(CatalogError::InvalidRecord("import provenance"));
        }
        if delta_id.is_none() {
            ensure_no_preparing_delta(&self.connection)?;
        }
        if !update_search_index {
            self.connection
                .pragma_update(None, "wal_autocheckpoint", 0_i64)?;
        } else {
            ensure_search_index_ready(&self.connection)?;
        }
        let imported_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("imported_at"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let delta_state = if let Some(delta_id) = delta_id {
            Some(
                query_row_optional_cached(
                    &transaction,
                    "SELECT status, after_modified, through_modified
                     FROM advisory_deltas WHERE delta_id = ?1",
                    [delta_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )?
                .ok_or_else(|| CatalogError::DeltaNotRegistered(delta_id.to_owned()))?,
            )
        } else {
            None
        };
        let completed_replay = delta_state
            .as_ref()
            .is_some_and(|(status, _, _)| status == "complete");
        let source_id = if completed_replay {
            registered_source_id(&transaction, source)?
        } else {
            register_source(&transaction, source, &imported_at)?
        };
        if let Some(snapshot_id) = snapshot_id {
            let registered = query_row_optional_cached(
                &transaction,
                "SELECT 1 FROM advisory_snapshots WHERE snapshot_id = ?1",
                [snapshot_id],
                |row| row.get::<_, i64>(0),
            )?
            .is_some();
            if !registered {
                return Err(CatalogError::SnapshotNotRegistered(snapshot_id.to_owned()));
            }
            ensure_snapshot_order(&transaction, source_id, &source.name, snapshot_id)?;
            execute_cached(
                &transaction,
                "INSERT OR IGNORE INTO source_snapshot_imports(
                     snapshot_id, source_id, record_count, deactivated_records
                 ) VALUES (?1, ?2, 0, 0)",
                params![snapshot_id, source_id],
            )?;
        }
        if let (Some(delta_id), Some(descriptor)) = (delta_id, delta_state.as_ref())
            && descriptor.0 == "preparing"
        {
            ensure_delta_order(&transaction, delta_id)?;
            execute_cached(
                &transaction,
                "INSERT OR IGNORE INTO source_delta_imports(
                     delta_id, source_id, record_count, withdrawn_records
                 ) VALUES (?1, ?2, 0, 0)",
                params![delta_id, source_id],
            )?;
        }
        if !update_search_index && !completed_replay {
            execute_cached(
                &transaction,
                "INSERT INTO catalog_metadata(key, value) VALUES ('search_index_status', 'dirty')
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [],
            )?;
        }
        let mut result = CatalogImportResult::default();
        for bytes in records {
            if result.records_seen >= MAX_IMPORT_RECORDS {
                return Err(CatalogError::ImportTooLarge(MAX_IMPORT_RECORDS));
            }
            let bytes = bytes.as_ref();
            validate_record_size(bytes)?;
            let record: OsvRecord = serde_json::from_slice(bytes)?;
            validate_osv_record_public(&record)?;
            result.records_seen += 1;
            if let (Some(delta_id), Some((status, after_modified, through_modified))) =
                (delta_id, delta_state.as_ref())
            {
                if status == "complete" {
                    verify_completed_delta_record(
                        &transaction,
                        source_id,
                        delta_id,
                        &record,
                        bytes,
                    )?;
                    result.records_unchanged += 1;
                    continue;
                }
                validate_delta_record_order(
                    &transaction,
                    source,
                    source_id,
                    &record,
                    bytes,
                    after_modified,
                    through_modified,
                )?;
            }
            import_osv_record_tx(
                &transaction,
                source,
                source_id,
                &record,
                bytes,
                &imported_at,
                update_search_index,
                &mut result,
            )?;
            if let Some(snapshot_id) = snapshot_id {
                let raw_sha256 = sha256(bytes);
                execute_cached(
                    &transaction,
                    "INSERT INTO snapshot_records(
                         snapshot_id, source_id, source_record_id, raw_sha256
                     ) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(snapshot_id, source_id, source_record_id)
                     DO UPDATE SET raw_sha256 = excluded.raw_sha256",
                    params![snapshot_id, source_id, record.id, raw_sha256],
                )?;
            }
            if let Some(delta_id) = delta_id {
                let raw_sha256 = sha256(bytes);
                let withdrawn = i64::from(record.withdrawn.is_some());
                let existing = query_row_optional_cached(
                    &transaction,
                    "SELECT raw_sha256, withdrawn FROM delta_records
                     WHERE delta_id = ?1 AND source_id = ?2 AND source_record_id = ?3",
                    params![delta_id, source_id, record.id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )?;
                if let Some(existing) = existing {
                    if existing != (raw_sha256, withdrawn) {
                        return Err(CatalogError::DeltaConflict(delta_id.to_owned()));
                    }
                } else {
                    execute_cached(
                        &transaction,
                        "INSERT INTO delta_records(
                             delta_id, source_id, source_record_id, raw_sha256, withdrawn
                         ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![delta_id, source_id, record.id, raw_sha256, withdrawn],
                    )?;
                }
            }
        }
        if let Some(snapshot_id) = snapshot_id {
            execute_cached(
                &transaction,
                "UPDATE source_snapshot_imports SET record_count = (
                     SELECT COUNT(*) FROM snapshot_records
                     WHERE snapshot_id = ?1 AND source_id = ?2
                 ) WHERE snapshot_id = ?1 AND source_id = ?2",
                params![snapshot_id, source_id],
            )?;
        }
        if let Some(delta_id) = delta_id
            && delta_state
                .as_ref()
                .is_some_and(|(status, _, _)| status == "preparing")
        {
            execute_cached(
                &transaction,
                "UPDATE source_delta_imports SET
                     record_count = (
                         SELECT COUNT(*) FROM delta_records
                         WHERE delta_id = ?1 AND source_id = ?2
                     ),
                     withdrawn_records = (
                         SELECT COUNT(*) FROM delta_records
                         WHERE delta_id = ?1 AND source_id = ?2 AND withdrawn = 1
                     )
                 WHERE delta_id = ?1 AND source_id = ?2",
                params![delta_id, source_id],
            )?;
        }
        transaction.commit()?;
        Ok(result)
    }

    pub fn complete_snapshot_source(
        &mut self,
        source: &CatalogSource,
        snapshot_id: &str,
        expected_records: u64,
    ) -> Result<CatalogImportResult, CatalogError> {
        validate_source(source)?;
        let completed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("snapshot.completed_at"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let source_id = query_row_optional_cached(
            &transaction,
            "SELECT source_id FROM sources WHERE name = ?1",
            [&source.name],
            |row| row.get::<_, i64>(0),
        )?
        .ok_or_else(|| CatalogError::SnapshotIncomplete(source.name.clone()))?;
        ensure_snapshot_order(&transaction, source_id, &source.name, snapshot_id)?;
        let observed_records = query_row_cached(
            &transaction,
            "SELECT COUNT(*) FROM snapshot_records
             WHERE snapshot_id = ?1 AND source_id = ?2",
            params![snapshot_id, source_id],
            |row| row.get::<_, i64>(0),
        )?;
        if observed_records
            != i64::try_from(expected_records)
                .map_err(|_| CatalogError::InvalidRecord("snapshot.source.record_count"))?
        {
            return Err(CatalogError::SnapshotIncomplete(format!(
                "{} expected {} records, observed {}",
                source.name, expected_records, observed_records
            )));
        }
        let deactivated = execute_cached(
            &transaction,
            "UPDATE source_records SET active = 0
             WHERE source_id = ?1 AND active = 1
               AND NOT EXISTS (
                   SELECT 1 FROM snapshot_records ss
                   WHERE ss.snapshot_id = ?2
                     AND ss.source_id = source_records.source_id
                     AND ss.source_record_id = source_records.source_record_id
               )",
            params![source_id, snapshot_id],
        )?;
        execute_cached(
            &transaction,
            "UPDATE source_records SET active = 1
             WHERE source_id = ?1 AND EXISTS (
                 SELECT 1 FROM snapshot_records ss
                 WHERE ss.snapshot_id = ?2
                   AND ss.source_id = source_records.source_id
                   AND ss.source_record_id = source_records.source_record_id
             )",
            params![source_id, snapshot_id],
        )?;
        execute_cached(
            &transaction,
            "UPDATE source_snapshot_imports
             SET record_count = ?1, deactivated_records = ?2, completed_at = ?3
             WHERE snapshot_id = ?4 AND source_id = ?5",
            params![
                expected_records as i64,
                deactivated as i64,
                completed_at,
                snapshot_id,
                source_id,
            ],
        )?;
        execute_cached(
            &transaction,
            "INSERT INTO catalog_metadata(key, value) VALUES ('search_index_status', 'dirty')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [],
        )?;
        transaction.commit()?;
        Ok(CatalogImportResult {
            records_deactivated: deactivated,
            ..CatalogImportResult::default()
        })
    }

    pub fn complete_snapshot(&mut self, snapshot_id: &str) -> Result<(), CatalogError> {
        let completed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("snapshot.completed_at"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected = query_row_optional_cached(
            &transaction,
            "SELECT accepted_records FROM advisory_snapshots WHERE snapshot_id = ?1",
            [snapshot_id],
            |row| row.get::<_, i64>(0),
        )?
        .ok_or_else(|| CatalogError::SnapshotNotRegistered(snapshot_id.to_owned()))?;
        let observed = query_row_cached(
            &transaction,
            "SELECT COUNT(*) FROM snapshot_records WHERE snapshot_id = ?1",
            [snapshot_id],
            |row| row.get::<_, i64>(0),
        )?;
        let incomplete_sources = query_row_cached(
            &transaction,
            "SELECT COUNT(*) FROM source_snapshot_imports
             WHERE snapshot_id = ?1 AND completed_at IS NULL",
            [snapshot_id],
            |row| row.get::<_, i64>(0),
        )?;
        if expected != observed || incomplete_sources != 0 {
            return Err(CatalogError::SnapshotIncomplete(format!(
                "{snapshot_id}: expected={expected} observed={observed} incomplete_sources={incomplete_sources}"
            )));
        }
        execute_cached(
            &transaction,
            "UPDATE advisory_snapshots
             SET status = 'complete', completed_at = ?1 WHERE snapshot_id = ?2",
            params![completed_at, snapshot_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn complete_delta_source(
        &mut self,
        source: &CatalogSource,
        delta_id: &str,
        expected_records: u64,
        expected_withdrawn: u64,
    ) -> Result<(), CatalogError> {
        validate_source(source)?;
        let completed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("delta.completed_at"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status = query_row_optional_cached(
            &transaction,
            "SELECT status FROM advisory_deltas WHERE delta_id = ?1",
            [delta_id],
            |row| row.get::<_, String>(0),
        )?
        .ok_or_else(|| CatalogError::DeltaNotRegistered(delta_id.to_owned()))?;
        if status == "preparing" {
            ensure_delta_order(&transaction, delta_id)?;
        }
        let source_id = query_row_optional_cached(
            &transaction,
            "SELECT source_id FROM sources WHERE name = ?1",
            [&source.name],
            |row| row.get::<_, i64>(0),
        )?
        .ok_or_else(|| CatalogError::DeltaIncomplete(source.name.clone()))?;
        let observed = query_row_cached(
            &transaction,
            "SELECT COUNT(*), COALESCE(SUM(withdrawn), 0) FROM delta_records
             WHERE delta_id = ?1 AND source_id = ?2",
            params![delta_id, source_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let expected = (
            i64::try_from(expected_records)
                .map_err(|_| CatalogError::InvalidRecord("delta.source.record_count"))?,
            i64::try_from(expected_withdrawn)
                .map_err(|_| CatalogError::InvalidRecord("delta.source.withdrawn_records"))?,
        );
        if observed != expected {
            return Err(CatalogError::DeltaIncomplete(format!(
                "{} expected {:?}, observed {:?}",
                source.name, expected, observed
            )));
        }
        if status == "complete" {
            return Ok(());
        }
        execute_cached(
            &transaction,
            "UPDATE source_delta_imports
             SET record_count = ?1, withdrawn_records = ?2, completed_at = ?3
             WHERE delta_id = ?4 AND source_id = ?5",
            params![expected.0, expected.1, completed_at, delta_id, source_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn complete_delta(&mut self, delta_id: &str) -> Result<(), CatalogError> {
        let completed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("delta.completed_at"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let descriptor = query_row_optional_cached(
            &transaction,
            "SELECT accepted_records, withdrawn_records, status
             FROM advisory_deltas WHERE delta_id = ?1",
            [delta_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?
        .ok_or_else(|| CatalogError::DeltaNotRegistered(delta_id.to_owned()))?;
        if descriptor.2 == "preparing" {
            ensure_delta_order(&transaction, delta_id)?;
        }
        let observed = query_row_cached(
            &transaction,
            "SELECT COUNT(*), COALESCE(SUM(withdrawn), 0)
             FROM delta_records WHERE delta_id = ?1",
            [delta_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let incomplete_sources = query_row_cached(
            &transaction,
            "SELECT COUNT(*) FROM source_delta_imports
             WHERE delta_id = ?1 AND completed_at IS NULL",
            [delta_id],
            |row| row.get::<_, i64>(0),
        )?;
        if observed != (descriptor.0, descriptor.1) || incomplete_sources != 0 {
            return Err(CatalogError::DeltaIncomplete(format!(
                "{delta_id}: expected=({}, {}) observed={observed:?} incomplete_sources={incomplete_sources}",
                descriptor.0, descriptor.1
            )));
        }
        if descriptor.2 == "complete" {
            return Ok(());
        }
        execute_cached(
            &transaction,
            "UPDATE advisory_deltas
             SET status = 'complete', completed_at = ?1 WHERE delta_id = ?2",
            params![completed_at, delta_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn rebuild_canonicalization(&mut self) -> Result<CanonicalRebuildResult, CatalogError> {
        ensure_no_preparing_delta(&self.connection)?;
        #[derive(Debug)]
        struct RecordState {
            rowid: i64,
            source_name: String,
            source_record_id: String,
            raw_sha256: String,
            old_canonical_id: String,
            candidate_id: String,
        }

        let rebuilt_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("canonical.rebuilt_at"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let records = {
            let mut statement = transaction.prepare(
                "SELECT sr.record_rowid, s.name, sr.source_record_id,
                        sr.raw_sha256, sr.canonical_id
                 FROM source_records sr
                 JOIN sources s ON s.source_id = sr.source_id
                 WHERE sr.active = 1
                 ORDER BY s.name, sr.source_record_id",
            )?;
            let rows = statement.query_map([], |row| {
                let source_name = row.get::<_, String>(1)?;
                let source_record_id = row.get::<_, String>(2)?;
                Ok(RecordState {
                    rowid: row.get(0)?,
                    candidate_id: canonical_id(&source_name, &source_record_id),
                    source_name,
                    source_record_id,
                    raw_sha256: row.get(3)?,
                    old_canonical_id: row.get(4)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if records.len() > MAX_CANONICAL_REBUILD_RECORDS {
            return Err(CatalogError::CanonicalRebuildTooLarge {
                kind: "record",
                maximum: MAX_CANONICAL_REBUILD_RECORDS,
            });
        }
        let mut dsu = DisjointSet::new(records.len());
        let row_indexes = records
            .iter()
            .enumerate()
            .map(|(index, record)| (record.rowid, index))
            .collect::<HashMap<_, _>>();
        let mut identifier_owners = HashMap::<String, usize>::new();
        for (index, record) in records.iter().enumerate() {
            if let Some(owner) = identifier_owners.insert(record.source_record_id.clone(), index) {
                dsu.union(owner, index);
            }
        }
        let mut relationship_count = records.len();
        {
            let mut statement = transaction.prepare(
                "SELECT ir.source_record_rowid, ir.identifier
                 FROM identifier_relationships ir
                 JOIN source_records sr ON sr.record_rowid = ir.source_record_rowid
                 WHERE sr.active = 1 AND ir.kind = 'alias'
                 ORDER BY ir.identifier, ir.source_record_rowid",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                relationship_count = relationship_count.saturating_add(1);
                if relationship_count > MAX_CANONICAL_REBUILD_RELATIONSHIPS {
                    return Err(CatalogError::CanonicalRebuildTooLarge {
                        kind: "exact relationship",
                        maximum: MAX_CANONICAL_REBUILD_RELATIONSHIPS,
                    });
                }
                let rowid = row.get::<_, i64>(0)?;
                let identifier = row.get::<_, String>(1)?;
                let index = *row_indexes
                    .get(&rowid)
                    .ok_or(CatalogError::InvalidRecord("canonical.record_rowid"))?;
                if let Some(owner) = identifier_owners.insert(identifier, index) {
                    dsu.union(owner, index);
                }
            }
        }
        let mut selected_by_root = HashMap::<usize, String>::new();
        for (index, record) in records.iter().enumerate() {
            let root = dsu.find(index);
            selected_by_root
                .entry(root)
                .and_modify(|selected| {
                    if record.candidate_id < *selected {
                        *selected = record.candidate_id.clone();
                    }
                })
                .or_insert_with(|| record.candidate_id.clone());
        }
        let selected_by_record = records
            .iter()
            .enumerate()
            .map(|(index, _)| {
                selected_by_root
                    .get(&dsu.find(index))
                    .cloned()
                    .ok_or(CatalogError::InvalidRecord("canonical.component"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut old_to_new = HashMap::<String, BTreeSet<String>>::new();
        let mut new_to_old = HashMap::<String, BTreeSet<String>>::new();
        for (record, selected) in records.iter().zip(&selected_by_record) {
            old_to_new
                .entry(record.old_canonical_id.clone())
                .or_default()
                .insert(selected.clone());
            new_to_old
                .entry(selected.clone())
                .or_default()
                .insert(record.old_canonical_id.clone());
        }
        let historical_redirects = {
            let mut statement = transaction
                .prepare("SELECT old_canonical_id, canonical_id FROM canonical_redirects")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "secureflow-canonical-rebuild-v2");
        for (record, selected) in records.iter().zip(&selected_by_record) {
            hash_field(&mut hasher, &record.source_name);
            hash_field(&mut hasher, &record.source_record_id);
            hash_field(&mut hasher, &record.raw_sha256);
            hash_field(&mut hasher, selected);
        }
        let rebuild_id = format!("sf_canonical_{}", hex_digest(hasher.finalize().as_slice()));

        execute_cached(&transaction, "DELETE FROM identifiers", [])?;
        execute_cached(&transaction, "DELETE FROM canonical_redirects", [])?;
        for selected in selected_by_root.values() {
            execute_cached(
                &transaction,
                "INSERT OR IGNORE INTO canonical_vulnerabilities(
                     canonical_id, created_at, updated_at
                 ) VALUES (?1, ?2, ?2)",
                params![selected, rebuilt_at],
            )?;
        }
        for (record, selected) in records.iter().zip(&selected_by_record) {
            execute_cached(
                &transaction,
                "UPDATE source_records SET canonical_id = ?1 WHERE record_rowid = ?2",
                params![selected, record.rowid],
            )?;
        }
        for (identifier, owner) in &identifier_owners {
            let selected = selected_by_root
                .get(&dsu.find(*owner))
                .ok_or(CatalogError::InvalidRecord("canonical.identifier"))?;
            execute_cached(
                &transaction,
                "INSERT INTO identifiers(identifier, canonical_id) VALUES (?1, ?2)",
                params![identifier, selected],
            )?;
        }
        let mut redirects = BTreeSet::<(String, String)>::new();
        for (old, targets) in &old_to_new {
            if targets.len() == 1 {
                let target = targets.iter().next().expect("one target");
                if old != target {
                    redirects.insert((old.clone(), target.clone()));
                }
            }
        }
        for (historical, previous_target) in historical_redirects {
            if let Some(targets) = old_to_new.get(&previous_target)
                && targets.len() == 1
            {
                let target = targets.iter().next().expect("one target");
                if historical != *target {
                    redirects.insert((historical, target.clone()));
                }
            }
        }
        for (old, target) in &redirects {
            execute_cached(
                &transaction,
                "INSERT INTO canonical_redirects(old_canonical_id, canonical_id)
                 VALUES (?1, ?2)",
                params![old, target],
            )?;
        }
        execute_cached(
            &transaction,
            "DELETE FROM canonical_vulnerabilities
             WHERE NOT EXISTS (
                 SELECT 1 FROM source_records sr
                 WHERE sr.canonical_id = canonical_vulnerabilities.canonical_id
             ) AND NOT EXISTS (
                 SELECT 1 FROM identifiers i
                 WHERE i.canonical_id = canonical_vulnerabilities.canonical_id
             )",
            [],
        )?;
        execute_cached(
            &transaction,
            "INSERT INTO catalog_metadata(key, value)
             VALUES ('canonicalization', 'exact-osv-alias-rebuild-v2')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [],
        )?;
        execute_cached(
            &transaction,
            "INSERT INTO catalog_metadata(key, value) VALUES ('last_canonical_rebuild_id', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [&rebuild_id],
        )?;
        transaction.commit()?;

        Ok(CanonicalRebuildResult {
            rebuild_id,
            active_records: records.len() as u64,
            exact_relationships: relationship_count as u64,
            old_components: old_to_new.len() as u64,
            new_components: selected_by_root.len() as u64,
            split_components: old_to_new
                .values()
                .filter(|targets| targets.len() > 1)
                .count() as u64,
            merged_components: new_to_old
                .values()
                .filter(|sources| sources.len() > 1)
                .count() as u64,
            unambiguous_redirects: redirects.len() as u64,
        })
    }

    pub fn rebuild_search_index(&mut self) -> Result<(), CatalogError> {
        ensure_no_preparing_delta(&self.connection)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        execute_cached(&transaction, "DELETE FROM source_record_fts", [])?;
        execute_cached(
            &transaction,
            "INSERT INTO source_record_fts(rowid, title, details)
             SELECT record_rowid, title, details FROM source_records WHERE active = 1",
            [],
        )?;
        execute_cached(
            &transaction,
            "INSERT INTO catalog_metadata(key, value) VALUES ('search_index_status', 'ready')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [],
        )?;
        transaction.commit()?;
        self.connection.execute_batch("PRAGMA optimize;")?;
        let (busy, log_frames, checkpointed_frames) =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?;
        self.connection
            .pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;
        if busy != 0 {
            return Err(CatalogError::CheckpointBusy {
                remaining_frames: log_frames.saturating_sub(checkpointed_frames),
            });
        }
        Ok(())
    }

    pub fn lookup_identifier(
        &self,
        identifier: &str,
        limit: usize,
    ) -> Result<Vec<CatalogHit>, CatalogError> {
        ensure_no_preparing_delta(&self.connection)?;
        validate_query(identifier, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT sr.canonical_id, s.name, sr.source_record_id, sr.title,
                    sr.modified_at, sr.withdrawn_at IS NOT NULL
             FROM identifiers i
             JOIN source_records sr ON sr.canonical_id = i.canonical_id
             JOIN sources s ON s.source_id = sr.source_id
             WHERE i.identifier = ?1 AND sr.active = 1
             ORDER BY sr.withdrawn_at IS NOT NULL, s.name, sr.source_record_id
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![identifier, limit as i64], hit_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn search_text(&self, query: &str, limit: usize) -> Result<Vec<CatalogHit>, CatalogError> {
        ensure_no_preparing_delta(&self.connection)?;
        validate_query(query, limit)?;
        ensure_search_index_ready(&self.connection)?;
        let escaped = format!("\"{}\"", query.replace('"', "\"\""));
        let mut statement = self.connection.prepare(
            "SELECT sr.canonical_id, s.name, sr.source_record_id, sr.title,
                    sr.modified_at, sr.withdrawn_at IS NOT NULL,
                    bm25(source_record_fts)
             FROM source_record_fts
             JOIN source_records sr ON sr.record_rowid = source_record_fts.rowid
             JOIN sources s ON s.source_id = sr.source_id
             WHERE source_record_fts MATCH ?1 AND sr.active = 1
             ORDER BY bm25(source_record_fts), sr.withdrawn_at IS NOT NULL,
                      s.name, sr.source_record_id
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![escaped, limit as i64], |row| {
            Ok(CatalogHit {
                canonical_id: row.get(0)?,
                source_name: row.get(1)?,
                source_record_id: row.get(2)?,
                title: row.get(3)?,
                modified_at: row.get(4)?,
                withdrawn: row.get(5)?,
                score: Some(row.get(6)?),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn search_package(
        &self,
        ecosystem: &str,
        name: &str,
        limit: usize,
    ) -> Result<Vec<CatalogHit>, CatalogError> {
        ensure_no_preparing_delta(&self.connection)?;
        validate_query(ecosystem, limit)?;
        validate_query(name, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT sr.canonical_id, s.name, sr.source_record_id,
                    sr.title, sr.modified_at, sr.withdrawn_at IS NOT NULL
             FROM affected_packages ap
             JOIN source_records sr ON sr.record_rowid = ap.source_record_rowid
             JOIN sources s ON s.source_id = sr.source_id
             WHERE ap.ecosystem = ?1 AND ap.package_name = ?2 AND sr.active = 1
             ORDER BY sr.withdrawn_at IS NOT NULL, s.name, sr.source_record_id
             LIMIT ?3",
        )?;
        let rows = statement.query_map(params![ecosystem, name, limit as i64], hit_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn search_package_version(
        &self,
        ecosystem: &str,
        name: &str,
        version: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CatalogVersionHit>, CatalogError> {
        validate_query(ecosystem, limit)?;
        validate_query(name, limit)?;
        if let Some(version) = version {
            validate_query(version, limit)?;
        }
        let hits = self.search_package(ecosystem, name, limit)?;
        let mut output = Vec::with_capacity(hits.len());
        let mut statement = self.connection.prepare(
            "SELECT ap.ranges_json, ap.versions_json
             FROM affected_packages ap
             JOIN source_records sr ON sr.record_rowid = ap.source_record_rowid
             JOIN sources s ON s.source_id = sr.source_id
             WHERE s.name = ?1 AND sr.source_record_id = ?2
               AND ap.ecosystem = ?3 AND ap.package_name = ?4
             ORDER BY ap.affected_id",
        )?;
        for hit in hits {
            let rows = statement
                .query_map(
                    params![hit.source_name, hit.source_record_id, ecosystem, name],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            output.push(CatalogVersionHit {
                advisory: hit,
                version_assessment: evaluate_package_version(version, &rows),
            });
        }
        Ok(output)
    }

    pub fn stats(&self) -> Result<CatalogStats, CatalogError> {
        let database_bytes = database_size(&self.path)?;
        let observed_schema = schema_version(&self.connection)?;
        let (deltas, complete_deltas) = if observed_schema >= 3 {
            (
                count(&self.connection, "advisory_deltas")?,
                nonnegative_count(self.connection.query_row(
                    "SELECT COUNT(*) FROM advisory_deltas WHERE status = 'complete'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)?,
            )
        } else {
            (0, 0)
        };
        Ok(CatalogStats {
            schema_version: u32::try_from(observed_schema)
                .map_err(|_| CatalogError::InvalidPath("negative catalog schema version"))?,
            sources: count(&self.connection, "sources")?,
            canonical_vulnerabilities: count(&self.connection, "canonical_vulnerabilities")?,
            active_canonical_vulnerabilities: nonnegative_count(self.connection.query_row(
                "SELECT COUNT(DISTINCT canonical_id) FROM source_records WHERE active = 1",
                [],
                |row| row.get::<_, i64>(0),
            )?)?,
            source_records: count(&self.connection, "source_records")?,
            active_source_records: nonnegative_count(self.connection.query_row(
                "SELECT COUNT(*) FROM source_records WHERE active = 1",
                [],
                |row| row.get::<_, i64>(0),
            )?)?,
            inactive_source_records: nonnegative_count(self.connection.query_row(
                "SELECT COUNT(*) FROM source_records WHERE active = 0",
                [],
                |row| row.get::<_, i64>(0),
            )?)?,
            source_record_revisions: count(&self.connection, "source_record_revisions")?,
            snapshots: count(&self.connection, "advisory_snapshots")?,
            deltas,
            complete_deltas,
            identifiers: count(&self.connection, "identifiers")?,
            relationships: count(&self.connection, "identifier_relationships")?,
            affected_packages: count(&self.connection, "affected_packages")?,
            references: count(&self.connection, "advisory_references")?,
            raw_revision_bytes: nonnegative_count(self.connection.query_row(
                "SELECT COALESCE(SUM(length(raw_json)), 0) FROM source_record_revisions",
                [],
                |row| row.get::<_, i64>(0),
            )?)?,
            database_bytes,
            search_index_status: search_index_status(&self.connection)?,
        })
    }

    pub fn check_integrity(&self) -> Result<CatalogIntegrity, CatalogError> {
        let quick_check = self
            .connection
            .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))?;
        let mut statement = self.connection.prepare("PRAGMA foreign_key_check")?;
        let mut rows = statement.query([])?;
        let mut foreign_key_violations = 0_u64;
        while rows.next()?.is_some() {
            foreign_key_violations = foreign_key_violations.saturating_add(1);
        }
        Ok(CatalogIntegrity {
            quick_check,
            foreign_key_violations,
            search_index_status: search_index_status(&self.connection)?,
        })
    }

    pub fn provenance(&self) -> Result<CatalogProvenance, CatalogError> {
        ensure_no_preparing_delta(&self.connection)?;
        let observed_schema = schema_version(&self.connection)?;
        let complete_snapshot_ids = {
            let mut statement = self.connection.prepare(
                "SELECT snapshot_id FROM advisory_snapshots
                 WHERE status = 'complete' ORDER BY snapshot_id",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let complete_delta_ids = if observed_schema >= 3 {
            let mut statement = self.connection.prepare(
                "SELECT delta_id FROM advisory_deltas
                 WHERE status = 'complete' ORDER BY delta_id",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        let canonicalization = self.connection.query_row(
            "SELECT value FROM catalog_metadata WHERE key = 'canonicalization'",
            [],
            |row| row.get::<_, String>(0),
        )?;
        let last_canonical_rebuild_id = self
            .connection
            .query_row(
                "SELECT value FROM catalog_metadata WHERE key = 'last_canonical_rebuild_id'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(CatalogProvenance {
            schema_version: u32::try_from(observed_schema)
                .map_err(|_| CatalogError::InvalidPath("negative catalog schema version"))?,
            complete_snapshot_ids,
            complete_delta_ids,
            canonicalization,
            last_canonical_rebuild_id,
        })
    }
}

fn configure_connection(connection: &Connection, read_only: bool) -> Result<(), CatalogError> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "cache_size", -65_536_i64)?;
    if !read_only {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
    }
    Ok(())
}

fn initialize_schema(connection: &Connection) -> Result<(), CatalogError> {
    connection.execute_batch(&format!(
        "PRAGMA application_id = {CATALOG_APPLICATION_ID};
         PRAGMA user_version = {CATALOG_SCHEMA_VERSION};

         CREATE TABLE IF NOT EXISTS catalog_metadata (
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS sources (
             source_id INTEGER PRIMARY KEY,
             name TEXT NOT NULL UNIQUE,
             license_expression TEXT NOT NULL,
             license_evidence_sha256 TEXT NOT NULL,
             locator TEXT NOT NULL,
             first_imported_at TEXT NOT NULL,
             last_imported_at TEXT NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS canonical_vulnerabilities (
             canonical_id TEXT PRIMARY KEY,
             created_at TEXT NOT NULL,
             updated_at TEXT NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS canonical_redirects (
             old_canonical_id TEXT PRIMARY KEY,
             canonical_id TEXT NOT NULL REFERENCES canonical_vulnerabilities(canonical_id)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS advisory_snapshots (
             snapshot_id TEXT PRIMARY KEY,
             manifest_sha256 TEXT NOT NULL UNIQUE,
             artifact_sha256 TEXT NOT NULL,
             artifact_revision TEXT NOT NULL,
             expected_ecosystem TEXT NOT NULL,
             acquired_at TEXT NOT NULL,
             accepted_records INTEGER NOT NULL CHECK(accepted_records >= 0),
             quarantined_records INTEGER NOT NULL CHECK(quarantined_records >= 0),
             status TEXT NOT NULL CHECK(status IN ('preparing', 'complete')),
             imported_at TEXT NOT NULL,
             completed_at TEXT
         ) STRICT;

         CREATE TABLE IF NOT EXISTS source_record_revisions (
             revision_id INTEGER PRIMARY KEY,
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             source_record_id TEXT NOT NULL,
             modified_at TEXT NOT NULL,
             raw_sha256 TEXT NOT NULL,
             raw_json BLOB NOT NULL,
             imported_at TEXT NOT NULL,
             UNIQUE(source_id, source_record_id, raw_sha256)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS source_records (
             record_rowid INTEGER PRIMARY KEY,
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             source_record_id TEXT NOT NULL,
             canonical_id TEXT NOT NULL REFERENCES canonical_vulnerabilities(canonical_id),
             modified_at TEXT NOT NULL,
             published_at TEXT,
             withdrawn_at TEXT,
             title TEXT NOT NULL,
             details TEXT NOT NULL,
             raw_sha256 TEXT NOT NULL,
             current_revision_id INTEGER NOT NULL REFERENCES source_record_revisions(revision_id),
             active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
             UNIQUE(source_id, source_record_id)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS snapshot_records (
             snapshot_id TEXT NOT NULL REFERENCES advisory_snapshots(snapshot_id),
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             source_record_id TEXT NOT NULL,
             raw_sha256 TEXT NOT NULL,
             PRIMARY KEY(snapshot_id, source_id, source_record_id)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS source_snapshot_imports (
             snapshot_id TEXT NOT NULL REFERENCES advisory_snapshots(snapshot_id),
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             record_count INTEGER NOT NULL CHECK(record_count >= 0),
             deactivated_records INTEGER NOT NULL DEFAULT 0 CHECK(deactivated_records >= 0),
             completed_at TEXT,
             PRIMARY KEY(snapshot_id, source_id)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS advisory_deltas (
             delta_id TEXT PRIMARY KEY,
             manifest_sha256 TEXT NOT NULL UNIQUE,
             index_sha256 TEXT NOT NULL,
             index_revision TEXT NOT NULL,
             expected_ecosystem TEXT NOT NULL,
             acquired_at TEXT NOT NULL,
             after_modified TEXT NOT NULL,
             through_modified TEXT NOT NULL,
             base_snapshot_id TEXT NOT NULL REFERENCES advisory_snapshots(snapshot_id),
             previous_delta_id TEXT REFERENCES advisory_deltas(delta_id),
             accepted_records INTEGER NOT NULL CHECK(accepted_records >= 0),
             quarantined_records INTEGER NOT NULL CHECK(quarantined_records >= 0),
             withdrawn_records INTEGER NOT NULL CHECK(withdrawn_records >= 0),
             status TEXT NOT NULL CHECK(status IN ('preparing', 'complete')),
             imported_at TEXT NOT NULL,
             completed_at TEXT
         ) STRICT;

         CREATE TABLE IF NOT EXISTS delta_records (
             delta_id TEXT NOT NULL REFERENCES advisory_deltas(delta_id),
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             source_record_id TEXT NOT NULL,
             raw_sha256 TEXT NOT NULL,
             withdrawn INTEGER NOT NULL CHECK(withdrawn IN (0, 1)),
             PRIMARY KEY(delta_id, source_id, source_record_id)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS source_delta_imports (
             delta_id TEXT NOT NULL REFERENCES advisory_deltas(delta_id),
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             record_count INTEGER NOT NULL CHECK(record_count >= 0),
             withdrawn_records INTEGER NOT NULL DEFAULT 0 CHECK(withdrawn_records >= 0),
             completed_at TEXT,
             PRIMARY KEY(delta_id, source_id)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS identifiers (
             identifier TEXT PRIMARY KEY,
             canonical_id TEXT NOT NULL REFERENCES canonical_vulnerabilities(canonical_id)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS identifier_relationships (
             source_record_rowid INTEGER NOT NULL REFERENCES source_records(record_rowid) ON DELETE CASCADE,
             kind TEXT NOT NULL CHECK(kind IN ('primary', 'alias', 'upstream', 'related')),
             identifier TEXT NOT NULL,
             PRIMARY KEY(source_record_rowid, kind, identifier)
         ) STRICT;

         CREATE TABLE IF NOT EXISTS affected_packages (
             affected_id INTEGER PRIMARY KEY,
             source_record_rowid INTEGER NOT NULL REFERENCES source_records(record_rowid) ON DELETE CASCADE,
             ecosystem TEXT NOT NULL,
             package_name TEXT NOT NULL,
             purl TEXT,
             ranges_json TEXT NOT NULL,
             versions_json TEXT NOT NULL
         ) STRICT;

         CREATE TABLE IF NOT EXISTS advisory_references (
             reference_id INTEGER PRIMARY KEY,
             source_record_rowid INTEGER NOT NULL REFERENCES source_records(record_rowid) ON DELETE CASCADE,
             kind TEXT,
             url TEXT NOT NULL,
             UNIQUE(source_record_rowid, kind, url)
         ) STRICT;

         CREATE INDEX IF NOT EXISTS source_records_canonical_idx
             ON source_records(canonical_id);
         CREATE INDEX IF NOT EXISTS source_records_active_idx
             ON source_records(source_id, active, source_record_id);
         CREATE INDEX IF NOT EXISTS source_snapshot_imports_source_idx
             ON source_snapshot_imports(source_id, completed_at);
         CREATE INDEX IF NOT EXISTS advisory_deltas_ecosystem_idx
             ON advisory_deltas(expected_ecosystem, acquired_at, status);
         CREATE INDEX IF NOT EXISTS source_delta_imports_source_idx
             ON source_delta_imports(source_id, completed_at);
         CREATE INDEX IF NOT EXISTS identifiers_canonical_idx
             ON identifiers(canonical_id);
         CREATE INDEX IF NOT EXISTS canonical_redirects_target_idx
             ON canonical_redirects(canonical_id);
         CREATE INDEX IF NOT EXISTS affected_packages_lookup_idx
             ON affected_packages(ecosystem, package_name, source_record_rowid);
         CREATE INDEX IF NOT EXISTS identifier_relationships_identifier_idx
             ON identifier_relationships(identifier);
         CREATE INDEX IF NOT EXISTS source_record_revisions_lookup_idx
             ON source_record_revisions(source_id, source_record_id, imported_at);

         CREATE VIRTUAL TABLE IF NOT EXISTS source_record_fts USING fts5(
             title,
             details,
             content = '',
             contentless_delete = 1,
             tokenize = 'unicode61 remove_diacritics 2'
         );

         INSERT OR IGNORE INTO catalog_metadata(key, value)
             VALUES ('canonicalization', 'exact-osv-alias-union-v1');
         INSERT OR IGNORE INTO catalog_metadata(key, value)
             VALUES ('search_index_status', 'ready');"
    ))?;
    Ok(())
}

fn migrate_v1_to_v2(connection: &Connection) -> Result<(), CatalogError> {
    let result = connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE advisory_snapshots (
             snapshot_id TEXT PRIMARY KEY,
             manifest_sha256 TEXT NOT NULL UNIQUE,
             artifact_sha256 TEXT NOT NULL,
             artifact_revision TEXT NOT NULL,
             expected_ecosystem TEXT NOT NULL,
             acquired_at TEXT NOT NULL,
             accepted_records INTEGER NOT NULL CHECK(accepted_records >= 0),
             quarantined_records INTEGER NOT NULL CHECK(quarantined_records >= 0),
             status TEXT NOT NULL CHECK(status IN ('preparing', 'complete')),
             imported_at TEXT NOT NULL,
             completed_at TEXT
         ) STRICT;
         ALTER TABLE source_records
             ADD COLUMN active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1));
         CREATE TABLE snapshot_records (
             snapshot_id TEXT NOT NULL REFERENCES advisory_snapshots(snapshot_id),
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             source_record_id TEXT NOT NULL,
             raw_sha256 TEXT NOT NULL,
             PRIMARY KEY(snapshot_id, source_id, source_record_id)
         ) STRICT;
         CREATE TABLE source_snapshot_imports (
             snapshot_id TEXT NOT NULL REFERENCES advisory_snapshots(snapshot_id),
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             record_count INTEGER NOT NULL CHECK(record_count >= 0),
             deactivated_records INTEGER NOT NULL DEFAULT 0 CHECK(deactivated_records >= 0),
             completed_at TEXT,
             PRIMARY KEY(snapshot_id, source_id)
         ) STRICT;
         CREATE INDEX source_records_active_idx
             ON source_records(source_id, active, source_record_id);
         CREATE INDEX source_snapshot_imports_source_idx
             ON source_snapshot_imports(source_id, completed_at);
         PRAGMA user_version = 2;
         COMMIT;",
    );
    if let Err(error) = result {
        let _ = connection.execute_batch("ROLLBACK;");
        return Err(error.into());
    }
    Ok(())
}

fn migrate_v2_to_v3(connection: &Connection) -> Result<(), CatalogError> {
    let result = connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE advisory_deltas (
             delta_id TEXT PRIMARY KEY,
             manifest_sha256 TEXT NOT NULL UNIQUE,
             index_sha256 TEXT NOT NULL,
             index_revision TEXT NOT NULL,
             expected_ecosystem TEXT NOT NULL,
             acquired_at TEXT NOT NULL,
             after_modified TEXT NOT NULL,
             through_modified TEXT NOT NULL,
             base_snapshot_id TEXT NOT NULL REFERENCES advisory_snapshots(snapshot_id),
             previous_delta_id TEXT REFERENCES advisory_deltas(delta_id),
             accepted_records INTEGER NOT NULL CHECK(accepted_records >= 0),
             quarantined_records INTEGER NOT NULL CHECK(quarantined_records >= 0),
             withdrawn_records INTEGER NOT NULL CHECK(withdrawn_records >= 0),
             status TEXT NOT NULL CHECK(status IN ('preparing', 'complete')),
             imported_at TEXT NOT NULL,
             completed_at TEXT
         ) STRICT;
         CREATE TABLE delta_records (
             delta_id TEXT NOT NULL REFERENCES advisory_deltas(delta_id),
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             source_record_id TEXT NOT NULL,
             raw_sha256 TEXT NOT NULL,
             withdrawn INTEGER NOT NULL CHECK(withdrawn IN (0, 1)),
             PRIMARY KEY(delta_id, source_id, source_record_id)
         ) STRICT;
         CREATE TABLE source_delta_imports (
             delta_id TEXT NOT NULL REFERENCES advisory_deltas(delta_id),
             source_id INTEGER NOT NULL REFERENCES sources(source_id),
             record_count INTEGER NOT NULL CHECK(record_count >= 0),
             withdrawn_records INTEGER NOT NULL DEFAULT 0 CHECK(withdrawn_records >= 0),
             completed_at TEXT,
             PRIMARY KEY(delta_id, source_id)
         ) STRICT;
         CREATE INDEX advisory_deltas_ecosystem_idx
             ON advisory_deltas(expected_ecosystem, acquired_at, status);
         CREATE INDEX source_delta_imports_source_idx
             ON source_delta_imports(source_id, completed_at);
         PRAGMA user_version = 3;
         COMMIT;",
    );
    if let Err(error) = result {
        let _ = connection.execute_batch("ROLLBACK;");
        return Err(error.into());
    }
    Ok(())
}

fn migrate_catalog(connection: &Connection, observed: i64) -> Result<(), CatalogError> {
    match observed {
        1 => {
            migrate_v1_to_v2(connection)?;
            migrate_v2_to_v3(connection)
        }
        2 => migrate_v2_to_v3(connection),
        version if version == i64::from(CATALOG_SCHEMA_VERSION) => Ok(()),
        version => Err(CatalogError::SchemaMismatch {
            expected: CATALOG_SCHEMA_VERSION,
            observed: version,
        }),
    }
}

fn verify_application_id(connection: &Connection) -> Result<(), CatalogError> {
    let application_id = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application_id != i64::from(CATALOG_APPLICATION_ID) {
        return Err(CatalogError::ApplicationIdMismatch(application_id));
    }
    Ok(())
}

fn schema_version(connection: &Connection) -> Result<i64, CatalogError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(Into::into)
}

fn verify_schema(connection: &Connection) -> Result<(), CatalogError> {
    verify_application_id(connection)?;
    let version = schema_version(connection)?;
    if version != i64::from(CATALOG_SCHEMA_VERSION) {
        return Err(CatalogError::SchemaMismatch {
            expected: CATALOG_SCHEMA_VERSION,
            observed: version,
        });
    }
    Ok(())
}

fn verify_read_schema(connection: &Connection) -> Result<(), CatalogError> {
    verify_application_id(connection)?;
    let version = schema_version(connection)?;
    if !(2..=i64::from(CATALOG_SCHEMA_VERSION)).contains(&version) {
        return Err(CatalogError::SchemaMismatch {
            expected: CATALOG_SCHEMA_VERSION,
            observed: version,
        });
    }
    Ok(())
}

fn register_source(
    transaction: &Transaction<'_>,
    source: &CatalogSource,
    imported_at: &str,
) -> Result<i64, CatalogError> {
    let existing = query_row_optional_cached(
        transaction,
        "SELECT source_id, license_expression, license_evidence_sha256, locator
             FROM sources WHERE name = ?1",
        [&source.name],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    if let Some((source_id, license, evidence, locator)) = existing {
        if license != source.license_expression
            || evidence != source.license_evidence_sha256
            || locator != source.locator
        {
            return Err(CatalogError::SourceConflict(source.name.clone()));
        }
        execute_cached(
            transaction,
            "UPDATE sources SET last_imported_at = ?1 WHERE source_id = ?2",
            params![imported_at, source_id],
        )?;
        return Ok(source_id);
    }
    execute_cached(
        transaction,
        "INSERT INTO sources(
             name, license_expression, license_evidence_sha256, locator,
             first_imported_at, last_imported_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![
            source.name,
            source.license_expression,
            source.license_evidence_sha256,
            source.locator,
            imported_at
        ],
    )?;
    Ok(transaction.last_insert_rowid())
}

fn registered_source_id(
    connection: &Connection,
    source: &CatalogSource,
) -> Result<i64, CatalogError> {
    let existing = query_row_optional_cached(
        connection,
        "SELECT source_id, license_expression, license_evidence_sha256, locator
         FROM sources WHERE name = ?1",
        [&source.name],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?
    .ok_or_else(|| CatalogError::DeltaIncomplete(source.name.clone()))?;
    if existing.1 != source.license_expression
        || existing.2 != source.license_evidence_sha256
        || existing.3 != source.locator
    {
        return Err(CatalogError::SourceConflict(source.name.clone()));
    }
    Ok(existing.0)
}

#[allow(clippy::too_many_arguments)]
fn import_osv_record_tx(
    transaction: &Transaction<'_>,
    source: &CatalogSource,
    source_id: i64,
    record: &OsvRecord,
    raw: &[u8],
    imported_at: &str,
    update_search_index: bool,
    result: &mut CatalogImportResult,
) -> Result<(), CatalogError> {
    let raw_sha256 = sha256(raw);
    let existing = query_row_optional_cached(
        transaction,
        "SELECT record_rowid, raw_sha256, canonical_id, active
             FROM source_records WHERE source_id = ?1 AND source_record_id = ?2",
        params![source_id, record.id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    if existing
        .as_ref()
        .is_some_and(|(_, existing_hash, _, _)| existing_hash == &raw_sha256)
    {
        execute_cached(
            transaction,
            "UPDATE source_records SET active = 1
             WHERE source_id = ?1 AND source_record_id = ?2",
            params![source_id, record.id],
        )?;
        if update_search_index
            && existing
                .as_ref()
                .is_some_and(|(_, _, _, active)| *active == 0)
        {
            execute_cached(
                transaction,
                "INSERT INTO source_record_fts(rowid, title, details)
                 SELECT record_rowid, title, details FROM source_records
                 WHERE source_id = ?1 AND source_record_id = ?2",
                params![source_id, record.id],
            )?;
        }
        result.records_unchanged += 1;
        return Ok(());
    }
    let is_new_record = existing.is_none();

    let mut exact_identifiers = BTreeSet::new();
    exact_identifiers.insert(record.id.clone());
    exact_identifiers.extend(record.aliases.iter().cloned());
    let candidate_id = canonical_id(&source.name, &record.id);
    execute_cached(
        transaction,
        "INSERT OR IGNORE INTO canonical_vulnerabilities(canonical_id, created_at, updated_at)
         VALUES (?1, ?2, ?2)",
        params![candidate_id, imported_at],
    )?;
    let mut canonical_ids = BTreeSet::from([candidate_id.clone()]);
    if let Some((_, _, existing_canonical, _)) = &existing {
        canonical_ids.insert(existing_canonical.clone());
    }
    for identifier in &exact_identifiers {
        if let Some(value) = query_row_optional_cached(
            transaction,
            "SELECT canonical_id FROM identifiers WHERE identifier = ?1",
            [identifier],
            |row| row.get::<_, String>(0),
        )? {
            canonical_ids.insert(value);
        }
    }
    let selected = canonical_ids
        .iter()
        .next()
        .cloned()
        .ok_or(CatalogError::InvalidRecord("canonical_id"))?;
    for merged in canonical_ids.iter().filter(|value| *value != &selected) {
        merge_canonical(transaction, merged, &selected)?;
        result.canonical_groups_merged += 1;
    }
    for identifier in &exact_identifiers {
        execute_cached(
            transaction,
            "INSERT INTO identifiers(identifier, canonical_id) VALUES (?1, ?2)
             ON CONFLICT(identifier) DO UPDATE SET canonical_id = excluded.canonical_id",
            params![identifier, selected],
        )?;
    }

    execute_cached(
        transaction,
        "INSERT OR IGNORE INTO source_record_revisions(
             source_id, source_record_id, modified_at, raw_sha256, raw_json, imported_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            source_id,
            record.id,
            record.modified,
            raw_sha256,
            raw,
            imported_at
        ],
    )?;
    let revision_id = query_row_cached(
        transaction,
        "SELECT revision_id FROM source_record_revisions
         WHERE source_id = ?1 AND source_record_id = ?2 AND raw_sha256 = ?3",
        params![source_id, record.id, raw_sha256],
        |row| row.get::<_, i64>(0),
    )?;
    let title = normalize_catalog_text(
        record
            .summary
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&record.id),
    );
    let details = normalize_catalog_text(record.details.as_deref().unwrap_or(""));
    let record_rowid = if let Some((record_rowid, _, _, _)) = existing {
        execute_cached(
            transaction,
            "UPDATE source_records SET
                 canonical_id = ?1, modified_at = ?2, published_at = ?3,
                 withdrawn_at = ?4, title = ?5, details = ?6, raw_sha256 = ?7,
                 current_revision_id = ?8, active = 1
             WHERE record_rowid = ?9",
            params![
                selected,
                record.modified,
                record.published,
                record.withdrawn,
                &title,
                &details,
                raw_sha256,
                revision_id,
                record_rowid
            ],
        )?;
        execute_cached(
            transaction,
            "DELETE FROM identifier_relationships WHERE source_record_rowid = ?1",
            [record_rowid],
        )?;
        execute_cached(
            transaction,
            "DELETE FROM affected_packages WHERE source_record_rowid = ?1",
            [record_rowid],
        )?;
        execute_cached(
            transaction,
            "DELETE FROM advisory_references WHERE source_record_rowid = ?1",
            [record_rowid],
        )?;
        if update_search_index {
            execute_cached(
                transaction,
                "DELETE FROM source_record_fts WHERE rowid = ?1",
                [record_rowid],
            )?;
        }
        result.records_updated += 1;
        record_rowid
    } else {
        execute_cached(
            transaction,
            "INSERT INTO source_records(
                 source_id, source_record_id, canonical_id, modified_at,
                 published_at, withdrawn_at, title, details, raw_sha256,
                 current_revision_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                source_id,
                record.id,
                selected,
                record.modified,
                record.published,
                record.withdrawn,
                &title,
                &details,
                raw_sha256,
                revision_id
            ],
        )?;
        result.records_inserted += 1;
        transaction.last_insert_rowid()
    };
    if update_search_index {
        execute_cached(
            transaction,
            "INSERT INTO source_record_fts(rowid, title, details) VALUES (?1, ?2, ?3)",
            params![record_rowid, title, details],
        )?;
    }

    insert_relationship(transaction, record_rowid, "primary", &record.id)?;
    for alias in &record.aliases {
        insert_relationship(transaction, record_rowid, "alias", alias)?;
    }
    for upstream in &record.upstream {
        insert_relationship(transaction, record_rowid, "upstream", upstream)?;
    }
    for related in &record.related {
        insert_relationship(transaction, record_rowid, "related", related)?;
    }
    for affected in &record.affected {
        let Some(package) = &affected.package else {
            continue;
        };
        let ranges_json = serde_json::to_string(&affected.ranges)?;
        let versions_json = serde_json::to_string(&affected.versions)?;
        execute_cached(
            transaction,
            "INSERT INTO affected_packages(
                 source_record_rowid, ecosystem, package_name, purl,
                 ranges_json, versions_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record_rowid,
                package.ecosystem,
                package.name,
                package.purl,
                ranges_json,
                versions_json
            ],
        )?;
    }
    for reference in &record.references {
        execute_cached(
            transaction,
            "INSERT OR IGNORE INTO advisory_references(
                 source_record_rowid, kind, url
             ) VALUES (?1, ?2, ?3)",
            params![record_rowid, reference.kind, reference.url],
        )?;
    }
    execute_cached(
        transaction,
        "UPDATE canonical_vulnerabilities SET updated_at = ?1 WHERE canonical_id = ?2",
        params![imported_at, selected],
    )?;
    if is_new_record && canonical_ids.len() > 1 {
        result.duplicate_records_linked += 1;
    }
    Ok(())
}

fn merge_canonical(
    transaction: &Transaction<'_>,
    from: &str,
    into: &str,
) -> Result<(), CatalogError> {
    execute_cached(
        transaction,
        "UPDATE source_records SET canonical_id = ?1 WHERE canonical_id = ?2",
        params![into, from],
    )?;
    execute_cached(
        transaction,
        "UPDATE identifiers SET canonical_id = ?1 WHERE canonical_id = ?2",
        params![into, from],
    )?;
    execute_cached(
        transaction,
        "UPDATE canonical_redirects SET canonical_id = ?1 WHERE canonical_id = ?2",
        params![into, from],
    )?;
    execute_cached(
        transaction,
        "INSERT INTO canonical_redirects(old_canonical_id, canonical_id) VALUES (?1, ?2)
         ON CONFLICT(old_canonical_id) DO UPDATE SET canonical_id = excluded.canonical_id",
        params![from, into],
    )?;
    execute_cached(
        transaction,
        "DELETE FROM canonical_vulnerabilities WHERE canonical_id = ?1",
        [from],
    )?;
    Ok(())
}

fn insert_relationship(
    transaction: &Transaction<'_>,
    record_rowid: i64,
    kind: &str,
    identifier: &str,
) -> Result<(), CatalogError> {
    execute_cached(
        transaction,
        "INSERT INTO identifier_relationships(source_record_rowid, kind, identifier)
         VALUES (?1, ?2, ?3)",
        params![record_rowid, kind, identifier],
    )?;
    Ok(())
}

fn ensure_snapshot_order(
    connection: &Connection,
    source_id: i64,
    source_name: &str,
    snapshot_id: &str,
) -> Result<String, CatalogError> {
    let attempted = query_row_optional_cached(
        connection,
        "SELECT acquired_at, artifact_sha256, artifact_revision
         FROM advisory_snapshots WHERE snapshot_id = ?1",
        [snapshot_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?
    .ok_or_else(|| CatalogError::SnapshotNotRegistered(snapshot_id.to_owned()))?;
    let latest = query_row_optional_cached(
        connection,
        "SELECT sn.acquired_at, sn.artifact_sha256, sn.artifact_revision
         FROM source_snapshot_imports si
         JOIN advisory_snapshots sn ON sn.snapshot_id = si.snapshot_id
         WHERE si.source_id = ?1 AND si.completed_at IS NOT NULL
           AND si.snapshot_id <> ?2
         ORDER BY sn.acquired_at DESC LIMIT 1",
        params![source_id, snapshot_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?;
    if let Some(latest) = latest {
        let attempted_time = OffsetDateTime::parse(&attempted.0, &Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("snapshot.acquired_at"))?;
        let latest_time = OffsetDateTime::parse(&latest.0, &Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("snapshot.latest_acquired_at"))?;
        if attempted_time < latest_time
            || (attempted_time == latest_time
                && (attempted.1 != latest.1 || attempted.2 != latest.2))
        {
            return Err(CatalogError::SnapshotRollback {
                source_name: source_name.to_owned(),
                latest: latest.0,
                attempted: attempted.0,
            });
        }
    }
    let latest_delta = query_row_optional_cached(
        connection,
        "SELECT d.delta_id, d.acquired_at
         FROM source_delta_imports di
         JOIN advisory_deltas d ON d.delta_id = di.delta_id
         WHERE di.source_id = ?1 AND di.completed_at IS NOT NULL
           AND d.status = 'complete'
         ORDER BY d.acquired_at DESC, d.delta_id DESC LIMIT 1",
        [source_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    if let Some((delta_id, delta_acquired_at)) = latest_delta {
        let attempted_time = OffsetDateTime::parse(&attempted.0, &Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("snapshot.acquired_at"))?;
        let latest_time = OffsetDateTime::parse(&delta_acquired_at, &Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("delta.acquired_at"))?;
        if attempted_time <= latest_time {
            return Err(CatalogError::SnapshotRollback {
                source_name: source_name.to_owned(),
                latest: format!("{delta_acquired_at} ({delta_id})"),
                attempted: attempted.0,
            });
        }
    }
    Ok(attempted.0)
}

fn ensure_delta_order(connection: &Connection, delta_id: &str) -> Result<(), CatalogError> {
    let attempted = query_row_optional_cached(
        connection,
        "SELECT expected_ecosystem, acquired_at, after_modified,
                through_modified, base_snapshot_id, previous_delta_id, status
         FROM advisory_deltas WHERE delta_id = ?1",
        [delta_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
            ))
        },
    )?
    .ok_or_else(|| CatalogError::DeltaNotRegistered(delta_id.to_owned()))?;
    if attempted.6 == "complete" {
        return Ok(());
    }

    let base = query_row_optional_cached(
        connection,
        "SELECT acquired_at, artifact_sha256, artifact_revision
         FROM advisory_snapshots
         WHERE snapshot_id = ?1 AND expected_ecosystem = ?2 AND status = 'complete'",
        params![attempted.4, attempted.0],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?
    .ok_or_else(|| CatalogError::DeltaIncomplete("base snapshot is not complete".into()))?;
    let latest_snapshot = query_row_cached(
        connection,
        "SELECT snapshot_id, acquired_at, artifact_sha256, artifact_revision
         FROM advisory_snapshots
         WHERE expected_ecosystem = ?1 AND status = 'complete'
         ORDER BY acquired_at DESC, completed_at DESC, snapshot_id DESC LIMIT 1",
        [&attempted.0],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    if latest_snapshot.1 != base.0 || latest_snapshot.2 != base.1 || latest_snapshot.3 != base.2 {
        return Err(CatalogError::DeltaRollback {
            ecosystem: attempted.0,
            latest: latest_snapshot.0,
            attempted: delta_id.to_owned(),
        });
    }

    if let Some(other) = query_row_optional_cached(
        connection,
        "SELECT delta_id FROM advisory_deltas
         WHERE expected_ecosystem = ?1 AND status = 'preparing' AND delta_id <> ?2
         ORDER BY imported_at DESC LIMIT 1",
        params![attempted.0, delta_id],
        |row| row.get::<_, String>(0),
    )? {
        return Err(CatalogError::DeltaRollback {
            ecosystem: attempted.0,
            latest: other,
            attempted: delta_id.to_owned(),
        });
    }

    let latest_delta = query_row_optional_cached(
        connection,
        "SELECT delta_id, acquired_at, through_modified, base_snapshot_id
         FROM advisory_deltas
         WHERE expected_ecosystem = ?1 AND status = 'complete' AND delta_id <> ?2
         ORDER BY acquired_at DESC, completed_at DESC, delta_id DESC LIMIT 1",
        params![attempted.0, delta_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    let acquired = OffsetDateTime::parse(&attempted.1, &Rfc3339)
        .map_err(|_| CatalogError::InvalidRecord("delta.acquired_at"))?;
    if let Some(latest) = latest_delta {
        let latest_acquired = OffsetDateTime::parse(&latest.1, &Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("delta.latest_acquired_at"))?;
        if latest.3 == attempted.4 {
            if attempted.5.as_deref() != Some(latest.0.as_str())
                || attempted.2 != latest.2
                || acquired <= latest_acquired
            {
                return Err(CatalogError::DeltaRollback {
                    ecosystem: attempted.0,
                    latest: latest.0,
                    attempted: delta_id.to_owned(),
                });
            }
        } else {
            let base_acquired = OffsetDateTime::parse(&base.0, &Rfc3339)
                .map_err(|_| CatalogError::InvalidRecord("snapshot.acquired_at"))?;
            if attempted.5.is_some() || base_acquired <= latest_acquired {
                return Err(CatalogError::DeltaRollback {
                    ecosystem: attempted.0,
                    latest: latest.0,
                    attempted: delta_id.to_owned(),
                });
            }
        }
    } else {
        let base_acquired = OffsetDateTime::parse(&base.0, &Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("snapshot.acquired_at"))?;
        let after = OffsetDateTime::parse(&attempted.2, &Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("delta.after_modified"))?;
        if attempted.5.is_some() || after > base_acquired || acquired < base_acquired {
            return Err(CatalogError::DeltaRollback {
                ecosystem: attempted.0,
                latest: attempted.4,
                attempted: delta_id.to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_delta_record_order(
    connection: &Connection,
    source: &CatalogSource,
    source_id: i64,
    record: &OsvRecord,
    raw: &[u8],
    after_modified: &str,
    through_modified: &str,
) -> Result<(), CatalogError> {
    let modified = OffsetDateTime::parse(&record.modified, &Rfc3339)
        .map_err(|_| CatalogError::InvalidRecord("modified"))?;
    let after = OffsetDateTime::parse(after_modified, &Rfc3339)
        .map_err(|_| CatalogError::InvalidRecord("delta.after_modified"))?;
    let through = OffsetDateTime::parse(through_modified, &Rfc3339)
        .map_err(|_| CatalogError::InvalidRecord("delta.through_modified"))?;
    if modified <= after || modified > through {
        return Err(CatalogError::InvalidRecord("delta.record.modified"));
    }
    if let Some((current_modified, current_hash)) = query_row_optional_cached(
        connection,
        "SELECT modified_at, raw_sha256 FROM source_records
         WHERE source_id = ?1 AND source_record_id = ?2",
        params![source_id, record.id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )? {
        let current = OffsetDateTime::parse(&current_modified, &Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("source_record.modified_at"))?;
        let attempted_hash = sha256(raw);
        if modified < current || (modified == current && attempted_hash != current_hash) {
            return Err(CatalogError::DeltaRecordRollback {
                source_name: source.name.clone(),
                record_id: record.id.clone(),
                current: current_modified,
                attempted: record.modified.clone(),
            });
        }
    }
    Ok(())
}

fn verify_completed_delta_record(
    connection: &Connection,
    source_id: i64,
    delta_id: &str,
    record: &OsvRecord,
    raw: &[u8],
) -> Result<(), CatalogError> {
    let expected = query_row_optional_cached(
        connection,
        "SELECT raw_sha256, withdrawn FROM delta_records
         WHERE delta_id = ?1 AND source_id = ?2 AND source_record_id = ?3",
        params![delta_id, source_id, record.id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )?
    .ok_or_else(|| CatalogError::DeltaIncomplete(record.id.clone()))?;
    let observed = (sha256(raw), i64::from(record.withdrawn.is_some()));
    if observed != expected {
        return Err(CatalogError::DeltaConflict(delta_id.to_owned()));
    }
    Ok(())
}

fn validate_source(source: &CatalogSource) -> Result<(), CatalogError> {
    validate_text(&source.name, 100, "source.name")?;
    validate_text(&source.license_expression, 200, "source.license_expression")?;
    if !super::valid_sha256(&source.license_evidence_sha256) {
        return Err(CatalogError::InvalidRecord(
            "source.license_evidence_sha256",
        ));
    }
    validate_text(&source.locator, 4_096, "source.locator")
}

fn validate_snapshot_descriptor(snapshot: &CatalogSnapshot) -> Result<(), CatalogError> {
    validate_text(&snapshot.snapshot_id, 100, "snapshot.snapshot_id")?;
    if !snapshot.snapshot_id.starts_with("sf_snapshot_") {
        return Err(CatalogError::InvalidRecord("snapshot.snapshot_id"));
    }
    if !super::valid_sha256(&snapshot.manifest_sha256)
        || !super::valid_sha256(&snapshot.artifact_sha256)
    {
        return Err(CatalogError::InvalidRecord("snapshot.sha256"));
    }
    validate_text(
        &snapshot.artifact_revision,
        500,
        "snapshot.artifact_revision",
    )?;
    validate_text(
        &snapshot.expected_ecosystem,
        100,
        "snapshot.expected_ecosystem",
    )?;
    validate_timestamp(&snapshot.acquired_at, "snapshot.acquired_at")?;
    if snapshot.accepted_records == 0
        || snapshot.accepted_records > MAX_IMPORT_RECORDS as u64
        || snapshot
            .accepted_records
            .saturating_add(snapshot.quarantined_records)
            > MAX_IMPORT_RECORDS as u64
    {
        return Err(CatalogError::InvalidRecord("snapshot.record_counts"));
    }
    Ok(())
}

fn validate_delta_descriptor(delta: &CatalogDelta) -> Result<(), CatalogError> {
    if !valid_prefixed_sha256(&delta.delta_id, "sf_delta_")
        || !super::valid_sha256(&delta.manifest_sha256)
        || !super::valid_sha256(&delta.index_sha256)
        || !valid_prefixed_sha256(&delta.base_snapshot_id, "sf_snapshot_")
        || delta
            .previous_delta_id
            .as_ref()
            .is_some_and(|value| !valid_prefixed_sha256(value, "sf_delta_"))
    {
        return Err(CatalogError::InvalidRecord("delta.identity"));
    }
    validate_text(&delta.index_revision, 500, "delta.index_revision")?;
    validate_text(&delta.expected_ecosystem, 100, "delta.expected_ecosystem")?;
    validate_timestamp(&delta.acquired_at, "delta.acquired_at")?;
    validate_timestamp(&delta.after_modified, "delta.after_modified")?;
    validate_timestamp(&delta.through_modified, "delta.through_modified")?;
    let acquired = OffsetDateTime::parse(&delta.acquired_at, &Rfc3339)
        .map_err(|_| CatalogError::InvalidRecord("delta.acquired_at"))?;
    let after = OffsetDateTime::parse(&delta.after_modified, &Rfc3339)
        .map_err(|_| CatalogError::InvalidRecord("delta.after_modified"))?;
    let through = OffsetDateTime::parse(&delta.through_modified, &Rfc3339)
        .map_err(|_| CatalogError::InvalidRecord("delta.through_modified"))?;
    if delta.accepted_records == 0
        || delta.accepted_records > MAX_IMPORT_RECORDS as u64
        || delta
            .accepted_records
            .saturating_add(delta.quarantined_records)
            > MAX_IMPORT_RECORDS as u64
        || delta.withdrawn_records > delta.accepted_records
        || after >= through
        || through > acquired
    {
        return Err(CatalogError::InvalidRecord("delta.accounting"));
    }
    Ok(())
}

fn valid_prefixed_sha256(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(super::valid_sha256)
}

pub fn validate_osv_record_public(record: &OsvRecord) -> Result<(), CatalogError> {
    validate_identifier(&record.id, "id")?;
    validate_timestamp(&record.modified, "modified")?;
    validate_optional_timestamp(record.published.as_deref(), "published")?;
    validate_optional_timestamp(record.withdrawn.as_deref(), "withdrawn")?;
    if let Some(version) = &record.schema_version {
        validate_text(version, 50, "schema_version")?;
    }
    validate_optional_content_text(record.summary.as_deref(), 1_000, "summary")?;
    validate_optional_content_text(record.details.as_deref(), 262_144, "details")?;
    if record.aliases.len() + record.upstream.len() + record.related.len()
        > MAX_IDENTIFIERS_PER_RECORD
    {
        return Err(CatalogError::InvalidRecord("identifiers"));
    }
    for identifier in record
        .aliases
        .iter()
        .chain(&record.upstream)
        .chain(&record.related)
    {
        validate_identifier(identifier, "identifier")?;
    }
    if record.affected.len() > MAX_AFFECTED_PER_RECORD {
        return Err(CatalogError::InvalidRecord("affected"));
    }
    for affected in &record.affected {
        if affected.versions.len() > MAX_VERSIONS_PER_AFFECTED {
            return Err(CatalogError::InvalidRecord("affected.versions"));
        }
        for version in &affected.versions {
            validate_text(version, 500, "affected.versions[]")?;
        }
        if let Some(package) = &affected.package {
            validate_text(&package.ecosystem, 100, "affected.package.ecosystem")?;
            validate_text(&package.name, 500, "affected.package.name")?;
            validate_optional_text(package.purl.as_deref(), 2_048, "affected.package.purl")?;
        }
    }
    if record.references.len() > MAX_REFERENCES_PER_RECORD {
        return Err(CatalogError::InvalidRecord("references"));
    }
    for reference in &record.references {
        validate_optional_text(reference.kind.as_deref(), 50, "references.type")?;
        validate_text(&reference.url, 4_096, "references.url")?;
    }
    Ok(())
}

fn validate_record_size(bytes: &[u8]) -> Result<(), CatalogError> {
    if bytes.is_empty() {
        return Err(CatalogError::InvalidRecord("empty record"));
    }
    if bytes.len() as u64 > MAX_OSV_RECORD_BYTES {
        return Err(CatalogError::RecordTooLarge {
            bytes: bytes.len() as u64,
            maximum: MAX_OSV_RECORD_BYTES,
        });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), CatalogError> {
    validate_text(value, 200, field)?;
    if !value.is_ascii() || value.bytes().any(|byte| !byte.is_ascii_graphic()) {
        return Err(CatalogError::InvalidRecord(field));
    }
    Ok(())
}

fn validate_text(value: &str, max_chars: usize, field: &'static str) -> Result<(), CatalogError> {
    if value.trim().is_empty()
        || value.chars().count() > max_chars
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(CatalogError::InvalidRecord(field));
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    max_chars: usize,
    field: &'static str,
) -> Result<(), CatalogError> {
    if let Some(value) = value {
        if value.is_empty() {
            return Ok(());
        }
        validate_text(value, max_chars, field)?;
    }
    Ok(())
}

fn validate_optional_content_text(
    value: Option<&str>,
    max_chars: usize,
    field: &'static str,
) -> Result<(), CatalogError> {
    if let Some(value) = value {
        if value.is_empty() {
            return Ok(());
        }
        if value.trim().is_empty() || value.chars().count() > max_chars {
            return Err(CatalogError::InvalidRecord(field));
        }
    }
    Ok(())
}

fn normalize_catalog_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn validate_timestamp(value: &str, field: &'static str) -> Result<(), CatalogError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| CatalogError::InvalidRecord(field))
}

fn validate_optional_timestamp(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), CatalogError> {
    if let Some(value) = value {
        validate_timestamp(value, field)?;
    }
    Ok(())
}

fn validate_query(value: &str, limit: usize) -> Result<(), CatalogError> {
    if value.trim().is_empty() || value.chars().count() > 500 {
        return Err(CatalogError::InvalidQuery(
            "query must contain 1 to 500 characters",
        ));
    }
    if limit == 0 || limit > MAX_QUERY_RESULTS {
        return Err(CatalogError::InvalidQuery(
            "limit must be between 1 and 1000",
        ));
    }
    Ok(())
}

fn canonical_id(source_name: &str, source_record_id: &str) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "secureflow-canonical-v1");
    hash_field(&mut hasher, source_name);
    hash_field(&mut hasher, source_record_id);
    format!("sf_vuln_{}", hex_digest(hasher.finalize().as_slice()))
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_digest(digest.as_slice())
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

fn hit_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CatalogHit> {
    Ok(CatalogHit {
        canonical_id: row.get(0)?,
        source_name: row.get(1)?,
        source_record_id: row.get(2)?,
        title: row.get(3)?,
        modified_at: row.get(4)?,
        withdrawn: row.get(5)?,
        score: None,
    })
}

fn count(connection: &Connection, table: &str) -> Result<u64, CatalogError> {
    let allowed = [
        "sources",
        "canonical_vulnerabilities",
        "source_records",
        "source_record_revisions",
        "identifiers",
        "identifier_relationships",
        "affected_packages",
        "advisory_references",
        "advisory_snapshots",
        "advisory_deltas",
    ];
    if !allowed.contains(&table) {
        return Err(CatalogError::InvalidQuery("unknown statistics table"));
    }
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let value = connection.query_row(&sql, [], |row| row.get::<_, i64>(0))?;
    nonnegative_count(value)
}

fn execute_cached<P: Params>(
    connection: &Connection,
    sql: &str,
    parameters: P,
) -> Result<usize, CatalogError> {
    Ok(connection.prepare_cached(sql)?.execute(parameters)?)
}

fn query_row_cached<T, P, F>(
    connection: &Connection,
    sql: &str,
    parameters: P,
    mapper: F,
) -> Result<T, CatalogError>
where
    P: Params,
    F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    Ok(connection
        .prepare_cached(sql)?
        .query_row(parameters, mapper)?)
}

fn query_row_optional_cached<T, P, F>(
    connection: &Connection,
    sql: &str,
    parameters: P,
    mapper: F,
) -> Result<Option<T>, CatalogError>
where
    P: Params,
    F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    Ok(connection
        .prepare_cached(sql)?
        .query_row(parameters, mapper)
        .optional()?)
}

fn search_index_status(connection: &Connection) -> Result<String, CatalogError> {
    connection
        .query_row(
            "SELECT value FROM catalog_metadata WHERE key = 'search_index_status'",
            [],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn ensure_no_preparing_delta(connection: &Connection) -> Result<(), CatalogError> {
    if schema_version(connection)? < 3 {
        return Ok(());
    }
    let preparing = nonnegative_count(connection.query_row(
        "SELECT COUNT(*) FROM advisory_deltas WHERE status = 'preparing'",
        [],
        |row| row.get::<_, i64>(0),
    )?)?;
    if preparing != 0 {
        return Err(CatalogError::DeltaPreparing(preparing));
    }
    Ok(())
}

fn ensure_search_index_ready(connection: &Connection) -> Result<(), CatalogError> {
    if search_index_status(connection)? != "ready" {
        return Err(CatalogError::InvalidQuery(
            "full-text index is dirty; rebuild it before searching",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
struct OsvVersionRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<OsvVersionEvent>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OsvVersionEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
    #[serde(default)]
    limit: Option<String>,
}

fn evaluate_package_version(
    requested_version: Option<&str>,
    rows: &[(String, String)],
) -> VersionAssessment {
    let mut affected_data_sha256 = rows
        .iter()
        .map(|(ranges, versions)| {
            let mut hasher = Sha256::new();
            hash_field(&mut hasher, "secureflow-affected-data-v1");
            hash_field(&mut hasher, ranges);
            hash_field(&mut hasher, versions);
            hex_digest(hasher.finalize().as_slice())
        })
        .collect::<Vec<_>>();
    affected_data_sha256.sort();
    affected_data_sha256.dedup();

    let Some(requested_version) = requested_version else {
        return VersionAssessment {
            status: VersionEvaluationStatus::NotEvaluated,
            basis: VersionEvaluationBasis::NotRequested,
            evaluated_version: None,
            matched_value: None,
            affected_data_sha256,
            issues: Vec::new(),
        };
    };

    let query_semver = Version::parse(requested_version);
    let mut issues = BTreeSet::new();
    let mut supported_data_observed = false;

    for (ranges_json, versions_json) in rows {
        let versions = match serde_json::from_str::<Vec<String>>(versions_json) {
            Ok(versions) => versions,
            Err(_) => {
                issues.insert(VersionEvaluationIssue::InvalidStoredJson);
                Vec::new()
            }
        };
        if !versions.is_empty() {
            supported_data_observed = true;
        }
        if versions.iter().any(|version| version == requested_version) {
            return VersionAssessment {
                status: VersionEvaluationStatus::Affected,
                basis: VersionEvaluationBasis::ExactEnumeratedVersion,
                evaluated_version: Some(requested_version.to_owned()),
                matched_value: Some(requested_version.to_owned()),
                affected_data_sha256,
                issues: Vec::new(),
            };
        }

        let ranges = match serde_json::from_str::<Vec<serde_json::Value>>(ranges_json) {
            Ok(ranges) => ranges,
            Err(_) => {
                issues.insert(VersionEvaluationIssue::InvalidStoredJson);
                continue;
            }
        };
        if versions.is_empty() && ranges.is_empty() {
            issues.insert(VersionEvaluationIssue::MissingVersionData);
        }
        for range_value in ranges {
            let range = match serde_json::from_value::<OsvVersionRange>(range_value.clone()) {
                Ok(range) => range,
                Err(_) => {
                    issues.insert(VersionEvaluationIssue::InvalidStoredJson);
                    continue;
                }
            };
            if range.kind != "SEMVER" {
                issues.insert(VersionEvaluationIssue::UnsupportedRangeType);
                continue;
            }
            supported_data_observed = true;
            let query = match &query_semver {
                Ok(query) => query,
                Err(_) => {
                    issues.insert(VersionEvaluationIssue::InvalidQuerySemver);
                    continue;
                }
            };
            match evaluate_semver_range(query, &range) {
                Ok(true) => {
                    let bytes = serde_json::to_vec(&range_value)
                        .expect("a parsed JSON value must serialize");
                    return VersionAssessment {
                        status: VersionEvaluationStatus::Affected,
                        basis: VersionEvaluationBasis::OsvSemverRange,
                        evaluated_version: Some(requested_version.to_owned()),
                        matched_value: Some(sha256(&bytes)),
                        affected_data_sha256,
                        issues: Vec::new(),
                    };
                }
                Ok(false) => {}
                Err(issue) => {
                    issues.insert(issue);
                }
            }
        }
    }

    let issues = issues.into_iter().collect::<Vec<_>>();
    if supported_data_observed && issues.is_empty() {
        VersionAssessment {
            status: VersionEvaluationStatus::NotAffected,
            basis: VersionEvaluationBasis::SupportedDataExcludesVersion,
            evaluated_version: Some(requested_version.to_owned()),
            matched_value: None,
            affected_data_sha256,
            issues,
        }
    } else {
        let issues = if issues.is_empty() {
            vec![VersionEvaluationIssue::MissingVersionData]
        } else {
            issues
        };
        VersionAssessment {
            status: VersionEvaluationStatus::Unknown,
            basis: VersionEvaluationBasis::UnsupportedOrInvalidData,
            evaluated_version: Some(requested_version.to_owned()),
            matched_value: None,
            affected_data_sha256,
            issues,
        }
    }
}

fn evaluate_semver_range(
    query: &Version,
    range: &OsvVersionRange,
) -> Result<bool, VersionEvaluationIssue> {
    if range.events.is_empty() {
        return Err(VersionEvaluationIssue::InvalidSemverEvents);
    }
    let mut introduced_observed = false;
    let mut interval_open = false;
    let mut query_affected = false;
    let mut last_boundary = None::<Version>;
    let mut limit_observed = false;
    let mut fixed_observed = false;
    let mut last_affected_observed = false;
    for (index, event) in range.events.iter().enumerate() {
        let field_count = [
            event.introduced.is_some(),
            event.fixed.is_some(),
            event.last_affected.is_some(),
            event.limit.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if field_count != 1 {
            return Err(VersionEvaluationIssue::InvalidSemverEvents);
        }
        if let Some(value) = &event.limit {
            if limit_observed || index + 1 != range.events.len() {
                return Err(VersionEvaluationIssue::InvalidSemverEvents);
            }
            limit_observed = true;
            if value != "*" {
                let limit = Version::parse(value)
                    .map_err(|_| VersionEvaluationIssue::InvalidSemverEvents)?;
                if last_boundary
                    .as_ref()
                    .is_some_and(|last| !last.cmp_precedence(&limit).is_lt())
                {
                    return Err(VersionEvaluationIssue::InvalidSemverEvents);
                }
                if !query.cmp_precedence(&limit).is_lt() {
                    query_affected = false;
                }
            }
            continue;
        }
        let (value, kind) = if let Some(value) = &event.introduced {
            introduced_observed = true;
            (value, 0_u8)
        } else if let Some(value) = &event.fixed {
            fixed_observed = true;
            if last_affected_observed {
                return Err(VersionEvaluationIssue::InvalidSemverEvents);
            }
            (value, 1_u8)
        } else if let Some(value) = &event.last_affected {
            last_affected_observed = true;
            if fixed_observed {
                return Err(VersionEvaluationIssue::InvalidSemverEvents);
            }
            (value, 2_u8)
        } else {
            return Err(VersionEvaluationIssue::InvalidSemverEvents);
        };
        let version = if kind == 0 && value == "0" {
            if index != 0 {
                return Err(VersionEvaluationIssue::InvalidSemverEvents);
            }
            None
        } else {
            Some(Version::parse(value).map_err(|_| VersionEvaluationIssue::InvalidSemverEvents)?)
        };
        if let Some(version) = &version {
            if last_boundary
                .as_ref()
                .is_some_and(|last| !last.cmp_precedence(version).is_lt())
            {
                return Err(VersionEvaluationIssue::InvalidSemverEvents);
            }
            last_boundary = Some(version.clone());
        }
        let comparison = version
            .as_ref()
            .map(|version| query.cmp_precedence(version));
        match kind {
            0 if !interval_open => {
                interval_open = true;
                if comparison.is_none_or(|ordering| !ordering.is_lt()) {
                    query_affected = true;
                }
            }
            1 if interval_open => {
                interval_open = false;
                if comparison.is_some_and(|ordering| !ordering.is_lt()) {
                    query_affected = false;
                }
            }
            2 if interval_open => {
                interval_open = false;
                if comparison.is_some_and(std::cmp::Ordering::is_gt) {
                    query_affected = false;
                }
            }
            _ => return Err(VersionEvaluationIssue::InvalidSemverEvents),
        }
    }
    if !introduced_observed {
        return Err(VersionEvaluationIssue::InvalidSemverEvents);
    }
    Ok(query_affected)
}

fn nonnegative_count(value: i64) -> Result<u64, CatalogError> {
    u64::try_from(value).map_err(|_| CatalogError::InvalidPath("negative SQLite count"))
}

fn prepare_catalog_path(path: &Path, create: bool) -> Result<bool, CatalogError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(CatalogError::InvalidPath("database path must name a file"));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(CatalogError::InvalidPath(
                "database path cannot be a symlink",
            ));
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(CatalogError::InvalidPath(
                "database path is not a regular file",
            ));
        }
        Ok(_) => return Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
            let parent = path.parent().ok_or(CatalogError::InvalidPath(
                "database path must have a parent directory",
            ))?;
            create_private_directories(parent)?;
        }
        Err(error) => {
            return Err(CatalogError::Filesystem {
                path: path.to_owned(),
                source: error,
            });
        }
    }
    Ok(false)
}

fn database_size(path: &Path) -> Result<u64, CatalogError> {
    let mut total = fs::metadata(path)
        .map_err(|source| CatalogError::Filesystem {
            path: path.to_owned(),
            source,
        })?
        .len();
    for suffix in ["-wal", "-shm"] {
        let sidecar = path_with_suffix(path, suffix);
        match fs::metadata(&sidecar) {
            Ok(metadata) => total = total.saturating_add(metadata.len()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CatalogError::Filesystem {
                    path: sidecar,
                    source,
                });
            }
        }
    }
    Ok(total)
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(unix)]
fn create_private_directories(path: &Path) -> Result<(), CatalogError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(path)
        .map_err(|source| CatalogError::Filesystem {
            path: path.to_owned(),
            source,
        })
}

#[cfg(not(unix))]
fn create_private_directories(path: &Path) -> Result<(), CatalogError> {
    fs::create_dir_all(path).map_err(|source| CatalogError::Filesystem {
        path: path.to_owned(),
        source,
    })
}

#[cfg(unix)]
fn secure_file_permissions(path: &Path) -> Result<(), CatalogError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        CatalogError::Filesystem {
            path: path.to_owned(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn secure_file_permissions(_path: &Path) -> Result<(), CatalogError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> CatalogSource {
        CatalogSource {
            name: "fixture-osv".into(),
            license_expression: "CC-BY-4.0".into(),
            license_evidence_sha256: "a".repeat(64),
            locator: "https://example.invalid/osv".into(),
        }
    }

    fn snapshot(fill: char, acquired_at: &str, accepted_records: u64) -> CatalogSnapshot {
        CatalogSnapshot {
            snapshot_id: format!("sf_snapshot_{}", fill.to_string().repeat(64)),
            manifest_sha256: fill.to_string().repeat(64),
            artifact_sha256: fill.to_string().repeat(64),
            artifact_revision: format!("fixture-{fill}"),
            expected_ecosystem: "crates.io".into(),
            acquired_at: acquired_at.into(),
            accepted_records,
            quarantined_records: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn delta(
        fill: char,
        base_snapshot_id: &str,
        previous_delta_id: Option<String>,
        acquired_at: &str,
        after_modified: &str,
        through_modified: &str,
        accepted_records: u64,
        withdrawn_records: u64,
    ) -> CatalogDelta {
        CatalogDelta {
            delta_id: format!("sf_delta_{}", fill.to_string().repeat(64)),
            manifest_sha256: fill.to_string().repeat(64),
            index_sha256: fill.to_string().repeat(64),
            index_revision: format!("etag-{fill}"),
            expected_ecosystem: "crates.io".into(),
            acquired_at: acquired_at.into(),
            after_modified: after_modified.into(),
            through_modified: through_modified.into(),
            base_snapshot_id: base_snapshot_id.into(),
            previous_delta_id,
            accepted_records,
            quarantined_records: 0,
            withdrawn_records,
        }
    }

    fn record_at(id: &str, modified: &str, title: &str, withdrawn: bool) -> Vec<u8> {
        let mut value = serde_json::json!({
            "schema_version": "1.7.0",
            "id": id,
            "modified": modified,
            "summary": title,
            "affected": [{
                "package": {"ecosystem": "crates.io", "name": "fixture"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
            }]
        });
        if withdrawn {
            value["withdrawn"] = serde_json::Value::String(modified.into());
        }
        serde_json::to_vec(&value).expect("fixture JSON")
    }

    fn record(id: &str, aliases: &[&str], title: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": "1.7.0",
            "id": id,
            "modified": "2026-08-23T00:00:00Z",
            "aliases": aliases,
            "summary": title,
            "details": "A bounded local fixture",
            "affected": [{
                "package": {
                    "ecosystem": "crates.io",
                    "name": "fixture",
                    "purl": "pkg:cargo/fixture"
                },
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
            }],
            "references": [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}]
        }))
        .expect("fixture JSON")
    }

    fn temporary_catalog(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "secureflow-catalog-{label}-{}-{}.sqlite3",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))
    }

    fn cleanup(path: &Path) {
        for candidate in [
            path.to_owned(),
            path_with_suffix(path, "-wal"),
            path_with_suffix(path, "-shm"),
        ] {
            let _ = fs::remove_file(candidate);
        }
    }

    #[test]
    fn exact_aliases_merge_source_records_without_using_related_ids() {
        let path = temporary_catalog("aliases");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let first = record("GHSA-aaaa-bbbb-cccc", &["CVE-2026-0001"], "alpha flaw");
        let second = record("CVE-2026-0001", &[], "same alpha flaw");
        let third = serde_json::to_vec(&serde_json::json!({
            "id": "RUSTSEC-2026-0002",
            "modified": "2026-08-23T00:00:00Z",
            "related": ["CVE-2026-0001"],
            "summary": "different beta flaw"
        }))
        .expect("fixture JSON");
        let result = catalog
            .import_osv_batch(&source(), [&first, &second, &third])
            .expect("import");
        assert_eq!(result.records_inserted, 3);
        let stats = catalog.stats().expect("stats");
        assert_eq!(stats.source_records, 3);
        assert_eq!(stats.canonical_vulnerabilities, 2);
        assert_eq!(
            catalog
                .lookup_identifier("CVE-2026-0001", 10)
                .expect("lookup")
                .len(),
            2
        );
        cleanup(&path);
    }

    #[test]
    fn package_version_evaluation_is_conservative_and_reproducible() {
        let path = temporary_catalog("version-evaluation");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let ranged = serde_json::to_vec(&serde_json::json!({
            "id": "GHSA-aaaa-bbbb-cccc",
            "modified": "2026-08-23T00:00:00Z",
            "summary": "semver fixture",
            "affected": [{
                "package": {"ecosystem": "crates.io", "name": "fixture"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "1.0.0"}, {"fixed": "2.0.0"}
                ]}]
            }]
        }))
        .expect("range fixture");
        let enumerated = serde_json::to_vec(&serde_json::json!({
            "id": "GHSA-dddd-eeee-ffff",
            "modified": "2026-08-23T00:00:00Z",
            "summary": "enumerated fixture",
            "affected": [{
                "package": {"ecosystem": "crates.io", "name": "fixture"},
                "versions": ["3.0.0"]
            }]
        }))
        .expect("enumerated fixture");
        let unsupported = serde_json::to_vec(&serde_json::json!({
            "id": "GHSA-gggg-hhhh-jjjj",
            "modified": "2026-08-23T00:00:00Z",
            "summary": "ecosystem fixture",
            "affected": [{
                "package": {"ecosystem": "crates.io", "name": "fixture"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "1"}, {"fixed": "9"}
                ]}],
                "versions": ["7"]
            }]
        }))
        .expect("unsupported fixture");
        catalog
            .import_osv_batch(&source(), [&ranged, &enumerated, &unsupported])
            .expect("import");

        let affected = catalog
            .search_package_version("crates.io", "fixture", Some("1.5.0"), 10)
            .expect("affected query");
        assert_eq!(affected.len(), 3);
        let ranged = affected
            .iter()
            .find(|hit| hit.advisory.source_record_id == "GHSA-aaaa-bbbb-cccc")
            .expect("ranged advisory");
        assert_eq!(
            ranged.version_assessment.status,
            VersionEvaluationStatus::Affected
        );
        assert_eq!(
            ranged.version_assessment.basis,
            VersionEvaluationBasis::OsvSemverRange
        );
        assert_eq!(ranged.version_assessment.affected_data_sha256.len(), 1);

        let excluded = catalog
            .search_package_version("crates.io", "fixture", Some("2.0.0"), 10)
            .expect("excluded query");
        let ranged = excluded
            .iter()
            .find(|hit| hit.advisory.source_record_id == "GHSA-aaaa-bbbb-cccc")
            .expect("ranged advisory");
        assert_eq!(
            ranged.version_assessment.status,
            VersionEvaluationStatus::NotAffected
        );

        let exact = catalog
            .search_package_version("crates.io", "fixture", Some("7"), 10)
            .expect("exact query");
        let unsupported = exact
            .iter()
            .find(|hit| hit.advisory.source_record_id == "GHSA-gggg-hhhh-jjjj")
            .expect("ecosystem advisory");
        assert_eq!(
            unsupported.version_assessment.status,
            VersionEvaluationStatus::Affected
        );
        assert_eq!(
            unsupported.version_assessment.basis,
            VersionEvaluationBasis::ExactEnumeratedVersion
        );

        let unknown = catalog
            .search_package_version("crates.io", "fixture", Some("8"), 10)
            .expect("unknown query");
        let unsupported = unknown
            .iter()
            .find(|hit| hit.advisory.source_record_id == "GHSA-gggg-hhhh-jjjj")
            .expect("ecosystem advisory");
        assert_eq!(
            unsupported.version_assessment.status,
            VersionEvaluationStatus::Unknown
        );
        assert_eq!(
            unsupported.version_assessment.issues,
            [VersionEvaluationIssue::UnsupportedRangeType]
        );
        cleanup(&path);
    }

    #[test]
    fn semver_evaluator_preserves_osv_boundaries_and_rejects_reordered_events() {
        let fixed_range: OsvVersionRange = serde_json::from_value(serde_json::json!({
            "type": "SEMVER",
            "events": [
                {"introduced": "0"},
                {"fixed": "1.0.0"}
            ]
        }))
        .expect("fixed range");
        let last_affected_range: OsvVersionRange = serde_json::from_value(serde_json::json!({
            "type": "SEMVER",
            "events": [
                {"introduced": "2.0.0-alpha.1"},
                {"last_affected": "2.0.0"},
                {"limit": "3.0.0"}
            ]
        }))
        .expect("last-affected range");
        assert!(evaluate_semver_range(&Version::parse("0.9.9").unwrap(), &fixed_range).unwrap());
        assert!(!evaluate_semver_range(&Version::parse("1.0.0").unwrap(), &fixed_range).unwrap());
        assert!(
            evaluate_semver_range(
                &Version::parse("2.0.0-alpha.1+build.7").unwrap(),
                &last_affected_range
            )
            .unwrap()
        );
        assert!(
            evaluate_semver_range(&Version::parse("2.0.0").unwrap(), &last_affected_range).unwrap()
        );
        assert!(
            !evaluate_semver_range(&Version::parse("2.0.1").unwrap(), &last_affected_range)
                .unwrap()
        );
        assert!(
            !evaluate_semver_range(&Version::parse("3.0.0").unwrap(), &last_affected_range)
                .unwrap()
        );

        let mixed_boundaries: OsvVersionRange = serde_json::from_value(serde_json::json!({
            "type": "SEMVER",
            "events": [
                {"introduced": "1.0.0"},
                {"fixed": "2.0.0"},
                {"introduced": "3.0.0"},
                {"last_affected": "4.0.0"}
            ]
        }))
        .expect("mixed range");
        assert_eq!(
            evaluate_semver_range(&Version::parse("3.5.0").unwrap(), &mixed_boundaries),
            Err(VersionEvaluationIssue::InvalidSemverEvents)
        );

        let reordered: OsvVersionRange = serde_json::from_value(serde_json::json!({
            "type": "SEMVER",
            "events": [{"fixed": "2.0.0"}, {"introduced": "1.0.0"}]
        }))
        .expect("reordered range");
        assert_eq!(
            evaluate_semver_range(&Version::parse("1.5.0").unwrap(), &reordered),
            Err(VersionEvaluationIssue::InvalidSemverEvents)
        );
    }

    #[test]
    fn canonical_rebuild_splits_components_after_an_alias_is_removed() {
        let path = temporary_catalog("canonical-split");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let linked = record("GHSA-aaaa-bbbb-cccc", &["CVE-2026-0001"], "linked");
        let cve = record("CVE-2026-0001", &[], "cve");
        catalog
            .import_osv_batch(&source(), [&linked, &cve])
            .expect("linked import");
        assert_eq!(
            catalog
                .stats()
                .expect("stats")
                .active_canonical_vulnerabilities,
            1
        );

        let corrected = record("GHSA-aaaa-bbbb-cccc", &[], "corrected");
        catalog
            .import_osv_record(&source(), &corrected)
            .expect("alias removal");
        assert_eq!(
            catalog
                .stats()
                .expect("stats")
                .active_canonical_vulnerabilities,
            1
        );
        let rebuild = catalog
            .rebuild_canonicalization()
            .expect("canonical rebuild");
        assert_eq!(rebuild.old_components, 1);
        assert_eq!(rebuild.new_components, 2);
        assert_eq!(rebuild.split_components, 1);
        assert_eq!(
            catalog
                .stats()
                .expect("stats")
                .active_canonical_vulnerabilities,
            2
        );
        let ghsa = catalog
            .lookup_identifier("GHSA-aaaa-bbbb-cccc", 10)
            .expect("GHSA lookup");
        let cve = catalog
            .lookup_identifier("CVE-2026-0001", 10)
            .expect("CVE lookup");
        assert_eq!(ghsa.len(), 1);
        assert_eq!(cve.len(), 1);
        assert_ne!(ghsa[0].canonical_id, cve[0].canonical_id);
        cleanup(&path);
    }

    #[test]
    fn revisions_are_retained_and_identical_content_is_idempotent() {
        let path = temporary_catalog("revisions");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let first = record("GHSA-aaaa-bbbb-cccc", &[], "first title");
        let second = record("GHSA-aaaa-bbbb-cccc", &[], "second title");
        catalog
            .import_osv_record(&source(), &first)
            .expect("first import");
        let unchanged = catalog
            .import_osv_record(&source(), &first)
            .expect("idempotent import");
        assert_eq!(unchanged.records_unchanged, 1);
        let updated = catalog
            .import_osv_record(&source(), &second)
            .expect("updated import");
        assert_eq!(updated.records_updated, 1);
        let stats = catalog.stats().expect("stats");
        assert_eq!(stats.source_records, 1);
        assert_eq!(stats.source_record_revisions, 2);
        assert_eq!(
            catalog.search_text("second title", 10).expect("search")[0].title,
            "second title"
        );
        cleanup(&path);
    }

    #[test]
    fn unchanged_reactivation_keeps_the_ready_search_index_complete() {
        let path = temporary_catalog("unchanged-reactivation");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let bytes = record("GHSA-aaaa-bbbb-cccc", &[], "reactivated title");
        catalog
            .import_osv_record(&source(), &bytes)
            .expect("initial import");
        catalog
            .connection
            .execute("UPDATE source_records SET active = 0", [])
            .expect("fixture deactivation");
        catalog.rebuild_search_index().expect("inactive rebuild");
        assert!(
            catalog
                .search_text("reactivated title", 10)
                .unwrap()
                .is_empty()
        );

        let result = catalog
            .import_osv_record(&source(), &bytes)
            .expect("unchanged reactivation");
        assert_eq!(result.records_unchanged, 1);
        assert_eq!(catalog.stats().unwrap().search_index_status, "ready");
        assert_eq!(
            catalog.search_text("reactivated title", 10).unwrap().len(),
            1
        );
        cleanup(&path);
    }

    #[test]
    fn source_metadata_conflicts_fail_closed() {
        let path = temporary_catalog("source-conflict");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let bytes = record("GHSA-aaaa-bbbb-cccc", &[], "title");
        catalog
            .import_osv_record(&source(), &bytes)
            .expect("first import");
        let mut changed = source();
        changed.license_expression = "MIT".into();
        assert!(matches!(
            catalog.import_osv_record(&changed, &bytes),
            Err(CatalogError::SourceConflict(_))
        ));
        cleanup(&path);
    }

    #[test]
    fn full_snapshots_deactivate_missing_records_and_reject_rollbacks() {
        let path = temporary_catalog("snapshot-lifecycle");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let first = record("GHSA-aaaa-bbbb-cccc", &[], "first");
        let second = record("GHSA-dddd-eeee-ffff", &[], "second");
        let initial = snapshot('a', "2026-08-22T00:00:00Z", 2);
        catalog
            .register_snapshot(&initial)
            .expect("register initial");
        catalog
            .import_osv_snapshot_batch_deferred_search(
                &source(),
                &initial.snapshot_id,
                [&first, &second],
            )
            .expect("import initial");
        catalog
            .complete_snapshot_source(&source(), &initial.snapshot_id, 2)
            .expect("complete initial source");
        catalog
            .complete_snapshot(&initial.snapshot_id)
            .expect("complete initial");

        let mut corrected_policy = initial.clone();
        corrected_policy.snapshot_id = format!("sf_snapshot_{}", "d".repeat(64));
        corrected_policy.manifest_sha256 = "d".repeat(64);
        catalog
            .register_snapshot(&corrected_policy)
            .expect("register same-artifact policy correction");
        catalog
            .import_osv_snapshot_batch_deferred_search(
                &source(),
                &corrected_policy.snapshot_id,
                [&first, &second],
            )
            .expect("same acquired artifact can be reprocessed by a new policy");
        catalog
            .complete_snapshot_source(&source(), &corrected_policy.snapshot_id, 2)
            .expect("complete corrected policy source");
        catalog
            .complete_snapshot(&corrected_policy.snapshot_id)
            .expect("complete corrected policy snapshot");

        let next = snapshot('b', "2026-08-23T00:00:00Z", 1);
        catalog.register_snapshot(&next).expect("register next");
        catalog
            .import_osv_snapshot_batch_deferred_search(&source(), &next.snapshot_id, [&first])
            .expect("import next");
        let completion = catalog
            .complete_snapshot_source(&source(), &next.snapshot_id, 1)
            .expect("complete next source");
        assert_eq!(completion.records_deactivated, 1);
        catalog
            .complete_snapshot(&next.snapshot_id)
            .expect("complete next");
        catalog.rebuild_search_index().expect("rebuild FTS");
        let stats = catalog.stats().expect("stats");
        assert_eq!(stats.snapshots, 3);
        assert_eq!(stats.source_records, 2);
        assert_eq!(stats.active_source_records, 1);
        assert_eq!(stats.inactive_source_records, 1);
        assert!(
            catalog
                .lookup_identifier("GHSA-dddd-eeee-ffff", 10)
                .expect("lookup")
                .is_empty()
        );

        let rollback = snapshot('c', "2026-08-21T00:00:00Z", 1);
        catalog
            .register_snapshot(&rollback)
            .expect("register rollback evidence");
        assert!(matches!(
            catalog.import_osv_snapshot_batch_deferred_search(
                &source(),
                &rollback.snapshot_id,
                [&second]
            ),
            Err(CatalogError::SnapshotRollback { .. })
        ));
        assert_eq!(catalog.stats().expect("stats").active_source_records, 1);
        cleanup(&path);
    }

    #[test]
    fn incremental_deltas_replay_recover_and_retain_explicit_withdrawals() {
        let path = temporary_catalog("delta-lifecycle");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let initial_record = record_at(
            "GHSA-aaaa-bbbb-cccc",
            "2026-08-23T00:00:00Z",
            "initial",
            false,
        );
        let base = snapshot('a', "2026-08-23T01:00:00Z", 1);
        catalog.register_snapshot(&base).expect("register base");
        catalog
            .import_osv_snapshot_batch_deferred_search(
                &source(),
                &base.snapshot_id,
                [&initial_record],
            )
            .expect("import base");
        catalog
            .complete_snapshot_source(&source(), &base.snapshot_id, 1)
            .expect("complete base source");
        catalog
            .complete_snapshot(&base.snapshot_id)
            .expect("complete base");
        catalog
            .rebuild_search_index()
            .expect("baseline search index");

        let first = delta(
            'b',
            &base.snapshot_id,
            None,
            "2026-08-23T03:00:00Z",
            "2026-08-23T01:00:00Z",
            "2026-08-23T02:00:00Z",
            1,
            1,
        );
        let withdrawn = record_at(
            "GHSA-aaaa-bbbb-cccc",
            "2026-08-23T02:00:00Z",
            "withdrawn",
            true,
        );
        catalog
            .register_delta(&first)
            .expect("register first delta");
        catalog
            .import_osv_delta_batch(&source(), &first.delta_id, [&withdrawn])
            .expect("import first delta");
        catalog
            .complete_delta_source(&source(), &first.delta_id, 1, 1)
            .expect("complete first source");
        catalog
            .complete_delta(&first.delta_id)
            .expect("complete first delta");
        let revisions_before_replay = catalog.stats().expect("stats").source_record_revisions;
        assert!(
            catalog
                .lookup_identifier("GHSA-aaaa-bbbb-cccc", 10)
                .expect("lookup")[0]
                .withdrawn
        );

        catalog.register_delta(&first).expect("idempotent register");
        let replay = catalog
            .import_osv_delta_batch(&source(), &first.delta_id, [&withdrawn])
            .expect("verified replay");
        assert_eq!(replay.records_seen, 1);
        assert_eq!(replay.records_unchanged, 1);
        assert_eq!(
            catalog.stats().expect("stats").source_record_revisions,
            revisions_before_replay
        );

        let fork = delta(
            'c',
            &base.snapshot_id,
            None,
            "2026-08-23T05:00:00Z",
            "2026-08-23T02:00:00Z",
            "2026-08-23T04:00:00Z",
            1,
            0,
        );
        assert!(matches!(
            catalog.register_delta(&fork),
            Err(CatalogError::DeltaRollback { .. })
        ));

        let second = delta(
            'd',
            &base.snapshot_id,
            Some(first.delta_id.clone()),
            "2026-08-23T05:00:00Z",
            "2026-08-23T02:00:00Z",
            "2026-08-23T04:00:00Z",
            2,
            0,
        );
        let updated = record_at(
            "GHSA-aaaa-bbbb-cccc",
            "2026-08-23T04:00:00Z",
            "restored",
            false,
        );
        let inserted = record_at("GHSA-dddd-eeee-ffff", "2026-08-23T03:00:00Z", "new", false);
        catalog.register_delta(&second).expect("register second");
        catalog
            .import_osv_delta_batch(&source(), &second.delta_id, [&updated])
            .expect("first recovery batch");
        drop(catalog);

        let catalog = Catalog::open_existing(&path).expect("diagnostic reader");
        let interrupted_stats = catalog.stats().expect("interrupted stats");
        assert_eq!(interrupted_stats.deltas, 2);
        assert_eq!(interrupted_stats.complete_deltas, 1);
        assert!(matches!(
            catalog.lookup_identifier("GHSA-aaaa-bbbb-cccc", 10),
            Err(CatalogError::DeltaPreparing(1))
        ));
        assert!(matches!(
            catalog.provenance(),
            Err(CatalogError::DeltaPreparing(1))
        ));
        drop(catalog);

        let mut catalog =
            Catalog::open_existing_writable(&path).expect("reopen after interruption");
        let unrelated_snapshot = snapshot('f', "2026-08-23T06:00:00Z", 1);
        assert!(matches!(
            catalog.register_snapshot(&unrelated_snapshot),
            Err(CatalogError::DeltaPreparing(1))
        ));
        catalog
            .import_osv_delta_batch(&source(), &second.delta_id, [&inserted])
            .expect("second recovery batch");
        catalog
            .complete_delta_source(&source(), &second.delta_id, 2, 0)
            .expect("complete recovered source");
        catalog
            .complete_delta(&second.delta_id)
            .expect("complete recovered delta");
        let stats = catalog.stats().expect("stats");
        assert_eq!(stats.deltas, 2);
        assert_eq!(stats.complete_deltas, 2);
        assert_eq!(stats.active_source_records, 2);
        assert_eq!(stats.search_index_status, "ready");
        assert_eq!(
            catalog.provenance().expect("provenance").complete_delta_ids,
            vec![first.delta_id.clone(), second.delta_id.clone()]
        );

        let older_full = snapshot('e', "2026-08-23T04:30:00Z", 1);
        catalog
            .register_snapshot(&older_full)
            .expect("retain attempted rollback evidence");
        assert!(matches!(
            catalog.import_osv_snapshot_batch_deferred_search(
                &source(),
                &older_full.snapshot_id,
                [&initial_record]
            ),
            Err(CatalogError::SnapshotRollback { .. })
        ));
        cleanup(&path);
    }

    #[test]
    fn delta_with_quarantine_cannot_advance_the_catalog_cursor() {
        let path = temporary_catalog("delta-quarantine");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let base = snapshot('a', "2026-08-23T01:00:00Z", 1);
        let initial = record_at(
            "GHSA-aaaa-bbbb-cccc",
            "2026-08-23T00:00:00Z",
            "initial",
            false,
        );
        catalog.register_snapshot(&base).expect("register base");
        catalog
            .import_osv_snapshot_batch_deferred_search(&source(), &base.snapshot_id, [&initial])
            .expect("import base");
        catalog
            .complete_snapshot_source(&source(), &base.snapshot_id, 1)
            .expect("complete source");
        catalog
            .complete_snapshot(&base.snapshot_id)
            .expect("complete");
        let mut blocked = delta(
            'b',
            &base.snapshot_id,
            None,
            "2026-08-23T03:00:00Z",
            "2026-08-23T01:00:00Z",
            "2026-08-23T02:00:00Z",
            1,
            0,
        );
        blocked.quarantined_records = 1;
        assert!(matches!(
            catalog.register_delta(&blocked),
            Err(CatalogError::DeltaHasQuarantine(1))
        ));
        assert_eq!(catalog.stats().expect("stats").deltas, 0);
        cleanup(&path);
    }

    #[test]
    fn writable_open_migrates_a_v1_catalog_without_reinitializing_it() {
        let path = temporary_catalog("migration-v1");
        let connection = Connection::open(&path).expect("v1 database");
        connection
            .execute_batch(&format!(
                "PRAGMA application_id = {CATALOG_APPLICATION_ID};
                 PRAGMA user_version = 1;
                 CREATE TABLE sources (
                     source_id INTEGER PRIMARY KEY,
                     name TEXT NOT NULL UNIQUE,
                     license_expression TEXT NOT NULL,
                     license_evidence_sha256 TEXT NOT NULL,
                     locator TEXT NOT NULL,
                     first_imported_at TEXT NOT NULL,
                     last_imported_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE canonical_vulnerabilities (
                     canonical_id TEXT PRIMARY KEY,
                     created_at TEXT NOT NULL,
                     updated_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE source_record_revisions (
                     revision_id INTEGER PRIMARY KEY,
                     source_id INTEGER NOT NULL REFERENCES sources(source_id),
                     source_record_id TEXT NOT NULL,
                     modified_at TEXT NOT NULL,
                     raw_sha256 TEXT NOT NULL,
                     raw_json BLOB NOT NULL,
                     imported_at TEXT NOT NULL,
                     UNIQUE(source_id, source_record_id, raw_sha256)
                 ) STRICT;
                 CREATE TABLE source_records (
                     record_rowid INTEGER PRIMARY KEY,
                     source_id INTEGER NOT NULL REFERENCES sources(source_id),
                     source_record_id TEXT NOT NULL,
                     canonical_id TEXT NOT NULL REFERENCES canonical_vulnerabilities(canonical_id),
                     modified_at TEXT NOT NULL,
                     published_at TEXT,
                     withdrawn_at TEXT,
                     title TEXT NOT NULL,
                     details TEXT NOT NULL,
                     raw_sha256 TEXT NOT NULL,
                     current_revision_id INTEGER NOT NULL REFERENCES source_record_revisions(revision_id),
                     UNIQUE(source_id, source_record_id)
                 ) STRICT;"
            ))
            .expect("v1 schema");
        drop(connection);
        let catalog = Catalog::open_or_create(&path).expect("migrated catalog");
        assert_eq!(
            schema_version(&catalog.connection).expect("version"),
            i64::from(CATALOG_SCHEMA_VERSION)
        );
        let active_columns = catalog
            .connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('source_records') WHERE name = 'active'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("active column");
        assert_eq!(active_columns, 1);
        cleanup(&path);
    }

    #[test]
    fn deferred_search_fails_closed_until_an_explicit_rebuild() {
        let path = temporary_catalog("deferred-search");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let bytes = record("GHSA-aaaa-bbbb-cccc", &[], "deferred title");
        catalog
            .import_osv_batch_deferred_search(&source(), [&bytes])
            .expect("deferred import");
        assert_eq!(catalog.stats().expect("stats").search_index_status, "dirty");
        assert!(matches!(
            catalog.search_text("deferred title", 10),
            Err(CatalogError::InvalidQuery(_))
        ));
        catalog.rebuild_search_index().expect("rebuild");
        assert_eq!(
            catalog
                .search_text("deferred title", 10)
                .expect("search")
                .len(),
            1
        );
        let integrity = catalog.check_integrity().expect("integrity");
        assert_eq!(integrity.quick_check, "ok");
        assert_eq!(integrity.foreign_key_violations, 0);
        cleanup(&path);
    }

    #[test]
    fn concurrent_readers_observe_consistent_states_during_writes() {
        use std::sync::{Arc, Barrier};

        let path = temporary_catalog("concurrent-readers");
        let mut initial = Catalog::open_or_create(&path).expect("catalog");
        let first = record("GHSA-aaaa-bbbb-cccc", &[], "initial title");
        initial
            .import_osv_record(&source(), &first)
            .expect("initial import");
        drop(initial);

        let barrier = Arc::new(Barrier::new(4));
        let writer_path = path.clone();
        let writer_barrier = barrier.clone();
        let writer = std::thread::spawn(move || {
            let mut catalog = Catalog::open_existing_writable(&writer_path).expect("writer");
            writer_barrier.wait();
            for index in 0..25_u32 {
                let id = format!("GHSA-test-test-{index:04}");
                let bytes = record(&id, &[], &format!("concurrent title {index}"));
                catalog
                    .import_osv_record(&source(), &bytes)
                    .expect("concurrent import");
            }
        });

        let mut readers = Vec::new();
        for _ in 0..3 {
            let reader_path = path.clone();
            let reader_barrier = barrier.clone();
            readers.push(std::thread::spawn(move || {
                let catalog = Catalog::open_existing(&reader_path).expect("reader");
                reader_barrier.wait();
                for _ in 0..50 {
                    let stats = catalog.stats().expect("consistent stats");
                    assert!(stats.active_source_records >= 1);
                    assert_eq!(
                        catalog
                            .lookup_identifier("GHSA-aaaa-bbbb-cccc", 1)
                            .expect("consistent lookup")
                            .len(),
                        1
                    );
                }
            }));
        }
        writer.join().expect("writer thread");
        for reader in readers {
            reader.join().expect("reader thread");
        }
        let catalog = Catalog::open_existing(&path).expect("final reader");
        assert_eq!(catalog.stats().expect("final stats").source_records, 26);
        drop(catalog);
        cleanup(&path);
    }

    #[test]
    fn unrelated_sqlite_databases_are_not_adopted_or_modified() {
        let path = temporary_catalog("unrelated");
        let connection = Connection::open(&path).expect("unrelated SQLite database");
        connection
            .execute("CREATE TABLE user_data(value TEXT NOT NULL)", [])
            .expect("fixture table");
        drop(connection);
        let before = fs::read(&path).expect("before bytes");
        assert!(matches!(
            Catalog::open_or_create(&path),
            Err(CatalogError::ApplicationIdMismatch(0))
        ));
        assert_eq!(fs::read(&path).expect("after bytes"), before);
        cleanup(&path);
    }

    #[test]
    fn oversized_and_unbounded_records_are_rejected() {
        let path = temporary_catalog("limits");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let oversized = vec![b'a'; MAX_OSV_RECORD_BYTES as usize + 1];
        assert!(matches!(
            catalog.import_osv_record(&source(), &oversized),
            Err(CatalogError::RecordTooLarge { .. })
        ));
        let too_many_aliases = serde_json::to_vec(&serde_json::json!({
            "id": "GHSA-aaaa-bbbb-cccc",
            "modified": "2026-08-23T00:00:00Z",
            "aliases": (0..=MAX_IDENTIFIERS_PER_RECORD)
                .map(|index| format!("CVE-2026-{index:06}"))
                .collect::<Vec<_>>()
        }))
        .expect("fixture JSON");
        assert!(matches!(
            catalog.import_osv_record(&source(), &too_many_aliases),
            Err(CatalogError::InvalidRecord("identifiers"))
        ));
        cleanup(&path);
    }

    #[test]
    fn raw_advisory_controls_are_retained_but_normalized_for_queries() {
        let path = temporary_catalog("content-controls");
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let bytes = serde_json::to_vec(&serde_json::json!({
            "id": "GHSA-aaaa-bbbb-cccc",
            "modified": "2026-08-23T00:00:00Z",
            "summary": "terminal\u{1b}[31m evidence",
            "details": "captured output\u{1b}[0m"
        }))
        .expect("fixture JSON");
        catalog
            .import_osv_record(&source(), &bytes)
            .expect("record import");
        let hits = catalog
            .lookup_identifier("GHSA-aaaa-bbbb-cccc", 1)
            .expect("lookup");
        assert_eq!(hits.len(), 1);
        assert!(!hits[0].title.chars().any(char::is_control));
        assert_eq!(
            catalog.stats().expect("stats").raw_revision_bytes,
            bytes.len() as u64
        );
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn catalog_rejects_symlinks_and_uses_private_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let path = temporary_catalog("permissions");
        let link = path.with_extension("link");
        let catalog = Catalog::open_or_create(&path).expect("catalog");
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        drop(catalog);
        symlink(&path, &link).expect("symlink");
        assert!(matches!(
            Catalog::open_existing(&link),
            Err(CatalogError::InvalidPath(_))
        ));
        let _ = fs::remove_file(link);
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn database_size_preserves_non_utf8_paths_for_sqlite_sidecars() {
        use std::os::unix::ffi::OsStringExt;

        let mut name = format!("secureflow-catalog-non-utf8-{}-", std::process::id()).into_bytes();
        name.push(0xff);
        name.extend_from_slice(b".sqlite3");
        let path = std::env::temp_dir().join(std::ffi::OsString::from_vec(name));
        let mut catalog = Catalog::open_or_create(&path).expect("catalog");
        let bytes = record("GHSA-aaaa-bbbb-cccc", &[], "title");
        catalog
            .import_osv_record(&source(), &bytes)
            .expect("record import");

        let expected = [
            path.clone(),
            path_with_suffix(&path, "-wal"),
            path_with_suffix(&path, "-shm"),
        ]
        .into_iter()
        .map(|candidate| fs::metadata(candidate).expect("catalog file").len())
        .sum::<u64>();
        assert_eq!(catalog.stats().expect("stats").database_bytes, expected);
        drop(catalog);
        cleanup(&path);
    }
}
