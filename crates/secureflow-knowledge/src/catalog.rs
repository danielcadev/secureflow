//! Indexed local catalog for public vulnerability advisories.
//!
//! The catalog is intentionally separate from the append-only human-decision
//! ledger. Source records remain attributable to their home database while
//! exact aliases may connect several source records to one internal canonical
//! entity. Upstream and related identifiers never trigger a merge.

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Params, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const CATALOG_SCHEMA_VERSION: u32 = 1;
pub const CATALOG_APPLICATION_ID: u32 = 0x5346_4b42;
pub const MAX_OSV_RECORD_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_IMPORT_RECORDS: usize = 1_100_000;
pub const MAX_QUERY_RESULTS: usize = 1_000;

const MAX_IDENTIFIERS_PER_RECORD: usize = 1_024;
const MAX_AFFECTED_PER_RECORD: usize = 4_096;
const MAX_REFERENCES_PER_RECORD: usize = 4_096;
const MAX_VERSIONS_PER_AFFECTED: usize = 100_000;

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
}

impl CatalogImportResult {
    pub fn merge(&mut self, other: Self) {
        self.records_seen += other.records_seen;
        self.records_inserted += other.records_inserted;
        self.records_updated += other.records_updated;
        self.records_unchanged += other.records_unchanged;
        self.duplicate_records_linked += other.duplicate_records_linked;
        self.canonical_groups_merged += other.canonical_groups_merged;
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogStats {
    pub schema_version: u32,
    pub sources: u64,
    pub canonical_vulnerabilities: u64,
    pub source_records: u64,
    pub source_record_revisions: u64,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogIntegrity {
    pub quick_check: String,
    pub foreign_key_violations: u64,
    pub search_index_status: String,
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
    Filesystem { path: PathBuf, source: std::io::Error },
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
}

pub struct Catalog {
    connection: Connection,
    path: PathBuf,
}

impl Catalog {
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
            verify_schema(&connection)?;
            configure_connection(&connection, false)?;
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
        verify_schema(&connection)?;
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
        verify_schema(&connection)?;
        configure_connection(&connection, false)?;
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
        self.import_osv_batch_internal(source, records, true)
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
        self.import_osv_batch_internal(source, records, false)
    }

    fn import_osv_batch_internal<I, B>(
        &mut self,
        source: &CatalogSource,
        records: I,
        update_search_index: bool,
    ) -> Result<CatalogImportResult, CatalogError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        validate_source(source)?;
        if !update_search_index {
            self.connection
                .pragma_update(None, "wal_autocheckpoint", 0_i64)?;
        }
        let imported_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| CatalogError::InvalidRecord("imported_at"))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let source_id = register_source(&transaction, source, &imported_at)?;
        if !update_search_index {
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
            validate_osv_record(&record)?;
            result.records_seen += 1;
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
        }
        transaction.commit()?;
        Ok(result)
    }

    pub fn rebuild_search_index(&mut self) -> Result<(), CatalogError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        execute_cached(&transaction, "DELETE FROM source_record_fts", [])?;
        execute_cached(
            &transaction,
            "INSERT INTO source_record_fts(rowid, title, details)
             SELECT record_rowid, title, details FROM source_records",
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
        let (busy, log_frames, checkpointed_frames) = self.connection.query_row(
            "PRAGMA wal_checkpoint(TRUNCATE)",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
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
        validate_query(identifier, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT sr.canonical_id, s.name, sr.source_record_id, sr.title,
                    sr.modified_at, sr.withdrawn_at IS NOT NULL
             FROM identifiers i
             JOIN source_records sr ON sr.canonical_id = i.canonical_id
             JOIN sources s ON s.source_id = sr.source_id
             WHERE i.identifier = ?1
             ORDER BY sr.withdrawn_at IS NOT NULL, s.name, sr.source_record_id
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![identifier, limit as i64], hit_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn search_text(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<CatalogHit>, CatalogError> {
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
             WHERE source_record_fts MATCH ?1
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
        validate_query(ecosystem, limit)?;
        validate_query(name, limit)?;
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT sr.canonical_id, s.name, sr.source_record_id,
                    sr.title, sr.modified_at, sr.withdrawn_at IS NOT NULL
             FROM affected_packages ap
             JOIN source_records sr ON sr.record_rowid = ap.source_record_rowid
             JOIN sources s ON s.source_id = sr.source_id
             WHERE ap.ecosystem = ?1 AND ap.package_name = ?2
             ORDER BY sr.withdrawn_at IS NOT NULL, s.name, sr.source_record_id
             LIMIT ?3",
        )?;
        let rows = statement.query_map(params![ecosystem, name, limit as i64], hit_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn stats(&self) -> Result<CatalogStats, CatalogError> {
        let database_bytes = database_size(&self.path)?;
        Ok(CatalogStats {
            schema_version: CATALOG_SCHEMA_VERSION,
            sources: count(&self.connection, "sources")?,
            canonical_vulnerabilities: count(&self.connection, "canonical_vulnerabilities")?,
            source_records: count(&self.connection, "source_records")?,
            source_record_revisions: count(&self.connection, "source_record_revisions")?,
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
             UNIQUE(source_id, source_record_id)
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

fn verify_schema(connection: &Connection) -> Result<(), CatalogError> {
    let application_id = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application_id != i64::from(CATALOG_APPLICATION_ID) {
        return Err(CatalogError::ApplicationIdMismatch(application_id));
    }
    let version = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != i64::from(CATALOG_SCHEMA_VERSION) {
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
            "SELECT record_rowid, raw_sha256, canonical_id
             FROM source_records WHERE source_id = ?1 AND source_record_id = ?2",
            params![source_id, record.id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
    if existing
        .as_ref()
        .is_some_and(|(_, existing_hash, _)| existing_hash == &raw_sha256)
    {
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
    if let Some((_, _, existing_canonical)) = &existing {
        canonical_ids.insert(existing_canonical.clone());
    }
    for identifier in &exact_identifiers {
        if let Some(value) = query_row_optional_cached(
            transaction,
                "SELECT canonical_id FROM identifiers WHERE identifier = ?1",
                [identifier],
                |row| row.get::<_, String>(0),
            )?
        {
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
        params![source_id, record.id, record.modified, raw_sha256, raw, imported_at],
    )?;
    let revision_id = query_row_cached(
        transaction,
        "SELECT revision_id FROM source_record_revisions
         WHERE source_id = ?1 AND source_record_id = ?2 AND raw_sha256 = ?3",
        params![source_id, record.id, raw_sha256],
        |row| row.get::<_, i64>(0),
    )?;
    let title = record
        .summary
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&record.id);
    let details = record.details.as_deref().unwrap_or("");
    let record_rowid = if let Some((record_rowid, _, _)) = existing {
        execute_cached(
            transaction,
            "UPDATE source_records SET
                 canonical_id = ?1, modified_at = ?2, published_at = ?3,
                 withdrawn_at = ?4, title = ?5, details = ?6, raw_sha256 = ?7,
                 current_revision_id = ?8
             WHERE record_rowid = ?9",
            params![
                selected,
                record.modified,
                record.published,
                record.withdrawn,
                title,
                details,
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
                title,
                details,
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

fn validate_source(source: &CatalogSource) -> Result<(), CatalogError> {
    validate_text(&source.name, 100, "source.name")?;
    validate_text(
        &source.license_expression,
        200,
        "source.license_expression",
    )?;
    if !super::valid_sha256(&source.license_evidence_sha256) {
        return Err(CatalogError::InvalidRecord(
            "source.license_evidence_sha256",
        ));
    }
    validate_text(&source.locator, 4_096, "source.locator")
}

fn validate_osv_record(record: &OsvRecord) -> Result<(), CatalogError> {
    validate_identifier(&record.id, "id")?;
    validate_timestamp(&record.modified, "modified")?;
    validate_optional_timestamp(record.published.as_deref(), "published")?;
    validate_optional_timestamp(record.withdrawn.as_deref(), "withdrawn")?;
    if let Some(version) = &record.schema_version {
        validate_text(version, 50, "schema_version")?;
    }
    validate_optional_text(record.summary.as_deref(), 1_000, "summary")?;
    validate_optional_text(record.details.as_deref(), 262_144, "details")?;
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

fn validate_text(
    value: &str,
    max_chars: usize,
    field: &'static str,
) -> Result<(), CatalogError> {
    if value.trim().is_empty()
        || value.chars().count() > max_chars
        || value.chars().any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
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
        return Err(CatalogError::InvalidQuery("query must contain 1 to 500 characters"));
    }
    if limit == 0 || limit > MAX_QUERY_RESULTS {
        return Err(CatalogError::InvalidQuery("limit must be between 1 and 1000"));
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

fn ensure_search_index_ready(connection: &Connection) -> Result<(), CatalogError> {
    if search_index_status(connection)? != "ready" {
        return Err(CatalogError::InvalidQuery(
            "full-text index is dirty; rebuild it before searching",
        ));
    }
    Ok(())
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
            return Err(CatalogError::InvalidPath("database path cannot be a symlink"));
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(CatalogError::InvalidPath("database path is not a regular file"));
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
    builder.create(path).map_err(|source| CatalogError::Filesystem {
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
        assert_eq!(catalog.search_text("deferred title", 10).expect("search").len(), 1);
        let integrity = catalog.check_integrity().expect("integrity");
        assert_eq!(integrity.quick_check, "ok");
        assert_eq!(integrity.foreign_key_violations, 0);
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

        let mut name = format!(
            "secureflow-catalog-non-utf8-{}-",
            std::process::id()
        )
        .into_bytes();
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
