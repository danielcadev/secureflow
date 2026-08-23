//! Hash-bound catalog backup manifests and restore verification.

use crate::catalog::{
    CATALOG_APPLICATION_ID, Catalog, CatalogIntegrity, CatalogProvenance, CatalogStats,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const BACKUP_VERSION: &str = "secureflow-catalog-backup-v1";
pub const MAX_BACKUP_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_BACKUP_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogBackupManifest {
    pub contract_version: String,
    pub backup_id: String,
    pub created_at: String,
    pub database_sha256: String,
    pub database_bytes: u64,
    pub application_id: u32,
    pub schema_version: u32,
    pub method: String,
    pub stats: CatalogStats,
    pub integrity: CatalogIntegrity,
    pub provenance: CatalogProvenance,
}

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("catalog backup field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("catalog backup filesystem operation failed for {path}: {source}")]
    Filesystem {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("catalog backup hash does not match its manifest")]
    HashMismatch,
    #[error("catalog backup size does not match its manifest")]
    SizeMismatch,
    #[error("catalog operation failed: {0}")]
    Catalog(#[from] crate::catalog::CatalogError),
    #[error("invalid catalog backup manifest JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not format backup timestamp: {0}")]
    Timestamp(#[from] time::error::Format),
}

pub fn create_backup(
    source: &Catalog,
    output: &Path,
) -> Result<CatalogBackupManifest, BackupError> {
    source.backup_to(output)?;
    let backup = Catalog::open_existing(output)?;
    let database_bytes = regular_file_size(output)?;
    let database_sha256 = hash_file(output)?;
    let manifest = CatalogBackupManifest {
        contract_version: BACKUP_VERSION.into(),
        backup_id: format!("sf_catalog_backup_{database_sha256}"),
        created_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        database_sha256,
        database_bytes,
        application_id: CATALOG_APPLICATION_ID,
        schema_version: crate::catalog::CATALOG_SCHEMA_VERSION,
        method: "sqlite-online-backup-api".into(),
        stats: backup.stats()?,
        integrity: backup.check_integrity()?,
        provenance: backup.provenance()?,
    };
    manifest.validate()?;
    Ok(manifest)
}

pub fn parse_manifest(bytes: &[u8]) -> Result<CatalogBackupManifest, BackupError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BACKUP_MANIFEST_BYTES {
        return Err(BackupError::InvalidField("manifest size"));
    }
    let manifest: CatalogBackupManifest = serde_json::from_slice(bytes)?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn verify_backup(
    backup_path: &Path,
    manifest: &CatalogBackupManifest,
) -> Result<(), BackupError> {
    manifest.validate()?;
    if regular_file_size(backup_path)? != manifest.database_bytes {
        return Err(BackupError::SizeMismatch);
    }
    if hash_file(backup_path)? != manifest.database_sha256 {
        return Err(BackupError::HashMismatch);
    }
    let catalog = Catalog::open_existing(backup_path)?;
    if catalog.stats()? != manifest.stats
        || catalog.check_integrity()? != manifest.integrity
        || catalog.provenance()? != manifest.provenance
    {
        return Err(BackupError::InvalidField(
            "catalog state differs from manifest",
        ));
    }
    Ok(())
}

pub fn restore_backup(
    backup_path: &Path,
    manifest: &CatalogBackupManifest,
    output: &Path,
) -> Result<CatalogBackupManifest, BackupError> {
    verify_backup(backup_path, manifest)?;
    let source = Catalog::open_existing(backup_path)?;
    create_backup(&source, output)
}

impl CatalogBackupManifest {
    pub fn validate(&self) -> Result<(), BackupError> {
        if self.contract_version != BACKUP_VERSION
            || self.backup_id != format!("sf_catalog_backup_{}", self.database_sha256)
            || !valid_sha256(&self.database_sha256)
            || self.database_bytes == 0
            || self.database_bytes > MAX_BACKUP_BYTES
            || self.application_id != CATALOG_APPLICATION_ID
            || self.schema_version != crate::catalog::CATALOG_SCHEMA_VERSION
            || self.stats.schema_version != self.schema_version
            || self.method != "sqlite-online-backup-api"
            || OffsetDateTime::parse(&self.created_at, &Rfc3339).is_err()
            || self.integrity.quick_check != "ok"
            || self.integrity.foreign_key_violations != 0
            || self.provenance.schema_version != self.schema_version
        {
            return Err(BackupError::InvalidField("manifest"));
        }
        Ok(())
    }
}

fn regular_file_size(path: &Path) -> Result<u64, BackupError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| BackupError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupError::InvalidField("backup must be a regular file"));
    }
    if metadata.len() == 0 || metadata.len() > MAX_BACKUP_BYTES {
        return Err(BackupError::InvalidField("backup size"));
    }
    Ok(metadata.len())
}

fn hash_file(path: &Path) -> Result<String, BackupError> {
    let mut file = fs::File::open(path).map_err(|source| BackupError::Filesystem {
        path: path.to_owned(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| BackupError::Filesystem {
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing into a String cannot fail");
    }
    Ok(output)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "secureflow-{label}-{}-{}.sqlite3",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))
    }

    #[test]
    fn backup_restore_is_verified_and_never_overwrites() {
        let source_path = temp_path("backup-source");
        let backup_path = temp_path("backup-copy");
        let restored_path = temp_path("backup-restored");
        let source = Catalog::open_or_create(&source_path).unwrap();
        let manifest = create_backup(&source, &backup_path).unwrap();
        verify_backup(&backup_path, &manifest).unwrap();
        let restored = restore_backup(&backup_path, &manifest, &restored_path).unwrap();
        verify_backup(&restored_path, &restored).unwrap();
        assert!(create_backup(&source, &backup_path).is_err());
        drop(source);
        for path in [source_path, backup_path, restored_path] {
            let _ = fs::remove_file(path);
        }
    }
}
