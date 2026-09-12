//! Linux local-filesystem state, with explicit locking and durable replacement.
use super::{Result, error, require};
#[cfg(target_os = "linux")]
use std::os::unix::{
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub fn checked_path(path: &Path) -> Result<()> {
    require(
        path.is_absolute(),
        "TRUST_FILESYSTEM",
        "absolute local path required",
    )?;
    let canonical = fs::canonicalize(path).map_err(|e| error("TRUST_FILESYSTEM", e))?;
    require(
        canonical.as_os_str() == path.as_os_str(),
        "TRUST_FILESYSTEM",
        "path aliases or symlinks forbidden",
    )
}
pub(crate) fn open_regular(path: &Path) -> Result<File> {
    checked_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .map_err(|e| error("TRUST_FILESYSTEM", e))?;
    let m = file.metadata().map_err(|e| error("TRUST_FILESYSTEM", e))?;
    require(m.is_file(), "TRUST_FILESYSTEM", "regular file required")?;
    #[cfg(target_os = "linux")]
    require(
        m.nlink() == 1,
        "TRUST_FILESYSTEM",
        "hardlink aliases forbidden",
    )?;
    Ok(file)
}
pub fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = open_regular(path)?;
    require(
        file.metadata()
            .map_err(|e| error("TRUST_FILESYSTEM", e))?
            .len()
            <= limit as u64,
        "TRUST_FORMAT",
        "file exceeds byte bound",
    )?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| error("TRUST_FILESYSTEM", e))?;
    require(
        bytes.len() <= limit,
        "TRUST_FORMAT",
        "actual read exceeds byte bound",
    )?;
    Ok(bytes)
}
pub fn private_dir(path: &Path) -> Result<()> {
    checked_path(path)?;
    #[cfg(target_os = "linux")]
    {
        let m = fs::metadata(path).map_err(|e| error("TRUST_FILESYSTEM", e))?;
        // SAFETY: geteuid has no pointer arguments or memory effects.
        let uid = unsafe { libc::geteuid() };
        require(
            m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0,
            "TRUST_FILESYSTEM",
            "directory must be owned by caller and private (0700)",
        )?;
        let f = File::open(path).map_err(|e| error("TRUST_FILESYSTEM", e))?;
        let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: f is live and stats points to writable statfs storage.
        let result = unsafe { libc::fstatfs(f.as_raw_fd(), stats.as_mut_ptr()) };
        require(
            result == 0,
            "TRUST_FILESYSTEM",
            "cannot establish filesystem durability support",
        )?;
        // SAFETY: successful fstatfs initialized stats.
        let kind = unsafe { stats.assume_init() }.f_type;
        require(
            [0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630].contains(&kind),
            "TRUST_FILESYSTEM",
            "unsupported filesystem",
        )?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Err(error(
        "TRUST_FILESYSTEM",
        "trusted state requires tested Linux local filesystem",
    ))
}
pub fn create_dir(path: &Path) -> Result<()> {
    private_dir(
        path.parent()
            .ok_or_else(|| error("TRUST_FILESYSTEM", "parent required"))?,
    )?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(target_os = "linux")]
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|e| error("TRUST_FILESYSTEM", e))?;
    sync_parent(path)
}
pub fn sync_parent(path: &Path) -> Result<()> {
    File::open(
        path.parent()
            .ok_or_else(|| error("TRUST_FILESYSTEM", "parent required"))?,
    )
    .and_then(|f| f.sync_all())
    .map_err(|e| error("TRUST_FILESYSTEM", e))
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| error("TRUST_FILESYSTEM", "parent required"))?;
    private_dir(parent)?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|e| error("TRUST_FILESYSTEM", e))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|e| error("TRUST_FILESYSTEM", e))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let source = std::ffi::CString::new(temporary.path().as_os_str().as_bytes())
            .map_err(|e| error("TRUST_FILESYSTEM", e))?;
        let destination = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|e| error("TRUST_FILESYSTEM", e))?;
        // SAFETY: both C strings outlive the syscall. AT_FDCWD uses these absolute
        // checked paths; RENAME_NOREPLACE never overwrites the destination.
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err(error("TRUST_FILESYSTEM", std::io::Error::last_os_error()));
        }
        sync_parent(path)
    }
    #[cfg(not(target_os = "linux"))]
    Err(error(
        "TRUST_FILESYSTEM",
        "atomic no-overwrite publication requires supported Linux",
    ))
}
pub struct StoreLock {
    pub path: PathBuf,
    directory: File,
    _lock: File,
}
impl StoreLock {
    pub fn open(path: &Path, exclusive: bool) -> Result<Self> {
        private_dir(path)?;
        let directory = File::open(path).map_err(|e| error("TRUST_STATE", e))?;
        let lock_path = path.join("lock");
        checked_path(&lock_path)?;
        let mut opts = OpenOptions::new();
        opts.read(true).write(exclusive);
        #[cfg(target_os = "linux")]
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let lock = opts.open(&lock_path).map_err(|e| error("TRUST_STATE", e))?;
        let m = lock.metadata().map_err(|e| error("TRUST_STATE", e))?;
        require(m.is_file(), "TRUST_STATE", "lock must be regular")?;
        #[cfg(target_os = "linux")]
        require(
            m.nlink() == 1 && m.permissions().mode() & 0o077 == 0,
            "TRUST_STATE",
            "unsafe lock",
        )?;
        let result = if exclusive {
            lock.try_lock()
        } else {
            lock.try_lock_shared()
        };
        result.map_err(|e| {
            error(
                "TRUST_STATE",
                format!("exclusive mutation or snapshot lock unavailable: {e}"),
            )
        })?;
        let guard = Self {
            path: path.to_owned(),
            directory,
            _lock: lock,
        };
        guard.check_identity()?;
        Ok(guard)
    }
    pub fn check_identity(&self) -> Result<()> {
        private_dir(&self.path)?;
        let now = fs::metadata(&self.path).map_err(|e| error("TRUST_STATE", e))?;
        let held = self
            .directory
            .metadata()
            .map_err(|e| error("TRUST_STATE", e))?;
        #[cfg(target_os = "linux")]
        require(
            now.dev() == held.dev() && now.ino() == held.ino(),
            "TRUST_STATE",
            "store replaced during operation",
        )?;
        #[cfg(not(target_os = "linux"))]
        let _ = (now, held);
        #[cfg(target_os = "linux")]
        {
            let path = self.path.join("lock");
            checked_path(&path)?;
            let current = fs::metadata(path).map_err(|e| error("TRUST_STATE", e))?;
            let held = self._lock.metadata().map_err(|e| error("TRUST_STATE", e))?;
            require(
                current.ino() == held.ino() && current.dev() == held.dev(),
                "TRUST_STATE",
                "mutation lock replaced",
            )?;
        }
        Ok(())
    }
    pub fn replace_state(&self, bytes: &[u8]) -> Result<()> {
        self.check_identity()?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(&self.path).map_err(|e| error("TRUST_STATE", e))?;
        temporary
            .write_all(bytes)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|e| error("TRUST_STATE", e))?;
        self.check_identity()?;
        fs::rename(temporary.path(), self.path.join("state.json"))
            .map_err(|e| error("TRUST_STATE", e))?;
        self.directory
            .sync_all()
            .map_err(|e| error("TRUST_STATE", e))
    }
}
