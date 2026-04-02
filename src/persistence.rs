//! Persistence Utilities for Critical Systems
//!
//! Implements patterns to prevent data corruption and flash wear.

use crate::{Error, Result};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Atomic File Store
///
/// Implements the "Write-Sync-Rename" pattern to ensure that files are never
/// left in a corrupted or truncated state due to power failure.
pub struct AtomicFileStore;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl AtomicFileStore {
    /// Write data to a file atomically.
    ///
    /// 1. WRITE to `filename.tmp`
    /// 2. SYNC (fsync) to ensure data is on physical media
    /// 3. RENAME `filename.tmp` to `filename` (Atomic operation)
    pub fn write(path: &Path, data: &[u8]) -> Result<()> {
        // Create a per-write unique temp file name in the same directory to guarantee atomic rename.
        // Avoid predictable `.tmp` names to reduce symlink/hardlink clobber attacks in shared dirs.
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("blob");
        let pid = std::process::id();

        let mut last_err_kind = None;
        for _ in 0..32 {
            let nonce = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tmp_name = format!(".{}.tmp.{}.{}", file_name, pid, nonce);
            let tmp_path = parent.join(tmp_name);

            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }

            let mut file = match opts.open(&tmp_path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    last_err_kind = Some(e.kind());
                    continue;
                }
                Err(e) => return Err(Error::IoError(e)),
            };

            // 1. Write to temp file
            if let Err(e) = file.write_all(data) {
                let _ = fs::remove_file(&tmp_path);
                return Err(Error::IoError(e));
            }

            // 2. Sync temp file contents to disk
            if let Err(e) = file.sync_all() {
                let _ = fs::remove_file(&tmp_path);
                return Err(Error::IoError(e));
            }
            drop(file); // Close before rename

            // 3. Atomic Rename (same directory)
            if let Err(e) = fs::rename(&tmp_path, path) {
                // Best-effort cleanup on rename failure (e.g., permissions, cross-device).
                let _ = fs::remove_file(&tmp_path);
                return Err(Error::IoError(e));
            }

            // 4. Sync parent directory metadata for durability (POSIX requirement).
            // Without this, a power loss can roll back the rename even if the file content was synced.
            #[cfg(unix)]
            {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        let dir = fs::File::open(parent).map_err(Error::IoError)?;
                        dir.sync_all().map_err(Error::IoError)?;
                    }
                }
            }

            return Ok(());
        }

        Err(Error::ClientError(format!(
            "Atomic write failed: could not allocate temp file (last error kind: {:?})",
            last_err_kind
        )))
    }

    /// Read data from a file with a strict size limit (Anti-OOM).
    ///
    /// # Arguments
    /// * `path` - The path to the file
    /// * `max_bytes` - Maximum allowed size in bytes
    pub fn read_with_limit(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
        use std::io::Read;

        let file = fs::File::open(path).map_err(Error::IoError)?;
        let metadata = file.metadata().map_err(Error::IoError)?;

        if metadata.len() > max_bytes as u64 {
            return Err(Error::ClientError(format!(
                "File too large: {} bytes (limit: {})",
                metadata.len(),
                max_bytes
            )));
        }

        // Use take to strictly enforce limit during read
        let mut reader = std::io::BufReader::new(file).take(max_bytes as u64);
        let mut buffer = Vec::with_capacity(metadata.len() as usize);
        reader.read_to_end(&mut buffer).map_err(Error::IoError)?;

        Ok(buffer)
    }
}

/// Lazy Persistence Manager
///
/// mitigates Flash Write Amplification by buffering writes in RAM
/// and only flushing to disk when:
/// - A time interval has passed (e.g., 5 minutes)
/// - OR a mutation threshold is reached (e.g., 100 updates)
/// - OR explicitly requested (Shutdown)
pub struct LazyPersistManager {
    last_flush: Instant,
    flush_interval: Duration,
    mutation_count: u32,
    mutation_threshold: u32,
    is_dirty: bool,
}

impl LazyPersistManager {
    /// Create a new PersistenceManager.
    pub fn new(flush_interval: Duration, mutation_threshold: u32) -> Self {
        Self {
            last_flush: Instant::now(),
            flush_interval,
            mutation_count: 0,
            mutation_threshold,
            is_dirty: false,
        }
    }

    /// Mark the state as dirty (needs save).
    pub fn mark_dirty(&mut self) {
        self.is_dirty = true;
        self.mutation_count += 1;
    }

    /// Check if a flush is required right now.
    pub fn should_flush(&self) -> bool {
        if !self.is_dirty {
            return false;
        }

        if self.mutation_count >= self.mutation_threshold {
            return true;
        }

        if self.last_flush.elapsed() >= self.flush_interval {
            return true;
        }

        false
    }

    /// Reset counters after a successful flush.
    pub fn notify_flushed(&mut self) {
        self.last_flush = Instant::now();
        self.mutation_count = 0;
        self.is_dirty = false;
    }
}
