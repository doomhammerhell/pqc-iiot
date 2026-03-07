//! Persistence Utilities for Critical Systems
//! 
//! Implements patterns to prevent data corruption and flash wear.

use crate::{Error, Result};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

/// Atomic File Store
/// 
/// Implements the "Write-Sync-Rename" pattern to ensure that files are never
/// left in a corrupted or truncated state due to power failure.
pub struct AtomicFileStore;

impl AtomicFileStore {
    /// Write data to a file atomically.
    /// 
    /// 1. WRITE to `filename.tmp`
    /// 2. SYNC (fsync) to ensure data is on physical media
    /// 3. RENAME `filename.tmp` to `filename` (Atomic operation)
    pub fn write(path: &Path, data: &[u8]) -> Result<()> {
        let tmp_path = path.with_extension("tmp");
        
        // 1. Write to temp file
        fs::write(&tmp_path, data).map_err(|e| Error::IoError(e))?;
        
        // 2. Sync to disk check
        let file = fs::File::open(&tmp_path).map_err(|e| Error::IoError(e))?;
        file.sync_all().map_err(|e| Error::IoError(e))?;
        drop(file); // Close before rename
        
        // 3. Atomic Rename
        fs::rename(&tmp_path, path).map_err(|e| Error::IoError(e))?;
        
        Ok(())
    }

    /// Read data from a file with a strict size limit (Anti-OOM).
    /// 
    /// # Arguments
    /// * `path` - The path to the file
    /// * `max_bytes` - Maximum allowed size in bytes
    pub fn read_with_limit(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
        use std::io::Read;
        
        let file = fs::File::open(path).map_err(|e| Error::IoError(e))?;
        let metadata = file.metadata().map_err(|e| Error::IoError(e))?;
        
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
        reader.read_to_end(&mut buffer).map_err(|e| Error::IoError(e))?;
        
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
