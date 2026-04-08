use crate::security::monotonic::{seal_u64, unseal_u64};
use crate::security::provider::SecurityProvider;
use crate::Result;
use log::{info, warn};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn system_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Best-effort secure time floor.
///
/// This is *not* a secure time source by itself; it enforces a monotonic floor (non-decreasing)
/// across restarts when `SecurityProvider::seal_data/unseal_data` is backed by non-rollback storage
/// (TPM NV, HSM, TEE monotonic counter, WORM remote service, etc).
///
/// Threat model notes:
/// - Without a real anti-rollback root (hardware monotonic counter), an attacker with filesystem
///   write access can roll this floor back by restoring an older sealed blob.
/// - A forward time jump (setting clock to the future) is always a DoS vector; we only log it.
pub struct SecureTimeFloor {
    provider: Arc<dyn SecurityProvider>,
    label: String,
    floor_unix_s: u64,
    last_persist: Instant,
    persist_interval: Duration,
    max_backward_skew_s: u64,
}

impl SecureTimeFloor {
    /// Load a persisted monotonic unix-second floor from the provider.
    ///
    /// On the first run (no sealed value), this initializes the floor to the current system time
    /// and seals it immediately.
    pub fn load(provider: Arc<dyn SecurityProvider>, label: impl Into<String>) -> Result<Self> {
        let label = label.into();
        let persisted = unseal_u64(&provider, &label)?;
        let floor = persisted.unwrap_or_else(system_unix_seconds);

        // If this is the first run (no persisted floor), anchor immediately.
        if persisted.is_none() {
            seal_u64(&provider, &label, floor)?;
            info!("secure time floor initialized: {}={}", label, floor);
        }

        Ok(Self {
            provider,
            label,
            floor_unix_s: floor,
            last_persist: Instant::now(),
            // Avoid flash wear: persist at most once per minute unless caller forces.
            persist_interval: Duration::from_secs(60),
            // Allow small backward skew without treating it as an attack (NTP adjustments, RTC jitter).
            max_backward_skew_s: 5,
        })
    }

    /// Returns a unix timestamp in seconds, clamped to a monotonic floor.
    ///
    /// On backward jumps greater than `max_backward_skew_s`, this clamps to the previous floor and
    /// logs a warning. On forward movement, the floor is advanced and persisted periodically.
    pub fn now_unix_s(&mut self) -> Result<u64> {
        let now = system_unix_seconds();

        if now + self.max_backward_skew_s < self.floor_unix_s {
            warn!(
                "secure time rollback detected: now={} < floor={} (label={})",
                now, self.floor_unix_s, self.label
            );
            return Ok(self.floor_unix_s);
        }

        if now > self.floor_unix_s {
            self.floor_unix_s = now;
            if self.last_persist.elapsed() >= self.persist_interval {
                seal_u64(&self.provider, &self.label, self.floor_unix_s)?;
                self.last_persist = Instant::now();
            }
        }

        Ok(now)
    }

    /// Force persistence of the current floor.
    pub fn flush(&mut self) -> Result<()> {
        seal_u64(&self.provider, &self.label, self.floor_unix_s)?;
        self.last_persist = Instant::now();
        Ok(())
    }

    /// Return the current monotonic floor value (unix seconds).
    pub fn floor_unix_s(&self) -> u64 {
        self.floor_unix_s
    }
}
