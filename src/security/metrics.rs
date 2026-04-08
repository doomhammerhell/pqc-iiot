use std::sync::atomic::{AtomicU64, Ordering};
// use std::sync::Arc;

/// Security Metrics for Anomaly Detection.
/// Uses atomic counters for high-performance, thread-safe updates.
#[derive(Debug)] // Kept Debug derive, removed Default as new() is explicit
pub struct SecurityMetrics {
    /// Number of active secure sessions.
    pub active_sessions: AtomicU64,
    /// Number of successful handshakes.
    pub successful_handshakes: AtomicU64,
    /// Number of failed handshakes (Indicator of Brute Force).
    pub failed_handshakes: AtomicU64,
    /// Number of decryption failures (Indicator of Probing/Fuzzing).
    pub decryption_failures: AtomicU64, // Potential probing attack
    /// Number of replay attacks detected.
    pub replay_attacks_detected: AtomicU64,
    /// Number of DoS puzzles issued to clients.
    pub dos_puzzles_issued: AtomicU64,
    /// Number of packets dropped due to rate limiting.
    pub rate_limit_drops: AtomicU64,
    /// Current Security Version Number (SVN).
    pub current_svn: AtomicU64,
    /// Integrity Status (1 = OK, 0 = FAILED).
    pub integrity_ok: AtomicU64,
    /// MQTT notification drops due to bounded channel backpressure.
    /// This is a signal of overload/DoS conditions and should be monitored.
    pub mqtt_rx_queue_drops: AtomicU64,
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityMetrics {
    /// Initialize new zeroed metrics.
    pub fn new() -> Self {
        Self {
            active_sessions: AtomicU64::new(0),
            successful_handshakes: AtomicU64::new(0),
            failed_handshakes: AtomicU64::new(0),
            decryption_failures: AtomicU64::new(0),
            replay_attacks_detected: AtomicU64::new(0),
            dos_puzzles_issued: AtomicU64::new(0),
            rate_limit_drops: AtomicU64::new(0),
            current_svn: AtomicU64::new(0),
            integrity_ok: AtomicU64::new(1), // Assume OK on start
            mqtt_rx_queue_drops: AtomicU64::new(0),
        }
    }

    /// Increment active sessions count.
    pub fn inc_active_sessions(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active sessions count.
    pub fn dec_active_sessions(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment successful handshakes.
    pub fn inc_success_handshake(&self) {
        self.successful_handshakes.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment failed handshakes.
    pub fn inc_failed_handshake(&self) {
        self.failed_handshakes.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment decryption failures.
    pub fn inc_decryption_failure(&self) {
        self.decryption_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment replay attacks.
    pub fn inc_replay_attack(&self) {
        self.replay_attacks_detected.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment rate-limit drops.
    pub fn inc_rate_limit_drop(&self) {
        self.rate_limit_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment MQTT RX queue drops (bounded channel full).
    pub fn inc_mqtt_rx_queue_drop(&self) {
        self.mqtt_rx_queue_drops.fetch_add(1, Ordering::Relaxed);
    }
}

// Global instance pattern can be used, or passed via dependency injection.
// For now, we define the struct.
