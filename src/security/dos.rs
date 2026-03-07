use sha2::{Sha256, Digest};
use std::time::Instant;
use std::collections::HashMap;
use rand_core::RngCore; // Needed for fill_bytes

/// DoS Hardening: Client Puzzles (Proof-of-Work)
/// 
/// Forces clients to burn CPU before the server allocates generic memory.
/// Uses a Hashcash-style mechanism: H(seed || nonce) must have N leading zeros.

#[derive(Debug, Clone)]
/// Client Puzzle using Hashcash-style PoW.
pub struct Puzzle {
    /// Random seed to prevent pre-computation.
    pub seed: [u8; 16],
    /// Difficulty level (number of leading zero bits required).
    pub difficulty: u8, // Number of zero bits required
}

impl Puzzle {
    /// Create a new puzzle with target difficulty.
    pub fn new(difficulty: u8) -> Self {
        let mut seed = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut seed);
        Self { seed, difficulty }
    }

    /// Verifies the solution provided by the client.
    /// Nonce is typically an 8-byte value.
    pub fn verify(&self, nonce: &[u8]) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.seed);
        hasher.update(nonce);
        let result = hasher.finalize();
        
        // Check leading zeros
        // Simple implementation: check first N/8 bytes are 0
        // For difficulty=8, byte[0] == 0.
        // For difficulty=16, byte[0]==0 && byte[1]==0.
        // ... (can be more granular with bit checks)
        
        let bytes_needed = (self.difficulty / 8) as usize;
        for i in 0..bytes_needed {
            if result[i] != 0 { return false; }
        }
        
        // Check remaining bits
        let remaining_bits = self.difficulty % 8;
        if remaining_bits > 0 {
            let mask = 0xFF << (8 - remaining_bits);
            if (result[bytes_needed] & mask) != 0 { return false; }
        }
        
        true
    }
}

/// Token Bucket Rate Limiter
pub struct ConnectionThrottler {
    /// Per-IP state: (Current Tokens, Last Refill Time).
    ips: HashMap<std::net::IpAddr, (u32, Instant)>,
    /// Max burst size.
    capacity: u32,
    /// Tokens added per second.
    refill_rate_per_sec: u32,
}

impl ConnectionThrottler {
    /// Create a new Token Bucket rate limiter.
    /// 
    /// * `capacity` - Max burst size.
    /// * `refill_rate` - Tokens added per second.
    pub fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            ips: HashMap::new(),
            capacity,
            refill_rate_per_sec: refill_rate,
        }
    }

    /// Check if a request from a given IP allowed.
    /// Returns `true` if allowed (token consumed), `false` if limited.
    pub fn allow_request(&mut self, ip: std::net::IpAddr) -> bool {
        // ANTI-DOS: Memory Protection
        if self.ips.len() > 10000 {
            // "Nuclear" cleanup - if under attack, drop state to protect memory.
            // Valid clients will just refill buckets.
            self.ips.clear();
        }

        let now = Instant::now();
        let (tokens, last_refill) = self.ips.entry(ip).or_insert((self.capacity, now));
        
        // Refill
        let elapsed = now.duration_since(*last_refill).as_secs() as u32;
        if elapsed > 0 {
            *tokens = std::cmp::min(self.capacity, *tokens + elapsed * self.refill_rate_per_sec);
            *last_refill = now;
        }
        
        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }
}
