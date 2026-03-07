use super::quote::AttestationQuote;
use crate::error::Result;

/// Policy engine for evaluating Attestation Quotes.
pub struct AttestationPolicy {
    /// List of allowed PCR digests (Golden Measurements)
    pub allowed_pcr_digests: Vec<Vec<u8>>,
}

impl AttestationPolicy {
    pub fn new() -> Self {
        Self {
            allowed_pcr_digests: Vec::new(),
        }
    }
    
    /// Evaluate a quote against the policy.
    pub fn evaluate(&self, quote: &AttestationQuote) -> Result<bool> {
        if self.allowed_pcr_digests.is_empty() {
             // If no policy, fail open? No, fail secure.
             return Ok(false);
        }
        
        for allowed in &self.allowed_pcr_digests {
            if quote.pcr_digest == *allowed {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
}
