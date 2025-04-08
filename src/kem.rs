//! Key Encapsulation Mechanism (KEM) using CRYSTALS-Kyber

use crate::{Error, Result};
use core::marker::PhantomData;
use heapless::Vec;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret};
use zeroize::Zeroize;

/// Maximum size for Kyber public keys
pub const MAX_PUBLIC_KEY_SIZE: usize = 1184;
/// Maximum size for Kyber secret keys
pub const MAX_SECRET_KEY_SIZE: usize = 2400;
/// Maximum size for Kyber ciphertexts
pub const MAX_CIPHERTEXT_SIZE: usize = 1088;
/// Size of the shared secret
pub const SHARED_SECRET_SIZE: usize = 32;

/// Kyber KEM implementation
#[derive(Debug, Default)]
pub struct Kyber<const N: usize = MAX_PUBLIC_KEY_SIZE> {
    _marker: PhantomData<[u8; N]>,
}

impl<const N: usize> Kyber<N> {
    /// Creates a new Kyber instance
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    /// Generates a new keypair
    pub fn generate_keypair(
        &self,
    ) -> Result<(Vec<u8, MAX_PUBLIC_KEY_SIZE>, Vec<u8, MAX_SECRET_KEY_SIZE>)> {
        let (pk, sk) = kyber768::keypair();
        let mut public_key = Vec::new();
        let mut secret_key = Vec::new();

        public_key
            .extend_from_slice(pk.as_bytes())
            .map_err(|_| Error::BufferTooSmall)?;
        secret_key
            .extend_from_slice(sk.as_bytes())
            .map_err(|_| Error::BufferTooSmall)?;

        Ok((public_key, secret_key))
    }

    /// Encapsulates a shared secret using a public key
    pub fn encapsulate(
        &self,
        public_key: &[u8],
    ) -> Result<(Vec<u8, MAX_CIPHERTEXT_SIZE>, Vec<u8, SHARED_SECRET_SIZE>)> {
        let pk = kyber768::PublicKey::from_bytes(public_key).map_err(|_| Error::InvalidInput)?;

        let (ss, ct) = kyber768::encapsulate(&pk);

        let mut ciphertext = Vec::new();
        let mut shared_secret = Vec::new();

        ciphertext
            .extend_from_slice(ct.as_bytes())
            .map_err(|_| Error::BufferTooSmall)?;
        shared_secret
            .extend_from_slice(ss.as_bytes())
            .map_err(|_| Error::BufferTooSmall)?;

        Ok((ciphertext, shared_secret))
    }

    /// Decapsulates a shared secret using a secret key and ciphertext
    pub fn decapsulate(
        &self,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8, SHARED_SECRET_SIZE>> {
        let sk = kyber768::SecretKey::from_bytes(secret_key).map_err(|_| Error::InvalidInput)?;
        let ct = kyber768::Ciphertext::from_bytes(ciphertext).map_err(|_| Error::InvalidInput)?;

        let ss = kyber768::decapsulate(&ct, &sk);
        let mut shared_secret = Vec::new();

        shared_secret
            .extend_from_slice(ss.as_bytes())
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(shared_secret)
    }
}

impl<const N: usize> Drop for Kyber<N> {
    fn drop(&mut self) {
        // No sensitive data to zeroize in the struct itself
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_kem() {
        let kyber = Kyber::new();

        // Generate keypair
        let (pk, sk) = kyber.generate_keypair().unwrap();

        // Encapsulate
        let (ct, ss_a) = kyber.encapsulate(&pk).unwrap();

        // Decapsulate
        let ss_b = kyber.decapsulate(&sk, &ct).unwrap();

        // Verify shared secrets match
        assert_eq!(ss_a, ss_b);
    }
}
