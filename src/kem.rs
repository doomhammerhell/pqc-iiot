//! Key Encapsulation Mechanism (KEM) using CRYSTALS-Kyber

use crate::{Error, Result};
use core::marker::PhantomData;
use heapless::Vec;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
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
    secret_key: Option<Vec<u8, MAX_SECRET_KEY_SIZE>>,
    public_key: Option<Vec<u8, MAX_PUBLIC_KEY_SIZE>>,
    shared_secret: Option<Vec<u8, SHARED_SECRET_SIZE>>,
}

impl<const N: usize> Kyber<N> {
    /// Creates a new Kyber instance
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
            secret_key: None,
            public_key: None,
            shared_secret: None,
        }
    }

    /// Generates a new keypair
    pub fn generate_keypair(
        &mut self,
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

        self.public_key = Some(public_key.clone());
        self.secret_key = Some(secret_key.clone());

        Ok((public_key, secret_key))
    }

    /// Encapsulates a shared secret using a public key
    pub fn encapsulate(
        &mut self,
        public_key: &[u8],
    ) -> Result<(Vec<u8, MAX_CIPHERTEXT_SIZE>, Vec<u8, SHARED_SECRET_SIZE>)> {
        let pk = kyber768::PublicKey::from_bytes(public_key).map_err(|_| Error::InvalidInput)?;
        let (ct, ss) = kyber768::encapsulate(&pk);
        let mut ciphertext = Vec::new();
        let mut shared_secret = Vec::new();

        ciphertext
            .extend_from_slice(ct.as_bytes())
            .map_err(|_| Error::BufferTooSmall)?;
        shared_secret
            .extend_from_slice(ss.as_bytes())
            .map_err(|_| Error::BufferTooSmall)?;

        self.shared_secret = Some(shared_secret.clone());

        Ok((ciphertext, shared_secret))
    }

    /// Decapsulates a shared secret using a secret key and ciphertext
    pub fn decapsulate(
        &mut self,
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

        self.shared_secret = Some(shared_secret.clone());

        Ok(shared_secret)
    }
}

impl<const N: usize> Drop for Kyber<N> {
    fn drop(&mut self) {
        if let Some(secret_key) = &mut self.secret_key {
            secret_key.zeroize();
        }
        if let Some(public_key) = &mut self.public_key {
            public_key.zeroize();
        }
        if let Some(shared_secret) = &mut self.shared_secret {
            shared_secret.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_key_generation() {
        let mut kyber: Kyber<MAX_PUBLIC_KEY_SIZE> = Kyber::new();
        let (pk, sk) = kyber.generate_keypair().unwrap();
        assert_eq!(pk.len(), MAX_PUBLIC_KEY_SIZE);
        assert_eq!(sk.len(), MAX_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_kyber_encapsulation_decapsulation() {
        let mut kyber: Kyber<MAX_PUBLIC_KEY_SIZE> = Kyber::new();
        let (pk, sk) = kyber.generate_keypair().unwrap();
        let (ct, ss_a) = kyber.encapsulate(&pk).unwrap();
        let ss_b = kyber.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }
}
