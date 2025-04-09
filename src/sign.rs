//! Digital signatures using Falcon

use crate::{Error, Result};
use core::marker::PhantomData;
use heapless::Vec;
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
use zeroize::Zeroize;

/// Maximum size for Falcon public keys
pub const MAX_PUBLIC_KEY_SIZE: usize = 1793;
/// Maximum size for Falcon secret keys
pub const MAX_SECRET_KEY_SIZE: usize = 2305;
/// Maximum size for Falcon signatures
pub const MAX_SIGNATURE_SIZE: usize = 1280;

/// Falcon signature implementation
#[derive(Debug, Default)]
pub struct Falcon<const N: usize = MAX_PUBLIC_KEY_SIZE> {
    _marker: PhantomData<[u8; N]>,
    secret_key: Option<Vec<u8, MAX_SECRET_KEY_SIZE>>,
    public_key: Option<Vec<u8, MAX_PUBLIC_KEY_SIZE>>,
}

impl<const N: usize> Falcon<N> {
    /// Creates a new Falcon instance
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
            secret_key: None,
            public_key: None,
        }
    }

    /// Generates a new keypair
    pub fn generate_keypair(
        &mut self,
    ) -> Result<(Vec<u8, MAX_PUBLIC_KEY_SIZE>, Vec<u8, MAX_SECRET_KEY_SIZE>)> {
        let (pk, sk) = falcon1024::keypair();
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

    /// Signs a message using a secret key
    pub fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8, MAX_SIGNATURE_SIZE>> {
        let sk = falcon1024::SecretKey::from_bytes(secret_key).map_err(|_| Error::InvalidInput)?;
        let signature = falcon1024::detached_sign(message, &sk);
        let mut sig_bytes = Vec::new();

        sig_bytes
            .extend_from_slice(signature.as_bytes())
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(sig_bytes)
    }

    /// Verifies a signature using a public key
    pub fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        let pk = falcon1024::PublicKey::from_bytes(public_key).map_err(|_| Error::InvalidInput)?;
        let sig = falcon1024::DetachedSignature::from_bytes(signature)
            .map_err(|_| Error::InvalidInput)?;

        falcon1024::verify_detached_signature(&sig, message, &pk)
            .map_err(|_| Error::SignatureVerification)
    }
}

impl<const N: usize> Drop for Falcon<N> {
    fn drop(&mut self) {
        if let Some(secret_key) = &mut self.secret_key {
            secret_key.zeroize();
        }
        if let Some(public_key) = &mut self.public_key {
            public_key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon_signature() {
        let mut falcon: Falcon<MAX_PUBLIC_KEY_SIZE> = Falcon::new();
        let message = b"Hello, IIoT!";

        // Generate keypair
        let (pk, sk) = falcon.generate_keypair().unwrap();

        // Sign a message
        let signature = falcon.sign(message, &sk).unwrap();

        // Verify the signature
        assert!(falcon.verify(message, &signature, &pk).is_ok());

        // Verify with wrong message
        let wrong_message = b"Wrong message";
        assert!(falcon.verify(wrong_message, &signature, &pk).is_err());
    }
}
