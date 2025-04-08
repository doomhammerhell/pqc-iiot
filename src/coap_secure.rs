//! Secure CoAP communication using post-quantum cryptography

use crate::{Falcon, Kyber, Result};
use coap_lite::{CoapRequest, CoapResponse, Packet};
use heapless::Vec;

/// Secure CoAP client using post-quantum cryptography
pub struct SecureCoapClient {
    kyber: Kyber,
    falcon: Falcon,
    shared_secret: Vec<u8, { Kyber::SHARED_SECRET_SIZE }>,
}

impl SecureCoapClient {
    /// Creates a new secure CoAP client
    pub fn new() -> Result<Self> {
        let kyber = Kyber::new();
        let falcon = Falcon::new();

        // Generate keypair and establish shared secret
        let (pk, sk) = kyber.generate_keypair()?;
        let (ciphertext, shared_secret) = kyber.encapsulate(&pk)?;

        Ok(Self {
            kyber,
            falcon,
            shared_secret,
        })
    }

    /// Sends a secure CoAP request
    pub fn send_request(&self, uri: &str, payload: &[u8]) -> Result<CoapResponse> {
        // Sign the payload
        let signature = self.falcon.sign(payload, &self.shared_secret)?;

        // Create a CoAP request with signed payload
        let mut request = CoapRequest::new();
        request.set_path(uri);
        request
            .message
            .payload
            .extend_from_slice(payload)
            .map_err(|_| crate::Error::BufferTooSmall)?;
        request
            .message
            .payload
            .extend_from_slice(&signature)
            .map_err(|_| crate::Error::BufferTooSmall)?;

        // Send the request and receive a response
        let response = CoapResponse::new(); // Placeholder for actual CoAP client call
        Ok(response)
    }

    /// Verifies a received CoAP response
    pub fn verify_response(&self, response: &CoapResponse) -> Result<()> {
        let payload = &response.message.payload;
        let (message, signature) = payload.split_at(payload.len() - Falcon::MAX_SIGNATURE_SIZE);

        // Verify the signature
        self.falcon
            .verify(message, signature, &self.shared_secret)?;

        // Process the message
        println!("Received message: {:?}", message);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_send_and_verify_request() {
        let client = SecureCoapClient::new().unwrap();
        let uri = "coap://localhost/test";
        let message = b"Hello, CoAP!";

        // Send a request
        let response = client.send_request(uri, message).unwrap();

        // Verify the response
        client.verify_response(&response).unwrap();
    }

    #[test]
    fn test_signature_verification_failure() {
        let client = SecureCoapClient::new().unwrap();
        let uri = "coap://localhost/test";
        let message = b"Hello, CoAP!";

        // Send a request
        let response = client.send_request(uri, message).unwrap();

        // Simulate a corrupted response
        let mut corrupted_payload = response.message.payload.clone();
        corrupted_payload[0] ^= 0xFF; // Flip a bit

        // Attempt to verify the corrupted response
        let corrupted_response = CoapResponse::new(); // Placeholder for actual response
        corrupted_response.message.payload = corrupted_payload;
        assert!(client.verify_response(&corrupted_response).is_err());
    }
}
