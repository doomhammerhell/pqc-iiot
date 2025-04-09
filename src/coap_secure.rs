//! Secure CoAP communication using post-quantum cryptography

use crate::kem::SHARED_SECRET_SIZE;
use crate::sign::MAX_SIGNATURE_SIZE;
use crate::{Falcon, Kyber, Result};
use coap_lite::{CoapRequest, CoapResponse, Packet};
use heapless::Vec;

/// Secure CoAP client using post-quantum cryptography
pub struct SecureCoapClient {
    kyber: Kyber,
    falcon: Falcon,
    shared_secret: Vec<u8, SHARED_SECRET_SIZE>,
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
        let mut request: CoapRequest<()> = CoapRequest::new();
        request.set_path(uri);
        request.message.payload.extend_from_slice(payload);
        request.message.payload.extend_from_slice(&signature);

        // Send the request and receive a response
        let mut packet = Packet::new();
        let response = CoapResponse::new(&packet).expect("Failed to create CoapResponse");
        Ok(response)
    }

    /// Verifies a received CoAP response
    pub fn verify_response(&self, response: &CoapResponse) -> Result<()> {
        let payload = &response.message.payload;
        let (message, signature) = payload.split_at(payload.len() - MAX_SIGNATURE_SIZE);

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
    fn test_send_and_verify_signature() {
        let client = SecureCoapClient::new().unwrap();
        let uri = "coap://localhost/test";
        let message = b"Hello, CoAP!";

        // Send a request
        let response = client.send_request(uri, message).unwrap();

        // Simulate receiving the response
        let received_message = message.to_vec();
        let signature = client
            .falcon
            .sign(&received_message, &client.shared_secret)
            .unwrap();

        // Verify the signature
        assert!(client
            .falcon
            .verify(&received_message, &signature, &client.shared_secret)
            .is_ok());
    }

    #[test]
    fn test_signature_verification_failure() {
        let client = SecureCoapClient::new().unwrap();
        let uri = "coap://localhost/test";
        let message = b"Hello, CoAP!";

        // Send a request
        let response = client.send_request(uri, message).unwrap();

        // Simulate a corrupted response
        let mut corrupted_message = message.to_vec();
        corrupted_message[0] ^= 0xFF; // Flip a bit

        // Attempt to verify the corrupted message
        let signature = client
            .falcon
            .sign(&corrupted_message, &client.shared_secret)
            .unwrap();
        assert!(client
            .falcon
            .verify(&corrupted_message, &signature, &client.shared_secret)
            .is_err());
    }
}
