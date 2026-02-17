use crate::crypto::traits::{PqcKEM, PqcSignature};
use crate::kem::{MAX_PUBLIC_KEY_SIZE, SHARED_SECRET_SIZE};
// use crate::sign::MAX_SIGNATURE_SIZE;
use crate::{Error, Falcon, Kyber, Result};
use coap_lite::{CoapRequest, CoapResponse, Packet, RequestType};
use heapless::Vec;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Secure CoAP client using post-quantum cryptography
#[allow(dead_code)]
pub struct SecureCoapClient {
    kyber: Kyber,
    falcon: Falcon,

    shared_secret: Vec<u8, { SHARED_SECRET_SIZE }>,
    public_key: Vec<u8, { MAX_PUBLIC_KEY_SIZE }>,
    sig_sk: Vec<u8, 1281>, // Falcon512 SK
    sig_pk: Vec<u8, 897>,  // Falcon512 PK

    // Configuration
    timeout: Duration,
    retransmission_count: u32,
    block_size: u16,
    multicast: bool,
    dtls_config: Option<()>, // Placeholder for DTLS config
    acl_rules: Option<()>,   // Placeholder for ACL

    // Socket
    socket: Option<UdpSocket>,
}

impl SecureCoapClient {
    /// Creates a new secure CoAP client
    pub fn new() -> Result<Self> {
        let kyber = Kyber::new();
        let falcon = Falcon::new();

        // Generate keypair and establish shared secret
        let (pk_vec, _sk) = kyber.generate_keypair()?;
        let (_ciphertext, ss_vec) = kyber.encapsulate(&pk_vec)?;

        let mut shared_secret = Vec::<u8, { SHARED_SECRET_SIZE }>::new();
        shared_secret
            .extend_from_slice(&ss_vec)
            .map_err(|_| Error::BufferTooSmall)?;

        let mut public_key = Vec::<u8, { MAX_PUBLIC_KEY_SIZE }>::new();
        public_key
            .extend_from_slice(&pk_vec)
            .map_err(|_| Error::BufferTooSmall)?;

        // Generate Falcon keys for signing
        let (f_pk, f_sk) = falcon.generate_keypair()?;
        let mut sig_sk = Vec::<u8, 1281>::new();
        sig_sk
            .extend_from_slice(&f_sk)
            .map_err(|_| Error::BufferTooSmall)?;
        let mut sig_pk = Vec::<u8, 897>::new();
        sig_pk
            .extend_from_slice(&f_pk)
            .map_err(|_| Error::BufferTooSmall)?;

        Ok(Self {
            kyber,
            falcon,
            shared_secret,
            public_key,
            sig_sk,
            sig_pk,
            timeout: Duration::from_secs(2),
            retransmission_count: 4,
            block_size: 1024,
            multicast: false,
            dtls_config: None,
            acl_rules: None,
            socket: None,
        })
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set retransmission count
    pub fn with_retransmission_count(mut self, count: u32) -> Self {
        self.retransmission_count = count;
        self
    }

    /// Set block size
    pub fn with_block_size(mut self, size: u16) -> Self {
        self.block_size = size;
        self
    }

    /// Set multicast
    pub fn with_multicast(mut self, multicast: bool) -> Self {
        self.multicast = multicast;
        self
    }

    /// Set DTLS config (placeholder)
    pub fn with_dtls_config(mut self, _config: ()) -> Self {
        self.dtls_config = Some(());
        self
    }

    /// Set ACL rules (placeholder)
    pub fn with_acl(mut self, _rules: ()) -> Self {
        self.acl_rules = Some(());
        self
    }

    /// Internal method to send request
    fn send_secure_request(
        &self,
        method: RequestType,
        server: SocketAddr,
        path: &str,
        payload: &[u8],
    ) -> Result<CoapResponse> {
        // Create socket if not exists (lazy init not easy with immutable self, so create per request or require init)
        // Since &self is immutable, we create a new socket for each request if we don't store it.
        // Or we use interior mutability (RefCell) or require &mut self.
        // `get` methods usually take `&self`.
        // I'll create a new socket bound to ephemeral port.

        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| Error::ClientError(e.to_string()))?;
        socket.set_read_timeout(Some(self.timeout)).ok();

        // Sign the payload
        let _signature = self.falcon.sign(&self.sig_sk, payload)?;
        let signature = self.falcon.sign(&self.sig_sk, payload)?;
        let sig_len = signature.len() as u16;

        // Create a CoAP request with signed payload
        let mut request: CoapRequest<()> = CoapRequest::new();
        request.set_method(method);
        request.set_path(path);
        request.message.payload.extend_from_slice(payload);
        request.message.payload.extend_from_slice(&signature);
        request
            .message
            .payload
            .extend_from_slice(&sig_len.to_be_bytes());

        // Serialize packet
        let packet_bytes = request
            .message
            .to_bytes()
            .map_err(|_| Error::ClientError("Packet serialization failed".into()))?;

        // Send to server
        socket
            .send_to(&packet_bytes, server)
            .map_err(|e| Error::ClientError(e.to_string()))?;

        // Receive response
        let mut buf = [0u8; 2048]; // Max packet size?
        let (amt, _src) = socket
            .recv_from(&mut buf)
            .map_err(|e| Error::ClientError(e.to_string()))?;

        let packet = Packet::from_bytes(&buf[..amt])
            .map_err(|_| Error::ClientError("Invalid packet".into()))?;
        // Direct construction to avoid strict validation in new()
        let response = CoapResponse { message: packet };
        Ok(response)
    }

    /// Sends a GET request
    pub fn get(&self, server: SocketAddr, resource: &str) -> Result<CoapResponse> {
        self.send_secure_request(RequestType::Get, server, resource, &[])
    }

    /// Sends a POST request
    pub fn post(&self, server: SocketAddr, resource: &str, payload: &[u8]) -> Result<CoapResponse> {
        self.send_secure_request(RequestType::Post, server, resource, payload)
    }

    /// Sends a PUT request
    pub fn put(&self, server: SocketAddr, resource: &str, payload: &[u8]) -> Result<CoapResponse> {
        self.send_secure_request(RequestType::Put, server, resource, payload)
    }

    /// Sends a DELETE request
    pub fn delete(&self, server: SocketAddr, resource: &str) -> Result<CoapResponse> {
        self.send_secure_request(RequestType::Delete, server, resource, &[])
    }

    /// Sends a secure CoAP request (legacy method, updated to use internal)
    /// This signature assumes implicit server? Or maybe this method was just a demo?
    /// The original signature was `uri: &str, payload: &[u8]`.
    /// URI usually contains scheme://host:port/path.
    /// I should parse it if possible, but parsing URI in no_std/minimal deps is hard.
    /// I'll deprecate or change this to take SocketAddr.
    /// I'll assume uri implies path and use a default server? No that's bad.
    /// I'll remove this method or update tests to use `get`/`post`.
    /// But I must keep it if I want to minimize breakage.
    /// I'll change it to use input uri as path, and REQUIRE a server addr?
    /// But signature is `(uri, payload)`.
    /// I'll leave it as a wrapper that errors out "Use get/post instead".
    /// Or interpret `uri` as full URI and try to parse.
    /// For now, I'll remove it and update tests to use `get/post`.
    /// Wait, I should implement `send_request` that matches old signature if possible.
    /// Old sig: `send_request(&self, uri: &str, payload: &[u8])`.
    /// If I can't resolve host, I can't send.
    /// Verifies a received CoAP response
    pub fn verify_response(&self, response: &CoapResponse) -> Result<std::vec::Vec<u8>> {
        let payload = &response.message.payload;
        // Read signature length (last 2 bytes)
        const LEN_SIZE: usize = 2;
        if payload.len() < LEN_SIZE {
            return Err(Error::SignatureVerification("Payload too short".into()));
        }
        let (rest, len_bytes) = payload.split_at(payload.len() - LEN_SIZE);
        let sig_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;

        if rest.len() < sig_len {
            return Err(Error::SignatureVerification("Signature too short".into()));
        }
        let (message, signature) = rest.split_at(rest.len() - sig_len);

        // Verify the signature
        // Verify the signature
        if !self.falcon.verify(&self.sig_pk, message, signature)? {
            return Err(Error::SignatureVerification("Verification failed".into()));
        }

        // Process the message
        // println!("Received message: {:?}", message);
        Ok(message.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_send_and_verify_request() {
        // Start a dummy echo server
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((amt, src)) = server_socket.recv_from(&mut buf) {
                // Echo back
                server_socket.send_to(&buf[..amt], src).unwrap();
            }
        });

        let client = SecureCoapClient::new().unwrap();
        let message = b"Hello, CoAP!";

        // Send a request
        // Using POST so we can actually verify payload round trip with signature
        let response = client.post(server_addr, "test", message).unwrap();

        // Verify the response
        client.verify_response(&response).unwrap();
    }

    #[test]
    fn test_signature_verification_failure() {
        // Start a dummy server that corrupts data
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((amt, src)) = server_socket.recv_from(&mut buf) {
                // Corrupt data (last byte is part of signature)
                if amt > 0 {
                    buf[amt - 1] ^= 0xFF;
                }
                server_socket.send_to(&buf[..amt], src).unwrap();
            }
        });

        let client = SecureCoapClient::new().unwrap();
        let message = b"Hello, CoAP!";

        // Send a request
        let response = client.post(server_addr, "test", message).unwrap();

        // Verify the response should fail
        assert!(client.verify_response(&response).is_err());
    }
}
