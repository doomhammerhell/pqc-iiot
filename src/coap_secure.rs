//! Secure CoAP support.
//!
//! This module provides two build modes:
//! - `coap-std`: A socket-based client built on `std::net::UdpSocket` and `coap-lite`.
//! - `coap` (without `coap-std`): A no-std compatible core that signs and verifies payloads,
//!   leaving transport and CoAP framing to the application.

#[cfg(feature = "coap-std")]
mod std_client {
    use crate::crypto::traits::PqcSignature;
    use crate::{Error, Falcon, Kyber, Result};
    use coap_lite::{CoapRequest, CoapResponse, Packet, RequestType};
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;

    /// DTLS Configuration for Secure CoAP.
    #[derive(Debug, Clone)]
    pub struct DtlsConfig {
        /// Identity (Client Certificate).
        pub identity: Vec<u8>,
        /// Private Key (for DTLS handshake).
        pub private_key: Vec<u8>,
        /// Trusted CA Root for server verification.
        pub root_ca: Vec<u8>,
    }

    /// Access Control List (ACL) Rules for CoAP Resources.
    #[derive(Debug, Clone)]
    pub struct AclRules {
        /// Allowed resource paths (perfect match).
        pub allowed_paths: Vec<String>,
        /// Allowed methods (GET, POST, PUT, DELETE).
        pub allowed_methods: Vec<String>,
    }

    /// Secure CoAP client using post-quantum cryptography.
    ///
    /// This implementation requires `std` networking and is intentionally kept simple:
    /// it signs payloads end-to-end and appends `[signature][sig_len_be_u16]` to the payload.
    #[allow(dead_code)]
    pub struct SecureCoapClient {
        kyber: Kyber,
        falcon: Falcon,

        // Falcon512 identity keys used for request signing and response verification.
        sig_sk: Vec<u8>,
        sig_pk: Vec<u8>,

        // Configuration
        timeout: Duration,
        retransmission_count: u32,
        block_size: u16,
        multicast: bool,
        dtls_config: Option<DtlsConfig>,
        acl_rules: Option<AclRules>,

        // Socket (reused to avoid ephemeral port exhaustion).
        socket: Option<UdpSocket>,
    }

    impl SecureCoapClient {
        /// Creates a new secure CoAP client.
        pub fn new() -> Result<Self> {
            let kyber = Kyber::new();
            let falcon = Falcon::new();

            // Generate Falcon keys for signing.
            let (pk, sk) = falcon.generate_keypair()?;

            Ok(Self {
                kyber,
                falcon,
                sig_sk: sk,
                sig_pk: pk,
                timeout: Duration::from_secs(2),
                retransmission_count: 4,
                block_size: 1024,
                multicast: false,
                dtls_config: None,
                acl_rules: None,
                socket: None,
            })
        }

        /// Set timeout.
        pub fn with_timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }

        /// Set retransmission count.
        pub fn with_retransmission_count(mut self, count: u32) -> Self {
            self.retransmission_count = count;
            self
        }

        /// Set block size.
        pub fn with_block_size(mut self, size: u16) -> Self {
            self.block_size = size;
            self
        }

        /// Set multicast.
        pub fn with_multicast(mut self, multicast: bool) -> Self {
            self.multicast = multicast;
            self
        }

        /// Set DTLS config.
        pub fn with_dtls_config(mut self, config: DtlsConfig) -> Self {
            self.dtls_config = Some(config);
            self
        }

        /// Set ACL rules.
        pub fn with_acl(mut self, rules: AclRules) -> Self {
            self.acl_rules = Some(rules);
            self
        }

        fn ensure_socket(&mut self) -> Result<&UdpSocket> {
            if self.socket.is_none() {
                let socket =
                    UdpSocket::bind("0.0.0.0:0").map_err(|e| Error::ClientError(e.to_string()))?;
                socket.set_read_timeout(Some(self.timeout)).ok();
                self.socket = Some(socket);
            }
            Ok(self.socket.as_ref().expect("socket just initialized"))
        }

        fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>> {
            let signature = self.falcon.sign(&self.sig_sk, payload)?;
            if signature.len() > u16::MAX as usize {
                return Err(Error::InvalidInput("Signature too large".into()));
            }
            let sig_len = signature.len() as u16;

            let mut out = Vec::with_capacity(payload.len() + signature.len() + 2);
            out.extend_from_slice(payload);
            out.extend_from_slice(&signature);
            out.extend_from_slice(&sig_len.to_be_bytes());
            Ok(out)
        }

        /// Internal method to send request.
        fn send_secure_request(
            &mut self,
            method: RequestType,
            server: SocketAddr,
            path: &str,
            payload: &[u8],
        ) -> Result<CoapResponse> {
            let signed_payload = self.sign_payload(payload)?;

            let mut request: CoapRequest<()> = CoapRequest::new();
            request.set_method(method);
            request.set_path(path);
            request.message.payload = signed_payload;

            let packet_bytes = request
                .message
                .to_bytes()
                .map_err(|_| Error::ClientError("Packet serialization failed".into()))?;

            let socket = self.ensure_socket()?;
            socket
                .send_to(&packet_bytes, server)
                .map_err(|e| Error::ClientError(e.to_string()))?;

            let mut buf = [0u8; 2048];
            let (amt, _src) = socket
                .recv_from(&mut buf)
                .map_err(|e| Error::ClientError(e.to_string()))?;

            let packet = Packet::from_bytes(&buf[..amt])
                .map_err(|_| Error::ClientError("Invalid packet".into()))?;
            Ok(CoapResponse { message: packet })
        }

        /// Sends a GET request.
        pub fn get(&mut self, server: SocketAddr, resource: &str) -> Result<CoapResponse> {
            self.send_secure_request(RequestType::Get, server, resource, &[])
        }

        /// Sends a POST request.
        pub fn post(
            &mut self,
            server: SocketAddr,
            resource: &str,
            payload: &[u8],
        ) -> Result<CoapResponse> {
            self.send_secure_request(RequestType::Post, server, resource, payload)
        }

        /// Sends a PUT request.
        pub fn put(
            &mut self,
            server: SocketAddr,
            resource: &str,
            payload: &[u8],
        ) -> Result<CoapResponse> {
            self.send_secure_request(RequestType::Put, server, resource, payload)
        }

        /// Sends a DELETE request.
        pub fn delete(&mut self, server: SocketAddr, resource: &str) -> Result<CoapResponse> {
            self.send_secure_request(RequestType::Delete, server, resource, &[])
        }

        /// Compatibility shim: request sending requires a concrete `SocketAddr` in this client.
        pub fn send_request(&mut self, _uri: &str, _payload: &[u8]) -> Result<CoapResponse> {
            Err(Error::ProtocolError(
                "Deprecated: use get/post with explicit SocketAddr".into(),
            ))
        }

        /// Verifies a received CoAP response and returns the unsigned message payload.
        pub fn verify_response(&self, response: &CoapResponse) -> Result<Vec<u8>> {
            verify_signed_payload(&self.falcon, &self.sig_pk, &response.message.payload)
        }
    }

    fn verify_signed_payload(falcon: &Falcon, pk: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
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

        if !falcon.verify(pk, message, signature)? {
            return Err(Error::SignatureVerification("Verification failed".into()));
        }
        Ok(message.to_vec())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::thread;

        #[test]
        fn test_send_and_verify_request() {
            let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let server_addr = server_socket.local_addr().unwrap();

            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                if let Ok((amt, src)) = server_socket.recv_from(&mut buf) {
                    server_socket.send_to(&buf[..amt], src).unwrap();
                }
            });

            let mut client = SecureCoapClient::new().unwrap();
            let message = b"Hello, CoAP!";

            let response = client.post(server_addr, "test", message).unwrap();
            client.verify_response(&response).unwrap();
        }

        #[test]
        fn test_signature_verification_failure() {
            let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let server_addr = server_socket.local_addr().unwrap();

            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                if let Ok((amt, src)) = server_socket.recv_from(&mut buf) {
                    if amt > 0 {
                        buf[amt - 1] ^= 0xFF;
                    }
                    server_socket.send_to(&buf[..amt], src).unwrap();
                }
            });

            let mut client = SecureCoapClient::new().unwrap();
            let message = b"Hello, CoAP!";
            let response = client.post(server_addr, "test", message).unwrap();

            assert!(client.verify_response(&response).is_err());
        }
    }
}

#[cfg(feature = "coap-std")]
pub use std_client::{AclRules, DtlsConfig, SecureCoapClient};

#[cfg(not(feature = "coap-std"))]
mod nostd_core {
    use crate::crypto::traits::PqcSignature;
    use crate::{Error, Falcon, Result};
    use alloc::vec::Vec;

    /// Transport-agnostic secure CoAP core for `no_std` builds.
    ///
    /// The payload format matches the `coap-std` client:
    /// `[message][signature][sig_len_be_u16]`.
    pub struct SecureCoapClient {
        falcon: Falcon,
        sig_pk: Vec<u8>,
    }

    impl SecureCoapClient {
        /// Creates a new secure CoAP core.
        ///
        /// Note: this core only verifies signed payloads. Key distribution and transport
        /// are the responsibility of the application.
        pub fn new(falcon: Falcon, sig_pk: Vec<u8>) -> Self {
            Self { falcon, sig_pk }
        }

        /// Verify a signed payload and return the unsigned message.
        pub fn verify_signed_payload(&self, payload: &[u8]) -> Result<Vec<u8>> {
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

            if !self.falcon.verify(&self.sig_pk, message, signature)? {
                return Err(Error::SignatureVerification("Verification failed".into()));
            }
            Ok(message.to_vec())
        }
    }
}

#[cfg(not(feature = "coap-std"))]
pub use nostd_core::SecureCoapClient;
