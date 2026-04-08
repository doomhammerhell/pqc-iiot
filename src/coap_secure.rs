//! Secure CoAP support.
//!
//! This module provides two build modes:
//! - `coap-std`: A socket-based client built on `std::net::UdpSocket` and `coap-lite`.
//! - `coap` (without `coap-std`): A no-std compatible core that signs and verifies payloads,
//!   leaving transport and CoAP framing to the application.

#[cfg(feature = "coap-std")]
mod std_client {
    use crate::crypto::traits::{PqcKEM, PqcSignature};
    use crate::{Error, Falcon, Kyber, KyberSecurityLevel, Result};
    use coap_lite::block_handler::{BlockHandler, BlockHandlerConfig, BlockValue};
    use coap_lite::{CoapOption, CoapRequest, CoapResponse, Packet, RequestType, ResponseType};
    use hkdf::Hkdf;
    use rand_core::{OsRng, RngCore};
    use sha2::Sha256;
    use std::collections::HashMap;
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
    use zeroize::{Zeroize, Zeroizing};

    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };

    const COAP_SESSION_INIT_PATH: &str = "pqc/session/init";
    const COAP_SESSION_VERSION_V1: u8 = 1;
    const COAP_MAX_SESSION_CONTROL_BYTES: usize = 64 * 1024;
    const COAP_MAX_SECURE_PAYLOAD_BYTES: usize = 256 * 1024;
    const COAP_SECURE_MSG_MAGIC_V2: &[u8] = b"PQCCP2";

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
    ///
    /// Security note:
    /// - This provides **authenticity** of application payloads when the peer's public key is pinned.
    /// - It does **not** provide transport confidentiality or replay protection. For critical IIoT use,
    ///   deploy OSCORE/DTLS (or an equivalent authenticated secure transport) underneath.
    #[allow(dead_code)]
    pub struct SecureCoapClient {
        kyber: Kyber,
        falcon: Falcon,

        // Falcon512 identity keys used for request signing and response verification.
        sig_sk: Vec<u8>,
        sig_pk: Vec<u8>,
        /// Pinned peer identity key used to verify responses.
        peer_sig_pk: Option<Vec<u8>>,

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
                peer_sig_pk: None,
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

        /// Pin the peer (server) Falcon public key used to verify responses.
        pub fn with_peer_sig_pk(mut self, peer_sig_pk: Vec<u8>) -> Self {
            self.peer_sig_pk = Some(peer_sig_pk);
            self
        }

        fn ensure_socket(&mut self) -> Result<UdpSocket> {
            if self.socket.is_none() {
                let socket =
                    UdpSocket::bind("0.0.0.0:0").map_err(|e| Error::ClientError(e.to_string()))?;
                socket
                    .set_read_timeout(Some(self.timeout))
                    .map_err(|e| Error::ClientError(e.to_string()))?;
                self.socket = Some(socket);
            }
            self.socket
                .as_ref()
                .ok_or_else(|| Error::ClientError("Socket missing".into()))?
                .try_clone()
                .map_err(|e| Error::ClientError(e.to_string()))
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
            let pk = self.peer_sig_pk.as_deref().ok_or_else(|| {
                Error::InvalidInput(
                    "Missing peer identity key: call SecureCoapClient::with_peer_sig_pk()"
                        .to_string(),
                )
            })?;
            verify_signed_payload(&self.falcon, pk, &response.message.payload)
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

    const COAP_SESSION_MAX_SKIPPED_KEYS: usize = 50;
    const COAP_SESSION_MAX_MESSAGES: u32 = 100_000;

    #[derive(Debug)]
    struct CoapSession {
        session_id: [u8; 16],
        send_chain_key: [u8; 32],
        recv_chain_key: [u8; 32],
        send_msg_num: u32,
        recv_msg_num: u32,
        skipped_message_keys: HashMap<u32, [u8; 32]>,
    }

    #[derive(Clone, Copy)]
    struct CoapMsgBinding<'a> {
        sender_id: &'a str,
        receiver_id: &'a str,
        code: u8,
        path: &'a str,
        token: &'a [u8],
    }

    impl CoapMsgBinding<'_> {
        fn aad_v2(&self, session_id: &[u8; 16], msg_num: u32) -> Vec<u8> {
            let mut aad = Vec::new();
            aad.extend_from_slice(b"pqc-iiot:coap-msg:v2");
            aad.extend_from_slice(&(self.sender_id.len() as u16).to_be_bytes());
            aad.extend_from_slice(self.sender_id.as_bytes());
            aad.extend_from_slice(&(self.receiver_id.len() as u16).to_be_bytes());
            aad.extend_from_slice(self.receiver_id.as_bytes());
            aad.push(self.code);
            aad.extend_from_slice(&(self.path.len() as u16).to_be_bytes());
            aad.extend_from_slice(self.path.as_bytes());
            aad.push(self.token.len() as u8);
            aad.extend_from_slice(self.token);
            aad.extend_from_slice(session_id);
            aad.extend_from_slice(&msg_num.to_be_bytes());
            aad
        }
    }

    impl CoapSession {
        fn new(session_id: [u8; 16], send_chain_key: [u8; 32], recv_chain_key: [u8; 32]) -> Self {
            Self {
                session_id,
                send_chain_key,
                recv_chain_key,
                send_msg_num: 0,
                recv_msg_num: 0,
                skipped_message_keys: HashMap::new(),
            }
        }

        fn kdf_ck(ck: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
            let hkdf = Hkdf::<Sha256>::from_prk(ck)
                .map_err(|_| Error::CryptoError("HKDF PRK init failed".into()))?;
            let mut mk = [0u8; 32];
            let mut next_ck = [0u8; 32];
            hkdf.expand(b"pqc-iiot:coap-session:v1:mk", &mut mk)
                .map_err(|_| Error::CryptoError("HKDF expand failed (mk)".into()))?;
            hkdf.expand(b"pqc-iiot:coap-session:v1:ck", &mut next_ck)
                .map_err(|_| Error::CryptoError("HKDF expand failed (ck)".into()))?;
            Ok((next_ck, mk))
        }

        fn nonce_v2(session_id: &[u8; 16], msg_num: u32) -> [u8; 12] {
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&session_id[..8]);
            nonce[8..].copy_from_slice(&msg_num.to_be_bytes());
            nonce
        }

        fn encrypt_v2(
            &mut self,
            binding: &CoapMsgBinding<'_>,
            plaintext: &[u8],
        ) -> Result<(u32, Vec<u8>)> {
            if self.send_msg_num >= COAP_SESSION_MAX_MESSAGES {
                return Err(Error::ProtocolError(format!(
                    "CoAP session {} exhausted message budget (send)",
                    hex::encode(self.session_id)
                )));
            }

            let (next_ck, mk) = Self::kdf_ck(&self.send_chain_key)?;
            self.send_chain_key = next_ck;
            let msg_num = self.send_msg_num;
            self.send_msg_num = self.send_msg_num.saturating_add(1);

            let aad = binding.aad_v2(&self.session_id, msg_num);
            let nonce_bytes = Self::nonce_v2(&self.session_id, msg_num);

            let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&mk));
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::CryptoError("AES-GCM encryption failed".into()))?;

            Ok((msg_num, ciphertext))
        }

        fn decrypt_with_mk_v2(
            &self,
            binding: &CoapMsgBinding<'_>,
            msg_num: u32,
            mk: &[u8; 32],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>> {
            let aad = binding.aad_v2(&self.session_id, msg_num);
            let nonce_bytes = Self::nonce_v2(&self.session_id, msg_num);
            let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(mk));
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::CryptoError("AES-GCM decryption failed".into()))
        }

        fn decrypt_v2(
            &mut self,
            binding: &CoapMsgBinding<'_>,
            msg_num: u32,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>> {
            if let Some(mk) = self.skipped_message_keys.remove(&msg_num) {
                return self.decrypt_with_mk_v2(binding, msg_num, &mk, ciphertext);
            }

            if msg_num < self.recv_msg_num {
                return Err(Error::CryptoError("Message too old / replay".into()));
            }

            let delta = msg_num - self.recv_msg_num;
            if delta > COAP_SESSION_MAX_SKIPPED_KEYS as u32 {
                return Err(Error::CryptoError(
                    "Message too far in the future (skip limit exceeded)".into(),
                ));
            }

            while self.recv_msg_num < msg_num {
                let (next_ck, mk) = Self::kdf_ck(&self.recv_chain_key)?;
                self.skipped_message_keys.insert(self.recv_msg_num, mk);
                self.recv_chain_key = next_ck;
                self.recv_msg_num = self.recv_msg_num.saturating_add(1);
            }

            let (next_ck, mk) = Self::kdf_ck(&self.recv_chain_key)?;
            self.recv_chain_key = next_ck;
            self.recv_msg_num = self.recv_msg_num.saturating_add(1);

            self.decrypt_with_mk_v2(binding, msg_num, &mk, ciphertext)
        }
    }

    impl Drop for CoapSession {
        fn drop(&mut self) {
            self.send_chain_key.zeroize();
            self.recv_chain_key.zeroize();
            for (_, key) in self.skipped_message_keys.iter_mut() {
                key.zeroize();
            }
            self.skipped_message_keys.clear();
        }
    }

    struct PendingCoapSessionInit {
        kem_sk: Zeroizing<Vec<u8>>,
        x25519_sk: X25519StaticSecret,
    }

    impl Drop for PendingCoapSessionInit {
        fn drop(&mut self) {
            self.kem_sk.zeroize();
            self.x25519_sk.zeroize();
        }
    }

    #[derive(Debug, Clone)]
    struct CachedCoapSessionResponse {
        session_seq: u64,
        session_id: [u8; 16],
        bytes: Vec<u8>,
    }

    fn vec_to_16(bytes: &[u8]) -> Result<[u8; 16]> {
        if bytes.len() != 16 {
            return Err(Error::InvalidInput(format!(
                "Invalid 16-byte field length: {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn vec_to_32(bytes: &[u8]) -> Result<[u8; 32]> {
        if bytes.len() != 32 {
            return Err(Error::InvalidInput(format!(
                "Invalid 32-byte field length: {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn kyber_for_pk_len(len: usize) -> Result<Kyber> {
        match len {
            800 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber512)),
            1184 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber768)),
            1568 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber1024)),
            _ => Err(Error::InvalidInput(format!(
                "Invalid Kyber public key length: {}",
                len
            ))),
        }
    }

    fn kyber_for_sk_len(len: usize) -> Result<Kyber> {
        match len {
            1632 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber512)),
            2400 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber768)),
            3168 => Ok(Kyber::new_with_level(KyberSecurityLevel::Kyber1024)),
            _ => Err(Error::InvalidInput(format!(
                "Invalid Kyber secret key length: {}",
                len
            ))),
        }
    }

    fn derive_session_chain_keys_v1(
        session_id: &[u8; 16],
        kem_ss: &[u8],
        dh_ss: &[u8],
    ) -> Result<([u8; 32], [u8; 32])> {
        if kem_ss.len() != 32 || dh_ss.len() != 32 {
            return Err(Error::CryptoError(format!(
                "Invalid session shared secret lengths: kem_ss={} dh_ss={}",
                kem_ss.len(),
                dh_ss.len()
            )));
        }
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(kem_ss);
        ikm[32..].copy_from_slice(dh_ss);

        let hk = Hkdf::<Sha256>::new(Some(session_id), &ikm);
        let mut ck_initiator = [0u8; 32];
        let mut ck_responder = [0u8; 32];
        hk.expand(b"pqc-iiot:coap-session:v1:ck-initiator", &mut ck_initiator)
            .map_err(|_| Error::CryptoError("HKDF expand failed (ck-initiator)".into()))?;
        hk.expand(b"pqc-iiot:coap-session:v1:ck-responder", &mut ck_responder)
            .map_err(|_| Error::CryptoError("HKDF expand failed (ck-responder)".into()))?;

        ikm.zeroize();

        Ok((ck_initiator, ck_responder))
    }

    struct CoapSessionInitSigInput<'a> {
        path: &'a str,
        session_id: &'a [u8; 16],
        session_seq: u64,
        initiator_id: &'a str,
        responder_id: &'a str,
        kem_pk: &'a [u8],
        x25519_pk: &'a [u8; 32],
        ts: u64,
    }

    fn session_init_payload_v1(input: &CoapSessionInitSigInput<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"pqc-iiot:coap-session:init:v1");
        buf.extend_from_slice(&(input.path.len() as u16).to_be_bytes());
        buf.extend_from_slice(input.path.as_bytes());
        buf.extend_from_slice(&(input.initiator_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(input.initiator_id.as_bytes());
        buf.extend_from_slice(&(input.responder_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(input.responder_id.as_bytes());
        buf.extend_from_slice(input.session_id);
        buf.extend_from_slice(&input.session_seq.to_be_bytes());
        buf.extend_from_slice(&input.ts.to_be_bytes());
        buf.extend_from_slice(&(input.kem_pk.len() as u32).to_be_bytes());
        buf.extend_from_slice(input.kem_pk);
        buf.extend_from_slice(input.x25519_pk);
        buf
    }

    struct CoapSessionRespSigInput<'a> {
        path: &'a str,
        session_id: &'a [u8; 16],
        session_seq: u64,
        initiator_id: &'a str,
        responder_id: &'a str,
        x25519_pk: &'a [u8; 32],
        kem_ciphertext: &'a [u8],
        ts: u64,
    }

    fn session_resp_payload_v1(input: &CoapSessionRespSigInput<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"pqc-iiot:coap-session:resp:v1");
        buf.extend_from_slice(&(input.path.len() as u16).to_be_bytes());
        buf.extend_from_slice(input.path.as_bytes());
        buf.extend_from_slice(&(input.initiator_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(input.initiator_id.as_bytes());
        buf.extend_from_slice(&(input.responder_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(input.responder_id.as_bytes());
        buf.extend_from_slice(input.session_id);
        buf.extend_from_slice(&input.session_seq.to_be_bytes());
        buf.extend_from_slice(&input.ts.to_be_bytes());
        buf.extend_from_slice(input.x25519_pk);
        buf.extend_from_slice(&(input.kem_ciphertext.len() as u32).to_be_bytes());
        buf.extend_from_slice(input.kem_ciphertext);
        buf
    }

    #[derive(Debug)]
    struct CoapSessionInit {
        initiator_id: String,
        responder_id: String,
        session_id: [u8; 16],
        session_seq: u64,
        kem_pk: Vec<u8>,
        x25519_pk: [u8; 32],
        ts: u64,
        signature: Vec<u8>,
    }

    #[derive(Debug)]
    struct CoapSessionResponse {
        initiator_id: String,
        responder_id: String,
        session_id: [u8; 16],
        session_seq: u64,
        x25519_pk: [u8; 32],
        kem_ciphertext: Vec<u8>,
        ts: u64,
        signature: Vec<u8>,
    }

    fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
        if input.len() < n {
            return Err(Error::ProtocolError("Truncated message".into()));
        }
        let (head, rest) = input.split_at(n);
        *input = rest;
        Ok(head)
    }

    fn read_u8(input: &mut &[u8]) -> Result<u8> {
        Ok(take(input, 1)?[0])
    }

    fn read_u16(input: &mut &[u8]) -> Result<u16> {
        let b = take(input, 2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn read_u32(input: &mut &[u8]) -> Result<u32> {
        let b = take(input, 4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(input: &mut &[u8]) -> Result<u64> {
        let b = take(input, 8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_vec_u32(input: &mut &[u8], max_len: usize) -> Result<Vec<u8>> {
        let len = read_u32(input)? as usize;
        if len > max_len {
            return Err(Error::InvalidInput(format!(
                "Field too large: {} > {}",
                len, max_len
            )));
        }
        Ok(take(input, len)?.to_vec())
    }

    fn read_string_u16(input: &mut &[u8], max_len: usize) -> Result<String> {
        let len = read_u16(input)? as usize;
        if len > max_len {
            return Err(Error::InvalidInput(format!(
                "String too large: {} > {}",
                len, max_len
            )));
        }
        let bytes = take(input, len)?;
        let s = core::str::from_utf8(bytes)
            .map_err(|_| Error::InvalidInput("Invalid UTF-8 string".into()))?;
        Ok(s.to_string())
    }

    fn encode_session_init_v1(msg: &CoapSessionInit) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(COAP_SESSION_VERSION_V1);
        out.extend_from_slice(&(msg.initiator_id.len() as u16).to_be_bytes());
        out.extend_from_slice(msg.initiator_id.as_bytes());
        out.extend_from_slice(&(msg.responder_id.len() as u16).to_be_bytes());
        out.extend_from_slice(msg.responder_id.as_bytes());
        out.extend_from_slice(&msg.session_id);
        out.extend_from_slice(&msg.session_seq.to_be_bytes());
        out.extend_from_slice(&msg.ts.to_be_bytes());
        out.extend_from_slice(&(msg.kem_pk.len() as u32).to_be_bytes());
        out.extend_from_slice(&msg.kem_pk);
        out.extend_from_slice(&msg.x25519_pk);
        out.extend_from_slice(&(msg.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&msg.signature);
        Ok(out)
    }

    fn decode_session_init_v1(bytes: &[u8]) -> Result<CoapSessionInit> {
        if bytes.len() > COAP_MAX_SESSION_CONTROL_BYTES {
            return Err(Error::InvalidInput("Session init too large".into()));
        }
        let mut input = bytes;
        let version = read_u8(&mut input)?;
        if version != COAP_SESSION_VERSION_V1 {
            return Err(Error::ProtocolError(format!(
                "Unsupported CoAP session init version: {}",
                version
            )));
        }
        let initiator_id = read_string_u16(&mut input, 128)?;
        let responder_id = read_string_u16(&mut input, 128)?;
        let session_id = vec_to_16(take(&mut input, 16)?)?;
        let session_seq = read_u64(&mut input)?;
        let ts = read_u64(&mut input)?;
        let kem_pk = read_vec_u32(&mut input, 4096)?;
        let x25519_pk = vec_to_32(take(&mut input, 32)?)?;
        let sig_len = read_u16(&mut input)? as usize;
        let signature = take(&mut input, sig_len)?.to_vec();
        if !input.is_empty() {
            return Err(Error::ProtocolError(
                "Trailing bytes in session init".into(),
            ));
        }
        Ok(CoapSessionInit {
            initiator_id,
            responder_id,
            session_id,
            session_seq,
            kem_pk,
            x25519_pk,
            ts,
            signature,
        })
    }

    fn encode_session_response_v1(msg: &CoapSessionResponse) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(COAP_SESSION_VERSION_V1);
        out.extend_from_slice(&(msg.initiator_id.len() as u16).to_be_bytes());
        out.extend_from_slice(msg.initiator_id.as_bytes());
        out.extend_from_slice(&(msg.responder_id.len() as u16).to_be_bytes());
        out.extend_from_slice(msg.responder_id.as_bytes());
        out.extend_from_slice(&msg.session_id);
        out.extend_from_slice(&msg.session_seq.to_be_bytes());
        out.extend_from_slice(&msg.ts.to_be_bytes());
        out.extend_from_slice(&msg.x25519_pk);
        out.extend_from_slice(&(msg.kem_ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&msg.kem_ciphertext);
        out.extend_from_slice(&(msg.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&msg.signature);
        Ok(out)
    }

    fn decode_session_response_v1(bytes: &[u8]) -> Result<CoapSessionResponse> {
        if bytes.len() > COAP_MAX_SESSION_CONTROL_BYTES {
            return Err(Error::InvalidInput("Session response too large".into()));
        }
        let mut input = bytes;
        let version = read_u8(&mut input)?;
        if version != COAP_SESSION_VERSION_V1 {
            return Err(Error::ProtocolError(format!(
                "Unsupported CoAP session response version: {}",
                version
            )));
        }
        let initiator_id = read_string_u16(&mut input, 128)?;
        let responder_id = read_string_u16(&mut input, 128)?;
        let session_id = vec_to_16(take(&mut input, 16)?)?;
        let session_seq = read_u64(&mut input)?;
        let ts = read_u64(&mut input)?;
        let x25519_pk = vec_to_32(take(&mut input, 32)?)?;
        let kem_ciphertext = read_vec_u32(&mut input, 8192)?;
        let sig_len = read_u16(&mut input)? as usize;
        let signature = take(&mut input, sig_len)?.to_vec();
        if !input.is_empty() {
            return Err(Error::ProtocolError(
                "Trailing bytes in session response".into(),
            ));
        }
        Ok(CoapSessionResponse {
            initiator_id,
            responder_id,
            session_id,
            session_seq,
            x25519_pk,
            kem_ciphertext,
            ts,
            signature,
        })
    }

    fn encode_secure_payload_v2(
        sender_id: &str,
        session_id: &[u8; 16],
        msg_num: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext.len() > u32::MAX as usize {
            return Err(Error::InvalidInput("Ciphertext too large".into()));
        }
        let sender_id_bytes = sender_id.as_bytes();
        if sender_id_bytes.len() > u16::MAX as usize {
            return Err(Error::InvalidInput("Sender id too long".into()));
        }
        let ct_len = ciphertext.len() as u32;
        let mut out = Vec::with_capacity(
            COAP_SECURE_MSG_MAGIC_V2.len()
                + 2
                + sender_id_bytes.len()
                + 1
                + 16
                + 4
                + 4
                + ciphertext.len(),
        );
        out.extend_from_slice(COAP_SECURE_MSG_MAGIC_V2);
        out.extend_from_slice(&(sender_id_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(sender_id_bytes);
        out.push(2);
        out.extend_from_slice(session_id);
        out.extend_from_slice(&msg_num.to_be_bytes());
        out.extend_from_slice(&ct_len.to_be_bytes());
        out.extend_from_slice(ciphertext);
        Ok(out)
    }

    #[derive(Debug, Clone)]
    struct CoapSecurePayloadV2 {
        sender_id: String,
        session_id: [u8; 16],
        msg_num: u32,
        ciphertext: Vec<u8>,
    }

    fn decode_secure_payload_v2(bytes: &[u8]) -> Result<CoapSecurePayloadV2> {
        if bytes.len() > COAP_MAX_SECURE_PAYLOAD_BYTES {
            return Err(Error::InvalidInput("Secure payload too large".into()));
        }
        if !bytes.starts_with(COAP_SECURE_MSG_MAGIC_V2) {
            return Err(Error::ProtocolError("Missing secure payload magic".into()));
        }
        let mut input = &bytes[COAP_SECURE_MSG_MAGIC_V2.len()..];
        let sender_len = read_u16(&mut input)? as usize;
        if sender_len == 0 || sender_len > 128 {
            return Err(Error::InvalidInput(format!(
                "Invalid sender id length: {}",
                sender_len
            )));
        }
        let sender_bytes = take(&mut input, sender_len)?;
        let sender_id = core::str::from_utf8(sender_bytes)
            .map_err(|_| Error::InvalidInput("Invalid sender_id UTF-8".into()))?
            .to_string();
        let version = read_u8(&mut input)?;
        if version != 2 {
            return Err(Error::ProtocolError(format!(
                "Unsupported secure payload version: {}",
                version
            )));
        }
        let session_id = vec_to_16(take(&mut input, 16)?)?;
        let msg_num = read_u32(&mut input)?;
        let ct_len = read_u32(&mut input)? as usize;
        let ciphertext = take(&mut input, ct_len)?.to_vec();
        if !input.is_empty() {
            return Err(Error::ProtocolError(
                "Trailing bytes in secure payload".into(),
            ));
        }
        Ok(CoapSecurePayloadV2 {
            sender_id,
            session_id,
            msg_num,
            ciphertext,
        })
    }

    /// Session-based Secure CoAP client (confidentiality + integrity + replay protection).
    ///
    /// This is *not* OSCORE/DTLS, but it provides equivalent primitives at the application layer:
    /// - Authenticated session handshake (Falcon signatures)
    /// - Forward secrecy from ephemeral X25519 + ephemeral Kyber KEM
    /// - AEAD payload encryption (AES-256-GCM) with per-message key evolution
    /// - Anti-replay / bounded out-of-order via a skipped-key window
    pub struct SecureCoapSessionClient {
        kyber: Kyber,
        falcon: Falcon,
        sig_sk: Zeroizing<Vec<u8>>,
        sig_pk: Vec<u8>,

        client_id: String,
        peer_id: String,
        peer_sig_pk: Vec<u8>,

        timeout: Duration,
        socket: Option<UdpSocket>,

        session_seq: u64,
        session: Option<CoapSession>,
    }

    impl SecureCoapSessionClient {
        /// Create a new session client.
        ///
        /// `peer_sig_pk` is the pinned Falcon public key for the remote peer identity.
        pub fn new(client_id: &str, peer_id: &str, peer_sig_pk: Vec<u8>) -> Result<Self> {
            let kyber = Kyber::new();
            let falcon = Falcon::new();
            let (sig_pk, sig_sk) = falcon.generate_keypair()?;
            Ok(Self {
                kyber,
                falcon,
                sig_sk: Zeroizing::new(sig_sk),
                sig_pk,
                client_id: client_id.to_string(),
                peer_id: peer_id.to_string(),
                peer_sig_pk,
                timeout: Duration::from_secs(2),
                socket: None,
                session_seq: 0,
                session: None,
            })
        }

        /// Return this client's Falcon identity public key.
        pub fn identity_sig_pk(&self) -> &[u8] {
            &self.sig_pk
        }

        /// Set the UDP read timeout used by CoAP exchanges (handshake + secure requests).
        pub fn with_timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }

        fn ensure_socket(&mut self) -> Result<UdpSocket> {
            if self.socket.is_none() {
                let socket =
                    UdpSocket::bind("0.0.0.0:0").map_err(|e| Error::ClientError(e.to_string()))?;
                socket
                    .set_read_timeout(Some(self.timeout))
                    .map_err(|e| Error::ClientError(e.to_string()))?;
                self.socket = Some(socket);
            }
            self.socket
                .as_ref()
                .ok_or_else(|| Error::ClientError("Socket missing".into()))?
                .try_clone()
                .map_err(|e| Error::ClientError(e.to_string()))
        }

        fn exchange_blockwise(
            &mut self,
            server: SocketAddr,
            method: RequestType,
            path: &str,
            token: Vec<u8>,
            payload: &[u8],
        ) -> Result<CoapResponse> {
            const BLOCK_SIZE: usize = 512;

            let socket = self.ensure_socket()?;

            let send_block = |block1: Option<BlockValue>,
                              block2: Option<BlockValue>,
                              chunk: &[u8]|
             -> Result<Packet> {
                let mut request: CoapRequest<()> = CoapRequest::new();
                request.set_method(method);
                request.set_path(path);
                request.message.header.message_id = (OsRng.next_u32() & 0xFFFF) as u16;
                request.message.set_token(token.clone());
                request.message.payload = chunk.to_vec();

                if let Some(b1) = block1 {
                    request.message.add_option_as(CoapOption::Block1, b1);
                }
                if let Some(b2) = block2 {
                    request.message.add_option_as(CoapOption::Block2, b2);
                }

                let bytes = request.message.to_bytes().map_err(|e| {
                    Error::ClientError(format!("Packet serialization failed: {}", e))
                })?;
                socket
                    .send_to(&bytes, server)
                    .map_err(|e| Error::ClientError(e.to_string()))?;

                let mut buf = vec![0u8; 65535];
                let (amt, _src) = socket
                    .recv_from(&mut buf)
                    .map_err(|e| Error::ClientError(e.to_string()))?;
                buf.truncate(amt);
                Packet::from_bytes(&buf).map_err(|_| Error::ClientError("Invalid packet".into()))
            };

            // Block1 upload if necessary.
            let mut response_packet = if payload.len() > BLOCK_SIZE {
                let mut num = 0usize;
                let mut offset = 0usize;
                loop {
                    let end = core::cmp::min(offset + BLOCK_SIZE, payload.len());
                    let more = end < payload.len();
                    let block1 = BlockValue::new(num, more, BLOCK_SIZE)
                        .map_err(|e| Error::ClientError(e.to_string()))?;
                    let resp = send_block(Some(block1), None, &payload[offset..end])?;
                    if more {
                        // Expect 2.31 Continue for intermediate blocks.
                        let code: u8 = resp.header.code.into();
                        let expected: u8 =
                            coap_lite::MessageClass::Response(ResponseType::Continue).into();
                        if code != expected {
                            // Some stacks may respond differently; fail closed.
                            return Err(Error::ProtocolError(format!(
                                "Unexpected block1 response code: {}",
                                code
                            )));
                        }
                    } else {
                        break resp;
                    }
                    offset = end;
                    num = num.saturating_add(1);
                }
            } else {
                // Single-shot request.
                send_block(None, None, payload)?
            };

            // Reassemble Block2 response if present.
            let mut assembled = Vec::new();
            let mut block2 = response_packet
                .get_first_option_as::<BlockValue>(CoapOption::Block2)
                .and_then(|x| x.ok());
            if let Some(mut b2) = block2.take() {
                loop {
                    let size = b2.size();
                    let offset = (b2.num as usize).saturating_mul(size);
                    if assembled.len() < offset {
                        assembled.resize(offset, 0);
                    }
                    if assembled.len() == offset {
                        assembled.extend_from_slice(&response_packet.payload);
                    } else if offset < assembled.len() {
                        let end = offset.saturating_add(response_packet.payload.len());
                        if assembled.len() < end {
                            assembled.resize(end, 0);
                        }
                        assembled[offset..end].copy_from_slice(&response_packet.payload);
                    }

                    if !b2.more {
                        response_packet.payload = assembled;
                        break;
                    }

                    let next = (b2.num as u32).saturating_add(1);
                    let next_b2 = BlockValue {
                        num: next as u16,
                        more: false,
                        size_exponent: b2.size_exponent,
                    };
                    response_packet = send_block(None, Some(next_b2), &[])?;
                    b2 = response_packet
                        .get_first_option_as::<BlockValue>(CoapOption::Block2)
                        .and_then(|x| x.ok())
                        .ok_or_else(|| {
                            Error::ProtocolError("Missing Block2 in follow-up response".into())
                        })?;
                }
            }

            Ok(CoapResponse {
                message: response_packet,
            })
        }

        /// Establish a secure session with `server` if not already connected.
        pub fn connect(&mut self, server: SocketAddr) -> Result<()> {
            if self.session.is_some() {
                return Ok(());
            }
            self.session_seq = self.session_seq.saturating_add(1).max(1);
            let session_seq = self.session_seq;

            let mut session_id = [0u8; 16];
            OsRng.fill_bytes(&mut session_id);

            let (kem_pk, kem_sk) = self.kyber.generate_keypair()?;
            let x25519_sk = X25519StaticSecret::random_from_rng(OsRng);
            let x25519_pk = X25519PublicKey::from(&x25519_sk).to_bytes();
            let ts = 0u64;

            let payload = session_init_payload_v1(&CoapSessionInitSigInput {
                path: COAP_SESSION_INIT_PATH,
                session_id: &session_id,
                session_seq,
                initiator_id: &self.client_id,
                responder_id: &self.peer_id,
                kem_pk: &kem_pk,
                x25519_pk: &x25519_pk,
                ts,
            });
            let signature = self.falcon.sign(&self.sig_sk, &payload)?;

            let init = CoapSessionInit {
                initiator_id: self.client_id.clone(),
                responder_id: self.peer_id.clone(),
                session_id,
                session_seq,
                kem_pk,
                x25519_pk,
                ts,
                signature,
            };

            let bytes = encode_session_init_v1(&init)?;
            let mut token = [0u8; 4];
            OsRng.fill_bytes(&mut token);
            let resp = self.exchange_blockwise(
                server,
                RequestType::Post,
                COAP_SESSION_INIT_PATH,
                token.to_vec(),
                &bytes,
            )?;
            let msg = decode_session_response_v1(&resp.message.payload)?;

            if msg.initiator_id != self.client_id || msg.responder_id != self.peer_id {
                return Err(Error::ProtocolError("Session response id mismatch".into()));
            }
            if msg.session_id != session_id {
                return Err(Error::ProtocolError(
                    "Session response session_id mismatch".into(),
                ));
            }
            if msg.session_seq != session_seq {
                return Err(Error::ProtocolError(
                    "Session response session_seq mismatch".into(),
                ));
            }

            let resp_payload = session_resp_payload_v1(&CoapSessionRespSigInput {
                path: COAP_SESSION_INIT_PATH,
                session_id: &session_id,
                session_seq,
                initiator_id: &self.client_id,
                responder_id: &self.peer_id,
                x25519_pk: &msg.x25519_pk,
                kem_ciphertext: &msg.kem_ciphertext,
                ts: msg.ts,
            });
            if !self
                .falcon
                .verify(&self.peer_sig_pk, &resp_payload, &msg.signature)?
            {
                return Err(Error::SignatureVerification(
                    "Session response signature invalid".into(),
                ));
            }

            let kyber = kyber_for_sk_len(kem_sk.len())?;
            let kem_ss = kyber.decapsulate(&kem_sk, &msg.kem_ciphertext)?;
            let dh_ss = x25519_sk
                .diffie_hellman(&X25519PublicKey::from(msg.x25519_pk))
                .to_bytes()
                .to_vec();

            let (ck_initiator, ck_responder) =
                derive_session_chain_keys_v1(&session_id, &kem_ss, &dh_ss)?;

            self.session = Some(CoapSession::new(session_id, ck_initiator, ck_responder));

            // Best-effort: wipe ephemeral secrets.
            drop(PendingCoapSessionInit {
                kem_sk: Zeroizing::new(kem_sk),
                x25519_sk,
            });

            Ok(())
        }

        fn encrypt_payload(
            session: &mut CoapSession,
            binding: &CoapMsgBinding<'_>,
            plaintext: &[u8],
        ) -> Result<Vec<u8>> {
            let (msg_num, ciphertext) = session.encrypt_v2(binding, plaintext)?;
            encode_secure_payload_v2(binding.sender_id, &session.session_id, msg_num, &ciphertext)
        }

        fn decrypt_payload(
            session: &mut CoapSession,
            expected_sender_id: &str,
            binding: &CoapMsgBinding<'_>,
            bytes: &[u8],
        ) -> Result<Vec<u8>> {
            let decoded = decode_secure_payload_v2(bytes)?;
            if decoded.sender_id != expected_sender_id {
                return Err(Error::ProtocolError("Unexpected sender_id".into()));
            }
            if decoded.session_id != session.session_id {
                return Err(Error::ProtocolError("Session id mismatch".into()));
            }
            session.decrypt_v2(binding, decoded.msg_num, &decoded.ciphertext)
        }

        fn send_secure_request(
            &mut self,
            method: RequestType,
            server: SocketAddr,
            path: &str,
            payload: &[u8],
        ) -> Result<CoapResponse> {
            self.connect(server)?;
            let socket = self.ensure_socket()?;
            let session = self.session.as_mut().ok_or_else(|| {
                Error::ClientError("Missing session after successful connect".into())
            })?;

            let mut request: CoapRequest<()> = CoapRequest::new();
            request.set_method(method);
            request.set_path(path);
            request.message.header.message_id = (OsRng.next_u32() & 0xFFFF) as u16;
            let mut token = [0u8; 4];
            OsRng.fill_bytes(&mut token);
            request.message.set_token(token.to_vec());

            let code: u8 = request.message.header.code.into();
            let token_bytes = request.message.get_token().to_vec();

            let binding = CoapMsgBinding {
                sender_id: &self.client_id,
                receiver_id: &self.peer_id,
                code,
                path,
                token: &token_bytes,
            };
            request.message.payload = Self::encrypt_payload(session, &binding, payload)?;

            let packet_bytes = request
                .message
                .to_bytes()
                .map_err(|_| Error::ClientError("Packet serialization failed".into()))?;

            socket
                .send_to(&packet_bytes, server)
                .map_err(|e| Error::ClientError(e.to_string()))?;

            let mut buf = vec![0u8; 65535];
            let (amt, _src) = socket
                .recv_from(&mut buf)
                .map_err(|e| Error::ClientError(e.to_string()))?;
            buf.truncate(amt);

            let packet = Packet::from_bytes(&buf)
                .map_err(|_| Error::ClientError("Invalid packet".into()))?;
            let mut response = CoapResponse { message: packet };

            let resp_code: u8 = response.message.header.code.into();
            let resp_token = response.message.get_token().to_vec();

            let resp_binding = CoapMsgBinding {
                sender_id: &self.peer_id,
                receiver_id: &self.client_id,
                code: resp_code,
                path,
                token: &resp_token,
            };
            let plaintext = Self::decrypt_payload(
                session,
                &self.peer_id,
                &resp_binding,
                &response.message.payload,
            )?;
            response.message.payload = plaintext;
            Ok(response)
        }

        /// Send an encrypted/authenticated CoAP `GET` request and return the decrypted response.
        pub fn get(&mut self, server: SocketAddr, resource: &str) -> Result<CoapResponse> {
            self.send_secure_request(RequestType::Get, server, resource, &[])
        }

        /// Send an encrypted/authenticated CoAP `POST` request and return the decrypted response.
        pub fn post(
            &mut self,
            server: SocketAddr,
            resource: &str,
            payload: &[u8],
        ) -> Result<CoapResponse> {
            self.send_secure_request(RequestType::Post, server, resource, payload)
        }
    }

    /// Minimal in-process Secure CoAP session server for tests and demos.
    pub struct SecureCoapSessionServer {
        server_id: String,
        block_handler: BlockHandler<SocketAddr>,
        falcon: Falcon,
        sig_sk: Zeroizing<Vec<u8>>,
        sig_pk: Vec<u8>,
        allowed_clients: HashMap<String, Vec<u8>>,
        last_session_seq: HashMap<String, u64>,
        session_resp_cache: HashMap<String, CachedCoapSessionResponse>,
        sessions: HashMap<String, CoapSession>,
    }

    impl SecureCoapSessionServer {
        /// Create a new in-process session server.
        pub fn new(server_id: &str) -> Result<Self> {
            let falcon = Falcon::new();
            let (sig_pk, sig_sk) = falcon.generate_keypair()?;
            Ok(Self {
                server_id: server_id.to_string(),
                block_handler: BlockHandler::new(BlockHandlerConfig::default()),
                falcon,
                sig_sk: Zeroizing::new(sig_sk),
                sig_pk,
                allowed_clients: HashMap::new(),
                last_session_seq: HashMap::new(),
                session_resp_cache: HashMap::new(),
                sessions: HashMap::new(),
            })
        }

        /// Return this server's Falcon identity public key.
        pub fn identity_sig_pk(&self) -> &[u8] {
            &self.sig_pk
        }

        /// Allow a client identity (pinned Falcon public key) to establish sessions.
        pub fn allow_client(&mut self, client_id: &str, client_sig_pk: Vec<u8>) {
            self.allowed_clients
                .insert(client_id.to_string(), client_sig_pk);
        }

        fn handle_session_init(&mut self, init: CoapSessionInit) -> Result<Vec<u8>> {
            if init.responder_id != self.server_id {
                return Err(Error::ProtocolError("Wrong responder_id".into()));
            }
            if init.session_seq == 0 {
                return Err(Error::InvalidInput("session_seq=0".into()));
            }

            let client_sig_pk = self
                .allowed_clients
                .get(&init.initiator_id)
                .ok_or_else(|| Error::SignatureVerification("Unknown initiator_id".into()))?;

            let payload = session_init_payload_v1(&CoapSessionInitSigInput {
                path: COAP_SESSION_INIT_PATH,
                session_id: &init.session_id,
                session_seq: init.session_seq,
                initiator_id: &init.initiator_id,
                responder_id: &init.responder_id,
                kem_pk: &init.kem_pk,
                x25519_pk: &init.x25519_pk,
                ts: init.ts,
            });
            if !self
                .falcon
                .verify(client_sig_pk, &payload, &init.signature)?
            {
                return Err(Error::SignatureVerification(
                    "Session init signature invalid".into(),
                ));
            }

            let last_seq = *self.last_session_seq.get(&init.initiator_id).unwrap_or(&0);
            if init.session_seq < last_seq {
                return Err(Error::ProtocolError("session_seq rollback".into()));
            }
            if init.session_seq == last_seq {
                if let Some(cached) = self.session_resp_cache.get(&init.initiator_id) {
                    if cached.session_seq == init.session_seq
                        && cached.session_id == init.session_id
                    {
                        return Ok(cached.bytes.clone());
                    }
                }
                return Err(Error::ProtocolError(
                    "Duplicate session_seq with different session_id".into(),
                ));
            }

            let responder_x_sk = X25519StaticSecret::random_from_rng(OsRng);
            let responder_x_pk = X25519PublicKey::from(&responder_x_sk).to_bytes();
            let dh_ss = responder_x_sk
                .diffie_hellman(&X25519PublicKey::from(init.x25519_pk))
                .to_bytes()
                .to_vec();

            let kyber = kyber_for_pk_len(init.kem_pk.len())?;
            let (kem_ciphertext, kem_ss) = kyber.encapsulate(&init.kem_pk)?;

            let (ck_initiator, ck_responder) =
                derive_session_chain_keys_v1(&init.session_id, &kem_ss, &dh_ss)?;

            // Replace any existing session for this peer deterministically.
            self.sessions.insert(
                init.initiator_id.clone(),
                CoapSession::new(init.session_id, ck_responder, ck_initiator),
            );

            self.last_session_seq
                .insert(init.initiator_id.clone(), init.session_seq);

            let ts = 0u64;
            let resp_payload = session_resp_payload_v1(&CoapSessionRespSigInput {
                path: COAP_SESSION_INIT_PATH,
                session_id: &init.session_id,
                session_seq: init.session_seq,
                initiator_id: &init.initiator_id,
                responder_id: &init.responder_id,
                x25519_pk: &responder_x_pk,
                kem_ciphertext: &kem_ciphertext,
                ts,
            });
            let signature = self.falcon.sign(&self.sig_sk, &resp_payload)?;

            let resp = CoapSessionResponse {
                initiator_id: init.initiator_id.clone(),
                responder_id: init.responder_id,
                session_id: init.session_id,
                session_seq: init.session_seq,
                x25519_pk: responder_x_pk,
                kem_ciphertext,
                ts,
                signature,
            };
            let bytes = encode_session_response_v1(&resp)?;
            self.session_resp_cache.insert(
                init.initiator_id,
                CachedCoapSessionResponse {
                    session_seq: resp.session_seq,
                    session_id: resp.session_id,
                    bytes: bytes.clone(),
                },
            );
            Ok(bytes)
        }

        fn handle_secure_request(
            &mut self,
            sender_id: &str,
            code: u8,
            path: &str,
            token: &[u8],
            decoded: CoapSecurePayloadV2,
        ) -> Result<Vec<u8>> {
            let session = self
                .sessions
                .get_mut(sender_id)
                .ok_or_else(|| Error::ProtocolError("No active session for sender".into()))?;

            if decoded.sender_id != sender_id {
                return Err(Error::ProtocolError("sender_id mismatch".into()));
            }
            if decoded.session_id != session.session_id {
                return Err(Error::ProtocolError("session_id mismatch".into()));
            }

            let binding = CoapMsgBinding {
                sender_id,
                receiver_id: &self.server_id,
                code,
                path,
                token,
            };
            let plaintext = session.decrypt_v2(&binding, decoded.msg_num, &decoded.ciphertext)?;
            Ok(plaintext)
        }

        fn encrypt_secure_response(
            &mut self,
            receiver_id: &str,
            code: u8,
            path: &str,
            token: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>> {
            let session = self
                .sessions
                .get_mut(receiver_id)
                .ok_or_else(|| Error::ProtocolError("No active session for receiver".into()))?;
            let binding = CoapMsgBinding {
                sender_id: &self.server_id,
                receiver_id,
                code,
                path,
                token,
            };
            let (msg_num, ciphertext) = session.encrypt_v2(&binding, plaintext)?;
            encode_secure_payload_v2(&self.server_id, &session.session_id, msg_num, &ciphertext)
        }

        /// Handle an incoming CoAP request packet and (optionally) produce a response packet.
        pub fn handle_packet(&mut self, packet: Packet, src: SocketAddr) -> Result<Option<Packet>> {
            let mut request: CoapRequest<SocketAddr> = CoapRequest::from_packet(packet, src);

            if self
                .block_handler
                .intercept_request(&mut request)
                .map_err(|e| Error::ClientError(e.to_string()))?
            {
                return Ok(request.response.map(|r| r.message));
            }

            let path = request.get_path();
            let code: u8 = request.message.header.code.into();
            let token = request.message.get_token().to_vec();

            let response = request
                .response
                .as_mut()
                .ok_or_else(|| Error::ClientError("Missing response template".into()))?;

            if path == COAP_SESSION_INIT_PATH {
                let init = decode_session_init_v1(&request.message.payload)?;
                let bytes = self.handle_session_init(init)?;
                response.message.payload = bytes;
                response.set_status(ResponseType::Content);

                let _ = self
                    .block_handler
                    .intercept_response(&mut request)
                    .map_err(|e| Error::ClientError(e.to_string()))?;
                return Ok(request.response.map(|r| r.message));
            }

            let decoded = match decode_secure_payload_v2(&request.message.payload) {
                Ok(v) => v,
                Err(_) => {
                    response.set_status(ResponseType::BadRequest);
                    response.message.payload = b"secure payload required".to_vec();
                    return Ok(request.response.map(|r| r.message));
                }
            };
            let sender_id = decoded.sender_id.clone();

            let plaintext = self.handle_secure_request(&sender_id, code, &path, &token, decoded)?;

            response.set_status(ResponseType::Content);
            let resp_code: u8 = response.message.header.code.into();
            let encrypted =
                self.encrypt_secure_response(&sender_id, resp_code, &path, &token, &plaintext)?;
            response.message.payload = encrypted;

            let _ = self
                .block_handler
                .intercept_response(&mut request)
                .map_err(|e| Error::ClientError(e.to_string()))?;

            Ok(request.response.map(|r| r.message))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::thread;

        #[test]
        fn test_send_and_verify_request() {
            let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let server_addr = server_socket.local_addr().unwrap();

            let falcon = Falcon::new();
            let (server_pk, server_sk) = falcon.generate_keypair().unwrap();

            thread::spawn(move || {
                let falcon = Falcon::new();
                let mut buf = [0u8; 2048];
                if let Ok((amt, src)) = server_socket.recv_from(&mut buf) {
                    let packet = Packet::from_bytes(&buf[..amt]).unwrap();
                    let request: CoapRequest<SocketAddr> = CoapRequest::from_packet(packet, src);

                    let mut response = request.response.unwrap();
                    let message = b"OK";
                    let signature = falcon.sign(&server_sk, message).unwrap();
                    let sig_len = signature.len() as u16;
                    let mut signed = Vec::new();
                    signed.extend_from_slice(message);
                    signed.extend_from_slice(&signature);
                    signed.extend_from_slice(&sig_len.to_be_bytes());
                    response.message.payload = signed;

                    let bytes = response.message.to_bytes().unwrap();
                    server_socket.send_to(&bytes, src).unwrap();
                }
            });

            let mut client = SecureCoapClient::new().unwrap().with_peer_sig_pk(server_pk);
            let message = b"Hello, CoAP!";

            let response = client.post(server_addr, "test", message).unwrap();
            let payload = client.verify_response(&response).unwrap();
            assert_eq!(payload, b"OK");
        }

        #[test]
        fn test_signature_verification_failure() {
            let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let server_addr = server_socket.local_addr().unwrap();

            let falcon = Falcon::new();
            let (server_pk, server_sk) = falcon.generate_keypair().unwrap();

            thread::spawn(move || {
                let falcon = Falcon::new();
                let mut buf = [0u8; 2048];
                if let Ok((amt, src)) = server_socket.recv_from(&mut buf) {
                    let packet = Packet::from_bytes(&buf[..amt]).unwrap();
                    let request: CoapRequest<SocketAddr> = CoapRequest::from_packet(packet, src);

                    let mut response = request.response.unwrap();
                    let message = b"OK";
                    let signature = falcon.sign(&server_sk, message).unwrap();
                    let sig_len = signature.len() as u16;
                    let mut signed = Vec::new();
                    signed.extend_from_slice(message);
                    signed.extend_from_slice(&signature);
                    signed.extend_from_slice(&sig_len.to_be_bytes());

                    // Tamper with payload after signing to ensure verification fails.
                    signed[0] ^= 0xFF;
                    response.message.payload = signed;

                    let bytes = response.message.to_bytes().unwrap();
                    server_socket.send_to(&bytes, src).unwrap();
                }
            });

            let mut client = SecureCoapClient::new().unwrap().with_peer_sig_pk(server_pk);
            let message = b"Hello, CoAP!";
            let response = client.post(server_addr, "test", message).unwrap();

            assert!(client.verify_response(&response).is_err());
        }

        #[test]
        fn coap_session_handshake_and_secure_echo() {
            let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            server_socket
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let server_addr = server_socket.local_addr().unwrap();

            let mut server = SecureCoapSessionServer::new("server").unwrap();
            let server_pk = server.identity_sig_pk().to_vec();

            let mut client = SecureCoapSessionClient::new("client", "server", server_pk).unwrap();
            client = client.with_timeout(Duration::from_secs(5));
            server.allow_client("client", client.identity_sig_pk().to_vec());

            thread::spawn(move || {
                let mut server = server;
                let mut buf = [0u8; 65535];
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if std::time::Instant::now() > deadline {
                        break;
                    }
                    match server_socket.recv_from(&mut buf) {
                        Ok((amt, src)) => {
                            let packet = Packet::from_bytes(&buf[..amt]).unwrap();
                            if let Ok(Some(resp)) = server.handle_packet(packet, src) {
                                let should_stop = resp.payload == b"hello-secure";
                                let bytes = resp.to_bytes().unwrap();
                                let _ = server_socket.send_to(&bytes, src);
                                if should_stop {
                                    break;
                                }
                            }
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            });

            let response = client
                .post(server_addr, "test/resource", b"hello-secure")
                .unwrap();
            assert_eq!(response.message.payload, b"hello-secure");
        }
    }
}

#[cfg(feature = "coap-std")]
pub use std_client::{
    AclRules, DtlsConfig, SecureCoapClient, SecureCoapSessionClient, SecureCoapSessionServer,
};

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
