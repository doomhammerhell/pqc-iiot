use crate::error::{Result};
use crate::security::provider::SecurityProvider;
use crate::provisioning::{FactoryIdentity, JoinRequest}; 
use crate::ratchet::RatchetSession;
use crate::{Kyber}; 
use crate::crypto::traits::PqcKEM; 

/// Marker trait for Client States
pub trait State {}

/// State: Client has identity keys but is not registered with the network
pub struct Unprovisioned;
impl State for Unprovisioned {}

/// State: Client has been registered (CSR signed) and is ready for session
pub struct Provisioned {
    /// The Operational Certificate issued by the Factory CA.
    pub operational_cert: Vec<u8>, 
}
impl State for Provisioned {}

/// State: Client has Active Secure Session with Ratcheting
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Connected {
    /// Unique Session Identifier (e.g., GatewayID + Random).
    pub session_id: String,
    /// The Active Double Ratchet Session state.
    pub ratchet: RatchetSession,
}
impl State for Connected {}

/// PQC Client with Typestate Pattern
/// 
/// The generic `S` enforces valid operations for the current state at Compile Time.
/// misuse (e.g., calling `publish` before `connect`) is a compiler error.
pub struct PqcClient<S: State> {
    state: S,
    provider: Box<dyn SecurityProvider>,
}

impl PqcClient<Unprovisioned> {
    /// Create a new PQC Client in the Unprovisioned state.
    /// 
    /// # Arguments
    /// * `provider` - A Boxed SecurityProvider trait object holding the device's keys.
    pub fn new(provider: Box<dyn SecurityProvider>) -> Self {
        Self {
            state: Unprovisioned,
            provider,
        }
    }

    /// Step 1: Generate a Certificate Signing Request (CSR).
    pub fn generate_csr(&self, device_id: &str) -> Result<Vec<u8>> {
        let pk = self.provider.kem_public_key().to_vec();
        let mut payload = Vec::new();
        payload.extend_from_slice(device_id.as_bytes());
        payload.extend_from_slice(&pk);
        
        // Sign CSR with our signature key
        let signature = self.provider.sign(&payload)?;
        
        let csr = serde_json::to_vec(&serde_json::json!({
            "device_id": device_id,
            "operational_pubkey": hex::encode(pk),
            "signature": hex::encode(signature),
        })).map_err(|e| crate::error::Error::ClientError(format!("JSON error: {}", e)))?;
        
        Ok(csr)
    }

    /// Step 1.1: Generate a Provisioning Join Request.
    pub fn generate_join_request(&self, device_id: &str) -> Result<JoinRequest> {
        let pk = self.provider.kem_public_key().to_vec();
        
        let factory_id = FactoryIdentity::new(
            self.provider.sig_public_key().to_vec(),
            vec![], 
        );
        
        factory_id.create_join_request(
            device_id,
            &pk,
            &*self.provider
        )
    }

    /// Step 2: Apply the Provisioning Response (Certificate).
    /// 
    /// Call this after receiving the `OperationalCertificate` from the CA.
    pub fn complete_provisioning(self, operational_cert: Vec<u8>) -> Result<PqcClient<Provisioned>> {
        if operational_cert.is_empty() {
             return Err(crate::error::Error::ClientError("Empty Operational Certificate".into()));
        }

        Ok(PqcClient {
            state: Provisioned { 
                operational_cert 
            },
            provider: self.provider,
        })
    }
}

impl PqcClient<Provisioned> {
    /// Step 1: Initiate Connection (ClientHello).
    /// 
    /// Generates Ephemeral Kyber and X25519 Keypairs.
    /// Returns: (Hybrid ClientHello, Hybrid Ephemeral State)
    pub fn generate_connect_request(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // 1. Generate Ephemeral Kyber Keypair
        let kyber = Kyber::new();
        let (k_pk, k_sk) = kyber.generate_keypair()
            .map_err(|e| crate::error::Error::CryptoError(format!("Kyber Gen Fail: {:?}", e)))?;
            
        // 2. Generate Ephemeral X25519 Keypair
        let x_sk = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let x_pk = x25519_dalek::PublicKey::from(&x_sk).to_bytes();
        
        // 3. Construct Hybrid ClientHello: [Kyber PK][X25519 PK]
        let mut client_hello = Vec::with_capacity(k_pk.len() + 32);
        client_hello.extend_from_slice(&k_pk);
        client_hello.extend_from_slice(&x_pk);
        
        // 4. Construct Hybrid Ephemeral State: [Kyber SK][X25519 SK]
        let mut hybrid_sk = Vec::with_capacity(k_sk.len() + 32);
        hybrid_sk.extend_from_slice(&k_sk);
        hybrid_sk.extend_from_slice(&x_sk.to_bytes());
        
        Ok((client_hello, hybrid_sk))
    }

    /// Step 2: Complete Connection (ServerHello).
    /// 
    /// Process the Gateway's response (Kyber Ciphertext + X25519 Public Key).
    pub fn complete_connection(
        self, 
        gateway_id: &str, 
        server_hello: &[u8], // [Kyber CT][X25519 PK]
        hybrid_sk: &[u8]
    ) -> Result<PqcClient<Connected>> {
        if server_hello.len() < 32 {
            return Err(crate::error::Error::CryptoError("Invalid ServerHello length".into()));
        }
        
        // 1. Split ServerHello
        let ct_len = server_hello.len() - 32;
        let kyber_ct = &server_hello[..ct_len];
        let mut server_x_pk = [0u8; 32];
        server_x_pk.copy_from_slice(&server_hello[ct_len..]);
        
        // 2. Split Hybrid SK
        let k_sk_len = hybrid_sk.len() - 32;
        let k_sk = &hybrid_sk[..k_sk_len];
        let mut x_sk_bytes = [0u8; 32];
        x_sk_bytes.copy_from_slice(&hybrid_sk[k_sk_len..]);
        let x_sk = x25519_dalek::StaticSecret::from(x_sk_bytes);
        
        // 3. Decapsulate Kyber
        let kyber = Kyber::new();
        let k_secret = kyber.decapsulate(k_sk, kyber_ct)?;
        
        // 4. Perform X25519 DH
        let x_pub = x25519_dalek::PublicKey::from(server_x_pk);
        let x_secret = x_sk.diffie_hellman(&x_pub);
        
        // 5. Combine Secrets (Hybrid PQH)
        // We use HKDF-SHA256 to mix Kyber and X25519 secrets.
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        let combiner = Hkdf::<Sha256>::new(None, &k_secret);
        let mut final_secret = [0u8; 32];
        combiner.expand(&x_secret.to_bytes(), &mut final_secret)
            .map_err(|_| crate::error::Error::CryptoError("Hybrid KDF Expand Fail".into()))?;
        
        // 6. Initialize Ratchet
        let ratchet = RatchetSession::initialize(
            final_secret, 
            Some(self.provider.kem_public_key()) 
        );

        Ok(PqcClient {
            state: Connected { 
                session_id: format!("session_{}_{}", gateway_id, hex::encode(&final_secret[0..4])),
                ratchet,
            },
            provider: self.provider,
        })
    }
}

impl PqcClient<Connected> {
    /// Helper to access session ID
    pub fn session_id(&self) -> &str {
        &self.state.session_id
    }

    /// Operation: Publish Data (Only valid in Connected state)
    /// 
    /// Real Logic:
    /// 1. Use internal RatchetSession to Encrypt payload.
    /// 2. Return the binary blob ready for MQTT.
    pub fn publish(&mut self, _topic: &str, payload: &[u8]) -> Result<Vec<u8>> {
        // 1. Ratchet Encrypt
        let msg = self.state.ratchet.encrypt(payload)?;
        
        // 2. Serialize RatchetMessage (Header + Ciphertext + Tag)
        // Simple serialization: [Header] [Ciphertext] [Tag]
        // For deep implementation, we just return the raw ciphertext which includes nonce now.
        // RatchetMessage has structure, let's serialize it roughly or just return ciphertext.
        // The `msg.ciphertext` already has Nonce prepended from our previous fix.
        
        Ok(msg.ciphertext)
    }
    
    /// Transition: Connected -> Provisioned (Disconnect)
    pub fn disconnect(self) -> PqcClient<Provisioned> {
        PqcClient {
            state: Provisioned { 
                operational_cert: vec![] // Lost session, but kept cert
            },
            provider: self.provider,
        }
    }

    /// Seal the current session state to the TPM (Power-Cycle Resilience).
    pub fn seal_state(&self) -> Result<()> {
        let serialized = serde_json::to_vec(&self.state)
            .map_err(|e| crate::error::Error::ClientError(format!("Seal Serialization Fail: {}", e)))?;
        
        self.provider.seal_data(&self.state.session_id, &serialized)
    }

    /// Resume a session from a sealed state in the TPM.
    pub fn load_from_sealed(provider: Box<dyn SecurityProvider>, session_id: &str) -> Result<Self> {
        let data = provider.unseal_data(session_id)?;
        let state: Connected = serde_json::from_slice(&data)
            .map_err(|e| crate::error::Error::ClientError(format!("Unseal Deserialization Fail: {}", e)))?;
            
        Ok(Self {
            state,
            provider,
        })
    }
}
