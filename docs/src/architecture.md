# Security Architecture

PQC-IIoT employs a layered security architecture designed to withstand both classical and post-quantum threats while adhering to rigorous industrial standards.

## 1. Hardware Abstraction Layer (HAL)

At the core is the `SecurityProvider` trait, which decouples cryptographic operations from the application logic. This allows:
- **Software Mode**: Development and testing using `Zeroize`-protected memory.
- **Hardware Mode**: Production deployment using TPM 2.0 or HSMs (Hardware Security Modules) where private keys never leave the secure boundary.

```rust
pub trait SecurityProvider: Send + Sync {
    fn kem_public_key(&self) -> &[u8];
    fn sig_public_key(&self) -> &[u8];
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
    // ...
}
```

## 2. Hybrid Encryption (Confidentiality)

We utilize a hybrid Key Encapsulation Mechanism (KEM) approach:
1.  **Kyber-768/1024** establishes a shared quantum-resistant secret.
2.  **AES-256-GCM** uses the shared secret to encrypt the actual data payload with high performance.

This ensures that even if classical key exchange methods (ECDH) are broken by quantum computers, the session keys remain secure.

## 3. Post-Quantum Identity (Authentication)

Identity is verified using **Falcon-512** signatures.
- **Strict Mode**: Only peers with public keys manually added to the `KeyStore` (Allow-list) can communicate.
- **TOFU (Trust On First Use)**: Can be enabled for easier onboarding, but prints security warnings.

## 4. Replay Protection

To prevent replay attacks:
1.  Each encrypted packet includes a monotonically increasing **Sequence Number**.
2.  The `KeyStore` persists the last seen sequence number for every peer.
3.  Packets with `seq <= last_seen` are dropped and logged as security events.

## 5. Audit Logging

A structured audit log records all security-critical events (key generation, authentication failures, replay attempts) for SIEM integration and compliance auditing.
