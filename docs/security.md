# Security Guide

This document provides detailed information about the security features and considerations of the PQC-IIoT crate.

For the project’s invariant-level security contract, see `SECURITY_INVARIANTS.md` at the repository root. That document is the reference for “what must always remain true” under adversarial conditions (replay, rollback, partitions, broker compromise).

## Table of Contents

- [Cryptographic Primitives](#cryptographic-primitives)
- [Protocol Security](#protocol-security)
- [Implementation Security](#implementation-security)
- [Best Practices](#best-practices)
- [Threat Model](#threat-model)
- [Security Considerations](#security-considerations)

## Cryptographic Primitives

### Key Encapsulation

#### CRYSTALS-Kyber
- NIST Round 3 finalist
- Security levels:
  - Kyber512 (Level 1)
  - Kyber768 (Level 3, recommended)
  - Kyber1024 (Level 5)
- Based on Module-LWE
- Constant-time implementation
- Side-channel resistant

#### SABER
- NIST Round 3 finalist
- Security levels:
  - LightSaber (Level 1)
  - Saber (Level 3, recommended)
  - FireSaber (Level 5)
- Based on Module-LWR
- Optimized for embedded systems
- Constant-time implementation

### Digital Signatures

#### Falcon
- NIST Round 3 finalist
- Security levels:
  - Falcon-512 (Level 1)
  - Falcon-1024 (Level 5)
- Based on NTRU lattices
- Compact signatures
- Fast verification

#### Dilithium
- NIST Round 3 finalist
- Security levels:
  - Dilithium2 (Level 2)
  - Dilithium3 (Level 3, recommended)
  - Dilithium5 (Level 5)
- Based on Module-LWE
- Balanced performance
- Robust implementation

## Protocol Security

### MQTT Security
- Provisioned identity (strict-mode) via signed operational certificates + key announcements bound to peer id/topic.
- v1 per-message hybrid encryption (Kyber + X25519 → AES-256-GCM) with signature authentication and sliding-window replay protection.
- v3 forward-secure sessions (authenticated handshake + DH-driven double ratchet) with topic/context binding and bounded out-of-order acceptance.
- Partition-aware policy + revocation updates (CA-signed, monotonic, retained) with fail-closed gates for high-risk operations.
- Asymmetric-cost DoS containment: size limits + peer-id sanitation + per-peer/global token-bucket budgets before expensive crypto.

### CoAP Security
- Signed payload mode: authenticity-only of application payloads when peer keys are pinned.
- Custom secure session mode: confidentiality + integrity + anti-replay at the application layer (not OSCORE/DTLS).
- For interoperability/compliance-critical deployments, OSCORE (with EDHOC) or DTLS is still the “industrial” transport/security boundary.

## Implementation Security

### Memory Safety
- Stack allocation where possible
- Zeroization of sensitive data
- Bounds checking
- No undefined behavior

### Side-Channel Resistance
- Constant-time operations
- Memory access patterns
- Branch-free code
- Cache timing protection

### Error Handling
- Secure error reporting
- No information leakage
- Graceful failure
- Recovery mechanisms

## Best Practices

### Key Management
1. **Generation**
   ```rust
   // Use recommended security levels
   let kyber = Kyber::new_with_level(KyberSecurityLevel::Kyber768);
   let falcon = Falcon::new_with_level(FalconSecurityLevel::Falcon512);
   ```

2. **Storage**
   ```rust
   // Store keys securely
   key_storage.store_public_key(&pk)?;
   key_storage.store_secret_key(&sk)?;
   ```

3. **Rotation**
   ```rust
   // Configure key rotation
   kyber.with_key_rotation_interval(Duration::from_secs(3600));
   ```

### Protocol Usage
1. **MQTT**
   ```rust
   // Strict mode requires provisioning (no TOFU):
   // - pin `trust_anchor_ca_sig_pk`
   // - install an `OperationalCertificate` for this identity
   //
   // See docs/mqtt.md for the end-to-end flow.
   let _client = SecureMqttClient::new("localhost", 1883, "client_id")?;
   ```

2. **CoAP**
   ```rust
   // Configure secure client
   let client = SecureCoapClient::new()?
       .with_dtls_config(dtls_config)?
       .with_acl(acl_rules)?;
   ```

## Threat Model

### Cryptographic Attacks
- Quantum computing attacks
- Classical cryptanalysis
- Side-channel attacks
- Fault injection

### Network Attacks
- Man-in-the-middle
- Replay attacks
- Denial of service
- Eavesdropping

### Implementation Attacks
- Memory corruption
- Timing attacks
- Power analysis
- Fault injection

## Security Considerations

### Hardware Requirements
- 32-bit processor
- 32KB RAM minimum
- 128KB Flash minimum
- Hardware RNG

### Performance Impact
- Key generation time
- Encryption/decryption time
- Signature/verification time
- Memory usage

### Deployment Guidelines
1. **Assessment**
   - Evaluate security requirements
   - Choose appropriate algorithms
   - Configure security levels

2. **Implementation**
   - Follow best practices
   - Enable security features
   - Configure monitoring

3. **Maintenance**
   - Regular updates
   - Key rotation
   - Security audits

## Update Process

### Vulnerability Assessment
1. Monitor security advisories
2. Evaluate impact
3. Plan updates
4. Test changes

### Patch Management
1. Review patches
2. Test updates
3. Deploy changes
4. Verify security

### Incident Response
1. Detect incidents
2. Assess impact
3. Contain threat
4. Recover systems
5. Learn from incident 
