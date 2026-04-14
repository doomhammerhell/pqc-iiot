# PQC-IIoT

A Rust crate for post-quantum cryptography in Industrial IoT systems.

**[📚 Full Documentation (NIST/Academic Standard)](https://doomhammerhell.github.io/pqc-iiot/)**

## Features

- Post-quantum cryptographic algorithms:
  - Hybrid KEM (Kyber-1024 + X25519)
  - Key Encapsulation Mechanisms (KEMs):
    - Kyber
    - HQC
  - Digital Signatures:
    - Falcon
- **Galactic Apex Security (V4)**:
  - **PUF Identification**: Root key derived from silicon fingerprint (Hardware-Intrinsic).
  - **Mathematical Proofs**: Double Ratchet validated via Property-Based Verification.
- `no_std` and `heapless` support
- Hardware acceleration support
- Performance monitoring and metrics
- Key rotation and management
- Security level management

## Security & Compliance Features

Designed for **FIPS 140-3** and **IEC 62443** compliance in Critical Infrastructure:

### Security Contract

The invariant-level security contract (threat model assumptions, trust boundaries, fail-closed gates) lives in `SECURITY_INVARIANTS.md`. Treat it as the reference for adversarial correctness and as the place where regressions must be codified as tests.

### 🛡️ Mathematically Proven Security ("World Class")
![Uncrashable](https://img.shields.io/badge/Formal_Verification-Kani-success)
![Fuzzing](https://img.shields.io/badge/Fuzzing-LibFuzzer-coverage)

- **Formal Verification (Kani)**: The Core Boot Logic (`PartitionManager`) is model-checked to be mathematically free of Panics and invalid state transitions.
- **Continuous Fuzzing**: The `fuzz_target` crate continuously bombards the cryptographic parsers with random inputs to guarantee robustness against malformed data.

### Compliance Features
- **Power-On Self-Tests (POST)**: Automatically verifies cryptographic integrity (KAT/PCT) on startup.
- **Integrity Checks**: Validates library integrity using SHA-256 checksums.
- **Secure Memory**: Automated zeroization of sensitive key material using `Zeroize`.
- **Audit Logging**: Structured security events for SIEM integration.
- **Hardware Abstraction**: Ready for TPM 2.0 / HSM integration via `SecurityProvider` trait.
## Cryptographic Profiles

The crate provides pre-defined combinations of KEM and signature algorithms, optimized for different IIoT scenarios:

### ProfileKyberFalcon
- **KEM**: Kyber (NIST Level 3)
- **Signature**: Falcon (NIST Level 5)
- **Use Case**: High-security applications requiring strong signatures
- **Performance**: Balanced between KEM and signature operations
- **Memory Usage**: Moderate

### ProfileSaberDilithium
- **KEM**: SABER (NIST Level 3)
- **Signature**: Dilithium (NIST Level 3)
- **Use Case**: Applications requiring standardized algorithms
- **Performance**: Optimized for consistent performance
- **Memory Usage**: Moderate to high

### ProfileKyberDilithium
- **KEM**: Kyber (NIST Level 3)
- **Signature**: Dilithium (NIST Level 3)
- **Use Case**: General-purpose IIoT applications
- **Performance**: Balanced across all operations
- **Memory Usage**: Moderate

## Choosing a Profile

Select a profile based on your requirements:

1. **Security Level**: Consider the NIST security level needed for your application
2. **Performance**: Evaluate the computational requirements of your devices
3. **Memory**: Check the available memory on your target devices
4. **Standardization**: Consider if you need standardized algorithms
5. **Use Case**: Match the profile to your specific IIoT scenario

## Usage

### Basic Usage

```rust
use pqc_iiot::crypto::profile::{CryptoProfileTrait, ProfileKyberFalcon};

// Create a profile instance
let profile = ProfileKyberFalcon::new();

// Generate key pair
let (pk, sk) = profile.generate_keypair().unwrap();

// Encapsulate a shared secret
let (ct, ss1) = profile.encapsulate(&pk).unwrap();

// Decapsulate the shared secret
let ss2 = profile.decapsulate(&sk, &ct).unwrap();
assert_eq!(ss1, ss2);

// Sign a message
let msg = b"Hello, IIoT!";
let sig = profile.sign(&sk, msg).unwrap();

// Verify the signature
let valid = profile.verify(&pk, msg, &sig).unwrap();
assert!(valid);
```

### Performance Monitoring

```rust
use pqc_iiot::crypto::traits::{Metrics, PqcKEM, PqcSignature};
use pqc_iiot::{Falcon, Kyber};
use std::time::Duration;

// Configure key rotation on the concrete primitives (profiles are composition layers).
let kyber = Kyber::new().with_key_rotation_interval(Duration::from_secs(3600));
let falcon = Falcon::new();

// Perform operations
let (pk, _sk) = kyber.generate_keypair().unwrap();
let (_ct, _ss) = kyber.encapsulate(&pk).unwrap();

let (sig_pk, sig_sk) = falcon.generate_keypair().unwrap();
let msg = b"Hello, IIoT!";
let sig = falcon.sign(&sig_sk, msg).unwrap();
assert!(falcon.verify(&sig_pk, msg, &sig).unwrap());

// Get performance metrics
let _ = kyber.metrics();
let _ = falcon.metrics();
```

## Configuration

Profiles can be configured through:

1. **Build-time Configuration**:
   - Feature flags in `Cargo.toml`
   - Environment variables

2. **Runtime Configuration**:
   - Profile selection
   - Security level adjustment
   - Key rotation intervals

## Security Considerations

- Use appropriate security levels for your threat model
- Implement proper key rotation policies
- Monitor performance metrics for anomalies
- Validate all cryptographic operations
- Use constant-time operations where possible

## Performance

Each profile has different performance characteristics:

| Profile | Key Generation | Encapsulation | Decapsulation | Signing | Verification |
|---------|---------------|---------------|---------------|---------|--------------|
| Kyber+Falcon | Fast | Fast | Fast | Moderate | Fast |
| SABER+Dilithium | Moderate | Moderate | Moderate | Fast | Moderate |
| Kyber+Dilithium | Fast | Fast | Fast | Fast | Moderate |

## Memory Usage

Approximate memory requirements:

| Profile | Static Memory | Dynamic Memory (Peak) |
|---------|--------------|----------------------|
| Kyber+Falcon | ~10KB | ~50KB |
| SABER+Dilithium | ~15KB | ~60KB |
| Kyber+Dilithium | ~12KB | ~55KB |

## License

This project is licensed under the MIT License.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests. 
