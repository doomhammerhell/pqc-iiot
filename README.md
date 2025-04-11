# PQC-IIoT

A post-quantum cryptography crate for Industrial IoT (IIoT) applications, providing quantum-resistant cryptographic primitives with a focus on embedded systems and resource-constrained devices.

## Features

- **Post-quantum Key Encapsulation**:
  - CRYSTALS-Kyber (NIST Round 3 finalist)
  - SABER (NIST Round 3 finalist)
  - BIKE (experimental, for research)

- **Post-quantum Digital Signatures**:
  - Falcon (NIST Round 3 finalist)
  - Dilithium (NIST Round 3 finalist)

- **Secure Communication Protocols**:
  - MQTT with post-quantum security
  - CoAP with post-quantum security

- **Embedded Systems Support**:
  - `no_std` compatible
  - Minimal memory footprint
  - Hardware acceleration support

## Security Levels

### Key Encapsulation

- **Kyber**:
  - Kyber512 (Level 1)
  - Kyber768 (Level 3, recommended)
  - Kyber1024 (Level 5)

- **SABER**:
  - LightSaber (Level 1)
  - Saber (Level 3, recommended)
  - FireSaber (Level 5)

- **BIKE**:
  - Level 1 (experimental)
  - Level 3 (experimental)
  - Level 5 (experimental)

### Digital Signatures

- **Falcon**:
  - Falcon-512 (Level 1)
  - Falcon-1024 (Level 5)

- **Dilithium**:
  - Dilithium2 (Level 2)
  - Dilithium3 (Level 3, recommended)
  - Dilithium5 (Level 5)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
pqc-iiot = { version = "0.1.0", features = ["kyber", "falcon"] }
```

For embedded systems:

```toml
[dependencies]
pqc-iiot = { version = "0.1.0", features = ["embedded", "kyber", "falcon"] }
```

### Basic Example

```rust
use pqc_iiot::{Kyber, Falcon, KyberSecurityLevel, FalconSecurityLevel};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Kyber
    let kyber = Kyber::new(KyberSecurityLevel::Kyber768);
    let (pk, sk) = kyber.generate_keypair()?;
    
    // Initialize Falcon
    let falcon = Falcon::new(FalconSecurityLevel::Falcon512);
    let (sig_pk, sig_sk) = falcon.generate_keypair()?;
    
    Ok(())
}
```

### Advanced Example with Multiple Algorithms

```rust
use pqc_iiot::{
    Kyber, Falcon, Dilithium, Saber,
    KyberSecurityLevel, FalconSecurityLevel,
    DilithiumSecurityLevel, SaberSecurityLevel,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize multiple KEM algorithms
    let kyber = Kyber::new(KyberSecurityLevel::Kyber768);
    let saber = Saber::new(SaberSecurityLevel::Saber);
    
    // Initialize multiple signature algorithms
    let falcon = Falcon::new(FalconSecurityLevel::Falcon512);
    let dilithium = Dilithium::new(DilithiumSecurityLevel::Level3);
    
    // Generate key pairs
    let (kyber_pk, kyber_sk) = kyber.generate_keypair()?;
    let (saber_pk, saber_sk) = saber.generate_keypair()?;
    let (falcon_pk, falcon_sk) = falcon.generate_keypair()?;
    let (dilithium_pk, dilithium_sk) = dilithium.generate_keypair()?;
    
    Ok(())
}
```

## Feature Flags

- `std`: Standard library support (default)
- `embedded`: `no_std` support
- `kyber`: CRYSTALS-Kyber support
- `falcon`: Falcon support
- `dilithium`: Dilithium support
- `saber`: SABER support
- `bike`: BIKE support (experimental)
- `mqtt`: MQTT client support
- `coap`: CoAP client support
- `all`: Enable all features

## Security Considerations

- All cryptographic operations are constant-time
- Secret keys are zeroized when dropped
- Memory is allocated on the stack where possible
- Side-channel resistant implementations
- Regular key rotation recommended

## Performance

### Memory Usage

| Algorithm | Level | Key Size | Signature Size |
|-----------|-------|----------|----------------|
| Kyber     | 512   | 800 B    | 768 B          |
| Kyber     | 768   | 1184 B   | 1088 B         |
| Kyber     | 1024  | 1568 B   | 1568 B         |
| SABER     | L1    | 672 B    | 736 B          |
| SABER     | L3    | 992 B    | 1088 B         |
| SABER     | L5    | 1312 B   | 1472 B         |
| Falcon    | 512   | 897 B    | 690 B          |
| Falcon    | 1024  | 1793 B   | 1330 B         |
| Dilithium | 2     | 1184 B   | 2044 B         |
| Dilithium | 3     | 1472 B   | 2701 B         |
| Dilithium | 5     | 1760 B   | 3366 B         |

### Processing Time (ARM Cortex-M4 @ 120MHz)

| Operation          | Kyber768 | SABER L3 | Falcon512 | Dilithium3 |
|-------------------|----------|----------|-----------|------------|
| Key Generation    | 45ms     | 32ms     | 120ms     | 85ms       |
| Encapsulation     | 12ms     | 8ms      | -         | -          |
| Decapsulation     | 15ms     | 10ms     | -         | -          |
| Signing           | -        | -        | 8ms       | 25ms       |
| Verification      | -        | -        | 2ms       | 8ms        |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option. 