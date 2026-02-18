# PQC-IIoT: Post-Quantum Cryptography for Industrial IoT

**PQC-IIoT** is a Rust-based security library designed to bring NIST-standard post-quantum cryptography (Kyber, Falcon) to resource-constrained Industrial IoT (IIoT) devices. It bridges the gap between modern cryptographic research and practical, mission-critical industrial applications.

## Key Features

- **Hybrid Encryption**: Combines Kyber-768 (KEM) with AES-256-GCM for robust data confidentiality.
- **Quantum-Resistant Signatures**: Uses Falcon-512 for high-speed, low-latency identity verification and command signing.
- **FIPS 140-3 Compliance Ready**: Includes Power-On Self-Tests (POST), Integrity Checks, and an Approved Mode of Operation.
- **Hardware Abstraction Layer (HAL)**: Seamlessly integrates with TPM 2.0 and HSMs, keeping private keys secure in hardware.
- **Secure Memory**: Automatic zeroization of sensitive data using the `zeroize` crate.
- **Protocols**: Native support for Secure MQTT and CoAP.

## Why PQC for IIoT?

Industrial systems often have lifespans exceeding 20 years. Devices deployed today effectively face the threat of quantum computers within their operational lifecycle ("Store Now, Decrypt Later"). PQC-IIoT ensures that critical infrastructure remains secure against future quantum attacks.

## Getting Started

Add the library to your `Cargo.toml`:

```toml
[dependencies]
pqc-iiot = "0.1.0"
```

See the [Usage Guide](usage.md) for detailed integration steps.

## License

This project is licensed under the MIT License.
