# PQC-IIoT

A post-quantum cryptography crate designed for Industrial IoT (IIoT) applications, providing quantum-resistant cryptographic primitives with a focus on embedded systems and resource-constrained devices.

## Features

- Post-quantum key encapsulation using CRYSTALS-Kyber
- Post-quantum digital signatures using Falcon
- `no_std` support for embedded systems via the `embedded` feature
- Zero-allocation implementations using `heapless`
- Constant-time operations for side-channel resistance
- Simple high-level API for common cryptographic operations

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
pqc-iiot = "0.1.0"
```

For embedded systems, enable the `embedded` feature:

```toml
[dependencies]
pqc-iiot = { version = "0.1.0", features = ["embedded"] }
```

### Example: Secure Communication Between IIoT Devices

```rust
use pqc_iiot::{Kyber, Falcon, Result};

// Generate keypairs
let kyber = Kyber::new();
let falcon = Falcon::new();

// Device 1: Generate keypairs
let (pk1, sk1) = kyber.generate_keypair()?;
let (sig_pk1, sig_sk1) = falcon.generate_keypair()?;

// Device 2: Generate keypairs
let (pk2, sk2) = kyber.generate_keypair()?;
let (sig_pk2, sig_sk2) = falcon.generate_keypair()?;

// Device 1: Encapsulate shared secret and sign
let message = b"Sensor reading: 25.5C";
let (ciphertext, shared_secret1) = kyber.encapsulate(&pk2)?;
let signature = falcon.sign(&ciphertext, &sig_sk1)?;

// Device 2: Verify signature and decapsulate
falcon.verify(&ciphertext, &signature, &sig_pk1)?;
let shared_secret2 = kyber.decapsulate(&sk2, &ciphertext)?;

// Shared secrets match
assert_eq!(shared_secret1, shared_secret2);
```

## Features

- `std` (default): Enable standard library support
- `embedded`: Enable `no_std` support for embedded systems

## Security Considerations

- This crate implements NIST PQC Round 3 finalists
- Constant-time operations are used where possible
- No dynamic memory allocation in `embedded` mode
- Side-channel resistance is a primary consideration

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Performance Benchmarks

The `pqc-iiot` crate has been benchmarked to evaluate the performance of its cryptographic operations. Below are the results from our benchmarks:

- **Key Generation**: Measures the time taken to generate a key pair using Kyber.
- **Encapsulation**: Measures the time taken to encapsulate a key using a public key.
- **Signature**: Measures the time taken to sign a message using Falcon.
- **Verification**: Measures the time taken to verify a signature against a message and public key.

These benchmarks were conducted on [specify hardware] and provide insights into the efficiency of post-quantum cryptographic operations in IIoT environments.

## Error Handling and Optimization

The crate includes robust error handling to manage common issues that may arise during cryptographic operations. Here are some scenarios and how to handle them:

- **Buffer Too Small**: Ensure that buffers are adequately sized to accommodate cryptographic outputs.
- **Invalid Input**: Validate inputs before processing to prevent errors.

For hardware-specific optimizations, consider the following:

- **Memory Constraints**: Use heapless data structures to manage memory efficiently in constrained environments.
- **Processing Power**: Optimize cryptographic operations to balance security and performance on low-power devices.

## Fuzz Testing

To ensure the security and robustness of the crate, fuzz testing has been integrated using `cargo-fuzz`. This helps identify vulnerabilities by testing the crate with random and unexpected inputs.

To run fuzz tests, use the following command:

```bash
cargo fuzz run fuzz_target
```

This will execute the fuzz tests and report any issues found during the process.

## Performance

This crate has been optimized to work efficiently on resource-constrained devices. We use micro-benchmarks to measure the execution time of critical operations such as key generation, encapsulation, signing, and verification. The benchmarks were conducted on different key sizes (Kyber-512, Kyber-1024) and various hardware configurations.

### Benchmarks

The benchmarks were conducted using the `criterion` library and the results showed that the crate can operate efficiently on devices with RAM capabilities ranging from 32KB to 512KB.

## Security

The crate adopts various security practices to ensure the integrity and confidentiality of communications.

### Security Best Practices

- **Constant Time**: All post-quantum operations are performed in constant-time to prevent timing attacks.
- **Security Tools**: We use `clippy` and `rust-secure-code` to ensure the code follows security best practices.
- **Attack Resistance**: The crate has been tested for resistance against Replay, Side-Channel, and Man-in-the-Middle attacks.

## Integration Examples

For complete integration examples with IIoT protocols such as MQTT and CoAP, see the `examples/` directory. These examples demonstrate how to use the crate in real systems, validating its use in IIoT environments. 