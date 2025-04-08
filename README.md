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