# PQC-IIoT Documentation

Welcome to the PQC-IIoT documentation! This guide provides comprehensive information about the PQC-IIoT crate, a post-quantum cryptography solution for Industrial IoT applications.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Security](#security)
- [Performance](#performance)
- [Examples](#examples)
- [Contributing](#contributing)

## Overview

PQC-IIoT is a Rust crate that provides post-quantum cryptographic primitives specifically designed for Industrial IoT applications. It implements NIST PQC Round 3 finalists and provides secure communication protocols for IIoT devices.

### Key Features

- Post-quantum key encapsulation using CRYSTALS-Kyber
- Post-quantum digital signatures using Falcon
- Secure MQTT and CoAP communication
- `no_std` support for embedded systems
- Constant-time operations
- Zero-allocation implementations

## Architecture

The crate is organized into several main components:

1. **Cryptographic Primitives**
   - `kem.rs`: Key encapsulation mechanisms
   - `sign.rs`: Digital signature schemes
   - `error.rs`: Error handling

2. **Protocol Integration**
   - `mqtt_secure.rs`: Secure MQTT client
   - `coap_secure.rs`: Secure CoAP client

3. **Utilities**
   - `utils.rs`: Helper functions and types
   - `constants.rs`: Cryptographic constants

## Getting Started

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
pqc-iiot = "0.1.0"
```

For embedded systems:

```toml
[dependencies]
pqc-iiot = { version = "0.1.0", features = ["embedded"] }
```

### Basic Usage

```rust
use pqc_iiot::{Kyber, Falcon, Result};

fn main() -> Result<()> {
    // Initialize cryptographic primitives
    let kyber = Kyber::new();
    let falcon = Falcon::new();

    // Generate keypairs
    let (pk, sk) = kyber.generate_keypair()?;
    let (sig_pk, sig_sk) = falcon.generate_keypair()?;

    // Use keys for secure communication
    Ok(())
}
```

## API Reference

Detailed API documentation is available in the following sections:

- [Cryptographic Primitives](crypto.md)
- [MQTT Client](mqtt.md)
- [CoAP Client](coap.md)
- [Error Handling](error.md)

## Security

The crate implements several security measures:

- Constant-time operations
- Side-channel resistance
- Replay attack protection
- Message integrity verification
- Key rotation support

See the [Security Guide](security.md) for detailed information.

## Performance

Performance characteristics and benchmarks are documented in the [Performance Guide](performance.md).

## Examples

Complete examples are available in the [examples directory](../examples/):

- [Basic Usage](../examples/basic_usage.rs)
- [MQTT Communication](../examples/mqtt_secure_example.rs)
- [CoAP Communication](../examples/coap_secure_example.rs)
- [IIoT Device](../examples/iiot_secure_comm.rs)

## Contributing

See the [Contributing Guide](../CONTRIBUTING.md) for information on how to contribute to the project. 