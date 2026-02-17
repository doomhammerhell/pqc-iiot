# Usage Guide

This guide provides step-by-step instructions on integrating **PQC-IIoT** into your industrial applications.

## Prerequisites

- **Rust Toolchain**: Stable channel (v1.70+ recommended).
- **Network Access**: Devices must be able to reach the MQTT broker or CoAP server.
- **Hardware**: Any target supported by Rust (x86_64, ARMv7, AArch64, RISC-V).

## Installation

Add `pqc-iiot` to your `Cargo.toml`:

```toml
[dependencies]
pqc-iiot = { git = "https://github.com/doomhammerhell/pqc-iiot", branch = "main" }
```

## Basic Initialization

Initialize the `SecurityProvider` (Defaults to Software):

```rust
use pqc_iiot::security::provider::SoftwareSecurityProvider;

let provider = SoftwareSecurityProvider::new();
```

See specific guides for [MQTT](usage/mqtt.md) and [CoAP](usage/coap.md).
