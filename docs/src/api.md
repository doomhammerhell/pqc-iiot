# API Reference

This section provides a high-level overview of the primary public APIs. For detailed documentation, run `cargo doc --open`.

## Core Modules

- **`pqc_iiot::SecureMqttClient`**: Main client for MQTT communication.
- **`pqc_iiot::SecureCoapClient`**: Main client for CoAP communication.
- **`pqc_iiot::security::keystore`**: Manages trusted identities and keys.
- **`pqc_iiot::security::provider`**: Interfaces for hardware integration.

## Key Traits

### `SecurityProvider`

The contract for all cryptographic operations.

| Method | Description |
|--------|-------------|
| `kem_public_key` | Returns the Kyber public key |
| `sig_public_key` | Returns the Falcon public key |
| `decrypt` | Hybrid decryption (Decaps + AES-GCM) |
| `sign` | Generates a detached Falcon signature |

### `Securitylevel`

Configuration for Kyber/Falcon parameter sets (Level 1, 3, 5).
