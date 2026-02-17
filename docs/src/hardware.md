# Hardware Integration

PQC-IIoT is designed to run securely on general-purpose hardware but supports enhanced security through dedicated hardware integration.

## Supported Hardware

- **TPM 2.0**: Using the `tss-esapi` crate standard.
- **Secure Elements (SE)**: Interface for I2C/SPI connected secure elements (e.g., ATECC608, SE050).
- **HSM**: PKCS#11 support (Planned).

## Integration Pattern

The library uses the `SecurityProvider` trait to abstract hardware details.

```rust
// Your custom provider implementation
struct TpmProvider { ... }

impl SecurityProvider for TpmProvider {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        // Send command to TPM to sign
        // Private key never leaves TPM
    }
}
```
