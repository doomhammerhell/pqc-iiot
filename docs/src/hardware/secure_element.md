# Secure Elements (SE)

For embedded devices without a TPM, Secure Elements (like NXP SE050 or Microchip ATECC608) offer similar protection.

## Integration

PQC-IIoT can offload the **AES-GCM** encryption to a Secure Element to protect the session data, while handling the PQC Key Exchange in software (as SEs typically lack PQC support currently).

```rust
impl SecurityProvider for MySecureElement {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Offload AES decryption to SE
        se_driver.aes_gcm_decrypt(...)
    }
}
```
