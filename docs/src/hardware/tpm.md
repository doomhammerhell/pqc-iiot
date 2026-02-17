# TPM 2.0 Integration

Trusted Platform Modules (TPM) provide a hardware root of trust. PQC-IIoT can leverage TPMs for:
- **Key Generation**: Keys are generated inside the TPM and never exposed.
- **Signing**: Falcon signing operations are performed by the TPM (if supported) or keys are unsealed only into secure memory.
- **Platform Integrity**: Validating the boot state (PCRs) before releasing keys.

## Implementation Status

Currently, standard TPMs do not natively support Kyber or Falcon.
**Our Approach**:
1.  **Hybrid Mode**: Use TPM to seal (encrypt) the PQC keys at rest.
2.  **Unsealing**: Keys are decrypted only into RAM protected by `Zeroize` when the application starts and PCRs match.

```rust
// Logical flow
let encrypted_key_blob = load_from_disk();
let key = tpm.unseal(encrypted_key_blob)?; // Fails if boot chain compromised
let provider = SoftwareSecurityProvider::new(key);
// ... use provider ...
```
