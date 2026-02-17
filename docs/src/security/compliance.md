# FIPS 140-3 Compliance

PQC-IIoT incorporates mandatory features required for FIPS 140-3 certification, easing the path for official validation of products built using this library.

## Approved Mode of Operation

The library enforces an **Approved Mode of Operation** which restricts the algorithms and configurations to those vetted by NIST (or in the process of standardization like Kyber/Falcon).

### Enabling Approved Mode

```rust
// This flag enforces FIPS checks
std::env::set_var("PQC_IIOT_FIPS_MODE", "1");
```

## Power-On Self-Tests (POST)

Upon initialization, the library automatically runs Known Answer Tests (KAT) for:
- **AES-256-GCM** (Encryption/Decryption)
- **SHA-256** (Hashing)
- **Kyber-768** (KEM Encapsulate/Decapsulate)
- **Falcon-512** (Sign/Verify)

If any test fails, the library panics and refuses to start, ensuring no cryptographic operations are performed with faulty logic.

## Integrity Checks

A software integrity check (using SHA-256) verifies that critical configuration and module components have not been tampered with on disk before loading.

## Conditional Self-Tests

- **Pairwisie Consistency Test (PCT)**: Every time a new key pair is generated, a PCT is run (Sign/Verify for signature keys, Encaps/Decaps for KEM keys) to verify correctness before the keys are used.

## Zeroization

Sensitive data (Private Keys, Shared Secrets) is actively overwritten with zeros using the `zeroize` crate when the memory is deallocated (`Drop` trait) or explicitly cleared.
