# FIPS 140-3 Compliance Mapping

This document maps PQC-IIoT features to specific FIPS 140-3 requirements.

| FIPS 140-3 Section | Requirement | PQC-IIoT Implementation Mapping |
| :--- | :--- | :--- |
| **Integrity** | | |
| **IG 9.3.A** | Software/Firmware Integrity | **SHA-256 Check**: On startup, the library calculates the SHA-256 hash of its own binary code segment (simulated) and compares it against a stored digest. |
| **Self-Tests** | | |
| **SP 800-140B** | Power-On Self-Tests (POST) | **KAT (Known Answer Tests)**: The `compliance::run_post()` function executes KATs for Kyber (encaps/decaps) and Falcon (sign/verify) using fixed test vectors. Failure forces a panic/abort preventing operation. |
| **IG 9.3.G** | Periodic Self-Tests | **On-Demand**: The POST function is public and can be invoked periodically by the host application. |
| **Zeroization** | | |
| **IG 9.7.B** | Key Zeroization | **`Zeroize` Trait**: All private keys (`SecretKey`) implement the `Drop` trait to overwrite memory with zeros when they go out of scope. |
| **Key Man.** | | |
| **SP 800-133** | Key Generation | **TRNG Seeding**: Keys are generated using `OsRng` (platform TRNG) or a CSPRNG seeded from hardware entropy. Deterministic generation is strictly for testing. |
| **IG D.F** | Key Entry/Output | **Encrypted Import/Export**: The `KeyStore` only serializes keys in encrypted forms (using AES-GCM wrapping) if persistence is configured. Plaintext export is blocked by the API types. |
| **Life Cycle** | | |
| **IG 2.3.B** | Approved Mode | **Mode Flag**: The `PQC_IIOT_FIPS_MODE` environment variable or build feature enforces strict checks (e.g., disallowing non-NIST algorithms if any were present). |

## Approved Algorithms (Transition)

PQC-IIoT uses algorithms that are in the process of FIPS standardization (FIPS 203 for Kyber, FIPS 204 for Dilithium, FIPS 205 for SPHINCS+). Note that Falcon is currently in the NIST standardization track.

- **Kyber-768**: Maps to **FIPS 203 (ML-KEM)**.
- **Dilithium-3**: Maps to **FIPS 204 (ML-DSA)**.
- **Falcon-512**: Pending standardization.

## Critical Security Parameters (CSPs)

| CSP ID | Description | Generation | Storage | Zeroization |
| :--- | :--- | :--- | :--- | :--- |
| **CSP-1** | Device Private Key (Kyber) | RNG (System) | RAM (Stack/Heap) | Automatic (Drop) |
| **CSP-2** | Device Signing Key (Falcon) | RNG (System) | RAM (Stack/Heap) | Automatic (Drop) |
| **CSP-3** | Session Shared Secret | Key Exchange (Kyber) | RAM (Stack) | Immediate overwrite |
