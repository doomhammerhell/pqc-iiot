# Formal Security Analysis & Verification

## Constant-Time Execution (Side-Channel Resistance)

PQC-IIoT is hardened against timing side-channel attacks. A key principle is that the execution time of cryptographic operations must be independent of secret inputs (private keys, shared secrets).

### Trapdoor Sampling (Falcon)
The most critical component for timing attacks in Falcon is the Gaussian sampler used during signature generation. PQC-IIoT relies on the constant-time implementation provided by `pqcrypto-falcon` (based on the reference C implementation or optimized assembly).

**Verification**:
- **Execution Paths**: Independent of the sign of coefficients.
- **Table Lookups**: Access patterns to pre-computed tables (e.g., for FFT or Gaussian CDF) are uniform or data-independent.

### Comparison Operations (Kyber)
During decryption (decapsulation), the comparison of re-encrypted ciphertexts (`c` vs `c'`) must be constant-time to prevent chosen-ciphertext attacks (e.g., exploiting partial decryption failures).

```rust
// Pseudocode for constant-time comparison
fn verify(a: &[u8], b: &[u8]) -> bool {
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y; // Bitwise OR accumulates differences
    }
    result == 0 // Check if accumulator is zero
}
```

## Memory Safety (Rust Guarantees)

PQC-IIoT leverages Rust's type system to eliminate entire classes of memory safety vulnerabilities common in C/C++ implementations (e.g., buffer overflows, use-after-free).

### Ownership & Borrowing
- **Zero-Copy Parsing**: Use of `&[u8]` slices with strict lifetimes ensures memory is valid during parsing.
- **Race Condition Prevention**: `Send` and `Sync` traits enforce thread safety at compile time, critical for the `SecurityProvider` trait shared across threads.

### Bounds Checking
All array accesses in Rust are bounds-checked by default. For performance-critical loops (e.g., NTT), we rely on iterator combinators (`zip`, `chunks`) which elide bounds checks safely while guaranteeing correctness.

## Fuzzing & Property-Based Testing

Beyond formal proofs, we empirically verify security properties using fuzzing.

### Targets
1.  **Packet Parsing**: `SecureMqttClient::poll` is fuzzed with random byte streams to ensure no panic or memory exhaustion occurs on malformed packets.
2.  **Ciphertext Malleability**: `hybrid::decrypt` is fuzzed with bit-flipped ciphertexts to ensure the authentication tag (AES-GCM) or FO-transform check (Kyber) consistently rejects invalid inputs.

### Corpus
A persistent corpus of valid and invalid packets is maintained to prevent regression of known edge cases.
