# Cryptographic Primitives

This document provides detailed information about the cryptographic primitives implemented in PQC-IIoT.

## Table of Contents

- [Key Encapsulation](#key-encapsulation)
- [Digital Signatures](#digital-signatures)
- [Error Handling](#error-handling)
- [Security Considerations](#security-considerations)

## Key Encapsulation

The `Kyber` struct provides post-quantum key encapsulation using the CRYSTALS-Kyber algorithm.

### Key Generation

```rust
use pqc_iiot::{Kyber, Result};

fn main() -> Result<()> {
    let kyber = Kyber::new();
    let (pk, sk) = kyber.generate_keypair()?;
    Ok(())
}
```

### Key Encapsulation

```rust
use pqc_iiot::{Kyber, Result};

fn main() -> Result<()> {
    let kyber = Kyber::new();
    let (pk, sk) = kyber.generate_keypair()?;
    
    // Encapsulate a shared secret
    let (ciphertext, shared_secret) = kyber.encapsulate(&pk)?;
    
    // Decapsulate the shared secret
    let decapsulated_secret = kyber.decapsulate(&sk, &ciphertext)?;
    
    assert_eq!(shared_secret, decapsulated_secret);
    Ok(())
}
```

### Security Levels

The crate supports multiple security levels:

- `Kyber512`: 128-bit security
- `Kyber768`: 192-bit security
- `Kyber1024`: 256-bit security

## Digital Signatures

The `Falcon` struct provides post-quantum digital signatures using the Falcon algorithm.

### Key Generation

```rust
use pqc_iiot::{Falcon, Result};

fn main() -> Result<()> {
    let falcon = Falcon::new();
    let (pk, sk) = falcon.generate_keypair()?;
    Ok(())
}
```

### Signing and Verification

```rust
use pqc_iiot::{Falcon, Result};

fn main() -> Result<()> {
    let falcon = Falcon::new();
    let (pk, sk) = falcon.generate_keypair()?;
    
    let message = b"Hello, world!";
    let signature = falcon.sign(message, &sk)?;
    
    // Verify the signature
    falcon.verify(message, &signature, &pk)?;
    Ok(())
}
```

## Error Handling

The crate uses a custom error type for cryptographic operations:

```rust
pub enum Error {
    /// Invalid input parameters
    InvalidInput(String),
    /// Signature verification failed
    SignatureVerification(String),
    /// Buffer too small for operation
    BufferTooSmall,
    /// Internal cryptographic error
    CryptoError(String),
}
```

## Security Considerations

### Constant-Time Operations

All cryptographic operations are implemented in constant time to prevent timing attacks.

### Memory Management

- Zero-allocation implementations for embedded systems
- Secure memory wiping for sensitive data
- Heap allocation only when necessary

### Side-Channel Resistance

- Constant-time comparisons
- Memory access patterns independent of secret data
- Branch-free implementations where possible

## Performance Characteristics

### Key Generation

| Algorithm | Time (ms) | Memory (KB) |
|-----------|-----------|-------------|
| Kyber512  | 1.2       | 32          |
| Kyber768  | 1.8       | 48          |
| Kyber1024 | 2.4       | 64          |

### Signing and Verification

| Operation | Time (ms) | Memory (KB) |
|-----------|-----------|-------------|
| Sign      | 0.8       | 16          |
| Verify    | 0.4       | 16          |

## Best Practices

1. **Key Management**
   - Rotate keys regularly
   - Store keys securely
   - Use appropriate key sizes

2. **Error Handling**
   - Always check return values
   - Handle errors appropriately
   - Don't expose sensitive information

3. **Memory Safety**
   - Use zeroize for sensitive data
   - Minimize heap allocations
   - Clear memory after use

## Examples

See the [examples directory](../examples/) for complete usage examples. 