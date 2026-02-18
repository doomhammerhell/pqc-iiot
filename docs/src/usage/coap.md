# Secure CoAP Integration

The `SecureCoapClient` provides secure Request/Response patterns over UDP using Hybrid Encryption.

## Example: Secure GET Request

```rust
use pqc_iiot::SecureCoapClient;
use std::net::SocketAddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Client
    let client = SecureCoapClient::new()?;
    
    let server_addr: SocketAddr = "127.0.0.1:5683".parse()?;
    
    // 2. Send Encrypted GET
    // Automatically performs handshake if session keys are missing
    let response = client.get(server_addr, "sensors/temp")?;
    
    // 3. Verify Response
    // Decrypts payload and verifies Falcon signature
    let payload = client.verify_response(&response)?;
    
    println!("Response: {:?}", String::from_utf8_lossy(&payload));
    
    Ok(())
}
```


## Protocol Specification

PQC-IIoT implements **Object Security for Constrained RESTful Environments (OSCORE)**-inspired application layer security, adapted for Post-Quantum primitives.

### Packet Format (Request & Response)

The CoAP payload is replaced entirely by the PQC blob.

#### 1. Secure Request (Client -> Server)

| Section | Field | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- |
| **Header** | **Version** | 1 | `0x01` |
| | **Capsule** | 1088 | Kyber-768 Ciphertext (Key Exchange) |
| **Body** | **Nonce** | 12 | AES-GCM Nonce |
| | **Ciphertext** | $Len(P) + 16$ | AES-256-GCM Encrypted Payload |
| **Auth** | **Signature** | ~666 | Falcon-512 Signature of entire packet |

**Total Overhead**: ~1770 bytes + Payload.
*Note: This necessitates specific CoAP Block-Wise Transfer (Block1) support or high-MTU networks (WiFi/Ethernet).*

#### 2. Secure Response (Server -> Client)

Since the session key is established in the Request, the Response does NOT need a new Kyber Capsule. It reuses the session key derived from the Request (or a derived session key).

| Section | Field | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- |
| **Body** | **Nonce** | 12 | New AES-GCM Nonce |
| | **Ciphertext** | $Len(P) + 16$ | AES-256-GCM Encrypted Response |
| **Auth** | **Signature** | ~666 | Falcon-512 Signature |

**Total Overhead**: ~680 bytes + Payload.

### Handshake Flow

1.  **Client** generates ephemeral Kyber KeyPair (or uses static if pre-provisioned).
2.  **Client** encapsulates against Server's Static Public Key -> `Capsule`, `SharedSecret`.
3.  **Client** encrypts Request Payload with `SharedSecret`.
4.  **Client** signs `[Capsule | Nonce | Ciphertext]` with Client's Falcon Private Key.
5.  **Server** receives, verifies Falcon Signature (Authentication).
6.  **Server** decapsulates `Capsule` -> `SharedSecret`.
7.  **Server** decrypts Payload.
8.  **Server** processes request, generates Response.
9.  **Server** encrypts Response with `SharedSecret` (and new Nonce).
10. **Server** signs Response.

