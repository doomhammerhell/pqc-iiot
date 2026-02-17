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

## Protocol Details

Unlike DTLS, which secures the transport layer, PQC-IIoT secures the **Application Payload**.
- **Request**: `[ Kyber Capsule | AES-Encrypted(Payload + Seq) | Falcon Sig ]`
- **Response**: `[ AES-Encrypted(Payload + Seq) | Falcon Sig ]`

This means metadata (Options, URI) is visible, but the data is quantum-resistant.
