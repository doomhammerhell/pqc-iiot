# Secure CoAP Integration

This repository currently provides two CoAP security modes:

- `SecureCoapClient`: **payload authenticity** only (Falcon signature appended to the CoAP payload).
- `SecureCoapSessionClient`: **session-based confidentiality + integrity + replay protection** using an authenticated handshake and AEAD (not OSCORE/DTLS).

`SecureCoapClient` provides payload authenticity for CoAP messages by attaching a Falcon signature to the CoAP payload and verifying responses against a pinned peer public key.

It is intentionally minimal and does not provide confidentiality or replay protection.

For safety/security-critical IIoT deployments, you should run CoAP over OSCORE or DTLS (or an equivalent authenticated secure transport). The session-based mode is a pragmatic security context but is not a standards-based OSCORE/DTLS implementation.

## Example: Secure GET Request

```rust
use pqc_iiot::SecureCoapClient;
use std::net::SocketAddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Client
    //
    // IMPORTANT: you must pin the peer's Falcon public key for response verification.
    // In production, obtain this from provisioning (not from the network/broker).
    let peer_sig_pk: Vec<u8> = vec![]; // provisioned
    let client = SecureCoapClient::new()?.with_peer_sig_pk(peer_sig_pk);
    
    let server_addr: SocketAddr = "127.0.0.1:5683".parse()?;
    
    // 2. Send request (payload is signed by the client)
    let response = client.get(server_addr, "sensors/temp")?;
    
    // 3. Verify Response
    // Verifies Falcon signature using the pinned peer public key and returns the unsigned payload.
    let payload = client.verify_response(&response)?;
    
    println!("Response: {:?}", String::from_utf8_lossy(&payload));
    
    Ok(())
}
```


## Protocol Specification

This repository does not implement OSCORE/DTLS. The protocol formats below are local to this project.

### `SecureCoapClient` Payload Format (Request & Response)

The CoAP payload is:

`[message][signature][sig_len_be_u16]`

Where:

- `message` is the application payload bytes
- `signature` is a Falcon detached signature
- `sig_len_be_u16` is the signature length (big-endian)

This format is simple but incomplete for critical systems:

- it does not bind method/path/options into the signature
- it does not provide anti-replay (no nonce/counter)
- it does not provide confidentiality

If you need those properties, use OSCORE/DTLS and treat this signature layer as redundant defense-in-depth (or remove it to avoid cost).

### `SecureCoapSessionClient` Session Mode (non-OSCORE)

The session client/server (`SecureCoapSessionClient` / `SecureCoapSessionServer`) implement:

- an authenticated session handshake (Falcon signatures) on `pqc/session/init`
- hybrid forward secrecy from ephemeral Kyber + ephemeral X25519
- AEAD payload protection using AES-256-GCM with per-message key evolution
- bounded out-of-order receive using a skipped-key window (anti-replay within the session)

This is an application-level security context, not OSCORE:

- it does not define a standardized security context for CoAP options beyond what is bound in the AAD
- it does not persist session replay state across restarts (a reboot drops sessions)
