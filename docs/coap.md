# CoAP Security (What Exists vs. What Is “Industrial”)

This crate currently exposes **two CoAP security modes** under `pqc_iiot::coap_secure` when `coap-std` is enabled:

1. `SecureCoapClient`: **signed payloads** (authenticity only).
2. `SecureCoapSessionClient` / `SecureCoapSessionServer`: a **custom session + symmetric ratchet** that provides confidentiality + integrity + replay protection at the application layer.

Neither mode is a standards-compliant replacement for **OSCORE (RFC 8613)** or **DTLS**. For critical IIoT deployments where interoperability and compliance matter, OSCORE/DTLS is still the correct transport/security boundary.

## Threat Model (Practical)

- The network is adversarial: MITM, replay, reordering, injection.
- UDP transport provides no integrity/confidentiality by itself.
- You must assume loss, duplication, and reordering.
- Identity must be explicit (pinned keys or provisioning-backed certs); TOFU is not a “critical” baseline.

## Mode A: Signed Payloads (`SecureCoapClient`)

This mode signs the application payload and appends a detached Falcon signature:

```
[message][signature][sig_len_be_u16]
```

### Properties

- Provides **end-to-end authenticity** *if* the peer’s Falcon public key is pinned.
- Does **not** provide confidentiality.
- Does **not** provide replay protection (beyond whatever the application does at higher layers).
- Does **not** protect CoAP headers/options (only the payload).

### Usage Sketch

```rust
use pqc_iiot::coap_secure::SecureCoapClient;
use std::net::SocketAddr;

let server: SocketAddr = "127.0.0.1:5683".parse().unwrap();

// Client generates its own signing keys on creation.
let mut client = SecureCoapClient::new().unwrap()
    .with_peer_sig_pk(/* pinned server Falcon pk */ vec![]);

let resp = client.get(server, "sensors/temp").unwrap();
let plaintext = client.verify_response(&resp).unwrap();
```

## Mode B: Custom Secure Sessions (`SecureCoapSessionClient`)

This mode implements an authenticated session handshake over a fixed CoAP path and then encrypts subsequent payloads using:

- Ephemeral Kyber KEM + ephemeral X25519 to derive initial chain keys.
- A symmetric ratchet (HKDF) to evolve message keys.
- AES-256-GCM for AEAD encryption.
- A skipped-key window to tolerate bounded out-of-order delivery.
- AAD binds the ciphertext to `(sender_id, receiver_id, code, path, token, session_id, msg_num)`.

### Properties

- Provides **confidentiality + integrity** of payloads after session establishment.
- Provides **anti-replay** and bounded out-of-order tolerance.
- Is not interoperable: **not OSCORE/DTLS** (no standards-based security context, no COSE/OSCORE option, no DTLS record layer).

### Usage Sketch

```rust
use pqc_iiot::coap_secure::SecureCoapSessionClient;
use std::net::SocketAddr;

let server: SocketAddr = "127.0.0.1:5683".parse().unwrap();

// peer_sig_pk must be pinned (server Falcon pk).
let mut client = SecureCoapSessionClient::new("device-1", "gw-1", /* peer_sig_pk */ vec![])
    .unwrap();

client.connect(server).unwrap();
let resp = client.get(server, "test/resource").unwrap();
assert!(!resp.message.payload.is_empty());
```

## “Industrial” Path (OSCORE/DTLS)

If the release target is **critical IIoT**, the correct endpoint is not “custom crypto in a CoAP module”; it is a **standards-defined transport/security context** with explicit compliance story:

- **OSCORE** for CoAP over UDP, typically with **EDHOC** for key establishment.
- **DTLS** for securing UDP transport when OSCORE is not viable.

This crate currently treats OSCORE/DTLS as out-of-scope for the `coap-std` implementation and documents the custom session mode as a practical building block, not an interoperability baseline.

If you want this repository to be “market standard”, the next concrete engineering step is to add an OSCORE/DTLS backend (feature-gated) and make the custom session mode explicitly “experimental / internal”.
