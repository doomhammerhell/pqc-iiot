# Secure MQTT Integration

The `SecureMqttClient` wraps standard MQTT functionality with post-quantum security layers.

## Example: Secure Publisher

```rust
use pqc_iiot::SecureMqttClient;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Client
    // This automatically generates keys or loads them from 'pqc-data/identity_client_id.json'
    let mut client = SecureMqttClient::new("broker.hivemq.com", 1883, "sensor_01")?;

    // 2. Perform Key Exchange
    // Publishes public keys to 'pqc/keys/sensor_01'
    client.bootstrap()?;

    // 3. Publish Encrypted Data
    let payload = b"{\"temp\": 25.5, \"unit\": \"C\"}";
    
    // Encrypts using Kyber+AES and Signs using Falcon
    client.publish_encrypted("sensors/data", payload)?;
    
    // 4. Processing Loop
    loop {
        // Polls implementation handles decryption and handshake messages
        client.poll(|topic, payload| {
            println!("Received on {}: {:?}", topic, String::from_utf8_lossy(payload));
        })?;
        std::thread::sleep(Duration::from_secs(1));
    }
}
```

## Critical Configuration

To enable **Strict Authentication**, you must pre-load trusted identities:

```rust
// Load trusted keys from a secure source
let trusted_keys = load_trusted_keys(); 
client.add_trusted_peer("controller_01", trusted_keys.falcon_pk);
```

## Protocol Specification

This section details the byte-level packet formats used for secure communication over MQTT.

### Topic Structure

- **`pqc/keys/{client_id}`**: Retained messages containing the client's Public Keys.
- **`{app_topic}`**: Application data topics (e.g., `sensors/temp`). Data on these topics is encrypted.

### 1. Key Advertisement Packet (Retained)

Published to `pqc/keys/{client_id}` on startup.

| Offset | Field | Type | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- | :--- |
| 0 | **Magic** | `u16` | 2 | `0x5051` ("PQ") |
| 2 | **Version** | `u8` | 1 | `0x01` |
| 3 | **Kyber PK** | `[u8]` | 1184 | Kyber-768 Public Key |
| 1187 | **Falcon PK** | `[u8]` | 897 | Falcon-512 Public Key |
| 2084 | **Signature** | `[u8]` | 666+ | Falcon Signature of previous fields |

Total Size: ~2750 bytes.

### 2. Encrypted Data Packet

Published to application topics.

| Offset | Field | Type | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- | :--- |
| 0 | **Version** | `u8` | 1 | `0x01` |
| 1 | **Capsule Len** | `u16` (BE) | 2 | Length of Kyber Capsule ($L_C$) |
| 3 | **Capsule** | `[u8]` | $L_C$ (~1088) | Kyber Encapsulated Secret |
| $3+L_C$ | **Nonce** | `[u8]` | 12 | AES-GCM Nonce |
| $15+L_C$ | **Ciphertext** | `[u8]` | $L_P + 16$ | AES-256-GCM Encrypted Payload + Tag |

**Decryption Flow**:
1.  Subscriber receives packet.
2.  Extracts **Capsule** and uses own **Kyber SK** to decapsulate -> **Shared Secret**.
3.  Derives AES-256 Key from Shared Secret.
4.  Decrypts **Ciphertext** using **Nonce** and derived Key.
5.  **Replay Check**: Decrypted payload contains a generic header with a sequence number.

### 3. Application Payload (Inside Ciphertext)

The plaintext inside the AES-GCM envelope has its own structure:

| Offset | Field | Type | Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| 0 | **Sequence** | `u64` (BE) | 8 | Monotonically increasing counter |
| 8 | **Timestamp** | `u64` (BE) | 8 | UNIX Timestamp (ms) |
| 16 | **Data** | `[u8]` | Var | Actual application data (JSON/Binary) |
| End | **Signature** | `[u8]` | Var | Falcon Signature of (Seq + Time + Data) |
