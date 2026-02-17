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
