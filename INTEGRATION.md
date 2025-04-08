# Integration Guide for PQC-IIoT

This guide provides detailed instructions on how to integrate the `pqc-iiot` crate with MQTT and CoAP networks for secure communication in IIoT applications.

## MQTT Integration

### Setting Up

1. **Add Dependency**: Ensure `rumqttc` is included in your `Cargo.toml`.

```toml
[dependencies]
rumqttc = "0.10"
```

2. **Initialize Secure MQTT Client**:

```rust
use pqc_iiot::SecureMqttClient;

let mut client = SecureMqttClient::new("broker.hivemq.com", 1883, "client_id").unwrap();
```

3. **Publish and Subscribe**:

```rust
let topic = "test/topic";
let message = b"Hello, MQTT!";

// Publish a message
client.publish(topic, message).unwrap();

// Subscribe to a topic
client.subscribe(topic).unwrap();
```

## CoAP Integration

### Setting Up

1. **Add Dependency**: Ensure `coap-lite` is included in your `Cargo.toml`.

```toml
[dependencies]
coap-lite = "0.9"
```

2. **Initialize Secure CoAP Client**:

```rust
use pqc_iiot::SecureCoapClient;

let client = SecureCoapClient::new().unwrap();
```

3. **Send and Verify Requests**:

```rust
let uri = "coap://localhost/test";
let message = b"Hello, CoAP!";

// Send a request
let response = client.send_request(uri, message).unwrap();

// Verify the response
client.verify_response(&response).unwrap();
```

## Security Considerations

- Ensure that all messages are signed and verified using Falcon.
- Use Kyber for key encapsulation to establish shared secrets.
- Implement replay attack protection by adding timestamps to messages.

## Examples

Refer to the `examples/` directory for real-world examples of devices exchanging secure messages using the `pqc-iiot` crate.

## Benchmarks

To benchmark the performance of the `pqc-iiot` crate, compare it with non-post-quantum solutions by measuring execution times and memory usage.

---

This guide should help you integrate the `pqc-iiot` crate into your IIoT applications, ensuring secure communication using post-quantum cryptography. 