# Integration Guide

This document provides detailed information about integrating PQC-IIoT into your IIoT systems.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Protocol Integration](#protocol-integration)
- [Security Integration](#security-integration)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Hardware Requirements

- **Processor**: 32-bit ARM Cortex-M0+ or better
- **RAM**: Minimum 32KB, Recommended 64KB
- **Flash**: Minimum 128KB, Recommended 256KB
- **Network**: Ethernet or WiFi interface

### Software Requirements

- **Operating System**: Any (including bare-metal)
- **Rust**: Stable toolchain
- **Dependencies**: See Cargo.toml

## Installation

### Cargo Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
pqc-iiot = { version = "0.1.0", features = ["kyber", "falcon"] }
```

For embedded systems:

```toml
[dependencies]
pqc-iiot = { version = "0.1.0", features = ["embedded", "kyber", "falcon"] }
```

### Feature Flags

- `std`: Standard library support (default)
- `embedded`: `no_std` support
- `kyber`: CRYSTALS-Kyber support
- `falcon`: Falcon support
- `dilithium`: Dilithium support
- `saber`: SABER support
- `bike`: BIKE support (experimental)
- `mqtt`: MQTT client support
- `coap`: CoAP client support
- `all`: Enable all features

## Configuration

### Basic Configuration

```rust
use pqc_iiot::{Kyber, Falcon, SecureMqttClient, SecureCoapClient};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize cryptographic primitives
    let kyber = Kyber::new(KyberSecurityLevel::Kyber768);
    let falcon = Falcon::new(FalconSecurityLevel::Falcon512);

    // Initialize MQTT client
    let mqtt_client = SecureMqttClient::new("localhost", 1883, "client_id")?;

    // Initialize CoAP client
    let coap_client = SecureCoapClient::new()?;

    Ok(())
}
```

### Advanced Configuration

```rust
use pqc_iiot::{
    Kyber, Falcon, Dilithium, Saber,
    KyberSecurityLevel, FalconSecurityLevel,
    DilithiumSecurityLevel, SaberSecurityLevel,
};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure Kyber
    let kyber = Kyber::new(KyberSecurityLevel::Kyber768)
        .with_key_rotation_interval(Duration::from_secs(3600));

    // Configure Falcon
    let falcon = Falcon::new(FalconSecurityLevel::Falcon512)
        .with_hash_algorithm(HashAlgorithm::Sha256);

    // Configure Dilithium
    let dilithium = Dilithium::new(DilithiumSecurityLevel::Level3)
        .with_signature_format(SignatureFormat::Compact);

    // Configure SABER
    let saber = Saber::new(SaberSecurityLevel::Saber)
        .with_key_rotation_interval(Duration::from_secs(3600));

    // Configure MQTT client
    let mqtt_client = SecureMqttClient::new("localhost", 1883, "client_id")?
        .with_keep_alive(Duration::from_secs(60))
        .with_clean_session(true)
        .with_qos(QoS::AtLeastOnce);

    // Configure CoAP client
    let coap_client = SecureCoapClient::new()?
        .with_timeout(Duration::from_secs(5))
        .with_retransmission_count(4)
        .with_block_size(1024);

    Ok(())
}
```

## Protocol Integration

### MQTT Integration

1. **Basic Setup**
   ```rust
   use pqc_iiot::mqtt_secure::SecureMqttClient;

   fn main() -> Result<(), Box<dyn std::error::Error>> {
       let mut client = SecureMqttClient::new("localhost", 1883, "client_id")?;
       
       // Publish message
       client.publish("topic", b"payload")?;
       
       // Subscribe to topic
       client.subscribe("topic")?;
       
       Ok(())
   }
   ```

2. **Advanced Usage**
   ```rust
   // Configure QoS
   client.with_qos(QoS::ExactlyOnce);
   
   // Set will message
   client.with_will("topic", b"payload", QoS::AtLeastOnce, true);
   
   // Set authentication
   client.with_credentials("username", "password");
   ```

### CoAP Integration

1. **Basic Setup**
   ```rust
   use pqc_iiot::coap_secure::SecureCoapClient;
   use std::net::SocketAddr;

   fn main() -> Result<(), Box<dyn std::error::Error>> {
       let client = SecureCoapClient::new()?;
       let server = "127.0.0.1:5683".parse::<SocketAddr>()?;
       
       // Send request
       let response = client.get(server, "resource")?;
       
       Ok(())
   }
   ```

2. **Advanced Usage**
   ```rust
   // Configure observation
   let observer = client.observe(server, "resource")?;
   
   // Configure block-wise transfer
   client.with_block_size(1024);
   
   // Configure multicast
   client.with_multicast(true);
   ```

## Security Integration

### Key Management

1. **Key Generation**
   ```rust
   // Generate Kyber keys
   let (kyber_pk, kyber_sk) = kyber.generate_keypair()?;
   
   // Generate Falcon keys
   let (falcon_pk, falcon_sk) = falcon.generate_keypair()?;
   
   // Generate Dilithium keys
   let (dilithium_pk, dilithium_sk) = dilithium.generate_keypair()?;
   
   // Generate SABER keys
   let (saber_pk, saber_sk) = saber.generate_keypair()?;
   ```

2. **Key Storage**
   ```rust
   // Store keys securely
   key_storage.store_public_key(&kyber_pk)?;
   key_storage.store_secret_key(&kyber_sk)?;
   ```

3. **Key Rotation**
   ```rust
   // Configure automatic key rotation
   kyber.with_key_rotation_interval(Duration::from_secs(3600));
   saber.with_key_rotation_interval(Duration::from_secs(3600));
   ```

### Security Configuration

1. **TLS/DTLS Setup**
   ```rust
   // Configure TLS
   mqtt_client.with_tls_config(tls_config)?;
   
   // Configure DTLS
   coap_client.with_dtls_config(dtls_config)?;
   ```

2. **Access Control**
   ```rust
   // Configure ACL
   mqtt_client.with_acl(acl_rules)?;
   coap_client.with_acl(acl_rules)?;
   ```

## Monitoring

### Performance Monitoring

1. **Metrics Collection**
   ```rust
   // Enable metrics
   kyber.enable_metrics();
   falcon.enable_metrics();
   dilithium.enable_metrics();
   saber.enable_metrics();
   
   // Collect metrics
   let metrics = kyber.get_metrics()?;
   ```

2. **Resource Monitoring**
   ```rust
   // Monitor memory usage
   let memory_usage = get_memory_usage();
   
   // Monitor CPU usage
   let cpu_usage = get_cpu_usage();
   ```

### Security Monitoring

1. **Event Logging**
   ```rust
   // Enable security logging
   enable_security_logging();
   
   // Log security events
   log_security_event(SecurityEvent::KeyRotation);
   ```

2. **Anomaly Detection**
   ```rust
   // Configure anomaly detection
   configure_anomaly_detection(thresholds);
   
   // Monitor for anomalies
   monitor_for_anomalies();
   ```

## Troubleshooting

### Common Issues

1. **Connection Issues**
   - Check network connectivity
   - Verify server configuration
   - Review security settings

2. **Performance Issues**
   - Monitor resource usage
   - Check configuration
   - Review logs

3. **Security Issues**
   - Verify key rotation
   - Check certificates
   - Review access control

### Debugging

1. **Enable Debug Logging**
   ```rust
   // Enable debug logging
   enable_debug_logging();
   
   // Set log level
   set_log_level(LogLevel::Debug);
   ```

2. **Collect Diagnostics**
   ```rust
   // Collect system diagnostics
   let diagnostics = collect_diagnostics();
   
   // Analyze performance
   analyze_performance();
   ``` 