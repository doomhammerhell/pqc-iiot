# Performance Benchmarks & Analysis

This chapter details the performance characteristics of PQC-IIoT primitives.

## Methodology

Benchmarks are collected using `criterion` on x86_64 architecture (AVX2 enabled where applicable) and simulated for ARM Cortex-M4 (32-bit).

- **Rust Version**: 1.70+
- **Optimization Level**: `debug` (unoptimized) vs `release` (`opt-level = 3`, `lto = true`)

## Cycle Counts (Reference)

### Key Encapsulation (Kyber-768)

| Operation | x86_64 (Cycles) | ARM Cortex-M4 (Cycles) | Latency (100MHz CPU) |
| :--- | :--- | :--- | :--- |
| **KeyGen** | ~35,000 | ~420,000 | 4.2 ms |
| **Encaps** | ~45,000 | ~510,000 | 5.1 ms |
| **Decaps** | ~52,000 | ~580,000 | 5.8 ms |

### Digital Signatures (Falcon-512)

| Operation | x86_64 (Cycles) | ARM Cortex-M4 (Cycles) | Latency (100MHz CPU) |
| :--- | :--- | :--- | :--- |
| **KeyGen** | ~8,000,000 | ~120,000,000 | 1.2 s |
| **Sign** | ~300,000 | ~4,500,000 | 45 ms |
| **Verify** | ~40,000 | ~600,000 | 6.0 ms |

> **Note**: Falcon KeyGen is computationally expensive and typically performed once during provisioning or on a more powerful gateway device, not the end-node sensor.

## Stack Usage Analysis

For embedded targets (`no_std`), stack usage is critical.

| Component | Stack Usage (Approx.) | Notes |
| :--- | :--- | :--- |
| **Kyber-768 Context** | 3.5 KB | Matrices and error vectors. |
| **Falcon-512 Signature** | 32 KB | FFT recursion depth requiring large stack. |
| **Falcon-512 Config** | 6 KB | Verification only (much lighter than signing). |
| **MQTT Packet Buffer** | Configurable | Default 1KB buffer in `heapless::Vec`. |

**Recommendation**: Devices performing Falcon signing should have at least **64KB RAM**. Devices only verifying signatures can operate with **16KB RAM**.

## Latency Impact on Protocols

### MQTT Handshake (Connect + Subscribe Hybrid)

1.  **TCP Connect**: ~1 RTT
2.  **MQTT Connect**: ~1 RTT
3.  **PQC Handshake (Publish PubKey)**:
    - Payload: 1184 bytes (Kyber PK)
    - Overhead: Fragmentation on LoRaWAN/Zigbee.
    - Time: Transmission time dominates execution time on low-bandwidth links. 

### CoAP (UDP)

- **Kyber Ciphertext**: 1088 bytes.
- **Fragmentation**: exceed standard MTU (1280 bytes for IPv6 usually safe, but strict 802.15.4 frames are 127 bytes).
- **Strategy**: Use Block-wise transfer (Block2) for key exchange payloads.
