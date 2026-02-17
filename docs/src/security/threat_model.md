# Threat Model

This document outlines the threats PQC-IIoT is designed to mitigate.

## 1. "Store Now, Decrypt Later" (SNDL)

**Threat**: Attackers record encrypted traffic today, intending to decrypt it years later when a sufficiently powerful quantum computer becomes available.
**Mitigation**: Use of Kyber (KEM) ensures that session keys cannot be retroactively recovered by quantum algorithms like Shor's algorithm.

## 2. Identity Impersonation

**Threat**: An attacker attempts to masquerade as a legitimate sensor or controller to inject false data or commands.
**Mitigation**: Falcon digital signatures provide strong, quantum-resistant authentication. Strict Allow-listing of public keys prevents unauthorized devices from joining the network.

## 3. Replay Attacks

**Threat**: An attacker captures a valid command (e.g., "Open Valve") and re-transmits it later.
**Mitigation**: Encrypted packets contain a sequential counter. The receiver tracks the `last_seen` counter for each peer and rejects duplicates or out-of-order packets.

## 4. Key Extraction from Memory

**Threat**: Malware or physical access allows an attacker to dump device RAM and extract private keys.
**Mitigation**:
- **Hardware**: Integration with TPM 2.0 ensures keys are non-exportable and operations happen inside the secure element.
- **Software**: The `software` provider uses the `zeroize` crate to wipe keys from memory immediately after use or on drop.

## 5. Side-Channel Attacks (SCA)

**Threat**: Analyzing power consumption or timing to deduce private keys.
**Mitigation**:
- Underlying libraries (`pqcrypto-*`) utilize constant-time implementations where available.
- Hardware offloading (TPM) provides physical resistance to SCA.
