# Threat Model

This document defines what PQC-IIoT assumes about adversaries and what security properties the current codebase aims to enforce.

This is a *systems* threat model: it explicitly treats the network, the broker, and local persistence as attacker-controlled unless proven otherwise.

## Actors and Capabilities

### A1 — Network attacker (remote)

Assume an attacker can:

- observe, replay, reorder, and drop traffic
- inject arbitrary packets
- attempt downgrade/TOFU by racing “first contact” messages
- exploit cost asymmetry (force expensive signature/KEM work)

### A2 — MQTT broker attacker (malicious broker)

Treat the broker as untrusted infrastructure. It can:

- publish arbitrary topics/payloads
- replay retained messages indefinitely
- rewrite key announcements
- act as a cardinality amplifier (many peer IDs, many topics)

### A3 — Local persistence attacker (filesystem write)

If an attacker can modify local files (keystore, audit log, identity), assume they can:

- truncate or rewrite logs
- roll back state to bypass replay protection
- poison keystore entries to block liveness (availability attack)

Unless the `SecurityProvider` is backed by a TPM/HSM, filesystem security is best-effort.

## Primary Threats and Current Mitigations

### T1 — Harvest-now, decrypt-later (HN-DL)

**Threat**: capture ciphertext today; attempt decryption in the future with quantum capability.

**Mitigation**: hybrid KEM uses Kyber/ML-KEM as the PQ component. The goal is to remove reliance on classical DH alone. (Note: no primitive has a proof of “quantum resistance”; security is based on current cryptanalytic consensus and conservative parameterization.)

### T2 — Identity impersonation / key announcement rewriting

**Threat**: broker or MITM republishes a valid announcement under a different peer ID, or injects forged keys to impersonate a peer.

**Mitigations**:

- strict mode (default) requires `OperationalCertificate` verification under a pinned CA key
- key announcements are signed over a canonical payload with explicit domain separation and peer-id binding
- epoch/key-id checks provide anti-rollback and collision detection

### T3 — Replay and reordering

**Threat**: attacker replays a valid encrypted command; or induces out-of-order delivery (common in field networks).

**Mitigation**: per-peer sliding replay window (bitmap) rejects duplicates while tolerating bounded reordering.

### T4 — Cross-topic / cross-protocol confusion

**Threat**: attacker re-routes a valid encrypted blob into a different MQTT topic and changes the semantic meaning at the application layer.

**Mitigation**: encrypted MQTT packets are signed over a digest that binds `sender_id + topic + encrypted_blob` under an explicit domain tag.

### T5 — Parsing and allocation DoS

**Threat**: attacker forces large allocations or pathological parsing via oversized JSON/key announcements.

**Mitigation**: hard byte limits are enforced *before* parsing/crypto for key announcements, attestation messages, and encrypted packets.

### T6 — Audit log rewriting / truncation

**Threat**: attacker with filesystem write access rewrites the audit log and recomputes any unkeyed hash chain.

**Mitigation**: audit entries are hash-chained and can be additionally signed via a `SecurityProvider` signer (meaningful only when backed by non-exportable keys in TPM/HSM).

## Known Gaps (Critical for real IIoT deployments)

These are not paper cuts; they are architectural blockers for safety/security-critical systems:

- **Secure time / monotonic counters**: without a trusted monotonic source, time-window enforcement and replay state rollback are weak.
- **Post-compromise security (PCS)**: MQTT sessions provide forward secrecy, but there is no DH ratchet / periodic re-key to recover after compromise of a current chain key.
- **CoAP transport standardization**: session-based secure CoAP exists, but OSCORE/DTLS are not implemented; full CoAP option/method binding and standardized replay context are still missing.
- **Distributed policy under partitions**: CA-signed policy/revocation updates exist, but guaranteed catch-up semantics are not implemented; fleets must define TTL/fail-closed behavior under long partitions.

The concrete invariants enforced by the codebase are specified in `security/invariants.md`.
