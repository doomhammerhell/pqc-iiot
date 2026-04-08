# Security Invariants (Contract)

This document is the *contract* for security-relevant behavior in PQC-IIoT. The intent is to make the system’s trust boundaries, assumptions, and “must-hold” properties explicit and regression-testable.

If a change violates an invariant, it is a **security bug**, even if unit tests still pass.

## Scope

This contract covers the reference protocol surfaces implemented in this repository:

- MQTT key announcements and encrypted payload delivery (`src/mqtt_secure.rs`)
- MQTT authenticated sessions + symmetric ratchet (forward secrecy building block) (`src/mqtt_secure.rs`)
- Provisioning-backed identity (`src/provisioning.rs`)
- Signed audit logging (`src/security/audit.rs`)
- CoAP payload authenticity shim + session-based secure mode (`src/coap_secure.rs`)

Out of scope (by design, today):

- OSCORE / DTLS transport security for CoAP (required for confidentiality + replay protection)
- Secure time / monotonic counters backed by TPM/TEE/HSM (we only implement a best-effort monotonic floor)
- Post-compromise security (PCS) for MQTT/CoAP (needs a DH ratchet / periodic re-key)

## Trust Boundaries

### 1) `SecurityProvider` boundary

Long-term secrets live behind `SecurityProvider` (`src/security/provider.rs`). Anything outside that boundary must be treated as hostile input:

- MQTT broker and network traffic
- local filesystem state (identity, keystore, audit log) unless sealed in a rollback-resistant provider

Critical deployment note:
`SecureMqttClient::new()` uses an exportable software identity for demos/tests. For production fleets,
use `SecureMqttClient::new_with_provider()` with a TPM/HSM/TEE-backed `SecurityProvider` so:

- identity keys are non-exportable, and
- sealed state (time floor, keystore anti-rollback counters, revocation sequence) is rollback-resistant.

### 2) MQTT broker is *not trusted*

Assume the broker can:

- reorder, retain, replay, and duplicate publishes
- inject arbitrary topics/payloads
- drop packets (liveness loss)

Therefore:

- no TOFU-by-accident in strict mode
- message authenticity cannot depend on broker ordering
- replay protection must be bounded and deterministic

## Invariants

### I0 — Peer identifiers are bounded and sanitized

Peer IDs appear:

- as MQTT topic suffixes (`pqc/keys/<peer_id>`)
- inside encrypted packet prefixes (`[id_len][peer_id]...`)
- as keystore hashmap keys and log/metric dimensions

**Invariant**:

- `peer_id` MUST be ASCII `[A-Za-z0-9_.-]` and `len(peer_id) <= 128`.
- Invalid IDs MUST be dropped *before* any expensive operation or state insertion.

**Enforced in**: `src/mqtt_secure.rs` (wire ID validation + early drops).

### I1 — Strict mode eliminates TOFU

**Invariant**:

- With `strict_mode=true` (default), a peer MUST NOT become trusted/ready unless:
  - an `OperationalCertificate` is present, and
  - the certificate verifies under a pinned CA public key, and
  - the certificate subject binds to `peer_id` (topic suffix), and
  - the announced keys match the certificate.

**Enforced in**: `SecureMqttClient::handle_key_exchange`.

**Regression tests**: `tests/integration_tests.rs::test_strict_mode`.

### I2 — Key announcements are identity-bound and non-malleable

**Invariant**:

- Key announcements MUST include a detached `key_signature`.
- The signature MUST verify over a canonical payload with explicit domain separation and `peer_id` binding.
- `key_epoch` MUST be monotonic per peer (anti-rollback).
- For the same `key_epoch`, `key_id` MUST be identical (epoch collision rejection).

**Enforced in**:

- canonical payload: `key_announcement_payload()` in `src/mqtt_secure.rs`
- anti-rollback: `handle_key_exchange` epoch/key_id checks

**Regression tests**:

- `tests/integration_tests.rs::test_key_announcement_binds_peer_id`
- `tests/integration_tests.rs::test_malicious_key_announcement_rejected`

### I3 — Encrypted MQTT messages have explicit domain separation and topic binding

**Invariant**:

- For encrypted MQTT packets, the signature MUST cover a digest of:
  - a protocol domain tag (`pqc-iiot:mqtt-msg:v1`)
  - `sender_id`
  - MQTT `topic`
  - `encrypted_blob`

This prevents cross-protocol confusion and topic re-routing (semantic confusion) attacks.

**Enforced in**:

- sender: `SecureMqttClient::publish_encrypted`
- receiver: `SecureMqttClient::process_notification`

**Regression tests**:

- `tests/mqtt_invariants.rs::mqtt_signature_binds_topic`

### I4 — Replay protection is bounded and supports limited reordering

MQTT delivery can be duplicated and out-of-order in real deployments. Strict monotonic sequencing is not availability-safe.

**Invariant**:

- Each peer maintains a sliding replay window (64-bit bitmap) relative to `last_sequence`.
- A sequence number MUST be accepted iff:
  - it is within the window, and
  - it has not been seen before.
- Messages older than the window MUST be rejected deterministically.

**Enforced in**: `replay_window_accept()` in `src/mqtt_secure.rs` (persisted in `PeerKeys`).

**Regression tests**:

- `tests/mqtt_invariants.rs::mqtt_replay_window_accepts_out_of_order_within_window`

### I5 — Input size limits exist before parsing / crypto

**Invariant**:

- Untrusted payloads MUST be rejected by size before any parsing or expensive cryptography.
- Limits MUST be explicit and configurable, not “implicit by broker defaults”.

**Enforced in**: `src/mqtt_secure.rs` per-message-type limits:

- key announcements
- attestation challenge/quote
- encrypted packets

### I6 — Audit log is signed if it claims tamper-evidence

A pure hash chain is *not* tamper-evident against an attacker with filesystem write access: they can rewrite the file and recompute the chain.

**Invariant**:

- If the audit log is used as evidence, each chained entry MUST be signed with a device identity key that is non-exportable in production (TPM/HSM-backed).
- If a non-exportable signer is not available, the audit log MUST be treated as best-effort observability, not forensics-grade evidence.

**Enforced in**:

- signing: `ChainedAuditLogger::new_signed()` in `src/security/audit.rs`
- consumers: `SecureMqttClient` uses the signed logger by default

### I7 — Distributed revocation updates are authenticated and monotonic

**Invariant**:

- Revocation updates MUST verify under a pinned CA signature key and be bound to the configured revocation topic.
- Updates MUST enforce monotonic `seq` to prevent rollback/replay.
- A revoked `(peer_id, key_id)` MUST NOT be able to:
  - complete a key exchange in strict mode, or
  - send encrypted messages that are accepted by receivers.

**Enforced in**:

- message format + verification: `src/security/revocation.rs`
- receiver application: `src/mqtt_secure.rs` (`handle_revocation_update`, key exchange gating, and pre-decrypt key_id checks)

**Regression tests**:

- `tests/integration_tests.rs::test_distributed_revocation_blocks_peer`

## What this contract does *not* guarantee

This project intentionally does not yet provide:

- a trusted secure time source (we only enforce a best-effort monotonic floor; validity windows remain weak without TPM/TEE/HSM)
- standardized CoAP transport security (OSCORE/DTLS); the session-based secure CoAP mode is application-level and not OSCORE
- post-compromise security (PCS) for MQTT/CoAP (no DH ratchet / periodic re-key)
- revocation removal / unrevocation semantics (revocation is monotonic and additive)

For critical IIoT deployments, treat these as **blockers**, not “nice-to-haves”.
