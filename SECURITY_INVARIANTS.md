# Security Invariants (Contract)

This repository targets adversarial Industrial IoT (IIoT) deployments: untrusted networks, untrusted brokers, long partitions, and periodic endpoint compromise.

This document is a **security contract**. Any change that weakens an invariant MUST either:

- be explicitly justified (threat model change), and
- ship with new/updated regression tests proving the intended behavior.

If you cannot test an invariant (e.g., hardware-backed anti-rollback), you must make the assumption explicit and **fail closed** for the operations that depend on it.

---

## 0. Threat Model and Trust Boundaries

### Actors

- **Device**: endpoint running `pqc-iiot`.
- **Peer**: another device/gateway.
- **Broker** (MQTT) / **Network** (UDP/CoAP): fully adversarial.
- **Control plane**: CA/gateway service that publishes signed fleet policy and revocations.
- **Local storage**: may be writable and rollbackable under attacker with host access.

### Adversary capabilities

- Network MITM: replay, reorder, inject, drop, delay.
- Broker compromise: topic re-routing, retained message substitution, message amplification.
- Endpoint compromise (transient): attacker reads process memory and filesystem; may later lose access.
- Filesystem rollback: attacker restores previous sealed blobs and keystore files.

### Non-goals (explicit)

- A software-only provider is **not** a root-of-trust. It can provide best-effort persistence and encryption-at-rest, but it cannot prevent rollback by an attacker with filesystem write access.
- The `SoftwareTpm` model is a simulation for functional flows; it must not be treated as a TPM-grade attestation root.

---

## 1. Provider / Persistence Invariants (Anti-Rollback)

### 1.1 Rollback resistance is an explicit capability

**Invariant:** Any security decision that relies on monotonic state across restarts MUST be gated by `SecurityProvider::is_rollback_resistant_storage() == true`.

Rationale: Without a sealed monotonic counter (TPM NV / TEE counter / HSM monotonic storage / remote append-only service), an attacker can roll back state by restoring old blobs.

Concrete gates in the MQTT stack:

- Fleet policy sequence floors: `pqc-iiot:fleet-policy-seq:v1:<storage_id>`
- Revocation sequence floors: `pqc-iiot:revocation-seq:v1:<storage_id>`
- Secure time floor: `pqc-iiot:time-floor:v1:<storage_id>`

**Fail-closed rule:** If fleet policy requires rollback-resistant storage, and the provider is not rollback-resistant, the client MUST fail closed for:

- new session establishment / rekey
- encrypted sends (when policy requires sessions)
- acceptance of policy updates that enforce monotonic security gates

Regression coverage:

- `tests/mqtt_invariants.rs::mqtt_policy_v2_fails_closed_without_rollback_resistant_storage`
- `tests/mqtt_invariants.rs::mqtt_policy_rollback_detected_via_sealed_seq_floor`

### 1.2 Sealed monotonic counters are monotonic by construction

**Invariant:** A sealed monotonic counter MUST never decrease.

Implementation note:

- Software providers implement monotonic counters via sealed blobs (best-effort, rollbackable).
- Hardware providers must override monotonic counter operations to use rollback-resistant primitives.

---

## 2. Fleet Policy / Revocation Invariants (Partitions)

### 2.1 Policy update stream is signed, monotonic, and partition-aware

**Invariant:** Fleet policy updates (`FleetPolicyUpdate`) are accepted only if:

- signature verifies under the pinned CA key, and
- `seq` increases monotonically (local state), and
- rollback is detected via a sealed monotonic floor when rollback-resistant storage is available.

**Invariant:** Revocation updates (`RevocationUpdate`) are accepted only if:

- signature verifies under the pinned CA key, and
- `seq` increases monotonically, and
- rollback is detected via a sealed monotonic floor when rollback-resistant storage is available.

### 2.2 Operational semantics under long partitions must be explicit

This repository separates operation classes:

- **High-risk**: session establishment, key rollover, accepting new trust material.
- **Medium-risk**: sending encrypted application data (telemetry/commands) depending on policy.
- **Low-risk**: local logging/metrics, receiving already-established session traffic (bounded).

**Invariant:** When policy is stale (TTL exceeded under secure time), the client MUST fail closed for high-risk operations.

Implementation note:

- TTL enforcement is only meaningful if `SecureTimeFloor` is rollback-resistant; otherwise it becomes best-effort DoS signaling.

**Invariant:** When a policy requires a minimum revocation sequence, the client MUST fail closed until caught up.

Regression coverage:

- `tests/control_plane_sync.rs::control_plane_serves_policy_sync_requests`
- `tests/mqtt_invariants.rs::mqtt_policy_v2_fails_closed_when_revocation_seq_behind`
- `tests/mqtt_invariants.rs::mqtt_policy_v2_ttl_stale_blocks_new_handshakes`

---

## 3. MQTT Protocol Invariants

### 3.1 Key announcements bind peer identity and topic context

**Invariant:** Key announcements are signed over a canonical payload that includes `peer_id` and key material. A signed announcement MUST NOT be replayable under another peer id/topic.

Regression coverage:

- `tests/integration_tests.rs::test_key_announcement_binds_peer_id`
- `tests/integration_tests.rs::test_malicious_key_announcement_rejected`

### 3.2 Domain separation for signatures

**Invariant:** Every signed message type MUST include explicit domain separation and bind the relevant routing context (MQTT topic, sender id).

Examples:

- Key announcements: `pqc-iiot:key-announce:v2`
- Encrypted MQTT v1 messages: digest binds `sender_id` + `topic` + blob under `pqc-iiot:mqtt-msg:v1`
- Session control messages: domain-separated payloads bind initiator/responder ids and target topics.

Regression coverage:

- `tests/mqtt_invariants.rs::mqtt_signature_binds_topic`

### 3.3 Anti-replay: cheap reject path, then bounded out-of-order acceptance

**Invariant:** The receiver MUST reject replays deterministically.

There are two replay domains:

1) **v1 per-message hybrid encryption**: monotonically increasing `sequence_number` with a bounded replay window.
2) **session traffic**: per-chain message numbers + bounded skipped-key window; (DH-ratchet) chain transitions must not allow rollback.

### 3.4 Asymmetric-cost DoS containment

**Invariant:** The implementation MUST provide a cheap reject path before expensive crypto:

- size limits before parsing (`serde_json::from_slice`)
- peer id validation before allocation
- token bucket budgets before signature verification / KEM / decrypt
- global peer budget caps to prevent cardinality explosions

Regression expectations:

- bounded memory growth (no unbounded HashMap growth from wire-controlled IDs)
- bounded CPU usage under sustained invalid traffic (rate limiting emits drops)

---

## 4. MQTT Sessions Invariants (Forward Secrecy + PCS)

### 4.1 Session handshake is authenticated and binds identities

**Invariant:** Session establishment is authenticated by long-term Falcon identities and bound to:

- initiator id, responder id
- handshake topics
- session id and per-peer monotonic `session_seq`

This prevents broker-mediated session splicing and downgrade/replay of old session init messages.

### 4.2 PCS requires a DH/KEM-driven ratchet, not only a symmetric chain

**Invariant:** A symmetric-only chain (`CK -> HKDF -> next_CK`) is forward-secret but not PCS:

- if the current chain key is compromised, the attacker can derive future keys until a rekey event.

**Required property:** The session must periodically incorporate fresh asymmetric shared secrets into the root key (DH or KEM ratchet) to regain secrecy after compromise ends.

In this codebase, the design target is:

- **DH-ratchet** inside sessions (PCS against classical compromise).
- **KEM refresh** via session re-handshake policy (PQC refresh, and PCS reset when bidirectional traffic is absent).

Regression coverage should include:

- topic binding (ciphertext replayed on another topic must fail)
- replay rejection (duplicate packet must fail)
- bounded out-of-order acceptance within a skip window

---

## 5. CoAP Security Invariants

**Invariant:** Signed payloads are authenticity-only and MUST NOT be described as transport security.

**Invariant:** Custom session encryption is not OSCORE/DTLS and MUST be marked experimental.

For IIoT-critical deployments, the “industrial path” is:

- OSCORE (RFC 8613), typically with EDHOC (RFC 9528), or
- DTLS, when OSCORE is not viable.

See `docs/coap.md`.

---

## 6. Attestation Invariants

**Invariant:** Attestation MUST NOT be treated as a root-of-trust unless backed by a real TPM/TEE chain.

The current model is a functional placeholder:

- software provider signs quotes with the identity signing key and uses synthetic PCRs
- the “AK == sig_pk” binding is a simplification

Any production-grade claim requires:

- EK/AK separation, manufacturer chain, PCR policy, event log, and verifier policy definition.

