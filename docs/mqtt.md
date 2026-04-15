# Secure MQTT Client (Provisioned Trust + Hybrid KEM)

`SecureMqttClient` is a synchronous MQTT client that implements a provisioned trust model (no TOFU) and per-message hybrid encryption suitable for adversarial IIoT environments.

This page documents the protocol-level behavior (messages, state, verification rules) and the operational expectations (provisioning, key rotation, attestation).

## Threat Model (Practical)

- MQTT broker is *not* trusted for integrity (can replay, inject, reorder).
- Network is fully adversarial (MITM, replay, downgrade attempts).
- Devices may be compromised; we need an explicit rotation story and anti-rollback on identity keys.
- Post-quantum (harvest-now, decrypt-later) is assumed for long-lived confidentiality.

## Trust Model: Provisioned Identity (No TOFU)

In `strict_mode` (default), a peer's key announcement on `pqc/keys/<peer_id>` is accepted only if:

1. `operational_cert` is present and verifies under the pinned mesh CA public key (`trust_anchor_ca_sig_pk`).
2. `operational_cert.device_id == <peer_id>` (topic binding).
3. The announced keys match the certificate:
   - `kem_pk == cert.kem_pk`
   - `sig_pk == cert.sig_pk`
   - `x25519_pk == cert.x25519_pk`
   - `key_epoch == cert.key_epoch`
   - `key_id == cert.key_id`
4. `key_signature` verifies over a canonical payload bound to `<peer_id>` using the certified `sig_pk`.
5. Anti-rollback + revocation checks pass:
   - Reject if `key_epoch` is lower than what is stored locally.
   - Reject if `key_id` is locally revoked.

This eliminates broker-mediated key substitution attacks and prevents downgrade to "just trust whatever was last published".

### Provisioning Flow (Factory -> Operational)

The crate provides a minimal provisioning protocol in `pqc_iiot::provisioning`:

- `FactoryIdentity`: immutable, factory-burned identity (root of trust).
- `JoinRequest`: device proposes operational keys, signed by the factory key.
- `OperationalCa`: gateway/CA verifies allowlist + join request and issues `OperationalCertificate`.
- `OperationalCertificate`: binds device_id + (kem_pk, sig_pk, x25519_pk) + `key_epoch` + validity window.

High-level pseudo-flow:

1. Device generates operational keys (Kyber KEM, Falcon signature, X25519 static).
2. Device creates `JoinRequest` signed by the factory key.
3. Gateway validates allowlist and issues `OperationalCertificate`.
4. Device pins `trust_anchor_ca_sig_pk` and stores `OperationalCertificate`.

## Bootstrapping (`bootstrap()`)

`bootstrap()` performs:

- Connect to broker.
- Subscribe to key announcements: `${key_prefix}+` (default `pqc/keys/+`).
- Subscribe to attestation topics (directed at this client):
  - `pqc/attest/challenge/<self_id>`
  - `pqc/attest/quote/<self_id>`
- Publish a **retained** signed key announcement to `pqc/keys/<self_id>`.

In strict mode, `bootstrap()` requires that `operational_cert` is configured and matches the local identity keys; otherwise it fails fast.

## Encrypted Messaging (`publish_encrypted`)

Sending path:

1. Look up target `PeerKeys` in the keystore.
2. Attach a monotonically increasing sequence number to the plaintext.
3. Hybrid-encrypt the attached payload (see below).
4. Sign the encrypted blob with the sender's Falcon identity key.
5. Publish the signed ciphertext to the chosen MQTT topic.

Receiving path:

1. Parse sender_id framing.
2. Verify signature over the encrypted blob using sender's certified `sig_pk`.
3. Decrypt hybrid packet.
4. Enforce replay protection using per-peer `last_sequence`.
5. Deliver plaintext to the callback.

## Hybrid KEM (v1): Kyber + X25519 -> AES-256-GCM

The hybrid packet format is versioned to support evolution and algorithm agility.

Packet v1:

```
[version=1][suite=1][capsule_len:u16][kyber_capsule][x25519_eph_pk:32][nonce:12][ciphertext+tag]
```

Key derivation:

- `kyber_ss = Kyber.Decapsulate(my_kem_sk, capsule)` (32 bytes)
- `x25519_ss = X25519(my_x25519_sk, sender_eph_pk)` (32 bytes)
- `k = HKDF-SHA256(kyber_ss || x25519_ss, info="pqc-iiot:hybrid:v1:aes-gcm-key")` (32 bytes)
- `AES-256-GCM(k, nonce, aad=header, plaintext)`

Notes:

- Header bytes are used as AEAD AAD to authenticate the capsule and ephemeral key.
- Legacy (pre-versioning) Kyber-only packets are still supported for transition, but strict deployments should treat them as deprecated.

## Key Rotation, Anti-Rollback, Revocation

### Rotation

Identity rotation is modeled as issuing a new `OperationalCertificate` with a higher `key_epoch` (monotonic per device_id).

On key announcement:

- If `key_epoch` increases, the client resets replay windows and (optionally) re-runs attestation before marking the peer trusted.
- If `key_epoch` decreases, announcement is rejected (anti-rollback).

### Revocation

Local revocation is tracked in the keystore and enforced during key exchange. The API is:

- `KeyStore::revoke_key_id(peer_id, key_id)`

Revocation distribution is an operational problem. The crate implements a minimal, broker-based control plane:

- Signed revocation updates are published (retained) on `pqc/revocations/v1`.
- Clients can publish best-effort sync requests on `pqc/revocations/sync/v1` to trigger a re-publish by a gateway/CA service.

The responder side is intentionally minimal and lives in `pqc_iiot::mqtt_control_plane::MqttControlPlane`.

### Fleet Policy (Signed, Monotonic, Partition-Aware)

Fleet security policy is a CA-signed update stream (not broker-trusted configuration):

- Updates are published (retained) on `pqc/policy/v1` as `FleetPolicyUpdate`.
- Clients can publish sync requests on `pqc/policy/sync/v1`.

Policy is treated as an explicit **security gate**:

- `require_sessions`: disallows v1 per-message hybrid encryption and requires v3 forward-secure sessions (double ratchet).
- `min_revocation_seq`: fail-closed until emergency revocations are caught up.
- `ttl_secs`: when secure time is available, new handshakes and encrypted sends fail-closed once the policy becomes stale.
- `require_rollback_resistant_storage`: fail-closed unless the provider backend is rollback resistant.

## Forward-Secure Sessions (v3: Double Ratchet)

Per-message hybrid encryption (`publish_encrypted`) is simple but does **not** provide post-compromise security (PCS): if a peer identity key is compromised, historical traffic is still safe (PQC), but the attacker can forge traffic until revocation/rotation and the receiver has to verify signatures on every packet.

For critical IIoT deployments, the crate supports forward-secure authenticated sessions:

- Session establishment is authenticated by long-term Falcon identities (no broker trust).
- Initial shared secret is hybrid: Kyber (PQC) + X25519 (classical) handshake DH.
- Session traffic uses a DH-driven **double ratchet**:
  - per-message symmetric ratchet (KDF chain) for forward secrecy
  - periodic DH ratchet steps for PCS recovery after compromise ends (when bidirectional traffic exists)

**Important:** the DH ratchet step is X25519 (classical). That gives PCS against a classical attacker who is no longer on the endpoint, but it is not “post-quantum PCS”. For PQC refresh, fleets should enforce periodic session re-handshakes (Kyber + X25519) via policy (`session_rekey_after_msgs` / `session_rekey_after_secs`) until a KEM-based in-session ratchet exists.

### Handshake (topics + messages)

Session control uses directed topics:

- Initiator → Responder: `pqc/session/init/<responder_id>` (`SessionInitMessage`)
- Responder → Initiator: `pqc/session/resp/<initiator_id>` (`SessionResponseMessage`)

Both messages are JSON and include a detached Falcon signature over a canonical payload that binds:

- MQTT topic
- initiator_id, responder_id
- session_id (16 bytes)
- session_seq (monotonic per-peer init sequence)
- initiator/responder ephemeral X25519 PKs
- initiator ephemeral Kyber PK + responder Kyber ciphertext
- timestamp (informational only)

### Encrypted session packet (wire format)

Session traffic is a binary packet carried as MQTT payload:

```
[sender_id_len:u16][sender_id][v=3][session_id:16][dh_pub:32][msg_num:u32][pn:u32][ct_len:u32][ct]
```

Where:

- `dh_pub` is the sender’s current ratchet DH public key.
- `msg_num` is the message number in the current sending chain.
- `pn` is the previous chain length (Double Ratchet “PN”), used for skipped-key recovery across DH transitions.
- `ct` is AES-256-GCM ciphertext+tag, with AAD binding `(sender_id, receiver_id, topic, session_id, dh_pub, msg_num, pn)`.

### Operational notes (availability vs security)

- The responder derives its send chain only after processing the first inbound DH ratchet step; the initiator should send first.
- Long partitions are handled via retained policy/revocation updates and best-effort sync requests (`pqc/policy/sync/v1`, `pqc/revocations/sync/v1`).
- Session rekey thresholds are driven by fleet policy (`session_rekey_after_msgs`, `session_rekey_after_secs`) and trigger a fresh handshake.

### Anti-Rollback Floors (Sealed Monotonic Counters)

Critical fleets must assume filesystem compromise and rollback attempts. To model this explicitly, the client persists:

- A **secure time floor** (unix seconds) under `pqc-iiot:time-floor:v1:<storage_id>`.
- A **fleet policy sequence floor** under `pqc-iiot:fleet-policy-seq:v1:<storage_id>`.
- A **revocation sequence floor** under `pqc-iiot:revocation-seq:v1:<storage_id>`.
- A **keystore generation** bound to a sealed monotonic counter and a sealed file digest.

Semantics:

- If a sealed floor indicates a higher `seq` than the locally loaded policy/revocation state, the client **fails closed** on security-sensitive operations and requests a control-plane sync.
- Rollback resistance is only as strong as the provider backend. For software-only providers, these are best-effort signals; for TPM/HSM/TEE-backed providers, they become enforceable invariants.

## Remote Attestation (Optional, Verifier-Driven)

If a client enables `with_attestation_required(true)`:

- Certified identity is still verified, but the peer is not marked `is_trusted` / ready until attestation succeeds.
- The verifier publishes a challenge to `pqc/attest/challenge/<peer_id>` containing a fresh nonce.
- The subject responds to `pqc/attest/quote/<verifier_id>` with:
  - `subject_id`
  - `AttestationQuote { pcr_digest, nonce, signature, ak_public_key }`

Verification rule (current simplified policy):

- Nonce must match the issued challenge.
- PCR digest must match the verifier's configured `expected_pcr_digest`.
- Quote signature must verify under `ak_public_key`.
- `ak_public_key` must match the peer's certified `sig_pk` (software-provider simplification; production should use a distinct AK certified by TPM/TEE).

Only after this does the verifier set `peer.is_trusted = true` and `is_peer_ready(peer) == true`.
