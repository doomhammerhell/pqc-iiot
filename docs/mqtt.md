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

This is intentionally local-policy-driven: revocation distribution is an operational problem (out-of-band channel, broker ACLs, or a control plane).

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

