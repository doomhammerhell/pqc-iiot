use pqc_iiot::crypto::traits::PqcSignature;
use pqc_iiot::mqtt_secure::SecureMqttClient;
use pqc_iiot::Falcon;
use rumqttc::{Client as RumqttClient, Event, MqttOptions, Packet, QoS};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

mod common;

fn mqtt_msg_digest(sender_id: &str, topic: &str, encrypted_blob: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pqc-iiot:mqtt-msg:v1");
    hasher.update((sender_id.len() as u16).to_be_bytes());
    hasher.update(sender_id.as_bytes());
    hasher.update((topic.len() as u16).to_be_bytes());
    hasher.update(topic.as_bytes());
    hasher.update((encrypted_blob.len() as u32).to_be_bytes());
    hasher.update(encrypted_blob);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn publish_raw(topic: &str, port: u16, payload: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = MqttOptions::new("raw_pub", "localhost", port);
    opts.set_clean_session(true);
    let (mut pub_client, mut pub_conn) = RumqttClient::new(opts, 10);
    let pub_handle = std::thread::spawn(move || {
        for notification in pub_conn.iter() {
            if notification.is_err() {
                break;
            }
        }
    });

    pub_client.publish(topic, QoS::AtLeastOnce, false, payload)?;
    pub_client.disconnect()?;
    drop(pub_client);
    pub_handle.join().expect("publisher thread panicked");
    Ok(())
}

fn wait_for_key_exchange(
    alice: &mut SecureMqttClient,
    bob: &mut SecureMqttClient,
    alice_id: &str,
    bob_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        alice.poll(|_, _| {})?;
        bob.poll(|_, _| {})?;
        if alice.has_peer(bob_id) && bob.has_peer(alice_id) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(format!(
        "key exchange did not converge: alice_has_bob={} bob_has_alice={}",
        alice.has_peer(bob_id),
        bob.has_peer(alice_id)
    )
    .into())
}

#[test]
fn mqtt_session_ratchet_establishes_and_binds_topic_and_rejects_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let port = 29840;
    common::start_mqtt_broker(port);
    let suffix: u32 = rand::random();

    let key_prefix = format!("pqc/session_keys_{}/", suffix);
    let topic_good = format!("secure/session_good_{}", suffix);
    let topic_bad = format!("secure/session_bad_{}", suffix);

    let alice_id = format!("alice_sess_{}", suffix);
    let bob_id = format!("bob_sess_{}", suffix);

    let mut alice = SecureMqttClient::new("localhost", port, &alice_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix);
    let mut bob = SecureMqttClient::new("localhost", port, &bob_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix);

    alice.bootstrap()?;
    bob.bootstrap()?;

    bob.subscribe(&topic_good)?;
    bob.subscribe(&topic_bad)?;

    // Wait for key exchange (TOFU) so both sides consider each other trusted.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        alice.poll(|_, _| {})?;
        bob.poll(|_, _| {})?;
        if alice.has_peer(&bob_id) && bob.has_peer(&alice_id) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(alice.has_peer(&bob_id), "Alice never learned Bob's keys");
    assert!(bob.has_peer(&alice_id), "Bob never learned Alice's keys");

    // Initiate a forward-secure session from Alice -> Bob.
    alice.initiate_session(&bob_id)?;

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        alice.poll(|_, _| {})?;
        bob.poll(|_, _| {})?;
        if alice.has_session(&bob_id) && bob.has_session(&alice_id) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(alice.has_session(&bob_id), "Alice session not established");
    assert!(bob.has_session(&alice_id), "Bob session not established");

    // Sniff the raw encrypted packet on topic_good, then replay it on:
    // - topic_bad (must fail topic binding)
    // - topic_good (must fail replay protection)
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
    let topic_good_sniff = topic_good.clone();
    let handle = std::thread::spawn(move || {
        let mut opts = MqttOptions::new("sniffer", "localhost", port);
        opts.set_clean_session(true);
        let (mut sniff_client, mut sniff_conn) = RumqttClient::new(opts, 10);
        sniff_client
            .subscribe(&topic_good_sniff, QoS::AtLeastOnce)
            .expect("sniffer subscribe");

        let mut ready_sent = false;
        for notification in sniff_conn.iter() {
            if let Ok(Event::Incoming(Packet::SubAck(_))) = notification {
                if !ready_sent {
                    let _ = ready_tx.send(());
                    ready_sent = true;
                }
                continue;
            }
            if let Ok(Event::Incoming(Packet::Publish(p))) = notification {
                if !ready_sent {
                    let _ = ready_tx.send(());
                }
                let _ = tx.send(p.payload.to_vec());
                break;
            }
        }
        let _ = sniff_client.disconnect();
    });

    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("sniffer not ready");

    alice.publish_encrypted(&topic_good, b"SESSION_OK", &bob_id)?;

    let raw_packet = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("did not sniff encrypted packet");
    handle.join().expect("sniffer thread panicked");

    // Replay on wrong topic.
    publish_raw(&topic_bad, port, raw_packet.clone())?;
    // Replay on correct topic (duplicate).
    publish_raw(&topic_good, port, raw_packet)?;

    let start = Instant::now();
    let mut got_good = 0u32;
    let mut got_bad = 0u32;
    while start.elapsed() < Duration::from_secs(3) {
        bob.poll(|t, p| {
            if t == topic_good && p == b"SESSION_OK" {
                got_good += 1;
            }
            if t == topic_bad && p == b"SESSION_OK" {
                got_bad += 1;
            }
        })?;
        if got_good >= 1 && got_bad > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert_eq!(
        got_good, 1,
        "Expected exactly one accepted plaintext on topic_good"
    );
    assert_eq!(
        got_bad, 0,
        "Expected no acceptance on topic_bad (topic binding)"
    );

    Ok(())
}

#[test]
fn mqtt_fleet_policy_require_sessions_enforced_and_updates_apply_monotonically(
) -> Result<(), Box<dyn std::error::Error>> {
    let port = 29842;
    common::start_mqtt_broker(port);
    let suffix: u32 = rand::random();

    let key_prefix = format!("pqc/policy_keys_{}/", suffix);
    let topic = format!("secure/policy_enforced_{}", suffix);

    let alice_id = format!("alice_policy_{}", suffix);
    let bob_id = format!("bob_policy_{}", suffix);

    // Mesh CA used to sign fleet policy updates.
    let falcon = Falcon::new();
    let (ca_pk, ca_sk) = falcon.generate_keypair().expect("ca keygen");

    let mut alice = SecureMqttClient::new("localhost", port, &alice_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix)
        .with_trust_anchor_ca_sig_pk(ca_pk.clone());
    let mut bob = SecureMqttClient::new("localhost", port, &bob_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix)
        .with_trust_anchor_ca_sig_pk(ca_pk);

    alice.bootstrap()?;
    bob.bootstrap()?;
    bob.subscribe(&topic)?;

    // Wait for key exchange (TOFU) so v1 encryption would work when allowed.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        alice.poll(|_, _| {})?;
        bob.poll(|_, _| {})?;
        if alice.has_peer(&bob_id) && bob.has_peer(&alice_id) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(alice.has_peer(&bob_id));
    assert!(bob.has_peer(&alice_id));

    // Apply policy seq=1: require sessions (disallow v1 fallback).
    let mut policy_1 = pqc_iiot::security::policy::FleetPolicyUpdate {
        version: pqc_iiot::security::policy::FleetPolicyUpdate::VERSION_V1,
        seq: 1,
        issued_at: 1,
        require_rollback_resistant_storage: false,
        strict_mode: false,
        attestation_required: false,
        require_sessions: true,
        min_revocation_seq: None,
        sig_verify_budget: None,
        decrypt_budget: None,
        ttl_secs: None,
        session_rekey_after_msgs: None,
        session_rekey_after_secs: None,
        signature: Vec::new(),
    };
    policy_1.sign(&ca_sk, "pqc/policy/v1")?;
    publish_raw(
        "pqc/policy/v1",
        port,
        serde_json::to_vec(&policy_1).expect("policy_1 json"),
    )?;

    let start = Instant::now();
    let mut enforced = false;
    while start.elapsed() < Duration::from_secs(3) {
        alice.poll(|_, _| {})?;
        bob.poll(|_, _| {})?;
        if alice
            .publish_encrypted(&topic, b"NO_SESSION", &bob_id)
            .is_err()
        {
            enforced = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(enforced, "expected require_sessions to block v1 publish");

    // Apply policy seq=2: allow v1 fallback again.
    let mut policy_2 = pqc_iiot::security::policy::FleetPolicyUpdate {
        version: pqc_iiot::security::policy::FleetPolicyUpdate::VERSION_V1,
        seq: 2,
        issued_at: 2,
        require_rollback_resistant_storage: false,
        strict_mode: false,
        attestation_required: false,
        require_sessions: false,
        min_revocation_seq: None,
        sig_verify_budget: None,
        decrypt_budget: None,
        ttl_secs: None,
        session_rekey_after_msgs: None,
        session_rekey_after_secs: None,
        signature: Vec::new(),
    };
    policy_2.sign(&ca_sk, "pqc/policy/v1")?;
    publish_raw(
        "pqc/policy/v1",
        port,
        serde_json::to_vec(&policy_2).expect("policy_2 json"),
    )?;

    // Now v1 publish should succeed without establishing a session.
    let start = Instant::now();
    let mut got = false;
    while start.elapsed() < Duration::from_secs(5) {
        alice.poll(|_, _| {})?;
        bob.poll(|t, p| {
            if t == topic && p == b"OK_V1" {
                got = true;
            }
        })?;
        if got {
            break;
        }
        if alice.publish_encrypted(&topic, b"OK_V1", &bob_id).is_ok() {
            // Give the receiver time to process.
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(got, "expected v1 publish to succeed after policy seq=2");

    Ok(())
}

#[test]
fn mqtt_policy_v2_fails_closed_without_rollback_resistant_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let port = 29844;
    common::start_mqtt_broker(port);
    let suffix: u32 = rand::random();

    let key_prefix = format!("pqc/policy2_keys_{}/", suffix);
    let topic = format!("secure/policy2_storage_gate_{}", suffix);

    let alice_id = format!("alice_policy2_{}", suffix);
    let bob_id = format!("bob_policy2_{}", suffix);

    let falcon = Falcon::new();
    let (ca_pk, ca_sk) = falcon.generate_keypair().expect("ca keygen");

    let mut alice = SecureMqttClient::new("localhost", port, &alice_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix)
        .with_trust_anchor_ca_sig_pk(ca_pk.clone());
    let mut bob = SecureMqttClient::new("localhost", port, &bob_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix)
        .with_trust_anchor_ca_sig_pk(ca_pk);

    alice.bootstrap()?;
    bob.bootstrap()?;
    bob.subscribe(&topic)?;

    wait_for_key_exchange(&mut alice, &mut bob, &alice_id, &bob_id)?;

    // Apply policy seq=1: require rollback-resistant storage (software provider must fail closed).
    let mut policy = pqc_iiot::security::policy::FleetPolicyUpdate {
        version: pqc_iiot::security::policy::FleetPolicyUpdate::VERSION_V2,
        seq: 1,
        issued_at: 1,
        require_rollback_resistant_storage: true,
        strict_mode: false,
        attestation_required: false,
        require_sessions: false,
        min_revocation_seq: None,
        sig_verify_budget: None,
        decrypt_budget: None,
        ttl_secs: None,
        session_rekey_after_msgs: None,
        session_rekey_after_secs: None,
        signature: Vec::new(),
    };
    policy.sign(&ca_sk, "pqc/policy/v1")?;
    publish_raw(
        "pqc/policy/v1",
        port,
        serde_json::to_vec(&policy).expect("policy json"),
    )?;

    // Wait for policy to apply: publish must fail with a storage gate error once applied.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        alice.poll(|_, _| {})?;
        bob.poll(|_, _| {})?;
        if let Err(e) = alice.publish_encrypted(&topic, b"X", &bob_id) {
            if format!("{e:?}").contains("rollback-resistant storage") {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let err = alice
        .publish_encrypted(&topic, b"BLOCKED", &bob_id)
        .expect_err("expected fail-closed without rollback-resistant storage");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("rollback-resistant storage"),
        "unexpected error: {msg}"
    );

    Ok(())
}

#[test]
fn mqtt_policy_v2_fails_closed_when_revocation_seq_behind() -> Result<(), Box<dyn std::error::Error>>
{
    let port = 29846;
    common::start_mqtt_broker(port);
    let suffix: u32 = rand::random();

    let key_prefix = format!("pqc/policy2_rev_keys_{}/", suffix);
    let topic = format!("secure/policy2_rev_gate_{}", suffix);

    let alice_id = format!("alice_policy2_rev_{}", suffix);
    let bob_id = format!("bob_policy2_rev_{}", suffix);

    let falcon = Falcon::new();
    let (ca_pk, ca_sk) = falcon.generate_keypair().expect("ca keygen");

    let mut alice = SecureMqttClient::new("localhost", port, &alice_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix)
        .with_trust_anchor_ca_sig_pk(ca_pk.clone());
    let mut bob = SecureMqttClient::new("localhost", port, &bob_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix)
        .with_trust_anchor_ca_sig_pk(ca_pk);

    alice.bootstrap()?;
    bob.bootstrap()?;
    bob.subscribe(&topic)?;

    wait_for_key_exchange(&mut alice, &mut bob, &alice_id, &bob_id)?;

    // Apply policy seq=1: require revocation catch-up.
    let mut policy = pqc_iiot::security::policy::FleetPolicyUpdate {
        version: pqc_iiot::security::policy::FleetPolicyUpdate::VERSION_V2,
        seq: 1,
        issued_at: 1,
        require_rollback_resistant_storage: false,
        strict_mode: false,
        attestation_required: false,
        require_sessions: false,
        min_revocation_seq: Some(10),
        sig_verify_budget: None,
        decrypt_budget: None,
        ttl_secs: None,
        session_rekey_after_msgs: None,
        session_rekey_after_secs: None,
        signature: Vec::new(),
    };
    policy.sign(&ca_sk, "pqc/policy/v1")?;
    publish_raw(
        "pqc/policy/v1",
        port,
        serde_json::to_vec(&policy).expect("policy json"),
    )?;

    // Wait for policy to apply: publish must fail with revocation gating once applied.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        alice.poll(|_, _| {})?;
        bob.poll(|_, _| {})?;
        if let Err(e) = alice.publish_encrypted(&topic, b"X", &bob_id) {
            if format!("{e:?}").contains("Revocation state behind") {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let err = alice
        .publish_encrypted(&topic, b"BLOCKED", &bob_id)
        .expect_err("expected fail-closed when revocation seq behind");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Revocation state behind"),
        "unexpected error: {msg}"
    );

    Ok(())
}

#[test]
fn mqtt_policy_v2_ttl_stale_blocks_new_handshakes() -> Result<(), Box<dyn std::error::Error>> {
    let port = 29848;
    common::start_mqtt_broker(port);
    let suffix: u32 = rand::random();

    let key_prefix = format!("pqc/policy2_ttl_keys_{}/", suffix);
    let topic = format!("secure/policy2_ttl_gate_{}", suffix);

    let alice_id = format!("alice_policy2_ttl_{}", suffix);
    let bob_id = format!("bob_policy2_ttl_{}", suffix);

    let falcon = Falcon::new();
    let (ca_pk, ca_sk) = falcon.generate_keypair().expect("ca keygen");

    let mut alice = SecureMqttClient::new("localhost", port, &alice_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix)
        .with_trust_anchor_ca_sig_pk(ca_pk.clone());
    let mut bob = SecureMqttClient::new("localhost", port, &bob_id)?
        .with_strict_mode(false)
        .with_key_prefix(&key_prefix)
        .with_trust_anchor_ca_sig_pk(ca_pk);

    alice.bootstrap()?;
    bob.bootstrap()?;
    bob.subscribe(&topic)?;

    wait_for_key_exchange(&mut alice, &mut bob, &alice_id, &bob_id)?;

    // Apply policy seq=1: TTL in the past -> always stale (secure time uses system unix time).
    let mut policy = pqc_iiot::security::policy::FleetPolicyUpdate {
        version: pqc_iiot::security::policy::FleetPolicyUpdate::VERSION_V2,
        seq: 1,
        issued_at: 0,
        require_rollback_resistant_storage: false,
        strict_mode: false,
        attestation_required: false,
        require_sessions: false,
        min_revocation_seq: None,
        sig_verify_budget: None,
        decrypt_budget: None,
        ttl_secs: Some(1),
        session_rekey_after_msgs: None,
        session_rekey_after_secs: None,
        signature: Vec::new(),
    };
    policy.sign(&ca_sk, "pqc/policy/v1")?;
    publish_raw(
        "pqc/policy/v1",
        port,
        serde_json::to_vec(&policy).expect("policy json"),
    )?;

    // Wait for policy to apply: publish must fail with a stale policy error once applied.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        alice.poll(|_, _| {})?;
        bob.poll(|_, _| {})?;
        if let Err(e) = alice.publish_encrypted(&topic, b"X", &bob_id) {
            if format!("{e:?}").contains("Fleet policy stale") {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let err = alice
        .publish_encrypted(&topic, b"BLOCKED", &bob_id)
        .expect_err("expected fail-closed when policy TTL is stale");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Fleet policy stale"),
        "unexpected error: {msg}"
    );

    Ok(())
}

#[test]
fn mqtt_replay_window_accepts_out_of_order_within_window() -> Result<(), Box<dyn std::error::Error>>
{
    let port = 29838;
    common::start_mqtt_broker(port);
    let suffix: u32 = rand::random();

    let topic = format!("secure/window_{}", suffix);
    let victim_id = format!("victim_window_{}", suffix);
    let alice_id = format!("alice_window_{}", suffix);

    let mut victim = SecureMqttClient::new("localhost", port, &victim_id)?;
    victim.subscribe(&topic)?;

    let falcon = Falcon::new();
    let (alice_pk, alice_sk) = falcon.generate_keypair().expect("alice keygen");
    victim.add_trusted_peer(&alice_id, alice_pk)?;

    let victim_kem_pk = victim.get_kem_public_key();
    let victim_x25519_pk = victim.get_x25519_public_key();

    // Craft two messages to the victim:
    // - send seq=3 first
    // - then send seq=2 (out-of-order but within the 64-bit window => must be accepted)
    let make_packet = |seq: u64, plaintext: &[u8]| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut attached_payload = Vec::with_capacity(8 + plaintext.len());
        attached_payload.extend_from_slice(&seq.to_be_bytes());
        attached_payload.extend_from_slice(plaintext);

        let encrypted_blob =
            pqc_iiot::hybrid::encrypt(&victim_kem_pk, &victim_x25519_pk, &attached_payload)?;

        let digest = mqtt_msg_digest(&alice_id, &topic, &encrypted_blob);
        let signature = falcon.sign(&alice_sk, &digest)?;
        let sig_len = signature.len() as u16;

        let sender_id_bytes = alice_id.as_bytes();
        let sender_id_len = sender_id_bytes.len() as u16;

        let mut message = Vec::new();
        message.extend_from_slice(&sender_id_len.to_be_bytes());
        message.extend_from_slice(sender_id_bytes);
        message.extend_from_slice(&encrypted_blob);
        message.extend_from_slice(&signature);
        message.extend_from_slice(&sig_len.to_be_bytes());
        Ok(message)
    };

    publish_raw(&topic, port, make_packet(3, b"M3")?)?;
    publish_raw(&topic, port, make_packet(2, b"M2")?)?;

    let start = Instant::now();
    let mut got_m3 = false;
    let mut got_m2 = false;
    while start.elapsed() < Duration::from_secs(3) {
        victim.poll(|t, p| {
            if t == topic && p == b"M3" {
                got_m3 = true;
            }
            if t == topic && p == b"M2" {
                got_m2 = true;
            }
        })?;
        if got_m3 && got_m2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(got_m3, "Expected to receive seq=3");
    assert!(
        got_m2,
        "Expected to accept out-of-order seq=2 within replay window"
    );

    // Duplicate seq=3 must be rejected.
    publish_raw(&topic, port, make_packet(3, b"M3_DUP")?)?;

    let start = Instant::now();
    let mut got_dup = false;
    while start.elapsed() < Duration::from_millis(300) {
        victim.poll(|t, p| {
            if t == topic && p == b"M3_DUP" {
                got_dup = true;
            }
        })?;
        if got_dup {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!got_dup, "Duplicate seq=3 must be rejected as replay");

    Ok(())
}

#[test]
fn mqtt_signature_binds_topic() -> Result<(), Box<dyn std::error::Error>> {
    let port = 29839;
    common::start_mqtt_broker(port);
    let suffix: u32 = rand::random();

    let topic_good = format!("secure/topic_good_{}", suffix);
    let topic_bad = format!("secure/topic_bad_{}", suffix);
    let victim_id = format!("victim_topic_{}", suffix);
    let alice_id = format!("alice_topic_{}", suffix);

    let mut victim = SecureMqttClient::new("localhost", port, &victim_id)?;
    victim.subscribe(&topic_good)?;

    let falcon = Falcon::new();
    let (alice_pk, alice_sk) = falcon.generate_keypair().expect("alice keygen");
    victim.add_trusted_peer(&alice_id, alice_pk)?;

    let victim_kem_pk = victim.get_kem_public_key();
    let victim_x25519_pk = victim.get_x25519_public_key();

    let mut attached_payload = Vec::with_capacity(8 + b"HELLO".len());
    attached_payload.extend_from_slice(&1u64.to_be_bytes());
    attached_payload.extend_from_slice(b"HELLO");

    let encrypted_blob =
        pqc_iiot::hybrid::encrypt(&victim_kem_pk, &victim_x25519_pk, &attached_payload)?;

    // Sign for the wrong topic, then publish on the right topic => must be rejected.
    let digest_bad = mqtt_msg_digest(&alice_id, &topic_bad, &encrypted_blob);
    let signature_bad = falcon.sign(&alice_sk, &digest_bad)?;

    let sender_id_bytes = alice_id.as_bytes();
    let sender_id_len = sender_id_bytes.len() as u16;
    let sig_len_bad = signature_bad.len() as u16;
    let mut message_bad = Vec::new();
    message_bad.extend_from_slice(&sender_id_len.to_be_bytes());
    message_bad.extend_from_slice(sender_id_bytes);
    message_bad.extend_from_slice(&encrypted_blob);
    message_bad.extend_from_slice(&signature_bad);
    message_bad.extend_from_slice(&sig_len_bad.to_be_bytes());

    publish_raw(&topic_good, port, message_bad)?;

    let start = Instant::now();
    let mut received = false;
    while start.elapsed() < Duration::from_millis(500) {
        victim.poll(|t, p| {
            if t == topic_good && p == b"HELLO" {
                received = true;
            }
        })?;
        if received {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !received,
        "Message signed for a different topic must be rejected"
    );

    // Now publish a correctly signed packet to demonstrate acceptance.
    let digest_good = mqtt_msg_digest(&alice_id, &topic_good, &encrypted_blob);
    let signature_good = falcon.sign(&alice_sk, &digest_good)?;
    let sig_len_good = signature_good.len() as u16;
    let mut message_good = Vec::new();
    message_good.extend_from_slice(&sender_id_len.to_be_bytes());
    message_good.extend_from_slice(sender_id_bytes);
    message_good.extend_from_slice(&encrypted_blob);
    message_good.extend_from_slice(&signature_good);
    message_good.extend_from_slice(&sig_len_good.to_be_bytes());

    publish_raw(&topic_good, port, message_good)?;

    let start = Instant::now();
    let mut received = false;
    while start.elapsed() < Duration::from_secs(2) {
        victim.poll(|t, p| {
            if t == topic_good && p == b"HELLO" {
                received = true;
            }
        })?;
        if received {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(received, "Correctly signed message must be accepted");

    Ok(())
}
