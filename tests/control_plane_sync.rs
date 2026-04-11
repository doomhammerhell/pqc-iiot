use pqc_iiot::crypto::traits::PqcSignature;
use pqc_iiot::mqtt_control_plane::MqttControlPlane;
use pqc_iiot::mqtt_secure::SecureMqttClient;
use pqc_iiot::security::policy::FleetPolicyUpdate;
use pqc_iiot::Falcon;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod common;

#[test]
fn control_plane_serves_policy_sync_requests() -> Result<(), Box<dyn std::error::Error>> {
    let port = 29860;
    common::start_mqtt_broker(port);
    let suffix: u32 = rand::random();

    let falcon = Falcon::new();
    let (ca_pk, ca_sk) = falcon.generate_keypair().expect("ca keygen");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut policy = FleetPolicyUpdate {
        version: FleetPolicyUpdate::VERSION_V2,
        seq: 1,
        issued_at: now,
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
    policy.sign(&ca_sk, "pqc/policy/v1")?;

    // Spawn a minimal control-plane responder that will serve the policy when clients request sync.
    let mut cp = MqttControlPlane::new("localhost", port, &format!("cp_{}", suffix));
    cp.set_policy_update(policy);
    thread::spawn(move || {
        let _ = cp.run();
    });

    // Client that pins the CA key so it can verify policy updates.
    let client_id = format!("alice_cp_{}", suffix);
    let mut alice = SecureMqttClient::new("localhost", port, &client_id)?
        .with_trust_anchor_ca_sig_pk(ca_pk)
        .with_strict_mode(false);
    alice.bootstrap()?;

    let topic = format!("secure/cp_sync_test_{}", suffix);
    let target_id = format!("bob_cp_{}", suffix);

    // Wait until the policy applies; once it does, publish_encrypted must fail closed without a session.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        alice.poll(|_, _| {})?;
        let err = alice.publish_encrypted(&topic, b"X", &target_id);
        if let Err(e) = err {
            let msg = format!("{e:?}");
            if msg.contains("Fleet policy requires sessions") {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(20));
    }

    let err = alice
        .publish_encrypted(&topic, b"BLOCKED", &target_id)
        .expect_err("expected policy to require sessions via sync responder");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Fleet policy requires sessions"),
        "unexpected error: {msg}"
    );

    Ok(())
}
