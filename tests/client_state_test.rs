use pqc_iiot::client_state::PqcClient;
use pqc_iiot::crypto::traits::{PqcKEM, PqcSignature};
use pqc_iiot::provisioning::FactoryIdentity;
use pqc_iiot::security::provider::SoftwareSecurityProvider;
use pqc_iiot::{Falcon, Kyber};

#[test]
fn test_client_state_machine_deep_flow() {
    // 1. Setup Provider with Keys (Simulating Factory State)
    let (k_pk, k_sk) = Kyber::new().generate_keypair().unwrap();
    let (f_pk, f_sk) = Falcon::new().generate_keypair().unwrap();

    let provider = Box::new(SoftwareSecurityProvider::new(k_sk, k_pk, f_sk, f_pk));

    // 2. Initialize Unprovisioned
    let client = PqcClient::new(provider);

    // 3. Provision (Generates Join Request, validates against "CA")
    let (factory_pk, factory_sk) = Falcon::new().generate_keypair().unwrap();
    let factory_id = FactoryIdentity::new(factory_pk, factory_sk);
    let _join_req = client
        .generate_join_request(&factory_id, "device_serial_001")
        .expect("Provisioning request failed");

    // Simulate CA Response (In a real test, verifying the signature of join_req would be good)
    let cert = b"OperationalCertificate_Trusted".to_vec();
    let client = client
        .complete_provisioning(cert)
        .expect("Provisioning completion failed");

    // 4. Connect (Simulates 3-way KEM Handshake from the Network perspective)
    let (client_hello, ephemeral_sk) = client
        .generate_connect_request()
        .expect("Connect request failed");

    // Simulate Server: parse Hybrid ClientHello = [Kyber PK][X25519 PK]
    // and reply with Hybrid ServerHello = [Kyber CT][X25519 PK].
    #[cfg(feature = "kyber")]
    let (server_hello, _server_shared_secret) = {
        let kyber = Kyber::new();
        let kyber_pk_len = client_hello.len() - 32;
        let client_k_pk = &client_hello[..kyber_pk_len];
        let client_x_pk = &client_hello[kyber_pk_len..];

        // Kyber encapsulation to client's ephemeral Kyber PK.
        let (ct, ss) = kyber
            .encapsulate(client_k_pk)
            .expect("Server encapsulation failed");

        // X25519 ECDH with client's ephemeral X25519 PK.
        let mut client_x_pk_bytes = [0u8; 32];
        client_x_pk_bytes.copy_from_slice(client_x_pk);

        let server_x_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let server_x_pk = x25519_dalek::PublicKey::from(&server_x_sk).to_bytes();
        let _x_secret =
            server_x_sk.diffie_hellman(&x25519_dalek::PublicKey::from(client_x_pk_bytes));

        let mut server_hello = Vec::with_capacity(ct.len() + 32);
        server_hello.extend_from_slice(&ct);
        server_hello.extend_from_slice(&server_x_pk);
        (server_hello, ss)
    };
    #[cfg(not(feature = "kyber"))]
    let (server_hello, _server_shared_secret) = (vec![], vec![]);

    let mut client = client
        .complete_connection("gateway.iot.local", &server_hello, &ephemeral_sk)
        .expect("Connection completion failed");

    // Verify Session ID format
    assert!(client
        .session_id()
        .starts_with("session_gateway.iot.local_"));

    // 5. Publish (Uses Ratchet Encryption)
    let payload = b"Sensitive Telemetry Data";
    let encrypted = client
        .publish("sensors/temp", payload)
        .expect("Publish failed");

    // Ciphertext should be larger than payload (Header + Tag + Nonce)
    assert!(encrypted.len() > payload.len());

    // 6. Disconnect
    let client = client.disconnect();

    // Can't publish anymore (compile-time check, but we can verify typestate by successful drop)
    drop(client);
}
