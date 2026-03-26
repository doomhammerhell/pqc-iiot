use pqc_iiot::client_state::PqcClient;
use pqc_iiot::security::provider::SoftwareSecurityProvider;
use pqc_iiot::{Kyber, Falcon};
use pqc_iiot::crypto::traits::{PqcKEM, PqcSignature};

#[test]
fn test_client_state_machine_deep_flow() {
    // 1. Setup Provider with Keys (Simulating Factory State)
    let (k_pk, k_sk) = Kyber::new().generate_keypair().unwrap();
    let (f_pk, f_sk) = Falcon::new().generate_keypair().unwrap();
    
    let provider = Box::new(SoftwareSecurityProvider::new(
        k_sk, k_pk, f_sk, f_pk
    ));

    // 2. Initialize Unprovisioned
    let client = PqcClient::new(provider);
    
    // 3. Provision (Generates Join Request, validates against "CA")
    let _join_req = client.generate_join_request("device_serial_001").expect("Provisioning request failed");
    
    // Simulate CA Response (In a real test, verifying the signature of join_req would be good)
    let cert = b"OperationalCertificate_Trusted".to_vec();
    let client = client.complete_provisioning(cert).expect("Provisioning completion failed");
    
    // 4. Connect (Simulates 3-way KEM Handshake from the Network perspective)
    let (client_hello, ephemeral_sk) = client.generate_connect_request().expect("Connect request failed");
    
    // Simulate Server: Encapsulate to Client's Ephemeral PK (ClientHello)
    // The server would send back a Ciphertext (ServerHello) and derive the Shared Secret.
    #[cfg(feature = "kyber")]
    let (server_hello, _server_shared_secret) = {
         let kyber = Kyber::new();
         kyber.encapsulate(&client_hello).expect("Server encapsulation failed")
    };
    #[cfg(not(feature = "kyber"))]
    let (server_hello, _server_shared_secret) = (vec![], vec![]);

    let mut client = client.complete_connection("gateway.iot.local", &server_hello, &ephemeral_sk).expect("Connection completion failed");
    
    // Verify Session ID format
    assert!(client.session_id().starts_with("session_gateway.iot.local_"));
    
    // 5. Publish (Uses Ratchet Encryption)
    let payload = b"Sensitive Telemetry Data";
    let encrypted = client.publish("sensors/temp", payload).expect("Publish failed");
    
    // Ciphertext should be larger than payload (Header + Tag + Nonce)
    assert!(encrypted.len() > payload.len());
    
    // 6. Disconnect
    let client = client.disconnect();
    
    // Can't publish anymore (compile-time check, but we can verify typestate by successful drop)
    drop(client);
}
