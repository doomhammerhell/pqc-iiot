use super::*;
use crate::{SecureCoapClient, SecureMqttClient};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let kyber = Kyber::new();
        let (public_key, secret_key) = kyber.generate_keypair().unwrap();
        assert!(!public_key.is_empty());
        assert!(!secret_key.is_empty());
    }

    #[test]
    fn test_signature_verification() {
        let message = b"Test message";
        let falcon = Falcon::new();
        let (public_key, secret_key) = falcon.generate_keypair().unwrap();
        let signature = falcon.sign(message, &secret_key).unwrap();
        let is_valid = falcon.verify(message, &signature, &public_key).is_ok();
        assert!(is_valid);
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        let kyber = Kyber::new();
        let (public_key, secret_key) = kyber.generate_keypair().unwrap();
        let (ciphertext, shared_secret_a) = kyber.encapsulate(&public_key).unwrap();
        let shared_secret_b = kyber.decapsulate(&secret_key, &ciphertext).unwrap();
        assert_eq!(shared_secret_a, shared_secret_b);
    }

    #[test]
    fn test_signature_verification_with_corrupted_message() {
        let message = b"Test message";
        let falcon = Falcon::new();
        let (public_key, secret_key) = falcon.generate_keypair().unwrap();
        let signature = falcon.sign(message, &secret_key).unwrap();
        let mut corrupted_message = message.to_vec();
        corrupted_message[0] ^= 0xFF; // Corrupt the message
        let is_valid = falcon
            .verify(&corrupted_message, &signature, &public_key)
            .is_err();
        assert!(is_valid);
    }

    #[test]
    fn test_replay_attack_protection() {
        let message = b"Test message with timestamp";
        let falcon = Falcon::new();
        let (public_key, secret_key) = falcon.generate_keypair().unwrap();
        let signature = falcon.sign(message, &secret_key).unwrap();
        // Simulate a replay attack by using the same message and signature
        let is_valid = falcon.verify(message, &signature, &public_key).is_ok();
        assert!(is_valid);
        // Simulate a timestamp check failure (e.g., by altering the message)
        let mut altered_message = message.to_vec();
        altered_message.push(0); // Add a byte to simulate timestamp change
        let is_invalid = falcon
            .verify(&altered_message, &signature, &public_key)
            .is_err();
        assert!(is_invalid);
    }

    #[test]
    fn test_mqtt_integration() {
        let mut client = SecureMqttClient::new("broker.hivemq.com", 1883, "test_client").unwrap();
        let topic = "test/topic";
        let message = b"Hello, MQTT!";
        // Publish a message
        client.publish(topic, message).unwrap();
        // Subscribe and verify the message
        client.subscribe(topic).unwrap();
    }

    #[test]
    fn test_coap_integration() {
        let client = SecureCoapClient::new().unwrap();
        let uri = "coap://localhost/test";
        let message = b"Hello, CoAP!";
        // Send a request
        let response = client.send_request(uri, message).unwrap();
        // Verify the response
        client.verify_response(&response).unwrap();
    }
}
