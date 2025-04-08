//! Secure MQTT communication using post-quantum cryptography

use crate::{Falcon, Kyber, Result};
use heapless::Vec;
use rumqttc::{Client, EventLoop, MqttOptions, Packet, QoS};
use std::time::Duration;

/// Secure MQTT client using post-quantum cryptography
pub struct SecureMqttClient {
    client: Client,
    kyber: Kyber,
    falcon: Falcon,
    shared_secret: Vec<u8, { Kyber::SHARED_SECRET_SIZE }>,
}

impl SecureMqttClient {
    /// Creates a new secure MQTT client
    pub fn new(broker: &str, port: u16, client_id: &str) -> Result<Self> {
        let mut mqttoptions = MqttOptions::new(client_id, broker, port);
        mqttoptions.set_keep_alive(Duration::from_secs(5));

        let (client, eventloop) = Client::new(mqttoptions, 10);

        let kyber = Kyber::new();
        let falcon = Falcon::new();

        // Generate keypair and establish shared secret
        let (pk, sk) = kyber.generate_keypair()?;
        let (ciphertext, shared_secret) = kyber.encapsulate(&pk)?;

        Ok(Self {
            client,
            kyber,
            falcon,
            shared_secret,
        })
    }

    /// Publishes a secure message to a topic
    pub fn publish(&self, topic: &str, payload: &[u8]) -> Result<()> {
        // Sign the payload
        let signature = self.falcon.sign(payload, &self.shared_secret)?;

        // Create a binary payload with signature
        let mut message = Vec::new();
        message
            .extend_from_slice(payload)
            .map_err(|_| crate::Error::BufferTooSmall)?;
        message
            .extend_from_slice(&signature)
            .map_err(|_| crate::Error::BufferTooSmall)?;

        // Publish the message
        self.client
            .publish(topic, QoS::AtLeastOnce, false, message.as_slice())?;
        Ok(())
    }

    /// Subscribes to a topic and verifies incoming messages
    pub fn subscribe(&mut self, topic: &str) -> Result<()> {
        self.client.subscribe(topic, QoS::AtLeastOnce)?;

        let mut eventloop = EventLoop::new();
        loop {
            let notification = eventloop.poll().unwrap();
            if let Packet::Publish(publish) = notification {
                let payload = publish.payload;
                let (message, signature) =
                    payload.split_at(payload.len() - Falcon::MAX_SIGNATURE_SIZE);

                // Verify the signature
                self.falcon
                    .verify(message, signature, &self.shared_secret)?;

                // Process the message
                println!("Received message: {:?}", message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_publish_and_subscribe() {
        let mut client = SecureMqttClient::new("broker.hivemq.com", 1883, "test_client").unwrap();
        let topic = "test/topic";
        let message = b"Hello, MQTT!";

        // Publish a message
        client.publish(topic, message).unwrap();

        // Subscribe and verify the message
        client.subscribe(topic).unwrap();
    }

    #[test]
    fn test_signature_verification_failure() {
        let mut client = SecureMqttClient::new("broker.hivemq.com", 1883, "test_client").unwrap();
        let topic = "test/topic";
        let message = b"Hello, MQTT!";

        // Publish a message
        client.publish(topic, message).unwrap();

        // Simulate a corrupted message
        let mut corrupted_message = message.to_vec();
        corrupted_message[0] ^= 0xFF; // Flip a bit

        // Attempt to verify the corrupted message
        assert!(client
            .falcon
            .verify(&corrupted_message, &client.shared_secret)
            .is_err());
    }
}
