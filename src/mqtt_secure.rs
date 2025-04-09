//! Secure MQTT communication using post-quantum cryptography

use crate::kem::MAX_PUBLIC_KEY_SIZE;
use crate::kem::SHARED_SECRET_SIZE;
use crate::sign::MAX_SIGNATURE_SIZE;
use crate::{Error, Falcon, Kyber, Result};
use heapless::Vec;
use rumqttc::{Client, Event, EventLoop, MqttOptions, Packet, QoS};
use std::time::Duration;
use tokio::runtime::Runtime;

/// Secure MQTT client using post-quantum cryptography
pub struct SecureMqttClient {
    client: Client,
    kyber: Kyber,
    falcon: Falcon<MAX_PUBLIC_KEY_SIZE>,
    shared_secret: Vec<u8, SHARED_SECRET_SIZE>,
    public_key: Vec<u8, MAX_PUBLIC_KEY_SIZE>,
}

impl SecureMqttClient {
    /// Creates a new secure MQTT client
    pub fn new(broker: &str, port: u16, client_id: &str) -> Result<Self> {
        let mut mqttoptions = MqttOptions::new(client_id, broker, port);
        mqttoptions.set_keep_alive(Duration::from_secs(5));

        let (client, eventloop) = Client::new(mqttoptions, 10);

        let mut kyber = Kyber::new();
        let mut falcon = Falcon::new();

        // Generate keypair and establish shared secret
        let (pk, sk) = kyber.generate_keypair()?;
        let (ciphertext, shared_secret) = kyber.encapsulate(&pk)?;

        Ok(Self {
            client,
            kyber,
            falcon,
            shared_secret,
            public_key: pk,
        })
    }

    /// Publishes a secure message to a topic
    pub fn publish(&mut self, topic: &str, payload: &[u8]) -> Result<()> {
        // Sign the payload
        let signature = self.falcon.sign(payload, &self.shared_secret)?;

        // Create a binary payload with signature
        let mut message: Vec<u8, { SHARED_SECRET_SIZE + MAX_SIGNATURE_SIZE }> = Vec::new();
        message
            .extend_from_slice(payload)
            .map_err(|_| Error::BufferTooSmall)?;
        message
            .extend_from_slice(&signature)
            .map_err(|_| Error::BufferTooSmall)?;

        // Publish the message
        self.client
            .publish(topic, QoS::AtLeastOnce, false, message.as_slice())
            .map_err(|e| Error::MqttError(e.to_string()))?;
        Ok(())
    }

    /// Subscribes to a topic and verifies incoming messages
    pub async fn subscribe(&mut self, topic: &str) -> Result<()> {
        self.client
            .subscribe(topic, QoS::AtLeastOnce)
            .map_err(|e| Error::MqttError(e.to_string()))?;

        let mut mqttoptions = MqttOptions::new("subscriber", "localhost", 1883);
        mqttoptions.set_keep_alive(Duration::from_secs(5));
        let mut eventloop = EventLoop::new(mqttoptions, 10);

        while let Ok(notification) = eventloop.poll().await {
            if let Event::Incoming(Packet::Publish(publish)) = notification {
                let payload = publish.payload;
                let (message, signature) = payload.split_at(payload.len() - MAX_SIGNATURE_SIZE);

                // Verify the signature
                self.falcon
                    .verify(message, signature, &self.shared_secret)?;

                // Process the message
                println!("Received message: {:?}", message);
            }
        }

        Ok(())
    }
}

// Implement From trait for ClientError
impl From<rumqttc::ClientError> for crate::Error {
    fn from(err: rumqttc::ClientError) -> Self {
        crate::Error::ClientError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_publish_and_verify_signature() {
        let mut client = SecureMqttClient::new("broker.hivemq.com", 1883, "test_client").unwrap();
        let topic = "test/topic";
        let message = b"Hello, MQTT!";

        // Publish a message
        client.publish(topic, message).unwrap();

        // Simulate receiving the message
        let received_message = message.to_vec();
        let signature = client
            .falcon
            .sign(&received_message, &client.shared_secret)
            .unwrap();

        // Verify the signature
        assert!(client
            .falcon
            .verify(&received_message, &signature, &client.shared_secret)
            .is_ok());
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
        let signature = client
            .falcon
            .sign(&corrupted_message, &client.shared_secret)
            .unwrap();
        assert!(client
            .falcon
            .verify(&corrupted_message, &signature, &client.shared_secret)
            .is_err());
    }
}
