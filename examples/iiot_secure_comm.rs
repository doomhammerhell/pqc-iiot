//! Example of secure IIoT communication using post-quantum cryptography
//!
//! This example demonstrates how to use the pqc-iiot crate to establish
//! secure communication between two IIoT devices using Kyber for key
//! exchange and Falcon for message authentication.

use heapless::{String, Vec};
use pqc_iiot::{Falcon, Kyber, Result};
use rand_core::OsRng;

// Maximum message size for our example
const MAX_MESSAGE_SIZE: usize = 128;

/// Simulates an IIoT device that can send and receive secure messages
struct IIoTDevice {
    name: String<32>,
    kyber: Kyber,
    falcon: Falcon,
    kem_pk: Vec<u8, { Kyber::MAX_PUBLIC_KEY_SIZE }>,
    kem_sk: Vec<u8, { Kyber::MAX_SECRET_KEY_SIZE }>,
    sig_pk: Vec<u8, { Falcon::MAX_PUBLIC_KEY_SIZE }>,
    sig_sk: Vec<u8, { Falcon::MAX_SECRET_KEY_SIZE }>,
}

impl IIoTDevice {
    /// Creates a new IIoT device with the given name
    fn new(name: &str) -> Result<Self> {
        let mut device_name = String::new();
        device_name.extend_from_slice(name.as_bytes()).unwrap();

        let kyber = Kyber::new();
        let falcon = Falcon::new();

        // Generate keypairs for both KEM and signatures
        let (kem_pk, kem_sk) = kyber.generate_keypair()?;
        let (sig_pk, sig_sk) = falcon.generate_keypair()?;

        Ok(Self {
            name: device_name,
            kyber,
            falcon,
            kem_pk,
            kem_sk,
            sig_pk,
            sig_sk,
        })
    }

    /// Prepares to receive a message by providing our public key
    fn get_public_key(&self) -> &[u8] {
        &self.kem_pk
    }

    /// Encrypts and signs a message for another device
    fn send_message(
        &self,
        message: &[u8],
        recipient_pk: &[u8],
    ) -> Result<(
        Vec<u8, { Kyber::MAX_CIPHERTEXT_SIZE }>,
        Vec<u8, { Falcon::MAX_SIGNATURE_SIZE }>,
    )> {
        // Encapsulate a shared secret using recipient's public key
        let (ciphertext, _shared_secret) = self.kyber.encapsulate(recipient_pk)?;

        // Sign the ciphertext
        let signature = self.falcon.sign(&ciphertext, &self.sig_sk)?;

        Ok((ciphertext, signature))
    }

    /// Decrypts and verifies a received message
    fn receive_message(
        &self,
        ciphertext: &[u8],
        signature: &[u8],
        sender_sig_pk: &[u8],
    ) -> Result<Vec<u8, SHARED_SECRET_SIZE>> {
        // Verify the signature first
        self.falcon.verify(ciphertext, signature, sender_sig_pk)?;

        // Decrypt the message using our secret key
        self.kyber.decapsulate(&self.kem_sk, ciphertext)
    }
}

fn main() -> Result<()> {
    // Create two IIoT devices
    let device1 = IIoTDevice::new("Sensor-001")?;
    let device2 = IIoTDevice::new("Controller-001")?;

    // Simulate secure message exchange
    println!("Simulating secure communication between IIoT devices...\n");

    // Device 1 sends a message to Device 2
    let message = b"Temperature: 25.5C";
    println!("Original message: {:?}", message);

    let (ciphertext, signature) = device1.send_message(message, device2.get_public_key())?;

    println!("Message encrypted and signed.");
    println!("Ciphertext size: {} bytes", ciphertext.len());
    println!("Signature size: {} bytes", signature.len());

    // Device 2 receives and verifies the message
    let shared_secret = device2.receive_message(&ciphertext, &signature, &device1.sig_pk)?;

    println!("\nMessage successfully decrypted and verified!");
    println!("Shared secret size: {} bytes", shared_secret.len());

    Ok(())
}
