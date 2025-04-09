//! Example of secure IIoT communication using post-quantum cryptography
//!
//! This example demonstrates how to use the pqc-iiot crate to establish
//! secure communication between two IIoT devices using Kyber for key
//! exchange and Falcon for message authentication.

use heapless::{String, Vec};
use pqc_iiot::{coap_secure::SecureCoapClient, mqtt_secure::SecureMqttClient};
use pqc_iiot::{Falcon, Kyber, Result};
use rand_core::OsRng;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::runtime::Runtime;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;

    // Configuração dos clientes
    let mut mqtt_client = match SecureMqttClient::new("localhost", 1883, "iiot_client") {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Erro ao criar cliente MQTT: {}", e);
            return Err(e.into());
        }
    };

    let coap_client = match SecureCoapClient::new() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Erro ao criar cliente CoAP: {}", e);
            return Err(e.into());
        }
    };

    // Configuração dos tópicos e recursos
    let mqtt_topic = "iiot/sensors/temperature";
    let coap_path = "iiot/sensors/humidity";

    // Simular leituras de sensores
    let temperature_data = b"25.5";
    let humidity_data = b"60.0";

    // Publicar dados de temperatura via MQTT
    if let Err(e) = mqtt_client.publish(mqtt_topic, temperature_data) {
        eprintln!("Erro ao publicar dados de temperatura: {}", e);
        return Err(e.into());
    }

    // Enviar dados de umidade via CoAP
    match coap_client.send_request(coap_path, humidity_data) {
        Ok(response) => {
            println!("Resposta do servidor CoAP: {:?}", response);
        }
        Err(e) => {
            eprintln!("Erro ao enviar dados de umidade: {}", e);
            return Err(e.into());
        }
    }

    // Assinar tópico MQTT para receber comandos
    if let Err(e) = rt.block_on(async {
        match mqtt_client.subscribe("iiot/commands").await {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Erro ao assinar tópico de comandos: {}", e);
                Err(e)
            }
        }
    }) {
        return Err(e.into());
    }

    // Simular recebimento de comando
    let command = b"{\"action\": \"calibrate\", \"sensor\": \"temperature\"}";
    if let Err(e) = mqtt_client.publish("iiot/commands", command) {
        eprintln!("Erro ao publicar comando: {}", e);
        return Err(e.into());
    }

    // Enviar confirmação via CoAP
    match coap_client.send_request("iiot/status", b"calibration_started") {
        Ok(response) => {
            println!("Confirmação enviada: {:?}", response);
        }
        Err(e) => {
            eprintln!("Erro ao enviar confirmação: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}
