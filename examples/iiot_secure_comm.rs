//! Example of secure IIoT communication using post-quantum cryptography
//!
//! This example demonstrates how to use the pqc-iiot crate to establish
//! secure communication between two IIoT devices using Kyber for key
//! exchange and Falcon for message authentication.

use pqc_iiot::{coap_secure::SecureCoapClient, mqtt_secure::SecureMqttClient};
use std::net::SocketAddr;
// use tokio::runtime::Runtime;



fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    // let rt = Runtime::new()?;

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
    let server_addr = "127.0.0.1:5683".parse::<SocketAddr>().unwrap();

    // Simular leituras de sensores
    let temperature_data = b"25.5";
    let humidity_data = b"60.0";

    // Publicar dados de temperatura via MQTT
    if let Err(e) = mqtt_client.publish(mqtt_topic, temperature_data) {
        eprintln!("Erro ao publicar dados de temperatura: {}", e);
        return Err(e.into());
    }

    // Enviar dados de umidade via CoAP
    match coap_client.post(server_addr, coap_path, humidity_data) {
        Ok(response) => {
            println!("Resposta do servidor CoAP: {:?}", response);
        }
        Err(e) => {
            eprintln!("Erro ao enviar dados de umidade: {}", e);
            return Err(e.into());
        }
    }

    // Assinar tópico MQTT para receber comandos
    if let Err(e) = mqtt_client.subscribe("iiot/commands") {
        eprintln!("Erro ao assinar tópico de comandos: {}", e);
        return Err(e.into());
    }

    // Simular recebimento de comando
    let command = b"{\"action\": \"calibrate\", \"sensor\": \"temperature\"}";
    if let Err(e) = mqtt_client.publish("iiot/commands", command) {
        eprintln!("Erro ao publicar comando: {}", e);
        return Err(e.into());
    }

    // Enviar confirmação via CoAP
    match coap_client.post(server_addr, "iiot/status", b"calibration_started") {
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
