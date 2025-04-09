use pqc_iiot::{coap_secure::SecureCoapClient, mqtt_secure::SecureMqttClient};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::runtime::Runtime;

struct IIoTDevice {
    mqtt_client: SecureMqttClient,
    coap_client: SecureCoapClient,
    device_id: String,
}

impl IIoTDevice {
    fn new(device_id: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mqtt_client = match SecureMqttClient::new("localhost", 1883, device_id) {
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

        Ok(Self {
            mqtt_client,
            coap_client,
            device_id: device_id.to_string(),
        })
    }

    fn publish_sensor_data(
        &mut self,
        sensor_type: &str,
        value: f32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let topic = format!("sensors/{}/{}", self.device_id, sensor_type);
        let payload = format!(
            "{{\"value\": {}, \"timestamp\": {}}}",
            value,
            chrono::Utc::now().timestamp()
        );

        match self.mqtt_client.publish(&topic, payload.as_bytes()) {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Erro ao publicar dados do sensor: {}", e);
                Err(e.into())
            }
        }
    }

    fn send_actuator_command(
        &self,
        actuator_type: &str,
        command: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = format!("actuators/{}/{}", self.device_id, actuator_type);

        match self.coap_client.send_request(&path, command.as_bytes()) {
            Ok(response) => {
                println!("Resposta do atuador: {:?}", response);
                Ok(())
            }
            Err(e) => {
                eprintln!("Erro ao enviar comando para o atuador: {}", e);
                Err(e.into())
            }
        }
    }

    fn discover_resources(&self) -> Result<(), Box<dyn std::error::Error>> {
        let resources = [
            "sensors/temperature",
            "sensors/humidity",
            "actuators/led",
            "config/network",
        ];

        for resource in resources.iter() {
            match self.coap_client.send_request(resource, b"discover") {
                Ok(response) => {
                    println!("Recurso {} encontrado: {:?}", resource, response);
                }
                Err(e) => {
                    eprintln!("Erro ao descobrir recurso {}: {}", resource, e);
                }
            }
        }

        Ok(())
    }

    fn handle_commands(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let rt = Runtime::new()?;
        let topic = format!("commands/{}", self.device_id);

        rt.block_on(async {
            match self.mqtt_client.subscribe(&topic).await {
                Ok(_) => {
                    // Simular recebimento de comandos
                    let commands = [
                        "{\"action\": \"calibrate\", \"sensor\": \"temperature\"}",
                        "{\"action\": \"set\", \"actuator\": \"led\", \"value\": \"on\"}",
                        "{\"action\": \"update\", \"config\": \"network\"}",
                    ];

                    for command in commands.iter() {
                        println!("Comando recebido: {}", command);
                        // Processar comando...
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("Erro ao assinar tópico de comandos: {}", e);
                    Err(e)
                }
            }
        })?;

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Criar dispositivo IIoT
    let mut device = IIoTDevice::new("device_001")?;

    // Publicar dados de sensores
    device.publish_sensor_data("temperature", 25.5)?;
    device.publish_sensor_data("humidity", 60.0)?;

    // Enviar comandos para atuadores
    device.send_actuator_command("led", "on")?;
    device.send_actuator_command("pump", "start")?;

    // Descobrir recursos disponíveis
    device.discover_resources()?;

    // Processar comandos recebidos
    device.handle_commands()?;

    Ok(())
}
