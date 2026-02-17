use pqc_iiot::mqtt_secure::SecureMqttClient;
// use std::time::Duration;
// use tokio::runtime::Runtime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    // Criar cliente MQTT seguro com tratamento de erro
    let mut client = match SecureMqttClient::new("localhost", 1883, "secure_client") {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Erro ao criar cliente MQTT: {}", e);
            return Err(e.into());
        }
    };

    // Publicar mensagem segura com tratamento de erro
    let topic = "secure/topic";
    let message = b"Hello, secure MQTT!";
    if let Err(e) = client.publish(topic, message) {
        eprintln!("Erro ao publicar mensagem: {}", e);
        return Err(e.into());
    }

    // Assinar e processar mensagens com tratamento de erro
    if let Err(e) = client.subscribe(topic) {
        eprintln!("Erro ao assinar tópico: {}", e);
        return Err(e.into());
    }

    Ok(())
}
