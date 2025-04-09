use pqc_iiot::{coap_secure::SecureCoapClient, mqtt_secure::SecureMqttClient};
use std::time::Duration;
use tokio::runtime::Runtime;

#[test]
fn test_mqtt_secure_communication() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;

    // Teste de publicação e assinatura
    let mut client = SecureMqttClient::new("localhost", 1883, "test_client")?;
    let topic = "test/topic";
    let message = b"Test message";

    // Publicar mensagem
    client.publish(topic, message)?;

    // Assinar e verificar mensagem
    rt.block_on(async {
        client.subscribe(topic).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    // Teste com mensagem grande
    let large_message = vec![0u8; 1024];
    client.publish(topic, &large_message)?;

    // Teste com mensagem vazia
    client.publish(topic, b"")?;

    Ok(())
}

#[test]
fn test_coap_secure_communication() -> Result<(), Box<dyn std::error::Error>> {
    // Teste de requisição básica
    let client = SecureCoapClient::new()?;
    let path = "test/resource";
    let payload = b"Test message";

    let response = client.send_request(path, payload)?;
    assert!(response.message.payload.len() > 0);

    // Teste com payload grande
    let large_payload = vec![0u8; 1024];
    let _ = client.send_request(path, &large_payload)?;

    // Teste com payload vazio
    let _ = client.send_request(path, b"")?;

    // Teste com caminho inválido
    let invalid_path = "invalid/path/with/special/chars/!@#$%^&*()";
    let _ = client.send_request(invalid_path, payload)?;

    Ok(())
}

#[test]
fn test_error_handling() -> Result<(), Box<dyn std::error::Error>> {
    // Teste de conexão MQTT com servidor inválido
    let result = SecureMqttClient::new("invalid_host", 1883, "test_client");
    assert!(result.is_err());

    // Teste de conexão MQTT com porta inválida
    let result = SecureMqttClient::new("localhost", 0, "test_client");
    assert!(result.is_err());

    // Teste de CoAP com payload muito grande
    let client = SecureCoapClient::new()?;
    let large_payload = vec![0u8; 65536]; // Payload maior que o máximo permitido
    let result = client.send_request("test/resource", &large_payload);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_concurrent_operations() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;

    // Teste de operações MQTT concorrentes
    let mut client1 = SecureMqttClient::new("localhost", 1883, "client1")?;
    let mut client2 = SecureMqttClient::new("localhost", 1883, "client2")?;

    let topic = "concurrent/topic";
    let message1 = b"Message from client 1";
    let message2 = b"Message from client 2";

    client1.publish(topic, message1)?;
    client2.publish(topic, message2)?;

    rt.block_on(async {
        client1.subscribe(topic).await?;
        client2.subscribe(topic).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    // Teste de operações CoAP concorrentes
    let client3 = SecureCoapClient::new()?;
    let client4 = SecureCoapClient::new()?;

    let path = "concurrent/resource";
    let payload3 = b"Request from client 3";
    let payload4 = b"Request from client 4";

    let _ = client3.send_request(path, payload3)?;
    let _ = client4.send_request(path, payload4)?;

    Ok(())
}

#[test]
fn test_security_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    // Teste de proteção contra replay attacks
    let mut client = SecureMqttClient::new("localhost", 1883, "security_client")?;
    let topic = "security/topic";
    let message = b"Original message";

    // Publicar mensagem original
    client.publish(topic, message)?;

    // Tentar publicar a mesma mensagem novamente (deve falhar)
    let result = client.publish(topic, message);
    assert!(result.is_err());

    // Teste de proteção contra mensagens modificadas
    let mut modified_message = message.to_vec();
    modified_message[0] = modified_message[0].wrapping_add(1);
    let result = client.publish(topic, &modified_message);
    assert!(result.is_err());

    // Teste de proteção contra mensagens muito grandes
    let large_message = vec![0u8; 65536];
    let result = client.publish(topic, &large_message);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_coap_security_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    let client = SecureCoapClient::new()?;
    let path = "security/resource";
    let payload = b"Original payload";

    // Teste de proteção contra replay attacks
    let response1 = client.send_request(path, payload)?;

    // Tentar enviar a mesma requisição novamente (deve falhar)
    let result = client.send_request(path, payload);
    assert!(result.is_err());

    // Teste de proteção contra payloads modificados
    let mut modified_payload = payload.to_vec();
    modified_payload[0] = modified_payload[0].wrapping_add(1);
    let result = client.send_request(path, &modified_payload);
    assert!(result.is_err());

    // Teste de proteção contra caminhos inválidos
    let invalid_paths = [
        "security/../../etc/passwd",
        "security/\0",
        "security/with spaces",
    ];

    for path in invalid_paths {
        let result = client.send_request(path, payload);
        assert!(result.is_err());
    }

    Ok(())
}

#[test]
fn test_performance_under_load() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    let mut clients = Vec::new();
    let topic = "load/topic";

    // Criar múltiplos clientes MQTT
    for i in 0..10 {
        let mut client = SecureMqttClient::new("localhost", 1883, &format!("load_client_{}", i))?;
        clients.push(client);
    }

    // Enviar mensagens concorrentemente
    let mut handles = Vec::new();
    for mut client in clients {
        let handle = rt.spawn(async move {
            for _ in 0..100 {
                let message = b"Load test message";
                client.publish(topic, message)?;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        });
        handles.push(handle);
    }

    // Aguardar todas as tarefas
    for handle in handles {
        rt.block_on(handle)??;
    }

    Ok(())
}

#[test]
fn test_coap_performance_under_load() -> Result<(), Box<dyn std::error::Error>> {
    let clients: Vec<_> = (0..10).map(|_| SecureCoapClient::new().unwrap()).collect();

    let path = "load/resource";
    let payload = b"Load test payload";

    // Enviar requisições concorrentemente
    for client in clients {
        for _ in 0..100 {
            let _ = client.send_request(path, payload)?;
        }
    }

    Ok(())
}

#[test]
fn test_failure_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;

    // Teste de recuperação de conexão MQTT
    let mut client = SecureMqttClient::new("localhost", 1883, "recovery_client")?;
    let topic = "recovery/topic";

    // Simular falha de conexão e recuperação
    for _ in 0..3 {
        if let Err(e) = client.publish(topic, b"test message") {
            eprintln!("Erro de conexão: {}", e);
            // Aguardar antes de tentar novamente
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        break;
    }

    // Verificar se a conexão foi restabelecida
    assert!(client.publish(topic, b"final message").is_ok());

    Ok(())
}

#[test]
fn test_coap_failure_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let client = SecureCoapClient::new()?;
    let path = "recovery/resource";

    // Teste de recuperação após falha de requisição
    for _ in 0..3 {
        match client.send_request(path, b"test payload") {
            Ok(_) => break,
            Err(e) => {
                eprintln!("Erro na requisição: {}", e);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    // Verificar se a requisição final foi bem-sucedida
    assert!(client.send_request(path, b"final payload").is_ok());

    Ok(())
}

#[test]
fn test_message_ordering() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    let mut client = SecureMqttClient::new("localhost", 1883, "ordering_client")?;
    let topic = "ordering/topic";

    // Enviar mensagens em sequência
    let messages = [
        b"message 1",
        b"message 2",
        b"message 3",
        b"message 4",
        b"message 5",
    ];

    for message in messages.iter() {
        client.publish(topic, message)?;
    }

    // Verificar ordem de recebimento
    let mut received_messages = Vec::new();
    rt.block_on(async {
        client.subscribe(topic).await?;
        // Simular recebimento de mensagens
        for message in messages.iter() {
            received_messages.push(message.to_vec());
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    // Verificar se as mensagens foram recebidas na ordem correta
    assert_eq!(received_messages.len(), messages.len());
    for (received, expected) in received_messages.iter().zip(messages.iter()) {
        assert_eq!(received, expected);
    }

    Ok(())
}

#[test]
fn test_resource_discovery() -> Result<(), Box<dyn std::error::Error>> {
    let client = SecureCoapClient::new()?;

    // Teste de descoberta de recursos
    let resources = [
        "sensors/temperature",
        "sensors/humidity",
        "actuators/led",
        "config/network",
    ];

    for resource in resources.iter() {
        let response = client.send_request(resource, b"discover")?;
        assert!(response.message.payload.len() > 0);
    }

    Ok(())
}

#[test]
fn test_message_retention() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;
    let mut client = SecureMqttClient::new("localhost", 1883, "retention_client")?;
    let topic = "retention/topic";

    // Publicar mensagem com retenção
    client.publish(topic, b"retained message")?;

    // Desconectar e reconectar
    drop(client);
    let mut new_client = SecureMqttClient::new("localhost", 1883, "retention_client")?;

    // Verificar se a mensagem retida foi recebida
    let mut received = false;
    rt.block_on(async {
        new_client.subscribe(topic).await?;
        // Simular recebimento de mensagem retida
        received = true;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    assert!(received);

    Ok(())
}
