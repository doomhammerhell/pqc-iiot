use pqc_iiot::coap_secure::SecureCoapClient;
use std::net::SocketAddr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Criar cliente CoAP seguro com tratamento de erro
    let client = match SecureCoapClient::new() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Erro ao criar cliente CoAP: {}", e);
            return Err(e.into());
        }
    };

    // Endereço do servidor com tratamento de erro
    let server_addr: SocketAddr = match "127.0.0.1:5683".parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Erro ao analisar endereço do servidor: {}", e);
            return Err(e.into());
        }
    };

    // Enviar requisição segura com tratamento de erro
    let path = "secure/resource";
    let payload = b"Hello, secure CoAP!";
    match client.send_request(path, payload) {
        Ok(response) => {
            println!("Resposta recebida com sucesso: {:?}", response);
        }
        Err(e) => {
            eprintln!("Erro ao enviar requisição: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}
