use coap_lite::{CoapRequest, Packet, ResponseType};
use rumqttd::{Broker, Config};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

pub fn start_mqtt_broker(port: u16) {
    let config_str = format!(
        r#"
        id = 0
        
        [router]
        max_connections = 100
        max_outgoing_packet_count = 200
        max_segment_size = 1048576
        max_segment_count = 10
        
        [v4]
          [v4.1]
            name = "test-server"
            listen = "127.0.0.1:{}"
            next_connection_delay_ms = 1
            connections = {{ max_inflight_count = 100, next_connection_delay_ms = 1, connection_timeout_ms = 3000, max_payload_size = 20480 }}
    "#,
        port
    );

    let config: Config = toml::from_str(&config_str).unwrap_or_else(|e| {
        panic!("Failed to parse MQTT config: {}", e);
    });

    thread::spawn(move || {
        let mut broker = Broker::new(config);
        broker.start().unwrap();
    });
    // Give it a moment to start
    thread::sleep(Duration::from_millis(100));
}

// Simple CoAP server mock
pub fn start_coap_server(port: u16) {
    thread::spawn(move || {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();

        let mut buf = [0u8; 65535]; // Increase buffer
        loop {
            if let Ok((amt, src)) = socket.recv_from(&mut buf) {
                let packet = Packet::from_bytes(&buf[..amt]).unwrap();
                let request = CoapRequest::from_packet(packet, src);

                let _path = request.get_path();

                let mut response = request.response.unwrap();

                // Echo the payload
                response.message.payload = request.message.payload.clone();
                response.set_status(ResponseType::Content);
                // response.message.header.message_id = request.message.header.message_id; // handled by request.response
                response
                    .message
                    .set_token(request.message.get_token().to_vec());

                let response_bytes = response.message.to_bytes().unwrap();
                socket.send_to(&response_bytes, src).ok();
            }
        }
    });
}
