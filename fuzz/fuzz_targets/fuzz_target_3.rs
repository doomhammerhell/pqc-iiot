#![no_main]
use libfuzzer_sys::fuzz_target;
use pqc_iiot::coap_secure::SecureCoapClient;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let client = SecureCoapClient::new().unwrap();
        let _ = client.send_request("fuzz/resource", data);
    }
});
