#![no_main]

use libfuzzer_sys::fuzz_target;
use pqc_iiot::{Falcon, Kyber};

fuzz_target!(|data: &[u8]| {
    // Test key generation and encapsulation
    if data.len() >= 32 {
        let mut kyber = Kyber::new();
        if let Ok((pk, sk)) = kyber.generate_keypair() {
            let _ = kyber.encapsulate(&pk);
            let _ = kyber.decapsulate(&sk, &pk);
        }
    }

    // Test signature operations
    if data.len() >= 32 {
        let mut falcon = Falcon::new();
        if let Ok((pk, sk)) = falcon.generate_keypair() {
            let _ = falcon.sign(data, &sk);
            let _ = falcon.verify(data, &pk, &pk);
        }
    }
});
