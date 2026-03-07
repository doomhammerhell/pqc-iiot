use pqc_iiot::ratchet::RatchetSession;
use rand::{Rng, thread_rng};

/// Chaos Monkey Stream Simulation
/// Wraps a message exchange and injects faults.
struct ChaosMonkey {
    drop_rate: f64,
    corrupt_rate: f64,
}

impl ChaosMonkey {
    fn new(drop_rate: f64, corrupt_rate: f64) -> Self {
        Self { drop_rate, corrupt_rate }
    }

    /// Process a payload through the chaos filter.
    /// Returns:
    /// - Some(payload) if passed (potentially corrupted)
    /// - None if dropped
    fn transmit(&self, data: &mut [u8]) -> Option<()> {
        let mut rng = thread_rng();
        
        // 1. Packet Loss
        if rng.gen_bool(self.drop_rate) {
            println!("Consumer: Packet DROPPED by Chaos Monkey");
            return None;
        }

        // 2. Bit Flips (Corruption)
        if rng.gen_bool(self.corrupt_rate) {
            println!("Consumer: Packet CORRUPTED by Chaos Monkey");
            if !data.is_empty() {
                let idx = rng.gen_range(0..data.len());
                data[idx] ^= 0xFF; // Flip all bits in byte
            }
        }
        
        Some(())
    }
}

#[test]
fn test_ratchet_chaos_resilience() {
    // 1. Setup: Alice and Bob share a Root Key (Simulating Handshake)
    let initial_rk = [0x55u8; 32];
    
    // Alice (Client)
    let mut alice = RatchetSession::initialize(initial_rk, None);
    
    // Bob (Server)
    let mut bob = RatchetSession::initialize(initial_rk, None);
    
    let chaos = ChaosMonkey::new(0.0, 1.0); // 100% Corruption for this test phase
    
    // 2. Alice sends a message (Normal)
    println!("--- Msg 1: Normal ---");
    let msg1 = alice.encrypt(b"Hello Bob").expect("Encryption failed");
    let decrypted1 = bob.decrypt(&msg1).expect("Decryption failed");
    assert_eq!(decrypted1, b"Hello Bob");
    
    // 3. Alice sends a message (Corrupted)
    println!("--- Msg 2: Chaos (Corruption) ---");
    let mut msg2 = alice.encrypt(b"Secret Plans").expect("Encryption failed");
    
    // Inject Fault into ciphertext
    chaos.transmit(&mut msg2.ciphertext); 
    // (Note: In real usage, msg2 would be serialized. Here we modify struct directly)
    
    // Bob attempts bad decrypt
    if bob.decrypt(&msg2).is_ok() {
        panic!("Bob decrypted corrupted message! Auth Tag failure expected.");
    } else {
        println!("Bob rejected corrupted message (As Expected)");
    }
    
    // 4. Alice sends Msg 3 (Self-Healing / Independence)
    // Even though Msg 2 failed, the session should proceed if chains are managed right.
    // NOTE: My simple ratchet advances chain on encrypt/decrypt. 
    // Alice advanced send_chain twice (Msg2, Msg3).
    // Bob advanced recv_chain ONCE (Msg1). Msg2 failed decrypt, so did bob advance?
    // If AES-GCM fails, `bob.decrypt` might NOT advance the chain state in a transactional way 
    // or it MIGHT have advanced before the error.
    // In `ratchet.rs`:
    // `let (next_ck, mk) = Self::kdf_ck(&self.chain_key_recv);`
    // `self.chain_key_recv = next_ck;` happens BEFORE decryption.
    // So Bob DID advance his chain even on failure.
    // This allows him to stay in sync with Alice for Msg 3.
    // This is "optimistic" ratchet.
    
    println!("--- Msg 3: Recovery ---");
    let msg3 = alice.encrypt(b"Still friends?").expect("Encryption failed");
    let decrypted3 = bob.decrypt(&msg3).expect("Decryption failed syncing");
    assert_eq!(decrypted3, b"Still friends?");
    
    println!("Test: Chaos Resilience PASSED");
}
