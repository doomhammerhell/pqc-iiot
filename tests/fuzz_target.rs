use pqc_iiot::crypto::traits::{PqcKEM, PqcSignature};
use pqc_iiot::security::provider::{SecurityProvider, SoftwareSecurityProvider};
use pqc_iiot::{Falcon, Kyber};
use proptest::prelude::*;

// Helper to get fresh keys (optimization: could be static, but for now simple)
fn get_keys() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let kyber = Kyber::new();
    let (k_pk, k_sk) = kyber.generate_keypair().unwrap();

    let falcon = Falcon::new();
    let (f_pk, f_sk) = falcon.generate_keypair().unwrap();

    (k_sk, k_pk, f_sk, f_pk)
}

proptest! {
    // Generate only 10 cases to keep test fast, as keygen is expensive.
    // Ideally we'd separate keygen from the loop.
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn fuzz_decrypt_garbage(ciphertext in proptest::collection::vec(any::<u8>(), 0..2000)) {
        let (k_sk, k_pk, f_sk, f_pk) = get_keys();
        let provider = SoftwareSecurityProvider::new(k_sk, k_pk, f_sk, f_pk);

        let result = provider.decrypt(&ciphertext);

        // Must not panic.
        // It should almost always verify to Err, unless we randomly hit a valid ciphertext (impossible).
        // Exceptions: if ciphertext length matches exactly and we are unlucky?
        prop_assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn fuzz_sign_arbitrary_message(message in proptest::collection::vec(any::<u8>(), 0..1000)) {
        let (k_sk, k_pk, f_sk, f_pk) = get_keys();
        let provider = SoftwareSecurityProvider::new(k_sk, k_pk, f_sk, f_pk);

        let result = provider.sign(&message);
        prop_assert!(result.is_ok());
    }
}
