#[cfg(test)]
mod tests {
    use pqc_iiot::security::provider::SecurityProvider;
    use pqc_iiot::security::tpm::TpmSecurityProvider;

    #[test]
    fn test_tpm_non_exportable_keys() {
        let tpm = TpmSecurityProvider::new().unwrap();

        // Verify keys cannot be exported
        assert!(
            tpm.export_secret_keys().is_none(),
            "TPM keys should be non-exportable"
        );
    }

    #[test]
    fn test_tpm_stub_limitations() {
        let tpm = TpmSecurityProvider::new().unwrap();
        let msg = b"test";

        // Verify sign returns error (stub)
        assert!(tpm.sign(msg).is_err(), "TPM stub should error on sign");

        // Verify decrypt returns error (stub)
        assert!(
            tpm.decrypt(msg).is_err(),
            "TPM stub should error on decrypt"
        );
    }
}
