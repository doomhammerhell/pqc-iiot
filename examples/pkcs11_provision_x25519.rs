#[cfg(feature = "hsm-pkcs11")]
fn main() -> pqc_iiot::Result<()> {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
    use cryptoki::session::UserType;
    use cryptoki::slot::Slot;
    use cryptoki::types::AuthPin;
    use pqc_iiot::{Error, Result};

    fn getenv(name: &str) -> Result<String> {
        std::env::var(name).map_err(|_| Error::InvalidInput(format!("Missing env var: {}", name)))
    }

    fn find_slot_by_token_label(pkcs11: &Pkcs11, want_label: &str) -> Result<Slot> {
        let slots = pkcs11.get_slots_with_token().map_err(|e| {
            Error::ClientError(format!("PKCS#11 get_slots_with_token failed: {}", e))
        })?;
        for slot in slots {
            let info = pkcs11
                .get_token_info(slot)
                .map_err(|e| Error::ClientError(format!("PKCS#11 token_info failed: {}", e)))?;
            let label = info.label().trim();
            if label == want_label.trim() {
                return Ok(slot);
            }
        }
        Err(Error::ClientError(format!(
            "PKCS#11 token not found (label={})",
            want_label
        )))
    }

    fn der_unwrap_octet_string(mut blob: &[u8]) -> Option<&[u8]> {
        // Minimal DER parser: OCTET STRING tag (0x04), short-form length only.
        if blob.len() < 2 {
            return None;
        }
        if blob[0] != 0x04 {
            return None;
        }
        let len = blob[1] as usize;
        blob = &blob[2..];
        if blob.len() != len {
            return None;
        }
        Some(blob)
    }

    // Inputs (env-vars keep this zero-dependency; integrate into your provisioning tooling as needed).
    let library_path = getenv("PQC_IIOT_PKCS11_LIBRARY")?;
    let user_pin = getenv("PQC_IIOT_PKCS11_PIN")?;
    let x25519_label = getenv("PQC_IIOT_PKCS11_X25519_LABEL")?;

    let slot = if let Ok(v) = std::env::var("PQC_IIOT_PKCS11_SLOT") {
        let n: u64 = v
            .parse()
            .map_err(|_| Error::InvalidInput("Invalid PQC_IIOT_PKCS11_SLOT".into()))?;
        Slot::try_from(n)
            .map_err(|e| Error::InvalidInput(format!("Invalid PKCS#11 slot {}: {}", n, e)))?
    } else {
        let token_label = getenv("PQC_IIOT_PKCS11_TOKEN_LABEL")?;
        let pkcs11 = Pkcs11::new(&library_path)
            .map_err(|e| Error::ClientError(format!("PKCS#11 library load failed: {}", e)))?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| Error::ClientError(format!("PKCS#11 initialize failed: {}", e)))?;
        let slot = find_slot_by_token_label(&pkcs11, &token_label)?;
        pkcs11.finalize().ok();
        slot
    };

    let pkcs11 = Pkcs11::new(&library_path)
        .map_err(|e| Error::ClientError(format!("PKCS#11 library load failed: {}", e)))?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|e| Error::ClientError(format!("PKCS#11 initialize failed: {}", e)))?;

    let session = pkcs11
        .open_rw_session(slot)
        .map_err(|e| Error::ClientError(format!("PKCS#11 open session failed: {}", e)))?;
    let user_pin = AuthPin::new(user_pin.into_boxed_str());
    session
        .login(UserType::User, Some(&user_pin))
        .map_err(|e| Error::ClientError(format!("PKCS#11 login failed: {}", e)))?;

    let pub_label = format!("{}.pub", x25519_label);

    fn find_unique_object(
        session: &cryptoki::session::Session,
        label: &str,
        class: ObjectClass,
        key_type: KeyType,
    ) -> Result<Option<cryptoki::object::ObjectHandle>> {
        let template = [
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(class),
            Attribute::KeyType(key_type),
        ];
        let objects = session
            .find_objects(&template)
            .map_err(|e| Error::ClientError(format!("PKCS#11 find_objects failed: {}", e)))?;
        match objects.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(*one)),
            _ => Err(Error::ClientError(format!(
                "PKCS#11 label is not unique (label={}, matches={})",
                label,
                objects.len()
            ))),
        }
    }

    let mut priv_key = find_unique_object(
        &session,
        &x25519_label,
        ObjectClass::PRIVATE_KEY,
        KeyType::EC_MONTGOMERY,
    )?;
    let mut pub_key = find_unique_object(
        &session,
        &pub_label,
        ObjectClass::PUBLIC_KEY,
        KeyType::EC_MONTGOMERY,
    )?;

    if priv_key.is_none() && pub_key.is_none() {
        let (pubk, privk) = {
            // Generate a token-resident X25519 keypair.
            // OID: 1.3.101.110 (id-X25519) DER = 06 03 2B 65 6E
            let ec_params = vec![0x06, 0x03, 0x2B, 0x65, 0x6E];
            let pub_t = [
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::EC_MONTGOMERY),
                Attribute::Token(true),
                Attribute::Label(pub_label.as_bytes().to_vec()),
                Attribute::EcParams(ec_params.clone()),
            ];
            let priv_t = [
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC_MONTGOMERY),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Derive(true),
                Attribute::Label(x25519_label.as_bytes().to_vec()),
                Attribute::EcParams(ec_params),
            ];
            session
                .generate_key_pair(&Mechanism::EccMontgomeryKeyPairGen, &pub_t, &priv_t)
                .map_err(|e| Error::CryptoError(format!("PKCS#11 keypairgen failed: {}", e)))?
        };
        priv_key = Some(privk);
        pub_key = Some(pubk);
    }

    let _priv_key = priv_key.ok_or_else(|| {
        Error::ClientError(format!(
            "Missing X25519 private key (label={}); reprovision recommended",
            x25519_label
        ))
    })?;
    let pub_key = pub_key.ok_or_else(|| {
        Error::ClientError(format!(
            "Missing X25519 public key (label={}); reprovision recommended",
            pub_label
        ))
    })?;

    // Export public key bytes (this is not secret).
    let attrs = session
        .get_attributes(pub_key, &[AttributeType::EcPoint])
        .map_err(|e| Error::ClientError(format!("PKCS#11 get_attributes failed: {}", e)))?;
    let pk_blob = match attrs.as_slice() {
        [Attribute::EcPoint(b)] => b.as_slice(),
        _ => {
            return Err(Error::ClientError(
                "Unexpected PKCS#11 attributes for EC public key".into(),
            ))
        }
    };
    let raw = der_unwrap_octet_string(pk_blob).unwrap_or(pk_blob);
    if raw.len() != 32 {
        return Err(Error::ClientError(format!(
            "Unexpected X25519 public key length from token: {}",
            raw.len()
        )));
    }

    println!("x25519_public_key_hex={}", hex::encode(raw));

    session.logout().ok();
    session.close().ok();
    pkcs11.finalize().ok();
    Ok(())
}

#[cfg(not(feature = "hsm-pkcs11"))]
fn main() {
    eprintln!("This example requires `--features hsm-pkcs11`.");
}
