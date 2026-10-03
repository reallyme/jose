// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

struct FixedEcdhPreparedKey {
    cek: reallyme_jose::Zeroizing<Vec<u8>>,
    epk: Value,
}

impl JweContentEncryptionKeyEncryptor for FixedEcdhPreparedKey {
    fn prepare_content_encryption_key(
        &mut self,
        _request: &CompactJweEncryptRequest<'_>,
    ) -> Result<PreparedJweEncryptionKey, JweError> {
        PreparedJweEncryptionKey::new(
            JweKeyManagementAlgorithm::EcdhEs,
            reallyme_jose::Zeroizing::new(self.cek.to_vec()),
            Vec::new(),
            Some(self.epk.clone()),
        )
    }
}

#[test]
fn jwe_compact_vectors_encrypt_to_expected_compact() -> Result<(), JweError> {
    let suite: JweVectorSuite =
        serde_json::from_str(include_str!("../../../../vectors/jwe-compact.json"))
            .map_err(|_| JweError::InvalidPayloadJson)?;

    for case in suite.cases {
        if case.expected_error.is_some() {
            continue;
        }
        #[cfg(target_arch = "wasm32")]
        if is_native_only_jwe_vector(&case) {
            continue;
        }
        let Some(plaintext) = case.plaintext_json_utf8.as_deref() else {
            continue;
        };
        let iv = hex_to_bytes(
            case.iv_hex
                .as_deref()
                .ok_or(JweError::InvalidContentCipherInput)?,
        )?;
        let iv: [u8; 12] = iv
            .try_into()
            .map_err(|_| JweError::InvalidContentCipherInput)?;
        let enc = match case.enc.as_str() {
            "A128GCM" => JweContentEncryptionAlgorithm::A128Gcm,
            "A192GCM" => JweContentEncryptionAlgorithm::A192Gcm,
            "A256GCM" => JweContentEncryptionAlgorithm::A256Gcm,
            _ => return Err(JweError::UnsupportedContentEncryptionAlgorithm),
        };
        let apu = case
            .protected_header
            .get("apu")
            .and_then(Value::as_str)
            .map(base64url_to_bytes)
            .transpose()
            .map_err(|_| JweError::InvalidHeader)?;
        let apv = case
            .protected_header
            .get("apv")
            .and_then(Value::as_str)
            .map(base64url_to_bytes)
            .transpose()
            .map_err(|_| JweError::InvalidHeader)?;
        let mut request = CompactJweEncryptRequest::new(plaintext.as_bytes(), enc);
        if let Some(kid) = case.protected_header.get("kid").and_then(Value::as_str) {
            request = request.with_kid(kid);
        }
        if let Some(apu) = apu.as_deref() {
            request = request.with_apu(apu);
        }
        if let Some(apv) = apv.as_deref() {
            request = request.with_apv(apv);
        }
        if let Some(typ) = case.protected_header.get("typ").and_then(Value::as_str) {
            request = request.with_typ(typ);
        }
        if let Some(cty) = case.protected_header.get("cty").and_then(Value::as_str) {
            request = request.with_cty(cty);
        }
        if case.protected_header.get("zip").and_then(Value::as_str) == Some("DEF") {
            request = request.with_compression(JweCompressionAlgorithm::Deflate);
        }
        let mut random = FixedRandom::new(iv);
        let compact = match case.alg.as_str() {
            "dir" => {
                let key = reallyme_jose::Zeroizing::new(hex_to_bytes(
                    case.cek_hex
                        .as_deref()
                        .ok_or(JweError::InvalidContentEncryptionKey)?,
                )?);
                encrypt_compact_jwe_bytes(
                    &request,
                    &mut DirectJweKeyEncryptor::new(&key),
                    &mut random,
                )?
            }
            "ECDH-ES" => {
                let header: CompactJweProtectedHeader =
                    serde_json::from_value(case.protected_header.clone())
                        .map_err(|_| JweError::InvalidHeader)?;
                let shared = vector_shared_secret(&case)?;
                let cek = derive_ecdh_es_content_encryption_key(&shared, &header)?;
                let expected = reallyme_jose::Zeroizing::new(hex_to_bytes(
                    case.derived_cek_hex
                        .as_deref()
                        .ok_or(JweError::InvalidContentEncryptionKey)?,
                )?);
                assert_eq!(cek.as_slice(), expected.as_slice(), "{}", case.id);
                let epk = header
                    .epk
                    .clone()
                    .ok_or(JweError::MissingRequiredHeaderParameter)?;
                let mut encryptor = FixedEcdhPreparedKey { cek, epk };
                encrypt_compact_jwe_bytes(&request, &mut encryptor, &mut random)?
            }
            _ => return Err(JweError::UnsupportedKeyManagementAlgorithm),
        };
        assert_eq!(compact, case.compact, "{}", case.id);
    }
    Ok(())
}

fn vector_shared_secret(
    case: &JweVectorCase,
) -> Result<reallyme_jose::Zeroizing<Vec<u8>>, JweError> {
    let private = reallyme_jose::Zeroizing::new(hex_to_bytes(
        case.ephemeral_private_key_hex
            .as_deref()
            .ok_or(JweError::InvalidKeyAgreementKey)?,
    )?);
    let public = hex_to_bytes(
        case.recipient_public_key_sec1_hex
            .as_deref()
            .ok_or(JweError::InvalidKeyAgreementKey)?,
    )?;
    let curve = case
        .protected_header
        .get("epk")
        .and_then(|epk| epk.get("crv"))
        .and_then(Value::as_str)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    match curve {
        "P-256" => reallyme_crypto::p256::derive_p256_shared_secret(&private, &public)
            .map(|secret| reallyme_jose::Zeroizing::new(secret.to_vec()))
            .map_err(|_| JweError::InvalidKeyAgreementKey),
        #[cfg(feature = "native")]
        "P-384" => reallyme_crypto::p384::derive_p384_shared_secret(&private, &public)
            .map(|secret| reallyme_jose::Zeroizing::new(secret.to_vec()))
            .map_err(|_| JweError::InvalidKeyAgreementKey),
        #[cfg(feature = "native")]
        "P-521" => reallyme_crypto::p521::derive_p521_shared_secret(&private, &public)
            .map(|secret| reallyme_jose::Zeroizing::new(secret.to_vec()))
            .map_err(|_| JweError::InvalidKeyAgreementKey),
        _ => Err(JweError::InvalidKeyAgreementKey),
    }
}
