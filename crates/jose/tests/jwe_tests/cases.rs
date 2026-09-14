// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn decrypts_compact_dir_a128gcm_json() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_dir_a128gcm(&key, &nonce, payload)?;

    let decoded: DirectPostPayload = decrypt_compact_jwe_json(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    )?;

    assert_eq!(
        decoded,
        DirectPostPayload {
            vp_token: "presented".to_owned(),
            state: "abc".to_owned(),
        }
    );
    Ok(())
}

#[test]
fn decrypts_compact_dir_a256gcm_bytes() -> Result<(), JweError> {
    let key = [3u8; 32];
    let nonce = [4u8; 12];
    let payload = br#"{"ok":true}"#;
    let compact = compact_jwe_dir_a256gcm(&key, &nonce, payload)?;

    let decoded = decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    )?;

    assert_eq!(&decoded[..], payload);
    Ok(())
}

#[test]
fn decrypts_compact_dir_a192gcm_bytes() -> Result<(), JweError> {
    let key = [5u8; 24];
    let nonce = [6u8; 12];
    let payload = br#"{"middle":true}"#;
    let compact = compact_jwe_dir_a192gcm(&key, &nonce, payload)?;

    let decoded = decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    )?;

    assert_eq!(&decoded[..], payload);
    Ok(())
}

#[test]
fn encrypts_compact_dir_a128gcm_json() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let mut rng = FixedRandom::new(nonce);
    let mut encryptor = DirectJweKeyEncryptor::new(&key);

    let compact = encrypt_compact_jwe_bytes(
        &CompactJweEncryptRequest::new(payload, JweContentEncryptionAlgorithm::A128Gcm),
        &mut encryptor,
        &mut rng,
    )?;

    let decoded: DirectPostPayload = decrypt_compact_jwe_json(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    )?;

    assert_eq!(
        decoded,
        DirectPostPayload {
            vp_token: "presented".to_owned(),
            state: "abc".to_owned(),
        }
    );
    Ok(())
}

#[test]
fn direct_encryption_rejects_ecdh_party_info() -> Result<(), JweError> {
    let key = [7u8; 16];
    let mut rng = FixedRandom::new([9u8; 12]);
    let mut encryptor = DirectJweKeyEncryptor::new(&key);

    let err = require_jwe_error(encrypt_compact_jwe_bytes(
        &CompactJweEncryptRequest::new(b"plaintext", JweContentEncryptionAlgorithm::A128Gcm)
            .with_apu(b"sender"),
        &mut encryptor,
        &mut rng,
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn prepared_ecdh_key_rejects_incomplete_ephemeral_jwk() {
    let result = PreparedJweEncryptionKey::new(
        JweKeyManagementAlgorithm::EcdhEs,
        reallyme_jose::Zeroizing::new(vec![0u8; 16]),
        Vec::new(),
        Some(json!({"kty":"EC","crv":"P-256","x":"AA"})),
    );

    assert!(matches!(result, Err(JweError::InvalidKeyAgreementKey)));
}

#[test]
fn encrypts_and_decrypts_p256_ecdh_es_with_fresh_ephemeral_key() -> Result<(), JweError> {
    let recipient_secret = private_scalar(5);
    let (recipient_public, recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?;
    let nonce = [4u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let mut rng = FixedRandom::new(nonce);
    let mut encryptor = P256EcdhEsJweKeyEncryptor::new(&recipient_public);

    let compact = encrypt_compact_jwe_bytes(
        &CompactJweEncryptRequest::new(payload, JweContentEncryptionAlgorithm::A128Gcm)
            .with_kid("recipient-key-1")
            .with_apu(b"wallet")
            .with_apv(b"issuer"),
        &mut encryptor,
        &mut rng,
    )?;

    let decoded: DirectPostPayload = decrypt_compact_jwe_json(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &P256EcdhEsJweKeyResolver::new(&recipient_private),
    )?;

    assert_eq!(
        decoded,
        DirectPostPayload {
            vp_token: "presented".to_owned(),
            state: "abc".to_owned(),
        }
    );
    Ok(())
}

#[test]
fn rejects_ecdh_es_epk_with_invalid_y_coordinate() -> Result<(), JweError> {
    let recipient_secret = private_scalar(5);
    let (recipient_public, recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?;
    let mut rng = FixedRandom::new([4u8; 12]);
    let mut encryptor = P256EcdhEsJweKeyEncryptor::new(&recipient_public);
    let compact = encrypt_compact_jwe_bytes(
        &CompactJweEncryptRequest::new(
            br#"{"vp_token":"presented","state":"abc"}"#,
            JweContentEncryptionAlgorithm::A128Gcm,
        ),
        &mut encryptor,
        &mut rng,
    )?;
    let mut parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 5);
    let mut protected_header: Value =
        serde_json::from_slice(&base64url_to_bytes(parts[0]).map_err(|_| JweError::InvalidHeader)?)
            .map_err(|_| JweError::InvalidHeader)?;
    let epk = protected_header
        .get_mut("epk")
        .and_then(Value::as_object_mut)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    epk.insert(
        "y".to_owned(),
        Value::String(bytes_to_base64url(&[0u8; 32])),
    );
    let protected_header_json =
        serde_json::to_vec(&protected_header).map_err(|_| JweError::InvalidHeader)?;
    let modified_header = bytes_to_base64url(&protected_header_json);
    parts[0] = modified_header.as_str();
    let invalid = parts.join(".");

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &invalid,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &P256EcdhEsJweKeyResolver::new(&recipient_private),
    ))?;

    assert!(matches!(err, JweError::InvalidKeyAgreementKey));
    Ok(())
}

#[test]
fn rejects_ecdh_es_epk_with_private_member() -> Result<(), JweError> {
    let recipient_secret = private_scalar(5);
    let (recipient_public, recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?;
    let mut rng = FixedRandom::new([4u8; 12]);
    let mut encryptor = P256EcdhEsJweKeyEncryptor::new(&recipient_public);
    let compact = encrypt_compact_jwe_bytes(
        &CompactJweEncryptRequest::new(
            br#"{"vp_token":"presented","state":"abc"}"#,
            JweContentEncryptionAlgorithm::A128Gcm,
        ),
        &mut encryptor,
        &mut rng,
    )?;
    let mut parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 5);
    let mut protected_header: Value =
        serde_json::from_slice(&base64url_to_bytes(parts[0]).map_err(|_| JweError::InvalidHeader)?)
            .map_err(|_| JweError::InvalidHeader)?;
    let epk = protected_header
        .get_mut("epk")
        .and_then(Value::as_object_mut)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    epk.insert(
        "d".to_owned(),
        Value::String(bytes_to_base64url(&[1u8; 32])),
    );
    let protected_header_json =
        serde_json::to_vec(&protected_header).map_err(|_| JweError::InvalidHeader)?;
    let modified_header = bytes_to_base64url(&protected_header_json);
    parts[0] = modified_header.as_str();
    let tampered = parts.join(".");

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &tampered,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &P256EcdhEsJweKeyResolver::new(&recipient_private),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_ecdh_es_unexpected_party_info() -> Result<(), JweError> {
    let recipient_secret = private_scalar(5);
    let (recipient_public, recipient_private) =
        reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&recipient_secret)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?;
    let mut rng = FixedRandom::new([4u8; 12]);
    let mut encryptor = P256EcdhEsJweKeyEncryptor::new(&recipient_public);
    let compact = encrypt_compact_jwe_bytes(
        &CompactJweEncryptRequest::new(
            br#"{"vp_token":"presented","state":"abc"}"#,
            JweContentEncryptionAlgorithm::A128Gcm,
        )
        .with_apu(b"wallet")
        .with_apv(b"issuer"),
        &mut encryptor,
        &mut rng,
    )?;
    let policy = CompactJwePolicy::new(
        &[JweKeyManagementAlgorithm::EcdhEs],
        &[JweContentEncryptionAlgorithm::A128Gcm],
    )
    .with_expected_apu(b"wallet")
    .with_expected_apv(b"verifier");

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &policy,
        &P256EcdhEsJweKeyResolver::new(&recipient_private),
    ))?;

    assert!(matches!(err, JweError::ApvPolicyMismatch));
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn jwe_compact_vectors_decrypt_or_fail_closed() -> Result<(), JweError> {
    let suite: JweVectorSuite =
        serde_json::from_str(include_str!("../../../../vectors/jwe-compact.json"))
            .map_err(|_| JweError::InvalidPayloadJson)?;

    assert!(!suite.cases.is_empty());

    let mut executed_cases = 0usize;
    for case in suite.cases {
        #[cfg(target_arch = "wasm32")]
        if is_native_only_jwe_vector(&case) {
            continue;
        }
        executed_cases = executed_cases
            .checked_add(1)
            .ok_or(JweError::LengthOverflow)?;
        let result = decrypt_jwe_vector_case(&case)?;

        match (
            case.expected_plaintext_json.as_ref(),
            case.expected_error.as_deref(),
        ) {
            (Some(expected), None) => {
                let decoded = result?;
                assert_eq!(&decoded, expected, "{}", case.id);
                assert!(matches!(
                    case.enc.as_str(),
                    "A128GCM" | "A192GCM" | "A256GCM"
                ));
                if let Some(expected_cek_hex) = case.derived_cek_hex.as_deref() {
                    assert_vector_derived_cek(&case, expected_cek_hex)?;
                }
            }
            (None, Some(expected_error)) => {
                let err = require_jwe_error(result)?;
                assert!(
                    jwe_error_matches(&err, expected_error),
                    "{} expected {expected_error}, got {err:?}",
                    case.id
                );
            }
            _ => return Err(JweError::InvalidPayloadJson),
        }
    }

    #[cfg(target_arch = "wasm32")]
    assert_eq!(executed_cases, 26);
    #[cfg(not(target_arch = "wasm32"))]
    assert_eq!(executed_cases, 28);

    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn is_native_only_jwe_vector(case: &JweVectorCase) -> bool {
    case.alg == "ECDH-ES"
        && case
            .recipient_private_key_hex
            .as_ref()
            .is_some_and(|key| matches!(key.len(), 96 | 132))
}

#[test]
fn rejects_key_management_algorithm_outside_policy() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A128GCM"}),
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;
    let policy = CompactJwePolicy::new(
        &[reallyme_jose::jwe::JweKeyManagementAlgorithm::EcdhEs],
        &[JweContentEncryptionAlgorithm::A128Gcm],
    );

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &policy,
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::UnsupportedKeyManagementAlgorithm));
    Ok(())
}

#[test]
fn rejects_tampered_authentication_tag() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_dir_a128gcm(&key, &nonce, payload)?;
    let mut parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 5);
    parts[4] = "AAAAAAAAAAAAAAAAAAAAAA";
    let tampered = parts.join(".");

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &tampered,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::Decrypt));
    Ok(())
}

#[test]
fn rejects_non_empty_encrypted_key_for_dir() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_dir_a128gcm(&key, &nonce, payload)?;
    let mut parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 5);
    parts[1] = "AA";
    let invalid = parts.join(".");

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &invalid,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidEncryptedKey));
    Ok(())
}

#[test]
fn rejects_duplicate_protected_header_parameter() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_protected_header_json(
        br#"{"alg":"dir","alg":"dir","enc":"A128GCM"}"#,
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_duplicate_epk_member() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_protected_header_json(
        br#"{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","x":"AQ","y":"AA"}}"#,
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_direct_jwe_with_ecdh_ephemeral_key_headers() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_header(
        &json!({
            "alg":"dir",
            "enc":"A128GCM",
            "epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"},
            "apu": bytes_to_base64url(b"sender"),
            "apv": bytes_to_base64url(b"recipient")
        }),
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_missing_key_management_algorithm() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_header(
        &json!({"enc":"A128GCM"}),
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_unsupported_compression_header() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A128GCM","zip":"DEF"}),
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_unsupported_critical_header() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A128GCM","crit":["exp"]}),
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_remote_key_header() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A128GCM","jku":"https://example.test/jwks.json"}),
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_certificate_url_header() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A128GCM","x5u":"https://example.test/cert.pem"}),
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_certificate_chain_header() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A128GCM","x5c":["AA"]}),
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_embedded_jwk_header() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A128GCM","jwk":{"kty":"oct","k":"AA"}}),
        &key,
        &nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidHeader));
    Ok(())
}

#[test]
fn rejects_modified_protected_header_aad() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_dir_a128gcm(&key, &nonce, payload)?;
    let mut parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 5);
    let modified_header = bytes_to_base64url(br#"{"alg":"dir","enc":"A128GCM","typ":"JWT"}"#);
    parts[0] = modified_header.as_str();
    let tampered = parts.join(".");

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &tampered,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::Decrypt));
    Ok(())
}

#[test]
fn rejects_modified_ciphertext() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_dir_a128gcm(&key, &nonce, payload)?;
    let mut parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 5);
    parts[3] = "AA";
    let tampered = parts.join(".");

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &tampered,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::Decrypt));
    Ok(())
}

#[test]
fn rejects_modified_iv() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_dir_a128gcm(&key, &nonce, payload)?;
    let mut parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 5);
    let modified_iv = bytes_to_base64url(&[8u8; 12]);
    parts[2] = modified_iv.as_str();
    let tampered = parts.join(".");

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &tampered,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::Decrypt));
    Ok(())
}
