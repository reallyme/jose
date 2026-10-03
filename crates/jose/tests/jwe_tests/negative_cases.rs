// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
fn rejects_compression_without_explicit_policy() -> Result<(), JweError> {
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

    assert!(matches!(err, JweError::UnsupportedCompressionAlgorithm));
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
