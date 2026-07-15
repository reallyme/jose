#![allow(
    missing_docs,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::unwrap_used
)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Compact JWE decrypt tests.

use serde::Deserialize;
use serde_json::{json, Value};

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::{CryptoError, RngFailureKind, RngOutputKind};
use reallyme_jose::jwe::{
    decrypt_compact_jwe_bytes, decrypt_compact_jwe_json, derive_ecdh_es_content_encryption_key,
    encrypt_compact_jwe_bytes, CompactJweEncryptRequest, CompactJwePolicy,
    CompactJweProtectedHeader, DirectJweKeyEncryptor, DirectJweKeyResolver,
    JweContentEncryptionAlgorithm, JweContentEncryptionKeyResolver, JweError,
    JweKeyManagementAlgorithm, P256EcdhEsJweKeyEncryptor, P256EcdhEsJweKeyResolver,
    PreparedJweEncryptionKey, MAX_COMPACT_JWE_BYTES,
};
#[cfg(feature = "native")]
use reallyme_jose::jwe::{P384EcdhEsJweKeyResolver, P521EcdhEsJweKeyResolver};

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct DirectPostPayload {
    vp_token: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct JweVectorSuite {
    cases: Vec<JweVectorCase>,
}

#[derive(Debug, Deserialize)]
struct JweVectorCase {
    id: String,
    alg: String,
    enc: String,
    cek_hex: Option<String>,
    recipient_private_key_hex: Option<String>,
    protected_header: Value,
    compact: String,
    expected_plaintext_json: Option<Value>,
    expected_error: Option<String>,
    derived_cek_hex: Option<String>,
}

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

#[test]
fn jwe_compact_vectors_decrypt_or_fail_closed() -> Result<(), JweError> {
    let suite: JweVectorSuite =
        serde_json::from_str(include_str!("../../conformance/vectors/jwe-compact.json"))
            .map_err(|_| JweError::InvalidPayloadJson)?;

    assert!(!suite.cases.is_empty());

    for case in suite.cases {
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

    Ok(())
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

#[test]
fn rejects_wrong_direct_key() -> Result<(), JweError> {
    let key = [7u8; 16];
    let wrong_key = [8u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = compact_jwe_dir_a128gcm(&key, &nonce, payload)?;

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&wrong_key),
    ))?;

    assert!(matches!(err, JweError::Decrypt));
    Ok(())
}

#[test]
fn rejects_invalid_ecdh_es_shared_secret_length_before_kdf() -> Result<(), JweError> {
    let header = CompactJweProtectedHeader {
        alg: JweKeyManagementAlgorithm::EcdhEs,
        enc: JweContentEncryptionAlgorithm::A128Gcm,
        kid: None,
        apu: None,
        apv: None,
        epk: Some(json!({"kty":"EC","crv":"P-256","x":"AA","y":"AA"})),
        typ: None,
        cty: None,
    };
    let err = require_jwe_error(derive_ecdh_es_content_encryption_key(&[], &header))?;

    assert!(matches!(err, JweError::InvalidSharedSecret));
    Ok(())
}

#[test]
fn rejects_non_json_payload_for_json_api() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let compact = compact_jwe_dir_a128gcm(&key, &nonce, b"not-json")?;

    let err = require_jwe_error(decrypt_compact_jwe_json::<DirectPostPayload>(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidPayloadJson));
    Ok(())
}

#[test]
fn rejects_jws_compact_when_decrypting_jwe() -> Result<(), JweError> {
    let rfc7515_appendix_a3_jws = concat!(
        "eyJhbGciOiJFUzI1NiJ9.",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQog",
        "Imh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.",
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA",
        "pmWQxfKTUJqPP3-Kg6NU1Q"
    );

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        rfc7515_appendix_a3_jws,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&[7u8; 16]),
    ))?;

    assert!(matches!(err, JweError::InvalidCompact));
    Ok(())
}

#[test]
fn rejects_compact_jwe_over_size_limit() -> Result<(), JweError> {
    let oversized = "a".repeat(
        MAX_COMPACT_JWE_BYTES
            .checked_add(1)
            .ok_or(JweError::LengthOverflow)?,
    );

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &oversized,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&[7u8; 16]),
    ))?;

    assert!(matches!(err, JweError::InputTooLarge));
    Ok(())
}

#[test]
fn rejects_invalid_compact_part_count() -> Result<(), JweError> {
    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        "a.b.c.d",
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&[7u8; 16]),
    ))?;

    assert!(matches!(err, JweError::InvalidCompact));
    Ok(())
}

#[test]
fn rejects_trailing_compact_jwe_segment() -> Result<(), JweError> {
    let key = [7u8; 16];
    let nonce = [9u8; 12];
    let payload = br#"{"vp_token":"presented","state":"abc"}"#;
    let compact = format!("{}.extra", compact_jwe_dir_a128gcm(&key, &nonce, payload)?);

    let err = require_jwe_error(decrypt_compact_jwe_bytes(
        &compact,
        &CompactJwePolicy::openid4vp_direct_post_jwt(),
        &DirectJweKeyResolver::new(&key),
    ))?;

    assert!(matches!(err, JweError::InvalidCompact));
    Ok(())
}

#[test]
fn derives_ecdh_es_a128gcm_cek_from_header_party_info() -> Result<(), JweError> {
    let header = serde_json::from_value(json!({
        "alg": "ECDH-ES",
        "enc": "A128GCM",
        "epk": {"kty":"EC","crv":"P-256","x":"AA","y":"AA"},
        "apu": bytes_to_base64url(b"wallet"),
        "apv": bytes_to_base64url(b"verifier")
    }))
    .map_err(|_| JweError::InvalidHeader)?;
    let shared_secret = [11u8; 32];

    let cek = derive_ecdh_es_content_encryption_key(&shared_secret, &header)?;

    assert_eq!(cek.len(), 16);
    Ok(())
}

#[test]
fn derives_rfc7518_appendix_c_ecdh_es_a128gcm_cek() -> Result<(), JweError> {
    let header = serde_json::from_value(json!({
        "alg": "ECDH-ES",
        "enc": "A128GCM",
        "epk": {"kty":"EC","crv":"P-256","x":"AA","y":"AA"},
        "apu": bytes_to_base64url(b"Alice"),
        "apv": bytes_to_base64url(b"Bob")
    }))
    .map_err(|_| JweError::InvalidHeader)?;
    let shared_secret = [
        158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110,
        163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
    ];

    let cek = derive_ecdh_es_content_encryption_key(&shared_secret, &header)?;

    assert_eq!(bytes_to_hex(&cek), "56aa8deaf8236d205c2228cd71a7101a");
    Ok(())
}

fn decrypt_jwe_vector_case(case: &JweVectorCase) -> Result<Result<Value, JweError>, JweError> {
    match case.alg.as_str() {
        "dir" | "RSA-OAEP" | "RSA1_5" | "A128KW" | "PBES2-HS256+A128KW" | "ECDH-ES+A128KW" => {
            let key = hex_to_bytes(
                case.cek_hex
                    .as_deref()
                    .ok_or(JweError::InvalidContentEncryptionKey)?,
            )?;
            Ok(decrypt_compact_jwe_json(
                &case.compact,
                &CompactJwePolicy::openid4vp_direct_post_jwt(),
                &DirectJweKeyResolver::new(&key),
            ))
        }
        "ECDH-ES" => decrypt_ecdh_es_jwe_vector_case(case),
        _ => Err(JweError::UnsupportedKeyManagementAlgorithm),
    }
}

fn decrypt_ecdh_es_jwe_vector_case(
    case: &JweVectorCase,
) -> Result<Result<Value, JweError>, JweError> {
    let recipient_private_key = hex_to_bytes(
        case.recipient_private_key_hex
            .as_deref()
            .ok_or(JweError::InvalidKeyAgreementKey)?,
    )?;
    Ok(match recipient_private_key.len() {
        32 => decrypt_compact_jwe_json(
            &case.compact,
            &CompactJwePolicy::openid4vp_direct_post_jwt(),
            &P256EcdhEsJweKeyResolver::new(&recipient_private_key),
        ),
        #[cfg(feature = "native")]
        48 => decrypt_compact_jwe_json(
            &case.compact,
            &CompactJwePolicy::openid4vp_direct_post_jwt(),
            &P384EcdhEsJweKeyResolver::new(&recipient_private_key),
        ),
        #[cfg(feature = "native")]
        66 => decrypt_compact_jwe_json(
            &case.compact,
            &CompactJwePolicy::openid4vp_direct_post_jwt(),
            &P521EcdhEsJweKeyResolver::new(&recipient_private_key),
        ),
        _ => Err(JweError::InvalidKeyAgreementKey),
    })
}

fn assert_vector_derived_cek(case: &JweVectorCase, expected_cek_hex: &str) -> Result<(), JweError> {
    let header: CompactJweProtectedHeader = serde_json::from_value(case.protected_header.clone())
        .map_err(|_| JweError::InvalidHeader)?;
    let cek = resolve_vector_cek(case, &header)?;

    assert_eq!(bytes_to_hex(&cek), expected_cek_hex, "{}", case.id);
    assert_apv_change_derives_different_cek(case, &cek)?;
    Ok(())
}

fn assert_apv_change_derives_different_cek(
    case: &JweVectorCase,
    original_cek: &[u8],
) -> Result<(), JweError> {
    if case.protected_header.get("apv").is_none() {
        return Ok(());
    }

    let mut changed_header_value = case.protected_header.clone();
    changed_header_value["apv"] = Value::String(bytes_to_base64url(b"different-recipient"));
    let changed_header: CompactJweProtectedHeader =
        serde_json::from_value(changed_header_value).map_err(|_| JweError::InvalidHeader)?;
    let changed_cek = resolve_vector_cek(case, &changed_header)?;

    assert_ne!(&changed_cek[..], original_cek, "{}", case.id);
    Ok(())
}

fn resolve_vector_cek(
    case: &JweVectorCase,
    header: &CompactJweProtectedHeader,
) -> Result<Vec<u8>, JweError> {
    let recipient_private_key = hex_to_bytes(
        case.recipient_private_key_hex
            .as_deref()
            .ok_or(JweError::InvalidKeyAgreementKey)?,
    )?;
    let cek = match recipient_private_key.len() {
        32 => P256EcdhEsJweKeyResolver::new(&recipient_private_key)
            .resolve_content_encryption_key(header, &[])?,
        #[cfg(feature = "native")]
        48 => P384EcdhEsJweKeyResolver::new(&recipient_private_key)
            .resolve_content_encryption_key(header, &[])?,
        #[cfg(feature = "native")]
        66 => P521EcdhEsJweKeyResolver::new(&recipient_private_key)
            .resolve_content_encryption_key(header, &[])?,
        _ => return Err(JweError::InvalidKeyAgreementKey),
    };
    Ok(cek.to_vec())
}

fn jwe_error_matches(err: &JweError, expected: &str) -> bool {
    matches!(
        (expected, err),
        ("InvalidCompact", JweError::InvalidCompact)
            | ("InvalidEncoding", JweError::InvalidEncoding)
            | ("InvalidHeader", JweError::InvalidHeader)
            | (
                "UnsupportedKeyManagementAlgorithm",
                JweError::UnsupportedKeyManagementAlgorithm
            )
            | (
                "UnsupportedContentEncryptionAlgorithm",
                JweError::UnsupportedContentEncryptionAlgorithm
            )
            | (
                "MissingRequiredHeaderParameter",
                JweError::MissingRequiredHeaderParameter
            )
            | ("HeaderPolicyMismatch", JweError::HeaderPolicyMismatch)
            | ("InvalidEncryptedKey", JweError::InvalidEncryptedKey)
            | (
                "InvalidContentEncryptionKey",
                JweError::InvalidContentEncryptionKey
            )
            | (
                "InvalidContentCipherInput",
                JweError::InvalidContentCipherInput
            )
            | ("Decrypt", JweError::Decrypt)
            | ("Encrypt", JweError::Encrypt)
            | ("InvalidKeyAgreementKey", JweError::InvalidKeyAgreementKey)
            | ("Randomness", JweError::Randomness)
            | ("InvalidPayloadJson", JweError::InvalidPayloadJson)
            | ("LengthOverflow", JweError::LengthOverflow)
            | ("InputTooLarge", JweError::InputTooLarge)
    )
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn compact_jwe_dir_a128gcm(
    key: &[u8; 16],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<String, JweError> {
    compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A128GCM"}),
        key,
        nonce,
        payload,
        JweContentEncryptionAlgorithm::A128Gcm,
    )
}

fn require_jwe_error<T>(result: Result<T, JweError>) -> Result<JweError, JweError> {
    match result {
        Ok(_) => Err(JweError::HeaderPolicyMismatch),
        Err(err) => Ok(err),
    }
}

fn hex_to_bytes(input: &str) -> Result<Vec<u8>, JweError> {
    if !input.len().is_multiple_of(2) {
        return Err(JweError::InvalidContentEncryptionKey);
    }

    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(value: u8) -> Result<u8, JweError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(JweError::InvalidContentEncryptionKey),
    }
}

fn private_scalar(last_byte: u8) -> [u8; 32] {
    private_scalar_with_len(last_byte)
}

fn private_scalar_with_len<const N: usize>(last_byte: u8) -> [u8; N] {
    let mut scalar = [0u8; N];
    scalar[N - 1] = last_byte;
    scalar
}

struct FixedRandom {
    bytes: [u8; 12],
}

impl FixedRandom {
    const fn new(bytes: [u8; 12]) -> Self {
        Self { bytes }
    }
}

impl reallyme_crypto::csprng::SecureRandom for FixedRandom {
    fn fill_secure(
        &mut self,
        output: &mut [u8],
        output_kind: RngOutputKind,
    ) -> Result<(), CryptoError> {
        if output.len() != self.bytes.len() {
            return Err(CryptoError::Rng {
                output: output_kind,
                kind: RngFailureKind::InvalidOutputLength,
            });
        }
        output.copy_from_slice(&self.bytes);
        Ok(())
    }
}

fn compact_jwe_dir_a256gcm(
    key: &[u8; 32],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<String, JweError> {
    compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A256GCM"}),
        key,
        nonce,
        payload,
        JweContentEncryptionAlgorithm::A256Gcm,
    )
}

fn compact_jwe_dir_a192gcm(
    key: &[u8; 24],
    nonce: &[u8; 12],
    payload: &[u8],
) -> Result<String, JweError> {
    compact_jwe_with_header(
        &json!({"alg":"dir","enc":"A192GCM"}),
        key,
        nonce,
        payload,
        JweContentEncryptionAlgorithm::A192Gcm,
    )
}

fn compact_jwe_with_header(
    header: &serde_json::Value,
    key: &[u8],
    nonce: &[u8; 12],
    payload: &[u8],
    enc: JweContentEncryptionAlgorithm,
) -> Result<String, JweError> {
    compact_jwe_with_protected_header_json(
        &serde_json::to_vec(header).map_err(|_| JweError::InvalidHeader)?,
        key,
        nonce,
        payload,
        enc,
    )
}

fn compact_jwe_with_protected_header_json(
    header_json: &[u8],
    key: &[u8],
    nonce: &[u8; 12],
    payload: &[u8],
    enc: JweContentEncryptionAlgorithm,
) -> Result<String, JweError> {
    let protected = bytes_to_base64url(header_json);
    let ciphertext_with_tag = match enc {
        JweContentEncryptionAlgorithm::A128Gcm => {
            let key = reallyme_crypto::aes::Aes128GcmKey::from_slice(key)
                .map_err(|_| JweError::InvalidContentEncryptionKey)?;
            let nonce = reallyme_crypto::aes::Aes128GcmNonce::from_slice(nonce)
                .map_err(|_| JweError::InvalidContentCipherInput)?;
            reallyme_crypto::aes::encrypt_aes128_gcm(
                &reallyme_crypto::aes::Aes128GcmEncryptRequest {
                    key: &key,
                    nonce,
                    aad: protected.as_bytes(),
                    plaintext: payload,
                },
            )
            .map_err(|_| JweError::Decrypt)?
        }
        JweContentEncryptionAlgorithm::A192Gcm => {
            let key = reallyme_crypto::aes::Aes192GcmKey::from_slice(key)
                .map_err(|_| JweError::InvalidContentEncryptionKey)?;
            let nonce = reallyme_crypto::aes::Aes192GcmNonce::from_slice(nonce)
                .map_err(|_| JweError::InvalidContentCipherInput)?;
            reallyme_crypto::aes::encrypt_aes192_gcm(
                &reallyme_crypto::aes::Aes192GcmEncryptRequest {
                    key: &key,
                    nonce,
                    aad: protected.as_bytes(),
                    plaintext: payload,
                },
            )
            .map_err(|_| JweError::Decrypt)?
        }
        JweContentEncryptionAlgorithm::A256Gcm => {
            let key = reallyme_crypto::aes::Aes256GcmKey::from_slice(key)
                .map_err(|_| JweError::InvalidContentEncryptionKey)?;
            let nonce = reallyme_crypto::aes::Aes256GcmNonce::from_slice(nonce)
                .map_err(|_| JweError::InvalidContentCipherInput)?;
            reallyme_crypto::aes::encrypt(&reallyme_crypto::aes::EncryptRequest {
                key: &key,
                nonce,
                aad: protected.as_bytes(),
                plaintext: payload,
            })
            .map_err(|_| JweError::Decrypt)?
        }
        _ => return Err(JweError::UnsupportedContentEncryptionAlgorithm),
    };

    let ciphertext_and_tag = ciphertext_with_tag.as_bytes();
    let tag_len = enc.tag_len();
    let split_at = ciphertext_and_tag
        .len()
        .checked_sub(tag_len)
        .ok_or(JweError::LengthOverflow)?;
    let ciphertext = bytes_to_base64url(&ciphertext_and_tag[..split_at]);
    let tag = bytes_to_base64url(&ciphertext_and_tag[split_at..]);
    let iv = bytes_to_base64url(nonce);

    Ok(format!("{protected}..{iv}.{ciphertext}.{tag}"))
}
