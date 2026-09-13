// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
    for pair in input.as_bytes().as_chunks::<2>().0 {
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

#[test]
fn oversized_jwe_is_rejected_before_randomness_is_consumed() {
    struct CountingRandom(usize);
    impl reallyme_crypto::csprng::SecureRandom for CountingRandom {
        fn fill_secure(&mut self, output: &mut [u8], _: RngOutputKind) -> Result<(), CryptoError> {
            self.0 += 1;
            output.fill(1);
            Ok(())
        }
    }
    let key = [7_u8; 16];
    let plaintext = vec![0_u8; 800_000];
    let request = CompactJweEncryptRequest::new(&plaintext, JweContentEncryptionAlgorithm::A128Gcm);
    let mut random = CountingRandom(0);
    assert!(matches!(
        encrypt_compact_jwe_bytes(&request, &mut DirectJweKeyEncryptor::new(&key), &mut random),
        Err(JweError::InputTooLarge)
    ));
    assert_eq!(random.0, 0);
}

#[test]
fn oversized_jwe_metadata_is_rejected_before_key_agreement() {
    let metadata = "a".repeat(MAX_COMPACT_JWE_BYTES + 1);
    let request = CompactJweEncryptRequest::new(b"", JweContentEncryptionAlgorithm::A128Gcm)
        .with_kid(&metadata);
    let mut random = FixedRandom::new([0_u8; 12]);
    assert!(matches!(
        encrypt_compact_jwe_bytes(
            &request,
            &mut P256EcdhEsJweKeyEncryptor::new(&[]),
            &mut random
        ),
        Err(JweError::InputTooLarge)
    ));
}

#[test]
fn jwe_size_preflight_preserves_each_gcm_boundary_with_escaped_metadata() {
    for (enc, key_len) in [
        (JweContentEncryptionAlgorithm::A128Gcm, 16),
        (JweContentEncryptionAlgorithm::A192Gcm, 24),
        (JweContentEncryptionAlgorithm::A256Gcm, 32),
    ] {
        let key = vec![7_u8; key_len];
        // JSON escaping and multi-byte UTF-8 must be measured after serialization.
        let kid = "\"\\\n🔐";
        let empty = encrypt_compact_jwe_bytes(
            &CompactJweEncryptRequest::new(b"", enc).with_kid(kid),
            &mut DirectJweKeyEncryptor::new(&key),
            &mut FixedRandom::new([0_u8; 12]),
        )
        .unwrap();
        let budget = MAX_COMPACT_JWE_BYTES.checked_sub(empty.len()).unwrap();
        let raw_limit = budget
            .checked_div(4)
            .unwrap()
            .checked_mul(3)
            .unwrap()
            .checked_add(match budget.checked_rem(4).unwrap() {
                2 => 1,
                3 => 2,
                _ => 0,
            })
            .unwrap();
        let plaintext = vec![0_u8; raw_limit];
        let compact = encrypt_compact_jwe_bytes(
            &CompactJweEncryptRequest::new(&plaintext, enc).with_kid(kid),
            &mut DirectJweKeyEncryptor::new(&key),
            &mut FixedRandom::new([1_u8; 12]),
        )
        .unwrap();
        assert!(compact.len() <= MAX_COMPACT_JWE_BYTES);
        assert!(MAX_COMPACT_JWE_BYTES.checked_sub(compact.len()).unwrap() <= 1);
        let algorithms = [enc];
        let policy = CompactJwePolicy::new(&[JweKeyManagementAlgorithm::Direct], &algorithms)
            .with_expected_kid(kid);
        let decoded =
            decrypt_compact_jwe_bytes(&compact, &policy, &DirectJweKeyResolver::new(&key)).unwrap();
        assert_eq!(&decoded[..], plaintext);
        let too_large = vec![0_u8; raw_limit.checked_add(1).unwrap()];
        assert!(matches!(
            encrypt_compact_jwe_bytes(
                &CompactJweEncryptRequest::new(&too_large, enc).with_kid(kid),
                &mut DirectJweKeyEncryptor::new(&key),
                &mut FixedRandom::new([2_u8; 12]),
            ),
            Err(JweError::InputTooLarge)
        ));
    }
}
