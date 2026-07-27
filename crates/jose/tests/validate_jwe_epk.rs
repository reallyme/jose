#![allow(missing_docs)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Compact JWE ephemeral-public-key profile tests.

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_jose::jwe::{
    decrypt_compact_jwe_bytes, CompactJwePolicy, JweContentEncryptionAlgorithm, JweError,
    JweKeyManagementAlgorithm, P256EcdhEsJweKeyResolver,
};

const P256_PRIVATE_KEY_LENGTH: usize = 32;
const P256_SHORT_COORDINATE_LENGTH: usize = 31;
const GCM_IV_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;
const ECDH_ES_ALGORITHMS: [JweKeyManagementAlgorithm; 1] = [JweKeyManagementAlgorithm::EcdhEs];
const A128_GCM_ALGORITHMS: [JweContentEncryptionAlgorithm; 1] =
    [JweContentEncryptionAlgorithm::A128Gcm];

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_public_metadata_outside_minimal_epk_profile() {
    const HEADERS: [&[u8]; 3] = [
        br#"{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA","kid":"ephemeral-key"}}"#,
        br#"{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA","use":"enc"}}"#,
        br#"{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA","alg":"ECDH-ES"}}"#,
    ];

    let policy = ecdh_es_a128gcm_policy();
    let recipient_private_key = [1u8; P256_PRIVATE_KEY_LENGTH];
    let resolver = P256EcdhEsJweKeyResolver::new(&recipient_private_key);

    for protected_header in HEADERS {
        let result = decrypt_compact_jwe_bytes(
            &compact_jwe_with_header(protected_header),
            &policy,
            &resolver,
        );
        assert!(matches!(result, Err(JweError::InvalidHeader)));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_shortened_epk_coordinate() -> Result<(), JweError> {
    let short_x = [0u8; P256_SHORT_COORDINATE_LENGTH];
    let full_y = [0u8; P256_PRIVATE_KEY_LENGTH];
    let protected_header = serde_json::json!({
        "alg": "ECDH-ES",
        "enc": "A128GCM",
        "epk": {
            "kty": "EC",
            "crv": "P-256",
            "x": bytes_to_base64url(&short_x),
            "y": bytes_to_base64url(&full_y),
        }
    });
    let protected_header =
        serde_json::to_vec(&protected_header).map_err(|_| JweError::InvalidHeader)?;
    let recipient_private_key = [1u8; P256_PRIVATE_KEY_LENGTH];

    let result = decrypt_compact_jwe_bytes(
        &compact_jwe_with_header(&protected_header),
        &ecdh_es_a128gcm_policy(),
        &P256EcdhEsJweKeyResolver::new(&recipient_private_key),
    );

    assert!(matches!(result, Err(JweError::InvalidKeyAgreementKey)));
    Ok(())
}

const fn ecdh_es_a128gcm_policy() -> CompactJwePolicy<'static> {
    CompactJwePolicy::new(&ECDH_ES_ALGORITHMS, &A128_GCM_ALGORITHMS)
}

fn compact_jwe_with_header(protected_header_json: &[u8]) -> String {
    let protected_header = bytes_to_base64url(protected_header_json);
    let iv = bytes_to_base64url(&[0u8; GCM_IV_LENGTH]);
    let tag = bytes_to_base64url(&[0u8; GCM_TAG_LENGTH]);
    format!("{protected_header}..{iv}..{tag}")
}
