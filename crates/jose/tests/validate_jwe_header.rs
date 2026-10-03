// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public compact-JWE protected-header deserialization tests.

use reallyme_jose::jwe::{
    CompactJwePolicy, CompactJweProtectedHeader, JweCompressionAlgorithm,
    JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm,
};

#[test]
fn policy_debug_redacts_bound_identifiers_and_party_info() {
    const ALGORITHMS: [JweKeyManagementAlgorithm; 1] = [JweKeyManagementAlgorithm::EcdhEs];
    const CIPHERS: [JweContentEncryptionAlgorithm; 1] = [JweContentEncryptionAlgorithm::A128Gcm];
    let policy = CompactJwePolicy::new(&ALGORITHMS, &CIPHERS)
        .with_expected_kid("secret-kid")
        .with_expected_typ("secret-type")
        .with_expected_cty("secret-content")
        .with_expected_apu(b"secret-u")
        .with_expected_apv(b"secret-v");
    let debug = format!("{policy:?}");
    assert!(debug.contains("<redacted>"));
    for secret in [
        "secret-kid",
        "secret-type",
        "secret-content",
        "secret-u",
        "secret-v",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn public_header_deserialization_accepts_a_hardened_direct_header() {
    let header = serde_json::from_str::<CompactJweProtectedHeader>(
        r#"{"alg":"dir","enc":"A128GCM","applicationExtension":true}"#,
    );

    assert!(matches!(
        header.as_ref().map(|value| value.alg),
        Ok(JweKeyManagementAlgorithm::Direct)
    ));
}

#[test]
fn public_header_deserialization_accepts_typed_deflate() {
    let header = serde_json::from_str::<CompactJweProtectedHeader>(
        r#"{"alg":"dir","enc":"A128GCM","zip":"DEF"}"#,
    );

    assert!(matches!(
        header.as_ref().map(|value| value.zip),
        Ok(Some(JweCompressionAlgorithm::Deflate))
    ));
}

#[test]
fn public_header_deserialization_rejects_dangerous_and_duplicate_members() {
    for header in [
        r#"{"alg":"dir","alg":"dir","enc":"A128GCM"}"#,
        r#"{"alg":"dir","enc":"A128GCM","b64":false}"#,
        r#"{"alg":"dir","enc":"A128GCM","crit":["applicationExtension"]}"#,
        r#"{"alg":"dir","enc":"A128GCM","zip":"GZIP"}"#,
        r#"{"alg":"dir","enc":"A128GCM","zip":"DEF","zip":"DEF"}"#,
        r#"{"alg":"dir","enc":"A128GCM","jku":"https://example.invalid/jwks"}"#,
        r#"{"alg":"dir","enc":"A128GCM","x5u":"https://example.invalid/cert"}"#,
        r#"{"alg":"dir","enc":"A128GCM","x5c":[]}"#,
        r#"{"alg":"dir","enc":"A128GCM","jwk":{}}"#,
    ] {
        assert!(serde_json::from_str::<CompactJweProtectedHeader>(header).is_err());
    }
}

#[test]
fn public_header_deserialization_rejects_unhardened_epk_shapes() {
    for header in [
        r#"{"alg":"ECDH-ES","enc":"A128GCM"}"#,
        r#"{"alg":"dir","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}"#,
        r#"{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","x":"AQ","y":"AA"}}"#,
        r#"{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA","kid":"unexpected"}}"#,
        r#"{"alg":"ECDH-ES","enc":"A128GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"private"}}"#,
    ] {
        assert!(serde_json::from_str::<CompactJweProtectedHeader>(header).is_err());
    }
}
