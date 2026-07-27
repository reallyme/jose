// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Public compact-JWE protected-header deserialization tests.

use reallyme_jose::jwe::{CompactJweProtectedHeader, JweKeyManagementAlgorithm};

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
fn public_header_deserialization_rejects_dangerous_and_duplicate_members() {
    for header in [
        r#"{"alg":"dir","alg":"dir","enc":"A128GCM"}"#,
        r#"{"alg":"dir","enc":"A128GCM","b64":false}"#,
        r#"{"alg":"dir","enc":"A128GCM","crit":["applicationExtension"]}"#,
        r#"{"alg":"dir","enc":"A128GCM","zip":"DEF"}"#,
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
