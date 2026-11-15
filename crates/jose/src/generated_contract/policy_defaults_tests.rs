// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::{OPENID_CONTENT_ENCRYPTION, OPENID_KEY_MANAGEMENT};

#[test]
fn presets_match_generated_contract_and_native_defaults() -> Result<(), serde_json::Error> {
    let standard_jwt_encode: crate::api::contract::JoseJwtHeaderEncodeOptions =
        serde_json::from_str(r#"{"typ":"JWT"}"#)?;
    let strict_temporal: crate::api::contract::JoseJwtTemporalOptions = serde_json::from_str(
        r#"{"requireExp":true,"requireNbf":false,"requireIat":false,"clockSkewSeconds":"60","maxFutureIatSkewSeconds":"60"}"#,
    )?;
    let standard_jwt_header: crate::api::contract::JoseJwtHeaderValidationPolicy =
        serde_json::from_str(
            r#"{"allowMissingTyp":false,"allowEmbeddedKeyHeader":false,"acceptedTypValues":["JWT"]}"#,
        )?;
    let openid4vp: crate::api::contract::JoseJwePolicy = serde_json::from_str(
        r#"{"allowedKeyManagementAlgorithms":["JOSE_JWE_HEADER_ALGORITHM_ECDH_ES","JOSE_JWE_HEADER_ALGORITHM_DIRECT"],"allowedContentEncryptionAlgorithms":["JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM","JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A192GCM","JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM"],"headerPolicy":{}}"#,
    )?;
    assert_eq!(
        standard_jwt_encode.typ.as_deref(),
        crate::jwt::JwtHeaderEncodeOptions::jwt().typ()
    );
    let header = crate::jwt::JwtHeaderValidationOptions::standard_jwt();
    assert_eq!(
        standard_jwt_header.allow_missing_typ,
        header.allow_missing_typ()
    );
    assert_eq!(
        standard_jwt_header.allow_embedded_key_header,
        header.allow_embedded_key_header()
    );
    assert_eq!(
        standard_jwt_header
            .accepted_typ_values
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>(),
        header.accepted_typ_values()
    );
    let temporal = crate::jwt::JwtTemporalValidationPolicy::strict();
    assert_eq!(strict_temporal.require_exp, temporal.require_exp());
    assert_eq!(strict_temporal.require_nbf, temporal.require_nbf());
    assert_eq!(strict_temporal.require_iat, temporal.require_iat());
    assert_eq!(
        strict_temporal.clock_skew_seconds,
        temporal.clock_skew_seconds()
    );
    assert_eq!(
        strict_temporal.max_future_iat_skew_seconds,
        temporal.max_future_iat_skew_seconds()
    );
    let profile = crate::jwe::CompactJwePolicy::openid4vp_direct_post_jwt();
    let _ = profile;
    assert_eq!(
        openid4vp.allowed_key_management_algorithms.as_ref(),
        OPENID_KEY_MANAGEMENT
            .iter()
            .copied()
            .map(crate::api::contract::JoseJweHeaderAlgorithm::from)
            .map(buffa::EnumValue::from)
            .collect::<Vec<_>>()
            .as_slice()
    );
    assert_eq!(
        openid4vp.allowed_content_encryption_algorithms.as_ref(),
        OPENID_CONTENT_ENCRYPTION
            .iter()
            .copied()
            .map(crate::api::contract::JoseJweContentEncryptionAlgorithm::from)
            .map(buffa::EnumValue::from)
            .collect::<Vec<_>>()
            .as_slice()
    );
    Ok(())
}
