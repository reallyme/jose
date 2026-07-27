// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Protobuf conversion for JWT operations.

use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseCompactResult, JoseErrorReason, JoseJwtClaimsResult, JoseJwtDecodeUnsignedRequest,
    JoseJwtEncodeUnsignedRequest, JoseJwtSignRequest, JoseJwtTemporalValidationPolicy,
    JoseJwtVerifyRequest,
};
use zeroize::Zeroizing;

use crate::jwt::{
    JwtClaimsValidationPolicy, JwtError, JwtHeaderEncodeOptions, JwtHeaderValidationOptions,
    JwtTemporalValidationPolicy,
};
use crate::operation_contract::jwt::{
    decode_unsigned_jwt, encode_unsigned_jwt, sign_jwt, verify_jwt_signature_only,
    verify_jwt_with_claims_policy,
};
use crate::wire::{JoseWireError, JoseWireResult};

use super::jwt_jwk::{jwk_from_json, JwkOperation};

pub(crate) fn encode_unsigned_jwt_request(
    mut request: JoseJwtEncodeUnsignedRequest,
) -> JoseWireResult<JoseCompactResult> {
    let claims_json = Zeroizing::new(core::mem::take(&mut request.claims_json));
    let compact = encode_unsigned_jwt(&claims_json).map_err(map_jwt_error)?;
    Ok(compact_result(compact))
}

pub(crate) fn decode_unsigned_jwt_request(
    mut request: JoseJwtDecodeUnsignedRequest,
) -> JoseWireResult<JoseJwtClaimsResult> {
    let compact = Zeroizing::new(core::mem::take(&mut request.compact));
    let mut claims_json = decode_unsigned_jwt(&compact).map_err(map_jwt_error)?;
    Ok(JoseJwtClaimsResult {
        claims_json: core::mem::take(&mut claims_json),
        __buffa_unknown_fields: Default::default(),
    })
}

pub(crate) fn sign_jwt_request(
    mut request: JoseJwtSignRequest,
) -> JoseWireResult<JoseCompactResult> {
    let private_key = Zeroizing::new(core::mem::take(&mut request.private_key));
    let claims_json = Zeroizing::new(core::mem::take(&mut request.claims_json));
    let jwk_json = Zeroizing::new(core::mem::take(&mut request.jwk_json));
    let jwk = jwk_from_json(&jwk_json, JwkOperation::Sign)?;
    let header_options = if request.typ.is_empty() {
        JwtHeaderEncodeOptions::jwt()
    } else {
        JwtHeaderEncodeOptions::new(Some(core::mem::take(&mut request.typ)))
    };
    let compact =
        sign_jwt(&claims_json, &jwk, &private_key, &header_options).map_err(map_jwt_error)?;
    Ok(compact_result(compact))
}

pub(crate) fn verify_jwt_request(
    mut request: JoseJwtVerifyRequest,
) -> JoseWireResult<JoseJwtClaimsResult> {
    let compact = Zeroizing::new(core::mem::take(&mut request.compact));
    let jwk_json = Zeroizing::new(core::mem::take(&mut request.jwk_json));
    let jwk = jwk_from_json(&jwk_json, JwkOperation::Verify)?;
    let accepted_typ_values: Vec<&str> = request
        .header_policy
        .accepted_typ_values
        .iter()
        .map(String::as_str)
        .collect();
    let header_policy = if request.header_policy.is_set() {
        JwtHeaderValidationOptions::new(
            request.header_policy.allow_missing_typ,
            request.header_policy.allow_embedded_key_header,
            &accepted_typ_values,
        )
    } else {
        JwtHeaderValidationOptions::standard_jwt()
    };

    let temporal_policy_is_set = request.temporal_policy.is_set();
    if temporal_policy_is_set == request.signature_only {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
        ));
    }

    let mut claims_json = if temporal_policy_is_set {
        let mut temporal_policy = request.temporal_policy.take().ok_or_else(|| {
            JoseWireError::primitive_internal(
                JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
            )
        })?;
        if temporal_policy.now_unix == 0 {
            return Err(JoseWireError::primitive_internal(
                JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME,
            ));
        }
        let expected_audience =
            Zeroizing::new(core::mem::take(&mut temporal_policy.expected_audience));
        let expected_issuer = Zeroizing::new(core::mem::take(&mut temporal_policy.expected_issuer));
        let expected_subject =
            Zeroizing::new(core::mem::take(&mut temporal_policy.expected_subject));
        let claims_policy = JwtClaimsValidationPolicy::new(
            temporal_policy_from_proto(&temporal_policy),
            &expected_audience,
            optional_expected_claim(&expected_issuer),
            optional_expected_claim(&expected_subject),
        );
        verify_jwt_with_claims_policy(
            &compact,
            &jwk,
            &request.public_key,
            temporal_policy.now_unix,
            claims_policy,
            &header_policy,
        )
    } else {
        verify_jwt_signature_only(&compact, &jwk, &request.public_key, &header_policy)
    }
    .map_err(map_jwt_error)?;

    Ok(JoseJwtClaimsResult {
        claims_json: core::mem::take(&mut claims_json),
        __buffa_unknown_fields: Default::default(),
    })
}

const fn optional_expected_claim(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn compact_result(compact: String) -> JoseCompactResult {
    JoseCompactResult {
        compact,
        __buffa_unknown_fields: Default::default(),
    }
}

const fn temporal_policy_from_proto(
    policy: &JoseJwtTemporalValidationPolicy,
) -> JwtTemporalValidationPolicy {
    JwtTemporalValidationPolicy::new(
        policy.require_exp,
        policy.require_nbf,
        policy.require_iat,
        policy.clock_skew_seconds,
        policy.max_future_iat_skew_seconds,
    )
}

const fn map_jwt_error(error: JwtError) -> JoseWireError {
    let reason = match error {
        JwtError::InvalidJwtFormat => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_COMPACT,
        JwtError::InputTooLarge => JoseErrorReason::JOSE_ERROR_REASON_JWT_INPUT_TOO_LARGE,
        JwtError::Base64Url => JoseErrorReason::JOSE_ERROR_REASON_JWT_BASE64URL_DECODE_FAILED,
        JwtError::LengthOverflow => JoseErrorReason::JOSE_ERROR_REASON_JWT_LENGTH_OVERFLOW,
        JwtError::InvalidHeader => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_HEADER,
        JwtError::UnsupportedAlgorithm => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_UNSUPPORTED_ALGORITHM
        }
        JwtError::AlgorithmMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_ALGORITHM_MISMATCH,
        JwtError::KeyIdMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_KID_POLICY_MISMATCH,
        JwtError::PublicKeyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_PUBLIC_KEY_MISMATCH,
        JwtError::SigningKeyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_SIGNING_KEY_MISMATCH,
        JwtError::MissingAlgorithm => JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_ALGORITHM,
        JwtError::MissingPrivateKey => JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_PRIVATE_KEY,
        JwtError::MissingPublicKey => JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_PUBLIC_KEY,
        JwtError::InvalidPublicKey => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_PUBLIC_KEY,
        JwtError::InvalidSignature => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_SIGNATURE,
        JwtError::Crypto => JoseErrorReason::JOSE_ERROR_REASON_JWT_CRYPTO_FAILED,
        JwtError::InvalidClaims => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_CLAIMS,
        JwtError::Serialization => JoseErrorReason::JOSE_ERROR_REASON_JWT_SERIALIZATION_FAILED,
        JwtError::MissingRequiredTemporalClaim(_) => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_REQUIRED_TEMPORAL_CLAIM
        }
        JwtError::InvalidTemporalClaimValue(_) => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_TEMPORAL_CLAIM_VALUE
        }
        JwtError::Expired => JoseErrorReason::JOSE_ERROR_REASON_JWT_EXPIRED,
        JwtError::NotYetValid => JoseErrorReason::JOSE_ERROR_REASON_JWT_NOT_YET_VALID,
        JwtError::IssuedAtInFuture => JoseErrorReason::JOSE_ERROR_REASON_JWT_ISSUED_AT_IN_FUTURE,
        JwtError::InvalidVerificationTime => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME
        }
        JwtError::InvalidTemporalPolicy => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY
        }
        JwtError::MissingRequiredRegisteredClaim(_) => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_REQUIRED_REGISTERED_CLAIM
        }
        JwtError::InvalidRegisteredClaimValue(_) => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_REGISTERED_CLAIM_VALUE
        }
        JwtError::AudienceMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_AUDIENCE_MISMATCH,
        JwtError::IssuerMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_ISSUER_MISMATCH,
        JwtError::SubjectMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_SUBJECT_MISMATCH,
        JwtError::InvalidClaimsPolicy => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY
        }
    };
    JoseWireError::primitive_internal(reason)
}
