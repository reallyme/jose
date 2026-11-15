// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protobuf conversion for JWT operations.

use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    __buffa::oneof::jose_jwt_verification_policy::Mode, JoseCompactResult, JoseErrorReason,
    JoseJwtClaimsResult, JoseJwtDecodeUnsignedRequest, JoseJwtEncodeUnsignedRequest,
    JoseJwtSignRequest, JoseJwtTemporalValidationPolicy, JoseJwtVerifyRequest,
};
use zeroize::Zeroizing;

use crate::jwt::{
    JwtClaimsValidationPolicy, JwtHeaderEncodeOptions, JwtHeaderValidationOptions,
    JwtTemporalValidationPolicy,
};
use crate::operation_contract::jwt::{
    decode_unsigned_jwt, encode_unsigned_jwt, sign_jwt, verify_jwt_signature_only,
    verify_jwt_with_claims_policy, verify_jwt_with_temporal_policy,
};
use crate::wire::{JoseWireError, JoseWireResult};

use super::jwt_jwk::{jwk_from_json, JwkOperation};

pub(crate) fn encode_unsigned_jwt_request(
    mut request: JoseJwtEncodeUnsignedRequest,
) -> JoseWireResult<JoseCompactResult> {
    let claims_json = Zeroizing::new(core::mem::take(&mut request.claims_json));
    let compact =
        encode_unsigned_jwt(&claims_json).map_err(|error| crate::map_failure::jwt(&error))?;
    Ok(compact_result(compact))
}

pub(crate) fn decode_unsigned_jwt_request(
    mut request: JoseJwtDecodeUnsignedRequest,
) -> JoseWireResult<JoseJwtClaimsResult> {
    let compact = Zeroizing::new(core::mem::take(&mut request.compact));
    let mut claims_json =
        decode_unsigned_jwt(&compact).map_err(|error| crate::map_failure::jwt(&error))?;
    Ok(JoseJwtClaimsResult {
        claims_json: core::mem::take(&mut *claims_json).into(),
    })
}

pub(crate) fn sign_jwt_request(
    mut request: JoseJwtSignRequest,
) -> JoseWireResult<JoseCompactResult> {
    let private_key = Zeroizing::new(core::mem::take(&mut request.private_key));
    let claims_json = Zeroizing::new(core::mem::take(&mut request.claims_json));
    let jwk_json = Zeroizing::new(core::mem::take(&mut request.jwk_json));
    let jwk = jwk_from_json(&jwk_json, JwkOperation::Sign)?;
    let header_options = header_options(request.header_options.take())?;
    let compact = sign_jwt(&claims_json, &jwk, &private_key, &header_options)
        .map_err(|error| crate::map_failure::jwt(&error))?;
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
        .map(|value| value.as_str())
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

    let mut verification = request.verification.take().ok_or_else(|| {
        JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
        )
    })?;
    let mut mode = verification.mode.take().ok_or_else(|| {
        JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
        )
    })?;
    let mut claims_json = match &mut mode {
        Mode::Claims(temporal_policy) => {
            if temporal_policy.now_unix == 0 {
                return Err(JoseWireError::primitive_internal(
                    JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME,
                ));
            }
            let expected_audience =
                Zeroizing::new(core::mem::take(&mut temporal_policy.expected_audience));
            let mut issuer_constraint = temporal_policy.expected_issuer_constraint.take();
            let mut subject_constraint = temporal_policy.expected_subject_constraint.take();
            if issuer_constraint
                .as_ref()
                .is_some_and(|constraint| constraint.value.is_empty())
                || subject_constraint
                    .as_ref()
                    .is_some_and(|constraint| constraint.value.is_empty())
            {
                return Err(JoseWireError::primitive_internal(
                    JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
                ));
            }
            let expected_issuer = Zeroizing::new(match issuer_constraint.as_mut() {
                Some(constraint) => core::mem::take(&mut constraint.value),
                None => String::new().into(),
            });
            let expected_subject = Zeroizing::new(match subject_constraint.as_mut() {
                Some(constraint) => core::mem::take(&mut constraint.value),
                None => String::new().into(),
            });
            let claims_policy = JwtClaimsValidationPolicy::new(
                temporal_policy_from_proto(temporal_policy),
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
        }
        Mode::SignatureOnly(_) => {
            verify_jwt_signature_only(&compact, &jwk, &request.public_key, &header_policy)
        }
        Mode::TemporalOnly(policy) => {
            let options = &policy.options;
            verify_jwt_with_temporal_policy(
                &compact,
                &jwk,
                &request.public_key,
                policy.now_unix,
                JwtTemporalValidationPolicy::new(
                    options.require_exp,
                    options.require_nbf,
                    options.require_iat,
                    options.clock_skew_seconds,
                    options.max_future_iat_skew_seconds,
                ),
                &header_policy,
            )
        }
    }
    .map_err(|error| crate::map_failure::jwt(&error))?;

    Ok(JoseJwtClaimsResult {
        claims_json: core::mem::take(&mut *claims_json).into(),
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
        compact: compact.into(),
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

pub(super) fn header_options(
    options: Option<
        reallyme_jose_proto::generated::proto::reallyme::jose::v1::JoseJwtHeaderEncodeOptions,
    >,
) -> JoseWireResult<JwtHeaderEncodeOptions> {
    Ok(match options {
        None => JwtHeaderEncodeOptions::jwt(),
        Some(mut options) => {
            if options.typ.as_ref().is_some_and(|value| value.is_empty()) {
                return Err(JoseWireError::primitive_internal(
                    JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_HEADER,
                ));
            }
            JwtHeaderEncodeOptions::new(
                options
                    .typ
                    .take()
                    .map(|value| core::mem::take(&mut *value.into_zeroizing())),
            )
        }
    })
}
