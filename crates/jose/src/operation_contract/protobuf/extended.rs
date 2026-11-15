// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated adapters for retained primitive and contract-inspection operations.

use buffa::{EnumValue, Enumeration};
use reallyme_codec::base64url::bytes_to_base64url;
use zeroize::Zeroizing;

use crate::api::contract::{
    JoseContractInfoRequest, JoseContractInfoResult, JoseContractLimit, JoseErrorBranch,
    JoseErrorReason, JoseJweDeriveKeyRequest, JoseJwtClaim, JoseOperationKind, JoseSecretBytes,
    JoseSignatureAlgorithm, JoseSignatureResult, JoseSignatureSignRequest,
    JoseSignatureSuiteInfoRequest, JoseSignatureSuiteInfoResult, JoseSignatureVerifyRequest,
    JoseTransportStatus, JoseValidationResult,
};
use crate::jwe::{
    derive_ecdh_es_content_encryption_key, CompactJweProtectedHeader, JweCompressionAlgorithm,
    JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm,
};
use crate::jws::suites::es256::{sign_p256_jose_prehash, verify_p256_jose_prehash};
use crate::resolve_algorithm::JwtAlgorithm;
use crate::wire::{JoseWireError, JoseWireResult};

fn require_p256(algorithm: EnumValue<JoseSignatureAlgorithm>) -> JoseWireResult<()> {
    if !JwtAlgorithm::try_from(algorithm)?.builtin_raw_provider() {
        return Err(JoseWireError::provider_internal(
            JoseErrorReason::ProviderUnsupported,
        ));
    }
    Ok(())
}

pub(crate) fn signature_sign(
    request: JoseSignatureSignRequest,
) -> JoseWireResult<JoseSignatureResult> {
    require_p256(request.algorithm)?;
    let signature = sign_p256_jose_prehash(&request.private_key, &request.signing_input)
        .map_err(|error| crate::map_failure::es256(&error))?;
    Ok(JoseSignatureResult {
        signature: signature.to_vec().into(),
    })
}

pub(crate) fn signature_verify(
    request: JoseSignatureVerifyRequest,
) -> JoseWireResult<JoseValidationResult> {
    require_p256(request.algorithm)?;
    verify_p256_jose_prehash(
        &request.signature,
        &request.signing_input,
        &request.public_key,
    )
    .map_err(|error| crate::map_failure::es256(&error))?;
    Ok(JoseValidationResult::default())
}

pub(crate) fn signature_suite_info(
    request: JoseSignatureSuiteInfoRequest,
) -> JoseWireResult<JoseSignatureSuiteInfoResult> {
    let selected = JwtAlgorithm::try_from(request.algorithm)?;
    Ok(JoseSignatureSuiteInfoResult {
        algorithm: request.algorithm,
        curve: selected.named_curve().into(),
        encoding: selected.signature_encoding().into(),
        signature_bytes: selected.signature_bytes(),
        builtin_provider: selected.builtin_raw_provider(),
    })
}

pub(crate) fn derive_key(mut request: JoseJweDeriveKeyRequest) -> JoseWireResult<JoseSecretBytes> {
    let secret = Zeroizing::new(core::mem::take(&mut request.shared_secret));
    let mut header = request.header.take().ok_or_else(invalid_header)?;
    let epk_json = Zeroizing::new(header.epk_json.take());
    let apu = Zeroizing::new(header.apu.take());
    let apv = Zeroizing::new(header.apv.take());
    let native = CompactJweProtectedHeader {
        alg: JweKeyManagementAlgorithm::try_from(header.algorithm)?,
        enc: JweContentEncryptionAlgorithm::try_from(header.content_encryption_algorithm)?,
        zip: header
            .compression_algorithm
            .map(JweCompressionAlgorithm::try_from)
            .transpose()?,
        kid: header
            .kid
            .take()
            .map(|value| core::mem::take(&mut *value.into_zeroizing())),
        apu: apu.as_ref().map(|value| bytes_to_base64url(value)),
        apv: apv.as_ref().map(|value| bytes_to_base64url(value)),
        epk: epk_json
            .as_ref()
            .map(|value| serde_json::from_slice(value).map_err(|_| invalid_header()))
            .transpose()?,
        typ: header
            .typ
            .take()
            .map(|value| core::mem::take(&mut *value.into_zeroizing())),
        cty: header
            .cty
            .take()
            .map(|value| core::mem::take(&mut *value.into_zeroizing())),
    };
    let mut derived = derive_ecdh_es_content_encryption_key(&secret, &native)
        .map_err(|error| crate::map_failure::jwe(&error))?;
    Ok(JoseSecretBytes {
        value: core::mem::take(&mut *derived).into(),
    })
}

const fn invalid_header() -> JoseWireError {
    JoseWireError::primitive_internal(JoseErrorReason::JweInvalidHeader)
}

pub(crate) fn contract_info(
    _request: JoseContractInfoRequest,
) -> JoseWireResult<JoseContractInfoResult> {
    Ok(JoseContractInfoResult {
        jwt_policy_limits: crate::api::contract::JoseJwtPolicyLimit::values()
            .iter()
            .copied()
            .filter(|value| *value != crate::api::contract::JoseJwtPolicyLimit::Unspecified)
            .map(EnumValue::from)
            .collect(),
        native_abi_version:
            reallyme_jose_proto::generated::proto::reallyme::jose::v1::JoseNativeAbiVersion::V1
                .into(),
        limits: JoseContractLimit::values()
            .iter()
            .copied()
            .filter(|value| *value != JoseContractLimit::Unspecified)
            .map(EnumValue::from)
            .collect(),
        claim_identifiers: JoseJwtClaim::values()
            .iter()
            .copied()
            .filter(|value| *value != JoseJwtClaim::Unspecified)
            .map(EnumValue::from)
            .collect(),
        error_branches: JoseErrorBranch::values()
            .iter()
            .copied()
            .filter(|value| *value != JoseErrorBranch::Unspecified)
            .map(EnumValue::from)
            .collect(),
        operation_kinds: JoseOperationKind::values()
            .iter()
            .copied()
            .filter(|value| *value != JoseOperationKind::Unspecified)
            .map(EnumValue::from)
            .collect(),
        transport_statuses: JoseTransportStatus::values()
            .iter()
            .copied()
            .filter(|value| *value != JoseTransportStatus::Unspecified)
            .map(EnumValue::from)
            .collect(),
    })
}

pub(crate) fn parse_claims(
    mut request: crate::api::contract::JoseJwtClaimsParseRequest,
) -> JoseWireResult<crate::api::contract::JoseJwtClaimsParseResult> {
    use crate::api::contract::{
        JoseJwtAudience, JoseJwtClaimsParseResult, JoseJwtRegisteredClaims,
    };
    let mut native = crate::operation_contract::jwt::parse_registered_claims(&request.claims_json)
        .map_err(|error| crate::map_failure::jwt(&error))?;
    let mut registered = JoseJwtRegisteredClaims::default();
    registered.iss = native
        .iss
        .take()
        .map(|mut value| core::mem::take(&mut value.0).into());
    registered.sub = native
        .sub
        .take()
        .map(|mut value| core::mem::take(&mut value.0).into());
    if let Some(audience) = native.aud.take() {
        let mut value = JoseJwtAudience::default();
        value.values = audience
            .into_iter()
            .map(|mut value| core::mem::take(&mut value.0).into())
            .collect();
        registered.aud = value.into();
    }
    registered.exp = native.exp.take().map(|value| value.as_i64());
    registered.nbf = native.nbf.take().map(|value| value.as_i64());
    registered.iat = native.iat.take().map(|value| value.as_i64());
    registered.jti = native.jti.take().map(Into::into);
    Ok(JoseJwtClaimsParseResult {
        registered: registered.into(),
        claims_json: core::mem::take(&mut request.claims_json),
    })
}
