// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Kani references the replacement functions through stub attributes.
#![allow(dead_code)]

use core::mem::{forget, ManuallyDrop};

use reallyme_crypto::core::{CryptoError, RngOutputKind};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseCompactResult, JoseJweDecryptRequest, JoseJweEncryptRequest, JoseJwePlaintextResult,
    JoseJwsSignRequest, JoseJwsVerifyRequest, JoseJwtClaimsResult, JoseJwtDecodeUnsignedRequest,
    JoseJwtEncodeUnsignedRequest, JoseJwtSignRequest, JoseJwtVerifyRequest, JoseVerifyResult,
};

use crate::api::contract::{
    JoseContractInfoRequest, JoseContractInfoResult, JoseJweDecryptWithProviderRequest,
    JoseJweDeriveKeyRequest, JoseJweEncryptWithProviderRequest, JoseJwtClaimsParseRequest,
    JoseJwtClaimsParseResult, JoseJwtSignWithProviderRequest, JoseSecretBytes, JoseSignatureResult,
    JoseSignatureSignRequest, JoseSignatureSuiteInfoRequest, JoseSignatureSuiteInfoResult,
    JoseSignatureVerifyRequest, JoseValidationResult,
};
use crate::operation_contract::providers::OperationProviders;

use super::{
    backend_output_error, execute_operation_request, validate_contract_version, validate_response,
    EnumValue, JoseOperationKind, JoseOperationRequest, JoseWireResult, RequestOperation, Response,
    SecureRandom,
};

fn operation_kind() -> JoseOperationKind {
    match kani::any::<u8>() {
        0 => JoseOperationKind::JwsSign,
        1 => JoseOperationKind::JwsVerify,
        2 => JoseOperationKind::JwtEncodeUnsigned,
        3 => JoseOperationKind::JwtDecodeUnsigned,
        4 => JoseOperationKind::JwtSign,
        5 => JoseOperationKind::JwtVerify,
        6 => JoseOperationKind::JweEncrypt,
        7 => JoseOperationKind::JweDecrypt,
        8 => JoseOperationKind::SignatureSign,
        9 => JoseOperationKind::SignatureVerify,
        10 => JoseOperationKind::SignatureSuiteInfo,
        11 => JoseOperationKind::JwtSignWithProvider,
        12 => JoseOperationKind::JweDeriveKey,
        13 => JoseOperationKind::JweEncryptWithProvider,
        14 => JoseOperationKind::JweDecryptWithProvider,
        15 => JoseOperationKind::ContractInfo,
        _ => JoseOperationKind::JwtClaimsParse,
    }
}

struct NoRandom;

impl SecureRandom for NoRandom {
    fn fill_secure(
        &mut self,
        _buffer: &mut [u8],
        _output: RngOutputKind,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE)
    }
}

fn adapter_result<T: Default>() -> JoseWireResult<T> {
    if kani::any::<bool>() {
        Ok(T::default())
    } else {
        Err(backend_output_error())
    }
}

// Model the adapter outcomes and omit teardown of the empty request fixtures.
// The dispatcher still moves the real generated oneof and wraps its outcome.
fn stub_sign(request: JoseJwsSignRequest) -> JoseWireResult<JoseCompactResult> {
    forget(request);
    adapter_result()
}

fn stub_verify(_request: &JoseJwsVerifyRequest) -> JoseWireResult<JoseVerifyResult> {
    adapter_result()
}

fn stub_encode(request: JoseJwtEncodeUnsignedRequest) -> JoseWireResult<JoseCompactResult> {
    forget(request);
    adapter_result()
}

fn stub_decode(request: JoseJwtDecodeUnsignedRequest) -> JoseWireResult<JoseJwtClaimsResult> {
    forget(request);
    adapter_result()
}

fn stub_jwt_sign(request: JoseJwtSignRequest) -> JoseWireResult<JoseCompactResult> {
    forget(request);
    adapter_result()
}

fn stub_jwt_verify(request: JoseJwtVerifyRequest) -> JoseWireResult<JoseJwtClaimsResult> {
    forget(request);
    adapter_result()
}

fn stub_encrypt<R: SecureRandom + ?Sized>(
    request: JoseJweEncryptRequest,
    _rng: &mut R,
) -> JoseWireResult<JoseCompactResult> {
    forget(request);
    adapter_result()
}

fn stub_decrypt(request: JoseJweDecryptRequest) -> JoseWireResult<JoseJwePlaintextResult> {
    forget(request);
    adapter_result()
}

fn stub_v2_signature_sign(
    request: JoseSignatureSignRequest,
) -> JoseWireResult<JoseSignatureResult> {
    forget(request);
    adapter_result()
}

fn stub_v2_signature_verify(
    request: JoseSignatureVerifyRequest,
) -> JoseWireResult<JoseValidationResult> {
    forget(request);
    adapter_result()
}

fn stub_v2_signature_suite_info(
    request: JoseSignatureSuiteInfoRequest,
) -> JoseWireResult<JoseSignatureSuiteInfoResult> {
    forget(request);
    adapter_result()
}

fn stub_v2_sign_jwt(
    request: JoseJwtSignWithProviderRequest,
    _providers: &dyn OperationProviders,
) -> JoseWireResult<JoseCompactResult> {
    forget(request);
    adapter_result()
}

fn stub_v2_derive_key(request: JoseJweDeriveKeyRequest) -> JoseWireResult<JoseSecretBytes> {
    forget(request);
    adapter_result()
}

fn stub_v2_encrypt_jwe<R: SecureRandom + ?Sized>(
    request: JoseJweEncryptWithProviderRequest,
    _providers: &mut dyn OperationProviders,
    _rng: &mut R,
) -> JoseWireResult<JoseCompactResult> {
    forget(request);
    adapter_result()
}

fn stub_v2_decrypt_with_provider(
    request: JoseJweDecryptWithProviderRequest,
    _providers: &dyn OperationProviders,
) -> JoseWireResult<JoseJwePlaintextResult> {
    forget(request);
    adapter_result()
}

fn stub_v2_contract_info(
    request: JoseContractInfoRequest,
) -> JoseWireResult<JoseContractInfoResult> {
    forget(request);
    adapter_result()
}

fn stub_v2_parse_claims(
    request: JoseJwtClaimsParseRequest,
) -> JoseWireResult<JoseJwtClaimsParseResult> {
    forget(request);
    adapter_result()
}

fn bounded_request_size(_request: &JoseOperationRequest, _cache: &mut buffa::SizeCache) -> u32 {
    // These generated fixtures fit the wire limit. The proof follows
    // selection and packaging after that independent size boundary.
    0
}

// Omit teardown of the generated test fixtures. This proof follows the
// response selection and the separate ABI harnesses check owned cleanup.
fn omit_request_fixture_zeroization(_request: &mut JoseOperationRequest) {}

fn omit_operation_fixture_zeroization(_operation: &mut RequestOperation) {}

macro_rules! omit_fixture_drops {
    ($( $name:ident: $fixture:ty ),+ $(,)?) => {
        $(fn $name(_fixture: &mut $fixture) {})+
    };
}

omit_fixture_drops!(
    omit_contract_info_request: JoseContractInfoRequest,
    omit_jwe_decrypt_request: JoseJweDecryptRequest,
    omit_jwe_decrypt_with_provider_request: JoseJweDecryptWithProviderRequest,
    omit_jwe_derive_key_request: JoseJweDeriveKeyRequest,
    omit_jwe_encrypt_request: JoseJweEncryptRequest,
    omit_jwe_encrypt_with_provider_request: JoseJweEncryptWithProviderRequest,
    omit_jws_sign_request: JoseJwsSignRequest,
    omit_jws_verify_request: JoseJwsVerifyRequest,
    omit_jwt_claims_parse_request: JoseJwtClaimsParseRequest,
    omit_jwt_decode_unsigned_request: JoseJwtDecodeUnsignedRequest,
    omit_jwt_encode_unsigned_request: JoseJwtEncodeUnsignedRequest,
    omit_jwt_sign_request: JoseJwtSignRequest,
    omit_jwt_sign_with_provider_request: JoseJwtSignWithProviderRequest,
    omit_jwt_verify_request: JoseJwtVerifyRequest,
    omit_signature_sign_request: JoseSignatureSignRequest,
    omit_signature_suite_info_request: JoseSignatureSuiteInfoRequest,
    omit_signature_verify_request: JoseSignatureVerifyRequest,
);

kani::stub_set!(
    operation_adapters,
    stub(
        <JoseOperationRequest as buffa::Message>::compute_size,
        bounded_request_size
    ),
    stub(
        <JoseOperationRequest as core::ops::Drop>::drop,
        omit_request_fixture_zeroization
    ),
    stub(
        <RequestOperation as core::ops::Drop>::drop,
        omit_operation_fixture_zeroization
    ),
    stub(
        <JoseContractInfoRequest as core::ops::Drop>::drop,
        omit_contract_info_request
    ),
    stub(
        <JoseJweDecryptRequest as core::ops::Drop>::drop,
        omit_jwe_decrypt_request
    ),
    stub(
        <JoseJweDecryptWithProviderRequest as core::ops::Drop>::drop,
        omit_jwe_decrypt_with_provider_request
    ),
    stub(
        <JoseJweDeriveKeyRequest as core::ops::Drop>::drop,
        omit_jwe_derive_key_request
    ),
    stub(
        <JoseJweEncryptRequest as core::ops::Drop>::drop,
        omit_jwe_encrypt_request
    ),
    stub(
        <JoseJweEncryptWithProviderRequest as core::ops::Drop>::drop,
        omit_jwe_encrypt_with_provider_request
    ),
    stub(
        <JoseJwsSignRequest as core::ops::Drop>::drop,
        omit_jws_sign_request
    ),
    stub(
        <JoseJwsVerifyRequest as core::ops::Drop>::drop,
        omit_jws_verify_request
    ),
    stub(
        <JoseJwtClaimsParseRequest as core::ops::Drop>::drop,
        omit_jwt_claims_parse_request
    ),
    stub(
        <JoseJwtDecodeUnsignedRequest as core::ops::Drop>::drop,
        omit_jwt_decode_unsigned_request
    ),
    stub(
        <JoseJwtEncodeUnsignedRequest as core::ops::Drop>::drop,
        omit_jwt_encode_unsigned_request
    ),
    stub(
        <JoseJwtSignRequest as core::ops::Drop>::drop,
        omit_jwt_sign_request
    ),
    stub(
        <JoseJwtSignWithProviderRequest as core::ops::Drop>::drop,
        omit_jwt_sign_with_provider_request
    ),
    stub(
        <JoseJwtVerifyRequest as core::ops::Drop>::drop,
        omit_jwt_verify_request
    ),
    stub(
        <JoseSignatureSignRequest as core::ops::Drop>::drop,
        omit_signature_sign_request
    ),
    stub(
        <JoseSignatureSuiteInfoRequest as core::ops::Drop>::drop,
        omit_signature_suite_info_request
    ),
    stub(
        <JoseSignatureVerifyRequest as core::ops::Drop>::drop,
        omit_signature_verify_request
    ),
    stub(super::sign_jws_request, stub_sign),
    stub(super::verify_jws_request, stub_verify),
    stub(super::encode_unsigned_jwt_request, stub_encode),
    stub(super::decode_unsigned_jwt_request, stub_decode),
    stub(super::sign_jwt_request, stub_jwt_sign),
    stub(super::verify_jwt_request, stub_jwt_verify),
    stub(super::encrypt_jwe_request, stub_encrypt),
    stub(super::decrypt_jwe_request, stub_decrypt),
    stub(super::extended::signature_sign, stub_v2_signature_sign),
    stub(super::extended::signature_verify, stub_v2_signature_verify),
    stub(
        super::extended::signature_suite_info,
        stub_v2_signature_suite_info
    ),
    stub(super::capabilities::sign_jwt, stub_v2_sign_jwt),
    stub(super::extended::derive_key, stub_v2_derive_key),
    stub(super::capabilities::encrypt_jwe, stub_v2_encrypt_jwe),
    stub(
        super::capabilities::decrypt_with_provider,
        stub_v2_decrypt_with_provider
    ),
    stub(super::extended::contract_info, stub_v2_contract_info),
    stub(super::extended::parse_claims, stub_v2_parse_claims),
);

// Fix the request arm in each harness so Kani can check dispatch independently
// of the other arms' generated allocation and destructors. Each harness still
// checks every consumer operation and both adapter outcomes.
macro_rules! prove_dispatch_arm {
    ($proof:ident, $operation:ident, $outcome:ident) => {
        #[kani::proof]
        #[kani::unwind(2)]
        #[kani::use_stub_set(operation_adapters)]
        fn $proof() {
            let request = JoseOperationRequest {
                operation: Some(RequestOperation::$operation(Box::default())),
            };
            // Model the lifetime through validation only. Generated response
            // owners here contain empty test payloads or a typed error.
            let response = ManuallyDrop::new(execute_operation_request(request, &mut NoRandom));
            let result = matches!(response.response.as_ref(), Some(Response::$operation(value))
                if matches!(value.outcome, Some(super::$outcome::Result(_))));
            let error = matches!(response.response.as_ref(), Some(Response::$operation(value))
                if matches!(value.outcome, Some(super::$outcome::Error(_))));
            kani::assert(result || error, "the selected operation owns the outcome");

            let expected = operation_kind();
            let validation = validate_response(&response, expected);
            let matches_request = expected == JoseOperationKind::$operation;
            kani::assert(
                validation == if matches_request { Ok(()) } else { Err(backend_output_error()) },
                "only a consumer expecting the selected operation accepts its response",
            );
            kani::cover!(validation.is_ok() && result, "matching result accepted");
            kani::cover!(validation.is_ok() && error, "matching operation error accepted");
            kani::cover!(validation.is_err() && result, "mismatched result rejected");
            kani::cover!(validation.is_err() && error, "mismatched operation error rejected");
        }
    };
}

prove_dispatch_arm!(jws_sign_dispatch, JwsSign, JwsSignOutcome);
prove_dispatch_arm!(jws_verify_dispatch, JwsVerify, JwsVerifyOutcome);
prove_dispatch_arm!(
    jwt_encode_unsigned_dispatch,
    JwtEncodeUnsigned,
    JwtEncodeUnsignedOutcome
);
prove_dispatch_arm!(
    jwt_decode_unsigned_dispatch,
    JwtDecodeUnsigned,
    JwtDecodeUnsignedOutcome
);
prove_dispatch_arm!(jwt_sign_dispatch, JwtSign, JwtSignOutcome);
prove_dispatch_arm!(jwt_verify_dispatch, JwtVerify, JwtVerifyOutcome);
prove_dispatch_arm!(jwe_encrypt_dispatch, JweEncrypt, JweEncryptOutcome);
prove_dispatch_arm!(jwe_decrypt_dispatch, JweDecrypt, JweDecryptOutcome);
prove_dispatch_arm!(signature_sign_dispatch, SignatureSign, SignatureSignOutcome);
prove_dispatch_arm!(
    signature_verify_dispatch,
    SignatureVerify,
    SignatureVerifyOutcome
);
prove_dispatch_arm!(
    signature_suite_info_dispatch,
    SignatureSuiteInfo,
    SignatureSuiteInfoOutcome
);
prove_dispatch_arm!(
    sign_jwt_dispatch,
    JwtSignWithProvider,
    JwtSignWithProviderOutcome
);
prove_dispatch_arm!(derive_key_dispatch, JweDeriveKey, JweDeriveKeyOutcome);
prove_dispatch_arm!(
    encrypt_jwe_dispatch,
    JweEncryptWithProvider,
    JweEncryptWithProviderOutcome
);
prove_dispatch_arm!(
    decrypt_with_provider_dispatch,
    JweDecryptWithProvider,
    JweDecryptWithProviderOutcome
);
prove_dispatch_arm!(contract_info_dispatch, ContractInfo, ContractInfoOutcome);
prove_dispatch_arm!(parse_claims_dispatch, JwtClaimsParse, JwtClaimsParseOutcome);

#[kani::proof]
#[kani::unwind(2)]
#[kani::use_stub_set(operation_adapters)]
fn missing_request_operation_produces_only_a_boundary_error() {
    let response = ManuallyDrop::new(execute_operation_request(
        JoseOperationRequest::default(),
        &mut NoRandom,
    ));
    kani::assert(
        matches!(response.response.as_ref(), Some(Response::BoundaryError(_))),
        "a missing selector produces only a boundary error",
    );
    kani::cover!(
        validate_response(&response, operation_kind()).is_ok(),
        "valid boundary error"
    );
}

#[kani::proof]
fn canonical_response_requires_the_exact_supported_version() {
    let version = kani::any::<i32>();
    let result = validate_contract_version(EnumValue::from(version));
    if version == 2 {
        kani::assert(
            result.is_ok(),
            "the version defined for this response contract is accepted",
        );
    } else {
        kani::assert(
            result == Err(backend_output_error()),
            "all other version numbers are rejected",
        );
    }
    kani::cover!(
        version == 0 && result.is_err(),
        "unspecified version rejected"
    );
    kani::cover!(
        version > 2 && result.is_err(),
        "unknown future version rejected"
    );
    kani::cover!(version == 1 && result.is_err(), "retired V1 rejected");
    kani::cover!(result.is_ok(), "supported V2 accepted");
}
