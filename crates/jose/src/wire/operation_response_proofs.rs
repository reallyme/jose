// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Kani references the replacement functions through stub attributes.
#![allow(dead_code)]

use core::mem::{forget, ManuallyDrop};

use reallyme_crypto::core::{CryptoError, RngFailureKind, RngOutputKind};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseJweDecryptRequest, JoseJweEncryptRequest, JoseJwsSignRequest, JoseJwsVerifyRequest,
    JoseJwtDecodeUnsignedRequest, JoseJwtEncodeUnsignedRequest, JoseJwtSignRequest,
    JoseJwtVerifyRequest,
};

use super::{
    backend_output_error, execute_operation_request, validate_contract_version, validate_response,
    EnumValue, JoseCompactResult, JoseJwePlaintextResult, JoseJwtClaimsResult, JoseOperationKind,
    JoseOperationRequest, JoseVerifyResult, JoseWireResult, RequestOperation, Response,
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
        _ => JoseOperationKind::JweDecrypt,
    }
}

struct NoRandom;

impl SecureRandom for NoRandom {
    fn fill_secure(
        &mut self,
        _buffer: &mut [u8],
        output: RngOutputKind,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Rng {
            output,
            kind: RngFailureKind::EntropyUnavailable,
        })
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

// JWS verification borrows its request, so the dispatcher still owns and
// drops that empty fixture after the simulated adapter call.
fn omit_jws_verify_fixture_zeroization(_request: &mut JoseJwsVerifyRequest) {}

kani::stub_set!(
    operation_adapters,
    stub(super::sign_jws_request, stub_sign),
    stub(super::verify_jws_request, stub_verify),
    stub(
        <JoseJwsVerifyRequest as core::ops::Drop>::drop,
        omit_jws_verify_fixture_zeroization
    ),
    stub(super::encode_unsigned_jwt_request, stub_encode),
    stub(super::decode_unsigned_jwt_request, stub_decode),
    stub(super::sign_jwt_request, stub_jwt_sign),
    stub(super::verify_jwt_request, stub_jwt_verify),
    stub(super::encrypt_jwe_request, stub_encrypt),
    stub(super::decrypt_jwe_request, stub_decrypt),
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
                __buffa_unknown_fields: Default::default(),
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
    if version == 1 {
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
        version > 1 && result.is_err(),
        "unknown future version rejected"
    );
    kani::cover!(result.is_ok(), "supported version accepted");
}
