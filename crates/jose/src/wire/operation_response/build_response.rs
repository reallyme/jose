// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pair generated operation results with their exact response branch.

use super::{canonical_response, jose_error, JoseWireResult};
use crate::api::contract::__buffa::oneof::{
    jose_contract_info_response::Outcome as ContractInfoOutcome,
    jose_jwe_decrypt_response::Outcome as JweDecryptOutcome,
    jose_jwe_decrypt_with_provider_response::Outcome as JweDecryptWithProviderOutcome,
    jose_jwe_derive_key_response::Outcome as JweDeriveKeyOutcome,
    jose_jwe_encrypt_response::Outcome as JweEncryptOutcome,
    jose_jwe_encrypt_with_provider_response::Outcome as JweEncryptWithProviderOutcome,
    jose_jws_sign_response::Outcome as JwsSignOutcome,
    jose_jws_verify_response::Outcome as JwsVerifyOutcome,
    jose_jwt_decode_unsigned_response::Outcome as JwtDecodeUnsignedOutcome,
    jose_jwt_encode_unsigned_response::Outcome as JwtEncodeUnsignedOutcome,
    jose_jwt_sign_response::Outcome as JwtSignOutcome,
    jose_jwt_sign_with_provider_response::Outcome as JwtSignWithProviderOutcome,
    jose_jwt_verify_response::Outcome as JwtVerifyOutcome, jose_operation_response::Response,
    jose_signature_sign_response::Outcome as SignatureSignOutcome,
    jose_signature_suite_info_response::Outcome as SignatureSuiteInfoOutcome,
    jose_signature_verify_response::Outcome as SignatureVerifyOutcome,
};
use crate::api::contract::{
    JoseCompactResult, JoseContractInfoResponse, JoseContractInfoResult, JoseJweDecryptResponse,
    JoseJweDecryptWithProviderResponse, JoseJweDeriveKeyResponse, JoseJweEncryptResponse,
    JoseJweEncryptWithProviderResponse, JoseJwePlaintextResult, JoseJwsSignResponse,
    JoseJwsVerifyResponse, JoseJwtClaimsResult, JoseJwtDecodeUnsignedResponse,
    JoseJwtEncodeUnsignedResponse, JoseJwtSignResponse, JoseJwtSignWithProviderResponse,
    JoseJwtVerifyResponse, JoseOperationResponse, JoseSecretBytes, JoseSignatureResult,
    JoseSignatureSignResponse, JoseSignatureSuiteInfoResponse, JoseSignatureSuiteInfoResult,
    JoseSignatureVerifyResponse, JoseValidationResult, JoseVerifyResult,
};

pub(super) fn jws_sign_response(
    result: JoseWireResult<JoseCompactResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwsSignOutcome::Result(Box::new(result)),
        Err(error) => JwsSignOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwsSign(Box::new(JoseJwsSignResponse {
        outcome: Some(outcome),
    })))
}

pub(super) fn jws_verify_response(
    result: JoseWireResult<JoseVerifyResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwsVerifyOutcome::Result(Box::new(result)),
        Err(error) => JwsVerifyOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwsVerify(Box::new(JoseJwsVerifyResponse {
        outcome: Some(outcome),
    })))
}

pub(super) fn jwt_encode_unsigned_response(
    result: JoseWireResult<JoseCompactResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwtEncodeUnsignedOutcome::Result(Box::new(result)),
        Err(error) => JwtEncodeUnsignedOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtEncodeUnsigned(Box::new(
        JoseJwtEncodeUnsignedResponse {
            outcome: Some(outcome),
        },
    )))
}

pub(super) fn jwt_decode_unsigned_response(
    result: JoseWireResult<JoseJwtClaimsResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwtDecodeUnsignedOutcome::Result(Box::new(result)),
        Err(error) => JwtDecodeUnsignedOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtDecodeUnsigned(Box::new(
        JoseJwtDecodeUnsignedResponse {
            outcome: Some(outcome),
        },
    )))
}

pub(super) fn jwt_sign_response(
    result: JoseWireResult<JoseCompactResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwtSignOutcome::Result(Box::new(result)),
        Err(error) => JwtSignOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtSign(Box::new(JoseJwtSignResponse {
        outcome: Some(outcome),
    })))
}

pub(super) fn jwt_verify_response(
    result: JoseWireResult<JoseJwtClaimsResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwtVerifyOutcome::Result(Box::new(result)),
        Err(error) => JwtVerifyOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtVerify(Box::new(JoseJwtVerifyResponse {
        outcome: Some(outcome),
    })))
}

pub(super) fn jwe_encrypt_response(
    result: JoseWireResult<JoseCompactResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JweEncryptOutcome::Result(Box::new(result)),
        Err(error) => JweEncryptOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JweEncrypt(Box::new(JoseJweEncryptResponse {
        outcome: Some(outcome),
    })))
}

pub(super) fn jwe_decrypt_response(
    result: JoseWireResult<JoseJwePlaintextResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JweDecryptOutcome::Result(Box::new(result)),
        Err(error) => JweDecryptOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JweDecrypt(Box::new(JoseJweDecryptResponse {
        outcome: Some(outcome),
    })))
}

pub(super) fn signature_sign_response(
    result: JoseWireResult<JoseSignatureResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => SignatureSignOutcome::Result(Box::new(result)),
        Err(error) => SignatureSignOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::SignatureSign(Box::new(
        JoseSignatureSignResponse {
            outcome: Some(outcome),
        },
    )))
}

pub(super) fn signature_verify_response(
    result: JoseWireResult<JoseValidationResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => SignatureVerifyOutcome::Result(Box::new(result)),
        Err(error) => SignatureVerifyOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::SignatureVerify(Box::new(
        JoseSignatureVerifyResponse {
            outcome: Some(outcome),
        },
    )))
}

pub(super) fn signature_suite_info_response(
    result: JoseWireResult<JoseSignatureSuiteInfoResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => SignatureSuiteInfoOutcome::Result(Box::new(result)),
        Err(error) => SignatureSuiteInfoOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::SignatureSuiteInfo(Box::new(
        JoseSignatureSuiteInfoResponse {
            outcome: Some(outcome),
        },
    )))
}

pub(super) fn jwt_sign_with_provider_response(
    result: JoseWireResult<JoseCompactResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JwtSignWithProviderOutcome::Result(Box::new(result)),
        Err(error) => JwtSignWithProviderOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtSignWithProvider(Box::new(
        JoseJwtSignWithProviderResponse {
            outcome: Some(outcome),
        },
    )))
}

pub(super) fn jwe_derive_key_response(
    result: JoseWireResult<JoseSecretBytes>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JweDeriveKeyOutcome::Result(Box::new(result)),
        Err(error) => JweDeriveKeyOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JweDeriveKey(Box::new(JoseJweDeriveKeyResponse {
        outcome: Some(outcome),
    })))
}

pub(super) fn jwe_encrypt_with_provider_response(
    result: JoseWireResult<JoseCompactResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JweEncryptWithProviderOutcome::Result(Box::new(result)),
        Err(error) => JweEncryptWithProviderOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JweEncryptWithProvider(Box::new(
        JoseJweEncryptWithProviderResponse {
            outcome: Some(outcome),
        },
    )))
}

pub(super) fn jwe_decrypt_with_provider_response(
    result: JoseWireResult<JoseJwePlaintextResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => JweDecryptWithProviderOutcome::Result(Box::new(result)),
        Err(error) => JweDecryptWithProviderOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JweDecryptWithProvider(Box::new(
        JoseJweDecryptWithProviderResponse {
            outcome: Some(outcome),
        },
    )))
}

pub(super) fn contract_info_response(
    result: JoseWireResult<JoseContractInfoResult>,
) -> JoseOperationResponse {
    let outcome = match result {
        Ok(result) => ContractInfoOutcome::Result(Box::new(result)),
        Err(error) => ContractInfoOutcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::ContractInfo(Box::new(JoseContractInfoResponse {
        outcome: Some(outcome),
    })))
}

pub(super) fn jwt_claims_parse_response(
    result: JoseWireResult<crate::api::contract::JoseJwtClaimsParseResult>,
) -> JoseOperationResponse {
    use crate::api::contract::__buffa::oneof::jose_jwt_claims_parse_response::Outcome;
    let outcome = match result {
        Ok(result) => Outcome::Result(Box::new(result)),
        Err(error) => Outcome::Error(Box::new(jose_error(error))),
    };
    canonical_response(Response::JwtClaimsParse(Box::new(
        crate::api::contract::JoseJwtClaimsParseResponse {
            outcome: Some(outcome),
        },
    )))
}
