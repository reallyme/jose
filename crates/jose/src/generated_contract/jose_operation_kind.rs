// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseOperationKind as Contract;

/// Closed native view of the schema's JoseOperationKind selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JoseOperationKind {
    /// Schema-defined JwsSign identity.
    JwsSign,
    /// Schema-defined JwsVerify identity.
    JwsVerify,
    /// Schema-defined SignatureSign identity.
    SignatureSign,
    /// Schema-defined SignatureVerify identity.
    SignatureVerify,
    /// Schema-defined SignatureSuiteInfo identity.
    SignatureSuiteInfo,
    /// Schema-defined JwsSignWithProvider identity.
    JwsSignWithProvider,
    /// Schema-defined JwsVerifyWithProvider identity.
    JwsVerifyWithProvider,
    /// Schema-defined JwsInspect identity.
    JwsInspect,
    /// Schema-defined JwtEncodeUnsigned identity.
    JwtEncodeUnsigned,
    /// Schema-defined JwtDecodeUnsigned identity.
    JwtDecodeUnsigned,
    /// Schema-defined JwtSign identity.
    JwtSign,
    /// Schema-defined JwtVerify identity.
    JwtVerify,
    /// Schema-defined JwtSignWithProvider identity.
    JwtSignWithProvider,
    /// Schema-defined JwtClaimsParse identity.
    JwtClaimsParse,
    /// Schema-defined JweEncrypt identity.
    JweEncrypt,
    /// Schema-defined JweDecrypt identity.
    JweDecrypt,
    /// Schema-defined JweDeriveKey identity.
    JweDeriveKey,
    /// Schema-defined JweEncryptWithProvider identity.
    JweEncryptWithProvider,
    /// Schema-defined JweDecryptWithProvider identity.
    JweDecryptWithProvider,
    /// Schema-defined ContractInfo identity.
    ContractInfo,
    /// Schema-defined JwkThumbprintSha256 identity.
    JwkThumbprintSha256,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseOperationKind>> for JoseOperationKind {
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_OPERATION_KIND_JWS_SIGN) => Ok(Self::JwsSign),
            Some(Contract::JOSE_OPERATION_KIND_JWS_VERIFY) => Ok(Self::JwsVerify),
            Some(Contract::JOSE_OPERATION_KIND_SIGNATURE_SIGN) => Ok(Self::SignatureSign),
            Some(Contract::JOSE_OPERATION_KIND_SIGNATURE_VERIFY) => Ok(Self::SignatureVerify),
            Some(Contract::JOSE_OPERATION_KIND_SIGNATURE_SUITE_INFO) => {
                Ok(Self::SignatureSuiteInfo)
            }
            Some(Contract::JOSE_OPERATION_KIND_JWS_SIGN_WITH_PROVIDER) => {
                Ok(Self::JwsSignWithProvider)
            }
            Some(Contract::JOSE_OPERATION_KIND_JWS_VERIFY_WITH_PROVIDER) => {
                Ok(Self::JwsVerifyWithProvider)
            }
            Some(Contract::JOSE_OPERATION_KIND_JWS_INSPECT) => Ok(Self::JwsInspect),
            Some(Contract::JOSE_OPERATION_KIND_JWT_ENCODE_UNSIGNED) => Ok(Self::JwtEncodeUnsigned),
            Some(Contract::JOSE_OPERATION_KIND_JWT_DECODE_UNSIGNED) => Ok(Self::JwtDecodeUnsigned),
            Some(Contract::JOSE_OPERATION_KIND_JWT_SIGN) => Ok(Self::JwtSign),
            Some(Contract::JOSE_OPERATION_KIND_JWT_VERIFY) => Ok(Self::JwtVerify),
            Some(Contract::JOSE_OPERATION_KIND_JWT_SIGN_WITH_PROVIDER) => {
                Ok(Self::JwtSignWithProvider)
            }
            Some(Contract::JOSE_OPERATION_KIND_JWT_CLAIMS_PARSE) => Ok(Self::JwtClaimsParse),
            Some(Contract::JOSE_OPERATION_KIND_JWE_ENCRYPT) => Ok(Self::JweEncrypt),
            Some(Contract::JOSE_OPERATION_KIND_JWE_DECRYPT) => Ok(Self::JweDecrypt),
            Some(Contract::JOSE_OPERATION_KIND_JWE_DERIVE_KEY) => Ok(Self::JweDeriveKey),
            Some(Contract::JOSE_OPERATION_KIND_JWE_ENCRYPT_WITH_PROVIDER) => {
                Ok(Self::JweEncryptWithProvider)
            }
            Some(Contract::JOSE_OPERATION_KIND_JWE_DECRYPT_WITH_PROVIDER) => {
                Ok(Self::JweDecryptWithProvider)
            }
            Some(Contract::JOSE_OPERATION_KIND_CONTRACT_INFO) => Ok(Self::ContractInfo),
            Some(Contract::JOSE_OPERATION_KIND_JWK_THUMBPRINT_SHA256) => {
                Ok(Self::JwkThumbprintSha256)
            }
            _ => Err(crate::wire::JoseWireError::backend_internal(
                crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL,
            )),
        }
    }
}

impl From<JoseOperationKind> for Contract {
    fn from(value: JoseOperationKind) -> Self {
        match value {
            JoseOperationKind::JwsSign => Self::JOSE_OPERATION_KIND_JWS_SIGN,
            JoseOperationKind::JwsVerify => Self::JOSE_OPERATION_KIND_JWS_VERIFY,
            JoseOperationKind::SignatureSign => Self::JOSE_OPERATION_KIND_SIGNATURE_SIGN,
            JoseOperationKind::SignatureVerify => Self::JOSE_OPERATION_KIND_SIGNATURE_VERIFY,
            JoseOperationKind::SignatureSuiteInfo => Self::JOSE_OPERATION_KIND_SIGNATURE_SUITE_INFO,
            JoseOperationKind::JwsSignWithProvider => {
                Self::JOSE_OPERATION_KIND_JWS_SIGN_WITH_PROVIDER
            }
            JoseOperationKind::JwsVerifyWithProvider => {
                Self::JOSE_OPERATION_KIND_JWS_VERIFY_WITH_PROVIDER
            }
            JoseOperationKind::JwsInspect => Self::JOSE_OPERATION_KIND_JWS_INSPECT,
            JoseOperationKind::JwtEncodeUnsigned => Self::JOSE_OPERATION_KIND_JWT_ENCODE_UNSIGNED,
            JoseOperationKind::JwtDecodeUnsigned => Self::JOSE_OPERATION_KIND_JWT_DECODE_UNSIGNED,
            JoseOperationKind::JwtSign => Self::JOSE_OPERATION_KIND_JWT_SIGN,
            JoseOperationKind::JwtVerify => Self::JOSE_OPERATION_KIND_JWT_VERIFY,
            JoseOperationKind::JwtSignWithProvider => {
                Self::JOSE_OPERATION_KIND_JWT_SIGN_WITH_PROVIDER
            }
            JoseOperationKind::JwtClaimsParse => Self::JOSE_OPERATION_KIND_JWT_CLAIMS_PARSE,
            JoseOperationKind::JweEncrypt => Self::JOSE_OPERATION_KIND_JWE_ENCRYPT,
            JoseOperationKind::JweDecrypt => Self::JOSE_OPERATION_KIND_JWE_DECRYPT,
            JoseOperationKind::JweDeriveKey => Self::JOSE_OPERATION_KIND_JWE_DERIVE_KEY,
            JoseOperationKind::JweEncryptWithProvider => {
                Self::JOSE_OPERATION_KIND_JWE_ENCRYPT_WITH_PROVIDER
            }
            JoseOperationKind::JweDecryptWithProvider => {
                Self::JOSE_OPERATION_KIND_JWE_DECRYPT_WITH_PROVIDER
            }
            JoseOperationKind::ContractInfo => Self::JOSE_OPERATION_KIND_CONTRACT_INFO,
            JoseOperationKind::JwkThumbprintSha256 => {
                Self::JOSE_OPERATION_KIND_JWK_THUMBPRINT_SHA256
            }
        }
    }
}

#[cfg(test)]
#[path = "jose_operation_kind_tests.rs"]
mod tests;
