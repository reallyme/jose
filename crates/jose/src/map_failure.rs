// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

//! Total native failure mappings derived from schema bindings.

use crate::jwe::JweError;
use crate::jwk::JwkThumbprintErrorReason;
use crate::jws::suites::{eddsa::JwsEddsaError, es256::JwsEs256Error};
use crate::jwt::JwtError;
use crate::operation_contract::jws::{
    JwsSignError, JwsSignErrorReason, JwsVerifyError, JwsVerifyErrorReason,
};
use crate::wire::{JoseWireError, JoseWireErrorConstructionError};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::JoseErrorReason;

pub(crate) const fn construction(error: &JoseWireErrorConstructionError) -> JoseErrorReason {
    match error {
        JoseWireErrorConstructionError::BranchReasonMismatch => {
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL
        }
    }
}

pub(crate) const fn jwe(error: &JweError) -> JoseWireError {
    match error {
        JweError::InvalidHeader => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_HEADER)
        }
        JweError::UnsupportedKeyManagementAlgorithm => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_KEY_MANAGEMENT_ALGORITHM,
        ),
        JweError::UnsupportedContentEncryptionAlgorithm => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM,
        ),
        JweError::MissingRequiredHeaderParameter => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_MISSING_REQUIRED_HEADER_PARAMETER,
        ),
        JweError::HeaderPolicyMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH,
        ),
        JweError::TypPolicyMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH,
        ),
        JweError::CtyPolicyMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH,
        ),
        JweError::KidPolicyMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_KID_POLICY_MISMATCH,
        ),
        JweError::ApuPolicyMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_APU_POLICY_MISMATCH,
        ),
        JweError::ApvPolicyMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_APV_POLICY_MISMATCH,
        ),
        JweError::UnsupportedCompressionAlgorithm => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_COMPRESSION_ALGORITHM,
        ),
        JweError::InvalidEncryptedKey => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_ENCRYPTED_KEY,
        ),
        JweError::InvalidContentEncryptionKey => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_ENCRYPTION_KEY,
        ),
        JweError::InvalidContentCipherInput => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_CIPHER_INPUT,
        ),
        JweError::Decrypt => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWE_DECRYPT_FAILED)
        }
        JweError::Encrypt => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWE_ENCRYPT_FAILED)
        }
        JweError::InvalidKeyAgreementKey => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_KEY_AGREEMENT_KEY,
        ),
        JweError::InvalidSharedSecret => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_SHARED_SECRET,
        ),
        JweError::InvalidPayloadJson => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_PAYLOAD_JSON,
        ),
        JweError::Compression => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_COMPRESSION_FAILED,
        ),
        JweError::Decompression => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_DECOMPRESSION_FAILED,
        ),
        JweError::DecompressedPlaintextTooLarge => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWE_DECOMPRESSED_PLAINTEXT_TOO_LARGE,
        ),
        JweError::InputTooLarge => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED,
        ),
        JweError::LengthOverflow => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_LENGTH_OVERFLOW,
        ),
        JweError::InvalidCompact => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_INVALID_COMPACT,
        ),
        JweError::InvalidEncoding => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_INVALID_ENCODING,
        ),
        JweError::Randomness => JoseWireError::provider_internal(
            JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
        ),
        JweError::KeyDerivation => JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_KEY_DERIVATION_FAILED,
        ),
    }
}

pub(crate) const fn jwt(error: &JwtError) -> JoseWireError {
    match error {
        JwtError::InvalidHeader => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_HEADER)
        }
        JwtError::UnsupportedAlgorithm => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_UNSUPPORTED_ALGORITHM,
        ),
        JwtError::AlgorithmMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_ALGORITHM_MISMATCH,
        ),
        JwtError::MissingAlgorithm => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_ALGORITHM,
        ),
        JwtError::MissingPrivateKey => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_PRIVATE_KEY,
        ),
        JwtError::MissingPublicKey => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_PUBLIC_KEY,
        ),
        JwtError::KeyIdMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_KID_POLICY_MISMATCH,
        ),
        JwtError::PublicKeyMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_PUBLIC_KEY_MISMATCH,
        ),
        JwtError::InvalidPublicKey => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_PUBLIC_KEY,
        ),
        JwtError::InvalidSignature => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_SIGNATURE,
        ),
        JwtError::Crypto => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWT_CRYPTO_FAILED)
        }
        JwtError::InvalidClaims => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_CLAIMS)
        }
        JwtError::Serialization => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_SERIALIZATION_FAILED,
        ),
        JwtError::MissingRequiredTemporalClaim(_) => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_REQUIRED_TEMPORAL_CLAIM,
        ),
        JwtError::InvalidTemporalClaimValue(_) => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_TEMPORAL_CLAIM_VALUE,
        ),
        JwtError::Expired => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWT_EXPIRED)
        }
        JwtError::NotYetValid => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWT_NOT_YET_VALID)
        }
        JwtError::IssuedAtInFuture => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_ISSUED_AT_IN_FUTURE,
        ),
        JwtError::InvalidVerificationTime => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME,
        ),
        JwtError::InvalidTemporalPolicy => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
        ),
        JwtError::InvalidClaimsPolicy => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
        ),
        JwtError::SigningKeyMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_SIGNING_KEY_MISMATCH,
        ),
        JwtError::MissingRequiredRegisteredClaim(_) => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_REQUIRED_REGISTERED_CLAIM,
        ),
        JwtError::InvalidRegisteredClaimValue(_) => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_REGISTERED_CLAIM_VALUE,
        ),
        JwtError::AudienceMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_AUDIENCE_MISMATCH,
        ),
        JwtError::IssuerMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_ISSUER_MISMATCH,
        ),
        JwtError::SubjectMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_SUBJECT_MISMATCH,
        ),
        JwtError::InputTooLarge => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED,
        ),
        JwtError::LengthOverflow => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_LENGTH_OVERFLOW,
        ),
        JwtError::InvalidJwtFormat => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_INVALID_COMPACT,
        ),
        JwtError::Base64Url => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_INVALID_ENCODING,
        ),
    }
}

pub(crate) const fn jwk_thumbprint(error: &JwkThumbprintErrorReason) -> JoseWireError {
    match error {
        JwkThumbprintErrorReason::MissingMember => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_MISSING_MEMBER,
        ),
        JwkThumbprintErrorReason::InvalidMemberType => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_INVALID_MEMBER_TYPE,
        ),
        JwkThumbprintErrorReason::UnsupportedKeyType => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_UNSUPPORTED_KEY_TYPE,
        ),
        JwkThumbprintErrorReason::InvalidJsonObject => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_INVALID_JSON_OBJECT,
        ),
        JwkThumbprintErrorReason::MemberTooLarge => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_MEMBER_TOO_LARGE,
        ),
        JwkThumbprintErrorReason::LengthOverflow => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_LENGTH_OVERFLOW,
        ),
        JwkThumbprintErrorReason::Serialization => JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_JWK_THUMBPRINT_SERIALIZATION,
        ),
        JwkThumbprintErrorReason::Allocation => JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_JWK_THUMBPRINT_ALLOCATION,
        ),
    }
}

pub(crate) const fn jws_sign(error: &JwsSignError) -> JoseWireError {
    match error.reason() {
        JwsSignErrorReason::SignFailed => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWS_SIGN_FAILED)
        }
        JwsSignErrorReason::BadDerSignature => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_DER_SIGNATURE,
        ),
        JwsSignErrorReason::InputTooLarge => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED,
        ),
        JwsSignErrorReason::LengthOverflow => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_LENGTH_OVERFLOW,
        ),
    }
}

pub(crate) const fn jws_verify(error: &JwsVerifyError) -> JoseWireError {
    match error.reason() {
        JwsVerifyErrorReason::BadPayloadBase64 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_PAYLOAD_BASE64,
        ),
        JwsVerifyErrorReason::BadHeaderBase64 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_BASE64,
        ),
        JwsVerifyErrorReason::BadHeaderUtf8 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_UTF8,
        ),
        JwsVerifyErrorReason::HeaderMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_HEADER_MISMATCH,
        ),
        JwsVerifyErrorReason::BadSignatureBase64 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_SIGNATURE_BASE64,
        ),
        JwsVerifyErrorReason::BadRawSignature => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_RAW_SIGNATURE,
        ),
        JwsVerifyErrorReason::InvalidSignature => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE,
        ),
        JwsVerifyErrorReason::LengthOverflow => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_LENGTH_OVERFLOW,
        ),
        JwsVerifyErrorReason::InvalidCompact => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_INVALID_COMPACT,
        ),
    }
}

pub(crate) const fn eddsa(error: &JwsEddsaError) -> JoseWireError {
    match error {
        JwsEddsaError::BadPayloadBase64 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_PAYLOAD_BASE64,
        ),
        JwsEddsaError::BadHeaderBase64 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_BASE64,
        ),
        JwsEddsaError::BadHeaderUtf8 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_UTF8,
        ),
        JwsEddsaError::HeaderMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_HEADER_MISMATCH,
        ),
        JwsEddsaError::BadSignatureBase64 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_SIGNATURE_BASE64,
        ),
        JwsEddsaError::InvalidSignature => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE,
        ),
        JwsEddsaError::SignFailed => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWS_SIGN_FAILED)
        }
        JwsEddsaError::InputTooLarge => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED,
        ),
        JwsEddsaError::LengthOverflow => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_LENGTH_OVERFLOW,
        ),
        JwsEddsaError::InvalidCompactEncoding => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_INVALID_COMPACT,
        ),
    }
}

pub(crate) const fn es256(error: &JwsEs256Error) -> JoseWireError {
    match error {
        JwsEs256Error::BadPayloadBase64 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_PAYLOAD_BASE64,
        ),
        JwsEs256Error::BadHeaderBase64 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_BASE64,
        ),
        JwsEs256Error::BadHeaderUtf8 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_UTF8,
        ),
        JwsEs256Error::HeaderMismatch => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_HEADER_MISMATCH,
        ),
        JwsEs256Error::BadSignatureBase64 => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_SIGNATURE_BASE64,
        ),
        JwsEs256Error::BadRawSignature => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_RAW_SIGNATURE,
        ),
        JwsEs256Error::InvalidSignature => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE,
        ),
        JwsEs256Error::VerifyFailed => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE,
        ),
        JwsEs256Error::SignFailed => {
            JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWS_SIGN_FAILED)
        }
        JwsEs256Error::BadDerSignature => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_DER_SIGNATURE,
        ),
        JwsEs256Error::InputTooLarge => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED,
        ),
        JwsEs256Error::LengthOverflow => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_LENGTH_OVERFLOW,
        ),
        JwsEs256Error::InvalidCompactEncoding => JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_INVALID_COMPACT,
        ),
    }
}
