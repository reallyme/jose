// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use super::proto::reallyme::jose::v1::{JoseErrorBranch, JoseErrorReason};

/// Current native function ABI.
pub const NATIVE_ABI_VERSION: u32 = 1;

/// Schema-defined compact bytes.
pub const COMPACT_BYTES: usize = 1048576;
/// Schema-defined proto json bytes.
pub const PROTO_JSON_BYTES: usize = 1572864;
/// Schema-defined response overhead bytes.
pub const RESPONSE_OVERHEAD_BYTES: usize = 32;
/// Schema-defined jwk thumbprint member bytes.
pub const JWK_THUMBPRINT_MEMBER_BYTES: usize = 8192;
/// Schema-defined proto recursion depth.
pub const PROTO_RECURSION_DEPTH: u32 = 64;
/// Schema-defined temporal skew seconds.
pub const TEMPORAL_SKEW_SECONDS: u64 = 300;
/// Schema-defined default temporal skew seconds.
pub const DEFAULT_TEMPORAL_SKEW_SECONDS: u64 = 60;
/// Schema-defined accepted type values.
pub const ACCEPTED_TYPE_VALUES: usize = 32;

/// Returns the branch assigned by the schema's reason family.
#[must_use]
pub const fn error_branch(reason: JoseErrorReason) -> Option<JoseErrorBranch> {
    match reason {
        JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8 => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_PAYLOAD_BASE64 => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_BASE64 => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_UTF8 => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWS_HEADER_MISMATCH => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_SIGNATURE_BASE64 => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_RAW_SIGNATURE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_SIGN_FAILED => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_DER_SIGNATURE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_MISSING_POLICY => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_INVALID_CHARACTER_POLICY => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_MISSING_BUDGET => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_MISSING_MEMBER => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_INPUT_TOO_LARGE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_OUTPUT_TOO_LARGE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_EMPTY_MEMBER => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_INVALID_CHARACTERS => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_LENGTH_OVERFLOW => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWS_TRANSPORT_INVALID_FRAMING => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_HEADER => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_KEY_MANAGEMENT_ALGORITHM => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_MISSING_REQUIRED_HEADER_PARAMETER => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_KID_POLICY_MISMATCH => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_APU_POLICY_MISMATCH => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_APV_POLICY_MISMATCH => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_COMPRESSION_ALGORITHM => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_ENCRYPTED_KEY => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_ENCRYPTION_KEY => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_CIPHER_INPUT => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_DECRYPT_FAILED => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWE_ENCRYPT_FAILED => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_KEY_AGREEMENT_KEY => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_SHARED_SECRET => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_PAYLOAD_JSON => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_COMPRESSION_FAILED => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_DECOMPRESSION_FAILED => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWE_DECOMPRESSED_PLAINTEXT_TOO_LARGE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_HEADER => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWT_UNSUPPORTED_ALGORITHM => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_ALGORITHM_MISMATCH => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_ALGORITHM => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_PRIVATE_KEY => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_PUBLIC_KEY => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_KID_POLICY_MISMATCH => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_PUBLIC_KEY_MISMATCH => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_PUBLIC_KEY => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_SIGNATURE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_CRYPTO_FAILED => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_CLAIMS => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWT_SERIALIZATION_FAILED => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_REQUIRED_TEMPORAL_CLAIM => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_TEMPORAL_CLAIM_VALUE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_EXPIRED => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWT_NOT_YET_VALID => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWT_ISSUED_AT_IN_FUTURE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_SIGNING_KEY_MISMATCH => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_REQUIRED_REGISTERED_CLAIM => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_REGISTERED_CLAIM_VALUE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_AUDIENCE_MISMATCH => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWT_ISSUER_MISMATCH => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWT_SUBJECT_MISMATCH => Some(JoseErrorBranch::Primitive),
        JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_MISSING_MEMBER => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_INVALID_MEMBER_TYPE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_UNSUPPORTED_KEY_TYPE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_INVALID_JSON_OBJECT => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_JWK_THUMBPRINT_MEMBER_TOO_LARGE => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_JSON => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_MISSING_OPERATION => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_LENGTH_OVERFLOW => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_INVALID_COMPACT => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_COMMON_INVALID_ENCODING => {
            Some(JoseErrorBranch::Primitive)
        }
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNAVAILABLE => Some(JoseErrorBranch::Provider),
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED => Some(JoseErrorBranch::Provider),
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE => {
            Some(JoseErrorBranch::Provider)
        }
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL => Some(JoseErrorBranch::Backend),
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_JSON_SERIALIZATION => {
            Some(JoseErrorBranch::Backend)
        }
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_KEY_DERIVATION_FAILED => {
            Some(JoseErrorBranch::Backend)
        }
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_JWK_THUMBPRINT_SERIALIZATION => {
            Some(JoseErrorBranch::Backend)
        }
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_JWK_THUMBPRINT_ALLOCATION => {
            Some(JoseErrorBranch::Backend)
        }
        JoseErrorReason::JOSE_ERROR_REASON_BACKEND_JWS_TRANSPORT_ALLOCATION => {
            Some(JoseErrorBranch::Backend)
        }
        JoseErrorReason::Unspecified => None,
    }
}
