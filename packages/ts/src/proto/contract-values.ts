// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

import { JoseErrorReason, JoseSdkErrorCode } from "./generated/reallyme/jose/v1/jose_pb.js";

/** Stable TypeScript error labels declared by the SDK contract. */
export const ReallyMeJoseSdkErrorCode = Object.freeze({
  INVALID_INPUT: "invalid-input",
  PROVIDER_NOT_INSTALLED: "provider-not-installed",
  PROVIDER_FAILURE: "provider-failure",
  MALFORMED_PROVIDER_RESPONSE: "malformed-provider-response",
  JOSE_FAILURE: "jose-failure",
});

export type ReallyMeJoseSdkErrorCode =
  typeof ReallyMeJoseSdkErrorCode[keyof typeof ReallyMeJoseSdkErrorCode];

export const sdkErrorSchemaCodes: Readonly<Record<ReallyMeJoseSdkErrorCode, JoseSdkErrorCode>> = Object.freeze({
  [ReallyMeJoseSdkErrorCode.INVALID_INPUT]: JoseSdkErrorCode.INVALID_INPUT,
  [ReallyMeJoseSdkErrorCode.PROVIDER_NOT_INSTALLED]: JoseSdkErrorCode.PROVIDER_NOT_INSTALLED,
  [ReallyMeJoseSdkErrorCode.PROVIDER_FAILURE]: JoseSdkErrorCode.PROVIDER_FAILURE,
  [ReallyMeJoseSdkErrorCode.MALFORMED_PROVIDER_RESPONSE]: JoseSdkErrorCode.MALFORMED_PROVIDER_RESPONSE,
  [ReallyMeJoseSdkErrorCode.JOSE_FAILURE]: JoseSdkErrorCode.JOSE_FAILURE,
});

export type ReallyMeJoseErrorBranch = "primitive" | "provider" | "backend";

export const STRICT_TEMPORAL_DEFAULTS = Object.freeze({ requireExp: true, requireNbf: false, requireIat: false, clockSkewSeconds: 60n, maxFutureIatSkewSeconds: 60n });

export const COMPACT_BYTES = 1048576;
export const PROTO_JSON_BYTES = 1572864;
export const RESPONSE_OVERHEAD_BYTES = 32;
export const JWK_THUMBPRINT_MEMBER_BYTES = 8192;
export const PROTO_RECURSION_DEPTH = 64;
export const TEMPORAL_SKEW_SECONDS = 300n;
export const DEFAULT_TEMPORAL_SKEW_SECONDS = 60n;
export const ACCEPTED_TYPE_VALUES = 32;

export const errorBranch = (reason: JoseErrorReason): ReallyMeJoseErrorBranch | undefined => {
  switch (reason) {
    case JoseErrorReason.JWS_INVALID_PAYLOAD_UTF8: return "primitive";
    case JoseErrorReason.JWS_BAD_PAYLOAD_BASE64: return "primitive";
    case JoseErrorReason.JWS_BAD_HEADER_BASE64: return "primitive";
    case JoseErrorReason.JWS_BAD_HEADER_UTF8: return "primitive";
    case JoseErrorReason.JWS_HEADER_MISMATCH: return "primitive";
    case JoseErrorReason.JWS_BAD_SIGNATURE_BASE64: return "primitive";
    case JoseErrorReason.JWS_BAD_RAW_SIGNATURE: return "primitive";
    case JoseErrorReason.JWS_INVALID_SIGNATURE: return "primitive";
    case JoseErrorReason.JWS_SIGN_FAILED: return "primitive";
    case JoseErrorReason.JWS_BAD_DER_SIGNATURE: return "primitive";
    case JoseErrorReason.JWE_INVALID_HEADER: return "primitive";
    case JoseErrorReason.JWE_UNSUPPORTED_KEY_MANAGEMENT_ALGORITHM: return "primitive";
    case JoseErrorReason.JWE_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM: return "primitive";
    case JoseErrorReason.JWE_MISSING_REQUIRED_HEADER_PARAMETER: return "primitive";
    case JoseErrorReason.JWE_HEADER_POLICY_MISMATCH: return "primitive";
    case JoseErrorReason.JWE_KID_POLICY_MISMATCH: return "primitive";
    case JoseErrorReason.JWE_APU_POLICY_MISMATCH: return "primitive";
    case JoseErrorReason.JWE_APV_POLICY_MISMATCH: return "primitive";
    case JoseErrorReason.JWE_UNSUPPORTED_COMPRESSION_ALGORITHM: return "primitive";
    case JoseErrorReason.JWE_INVALID_ENCRYPTED_KEY: return "primitive";
    case JoseErrorReason.JWE_INVALID_CONTENT_ENCRYPTION_KEY: return "primitive";
    case JoseErrorReason.JWE_INVALID_CONTENT_CIPHER_INPUT: return "primitive";
    case JoseErrorReason.JWE_DECRYPT_FAILED: return "primitive";
    case JoseErrorReason.JWE_ENCRYPT_FAILED: return "primitive";
    case JoseErrorReason.JWE_INVALID_KEY_AGREEMENT_KEY: return "primitive";
    case JoseErrorReason.JWE_INVALID_SHARED_SECRET: return "primitive";
    case JoseErrorReason.JWE_INVALID_PAYLOAD_JSON: return "primitive";
    case JoseErrorReason.JWE_COMPRESSION_FAILED: return "primitive";
    case JoseErrorReason.JWE_DECOMPRESSION_FAILED: return "primitive";
    case JoseErrorReason.JWE_DECOMPRESSED_PLAINTEXT_TOO_LARGE: return "primitive";
    case JoseErrorReason.JWT_INVALID_HEADER: return "primitive";
    case JoseErrorReason.JWT_UNSUPPORTED_ALGORITHM: return "primitive";
    case JoseErrorReason.JWT_ALGORITHM_MISMATCH: return "primitive";
    case JoseErrorReason.JWT_MISSING_ALGORITHM: return "primitive";
    case JoseErrorReason.JWT_MISSING_PRIVATE_KEY: return "primitive";
    case JoseErrorReason.JWT_MISSING_PUBLIC_KEY: return "primitive";
    case JoseErrorReason.JWT_KID_POLICY_MISMATCH: return "primitive";
    case JoseErrorReason.JWT_PUBLIC_KEY_MISMATCH: return "primitive";
    case JoseErrorReason.JWT_INVALID_PUBLIC_KEY: return "primitive";
    case JoseErrorReason.JWT_INVALID_JWK: return "primitive";
    case JoseErrorReason.JWT_INVALID_SIGNATURE: return "primitive";
    case JoseErrorReason.JWT_CRYPTO_FAILED: return "primitive";
    case JoseErrorReason.JWT_INVALID_CLAIMS: return "primitive";
    case JoseErrorReason.JWT_SERIALIZATION_FAILED: return "primitive";
    case JoseErrorReason.JWT_MISSING_REQUIRED_TEMPORAL_CLAIM: return "primitive";
    case JoseErrorReason.JWT_INVALID_TEMPORAL_CLAIM_VALUE: return "primitive";
    case JoseErrorReason.JWT_EXPIRED: return "primitive";
    case JoseErrorReason.JWT_NOT_YET_VALID: return "primitive";
    case JoseErrorReason.JWT_ISSUED_AT_IN_FUTURE: return "primitive";
    case JoseErrorReason.JWT_INVALID_VERIFICATION_TIME: return "primitive";
    case JoseErrorReason.JWT_INVALID_VERIFICATION_POLICY: return "primitive";
    case JoseErrorReason.JWT_SIGNING_KEY_MISMATCH: return "primitive";
    case JoseErrorReason.JWT_MISSING_REQUIRED_REGISTERED_CLAIM: return "primitive";
    case JoseErrorReason.JWT_INVALID_REGISTERED_CLAIM_VALUE: return "primitive";
    case JoseErrorReason.JWT_AUDIENCE_MISMATCH: return "primitive";
    case JoseErrorReason.JWT_ISSUER_MISMATCH: return "primitive";
    case JoseErrorReason.JWT_SUBJECT_MISMATCH: return "primitive";
    case JoseErrorReason.JWK_THUMBPRINT_MISSING_MEMBER: return "primitive";
    case JoseErrorReason.JWK_THUMBPRINT_INVALID_MEMBER_TYPE: return "primitive";
    case JoseErrorReason.JWK_THUMBPRINT_UNSUPPORTED_KEY_TYPE: return "primitive";
    case JoseErrorReason.JWK_THUMBPRINT_INVALID_JSON_OBJECT: return "primitive";
    case JoseErrorReason.JWK_THUMBPRINT_MEMBER_TOO_LARGE: return "primitive";
    case JoseErrorReason.COMMON_MALFORMED_PROTOBUF: return "primitive";
    case JoseErrorReason.COMMON_MALFORMED_JSON: return "primitive";
    case JoseErrorReason.COMMON_MISSING_OPERATION: return "primitive";
    case JoseErrorReason.COMMON_RESOURCE_LIMIT_EXCEEDED: return "primitive";
    case JoseErrorReason.COMMON_LENGTH_OVERFLOW: return "primitive";
    case JoseErrorReason.COMMON_INVALID_COMPACT: return "primitive";
    case JoseErrorReason.COMMON_INVALID_ENCODING: return "primitive";
    case JoseErrorReason.PROVIDER_UNAVAILABLE: return "provider";
    case JoseErrorReason.PROVIDER_UNSUPPORTED: return "provider";
    case JoseErrorReason.PROVIDER_RANDOMNESS_UNAVAILABLE: return "provider";
    case JoseErrorReason.BACKEND_INTERNAL: return "backend";
    case JoseErrorReason.BACKEND_JSON_SERIALIZATION: return "backend";
    case JoseErrorReason.BACKEND_KEY_DERIVATION_FAILED: return "backend";
    case JoseErrorReason.BACKEND_JWK_THUMBPRINT_SERIALIZATION: return "backend";
    case JoseErrorReason.BACKEND_JWK_THUMBPRINT_ALLOCATION: return "backend";
    default: return undefined;
  }
};
