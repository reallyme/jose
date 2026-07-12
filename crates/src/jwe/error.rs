// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Compact JWE parse, policy, and decrypt failures.
#[derive(Debug, Error)]
pub enum JweError {
    /// The compact serialization did not contain five well-formed segments.
    #[error("invalid compact JWE")]
    InvalidCompact,

    /// A Base64URL segment was malformed.
    #[error("invalid compact JWE segment encoding")]
    InvalidEncoding,

    /// The protected header was not valid JSON or did not match the supported shape.
    #[error("invalid JWE protected header")]
    InvalidHeader,

    /// The key-management algorithm is not supported by the configured policy.
    #[error("unsupported JWE key-management algorithm")]
    UnsupportedKeyManagementAlgorithm,

    /// The content-encryption algorithm is not supported by the configured policy.
    #[error("unsupported JWE content-encryption algorithm")]
    UnsupportedContentEncryptionAlgorithm,

    /// A required protected-header parameter was missing.
    #[error("missing required JWE protected-header parameter")]
    MissingRequiredHeaderParameter,

    /// A protected-header parameter was present but did not match policy.
    #[error("JWE protected-header policy mismatch")]
    HeaderPolicyMismatch,

    /// The encrypted-key segment is invalid for the selected key-management algorithm.
    #[error("invalid JWE encrypted-key segment")]
    InvalidEncryptedKey,

    /// The resolved content-encryption key has the wrong length.
    #[error("invalid JWE content-encryption key")]
    InvalidContentEncryptionKey,

    /// The IV or authentication tag has the wrong length for the content cipher.
    #[error("invalid JWE content-cipher input")]
    InvalidContentCipherInput,

    /// Content decryption or authentication failed.
    #[error("JWE content decryption failed")]
    Decrypt,

    /// Content encryption failed.
    #[error("JWE content encryption failed")]
    Encrypt,

    /// JWE key-agreement material was invalid.
    #[error("invalid JWE key-agreement key")]
    InvalidKeyAgreementKey,

    /// Secure random generation failed.
    #[error("JWE random generation failed")]
    Randomness,

    /// Decrypted payload was not valid JSON for the requested type.
    #[error("invalid JWE payload JSON")]
    InvalidPayloadJson,

    /// A checked length calculation overflowed.
    #[error("JWE input length overflow")]
    LengthOverflow,

    /// The compact JWE exceeded the configured parser input limit.
    #[error("JWE input too large")]
    InputTooLarge,
}
