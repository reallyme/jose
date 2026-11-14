// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{JweContentEncryptionAlgorithm, JweError, JweKeyManagementAlgorithm};

pub(super) const fn validate_encrypted_key_segment(
    algorithm: JweKeyManagementAlgorithm,
    encrypted_key_len: usize,
) -> Result<(), JweError> {
    // Both profiles establish the CEK directly, so neither serializes a
    // wrapped key. Keep the match exhaustive for any future wrapping mode.
    match algorithm {
        JweKeyManagementAlgorithm::Direct | JweKeyManagementAlgorithm::EcdhEs => {
            if encrypted_key_len == 0 {
                Ok(())
            } else {
                Err(JweError::InvalidEncryptedKey)
            }
        }
    }
}

pub(super) fn validate_resolver_key_management(
    resolver_algorithm: JweKeyManagementAlgorithm,
    header_algorithm: JweKeyManagementAlgorithm,
    encrypted_key_len: usize,
) -> Result<(), JweError> {
    // The caller selects the built-in resolver. A permitted header algorithm
    // still has to agree with that resolver before it can use key material.
    if header_algorithm != resolver_algorithm {
        return Err(JweError::InvalidEncryptedKey);
    }
    validate_encrypted_key_segment(header_algorithm, encrypted_key_len)
}

pub(super) const fn validate_content_encryption_key_length(
    suite: JweContentEncryptionAlgorithm,
    key_len: usize,
) -> Result<(), JweError> {
    if key_len == suite.key_len() {
        Ok(())
    } else {
        Err(JweError::InvalidContentEncryptionKey)
    }
}

#[cfg(kani)]
#[path = "validate_key_management_proofs.rs"]
mod proofs;
