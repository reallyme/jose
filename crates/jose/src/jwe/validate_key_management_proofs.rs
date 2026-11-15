// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::jwe::validate_header::validate_jwe_header_structure;

use super::{
    validate_content_encryption_key_length, validate_encrypted_key_segment,
    validate_resolver_key_management, JweContentEncryptionAlgorithm, JweError,
    JweKeyManagementAlgorithm,
};

#[kani::proof]
fn key_management_requires_matching_mode_and_empty_encrypted_key() {
    use JweKeyManagementAlgorithm::{Direct, EcdhEs};

    let header_is_ecdh = kani::any::<bool>();
    let resolver_is_ecdh = kani::any::<bool>();
    let header = if header_is_ecdh { EcdhEs } else { Direct };
    let resolver = if resolver_is_ecdh { EcdhEs } else { Direct };
    let segment_len = kani::any::<usize>();
    let has_epk = kani::any::<bool>();
    let has_apu = kani::any::<bool>();
    let has_apv = kani::any::<bool>();

    let structure = validate_jwe_header_structure(header, has_epk, has_apu, has_apv);
    let segment = validate_encrypted_key_segment(header, segment_len);
    let binding = validate_resolver_key_management(resolver, header, segment_len);

    if header_is_ecdh && !has_epk {
        kani::assert(
            matches!(structure, Err(JweError::MissingRequiredHeaderParameter)),
            "ECDH-ES requires an ephemeral public key",
        );
    } else if !header_is_ecdh && (has_epk || has_apu || has_apv) {
        kani::assert(
            matches!(structure, Err(JweError::InvalidHeader)),
            "direct mode forbids ECDH-ES header parameters",
        );
    } else {
        kani::assert(
            structure.is_ok(),
            "valid mode-specific parameters are permitted",
        );
    }
    if segment_len == 0 {
        kani::assert(
            segment.is_ok(),
            "an empty segment is permitted for both modes",
        );
    } else {
        kani::assert(
            matches!(segment, Err(JweError::InvalidEncryptedKey)),
            "neither direct CEK mode permits a wrapped key",
        );
    }
    if header_is_ecdh == resolver_is_ecdh && segment_len == 0 {
        kani::assert(
            binding.is_ok(),
            "matching mode and empty segment permit resolution",
        );
    } else {
        kani::assert(
            matches!(binding, Err(JweError::InvalidEncryptedKey)),
            "a built-in resolver rejects a different mode or nonempty segment",
        );
    }

    let mode_is_usable = structure.is_ok() && segment.is_ok() && binding.is_ok();
    kani::cover!(mode_is_usable && !header_is_ecdh, "direct mode can proceed");
    kani::cover!(mode_is_usable && header_is_ecdh, "ECDH-ES mode can proceed");
    kani::cover!(
        structure.is_ok()
            && segment.is_ok()
            && header_is_ecdh
            && !resolver_is_ecdh
            && binding.is_err(),
        "direct resolver rejects a valid ECDH-ES header"
    );
    kani::cover!(
        structure.is_ok()
            && segment.is_ok()
            && !header_is_ecdh
            && resolver_is_ecdh
            && binding.is_err(),
        "ECDH-ES resolver rejects a valid direct header"
    );
    kani::cover!(
        structure.is_ok()
            && header_is_ecdh == resolver_is_ecdh
            && segment_len != 0
            && binding.is_err(),
        "matching algorithms cannot bypass the encrypted-key segment check"
    );
}

#[kani::proof]
fn aes_gcm_accepts_exactly_the_selected_suite_key_length() {
    use JweContentEncryptionAlgorithm::{A128Gcm, A192Gcm, A256Gcm};

    // The expected lengths come from the JWA suite definitions, independently
    // of the backend constants and ECDH-ES KDF instantiations.
    let (suite, expected_len) = match kani::any::<u8>() {
        0 => (A128Gcm, 16),
        1 => (A192Gcm, 24),
        _ => (A256Gcm, 32),
    };
    let actual_len = kani::any::<usize>();
    let result = validate_content_encryption_key_length(suite, actual_len);
    kani::assert(
        suite.key_len() == expected_len,
        "the suite advertises its JWA key length",
    );
    if actual_len == expected_len {
        kani::assert(result.is_ok(), "the exact key length is accepted");
    } else {
        kani::assert(
            matches!(result, Err(JweError::InvalidContentEncryptionKey)),
            "every other key length is rejected",
        );
    }

    kani::cover!(
        result.is_ok() && matches!(suite, A128Gcm),
        "AES-128-GCM accepts 16 bytes"
    );
    kani::cover!(
        result.is_ok() && matches!(suite, A192Gcm),
        "AES-192-GCM accepts 24 bytes"
    );
    kani::cover!(
        result.is_ok() && matches!(suite, A256Gcm),
        "AES-256-GCM accepts 32 bytes"
    );
    kani::cover!(
        result.is_err() && matches!(suite, A192Gcm) && actual_len == 32,
        "a valid AES-256-GCM key length cannot select another suite"
    );
}
