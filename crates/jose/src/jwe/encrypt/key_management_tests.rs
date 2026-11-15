// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{map_keypair_generation_error, CryptoError, JweError};

#[test]
fn preserves_entropy_failure_without_mislabeling_invalid_key_material() {
    assert!(matches!(
        map_keypair_generation_error(CryptoError::PROVIDER_RANDOMNESS_UNAVAILABLE),
        JweError::Randomness
    ));
    assert!(matches!(
        map_keypair_generation_error(CryptoError::PRIMITIVE_INVALID_KEY),
        JweError::InvalidKeyAgreementKey
    ));
}
