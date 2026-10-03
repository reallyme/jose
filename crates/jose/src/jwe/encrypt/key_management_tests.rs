// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::{RngFailureKind, RngOutputKind};

use super::{map_keypair_generation_error, CryptoError, JweError};

#[test]
fn preserves_entropy_failure_without_mislabeling_invalid_key_material() {
    let entropy = CryptoError::Rng {
        output: RngOutputKind::AeadNonce12,
        kind: RngFailureKind::EntropyUnavailable,
    };
    assert!(matches!(
        map_keypair_generation_error(entropy),
        JweError::Randomness
    ));
    assert!(matches!(
        map_keypair_generation_error(CryptoError::InvalidKey),
        JweError::InvalidKeyAgreementKey
    ));
}
