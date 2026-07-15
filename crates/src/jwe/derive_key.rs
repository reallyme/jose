// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_codec::base64url::base64url_to_bytes;
use zeroize::Zeroize;

use crate::Zeroizing;

use super::{CompactJweProtectedHeader, JweContentEncryptionAlgorithm, JweError};

/// Derives an ECDH-ES content-encryption key from a caller-computed shared
/// secret and the JOSE protected-header party-info parameters.
///
/// The ECDH operation itself is intentionally outside this helper: callers own
/// private-key lookup, `epk` validation, and curve-specific agreement. JOSE owns
/// the JWA Concat KDF profile and header parameter handling.
///
/// # Errors
///
/// Returns [`JweError`] when the shared secret or party-info values are invalid,
/// the content-encryption algorithm is unsupported by this profile, or the
/// Concat KDF backend fails.
pub fn derive_ecdh_es_content_encryption_key(
    shared_secret: &[u8],
    header: &CompactJweProtectedHeader,
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    match header.enc {
        JweContentEncryptionAlgorithm::A128Gcm => {
            derive_ecdh_es_content_encryption_key_for_len::<16>(shared_secret, header)
        }
        JweContentEncryptionAlgorithm::A192Gcm => {
            derive_ecdh_es_content_encryption_key_for_len::<24>(shared_secret, header)
        }
        JweContentEncryptionAlgorithm::A256Gcm => {
            derive_ecdh_es_content_encryption_key_for_len::<32>(shared_secret, header)
        }
    }
}

fn derive_ecdh_es_content_encryption_key_for_len<const N: usize>(
    shared_secret: &[u8],
    header: &CompactJweProtectedHeader,
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    let shared_secret = reallyme_crypto::concat_kdf::JwaSharedSecret::from_slice(shared_secret)
        .map_err(|_| JweError::InvalidSharedSecret)?;
    let algorithm_id =
        reallyme_crypto::concat_kdf::JwaAlgorithmId::from_slice(header.enc.as_str().as_bytes())
            .map_err(|_| JweError::InvalidHeader)?;
    let party_u_info = decode_party_info(header.apu.as_deref())?;
    let party_v_info = decode_party_info(header.apv.as_deref())?;

    let derived = reallyme_crypto::concat_kdf::derive_jwa_concat_kdf_sha256::<N>(
        &reallyme_crypto::concat_kdf::JwaConcatKdfRequest {
            shared_secret: &shared_secret,
            algorithm_id: &algorithm_id,
            party_u_info: &party_u_info,
            party_v_info: &party_v_info,
        },
    )
    .map_err(|_| JweError::KeyDerivation)?;

    let mut derived_bytes = derived.into_bytes();
    let cek = Zeroizing::new(derived_bytes.to_vec());
    derived_bytes.zeroize();
    Ok(cek)
}

fn decode_party_info(
    value: Option<&str>,
) -> Result<reallyme_crypto::concat_kdf::JwaPartyInfo, JweError> {
    let bytes = match value {
        Some(encoded) => base64url_to_bytes(encoded).map_err(|_| JweError::InvalidHeader)?,
        None => Vec::new(),
    };
    reallyme_crypto::concat_kdf::JwaPartyInfo::from_slice(&bytes)
        .map_err(|_| JweError::InvalidHeader)
}
