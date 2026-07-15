// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_codec::base64url::base64url_to_bytes;
use serde::de::DeserializeOwned;

use crate::Zeroizing;

use super::{
    parse_compact::parse_compact_jwe, CompactJwePolicy, CompactJweProtectedHeader,
    JweContentEncryptionAlgorithm, JweError, JweKeyManagementAlgorithm,
};

/// Resolves a content-encryption key for a parsed and policy-validated JWE.
pub trait JweContentEncryptionKeyResolver {
    /// Returns the CEK for the protected header and encrypted-key segment.
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError>;
}

/// Direct CEK resolver for `alg = "dir"` compact JWEs.
pub struct DirectJweKeyResolver<'a> {
    key: &'a [u8],
}

impl<'a> DirectJweKeyResolver<'a> {
    /// Builds a direct-key resolver over caller-owned CEK bytes.
    #[must_use]
    pub const fn new(key: &'a [u8]) -> Self {
        Self { key }
    }
}

impl JweContentEncryptionKeyResolver for DirectJweKeyResolver<'_> {
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        if header.alg != JweKeyManagementAlgorithm::Direct || !encrypted_key.is_empty() {
            return Err(JweError::InvalidEncryptedKey);
        }
        if self.key.len() != header.enc.key_len() {
            return Err(JweError::InvalidContentEncryptionKey);
        }
        Ok(Zeroizing::new(self.key.to_vec()))
    }
}

/// Decrypts a compact JWE into plaintext bytes.
///
/// # Errors
///
/// Returns [`JweError`] for malformed compact input, invalid Base64URL or
/// protected-header JSON, header policy failures, invalid key-management
/// output, invalid IV/tag lengths, CEK resolution failures, or content
/// authentication/decryption failure.
pub fn decrypt_compact_jwe_bytes(
    compact_jwe: &str,
    policy: &CompactJwePolicy<'_>,
    key_resolver: &dyn JweContentEncryptionKeyResolver,
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    let parts = parse_compact_jwe(compact_jwe)?;
    let protected_bytes =
        base64url_to_bytes(parts.protected_header).map_err(|_| JweError::InvalidEncoding)?;
    let raw_header: super::validate_header::RawCompactJweProtectedHeader =
        serde_json::from_slice(&protected_bytes).map_err(|_| JweError::InvalidHeader)?;
    let header = CompactJweProtectedHeader::try_from(raw_header)?;
    policy.validate(&header)?;

    let encrypted_key =
        base64url_to_bytes(parts.encrypted_key).map_err(|_| JweError::InvalidEncoding)?;
    require_empty_encrypted_key_for_direct_cek_alg(header.alg, &encrypted_key)?;

    let iv = base64url_to_bytes(parts.iv).map_err(|_| JweError::InvalidEncoding)?;
    let ciphertext = base64url_to_bytes(parts.ciphertext).map_err(|_| JweError::InvalidEncoding)?;
    let tag = base64url_to_bytes(parts.tag).map_err(|_| JweError::InvalidEncoding)?;

    if iv.len() != header.enc.nonce_len() || tag.len() != header.enc.tag_len() {
        return Err(JweError::InvalidContentCipherInput);
    }

    let cek = key_resolver.resolve_content_encryption_key(&header, &encrypted_key)?;
    if cek.len() != header.enc.key_len() {
        return Err(JweError::InvalidContentEncryptionKey);
    }

    let ciphertext_with_tag = join_ciphertext_and_tag(ciphertext, tag)?;
    decrypt_content(
        header.enc,
        &cek,
        &iv,
        parts.protected_header.as_bytes(),
        ciphertext_with_tag,
    )
}

/// Decrypts a compact JWE and decodes the plaintext as JSON.
///
/// # Errors
///
/// Returns [`JweError`] when compact decryption fails or the decrypted
/// plaintext is not valid JSON for the requested type.
pub fn decrypt_compact_jwe_json<T: DeserializeOwned>(
    compact_jwe: &str,
    policy: &CompactJwePolicy<'_>,
    key_resolver: &dyn JweContentEncryptionKeyResolver,
) -> Result<T, JweError> {
    let plaintext = decrypt_compact_jwe_bytes(compact_jwe, policy, key_resolver)?;
    serde_json::from_slice(&plaintext).map_err(|_| JweError::InvalidPayloadJson)
}

const fn require_empty_encrypted_key_for_direct_cek_alg(
    alg: JweKeyManagementAlgorithm,
    encrypted_key: &[u8],
) -> Result<(), JweError> {
    match alg {
        JweKeyManagementAlgorithm::Direct | JweKeyManagementAlgorithm::EcdhEs => {
            if encrypted_key.is_empty() {
                Ok(())
            } else {
                Err(JweError::InvalidEncryptedKey)
            }
        }
    }
}

fn join_ciphertext_and_tag(
    mut ciphertext: Vec<u8>,
    mut tag: Vec<u8>,
) -> Result<reallyme_crypto::aes::CiphertextWithTag, JweError> {
    let new_len = ciphertext
        .len()
        .checked_add(tag.len())
        .ok_or(JweError::LengthOverflow)?;
    ciphertext.reserve_exact(tag.len());
    ciphertext.append(&mut tag);
    if ciphertext.len() != new_len {
        return Err(JweError::LengthOverflow);
    }
    reallyme_crypto::aes::CiphertextWithTag::from_vec(ciphertext)
        .map_err(|_| JweError::InvalidContentCipherInput)
}

fn decrypt_content(
    enc: JweContentEncryptionAlgorithm,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: reallyme_crypto::aes::CiphertextWithTag,
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    match enc {
        JweContentEncryptionAlgorithm::A128Gcm => {
            let key = reallyme_crypto::aes::Aes128GcmKey::from_slice(cek)
                .map_err(|_| JweError::InvalidContentEncryptionKey)?;
            let nonce = reallyme_crypto::aes::Aes128GcmNonce::from_slice(iv)
                .map_err(|_| JweError::InvalidContentCipherInput)?;
            let mut plaintext = reallyme_crypto::aes::decrypt_aes128_gcm(
                &reallyme_crypto::aes::Aes128GcmDecryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    ciphertext: &ciphertext,
                },
            )
            .map_err(|_| JweError::Decrypt)?;
            Ok(Zeroizing::new(core::mem::take(&mut plaintext)))
        }
        JweContentEncryptionAlgorithm::A192Gcm => {
            let key = reallyme_crypto::aes::Aes192GcmKey::from_slice(cek)
                .map_err(|_| JweError::InvalidContentEncryptionKey)?;
            let nonce = reallyme_crypto::aes::Aes192GcmNonce::from_slice(iv)
                .map_err(|_| JweError::InvalidContentCipherInput)?;
            let mut plaintext = reallyme_crypto::aes::decrypt_aes192_gcm(
                &reallyme_crypto::aes::Aes192GcmDecryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    ciphertext: &ciphertext,
                },
            )
            .map_err(|_| JweError::Decrypt)?;
            Ok(Zeroizing::new(core::mem::take(&mut plaintext)))
        }
        JweContentEncryptionAlgorithm::A256Gcm => {
            let key = reallyme_crypto::aes::Aes256GcmKey::from_slice(cek)
                .map_err(|_| JweError::InvalidContentEncryptionKey)?;
            let nonce = reallyme_crypto::aes::Aes256GcmNonce::from_slice(iv)
                .map_err(|_| JweError::InvalidContentCipherInput)?;
            let mut plaintext =
                reallyme_crypto::aes::decrypt(&reallyme_crypto::aes::DecryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    ciphertext: &ciphertext,
                })
                .map_err(|_| JweError::Decrypt)?;
            Ok(Zeroizing::new(core::mem::take(&mut plaintext)))
        }
    }
}
