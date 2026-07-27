// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;
use zeroize::Zeroize;

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::RngOutputKind;

use crate::{JsonValue, SecureRandom, Zeroizing};

use super::{
    parse_compact::format_compact_jwe, JweContentEncryptionAlgorithm, JweError,
    JweKeyManagementAlgorithm,
};

const _: () = {
    assert!(
        reallyme_crypto::aes::AES_128_GCM_NONCE_LENGTH
            == reallyme_crypto::aes::AES_192_GCM_NONCE_LENGTH
    );
    assert!(
        reallyme_crypto::aes::AES_128_GCM_NONCE_LENGTH
            == reallyme_crypto::aes::AES_256_GCM_NONCE_LENGTH
    );
};

/// Compact JWE encryption request.
pub struct CompactJweEncryptRequest<'a> {
    /// Plaintext bytes to encrypt.
    plaintext: &'a [u8],
    /// Content-encryption algorithm.
    enc: JweContentEncryptionAlgorithm,
    /// Optional key identifier copied into the protected header.
    kid: Option<&'a str>,
    /// Agreement PartyUInfo as raw bytes; JOSE encodes this as Base64URL.
    apu: Option<&'a [u8]>,
    /// Agreement PartyVInfo as raw bytes; JOSE encodes this as Base64URL.
    apv: Option<&'a [u8]>,
    /// Optional JOSE type.
    typ: Option<&'a str>,
    /// Optional JOSE content type.
    cty: Option<&'a str>,
}

impl<'a> CompactJweEncryptRequest<'a> {
    /// Builds a compact-JWE encryption request over caller-owned plaintext bytes.
    #[must_use]
    pub const fn new(plaintext: &'a [u8], enc: JweContentEncryptionAlgorithm) -> Self {
        Self {
            plaintext,
            enc,
            kid: None,
            apu: None,
            apv: None,
            typ: None,
            cty: None,
        }
    }

    /// Sets the protected-header `kid` value.
    #[must_use]
    pub const fn with_kid(mut self, kid: &'a str) -> Self {
        self.kid = Some(kid);
        self
    }

    /// Sets raw Agreement PartyUInfo bytes.
    #[must_use]
    pub const fn with_apu(mut self, apu: &'a [u8]) -> Self {
        self.apu = Some(apu);
        self
    }

    /// Sets raw Agreement PartyVInfo bytes.
    #[must_use]
    pub const fn with_apv(mut self, apv: &'a [u8]) -> Self {
        self.apv = Some(apv);
        self
    }

    /// Sets the protected-header `typ` value.
    #[must_use]
    pub const fn with_typ(mut self, typ: &'a str) -> Self {
        self.typ = Some(typ);
        self
    }

    /// Sets the protected-header `cty` value.
    #[must_use]
    pub const fn with_cty(mut self, cty: &'a str) -> Self {
        self.cty = Some(cty);
        self
    }

    /// Returns plaintext bytes to encrypt.
    #[must_use]
    pub const fn plaintext(&self) -> &'a [u8] {
        self.plaintext
    }

    /// Returns the content-encryption algorithm.
    #[must_use]
    pub const fn enc(&self) -> JweContentEncryptionAlgorithm {
        self.enc
    }

    pub(crate) const fn kid(&self) -> Option<&'a str> {
        self.kid
    }

    pub(crate) const fn apu(&self) -> Option<&'a [u8]> {
        self.apu
    }

    pub(crate) const fn apv(&self) -> Option<&'a [u8]> {
        self.apv
    }

    pub(crate) const fn typ(&self) -> Option<&'a str> {
        self.typ
    }

    pub(crate) const fn cty(&self) -> Option<&'a str> {
        self.cty
    }
}

mod ec_keys;
mod key_management;

pub use key_management::{
    DirectJweKeyEncryptor, JweContentEncryptionKeyEncryptor, P256EcdhEsJweKeyEncryptor,
    P256EcdhEsJweKeyResolver, PreparedJweEncryptionKey,
};
#[cfg(feature = "native")]
pub use key_management::{
    P384EcdhEsJweKeyEncryptor, P384EcdhEsJweKeyResolver, P521EcdhEsJweKeyEncryptor,
    P521EcdhEsJweKeyResolver,
};

/// Encrypts plaintext bytes as a compact JWE.
///
/// The protected header is authenticated as JWE AAD. For `ECDH-ES`, this
/// function relies on the supplied encryptor to produce fresh key agreement
/// material.
///
/// `rng` supplies the fresh AES-GCM IV. ECDH-ES encryptors generate their
/// ephemeral keypairs independently through the cryptographic backend's
/// CSPRNG, so injecting a deterministic IV source does not make ECDH key
/// generation deterministic.
///
/// # Errors
///
/// Returns [`JweError`] when key-management output is invalid, randomness is
/// unavailable, header serialization fails, content-encryption input lengths
/// are invalid, encryption fails, or compact serialization length arithmetic
/// overflows.
pub fn encrypt_compact_jwe_bytes<R: SecureRandom + ?Sized>(
    request: &CompactJweEncryptRequest<'_>,
    key_encryptor: &mut dyn JweContentEncryptionKeyEncryptor,
    rng: &mut R,
) -> Result<String, JweError> {
    crate::operation_contract::jwe::encrypt_jwe(request, key_encryptor, rng)
}

pub(crate) fn encrypt_compact_jwe_bytes_core<R: SecureRandom + ?Sized>(
    request: &CompactJweEncryptRequest<'_>,
    key_encryptor: &mut dyn JweContentEncryptionKeyEncryptor,
    rng: &mut R,
) -> Result<String, JweError> {
    let prepared = key_encryptor.prepare_content_encryption_key(request)?;
    let mut header = SerializableCompactJweProtectedHeader {
        alg: prepared.alg,
        enc: request.enc(),
        kid: request.kid(),
        apu: encode_optional_base64url(request.apu()),
        apv: encode_optional_base64url(request.apv()),
        epk: prepared.epk.as_ref(),
        typ: request.typ(),
        cty: request.cty(),
    };
    super::validate_header::validate_jwe_header_structure(
        prepared.alg,
        prepared.epk.is_some(),
        request.apu().is_some(),
        request.apv().is_some(),
    )?;
    let protected_header_result = serde_json::to_vec(&header);
    header.apu.zeroize();
    header.apv.zeroize();
    let protected_header_json = protected_header_result.map_err(|_| JweError::InvalidHeader)?;
    let protected_header = encode_jwe_base64url(&protected_header_json);

    let mut nonce = [0u8; reallyme_crypto::aes::AES_128_GCM_NONCE_LENGTH];
    rng.fill_secure(&mut nonce, RngOutputKind::AeadNonce12)
        .map_err(|_| JweError::Randomness)?;
    let ciphertext_with_tag = encrypt_content(
        request.enc(),
        &prepared.cek,
        &nonce,
        protected_header.as_bytes(),
        request.plaintext(),
    )?;
    let ciphertext_and_tag = ciphertext_with_tag.as_bytes();
    let tag_len = request.enc().tag_len();
    let split_at = ciphertext_and_tag
        .len()
        .checked_sub(tag_len)
        .ok_or(JweError::LengthOverflow)?;
    let encrypted_key = encode_jwe_base64url(&prepared.encrypted_key);
    let iv = encode_jwe_base64url(&nonce);
    let ciphertext_bytes = ciphertext_and_tag
        .get(..split_at)
        .ok_or(JweError::LengthOverflow)?;
    let tag_bytes = ciphertext_and_tag
        .get(split_at..)
        .ok_or(JweError::LengthOverflow)?;
    let ciphertext = encode_jwe_base64url(ciphertext_bytes);
    let tag = encode_jwe_base64url(tag_bytes);

    format_compact_jwe(&protected_header, &encrypted_key, &iv, &ciphertext, &tag)
}

/// Encrypts a JSON-serializable payload as a compact JWE.
///
/// # Errors
///
/// Returns [`JweError`] when payload JSON serialization fails or when
/// [`encrypt_compact_jwe_bytes`] fails.
pub fn encrypt_compact_jwe_json<T: Serialize, R: SecureRandom + ?Sized>(
    payload: &T,
    enc: JweContentEncryptionAlgorithm,
    key_encryptor: &mut dyn JweContentEncryptionKeyEncryptor,
    rng: &mut R,
) -> Result<String, JweError> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(payload).map_err(|_| JweError::InvalidPayloadJson)?);
    crate::operation_contract::jwe::encrypt_jwe(
        &CompactJweEncryptRequest::new(&plaintext, enc),
        key_encryptor,
        rng,
    )
}

#[derive(Serialize)]
struct SerializableCompactJweProtectedHeader<'a> {
    alg: JweKeyManagementAlgorithm,
    enc: JweContentEncryptionAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epk: Option<&'a JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<&'a str>,
}

fn encrypt_content(
    enc: JweContentEncryptionAlgorithm,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<reallyme_crypto::aes::CiphertextWithTag, JweError> {
    match enc {
        JweContentEncryptionAlgorithm::A128Gcm => {
            let key = reallyme_crypto::aes::Aes128GcmKey::from_slice(cek)
                .map_err(|_| JweError::InvalidContentEncryptionKey)?;
            let nonce = reallyme_crypto::aes::Aes128GcmNonce::from_slice(iv)
                .map_err(|_| JweError::InvalidContentCipherInput)?;
            reallyme_crypto::aes::encrypt_aes128_gcm(
                &reallyme_crypto::aes::Aes128GcmEncryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    plaintext,
                },
            )
            .map_err(|_| JweError::Encrypt)
        }
        JweContentEncryptionAlgorithm::A192Gcm => {
            let key = reallyme_crypto::aes::Aes192GcmKey::from_slice(cek)
                .map_err(|_| JweError::InvalidContentEncryptionKey)?;
            let nonce = reallyme_crypto::aes::Aes192GcmNonce::from_slice(iv)
                .map_err(|_| JweError::InvalidContentCipherInput)?;
            reallyme_crypto::aes::encrypt_aes192_gcm(
                &reallyme_crypto::aes::Aes192GcmEncryptRequest {
                    key: &key,
                    nonce,
                    aad,
                    plaintext,
                },
            )
            .map_err(|_| JweError::Encrypt)
        }
        JweContentEncryptionAlgorithm::A256Gcm => {
            let key = reallyme_crypto::aes::Aes256GcmKey::from_slice(cek)
                .map_err(|_| JweError::InvalidContentEncryptionKey)?;
            let nonce = reallyme_crypto::aes::Aes256GcmNonce::from_slice(iv)
                .map_err(|_| JweError::InvalidContentCipherInput)?;
            reallyme_crypto::aes::encrypt(&reallyme_crypto::aes::EncryptRequest {
                key: &key,
                nonce,
                aad,
                plaintext,
            })
            .map_err(|_| JweError::Encrypt)
        }
    }
}

fn encode_optional_base64url(value: Option<&[u8]>) -> Option<String> {
    value.map(encode_jwe_base64url)
}

fn encode_jwe_base64url(bytes: &[u8]) -> String {
    bytes_to_base64url(bytes)
}
