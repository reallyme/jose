// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;
use serde_json::Map;
use zeroize::Zeroize;

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_crypto::core::RngOutputKind;

use crate::{JsonValue, SecureRandom, Zeroizing};

use super::{
    derive_ecdh_es_content_encryption_key, parse_compact::format_compact_jwe,
    CompactJweProtectedHeader, JweContentEncryptionAlgorithm, JweError, JweKeyManagementAlgorithm,
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

/// Prepared CEK and protected-header additions from a JWE key-management step.
pub struct PreparedJweEncryptionKey {
    alg: JweKeyManagementAlgorithm,
    cek: Zeroizing<Vec<u8>>,
    encrypted_key: Vec<u8>,
    epk: Option<JsonValue>,
}

impl PreparedJweEncryptionKey {
    /// Builds prepared key-management output for a compact JWE encrypt call.
    ///
    /// Custom key-management implementations can use this constructor to return
    /// a CEK, an optional encrypted-key segment, and required protected-header
    /// additions without exposing mutable internals.
    pub fn new(
        alg: JweKeyManagementAlgorithm,
        cek: Zeroizing<Vec<u8>>,
        encrypted_key: Vec<u8>,
        epk: Option<JsonValue>,
    ) -> Result<Self, JweError> {
        match alg {
            JweKeyManagementAlgorithm::Direct | JweKeyManagementAlgorithm::EcdhEs => {
                if !encrypted_key.is_empty() {
                    return Err(JweError::InvalidEncryptedKey);
                }
            }
        }
        if alg == JweKeyManagementAlgorithm::EcdhEs && epk.is_none() {
            return Err(JweError::MissingRequiredHeaderParameter);
        }
        if alg == JweKeyManagementAlgorithm::Direct && epk.is_some() {
            return Err(JweError::InvalidHeader);
        }
        if let Some(epk) = epk.as_ref() {
            validate_public_epk_jwk(epk)?;
        }
        Ok(Self {
            alg,
            cek,
            encrypted_key,
            epk,
        })
    }
}

fn validate_public_epk_jwk(jwk: &JsonValue) -> Result<(), JweError> {
    let object = jwk.as_object().ok_or(JweError::InvalidKeyAgreementKey)?;
    if object.len() != 4
        || !["kty", "crv", "x", "y"]
            .iter()
            .all(|key| object.contains_key(*key))
    {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    for (key, value) in object {
        match key.as_str() {
            "kty" | "crv" | "x" | "y" if value.as_str().is_some() => {}
            "kty" | "crv" | "x" | "y" => return Err(JweError::InvalidKeyAgreementKey),
            _ => return Err(JweError::InvalidKeyAgreementKey),
        }
    }
    Ok(())
}

/// Encrypt-side JWE key-management boundary.
pub trait JweContentEncryptionKeyEncryptor {
    /// Produces a CEK and any key-management protected-header parameters.
    fn prepare_content_encryption_key(
        &mut self,
        request: &CompactJweEncryptRequest<'_>,
    ) -> Result<PreparedJweEncryptionKey, JweError>;
}

/// Direct CEK encryptor for `alg = "dir"` compact JWEs.
pub struct DirectJweKeyEncryptor<'a> {
    key: &'a [u8],
}

impl<'a> DirectJweKeyEncryptor<'a> {
    /// Builds a direct-key encryptor over caller-owned CEK bytes.
    #[must_use]
    pub const fn new(key: &'a [u8]) -> Self {
        Self { key }
    }
}

impl JweContentEncryptionKeyEncryptor for DirectJweKeyEncryptor<'_> {
    fn prepare_content_encryption_key(
        &mut self,
        request: &CompactJweEncryptRequest<'_>,
    ) -> Result<PreparedJweEncryptionKey, JweError> {
        if self.key.len() != request.enc().key_len() {
            return Err(JweError::InvalidContentEncryptionKey);
        }
        Ok(PreparedJweEncryptionKey {
            alg: JweKeyManagementAlgorithm::Direct,
            cek: Zeroizing::new(self.key.to_vec()),
            encrypted_key: Vec::new(),
            epk: None,
        })
    }
}

/// P-256 ECDH-ES encryptor for compact JWEs.
///
/// Production encryption uses fresh ephemeral key material generated by the
/// crypto backend for each message.
pub struct P256EcdhEsJweKeyEncryptor<'a> {
    recipient_public_key_sec1: &'a [u8],
}

impl<'a> P256EcdhEsJweKeyEncryptor<'a> {
    /// Builds an ECDH-ES encryptor for a recipient P-256 public key in SEC1 form.
    #[must_use]
    pub const fn new(recipient_public_key_sec1: &'a [u8]) -> Self {
        Self {
            recipient_public_key_sec1,
        }
    }
}

impl JweContentEncryptionKeyEncryptor for P256EcdhEsJweKeyEncryptor<'_> {
    fn prepare_content_encryption_key(
        &mut self,
        request: &CompactJweEncryptRequest<'_>,
    ) -> Result<PreparedJweEncryptionKey, JweError> {
        let (ephemeral_public, mut ephemeral_private) =
            reallyme_crypto::p256::generate_p256_keypair()
                .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        let mut shared_secret = reallyme_crypto::p256::derive_p256_shared_secret(
            &ephemeral_private,
            self.recipient_public_key_sec1,
        )
        .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        ephemeral_private.zeroize();

        let epk = p256_epk_from_sec1_public_key(&ephemeral_public)?;
        let header = CompactJweProtectedHeader {
            alg: JweKeyManagementAlgorithm::EcdhEs,
            enc: request.enc(),
            kid: request.kid().map(str::to_owned),
            apu: encode_optional_base64url(request.apu()),
            apv: encode_optional_base64url(request.apv()),
            epk: Some(epk.clone()),
            typ: request.typ().map(str::to_owned),
            cty: request.cty().map(str::to_owned),
        };
        let cek = derive_ecdh_es_content_encryption_key(&shared_secret, &header)?;
        shared_secret.zeroize();

        Ok(PreparedJweEncryptionKey {
            alg: JweKeyManagementAlgorithm::EcdhEs,
            cek,
            encrypted_key: Vec::new(),
            epk: Some(epk),
        })
    }
}

/// Decrypt-side P-256 ECDH-ES resolver for compact JWEs.
pub struct P256EcdhEsJweKeyResolver<'a> {
    recipient_private_key: &'a [u8],
}

impl<'a> P256EcdhEsJweKeyResolver<'a> {
    /// Builds a resolver over caller-owned recipient P-256 private key bytes.
    #[must_use]
    pub const fn new(recipient_private_key: &'a [u8]) -> Self {
        Self {
            recipient_private_key,
        }
    }
}

impl super::JweContentEncryptionKeyResolver for P256EcdhEsJweKeyResolver<'_> {
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        if header.alg != JweKeyManagementAlgorithm::EcdhEs || !encrypted_key.is_empty() {
            return Err(JweError::InvalidEncryptedKey);
        }
        let epk = header
            .epk
            .as_ref()
            .ok_or(JweError::MissingRequiredHeaderParameter)?;
        let ephemeral_public_key = p256_public_key_from_jwk(epk)?;
        let mut shared_secret = reallyme_crypto::p256::derive_p256_shared_secret(
            self.recipient_private_key,
            &ephemeral_public_key,
        )
        .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        let cek = derive_ecdh_es_content_encryption_key(&shared_secret, header)?;
        shared_secret.zeroize();
        Ok(cek)
    }
}

/// Native P-384 ECDH-ES encryptor for compact JWEs.
///
/// Production encryption uses fresh ephemeral key material generated by the
/// crypto backend for each message.
#[cfg(feature = "native")]
pub struct P384EcdhEsJweKeyEncryptor<'a> {
    recipient_public_key_sec1: &'a [u8],
}

#[cfg(feature = "native")]
impl<'a> P384EcdhEsJweKeyEncryptor<'a> {
    /// Builds an ECDH-ES encryptor for a recipient P-384 public key in SEC1 form.
    #[must_use]
    pub const fn new(recipient_public_key_sec1: &'a [u8]) -> Self {
        Self {
            recipient_public_key_sec1,
        }
    }
}

#[cfg(feature = "native")]
impl JweContentEncryptionKeyEncryptor for P384EcdhEsJweKeyEncryptor<'_> {
    fn prepare_content_encryption_key(
        &mut self,
        request: &CompactJweEncryptRequest<'_>,
    ) -> Result<PreparedJweEncryptionKey, JweError> {
        let (ephemeral_public, mut ephemeral_private) =
            reallyme_crypto::p384::generate_p384_keypair()
                .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        let mut shared_secret = reallyme_crypto::p384::derive_p384_shared_secret(
            &ephemeral_private,
            self.recipient_public_key_sec1,
        )
        .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        ephemeral_private.zeroize();

        let epk = p384_epk_from_sec1_public_key(&ephemeral_public)?;
        let header = CompactJweProtectedHeader {
            alg: JweKeyManagementAlgorithm::EcdhEs,
            enc: request.enc(),
            kid: request.kid().map(str::to_owned),
            apu: encode_optional_base64url(request.apu()),
            apv: encode_optional_base64url(request.apv()),
            epk: Some(epk.clone()),
            typ: request.typ().map(str::to_owned),
            cty: request.cty().map(str::to_owned),
        };
        let cek = derive_ecdh_es_content_encryption_key(&shared_secret, &header)?;
        shared_secret.zeroize();

        Ok(PreparedJweEncryptionKey {
            alg: JweKeyManagementAlgorithm::EcdhEs,
            cek,
            encrypted_key: Vec::new(),
            epk: Some(epk),
        })
    }
}

/// Native decrypt-side P-384 ECDH-ES resolver for compact JWEs.
#[cfg(feature = "native")]
pub struct P384EcdhEsJweKeyResolver<'a> {
    recipient_private_key: &'a [u8],
}

#[cfg(feature = "native")]
impl<'a> P384EcdhEsJweKeyResolver<'a> {
    /// Builds a resolver over caller-owned recipient P-384 private key bytes.
    #[must_use]
    pub const fn new(recipient_private_key: &'a [u8]) -> Self {
        Self {
            recipient_private_key,
        }
    }
}

#[cfg(feature = "native")]
impl super::JweContentEncryptionKeyResolver for P384EcdhEsJweKeyResolver<'_> {
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        if header.alg != JweKeyManagementAlgorithm::EcdhEs || !encrypted_key.is_empty() {
            return Err(JweError::InvalidEncryptedKey);
        }
        let epk = header
            .epk
            .as_ref()
            .ok_or(JweError::MissingRequiredHeaderParameter)?;
        let ephemeral_public_key = p384_public_key_from_jwk(epk)?;
        let mut shared_secret = reallyme_crypto::p384::derive_p384_shared_secret(
            self.recipient_private_key,
            &ephemeral_public_key,
        )
        .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        let cek = derive_ecdh_es_content_encryption_key(&shared_secret, header)?;
        shared_secret.zeroize();
        Ok(cek)
    }
}

/// Native P-521 ECDH-ES encryptor for compact JWEs.
///
/// Production encryption uses fresh ephemeral key material generated by the
/// crypto backend for each message.
#[cfg(feature = "native")]
pub struct P521EcdhEsJweKeyEncryptor<'a> {
    recipient_public_key_sec1: &'a [u8],
}

#[cfg(feature = "native")]
impl<'a> P521EcdhEsJweKeyEncryptor<'a> {
    /// Builds an ECDH-ES encryptor for a recipient P-521 public key in SEC1 form.
    #[must_use]
    pub const fn new(recipient_public_key_sec1: &'a [u8]) -> Self {
        Self {
            recipient_public_key_sec1,
        }
    }
}

#[cfg(feature = "native")]
impl JweContentEncryptionKeyEncryptor for P521EcdhEsJweKeyEncryptor<'_> {
    fn prepare_content_encryption_key(
        &mut self,
        request: &CompactJweEncryptRequest<'_>,
    ) -> Result<PreparedJweEncryptionKey, JweError> {
        let (ephemeral_public, mut ephemeral_private) =
            reallyme_crypto::p521::generate_p521_keypair()
                .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        let mut shared_secret = reallyme_crypto::p521::derive_p521_shared_secret(
            &ephemeral_private,
            self.recipient_public_key_sec1,
        )
        .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        ephemeral_private.zeroize();

        let epk = p521_epk_from_sec1_public_key(&ephemeral_public)?;
        let header = CompactJweProtectedHeader {
            alg: JweKeyManagementAlgorithm::EcdhEs,
            enc: request.enc(),
            kid: request.kid().map(str::to_owned),
            apu: encode_optional_base64url(request.apu()),
            apv: encode_optional_base64url(request.apv()),
            epk: Some(epk.clone()),
            typ: request.typ().map(str::to_owned),
            cty: request.cty().map(str::to_owned),
        };
        let cek = derive_ecdh_es_content_encryption_key(&shared_secret, &header)?;
        shared_secret.zeroize();

        Ok(PreparedJweEncryptionKey {
            alg: JweKeyManagementAlgorithm::EcdhEs,
            cek,
            encrypted_key: Vec::new(),
            epk: Some(epk),
        })
    }
}

/// Native decrypt-side P-521 ECDH-ES resolver for compact JWEs.
#[cfg(feature = "native")]
pub struct P521EcdhEsJweKeyResolver<'a> {
    recipient_private_key: &'a [u8],
}

#[cfg(feature = "native")]
impl<'a> P521EcdhEsJweKeyResolver<'a> {
    /// Builds a resolver over caller-owned recipient P-521 private key bytes.
    #[must_use]
    pub const fn new(recipient_private_key: &'a [u8]) -> Self {
        Self {
            recipient_private_key,
        }
    }
}

#[cfg(feature = "native")]
impl super::JweContentEncryptionKeyResolver for P521EcdhEsJweKeyResolver<'_> {
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        if header.alg != JweKeyManagementAlgorithm::EcdhEs || !encrypted_key.is_empty() {
            return Err(JweError::InvalidEncryptedKey);
        }
        let epk = header
            .epk
            .as_ref()
            .ok_or(JweError::MissingRequiredHeaderParameter)?;
        let ephemeral_public_key = p521_public_key_from_jwk(epk)?;
        let mut shared_secret = reallyme_crypto::p521::derive_p521_shared_secret(
            self.recipient_private_key,
            &ephemeral_public_key,
        )
        .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        let cek = derive_ecdh_es_content_encryption_key(&shared_secret, header)?;
        shared_secret.zeroize();
        Ok(cek)
    }
}

/// Encrypts plaintext bytes as a compact JWE.
///
/// The protected header is authenticated as JWE AAD. For `ECDH-ES`, this
/// function relies on the supplied encryptor to produce fresh key agreement
/// material.
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
    encrypt_compact_jwe_bytes(
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

fn p256_epk_from_sec1_public_key(public_key_sec1: &[u8]) -> Result<JsonValue, JweError> {
    ec_epk_from_sec1_public_key(
        public_key_sec1,
        "P-256",
        32,
        33,
        65,
        reallyme_crypto::p256::compress_public_key,
        reallyme_crypto::p256::decompress_public_key,
    )
}

fn p256_public_key_from_jwk(jwk: &JsonValue) -> Result<Vec<u8>, JweError> {
    ec_public_key_from_jwk(
        jwk,
        "P-256",
        32,
        33,
        reallyme_crypto::p256::decompress_public_key,
        reallyme_crypto::p256::compress_public_key,
    )
}

#[cfg(feature = "native")]
fn p384_epk_from_sec1_public_key(public_key_sec1: &[u8]) -> Result<JsonValue, JweError> {
    ec_epk_from_sec1_public_key(
        public_key_sec1,
        "P-384",
        48,
        49,
        97,
        reallyme_crypto::p384::compress_p384,
        reallyme_crypto::p384::decompress_p384,
    )
}

#[cfg(feature = "native")]
fn p384_public_key_from_jwk(jwk: &JsonValue) -> Result<Vec<u8>, JweError> {
    ec_public_key_from_jwk(
        jwk,
        "P-384",
        48,
        49,
        reallyme_crypto::p384::decompress_p384,
        reallyme_crypto::p384::compress_p384,
    )
}

#[cfg(feature = "native")]
fn p521_epk_from_sec1_public_key(public_key_sec1: &[u8]) -> Result<JsonValue, JweError> {
    ec_epk_from_sec1_public_key(
        public_key_sec1,
        "P-521",
        66,
        67,
        133,
        reallyme_crypto::p521::compress_p521,
        reallyme_crypto::p521::decompress_p521,
    )
}

#[cfg(feature = "native")]
fn p521_public_key_from_jwk(jwk: &JsonValue) -> Result<Vec<u8>, JweError> {
    ec_public_key_from_jwk(
        jwk,
        "P-521",
        66,
        67,
        reallyme_crypto::p521::decompress_p521,
        reallyme_crypto::p521::compress_p521,
    )
}

fn ec_epk_from_sec1_public_key(
    public_key_sec1: &[u8],
    crv: &'static str,
    coordinate_len: usize,
    compressed_len: usize,
    uncompressed_len: usize,
    compress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
    decompress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
) -> Result<JsonValue, JweError> {
    let uncompressed = ec_uncompressed_public_key(
        public_key_sec1,
        compressed_len,
        uncompressed_len,
        compress,
        decompress,
    )?;
    let x_start = 1usize;
    let x_end = x_start
        .checked_add(coordinate_len)
        .ok_or(JweError::LengthOverflow)?;
    let y_end = x_end
        .checked_add(coordinate_len)
        .ok_or(JweError::LengthOverflow)?;
    let x = uncompressed
        .get(x_start..x_end)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    let y = uncompressed
        .get(x_end..y_end)
        .ok_or(JweError::InvalidKeyAgreementKey)?;

    let mut epk = Map::new();
    epk.insert("kty".to_owned(), JsonValue::String("EC".to_owned()));
    epk.insert("crv".to_owned(), JsonValue::String(crv.to_owned()));
    epk.insert("x".to_owned(), JsonValue::String(encode_jwe_base64url(x)));
    epk.insert("y".to_owned(), JsonValue::String(encode_jwe_base64url(y)));
    Ok(JsonValue::Object(epk))
}

fn encode_optional_base64url(value: Option<&[u8]>) -> Option<String> {
    value.map(encode_jwe_base64url)
}

fn encode_jwe_base64url(bytes: &[u8]) -> String {
    bytes_to_base64url(bytes)
}

fn ec_uncompressed_public_key(
    public_key_sec1: &[u8],
    compressed_len: usize,
    uncompressed_len: usize,
    compress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
    decompress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
) -> Result<Vec<u8>, JweError> {
    if public_key_sec1.len() == compressed_len {
        return decompress(public_key_sec1).map_err(|_| JweError::InvalidKeyAgreementKey);
    }
    if public_key_sec1.len() == uncompressed_len && public_key_sec1.first().copied() == Some(0x04) {
        compress(public_key_sec1).map_err(|_| JweError::InvalidKeyAgreementKey)?;
        return Ok(public_key_sec1.to_vec());
    }
    Err(JweError::InvalidKeyAgreementKey)
}

fn ec_public_key_from_jwk(
    jwk: &JsonValue,
    crv: &'static str,
    coordinate_len: usize,
    compressed_len: usize,
    decompress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
    compress: fn(&[u8]) -> Result<Vec<u8>, reallyme_crypto::core::CryptoError>,
) -> Result<Vec<u8>, JweError> {
    let object = jwk.as_object().ok_or(JweError::InvalidKeyAgreementKey)?;
    let kty = object
        .get("kty")
        .and_then(JsonValue::as_str)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    let header_crv = object
        .get("crv")
        .and_then(JsonValue::as_str)
        .ok_or(JweError::InvalidKeyAgreementKey)?;
    if kty != "EC" || header_crv != crv {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    if object
        .get("alg")
        .and_then(JsonValue::as_str)
        .is_some_and(|alg| alg != "ECDH-ES")
    {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    let x = base64url_to_bytes(
        object
            .get("x")
            .and_then(JsonValue::as_str)
            .ok_or(JweError::InvalidKeyAgreementKey)?,
    )
    .map_err(|_| JweError::InvalidKeyAgreementKey)?;
    let y = base64url_to_bytes(
        object
            .get("y")
            .and_then(JsonValue::as_str)
            .ok_or(JweError::InvalidKeyAgreementKey)?,
    )
    .map_err(|_| JweError::InvalidKeyAgreementKey)?;
    if x.len() != coordinate_len || y.len() != coordinate_len {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    let uncompressed_coordinate_len = coordinate_len
        .checked_mul(2)
        .and_then(|len| len.checked_add(1))
        .ok_or(JweError::LengthOverflow)?;
    let mut uncompressed = Vec::with_capacity(uncompressed_coordinate_len);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    if uncompressed.len() != uncompressed_coordinate_len {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    let compressed = compress(&uncompressed).map_err(|_| JweError::InvalidKeyAgreementKey)?;
    if compressed.len() != compressed_len {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    let decoded = decompress(&compressed).map_err(|_| JweError::InvalidKeyAgreementKey)?;
    if decoded != uncompressed {
        return Err(JweError::InvalidKeyAgreementKey);
    }
    Ok(compressed)
}
