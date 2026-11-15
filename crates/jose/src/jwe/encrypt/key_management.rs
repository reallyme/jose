// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::{CryptoError, CryptoErrorReason};
use zeroize::Zeroize;

use crate::jwe::validate_ephemeral_key::{agree_with_validated_ephemeral_key, PublicEphemeralJwk};
use crate::jwe::validate_header::validate_jwe_header_structure;
use crate::jwe::validate_key_management::{
    validate_content_encryption_key_length, validate_encrypted_key_segment,
    validate_resolver_key_management,
};
use crate::jwe::{
    derive_ecdh_es_content_encryption_key, CompactJweProtectedHeader,
    JweContentEncryptionKeyResolver, JweError, JweKeyManagementAlgorithm,
};
use crate::{JsonValue, Zeroizing};

use super::ec_keys::{p256_epk_from_sec1_public_key, p256_public_key_from_jwk};
#[cfg(feature = "native")]
use super::ec_keys::{
    p384_epk_from_sec1_public_key, p384_public_key_from_jwk, p521_epk_from_sec1_public_key,
    p521_public_key_from_jwk,
};
use super::{encode_optional_base64url, CompactJweEncryptRequest};

const fn map_keypair_generation_error(error: CryptoError) -> JweError {
    match error.reason() {
        CryptoErrorReason::ProviderRandomnessUnavailable => JweError::Randomness,
        _ => JweError::InvalidKeyAgreementKey,
    }
}

fn resolve_ecdh_es_cek(
    header: &CompactJweProtectedHeader,
    encrypted_key: &[u8],
    recipient_private_key: &[u8],
    decode_epk: impl FnOnce(&JsonValue) -> Result<Vec<u8>, JweError>,
    derive_shared_secret: impl FnOnce(&[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>,
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    validate_resolver_key_management(
        JweKeyManagementAlgorithm::EcdhEs,
        header.alg,
        encrypted_key.len(),
    )?;
    agree_with_validated_ephemeral_key(header.epk.as_ref(), decode_epk, |ephemeral_public_key| {
        let shared_secret = derive_shared_secret(recipient_private_key, &ephemeral_public_key)
            .map_err(|_| JweError::InvalidKeyAgreementKey)?;
        derive_ecdh_es_content_encryption_key(&shared_secret, header)
    })
}

#[cfg(test)]
#[path = "key_management_tests.rs"]
mod key_management_tests;

/// Prepared CEK and protected-header additions from a JWE key-management step.
pub struct PreparedJweEncryptionKey {
    pub(super) alg: JweKeyManagementAlgorithm,
    pub(super) cek: Zeroizing<Vec<u8>>,
    pub(super) encrypted_key: Vec<u8>,
    pub(super) epk: Option<JsonValue>,
}

impl PreparedJweEncryptionKey {
    pub(crate) const fn algorithm(&self) -> JweKeyManagementAlgorithm {
        self.alg
    }

    pub(crate) fn ephemeral_curve(&self) -> Option<&str> {
        self.epk
            .as_ref()
            .and_then(|value| value.get("crv"))
            .and_then(JsonValue::as_str)
    }

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
        validate_encrypted_key_segment(alg, encrypted_key.len())?;
        validate_jwe_header_structure(alg, epk.is_some(), false, false)?;
        if let Some(epk) = epk.as_ref() {
            PublicEphemeralJwk::try_from(epk)?;
        }
        Ok(Self {
            alg,
            cek,
            encrypted_key,
            epk,
        })
    }
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
    ///
    /// This stateless boundary generates a fresh 96-bit IV for each encryption
    /// but cannot count invocations made with the same caller-owned CEK.
    /// Applications must enforce an AES-GCM per-key usage budget and rotate the
    /// CEK before the applicable NIST SP 800-38D invocation limit is reached.
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
        validate_content_encryption_key_length(request.enc(), self.key.len())?;
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
/// crypto backend's CSPRNG for each message. This randomness is independent
/// of the IV source passed to `encrypt_compact_jwe_bytes`.
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
            reallyme_crypto::p256::generate_p256_keypair().map_err(map_keypair_generation_error)?;
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
            zip: request.compression(),
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

impl JweContentEncryptionKeyResolver for P256EcdhEsJweKeyResolver<'_> {
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        resolve_ecdh_es_cek(
            header,
            encrypted_key,
            self.recipient_private_key,
            p256_public_key_from_jwk,
            reallyme_crypto::p256::derive_p256_shared_secret,
        )
    }
}

/// Native P-384 ECDH-ES encryptor for compact JWEs.
///
/// Production encryption uses fresh ephemeral key material generated by the
/// crypto backend's CSPRNG for each message. This randomness is independent
/// of the IV source passed to `encrypt_compact_jwe_bytes`.
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
            reallyme_crypto::p384::generate_p384_keypair().map_err(map_keypair_generation_error)?;
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
            zip: request.compression(),
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
impl JweContentEncryptionKeyResolver for P384EcdhEsJweKeyResolver<'_> {
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        resolve_ecdh_es_cek(
            header,
            encrypted_key,
            self.recipient_private_key,
            p384_public_key_from_jwk,
            reallyme_crypto::p384::derive_p384_shared_secret,
        )
    }
}

/// Native P-521 ECDH-ES encryptor for compact JWEs.
///
/// Production encryption uses fresh ephemeral key material generated by the
/// crypto backend's CSPRNG for each message. This randomness is independent
/// of the IV source passed to `encrypt_compact_jwe_bytes`.
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
            reallyme_crypto::p521::generate_p521_keypair().map_err(map_keypair_generation_error)?;
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
            zip: request.compression(),
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
impl JweContentEncryptionKeyResolver for P521EcdhEsJweKeyResolver<'_> {
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        resolve_ecdh_es_cek(
            header,
            encrypted_key,
            self.recipient_private_key,
            p521_public_key_from_jwk,
            reallyme_crypto::p521::derive_p521_shared_secret,
        )
    }
}
