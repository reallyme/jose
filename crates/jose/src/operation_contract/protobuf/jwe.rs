// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Protobuf adapters for canonical JWE execution.

use buffa::EnumValue;
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseCompactResult, JoseErrorReason, JoseJweContentEncryptionAlgorithm, JoseJweDecryptRequest,
    JoseJweEncryptRequest, JoseJweKeyManagementAlgorithm, JoseJwePlaintextResult,
};
use zeroize::Zeroizing;

use crate::jwe::{
    CompactJweEncryptRequest, CompactJwePolicy, DirectJweKeyEncryptor, DirectJweKeyResolver,
    JweContentEncryptionAlgorithm, JweContentEncryptionKeyEncryptor,
    JweContentEncryptionKeyResolver, JweError, JweKeyManagementAlgorithm,
    P256EcdhEsJweKeyEncryptor, P256EcdhEsJweKeyResolver, PreparedJweEncryptionKey,
};
#[cfg(feature = "native")]
use crate::jwe::{
    P384EcdhEsJweKeyEncryptor, P384EcdhEsJweKeyResolver, P521EcdhEsJweKeyEncryptor,
    P521EcdhEsJweKeyResolver,
};
use crate::operation_contract::jwe::{decrypt_jwe, encrypt_jwe};
use crate::wire::{JoseWireError, JoseWireResult};
use crate::SecureRandom;

pub(crate) fn encrypt_jwe_request<R: SecureRandom + ?Sized>(
    mut request: JoseJweEncryptRequest,
    rng: &mut R,
) -> JoseWireResult<JoseCompactResult> {
    let plaintext = Zeroizing::new(core::mem::take(&mut request.plaintext));
    let key = Zeroizing::new(core::mem::take(&mut request.key));
    let kid = Zeroizing::new(core::mem::take(&mut request.kid));
    let typ = Zeroizing::new(core::mem::take(&mut request.typ));
    let cty = Zeroizing::new(core::mem::take(&mut request.cty));
    let apu = Zeroizing::new(core::mem::take(&mut request.apu));
    let apv = Zeroizing::new(core::mem::take(&mut request.apv));
    let enc = content_encryption_from_proto(request.content_encryption_algorithm)?;
    let mut native_request = CompactJweEncryptRequest::new(&plaintext, enc);
    if let Some(value) = optional_str(&kid) {
        native_request = native_request.with_kid(value);
    }
    if let Some(value) = optional_bytes(&apu) {
        native_request = native_request.with_apu(value);
    }
    if let Some(value) = optional_bytes(&apv) {
        native_request = native_request.with_apv(value);
    }
    if let Some(value) = optional_str(&typ) {
        native_request = native_request.with_typ(value);
    }
    if let Some(value) = optional_str(&cty) {
        native_request = native_request.with_cty(value);
    }

    let mut encryptor = key_encryptor_from_proto(request.key_management_algorithm, &key)?;
    let compact = encrypt_jwe(&native_request, &mut encryptor, rng).map_err(map_jwe_error)?;

    Ok(JoseCompactResult {
        compact,
        __buffa_unknown_fields: Default::default(),
    })
}

pub(crate) fn decrypt_jwe_request(
    mut request: JoseJweDecryptRequest,
) -> JoseWireResult<JoseJwePlaintextResult> {
    let key = Zeroizing::new(core::mem::take(&mut request.key));
    let compact = Zeroizing::new(core::mem::take(&mut request.compact));
    let header_policy_is_set = request.header_policy.is_set();
    let mut header_policy = request.header_policy.take().unwrap_or_default();
    let expected_kid_is_set = header_policy.expected_kid.is_set();
    let expected_typ_is_set = header_policy.expected_typ.is_set();
    let expected_cty_is_set = header_policy.expected_cty.is_set();
    let expected_apu_is_set = header_policy.expected_apu.is_set();
    let expected_apv_is_set = header_policy.expected_apv.is_set();
    let expected_kid = Zeroizing::new(
        header_policy
            .expected_kid
            .take()
            .map_or_else(String::new, |mut value| core::mem::take(&mut value.value)),
    );
    let expected_typ = Zeroizing::new(
        header_policy
            .expected_typ
            .take()
            .map_or_else(String::new, |mut value| core::mem::take(&mut value.value)),
    );
    let expected_cty = Zeroizing::new(
        header_policy
            .expected_cty
            .take()
            .map_or_else(String::new, |mut value| core::mem::take(&mut value.value)),
    );
    let expected_apu = Zeroizing::new(
        header_policy
            .expected_apu
            .take()
            .map_or_else(Vec::new, |mut value| core::mem::take(&mut value.value)),
    );
    let expected_apv = Zeroizing::new(
        header_policy
            .expected_apv
            .take()
            .map_or_else(Vec::new, |mut value| core::mem::take(&mut value.value)),
    );
    let alg = key_management_from_proto(request.key_management_algorithm)?;
    let enc = content_encryption_from_proto(request.content_encryption_algorithm)?;
    let mut policy =
        CompactJwePolicy::new(core::slice::from_ref(&alg), core::slice::from_ref(&enc));
    if header_policy_is_set {
        if header_policy.require_kid {
            policy = policy.require_kid();
        }
        if expected_kid_is_set {
            policy = policy.with_expected_kid(&expected_kid);
        }
        if expected_typ_is_set {
            policy = policy.with_expected_typ(&expected_typ);
        }
        if expected_cty_is_set {
            policy = policy.with_expected_cty(&expected_cty);
        }
        if expected_apu_is_set {
            policy = policy.with_expected_apu(&expected_apu);
        }
        if expected_apv_is_set {
            policy = policy.with_expected_apv(&expected_apv);
        }
    }

    let resolver = key_resolver_from_proto(request.key_management_algorithm, &key)?;
    let mut plaintext = decrypt_jwe(&compact, &policy, &resolver).map_err(map_jwe_error)?;

    Ok(JoseJwePlaintextResult {
        plaintext: core::mem::take(&mut plaintext),
        __buffa_unknown_fields: Default::default(),
    })
}

const fn optional_str(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

const fn optional_bytes(value: &[u8]) -> Option<&[u8]> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn known_key_management_algorithm(
    value: EnumValue<JoseJweKeyManagementAlgorithm>,
) -> JoseWireResult<JoseJweKeyManagementAlgorithm> {
    value.as_known().ok_or(unsupported_provider_error())
}

enum ProtobufJweKeyEncryptor<'a> {
    Direct(DirectJweKeyEncryptor<'a>),
    P256(P256EcdhEsJweKeyEncryptor<'a>),
    #[cfg(feature = "native")]
    P384(P384EcdhEsJweKeyEncryptor<'a>),
    #[cfg(feature = "native")]
    P521(P521EcdhEsJweKeyEncryptor<'a>),
}

impl JweContentEncryptionKeyEncryptor for ProtobufJweKeyEncryptor<'_> {
    fn prepare_content_encryption_key(
        &mut self,
        request: &CompactJweEncryptRequest<'_>,
    ) -> Result<PreparedJweEncryptionKey, JweError> {
        match self {
            Self::Direct(provider) => provider.prepare_content_encryption_key(request),
            Self::P256(provider) => provider.prepare_content_encryption_key(request),
            #[cfg(feature = "native")]
            Self::P384(provider) => provider.prepare_content_encryption_key(request),
            #[cfg(feature = "native")]
            Self::P521(provider) => provider.prepare_content_encryption_key(request),
        }
    }
}

fn key_encryptor_from_proto<'a>(
    value: EnumValue<JoseJweKeyManagementAlgorithm>,
    key: &'a [u8],
) -> JoseWireResult<ProtobufJweKeyEncryptor<'a>> {
    match known_key_management_algorithm(value)? {
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT => Ok(
            ProtobufJweKeyEncryptor::Direct(DirectJweKeyEncryptor::new(key)),
        ),
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256 => Ok(
            ProtobufJweKeyEncryptor::P256(P256EcdhEsJweKeyEncryptor::new(key)),
        ),
        #[cfg(feature = "native")]
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384 => Ok(
            ProtobufJweKeyEncryptor::P384(P384EcdhEsJweKeyEncryptor::new(key)),
        ),
        #[cfg(feature = "native")]
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521 => Ok(
            ProtobufJweKeyEncryptor::P521(P521EcdhEsJweKeyEncryptor::new(key)),
        ),
        #[cfg(not(feature = "native"))]
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384
        | JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521 => {
            Err(unsupported_provider_error())
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_UNSPECIFIED => {
            Err(unsupported_provider_error())
        }
    }
}

enum ProtobufJweKeyResolver<'a> {
    Direct(DirectJweKeyResolver<'a>),
    P256(P256EcdhEsJweKeyResolver<'a>),
    #[cfg(feature = "native")]
    P384(P384EcdhEsJweKeyResolver<'a>),
    #[cfg(feature = "native")]
    P521(P521EcdhEsJweKeyResolver<'a>),
}

impl JweContentEncryptionKeyResolver for ProtobufJweKeyResolver<'_> {
    fn resolve_content_encryption_key(
        &self,
        header: &crate::jwe::CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JweError> {
        match self {
            Self::Direct(provider) => {
                provider.resolve_content_encryption_key(header, encrypted_key)
            }
            Self::P256(provider) => provider.resolve_content_encryption_key(header, encrypted_key),
            #[cfg(feature = "native")]
            Self::P384(provider) => provider.resolve_content_encryption_key(header, encrypted_key),
            #[cfg(feature = "native")]
            Self::P521(provider) => provider.resolve_content_encryption_key(header, encrypted_key),
        }
    }
}

fn key_resolver_from_proto<'a>(
    value: EnumValue<JoseJweKeyManagementAlgorithm>,
    key: &'a [u8],
) -> JoseWireResult<ProtobufJweKeyResolver<'a>> {
    match known_key_management_algorithm(value)? {
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT => Ok(
            ProtobufJweKeyResolver::Direct(DirectJweKeyResolver::new(key)),
        ),
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256 => Ok(
            ProtobufJweKeyResolver::P256(P256EcdhEsJweKeyResolver::new(key)),
        ),
        #[cfg(feature = "native")]
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384 => Ok(
            ProtobufJweKeyResolver::P384(P384EcdhEsJweKeyResolver::new(key)),
        ),
        #[cfg(feature = "native")]
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521 => Ok(
            ProtobufJweKeyResolver::P521(P521EcdhEsJweKeyResolver::new(key)),
        ),
        #[cfg(not(feature = "native"))]
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384
        | JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521 => {
            Err(unsupported_provider_error())
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_UNSPECIFIED => {
            Err(unsupported_provider_error())
        }
    }
}

fn content_encryption_from_proto(
    value: EnumValue<JoseJweContentEncryptionAlgorithm>,
) -> JoseWireResult<JweContentEncryptionAlgorithm> {
    match value.as_known() {
        Some(JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM) => {
            Ok(JweContentEncryptionAlgorithm::A128Gcm)
        }
        Some(JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A192GCM) => {
            Ok(JweContentEncryptionAlgorithm::A192Gcm)
        }
        Some(JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM) => {
            Ok(JweContentEncryptionAlgorithm::A256Gcm)
        }
        Some(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_UNSPECIFIED,
        )
        | None => Err(unsupported_provider_error()),
    }
}

fn key_management_from_proto(
    value: EnumValue<JoseJweKeyManagementAlgorithm>,
) -> JoseWireResult<JweKeyManagementAlgorithm> {
    match value.as_known() {
        Some(JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT) => {
            Ok(JweKeyManagementAlgorithm::Direct)
        }
        Some(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256
            | JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384
            | JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521,
        ) => Ok(JweKeyManagementAlgorithm::EcdhEs),
        Some(JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_UNSPECIFIED)
        | None => Err(unsupported_provider_error()),
    }
}

const fn unsupported_provider_error() -> JoseWireError {
    JoseWireError::provider_internal(JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED)
}

const fn map_jwe_error(error: JweError) -> JoseWireError {
    let reason = match error {
        JweError::InvalidCompact => JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_COMPACT,
        JweError::InputTooLarge => JoseErrorReason::JOSE_ERROR_REASON_JWE_INPUT_TOO_LARGE,
        JweError::InvalidEncoding => JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_ENCODING,
        JweError::InvalidHeader => JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_HEADER,
        JweError::UnsupportedKeyManagementAlgorithm => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_KEY_MANAGEMENT_ALGORITHM
        }
        JweError::UnsupportedContentEncryptionAlgorithm => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM
        }
        JweError::MissingRequiredHeaderParameter => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_MISSING_REQUIRED_HEADER_PARAMETER
        }
        JweError::HeaderPolicyMismatch
        | JweError::TypPolicyMismatch
        | JweError::CtyPolicyMismatch => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH
        }
        JweError::KidPolicyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWE_KID_POLICY_MISMATCH,
        JweError::ApuPolicyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWE_APU_POLICY_MISMATCH,
        JweError::ApvPolicyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWE_APV_POLICY_MISMATCH,
        JweError::InvalidEncryptedKey => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_ENCRYPTED_KEY
        }
        JweError::InvalidContentEncryptionKey => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_ENCRYPTION_KEY
        }
        JweError::InvalidContentCipherInput => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_CIPHER_INPUT
        }
        JweError::Decrypt => JoseErrorReason::JOSE_ERROR_REASON_JWE_DECRYPT_FAILED,
        JweError::Encrypt => JoseErrorReason::JOSE_ERROR_REASON_JWE_ENCRYPT_FAILED,
        JweError::InvalidKeyAgreementKey => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_KEY_AGREEMENT_KEY
        }
        JweError::InvalidSharedSecret => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_SHARED_SECRET
        }
        JweError::KeyDerivation => {
            return JoseWireError::backend_internal(
                JoseErrorReason::JOSE_ERROR_REASON_BACKEND_KEY_DERIVATION_FAILED,
            )
        }
        JweError::Randomness => {
            return JoseWireError::provider_internal(
                JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
            )
        }
        JweError::InvalidPayloadJson => JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_PAYLOAD_JSON,
        JweError::LengthOverflow => JoseErrorReason::JOSE_ERROR_REASON_JWE_LENGTH_OVERFLOW,
    };
    JoseWireError::primitive_internal(reason)
}
