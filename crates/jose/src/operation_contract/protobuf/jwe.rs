// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protobuf adapters for canonical JWE execution.

use buffa::EnumValue;
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseCompactResult, JoseJweCompressionAlgorithm, JoseJweContentEncryptionAlgorithm,
    JoseJweDecryptRequest, JoseJweEncryptRequest, JoseJweHeaderValidationPolicy,
    JoseJweKeyManagementAlgorithm, JoseJwePlaintextResult,
};
use zeroize::Zeroizing;

use crate::jwe::{
    CompactJweEncryptRequest, CompactJwePolicy, DirectJweKeyEncryptor, DirectJweKeyResolver,
    JweCompressionAlgorithm, JweContentEncryptionAlgorithm, JweContentEncryptionKeyEncryptor,
    JweContentEncryptionKeyResolver, JweError, JweKeyManagementAlgorithm,
    P256EcdhEsJweKeyEncryptor, P256EcdhEsJweKeyResolver, PreparedJweEncryptionKey,
};
#[cfg(feature = "native")]
use crate::jwe::{
    P384EcdhEsJweKeyEncryptor, P384EcdhEsJweKeyResolver, P521EcdhEsJweKeyEncryptor,
    P521EcdhEsJweKeyResolver,
};
use crate::operation_contract::jwe::{decrypt_jwe, encrypt_jwe};
use crate::resolve_algorithm::JweKeyManagementSuite;
use crate::wire::JoseWireResult;
#[cfg(not(feature = "native"))]
use crate::wire::{proto::proto::reallyme::jose::v1::JoseErrorReason, JoseWireError};
use crate::SecureRandom;

pub(crate) fn encrypt_jwe_request<R: SecureRandom + ?Sized>(
    request: JoseJweEncryptRequest,
    rng: &mut R,
) -> JoseWireResult<JoseCompactResult> {
    encrypt_jwe_with_provider(request, rng, None)
}

pub(super) fn encrypt_jwe_with_provider<R: SecureRandom + ?Sized>(
    mut request: JoseJweEncryptRequest,
    rng: &mut R,
    provider: Option<&mut dyn JweContentEncryptionKeyEncryptor>,
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
    if let Some(value) = kid.as_deref() {
        native_request = native_request.with_kid(value);
    }
    if let Some(value) = apu.as_deref() {
        native_request = native_request.with_apu(value);
    }
    if let Some(value) = apv.as_deref() {
        native_request = native_request.with_apv(value);
    }
    if let Some(value) = typ.as_deref() {
        native_request = native_request.with_typ(value);
    }
    if let Some(value) = cty.as_deref() {
        native_request = native_request.with_cty(value);
    }
    if let Some(compression) = compression_from_proto(request.compression_algorithm)? {
        native_request = native_request.with_compression(compression);
    }

    let compact = match provider {
        Some(provider) => {
            // The selected suite remains authoritative even when key ownership
            // belongs to an external capability.
            let expected = JweKeyManagementSuite::try_from(request.key_management_algorithm)?;
            let mut bound = BoundEncryptor { provider, expected };
            encrypt_jwe(&native_request, &mut bound, rng)
        }
        None => {
            let mut encryptor = key_encryptor_from_proto(request.key_management_algorithm, &key)?;
            encrypt_jwe(&native_request, &mut encryptor, rng)
        }
    }
    .map_err(|error| crate::map_failure::jwe(&error))?;

    Ok(JoseCompactResult {
        compact: compact.into(),
    })
}

pub(crate) fn decrypt_jwe_request(
    mut request: JoseJweDecryptRequest,
) -> JoseWireResult<JoseJwePlaintextResult> {
    let key = Zeroizing::new(core::mem::take(&mut request.key));
    let compact = Zeroizing::new(core::mem::take(&mut request.compact));
    let header_policy = request.header_policy.take();
    let allowed_compression_algorithms = header_policy
        .as_ref()
        .map(compression_allowlist)
        .transpose()?
        .unwrap_or_default();
    let alg = key_management_from_proto(request.key_management_algorithm)?;
    let enc = content_encryption_from_proto(request.content_encryption_algorithm)?;
    let mut policy =
        CompactJwePolicy::new(core::slice::from_ref(&alg), core::slice::from_ref(&enc));
    if let Some(header) = header_policy.as_ref() {
        policy = apply_header_policy(policy, header, &allowed_compression_algorithms);
    }

    let resolver = key_resolver_from_proto(request.key_management_algorithm, &key)?;
    let mut plaintext = decrypt_jwe(&compact, &policy, &resolver)
        .map_err(|error| crate::map_failure::jwe(&error))?;

    Ok(JoseJwePlaintextResult {
        plaintext: core::mem::take(&mut *plaintext).into(),
    })
}

struct BoundEncryptor<'a> {
    provider: &'a mut dyn JweContentEncryptionKeyEncryptor,
    expected: JweKeyManagementSuite,
}

impl JweContentEncryptionKeyEncryptor for BoundEncryptor<'_> {
    fn prepare_content_encryption_key(
        &mut self,
        request: &CompactJweEncryptRequest<'_>,
    ) -> Result<PreparedJweEncryptionKey, JweError> {
        let prepared = self.provider.prepare_content_encryption_key(request)?;
        if prepared.algorithm() != self.expected.header_algorithm()
            || prepared.ephemeral_curve() != self.expected.jwk_curve()
        {
            return Err(JweError::HeaderPolicyMismatch);
        }
        Ok(prepared)
    }
}

pub(super) fn compression_allowlist(
    policy: &JoseJweHeaderValidationPolicy,
) -> JoseWireResult<Vec<JweCompressionAlgorithm>> {
    policy
        .allowed_compression_algorithms
        .iter()
        .copied()
        .map(JweCompressionAlgorithm::try_from)
        .collect()
}

pub(super) fn apply_header_policy<'a>(
    mut policy: CompactJwePolicy<'a>,
    header: &'a JoseJweHeaderValidationPolicy,
    compression: &'a [JweCompressionAlgorithm],
) -> CompactJwePolicy<'a> {
    policy = policy.with_allowed_compression_algorithms(compression);
    if header.require_kid {
        policy = policy.require_kid();
    }
    if let Some(value) = header.expected_kid.as_option() {
        policy = policy.with_expected_kid(&value.value);
    }
    if let Some(value) = header.expected_typ.as_option() {
        policy = policy.with_expected_typ(&value.value);
    }
    if let Some(value) = header.expected_cty.as_option() {
        policy = policy.with_expected_cty(&value.value);
    }
    if let Some(value) = header.expected_apu.as_option() {
        policy = policy.with_expected_apu(&value.value);
    }
    if let Some(value) = header.expected_apv.as_option() {
        policy = policy.with_expected_apv(&value.value);
    }
    policy
}

fn compression_from_proto(
    value: EnumValue<JoseJweCompressionAlgorithm>,
) -> JoseWireResult<Option<JweCompressionAlgorithm>> {
    if value.as_known()
        == Some(JoseJweCompressionAlgorithm::JOSE_JWE_COMPRESSION_ALGORITHM_UNSPECIFIED)
    {
        return Ok(None);
    }
    JweCompressionAlgorithm::try_from(value).map(Some)
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
    match JweKeyManagementSuite::try_from(value)? {
        JweKeyManagementSuite::Direct => Ok(ProtobufJweKeyEncryptor::Direct(
            DirectJweKeyEncryptor::new(key),
        )),
        JweKeyManagementSuite::P256 => Ok(ProtobufJweKeyEncryptor::P256(
            P256EcdhEsJweKeyEncryptor::new(key),
        )),
        #[cfg(feature = "native")]
        JweKeyManagementSuite::P384 => Ok(ProtobufJweKeyEncryptor::P384(
            P384EcdhEsJweKeyEncryptor::new(key),
        )),
        #[cfg(feature = "native")]
        JweKeyManagementSuite::P521 => Ok(ProtobufJweKeyEncryptor::P521(
            P521EcdhEsJweKeyEncryptor::new(key),
        )),
        #[cfg(not(feature = "native"))]
        JweKeyManagementSuite::P384 | JweKeyManagementSuite::P521 => {
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
    match JweKeyManagementSuite::try_from(value)? {
        JweKeyManagementSuite::Direct => Ok(ProtobufJweKeyResolver::Direct(
            DirectJweKeyResolver::new(key),
        )),
        JweKeyManagementSuite::P256 => Ok(ProtobufJweKeyResolver::P256(
            P256EcdhEsJweKeyResolver::new(key),
        )),
        #[cfg(feature = "native")]
        JweKeyManagementSuite::P384 => Ok(ProtobufJweKeyResolver::P384(
            P384EcdhEsJweKeyResolver::new(key),
        )),
        #[cfg(feature = "native")]
        JweKeyManagementSuite::P521 => Ok(ProtobufJweKeyResolver::P521(
            P521EcdhEsJweKeyResolver::new(key),
        )),
        #[cfg(not(feature = "native"))]
        JweKeyManagementSuite::P384 | JweKeyManagementSuite::P521 => {
            Err(unsupported_provider_error())
        }
    }
}

fn content_encryption_from_proto(
    value: EnumValue<JoseJweContentEncryptionAlgorithm>,
) -> JoseWireResult<JweContentEncryptionAlgorithm> {
    JweContentEncryptionAlgorithm::try_from(value)
}

fn key_management_from_proto(
    value: EnumValue<JoseJweKeyManagementAlgorithm>,
) -> JoseWireResult<JweKeyManagementAlgorithm> {
    JweKeyManagementSuite::try_from(value).map(JweKeyManagementSuite::header_algorithm)
}

#[cfg(not(feature = "native"))]
const fn unsupported_provider_error() -> JoseWireError {
    JoseWireError::provider_internal(JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED)
}
