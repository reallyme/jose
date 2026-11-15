// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Application-scoped capability adapters for generated operation requests.

use core::num::NonZeroU64;
use zeroize::Zeroizing;

use crate::api::contract::{
    JoseCompactResult, JoseErrorReason, JoseJweDecryptWithProviderRequest,
    JoseJweEncryptWithProviderRequest, JoseJwePlaintextResult, JoseJwtSignWithProviderRequest,
};
use crate::jwe::{CompactJwePolicy, JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm};
use crate::operation_contract::jwe::decrypt_jwe;
use crate::operation_contract::jwt::sign_jwt_with_signer;
use crate::operation_contract::providers::OperationProviders;
use crate::wire::{JoseWireError, JoseWireResult};
use crate::SecureRandom;

use super::jwe::{apply_header_policy, compression_allowlist, encrypt_jwe_with_provider};
use super::jwt::header_options;
use super::jwt_jwk::{jwk_from_json, JwkOperation};

fn capability_handle(value: Option<u64>) -> JoseWireResult<NonZeroU64> {
    value
        .and_then(NonZeroU64::new)
        .ok_or_else(|| JoseWireError::primitive_internal(JoseErrorReason::CommonMalformedProtobuf))
}

pub(crate) fn sign_jwt(
    mut request: JoseJwtSignWithProviderRequest,
    providers: &dyn OperationProviders,
) -> JoseWireResult<JoseCompactResult> {
    let handle = capability_handle(request.signer_handle)?;
    let claims = Zeroizing::new(core::mem::take(&mut request.claims_json));
    let jwk_json = Zeroizing::new(core::mem::take(&mut request.jwk_json));
    let jwk = jwk_from_json(&jwk_json, JwkOperation::Sign)?;
    let options = header_options(request.header_options.take())?;
    let signer = providers.signer(handle)?;
    let compact = sign_jwt_with_signer(&claims, &jwk, signer, &options)
        .map_err(|error| crate::map_failure::jwt(&error))?;
    Ok(JoseCompactResult {
        compact: compact.into(),
    })
}

pub(crate) fn encrypt_jwe<R: SecureRandom + ?Sized>(
    mut request: JoseJweEncryptWithProviderRequest,
    providers: &mut dyn OperationProviders,
    rng: &mut R,
) -> JoseWireResult<JoseCompactResult> {
    let handle = capability_handle(request.provider_handle)?;
    let parameters = request
        .parameters
        .take()
        .ok_or_else(|| JoseWireError::primitive_internal(JoseErrorReason::JweInvalidHeader))?;
    if !parameters.key.is_empty() {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JweInvalidKeyAgreementKey,
        ));
    }
    let provider = providers.jwe_encryptor(handle)?;
    encrypt_jwe_with_provider(parameters, rng, Some(provider))
}

pub(crate) fn decrypt_with_provider(
    mut request: JoseJweDecryptWithProviderRequest,
    providers: &dyn OperationProviders,
) -> JoseWireResult<JoseJwePlaintextResult> {
    let handle = capability_handle(request.provider_handle)?;
    let compact = Zeroizing::new(core::mem::take(&mut request.compact));
    let policy = request
        .policy
        .take()
        .ok_or_else(|| JoseWireError::primitive_internal(JoseErrorReason::JweInvalidHeader))?;
    let algorithms = policy
        .allowed_key_management_algorithms
        .iter()
        .copied()
        .map(JweKeyManagementAlgorithm::try_from)
        .collect::<JoseWireResult<Vec<_>>>()?;
    let content = policy
        .allowed_content_encryption_algorithms
        .iter()
        .copied()
        .map(JweContentEncryptionAlgorithm::try_from)
        .collect::<JoseWireResult<Vec<_>>>()?;
    let compression = compression_allowlist(&policy.header_policy)?;
    let native_policy = apply_header_policy(
        CompactJwePolicy::new(&algorithms, &content),
        &policy.header_policy,
        &compression,
    );
    let resolver = providers.jwe_resolver(handle)?;
    let mut plaintext = decrypt_jwe(&compact, &native_policy, resolver)
        .map_err(|error| crate::map_failure::jwe(&error))?;
    Ok(JoseJwePlaintextResult {
        plaintext: core::mem::take(&mut *plaintext).into(),
    })
}
