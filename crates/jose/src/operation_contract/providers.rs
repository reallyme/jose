// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Caller-scoped capabilities named by generated operation handles.

use core::num::NonZeroU64;

use crate::api::contract::{JoseExternalJwsAlgorithm, JoseInspectedCompactJws};
use crate::jwe::{JweContentEncryptionKeyEncryptor, JweContentEncryptionKeyResolver};
use crate::wire::proto::proto::reallyme::jose::v1::JoseErrorReason;
use crate::wire::{JoseWireError, JoseWireResult};
use crate::Signer;
use zeroize::Zeroizing;

const fn unavailable() -> JoseWireError {
    JoseWireError::provider_internal(JoseErrorReason::ProviderUnavailable)
}

/// Application-local capabilities for schema-defined provider handles.
///
/// Resolve handles only within the caller's authorization context. Returned
/// capabilities must remain stable for the call; no global registry or key
/// export is introduced by this interface. Missing capabilities fail closed.
pub trait OperationProviders {
    /// Resolves a JWT signer without exporting its private key.
    /// # Errors
    /// Returns a fixed provider failure when the capability is unavailable.
    fn signer(&self, _handle: NonZeroU64) -> JoseWireResult<&dyn Signer> {
        Err(unavailable())
    }

    /// Signs exact compact JWS input and returns JOSE wire signature bytes.
    /// The provider must bind the handle to the selected algorithm.
    /// # Errors
    /// Returns a fixed failure when the capability cannot sign for the algorithm.
    fn sign_compact_jws(
        &self,
        _handle: NonZeroU64,
        _algorithm: JoseExternalJwsAlgorithm,
        _signing_input: &[u8],
    ) -> JoseWireResult<Zeroizing<Vec<u8>>> {
        Err(unavailable())
    }

    /// Verifies compact JWS against the key authorized for this handle and algorithm.
    /// # Errors
    /// Returns a fixed error if the capability is unavailable or authentication fails.
    fn verify_compact_jws(
        &self,
        _handle: NonZeroU64,
        _algorithm: JoseExternalJwsAlgorithm,
        _signing_input: &[u8],
        _input: &JoseInspectedCompactJws,
    ) -> JoseWireResult<()> {
        Err(unavailable())
    }

    /// Resolves a JWE encryption capability.
    /// # Errors
    /// Returns a fixed provider failure when the capability is unavailable.
    fn jwe_encryptor(
        &mut self,
        _handle: NonZeroU64,
    ) -> JoseWireResult<&mut dyn JweContentEncryptionKeyEncryptor> {
        Err(unavailable())
    }

    /// Resolves a JWE decryption capability under an explicit header policy.
    /// # Errors
    /// Returns a fixed provider failure when the capability is unavailable.
    fn jwe_resolver(
        &self,
        _handle: NonZeroU64,
    ) -> JoseWireResult<&dyn JweContentEncryptionKeyResolver> {
        Err(unavailable())
    }
}

/// Built-in operations with no application-local handles enabled.
pub struct BuiltinProviders;

impl OperationProviders for BuiltinProviders {}
