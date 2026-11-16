// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::num::NonZeroU64;

use crate::api::contract::{
    JoseCompactResult, JoseErrorReason, JoseJwsSignWithProviderRequest,
    JoseJwsVerifyWithProviderRequest, JoseVerifyResult,
};
use crate::jws::{sign_compact_jws_with_provider, verify_compact_jws_with_provider};
use crate::operation_contract::providers::OperationProviders;
use crate::wire::{JoseWireError, JoseWireResult};

pub(crate) fn sign(
    request: &JoseJwsSignWithProviderRequest,
    providers: &dyn OperationProviders,
) -> JoseWireResult<JoseCompactResult> {
    sign_compact_jws_with_provider(request, |algorithm, signing_input| {
        providers.sign_compact_jws(handle(request.signer_handle)?, algorithm, signing_input)
    })
}

pub(crate) fn verify(
    request: &JoseJwsVerifyWithProviderRequest,
    providers: &dyn OperationProviders,
) -> JoseWireResult<JoseVerifyResult> {
    verify_compact_jws_with_provider(request, |algorithm, signing_input, parts| {
        providers.verify_compact_jws(
            handle(request.verifier_handle)?,
            algorithm,
            signing_input,
            parts,
        )
    })
    .map(|(verified, ())| verified)
}

fn handle(value: Option<u64>) -> JoseWireResult<NonZeroU64> {
    value
        .and_then(NonZeroU64::new)
        .ok_or_else(|| JoseWireError::provider_internal(JoseErrorReason::ProviderUnavailable))
}
