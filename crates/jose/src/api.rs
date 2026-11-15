// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authoritative generated JOSE contract and typed execution.

pub use crate::operation_contract::providers::{BuiltinProviders, OperationProviders};
/// Schema-generated requests, results, selectors, and stable reason codes.
pub use reallyme_jose_proto::generated::proto::reallyme::jose::v1 as contract;

/// Executes a generated request using built-in providers and secure randomness.
#[must_use]
pub fn execute(request: contract::JoseOperationRequest) -> contract::JoseOperationResponse {
    execute_with_providers(request, &mut BuiltinProviders)
}

/// Executes a generated request with caller-owned, non-exporting capabilities.
#[must_use]
pub fn execute_with_providers(
    request: contract::JoseOperationRequest,
    providers: &mut dyn OperationProviders,
) -> contract::JoseOperationResponse {
    crate::wire::execute_operation_request_with_providers(
        request,
        &mut crate::OsSecureRandom,
        providers,
    )
}
