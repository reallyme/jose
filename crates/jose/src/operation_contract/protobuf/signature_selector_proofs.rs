// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{JoseErrorReason, JoseSignatureAlgorithm};
use crate::operation_contract::jws::JwsAlgorithm;
use crate::wire::JoseWireErrorBranch;
use buffa::EnumValue;

#[kani::proof]
fn signature_selector_recognizes_only_declared_algorithms() {
    let code = kani::any::<i32>();
    let result = JwsAlgorithm::try_from(EnumValue::<JoseSignatureAlgorithm>::from(code));
    match code {
        100 => kani::assert(
            result == Ok(JwsAlgorithm::Eddsa),
            "the EdDSA wire value selects EdDSA",
        ),
        200 => kani::assert(
            result == Ok(JwsAlgorithm::Es256),
            "the ES256 wire value selects ES256",
        ),
        _ => kani::assert(
            result.is_err_and(|error| {
                error.branch() == JoseWireErrorBranch::Provider
                    && error.reason() == JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED
            }),
            "all unspecified, reserved, and unknown signature selectors fail closed",
        ),
    }
    kani::cover!(result == Ok(JwsAlgorithm::Eddsa), "EdDSA accepted");
    kani::cover!(result == Ok(JwsAlgorithm::Es256), "ES256 accepted");
    kani::cover!(code == 0 && result.is_err(), "unspecified rejected");
    kani::cover!(
        code < 0 && result.is_err(),
        "unknown negative selector rejected"
    );
}
