// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::EnumValue;
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    JoseErrorReason, JoseSignatureAlgorithm,
};

use crate::jws::parse_header::JwsAlgorithm;
use crate::wire::{JoseWireError, JoseWireResult};

pub(super) fn select_signature_algorithm(
    value: EnumValue<JoseSignatureAlgorithm>,
) -> JoseWireResult<JwsAlgorithm> {
    use JoseSignatureAlgorithm::{
        JOSE_SIGNATURE_ALGORITHM_EDDSA, JOSE_SIGNATURE_ALGORITHM_ES256,
        JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED,
    };

    match value.as_known() {
        Some(JOSE_SIGNATURE_ALGORITHM_EDDSA) => Ok(JwsAlgorithm::Eddsa),
        Some(JOSE_SIGNATURE_ALGORITHM_ES256) => Ok(JwsAlgorithm::Es256),
        Some(JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED) | None => Err(JoseWireError::provider_internal(
            JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
        )),
    }
}

#[cfg(kani)]
#[path = "signature_selector_proofs.rs"]
mod proofs;
