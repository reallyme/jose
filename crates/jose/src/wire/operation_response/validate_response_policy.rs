// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::EnumValue;

use crate::api::contract::{JoseError, JoseOperationContractVersion};
use crate::wire::{validate_jose_error, JoseWireResult};

use super::{backend_output_error, JoseOperationKind};

pub(super) fn validate_contract_version(
    version: EnumValue<JoseOperationContractVersion>,
) -> JoseWireResult<()> {
    if version.as_known() == Some(JoseOperationContractVersion::JOSE_OPERATION_CONTRACT_VERSION_V2)
    {
        Ok(())
    } else {
        Err(backend_output_error())
    }
}

pub(super) fn require_operation(
    actual: JoseOperationKind,
    expected: JoseOperationKind,
) -> JoseWireResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(backend_output_error())
    }
}

pub(super) fn validate_response_error(error: &JoseError) -> JoseWireResult<()> {
    validate_jose_error(error).map_err(|_| backend_output_error())
}
