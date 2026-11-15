// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use crate::api::contract::JoseErrorBranch as Contract;

/// Closed native view of the schema's JoseErrorBranch selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JoseWireErrorBranch {
    /// Schema-defined Primitive identity.
    Primitive,
    /// Schema-defined Provider identity.
    Provider,
    /// Schema-defined Backend identity.
    Backend,
}

impl TryFrom<buffa::EnumValue<crate::api::contract::JoseErrorBranch>> for JoseWireErrorBranch {
    type Error = crate::wire::JoseWireError;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_ERROR_BRANCH_PRIMITIVE) => Ok(Self::Primitive),
            Some(Contract::JOSE_ERROR_BRANCH_PROVIDER) => Ok(Self::Provider),
            Some(Contract::JOSE_ERROR_BRANCH_BACKEND) => Ok(Self::Backend),
            _ => Err(crate::wire::JoseWireError::backend_internal(
                crate::api::contract::JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL,
            )),
        }
    }
}

impl From<JoseWireErrorBranch> for Contract {
    fn from(value: JoseWireErrorBranch) -> Self {
        match value {
            JoseWireErrorBranch::Primitive => Self::JOSE_ERROR_BRANCH_PRIMITIVE,
            JoseWireErrorBranch::Provider => Self::JOSE_ERROR_BRANCH_PROVIDER,
            JoseWireErrorBranch::Backend => Self::JOSE_ERROR_BRANCH_BACKEND,
        }
    }
}

#[cfg(test)]
#[path = "jose_wire_error_branch_tests.rs"]
mod tests;
