// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// Derived from the protobuf contract. Change the schema and regenerate.

use reallyme_jose::api::contract::JoseTransportStatus as Contract;

/// Closed native view of the schema's JoseTransportStatus selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JoseFfiStatus {
    /// Schema-defined Success identity.
    Success,
    /// Schema-defined CallerError identity.
    CallerError,
    /// Schema-defined ProviderError identity.
    ProviderError,
    /// Schema-defined BackendError identity.
    BackendError,
    /// Schema-defined PanicCaught identity.
    PanicCaught,
    /// Schema-defined OutputCapacityMismatch identity.
    OutputCapacityMismatch,
    /// Schema-defined UnsupportedAbi identity.
    UnsupportedAbi,
}

impl TryFrom<buffa::EnumValue<reallyme_jose::api::contract::JoseTransportStatus>>
    for JoseFfiStatus
{
    type Error = Self;
    fn try_from(value: buffa::EnumValue<Contract>) -> Result<Self, Self::Error> {
        match value.as_known() {
            Some(Contract::JOSE_TRANSPORT_STATUS_SUCCESS) => Ok(Self::Success),
            Some(Contract::JOSE_TRANSPORT_STATUS_CALLER_ERROR) => Ok(Self::CallerError),
            Some(Contract::JOSE_TRANSPORT_STATUS_PROVIDER_ERROR) => Ok(Self::ProviderError),
            Some(Contract::JOSE_TRANSPORT_STATUS_BACKEND_ERROR) => Ok(Self::BackendError),
            Some(Contract::JOSE_TRANSPORT_STATUS_PANIC_CAUGHT) => Ok(Self::PanicCaught),
            Some(Contract::JOSE_TRANSPORT_STATUS_OUTPUT_CAPACITY_MISMATCH) => {
                Ok(Self::OutputCapacityMismatch)
            }
            Some(Contract::JOSE_TRANSPORT_STATUS_UNSUPPORTED_ABI) => Ok(Self::UnsupportedAbi),
            _ => Err(Self::CallerError),
        }
    }
}

impl From<JoseFfiStatus> for Contract {
    fn from(value: JoseFfiStatus) -> Self {
        match value {
            JoseFfiStatus::Success => Self::JOSE_TRANSPORT_STATUS_SUCCESS,
            JoseFfiStatus::CallerError => Self::JOSE_TRANSPORT_STATUS_CALLER_ERROR,
            JoseFfiStatus::ProviderError => Self::JOSE_TRANSPORT_STATUS_PROVIDER_ERROR,
            JoseFfiStatus::BackendError => Self::JOSE_TRANSPORT_STATUS_BACKEND_ERROR,
            JoseFfiStatus::PanicCaught => Self::JOSE_TRANSPORT_STATUS_PANIC_CAUGHT,
            JoseFfiStatus::OutputCapacityMismatch => {
                Self::JOSE_TRANSPORT_STATUS_OUTPUT_CAPACITY_MISMATCH
            }
            JoseFfiStatus::UnsupportedAbi => Self::JOSE_TRANSPORT_STATUS_UNSUPPORTED_ABI,
        }
    }
}

impl JoseFfiStatus {
    /// Returns the schema-defined code.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::CallerError => -1,
            Self::ProviderError => -2,
            Self::BackendError => -3,
            Self::PanicCaught => -4,
            Self::OutputCapacityMismatch => -5,
            Self::UnsupportedAbi => -6,
        }
    }
}

#[cfg(test)]
#[path = "jose_ffi_status_tests.rs"]
mod tests;
