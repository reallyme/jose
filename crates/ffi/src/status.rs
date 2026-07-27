// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Stable transport status values for the JOSE C ABI.

/// Status returned by non-leaf JOSE C ABI functions.
///
/// Operation-specific primitive, provider, and backend failures are encoded in
/// `JoseOperationResponse`; these values describe failures of the C boundary
/// itself. Reserved semantic classes keep the ABI extensible without exposing
/// backend text or collapsing the generated typed response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JoseFfiStatus {
    /// The boundary produced a complete canonical response.
    Success,
    /// A pointer, length, alias, or pre-copy input bound was invalid.
    CallerError,
    /// Reserved for a future platform-provider transport failure.
    ProviderError,
    /// The boundary could not safely represent provider output.
    BackendError,
    /// A panic was caught before it could cross the native boundary.
    PanicCaught,
    /// The output buffer is too small; `len_out` contains the exact requirement.
    OutputCapacityMismatch,
    /// The caller requested an unsupported ABI version.
    UnsupportedAbi,
}

impl JoseFfiStatus {
    /// Returns the frozen signed C representation.
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
