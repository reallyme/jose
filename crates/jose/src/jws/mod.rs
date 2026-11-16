// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON Web Signature support.

mod authenticated;
pub(crate) mod parse_compact;
pub(crate) mod parse_header;
mod provider;
pub(crate) mod sign;
pub(crate) mod sign_p256;
pub mod suites;
pub(crate) mod verify;
pub(crate) mod verify_p256;

pub use crate::generated_contract::ExternalJwsAlgorithm;
pub use authenticated::AuthenticatedCompactJws;
pub use parse_compact::MAX_COMPACT_JWS_BYTES;
pub use provider::{
    compact_jws_signing_parts, external_jws_algorithm, inspect_compact_jws,
    sign_compact_jws_with_provider, verify_compact_jws_with_provider,
};
