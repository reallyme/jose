// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Borrowed JWK member views and RFC 7638 SHA-256 thumbprints.

mod borrow_contract_members;
mod borrow_json_members;
mod encode_required_members;
mod error;
mod thumbprint_sha256;

pub use borrow_json_members::thumbprint_sha256_from_json;
pub use error::JwkThumbprintErrorReason;
pub(crate) use thumbprint_sha256::SHA256_DIGEST_BYTES;
pub use thumbprint_sha256::{
    thumbprint_sha256, JwkThumbprintMembers, MAX_JWK_THUMBPRINT_MEMBER_BYTES,
};

#[cfg(test)]
mod tests;
