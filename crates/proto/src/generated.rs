// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generated Buffa code boundary.

#[path = "generated/package.rs"]
mod package;
pub use package::JOSE_PROTO_PACKAGE;

/// Limits and reason classifications derived from the protobuf schema.
#[cfg(feature = "generated")]
#[path = "generated/contract_values.rs"]
pub mod contract_values;

/// Generated Buffa protobuf message and view types.
#[allow(
    missing_docs,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::must_use_candidate
)]
#[cfg(feature = "generated")]
#[path = "generated/buffa/mod.rs"]
pub mod proto;
