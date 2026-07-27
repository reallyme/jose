// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Protobuf boundary helpers for JOSE operations.
//!
//! The native Rust APIs in `jws`, `jwt`, and `jwe` stay ergonomic and use
//! Rust-native inputs. This module provides the parallel wire layer for RPC,
//! FFI, SDK, and conformance boundaries: protobuf requests in, protobuf result
//! bytes or structured `JoseError` protobuf bytes out. It intentionally does
//! not define or run an RPC service.

mod operation_response;

use buffa::{DecodeOptions, EnumValue, Enumeration, Message};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    __buffa::oneof::jose_error::Error as JoseErrorBranchProto, JoseBackendError, JoseError,
    JoseErrorReason, JosePrimitiveError, JoseProviderError,
};
use serde::de::DeserializeOwned;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::reject_duplicate_json_members::reject_duplicate_json_members;

pub use operation_response::{
    decode_operation_response_v1, execute_operation_json_v1, execute_operation_request,
    execute_operation_v1, JoseOperationKind,
};

const MAX_JOSE_WIRE_BYTES: usize = 1024 * 1024;
const JOSE_PROTO_RECURSION_LIMIT: u32 = 64;
const JOSE_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;
/// Maximum protobuf framing overhead above one bounded operation result.
pub const MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES: usize = 32;

/// Maximum accepted protobuf message size at the JOSE wire boundary.
pub const MAX_JOSE_PROTO_MESSAGE_BYTES: usize = MAX_JOSE_WIRE_BYTES;

/// Maximum accepted ProtoJSON message size at the JOSE wire boundary.
pub const MAX_JOSE_PROTO_JSON_BYTES: usize = 1_572_864;

/// Typed wire-boundary error branch.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum JoseWireErrorBranch {
    /// Caller-owned input, JOSE primitive, or policy failure.
    Primitive,
    /// Provider selection or availability failure.
    Provider,
    /// Output serialization, cryptographic backend, or internal failure.
    Backend,
}

/// Typed wire-boundary error preserving both branch and exact reason.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[error("JOSE wire boundary error")]
pub struct JoseWireError {
    branch: JoseWireErrorBranch,
    reason: JoseErrorReason,
}

/// Error returned when a reason is assigned to the wrong public error branch.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum JoseWireErrorConstructionError {
    /// The reason belongs to a different branch or is unspecified.
    #[error("JOSE error reason does not belong to the selected branch")]
    BranchReasonMismatch,
}

impl JoseWireError {
    /// Returns the stable error branch.
    #[must_use]
    pub const fn branch(self) -> JoseWireErrorBranch {
        self.branch
    }

    /// Returns the exact stable reason.
    #[must_use]
    pub const fn reason(self) -> JoseErrorReason {
        self.reason
    }

    /// Constructs a public wire error only when branch and reason agree.
    ///
    /// # Errors
    ///
    /// Returns [`JoseWireErrorConstructionError::BranchReasonMismatch`] for an
    /// unspecified reason or a reason owned by another branch.
    pub fn try_new(
        branch: JoseWireErrorBranch,
        reason: JoseErrorReason,
    ) -> Result<Self, JoseWireErrorConstructionError> {
        if !reason_is_valid_for_branch(branch, reason) {
            return Err(JoseWireErrorConstructionError::BranchReasonMismatch);
        }
        Ok(Self { branch, reason })
    }

    pub(crate) const fn primitive_internal(reason: JoseErrorReason) -> Self {
        Self {
            branch: JoseWireErrorBranch::Primitive,
            reason,
        }
    }

    pub(crate) const fn provider_internal(reason: JoseErrorReason) -> Self {
        Self {
            branch: JoseWireErrorBranch::Provider,
            reason,
        }
    }

    pub(crate) const fn backend_internal(reason: JoseErrorReason) -> Self {
        Self {
            branch: JoseWireErrorBranch::Backend,
            reason,
        }
    }
}

/// Result alias for the JOSE protobuf boundary.
pub type JoseWireResult<T> = Result<T, JoseWireError>;

/// Re-export of the generated protobuf boundary.
pub mod proto {
    pub use reallyme_jose_proto::generated::proto;
    pub use reallyme_jose_proto::generated::JOSE_PROTO_PACKAGE;
}

/// Encodes a protobuf message with Buffa.
#[must_use]
pub fn encode_protobuf<M: Message>(message: &M) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(message.encode_to_vec())
}

/// Decodes a bounded protobuf message from untrusted bytes.
///
/// # Errors
///
/// Returns [`JoseWireError`] with a primitive branch when caller input exceeds
/// the boundary size limit or cannot be decoded as the requested message.
pub fn decode_protobuf<M: Message>(bytes: &[u8]) -> JoseWireResult<M> {
    decode_protobuf_with_limit(bytes, MAX_JOSE_PROTO_MESSAGE_BYTES)
}

fn decode_protobuf_with_limit<M: Message>(bytes: &[u8], max_bytes: usize) -> JoseWireResult<M> {
    if bytes.len() > max_bytes {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED,
        ));
    }

    DecodeOptions::new()
        .with_recursion_limit(JOSE_PROTO_RECURSION_LIMIT)
        .with_max_message_size(max_bytes)
        .with_unknown_field_limit(JOSE_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(bytes)
        .map_err(|_| {
            JoseWireError::primitive_internal(
                JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF,
            )
        })
}

/// Encodes a generated protobuf message as proto3-compatible JSON bytes.
///
/// # Errors
///
/// Returns [`JoseWireError`] with a backend branch if JSON serialization fails.
pub fn encode_json<M: serde::Serialize>(message: &M) -> JoseWireResult<Zeroizing<Vec<u8>>> {
    serde_json::to_vec(message)
        .map(Zeroizing::new)
        .map_err(|_| {
            JoseWireError::backend_internal(
                JoseErrorReason::JOSE_ERROR_REASON_BACKEND_JSON_SERIALIZATION,
            )
        })
}

/// Decodes a generated protobuf message from proto3-compatible JSON bytes.
///
/// # Errors
///
/// Returns [`JoseWireError`] with a primitive branch when caller JSON exceeds
/// the boundary limit or cannot be decoded as the requested message.
pub fn decode_json<M: DeserializeOwned + Message>(bytes: &[u8]) -> JoseWireResult<M> {
    if bytes.len() > MAX_JOSE_PROTO_JSON_BYTES {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED,
        ));
    }

    reject_duplicate_json_members(bytes).map_err(|_| {
        JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_JSON)
    })?;

    let message: M = serde_json::from_slice(bytes).map_err(|_| {
        JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_JSON)
    })?;
    let encoded = encode_protobuf(&message);
    if encoded.len() > MAX_JOSE_PROTO_MESSAGE_BYTES {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED,
        ));
    }
    Ok(message)
}

/// Builds the structured `JoseError` protobuf message for a boundary error.
#[must_use]
pub fn jose_error(error: JoseWireError) -> JoseError {
    let reason = EnumValue::from(error.reason());
    let branch = match error.branch() {
        JoseWireErrorBranch::Primitive => {
            JoseErrorBranchProto::Primitive(Box::new(JosePrimitiveError {
                reason,
                __buffa_unknown_fields: Default::default(),
            }))
        }
        JoseWireErrorBranch::Provider => {
            JoseErrorBranchProto::Provider(Box::new(JoseProviderError {
                reason,
                __buffa_unknown_fields: Default::default(),
            }))
        }
        JoseWireErrorBranch::Backend => JoseErrorBranchProto::Backend(Box::new(JoseBackendError {
            reason,
            __buffa_unknown_fields: Default::default(),
        })),
    };

    JoseError {
        error: Some(branch),
        __buffa_unknown_fields: Default::default(),
    }
}

/// Encodes a structured `JoseError` as protobuf bytes.
#[must_use]
pub fn jose_error_bytes(error: JoseWireError) -> Zeroizing<Vec<u8>> {
    encode_protobuf(&jose_error(error))
}

pub(super) fn validate_jose_error(error: &JoseError) -> JoseWireResult<()> {
    let (branch, reason) = match &error.error {
        Some(JoseErrorBranchProto::Primitive(error)) => {
            (JoseWireErrorBranch::Primitive, error.reason)
        }
        Some(JoseErrorBranchProto::Provider(error)) => {
            (JoseWireErrorBranch::Provider, error.reason)
        }
        Some(JoseErrorBranchProto::Backend(error)) => (JoseWireErrorBranch::Backend, error.reason),
        None => {
            return Err(JoseWireError::primitive_internal(
                JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF,
            ));
        }
    };

    match reason.as_known() {
        Some(reason) if reason_is_valid_for_branch(branch, reason) => Ok(()),
        Some(JoseErrorReason::JOSE_ERROR_REASON_UNSPECIFIED) | Some(_) | None => {
            Err(JoseWireError::primitive_internal(
                JoseErrorReason::JOSE_ERROR_REASON_COMMON_MALFORMED_PROTOBUF,
            ))
        }
    }
}

fn reason_is_valid_for_branch(branch: JoseWireErrorBranch, reason: JoseErrorReason) -> bool {
    match branch {
        JoseWireErrorBranch::Primitive => {
            let value = reason.to_i32();
            (100..=399).contains(&value) || (700..=703).contains(&value)
        }
        JoseWireErrorBranch::Provider => (800..=802).contains(&reason.to_i32()),
        JoseWireErrorBranch::Backend => (900..=902).contains(&reason.to_i32()),
    }
}
