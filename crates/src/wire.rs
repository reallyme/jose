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

use core::str;

use buffa::{DecodeOptions, EnumValue, Enumeration, Message};
use reallyme_jose_proto::generated::proto::reallyme::jose::v1::{
    __buffa::oneof::{
        jose_error::Error as JoseErrorBranchProto,
        jose_operation_request::Operation as JoseOperation,
    },
    JoseBackendError, JoseCompactResult, JoseError, JoseErrorReason,
    JoseJweContentEncryptionAlgorithm, JoseJweDecryptRequest, JoseJweEncryptRequest,
    JoseJweKeyManagementAlgorithm, JoseJwePlaintextResult, JoseJwsSignRequest,
    JoseJwsVerifyRequest, JoseJwtClaimsResult, JoseJwtDecodeUnsignedRequest,
    JoseJwtEncodeUnsignedRequest, JoseJwtSignRequest, JoseJwtTemporalValidationPolicy,
    JoseJwtVerifyRequest, JoseOperationRequest, JosePrimitiveError, JoseProtoResultEnvelope,
    JoseProtoResultStatus, JoseProviderError, JoseSignatureAlgorithm, JoseVerifyResult,
};
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::jwe::{
    decrypt_compact_jwe_bytes, encrypt_compact_jwe_bytes, CompactJweEncryptRequest,
    CompactJwePolicy, DirectJweKeyEncryptor, DirectJweKeyResolver, JweContentEncryptionAlgorithm,
    JweError, JweKeyManagementAlgorithm, P256EcdhEsJweKeyEncryptor, P256EcdhEsJweKeyResolver,
};
#[cfg(feature = "native")]
use crate::jwe::{
    P384EcdhEsJweKeyEncryptor, P384EcdhEsJweKeyResolver, P521EcdhEsJweKeyEncryptor,
    P521EcdhEsJweKeyResolver,
};
use crate::jws::suites::{
    eddsa::{sign_eddsa_jws, verify_eddsa_jws, JwsEddsaError},
    es256::{sign_es256_jws, verify_es256_jws, JwsEs256Error},
};
use crate::jwt::{
    decode_unsigned_jwt_claims_json,
    decode_verify_jwt_claims_json_signature_only_with_header_validation,
    decode_verify_jwt_claims_json_with_temporal_validation_and_header_validation, JwtError,
    JwtHeaderEncodeOptions, JwtHeaderValidationOptions, JwtTemporalValidationPolicy,
};
use crate::jwt::{
    encode_signed_jwt_claims_json, encode_unsigned_jwt_claims_json, reject_duplicate_object_members,
};
use crate::{Jwk, SecureRandom};

const MAX_JOSE_WIRE_BYTES: usize = 1024 * 1024;
const JOSE_PROTO_RECURSION_LIMIT: u32 = 64;
const MAX_JOSE_PROTO_ENVELOPE_OVERHEAD_BYTES: usize = 32;

/// Maximum accepted protobuf message size at the JOSE wire boundary.
pub const MAX_JOSE_PROTO_MESSAGE_BYTES: usize = MAX_JOSE_WIRE_BYTES;

/// Maximum accepted JSON result-envelope size at the JOSE wire boundary.
pub const MAX_JOSE_PROTO_JSON_BYTES: usize = 1_572_864;

/// Status for a protobuf-facing JOSE operation result.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum JoseProtoStatus {
    /// Payload contains the operation-specific result protobuf message.
    Result,
    /// Payload contains a structured `JoseError` protobuf message.
    JoseError,
}

/// Result envelope used by protobuf-facing JOSE operations.
pub struct JoseProtoOutput {
    status: JoseProtoStatus,
    bytes: Zeroizing<Vec<u8>>,
}

impl JoseProtoOutput {
    /// Construct an envelope carrying successful result bytes.
    #[must_use]
    pub fn result(bytes: Vec<u8>) -> Self {
        Self {
            status: JoseProtoStatus::Result,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Construct an envelope carrying structured error bytes.
    #[must_use]
    pub fn jose_error(bytes: Vec<u8>) -> Self {
        Self {
            status: JoseProtoStatus::JoseError,
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Return whether this envelope contains result or error protobuf bytes.
    #[must_use]
    pub const fn status(&self) -> JoseProtoStatus {
        self.status
    }

    /// Borrow the protobuf bytes carried by this envelope.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Borrow the protobuf payload carried by this envelope.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the envelope and return zeroizing protobuf bytes.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

/// Typed wire-boundary error branch.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum JoseWireErrorBranch {
    /// Caller-owned input, JOSE primitive, or policy failure.
    Primitive,
    /// Provider selection or availability failure.
    Provider,
    /// Backend, serialization, protobuf, or internal failure.
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

    const fn primitive_internal(reason: JoseErrorReason) -> Self {
        Self {
            branch: JoseWireErrorBranch::Primitive,
            reason,
        }
    }

    const fn provider_internal(reason: JoseErrorReason) -> Self {
        Self {
            branch: JoseWireErrorBranch::Provider,
            reason,
        }
    }

    const fn backend_internal(reason: JoseErrorReason) -> Self {
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
/// Returns [`JoseWireError`] with a backend branch when input exceeds the
/// boundary size limit or cannot be decoded as the requested protobuf message.
pub fn decode_protobuf<M: Message>(bytes: &[u8]) -> JoseWireResult<M> {
    decode_protobuf_with_limit(bytes, MAX_JOSE_PROTO_MESSAGE_BYTES)
}

fn decode_protobuf_with_limit<M: Message>(bytes: &[u8], max_bytes: usize) -> JoseWireResult<M> {
    if bytes.len() > max_bytes {
        return Err(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        ));
    }

    DecodeOptions::new()
        .with_recursion_limit(JOSE_PROTO_RECURSION_LIMIT)
        .with_max_message_size(max_bytes)
        .decode_from_slice(bytes)
        .map_err(|_| {
            JoseWireError::backend_internal(
                JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF,
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
/// Returns [`JoseWireError`] with a backend branch when the JSON input exceeds
/// the boundary limit or cannot be decoded as the requested message.
pub fn decode_json<M: DeserializeOwned + Message>(bytes: &[u8]) -> JoseWireResult<M> {
    if bytes.len() > MAX_JOSE_PROTO_JSON_BYTES {
        return Err(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        ));
    }

    let message: M = serde_json::from_slice(bytes).map_err(|_| {
        JoseWireError::backend_internal(JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_JSON)
    })?;
    let encoded = encode_protobuf(&message);
    if encoded.len() > MAX_JOSE_PROTO_MESSAGE_BYTES {
        return Err(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
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

/// Wraps a boundary error as a protobuf-facing output object.
#[must_use]
pub fn jose_error_output(error: JoseWireError) -> JoseProtoOutput {
    JoseProtoOutput {
        status: JoseProtoStatus::JoseError,
        bytes: jose_error_bytes(error),
    }
}

/// Serialize a result envelope using the generated proto JSON mapping.
///
/// # Errors
///
/// Returns a structured [`JoseProtoOutput`] error when the envelope exceeds
/// wire limits or JSON serialization fails.
pub fn jose_proto_output_to_json(
    output: &JoseProtoOutput,
) -> Result<Zeroizing<String>, JoseProtoOutput> {
    if output.bytes.len() > MAX_JOSE_PROTO_MESSAGE_BYTES {
        return Err(jose_error_output(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        )));
    }

    let mut envelope = proto_result_envelope_from_output(output);
    let result = serde_json::to_string(&envelope).map_err(|_| {
        jose_error_output(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_JSON_SERIALIZATION,
        ))
    });
    envelope.payload.zeroize();

    let json = result?;
    if json.len() > MAX_JOSE_PROTO_JSON_BYTES {
        return Err(jose_error_output(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        )));
    }
    Ok(Zeroizing::new(json))
}

/// Decode a JSON result envelope produced by [`jose_proto_output_to_json`].
///
/// # Errors
///
/// Returns a structured [`JoseProtoOutput`] error when the JSON envelope is
/// malformed or exceeds the configured wire limits.
pub fn jose_proto_output_from_json(json: &str) -> Result<JoseProtoOutput, JoseProtoOutput> {
    if json.len() > MAX_JOSE_PROTO_JSON_BYTES {
        return Err(jose_error_output(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        )));
    }

    let decoded: JoseProtoResultEnvelope = serde_json::from_str(json).map_err(|_| {
        jose_error_output(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_JSON,
        ))
    })?;
    output_from_proto_result_envelope(decoded)
}

/// Wraps successful result protobuf bytes in the transport-neutral envelope.
///
/// # Errors
///
/// Returns a resource-limit error output when the result payload or encoded
/// envelope exceeds the configured wire limits.
pub fn result_envelope_bytes(result_bytes: Vec<u8>) -> Result<Zeroizing<Vec<u8>>, JoseProtoOutput> {
    encode_proto_result_envelope(&JoseProtoOutput::result(result_bytes))
}

/// Wraps structured `JoseError` protobuf bytes in the transport-neutral envelope.
#[must_use]
pub fn error_envelope_bytes(error: JoseWireError) -> Zeroizing<Vec<u8>> {
    encode_proto_result_envelope_unchecked(&jose_error_output(error))
}

/// Encode a protobuf result envelope carrying result bytes or `JoseError` bytes.
///
/// # Errors
///
/// Returns a structured [`JoseProtoOutput`] error when the result payload or
/// encoded envelope would exceed the configured wire limits.
pub fn encode_proto_result_envelope(
    output: &JoseProtoOutput,
) -> Result<Zeroizing<Vec<u8>>, JoseProtoOutput> {
    if output.bytes.len() > MAX_JOSE_PROTO_MESSAGE_BYTES {
        return Err(jose_error_output(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        )));
    }

    let encoded = encode_proto_result_envelope_unchecked(output);
    if encoded.len() > max_jose_proto_envelope_bytes()? {
        return Err(jose_error_output(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        )));
    }
    Ok(encoded)
}

/// Decode a protobuf result envelope produced by [`process_proto`].
///
/// # Errors
///
/// Returns a structured [`JoseProtoOutput`] error when the envelope is
/// malformed or exceeds the configured wire limits.
pub fn decode_proto_result_envelope(bytes: &[u8]) -> Result<JoseProtoOutput, JoseProtoOutput> {
    if bytes.len() > max_jose_proto_envelope_bytes()? {
        return Err(jose_error_output(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        )));
    }

    let envelope = decode_protobuf_with_limit::<JoseProtoResultEnvelope>(
        bytes,
        max_jose_proto_envelope_bytes()?,
    )
    .map_err(jose_error_output)?;
    output_from_proto_result_envelope(envelope)
}

fn output_from_proto_result_envelope(
    mut envelope: JoseProtoResultEnvelope,
) -> Result<JoseProtoOutput, JoseProtoOutput> {
    if envelope.payload.len() > MAX_JOSE_PROTO_MESSAGE_BYTES {
        envelope.payload.zeroize();
        return Err(jose_error_output(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_RESOURCE_LIMIT_EXCEEDED,
        )));
    }
    let status = match envelope.status.as_known() {
        Some(JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_RESULT) => JoseProtoStatus::Result,
        Some(JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR) => {
            if validate_jose_error_payload(&envelope.payload).is_err() {
                envelope.payload.zeroize();
                return Err(jose_error_output(JoseWireError::backend_internal(
                    JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF,
                )));
            }
            JoseProtoStatus::JoseError
        }
        Some(JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_UNSPECIFIED) | None => {
            envelope.payload.zeroize();
            return Err(jose_error_output(JoseWireError::backend_internal(
                JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF,
            )));
        }
    };

    let bytes = core::mem::take(&mut envelope.payload);
    Ok(JoseProtoOutput {
        status,
        bytes: Zeroizing::new(bytes),
    })
}

fn validate_jose_error_payload(payload: &[u8]) -> JoseWireResult<()> {
    let error = decode_protobuf::<JoseError>(payload)?;
    let (branch, reason) = match error.error {
        Some(JoseErrorBranchProto::Primitive(error)) => {
            (JoseWireErrorBranch::Primitive, error.reason)
        }
        Some(JoseErrorBranchProto::Provider(error)) => {
            (JoseWireErrorBranch::Provider, error.reason)
        }
        Some(JoseErrorBranchProto::Backend(error)) => (JoseWireErrorBranch::Backend, error.reason),
        None => {
            return Err(JoseWireError::backend_internal(
                JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF,
            ));
        }
    };

    match reason.as_known() {
        Some(reason) if reason_is_valid_for_branch(branch, reason) => Ok(()),
        Some(JoseErrorReason::JOSE_ERROR_REASON_UNSPECIFIED) | Some(_) | None => {
            Err(JoseWireError::backend_internal(
                JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MALFORMED_PROTOBUF,
            ))
        }
    }
}

fn reason_is_valid_for_branch(branch: JoseWireErrorBranch, reason: JoseErrorReason) -> bool {
    let value = reason.to_i32();
    match branch {
        JoseWireErrorBranch::Primitive => (1..=63).contains(&value),
        JoseWireErrorBranch::Provider => (64..=66).contains(&value),
        JoseWireErrorBranch::Backend => (67..=73).contains(&value),
    }
}

fn encode_proto_result_envelope_unchecked(output: &JoseProtoOutput) -> Zeroizing<Vec<u8>> {
    let mut envelope = proto_result_envelope_from_output(output);
    let bytes = encode_protobuf(&envelope);
    envelope.payload.zeroize();
    bytes
}

fn proto_result_envelope_from_output(output: &JoseProtoOutput) -> JoseProtoResultEnvelope {
    let status = match output.status {
        JoseProtoStatus::Result => JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_RESULT,
        JoseProtoStatus::JoseError => JoseProtoResultStatus::JOSE_PROTO_RESULT_STATUS_JOSE_ERROR,
    };
    JoseProtoResultEnvelope {
        status: EnumValue::from(status),
        payload: output.bytes.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn max_jose_proto_envelope_bytes() -> Result<usize, JoseProtoOutput> {
    MAX_JOSE_PROTO_MESSAGE_BYTES
        .checked_add(MAX_JOSE_PROTO_ENVELOPE_OVERHEAD_BYTES)
        .ok_or_else(|| {
            jose_error_output(JoseWireError::backend_internal(
                JoseErrorReason::JOSE_ERROR_REASON_BACKEND_INTERNAL,
            ))
        })
}

fn output_from_result(result: JoseWireResult<Vec<u8>>) -> JoseProtoOutput {
    match result {
        Ok(bytes) => JoseProtoOutput::result(bytes),
        Err(error) => jose_error_output(error),
    }
}

fn take_zeroizing_vec(mut bytes: Zeroizing<Vec<u8>>) -> Vec<u8> {
    core::mem::take(&mut *bytes)
}

fn envelope_from_result(result: JoseWireResult<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    encode_output_or_error(&output_from_result(result))
}

fn encode_output_or_error(output: &JoseProtoOutput) -> Zeroizing<Vec<u8>> {
    match encode_proto_result_envelope(output) {
        Ok(bytes) => bytes,
        Err(error_output) => encode_proto_result_envelope_unchecked(&error_output),
    }
}

/// Executes a generated JOSE operation request and returns a result/error envelope.
#[must_use]
pub fn process_operation<R: SecureRandom + ?Sized>(
    request: JoseOperationRequest,
    rng: &mut R,
) -> Zeroizing<Vec<u8>> {
    encode_output_or_error(&process_operation_output(request, rng))
}

/// Executes a generated JOSE operation request and returns a structured output.
#[must_use]
pub fn process_operation_output<R: SecureRandom + ?Sized>(
    request: JoseOperationRequest,
    rng: &mut R,
) -> JoseProtoOutput {
    output_from_result(process_operation_result_bytes(request, rng))
}

/// Decodes and executes the single binary protobuf JOSE operation entrypoint.
#[must_use]
pub fn process_proto<R: SecureRandom + ?Sized>(
    request_bytes: &[u8],
    rng: &mut R,
) -> Zeroizing<Vec<u8>> {
    encode_output_or_error(&process_proto_output(request_bytes, rng))
}

/// Decodes and executes the single binary protobuf JOSE operation entrypoint.
#[must_use]
pub fn process_proto_output<R: SecureRandom + ?Sized>(
    request_bytes: &[u8],
    rng: &mut R,
) -> JoseProtoOutput {
    output_from_result(
        decode_protobuf(request_bytes)
            .and_then(|request| process_operation_result_bytes(request, rng)),
    )
}

/// Decodes and executes the single JSON protobuf JOSE operation entrypoint.
#[must_use]
pub fn process_json<R: SecureRandom + ?Sized>(
    request_json: &[u8],
    rng: &mut R,
) -> Zeroizing<Vec<u8>> {
    encode_output_or_error(&process_json_output(request_json, rng))
}

/// Decodes and executes the single JSON protobuf JOSE operation entrypoint.
#[must_use]
pub fn process_json_output<R: SecureRandom + ?Sized>(
    request_json: &[u8],
    rng: &mut R,
) -> JoseProtoOutput {
    output_from_result(
        decode_json(request_json).and_then(|request| process_operation_result_bytes(request, rng)),
    )
}

/// Executes a JWS signing request and returns a result/error envelope.
#[must_use]
pub fn sign_jws_envelope(request: JoseJwsSignRequest) -> Zeroizing<Vec<u8>> {
    envelope_from_result(sign_jws_result_bytes(request))
}

/// Decodes and executes a binary protobuf JWS signing request.
#[must_use]
pub fn sign_jws_envelope_from_protobuf(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_protobuf(request_bytes).and_then(sign_jws_result_bytes))
}

/// Decodes and executes a JSON protobuf JWS signing request.
#[must_use]
pub fn sign_jws_envelope_from_json(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_json(request_json).and_then(sign_jws_result_bytes))
}

/// Executes a JWS verification request and returns a result/error envelope.
#[must_use]
pub fn verify_jws_envelope(request: JoseJwsVerifyRequest) -> Zeroizing<Vec<u8>> {
    envelope_from_result(verify_jws_result_bytes(request))
}

/// Decodes and executes a binary protobuf JWS verification request.
#[must_use]
pub fn verify_jws_envelope_from_protobuf(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_protobuf(request_bytes).and_then(verify_jws_result_bytes))
}

/// Decodes and executes a JSON protobuf JWS verification request.
#[must_use]
pub fn verify_jws_envelope_from_json(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_json(request_json).and_then(verify_jws_result_bytes))
}

/// Executes an unsigned-JWT encode request and returns a result/error envelope.
#[must_use]
pub fn encode_unsigned_jwt_envelope(request: JoseJwtEncodeUnsignedRequest) -> Zeroizing<Vec<u8>> {
    envelope_from_result(encode_unsigned_jwt_result_bytes(request))
}

/// Decodes and executes a binary protobuf unsigned-JWT encode request.
#[must_use]
pub fn encode_unsigned_jwt_envelope_from_protobuf(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_protobuf(request_bytes).and_then(encode_unsigned_jwt_result_bytes))
}

/// Decodes and executes a JSON protobuf unsigned-JWT encode request.
#[must_use]
pub fn encode_unsigned_jwt_envelope_from_json(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_json(request_json).and_then(encode_unsigned_jwt_result_bytes))
}

/// Executes an unsigned-JWT decode request and returns a result/error envelope.
#[must_use]
pub fn decode_unsigned_jwt_envelope(request: JoseJwtDecodeUnsignedRequest) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_unsigned_jwt_result_bytes(request))
}

/// Decodes and executes a binary protobuf unsigned-JWT decode request.
#[must_use]
pub fn decode_unsigned_jwt_envelope_from_protobuf(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_protobuf(request_bytes).and_then(decode_unsigned_jwt_result_bytes))
}

/// Decodes and executes a JSON protobuf unsigned-JWT decode request.
#[must_use]
pub fn decode_unsigned_jwt_envelope_from_json(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_json(request_json).and_then(decode_unsigned_jwt_result_bytes))
}

/// Executes a signed-JWT encode request and returns a result/error envelope.
#[must_use]
pub fn sign_jwt_envelope(request: JoseJwtSignRequest) -> Zeroizing<Vec<u8>> {
    envelope_from_result(sign_jwt_result_bytes(request))
}

/// Decodes and executes a binary protobuf signed-JWT encode request.
#[must_use]
pub fn sign_jwt_envelope_from_protobuf(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_protobuf(request_bytes).and_then(sign_jwt_result_bytes))
}

/// Decodes and executes a JSON protobuf signed-JWT encode request.
#[must_use]
pub fn sign_jwt_envelope_from_json(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_json(request_json).and_then(sign_jwt_result_bytes))
}

/// Executes a signed-JWT verify request and returns a result/error envelope.
#[must_use]
pub fn verify_jwt_envelope(request: JoseJwtVerifyRequest) -> Zeroizing<Vec<u8>> {
    envelope_from_result(verify_jwt_result_bytes(request))
}

/// Decodes and executes a binary protobuf signed-JWT verify request.
#[must_use]
pub fn verify_jwt_envelope_from_protobuf(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_protobuf(request_bytes).and_then(verify_jwt_result_bytes))
}

/// Decodes and executes a JSON protobuf signed-JWT verify request.
#[must_use]
pub fn verify_jwt_envelope_from_json(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_json(request_json).and_then(verify_jwt_result_bytes))
}

/// Executes a compact-JWE encryption request and returns a result/error envelope.
#[must_use]
pub fn encrypt_jwe_envelope<R: SecureRandom + ?Sized>(
    request: JoseJweEncryptRequest,
    rng: &mut R,
) -> Zeroizing<Vec<u8>> {
    envelope_from_result(encrypt_jwe_result_bytes(request, rng))
}

/// Decodes and executes a binary protobuf compact-JWE encryption request.
#[must_use]
pub fn encrypt_jwe_envelope_from_protobuf<R: SecureRandom + ?Sized>(
    request_bytes: &[u8],
    rng: &mut R,
) -> Zeroizing<Vec<u8>> {
    envelope_from_result(
        decode_protobuf(request_bytes).and_then(|request| encrypt_jwe_result_bytes(request, rng)),
    )
}

/// Decodes and executes a JSON protobuf compact-JWE encryption request.
#[must_use]
pub fn encrypt_jwe_envelope_from_json<R: SecureRandom + ?Sized>(
    request_json: &[u8],
    rng: &mut R,
) -> Zeroizing<Vec<u8>> {
    envelope_from_result(
        decode_json(request_json).and_then(|request| encrypt_jwe_result_bytes(request, rng)),
    )
}

/// Executes a compact-JWE decryption request and returns a result/error envelope.
#[must_use]
pub fn decrypt_jwe_envelope(request: JoseJweDecryptRequest) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decrypt_jwe_result_bytes(request))
}

/// Decodes and executes a binary protobuf compact-JWE decryption request.
#[must_use]
pub fn decrypt_jwe_envelope_from_protobuf(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_protobuf(request_bytes).and_then(decrypt_jwe_result_bytes))
}

/// Decodes and executes a JSON protobuf compact-JWE decryption request.
#[must_use]
pub fn decrypt_jwe_envelope_from_json(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    envelope_from_result(decode_json(request_json).and_then(decrypt_jwe_result_bytes))
}

fn process_operation_result_bytes<R: SecureRandom + ?Sized>(
    request: JoseOperationRequest,
    rng: &mut R,
) -> JoseWireResult<Vec<u8>> {
    let Some(operation) = request.operation else {
        return Err(JoseWireError::backend_internal(
            JoseErrorReason::JOSE_ERROR_REASON_BACKEND_MISSING_OPERATION,
        ));
    };

    match operation {
        JoseOperation::JwsSign(request) => sign_jws_result_bytes(*request),
        JoseOperation::JwsVerify(request) => verify_jws_result_bytes(*request),
        JoseOperation::JwtEncodeUnsigned(request) => encode_unsigned_jwt_result_bytes(*request),
        JoseOperation::JwtDecodeUnsigned(request) => decode_unsigned_jwt_result_bytes(*request),
        JoseOperation::JwtSign(request) => sign_jwt_result_bytes(*request),
        JoseOperation::JwtVerify(request) => verify_jwt_result_bytes(*request),
        JoseOperation::JweEncrypt(request) => encrypt_jwe_result_bytes(*request, rng),
        JoseOperation::JweDecrypt(request) => decrypt_jwe_result_bytes(*request),
    }
}

fn sign_jws_result_bytes(mut request: JoseJwsSignRequest) -> JoseWireResult<Vec<u8>> {
    let private_key = Zeroizing::new(core::mem::take(&mut request.private_key));
    let payload_bytes = Zeroizing::new(core::mem::take(&mut request.payload));
    let payload = str::from_utf8(&payload_bytes).map_err(|_| {
        JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_PAYLOAD_UTF8,
        )
    })?;
    let compact = match known_signature_algorithm(request.algorithm)? {
        JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256 => {
            sign_es256_jws(&private_key, payload).map_err(map_jws_es256_error)?
        }
        JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA => {
            sign_eddsa_jws(&private_key, payload).map_err(map_jws_eddsa_error)?
        }
        JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED => {
            return Err(JoseWireError::provider_internal(
                JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            ));
        }
    };

    Ok(take_zeroizing_vec(encode_protobuf(&JoseCompactResult {
        compact,
        __buffa_unknown_fields: Default::default(),
    })))
}

fn verify_jws_result_bytes(mut request: JoseJwsVerifyRequest) -> JoseWireResult<Vec<u8>> {
    let compact = Zeroizing::new(core::mem::take(&mut request.compact));
    match known_signature_algorithm(request.algorithm)? {
        JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_ES256 => {
            verify_es256_jws(&compact, &request.public_key).map_err(map_jws_es256_error)?;
        }
        JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_EDDSA => {
            verify_eddsa_jws(&compact, &request.public_key).map_err(map_jws_eddsa_error)?;
        }
        JoseSignatureAlgorithm::JOSE_SIGNATURE_ALGORITHM_UNSPECIFIED => {
            return Err(JoseWireError::provider_internal(
                JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            ));
        }
    }

    Ok(take_zeroizing_vec(encode_protobuf(&JoseVerifyResult {
        __buffa_unknown_fields: Default::default(),
    })))
}

fn encode_unsigned_jwt_result_bytes(
    mut request: JoseJwtEncodeUnsignedRequest,
) -> JoseWireResult<Vec<u8>> {
    let claims_json = Zeroizing::new(core::mem::take(&mut request.claims_json));
    let compact = encode_unsigned_jwt_claims_json(&claims_json).map_err(map_jwt_error)?;
    Ok(take_zeroizing_vec(encode_protobuf(&JoseCompactResult {
        compact,
        __buffa_unknown_fields: Default::default(),
    })))
}

fn decode_unsigned_jwt_result_bytes(
    mut request: JoseJwtDecodeUnsignedRequest,
) -> JoseWireResult<Vec<u8>> {
    let compact = Zeroizing::new(core::mem::take(&mut request.compact));
    let claims_json = decode_unsigned_jwt_claims_json(&compact).map_err(map_jwt_error)?;
    encode_claims_result(claims_json)
}

fn sign_jwt_result_bytes(mut request: JoseJwtSignRequest) -> JoseWireResult<Vec<u8>> {
    let private_key = Zeroizing::new(core::mem::take(&mut request.private_key));
    let claims_json = Zeroizing::new(core::mem::take(&mut request.claims_json));
    let jwk_json = Zeroizing::new(core::mem::take(&mut request.jwk_json));
    let jwk = jwk_from_json(&jwk_json, JwkOperation::Sign)?;
    let header_options = if request.typ.is_empty() {
        JwtHeaderEncodeOptions::jwt()
    } else {
        JwtHeaderEncodeOptions::new(Some(core::mem::take(&mut request.typ)))
    };
    let compact = encode_signed_jwt_claims_json(&claims_json, &jwk, &private_key, &header_options)
        .map_err(map_jwt_error)?;

    Ok(take_zeroizing_vec(encode_protobuf(&JoseCompactResult {
        compact,
        __buffa_unknown_fields: Default::default(),
    })))
}

fn verify_jwt_result_bytes(mut request: JoseJwtVerifyRequest) -> JoseWireResult<Vec<u8>> {
    let compact = Zeroizing::new(core::mem::take(&mut request.compact));
    let jwk_json = Zeroizing::new(core::mem::take(&mut request.jwk_json));
    let jwk = jwk_from_json(&jwk_json, JwkOperation::Verify)?;
    let accepted_typ_values: Vec<&str> = request
        .header_policy
        .accepted_typ_values
        .iter()
        .map(String::as_str)
        .collect();
    let header_policy = if request.header_policy.is_set() {
        JwtHeaderValidationOptions::new(
            request.header_policy.allow_missing_typ,
            request.header_policy.allow_embedded_key_header,
            &accepted_typ_values,
        )
    } else {
        JwtHeaderValidationOptions::standard_jwt()
    };

    let temporal_policy_is_set = request.temporal_policy.is_set();
    if temporal_policy_is_set && request.signature_only {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
        ));
    }
    if !temporal_policy_is_set && !request.signature_only {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY,
        ));
    }

    let claims = if temporal_policy_is_set {
        if request.temporal_policy.now_unix == 0 {
            return Err(JoseWireError::primitive_internal(
                JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_TIME,
            ));
        }
        let temporal_policy = temporal_policy_from_proto(&request.temporal_policy);
        decode_verify_jwt_claims_json_with_temporal_validation_and_header_validation(
            &compact,
            &jwk,
            &request.public_key,
            request.temporal_policy.now_unix,
            temporal_policy,
            &header_policy,
        )
    } else {
        decode_verify_jwt_claims_json_signature_only_with_header_validation(
            &compact,
            &jwk,
            &request.public_key,
            &header_policy,
        )
    }
    .map_err(map_jwt_error)?;

    encode_claims_result(claims)
}

fn encrypt_jwe_result_bytes<R: SecureRandom + ?Sized>(
    mut request: JoseJweEncryptRequest,
    rng: &mut R,
) -> JoseWireResult<Vec<u8>> {
    let plaintext = Zeroizing::new(core::mem::take(&mut request.plaintext));
    let key = Zeroizing::new(core::mem::take(&mut request.key));
    let enc = content_encryption_from_proto(request.content_encryption_algorithm)?;
    let kid = optional_str(&request.kid);
    let typ = optional_str(&request.typ);
    let cty = optional_str(&request.cty);
    let apu = optional_bytes(&request.apu);
    let apv = optional_bytes(&request.apv);
    let mut native_request = CompactJweEncryptRequest::new(&plaintext, enc);
    if let Some(kid) = kid {
        native_request = native_request.with_kid(kid);
    }
    if let Some(apu) = apu {
        native_request = native_request.with_apu(apu);
    }
    if let Some(apv) = apv {
        native_request = native_request.with_apv(apv);
    }
    if let Some(typ) = typ {
        native_request = native_request.with_typ(typ);
    }
    if let Some(cty) = cty {
        native_request = native_request.with_cty(cty);
    }

    let compact = match known_jwe_key_management_algorithm(request.key_management_algorithm)? {
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT => {
            let mut encryptor = DirectJweKeyEncryptor::new(&key);
            encrypt_compact_jwe_bytes(&native_request, &mut encryptor, rng)
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256 => {
            let mut encryptor = P256EcdhEsJweKeyEncryptor::new(&key);
            encrypt_compact_jwe_bytes(&native_request, &mut encryptor, rng)
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384 => {
            #[cfg(feature = "native")]
            {
                let mut encryptor = P384EcdhEsJweKeyEncryptor::new(&key);
                encrypt_compact_jwe_bytes(&native_request, &mut encryptor, rng)
            }
            #[cfg(not(feature = "native"))]
            {
                return Err(JoseWireError::provider_internal(
                    JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
                ));
            }
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521 => {
            #[cfg(feature = "native")]
            {
                let mut encryptor = P521EcdhEsJweKeyEncryptor::new(&key);
                encrypt_compact_jwe_bytes(&native_request, &mut encryptor, rng)
            }
            #[cfg(not(feature = "native"))]
            {
                return Err(JoseWireError::provider_internal(
                    JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
                ));
            }
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_UNSPECIFIED => {
            return Err(JoseWireError::provider_internal(
                JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            ));
        }
    }
    .map_err(map_jwe_error)?;

    Ok(take_zeroizing_vec(encode_protobuf(&JoseCompactResult {
        compact,
        __buffa_unknown_fields: Default::default(),
    })))
}

fn decrypt_jwe_result_bytes(mut request: JoseJweDecryptRequest) -> JoseWireResult<Vec<u8>> {
    let key = Zeroizing::new(core::mem::take(&mut request.key));
    let alg = jwe_key_management_from_proto(request.key_management_algorithm)?;
    let enc = content_encryption_from_proto(request.content_encryption_algorithm)?;
    let mut policy =
        CompactJwePolicy::new(core::slice::from_ref(&alg), core::slice::from_ref(&enc));
    if request.header_policy.is_set() {
        if request.header_policy.require_kid {
            policy = policy.require_kid();
        }
        if request.header_policy.expected_kid.is_set() {
            policy = policy.with_expected_kid(&request.header_policy.expected_kid.value);
        }
        if request.header_policy.expected_typ.is_set() {
            policy = policy.with_expected_typ(&request.header_policy.expected_typ.value);
        }
        if request.header_policy.expected_cty.is_set() {
            policy = policy.with_expected_cty(&request.header_policy.expected_cty.value);
        }
        if request.header_policy.expected_apu.is_set() {
            policy = policy.with_expected_apu(&request.header_policy.expected_apu.value);
        }
        if request.header_policy.expected_apv.is_set() {
            policy = policy.with_expected_apv(&request.header_policy.expected_apv.value);
        }
    }

    let plaintext = match known_jwe_key_management_algorithm(request.key_management_algorithm)? {
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT => {
            let resolver = DirectJweKeyResolver::new(&key);
            decrypt_compact_jwe_bytes(&request.compact, &policy, &resolver)
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256 => {
            let resolver = P256EcdhEsJweKeyResolver::new(&key);
            decrypt_compact_jwe_bytes(&request.compact, &policy, &resolver)
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384 => {
            #[cfg(feature = "native")]
            {
                let resolver = P384EcdhEsJweKeyResolver::new(&key);
                decrypt_compact_jwe_bytes(&request.compact, &policy, &resolver)
            }
            #[cfg(not(feature = "native"))]
            {
                return Err(JoseWireError::provider_internal(
                    JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
                ));
            }
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521 => {
            #[cfg(feature = "native")]
            {
                let resolver = P521EcdhEsJweKeyResolver::new(&key);
                decrypt_compact_jwe_bytes(&request.compact, &policy, &resolver)
            }
            #[cfg(not(feature = "native"))]
            {
                return Err(JoseWireError::provider_internal(
                    JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
                ));
            }
        }
        JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_UNSPECIFIED => {
            return Err(JoseWireError::provider_internal(
                JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
            ));
        }
    }
    .map_err(map_jwe_error)?;

    let mut result = JoseJwePlaintextResult {
        plaintext: plaintext.to_vec(),
        __buffa_unknown_fields: Default::default(),
    };
    let bytes = take_zeroizing_vec(encode_protobuf(&result));
    result.plaintext.zeroize();
    Ok(bytes)
}

fn encode_claims_result(mut claims_json: Zeroizing<Vec<u8>>) -> JoseWireResult<Vec<u8>> {
    let mut result = JoseJwtClaimsResult {
        claims_json: core::mem::take(&mut claims_json),
        __buffa_unknown_fields: Default::default(),
    };
    let bytes = take_zeroizing_vec(encode_protobuf(&result));
    result.claims_json.zeroize();
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum JwkOperation {
    Sign,
    Verify,
}

struct SensitiveJwk(Jwk);

impl core::ops::Deref for SensitiveJwk {
    type Target = Jwk;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveJwk {
    fn drop(&mut self) {
        zeroize_jwk(&mut self.0);
    }
}

fn jwk_from_json(bytes: &[u8], operation: JwkOperation) -> JoseWireResult<SensitiveJwk> {
    reject_duplicate_object_members(bytes).map_err(|_| {
        JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK)
    })?;
    let mut value: JsonValue = serde_json::from_slice(bytes).map_err(|_| {
        JoseWireError::primitive_internal(JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK)
    })?;
    let policy_result = validate_jwk_operation(&value, operation);
    let result = policy_result.and_then(|()| {
        serde_json::from_slice(bytes)
            .map(SensitiveJwk)
            .map_err(|_| {
                JoseWireError::primitive_internal(
                    JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK,
                )
            })
    });
    zeroize_json_value(value.take());
    result
}

fn validate_jwk_operation(value: &JsonValue, operation: JwkOperation) -> JoseWireResult<()> {
    let object = value.as_object().ok_or(JoseWireError::primitive_internal(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK,
    ))?;
    if object
        .get("use")
        .is_some_and(|value| value.as_str() != Some("sig"))
    {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_ALGORITHM_MISMATCH,
        ));
    }
    let Some(key_ops) = object.get("key_ops") else {
        return Ok(());
    };
    let key_ops = key_ops.as_array().ok_or(JoseWireError::primitive_internal(
        JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_JWK,
    ))?;
    let required = match operation {
        JwkOperation::Sign => "sign",
        JwkOperation::Verify => "verify",
    };
    if !key_ops.iter().any(|value| value.as_str() == Some(required))
        || key_ops.iter().any(|value| {
            !matches!(
                value.as_str(),
                Some(
                    "sign"
                        | "verify"
                        | "encrypt"
                        | "decrypt"
                        | "wrapKey"
                        | "unwrapKey"
                        | "deriveKey"
                        | "deriveBits"
                )
            )
        })
    {
        return Err(JoseWireError::primitive_internal(
            JoseErrorReason::JOSE_ERROR_REASON_JWT_ALGORITHM_MISMATCH,
        ));
    }
    Ok(())
}

fn zeroize_jwk(jwk: &mut Jwk) {
    match jwk {
        Jwk::Ec(value) => {
            value.kty.zeroize();
            value.crv.zeroize();
            value.x.zeroize();
            value.y.zeroize();
            value.alg.zeroize();
            value.use_.zeroize();
            value.kid.zeroize();
        }
        Jwk::Okp(value) => {
            value.kty.zeroize();
            value.crv.zeroize();
            value.x.zeroize();
            value.alg.zeroize();
            value.use_.zeroize();
            value.kid.zeroize();
        }
        Jwk::Akp(value) => {
            value.kty.zeroize();
            value.alg.zeroize();
            value.public_key.zeroize();
            value.use_.zeroize();
            value.kid.zeroize();
        }
    }
}

fn zeroize_json_value(value: JsonValue) {
    match value {
        JsonValue::String(mut value) => value.zeroize(),
        JsonValue::Array(values) => values.into_iter().for_each(zeroize_json_value),
        JsonValue::Object(values) => values.into_iter().for_each(|(mut key, value)| {
            key.zeroize();
            zeroize_json_value(value);
        }),
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}

const fn temporal_policy_from_proto(
    policy: &JoseJwtTemporalValidationPolicy,
) -> JwtTemporalValidationPolicy {
    JwtTemporalValidationPolicy::new(
        policy.require_exp,
        policy.require_nbf,
        policy.require_iat,
        policy.clock_skew_seconds,
        policy.max_future_iat_skew_seconds,
    )
}

const fn optional_str(value: &str) -> Option<&str> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

const fn optional_bytes(value: &[u8]) -> Option<&[u8]> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn known_signature_algorithm(
    value: EnumValue<JoseSignatureAlgorithm>,
) -> JoseWireResult<JoseSignatureAlgorithm> {
    value.as_known().ok_or(JoseWireError::provider_internal(
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
    ))
}

fn known_jwe_key_management_algorithm(
    value: EnumValue<JoseJweKeyManagementAlgorithm>,
) -> JoseWireResult<JoseJweKeyManagementAlgorithm> {
    value.as_known().ok_or(JoseWireError::provider_internal(
        JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
    ))
}

fn content_encryption_from_proto(
    value: EnumValue<JoseJweContentEncryptionAlgorithm>,
) -> JoseWireResult<JweContentEncryptionAlgorithm> {
    match value.as_known() {
        Some(JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM) => {
            Ok(JweContentEncryptionAlgorithm::A128Gcm)
        }
        Some(JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A192GCM) => {
            Ok(JweContentEncryptionAlgorithm::A192Gcm)
        }
        Some(JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A256GCM) => {
            Ok(JweContentEncryptionAlgorithm::A256Gcm)
        }
        Some(
            JoseJweContentEncryptionAlgorithm::JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_UNSPECIFIED,
        )
        | None => Err(JoseWireError::provider_internal(
            JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
        )),
    }
}

fn jwe_key_management_from_proto(
    value: EnumValue<JoseJweKeyManagementAlgorithm>,
) -> JoseWireResult<JweKeyManagementAlgorithm> {
    match value.as_known() {
        Some(JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT) => {
            Ok(JweKeyManagementAlgorithm::Direct)
        }
        Some(
            JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P256
            | JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P384
            | JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_ECDH_ES_P521,
        ) => Ok(JweKeyManagementAlgorithm::EcdhEs),
        Some(JoseJweKeyManagementAlgorithm::JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_UNSPECIFIED)
        | None => Err(JoseWireError::provider_internal(
            JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_UNSUPPORTED,
        )),
    }
}

const fn map_jws_es256_error(error: JwsEs256Error) -> JoseWireError {
    let reason = match error {
        JwsEs256Error::InvalidCompactEncoding => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_COMPACT
        }
        JwsEs256Error::LengthOverflow => JoseErrorReason::JOSE_ERROR_REASON_JWS_LENGTH_OVERFLOW,
        JwsEs256Error::InputTooLarge => JoseErrorReason::JOSE_ERROR_REASON_JWS_INPUT_TOO_LARGE,
        JwsEs256Error::BadHeaderBase64 => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_BASE64,
        JwsEs256Error::BadHeaderUtf8 => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_UTF8,
        JwsEs256Error::HeaderMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWS_HEADER_MISMATCH,
        JwsEs256Error::BadSignatureBase64 => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_SIGNATURE_BASE64
        }
        JwsEs256Error::BadRawSignature => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_RAW_SIGNATURE,
        JwsEs256Error::InvalidSignature | JwsEs256Error::VerifyFailed => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE
        }
        JwsEs256Error::SignFailed => JoseErrorReason::JOSE_ERROR_REASON_JWS_SIGN_FAILED,
        JwsEs256Error::BadDerSignature => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_DER_SIGNATURE,
    };
    JoseWireError::primitive_internal(reason)
}

const fn map_jws_eddsa_error(error: JwsEddsaError) -> JoseWireError {
    let reason = match error {
        JwsEddsaError::InvalidCompactEncoding => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_COMPACT
        }
        JwsEddsaError::LengthOverflow => JoseErrorReason::JOSE_ERROR_REASON_JWS_LENGTH_OVERFLOW,
        JwsEddsaError::InputTooLarge => JoseErrorReason::JOSE_ERROR_REASON_JWS_INPUT_TOO_LARGE,
        JwsEddsaError::BadHeaderBase64 => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_BASE64,
        JwsEddsaError::BadHeaderUtf8 => JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_HEADER_UTF8,
        JwsEddsaError::HeaderMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWS_HEADER_MISMATCH,
        JwsEddsaError::BadSignatureBase64 => {
            JoseErrorReason::JOSE_ERROR_REASON_JWS_BAD_SIGNATURE_BASE64
        }
        JwsEddsaError::InvalidSignature => JoseErrorReason::JOSE_ERROR_REASON_JWS_INVALID_SIGNATURE,
        JwsEddsaError::SignFailed => JoseErrorReason::JOSE_ERROR_REASON_JWS_SIGN_FAILED,
    };
    JoseWireError::primitive_internal(reason)
}

const fn map_jwe_error(error: JweError) -> JoseWireError {
    let reason = match error {
        JweError::InvalidCompact => JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_COMPACT,
        JweError::InputTooLarge => JoseErrorReason::JOSE_ERROR_REASON_JWE_INPUT_TOO_LARGE,
        JweError::InvalidEncoding => JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_ENCODING,
        JweError::InvalidHeader => JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_HEADER,
        JweError::UnsupportedKeyManagementAlgorithm => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_KEY_MANAGEMENT_ALGORITHM
        }
        JweError::UnsupportedContentEncryptionAlgorithm => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM
        }
        JweError::MissingRequiredHeaderParameter => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_MISSING_REQUIRED_HEADER_PARAMETER
        }
        JweError::HeaderPolicyMismatch
        | JweError::TypPolicyMismatch
        | JweError::CtyPolicyMismatch => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_HEADER_POLICY_MISMATCH
        }
        JweError::KidPolicyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWE_KID_POLICY_MISMATCH,
        JweError::ApuPolicyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWE_APU_POLICY_MISMATCH,
        JweError::ApvPolicyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWE_APV_POLICY_MISMATCH,
        JweError::InvalidEncryptedKey => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_ENCRYPTED_KEY
        }
        JweError::InvalidContentEncryptionKey => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_ENCRYPTION_KEY
        }
        JweError::InvalidContentCipherInput => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_CONTENT_CIPHER_INPUT
        }
        JweError::Decrypt => JoseErrorReason::JOSE_ERROR_REASON_JWE_DECRYPT_FAILED,
        JweError::Encrypt => JoseErrorReason::JOSE_ERROR_REASON_JWE_ENCRYPT_FAILED,
        JweError::InvalidKeyAgreementKey => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_KEY_AGREEMENT_KEY
        }
        JweError::InvalidSharedSecret => {
            JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_SHARED_SECRET
        }
        JweError::KeyDerivation => {
            return JoseWireError::backend_internal(
                JoseErrorReason::JOSE_ERROR_REASON_BACKEND_KEY_DERIVATION_FAILED,
            );
        }
        JweError::Randomness => {
            return JoseWireError::provider_internal(
                JoseErrorReason::JOSE_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE,
            );
        }
        JweError::InvalidPayloadJson => JoseErrorReason::JOSE_ERROR_REASON_JWE_INVALID_PAYLOAD_JSON,
        JweError::LengthOverflow => JoseErrorReason::JOSE_ERROR_REASON_JWE_LENGTH_OVERFLOW,
    };
    JoseWireError::primitive_internal(reason)
}

const fn map_jwt_error(error: JwtError) -> JoseWireError {
    let reason = match error {
        JwtError::InvalidJwtFormat => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_COMPACT,
        JwtError::InputTooLarge => JoseErrorReason::JOSE_ERROR_REASON_JWT_INPUT_TOO_LARGE,
        JwtError::Base64Url => JoseErrorReason::JOSE_ERROR_REASON_JWT_BASE64URL_DECODE_FAILED,
        JwtError::LengthOverflow => JoseErrorReason::JOSE_ERROR_REASON_JWT_LENGTH_OVERFLOW,
        JwtError::InvalidHeader => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_HEADER,
        JwtError::UnsupportedAlgorithm => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_UNSUPPORTED_ALGORITHM
        }
        JwtError::AlgorithmMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_ALGORITHM_MISMATCH,
        JwtError::KeyIdMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_KID_POLICY_MISMATCH,
        JwtError::PublicKeyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_PUBLIC_KEY_MISMATCH,
        JwtError::SigningKeyMismatch => JoseErrorReason::JOSE_ERROR_REASON_JWT_SIGNING_KEY_MISMATCH,
        JwtError::MissingAlgorithm => JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_ALGORITHM,
        JwtError::MissingPrivateKey => JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_PRIVATE_KEY,
        JwtError::MissingPublicKey => JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_PUBLIC_KEY,
        JwtError::InvalidPublicKey => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_PUBLIC_KEY,
        JwtError::InvalidSignature => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_SIGNATURE,
        JwtError::Crypto => JoseErrorReason::JOSE_ERROR_REASON_JWT_CRYPTO_FAILED,
        JwtError::InvalidClaims => JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_CLAIMS,
        JwtError::Serialization => JoseErrorReason::JOSE_ERROR_REASON_JWT_SERIALIZATION_FAILED,
        JwtError::MissingRequiredTemporalClaim(_) => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_MISSING_REQUIRED_TEMPORAL_CLAIM
        }
        JwtError::InvalidTemporalClaimValue(_) => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_TEMPORAL_CLAIM_VALUE
        }
        JwtError::Expired => JoseErrorReason::JOSE_ERROR_REASON_JWT_EXPIRED,
        JwtError::NotYetValid => JoseErrorReason::JOSE_ERROR_REASON_JWT_NOT_YET_VALID,
        JwtError::IssuedAtInFuture => JoseErrorReason::JOSE_ERROR_REASON_JWT_ISSUED_AT_IN_FUTURE,
        JwtError::InvalidTemporalPolicy => {
            JoseErrorReason::JOSE_ERROR_REASON_JWT_INVALID_VERIFICATION_POLICY
        }
    };
    JoseWireError::primitive_internal(reason)
}
