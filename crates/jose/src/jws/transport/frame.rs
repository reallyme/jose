// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::api::contract::{JoseJwsTransportFrameBudgets, JoseJwsTransportPolicy};

use super::{admit, JwsTransportErrorReason as Error};

/// Borrowed projection of the schema-defined unauthenticated framing request.
/// The caller retains ownership and cleanup of the original compact text.
pub struct FrameCompactJwsRequest<'a, 'policy> {
    /// Original UTF-8 compact text; no normalization is performed.
    pub compact: &'a str,
    /// Independent admission of each member's emptiness and characters.
    pub policy: &'policy JoseJwsTransportPolicy,
    /// Explicit caller byte budget, independent of verification limits.
    pub budgets: &'policy JoseJwsTransportFrameBudgets,
}

/// Unauthenticated encoded slices borrowed from their original compact input.
///
/// No member has been decoded or authenticated. The lifetime cannot outlive
/// the input; this view cannot be converted into an authentication receipt.
///
/// ```compile_fail
/// use reallyme_jose::jws::transport::{frame_compact_jws_unauthenticated, FrameCompactJwsRequest};
/// # use reallyme_jose::api::contract::{JoseJwsTransportPolicy, JoseJwsTransportFrameBudgets};
/// # let policy = JoseJwsTransportPolicy::default();
/// # let budgets = JoseJwsTransportFrameBudgets::default();
/// let view = {
///     let compact = String::from("header.payload.signature");
///     frame_compact_jws_unauthenticated(&FrameCompactJwsRequest {
///         compact: &compact, policy: &policy, budgets: &budgets,
///     })
/// };
/// let _ = view.map(|view| view.payload().len());
/// ```
pub struct UnauthenticatedCompactJwsView<'a> {
    protected_header: &'a str,
    payload: &'a str,
    signature: &'a str,
    signing_input: &'a str,
}

impl<'a> UnauthenticatedCompactJwsView<'a> {
    /// Borrows the original encoded protected-header slice.
    #[must_use]
    pub const fn protected_header(&self) -> &'a str {
        self.protected_header
    }

    /// Borrows the original encoded payload slice.
    #[must_use]
    pub const fn payload(&self) -> &'a str {
        self.payload
    }

    /// Borrows the original encoded signature slice.
    #[must_use]
    pub const fn signature(&self) -> &'a str {
        self.signature
    }

    /// Borrows the exact header, first dot and payload, without the second dot.
    /// This is signing-input framing only, without a signature assertion.
    #[must_use]
    pub const fn signing_input(&self) -> &'a str {
        self.signing_input
    }
}

impl core::fmt::Debug for UnauthenticatedCompactJwsView<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("UnauthenticatedCompactJwsView([REDACTED])")
    }
}

/// Borrows exactly three original members under caller-selected admission.
///
/// This function performs no allocation, decoding, canonicality checking,
/// header inspection or signature verification. Input limits are UTF-8 byte
/// counts and are never clamped to the strict verification limit.
///
/// # Errors
/// Rejects missing budgets/policies, excess input, separator counts other than
/// two, and members disallowed by their policies, using fixed transport errors.
pub fn frame_compact_jws_unauthenticated<'a>(
    request: &FrameCompactJwsRequest<'a, '_>,
) -> Result<UnauthenticatedCompactJwsView<'a>, Error> {
    let compact = request.compact;
    if compact.len() > admit::budget(request.budgets.max_input_bytes)? {
        return Err(Error::InputTooLarge);
    }
    let (protected_header, remainder) = compact.split_once('.').ok_or(Error::InvalidFraming)?;
    let (payload, signature) = remainder.split_once('.').ok_or(Error::InvalidFraming)?;
    if signature.contains('.') {
        return Err(Error::InvalidFraming);
    }
    admit::members(protected_header, payload, signature, request.policy)?;
    let payload_end = protected_header
        .len()
        .checked_add(1)
        .and_then(|start| start.checked_add(payload.len()))
        .ok_or(Error::LengthOverflow)?;
    let signing_input = compact.get(..payload_end).ok_or(Error::InvalidFraming)?;
    Ok(UnauthenticatedCompactJwsView {
        protected_header,
        payload,
        signature,
        signing_input,
    })
}
