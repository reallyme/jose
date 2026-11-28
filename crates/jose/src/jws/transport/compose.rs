// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::api::contract::{JoseJwsTransportComposeBudgets, JoseJwsTransportPolicy};

use super::{admit, JwsTransportErrorReason as Error};

/// Borrowed projection of the schema-defined unauthenticated composer request.
pub struct ComposeCompactJwsRequest<'a> {
    /// Original protected-member text, including any admitted dots.
    pub protected_header: &'a str,
    /// Original payload-member text, including any admitted dots.
    pub payload: &'a str,
    /// Original signature-member text, including any admitted dots.
    pub signature: &'a str,
    /// Independent empty-string and character admission for each member.
    pub policy: &'a JoseJwsTransportPolicy,
    /// Aggregate member input and composed output budgets, in UTF-8 bytes.
    pub budgets: &'a JoseJwsTransportComposeBudgets,
}

/// Wipe-owned, unauthenticated text produced by verbatim member forwarding.
/// It may fail subsequent framing, strict inspection or verification.
pub struct UnauthenticatedCompactJws {
    compact: Zeroizing<String>,
}

impl UnauthenticatedCompactJws {
    /// Borrows the exact composed text without decoding or authenticating it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.compact.as_str()
    }

    /// Transfers the text while preserving zeroization on drop.
    #[must_use]
    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.compact
    }
}

impl Zeroize for UnauthenticatedCompactJws {
    fn zeroize(&mut self) {
        self.compact.zeroize();
    }
}

// The sole owning field zeroizes its full allocation when it is dropped.
impl ZeroizeOnDrop for UnauthenticatedCompactJws {}

impl core::fmt::Debug for UnauthenticatedCompactJws {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("UnauthenticatedCompactJws([REDACTED])")
    }
}

/// Joins the three supplied member strings verbatim with two inserted dots.
///
/// Only selected member admission is applied. Embedded dots remain intact
/// under policies that admit them; this result is not strictly inspected.
/// Input bytes exclude the inserted dots; output bytes include them. No
/// verification limit is imposed on either explicit caller budget.
///
/// # Errors
/// Rejects missing budgets/policies, budget overruns, disallowed members,
/// checked-length overflow and allocation failure with fixed transport errors.
pub fn compose_compact_jws_unauthenticated(
    request: &ComposeCompactJwsRequest<'_>,
) -> Result<UnauthenticatedCompactJws, Error> {
    let input_limit = admit::budget(request.budgets.max_input_bytes)?;
    let output_limit = admit::budget(request.budgets.max_output_bytes)?;
    let (input, output) = admit::composed_lengths(
        request.protected_header.len(),
        request.payload.len(),
        request.signature.len(),
    )?;
    if input > input_limit {
        return Err(Error::InputTooLarge);
    }
    if output > output_limit {
        return Err(Error::OutputTooLarge);
    }
    admit::members(
        request.protected_header,
        request.payload,
        request.signature,
        request.policy,
    )?;

    // Complete admission before allocating, then reserve the complete output.
    // No growth or fallible parsing can leave an unguarded partial output.
    let mut compact = Zeroizing::new(String::new());
    compact
        .try_reserve_exact(output)
        .map_err(|_| Error::Allocation)?;
    compact.push_str(request.protected_header);
    compact.push('.');
    compact.push_str(request.payload);
    compact.push('.');
    compact.push_str(request.signature);
    Ok(UnauthenticatedCompactJws { compact })
}
