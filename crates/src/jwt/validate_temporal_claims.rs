// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value as JsonValue;

use super::{JwtError, JwtTemporalClaim};

/// Temporal claim validation policy for signed JWT verification.
#[derive(Debug, Clone, Copy)]
pub struct JwtTemporalValidationPolicy {
    /// Require an `exp` claim.
    pub require_exp: bool,
    /// Require an `nbf` claim.
    pub require_nbf: bool,
    /// Require an `iat` claim.
    pub require_iat: bool,
    /// Symmetric leeway applied to `exp` and `nbf`, in seconds.
    pub clock_skew_seconds: u64,
    /// Maximum accepted future skew for `iat`, in seconds.
    pub max_future_iat_skew_seconds: u64,
}

impl JwtTemporalValidationPolicy {
    /// Returns a verifier-grade default policy that requires expiration.
    pub fn strict() -> Self {
        Self {
            require_exp: true,
            require_nbf: false,
            require_iat: false,
            clock_skew_seconds: 60,
            max_future_iat_skew_seconds: 60,
        }
    }
}

pub(super) fn validate_temporal_claims(
    payload: &JsonValue,
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
) -> Result<(), JwtError> {
    let exp = parse_optional_numeric_date(payload, JwtTemporalClaim::Exp)?;
    let nbf = parse_optional_numeric_date(payload, JwtTemporalClaim::Nbf)?;
    let iat = parse_optional_numeric_date(payload, JwtTemporalClaim::Iat)?;

    if temporal_policy.require_exp && exp.is_none() {
        return Err(JwtError::MissingRequiredTemporalClaim(
            JwtTemporalClaim::Exp,
        ));
    }
    if temporal_policy.require_nbf && nbf.is_none() {
        return Err(JwtError::MissingRequiredTemporalClaim(
            JwtTemporalClaim::Nbf,
        ));
    }
    if temporal_policy.require_iat && iat.is_none() {
        return Err(JwtError::MissingRequiredTemporalClaim(
            JwtTemporalClaim::Iat,
        ));
    }

    validate_expiration(exp, now_unix, temporal_policy.clock_skew_seconds)?;
    validate_not_before(nbf, now_unix, temporal_policy.clock_skew_seconds)?;
    validate_issued_at(iat, now_unix, temporal_policy.max_future_iat_skew_seconds)?;

    Ok(())
}

fn parse_optional_numeric_date(
    payload: &JsonValue,
    claim: JwtTemporalClaim,
) -> Result<Option<u64>, JwtError> {
    let key = match claim {
        JwtTemporalClaim::Exp => "exp",
        JwtTemporalClaim::Nbf => "nbf",
        JwtTemporalClaim::Iat => "iat",
    };

    let Some(value) = payload.get(key) else {
        return Ok(None);
    };

    value
        .as_u64()
        .ok_or(JwtError::InvalidTemporalClaimValue(claim))
        .map(Some)
}

fn validate_expiration(
    exp: Option<u64>,
    now_unix: u64,
    clock_skew_seconds: u64,
) -> Result<(), JwtError> {
    let Some(exp_unix) = exp else {
        return Ok(());
    };

    if exp_unix == 0 {
        return Err(JwtError::InvalidTemporalClaimValue(JwtTemporalClaim::Exp));
    }
    if now_unix.saturating_sub(clock_skew_seconds) > exp_unix {
        return Err(JwtError::Expired);
    }
    Ok(())
}

fn validate_not_before(
    nbf: Option<u64>,
    now_unix: u64,
    clock_skew_seconds: u64,
) -> Result<(), JwtError> {
    let Some(nbf_unix) = nbf else {
        return Ok(());
    };

    if nbf_unix == 0 {
        return Err(JwtError::InvalidTemporalClaimValue(JwtTemporalClaim::Nbf));
    }
    if now_unix.saturating_add(clock_skew_seconds) < nbf_unix {
        return Err(JwtError::NotYetValid);
    }
    Ok(())
}

fn validate_issued_at(
    iat: Option<u64>,
    now_unix: u64,
    max_future_iat_skew_seconds: u64,
) -> Result<(), JwtError> {
    let Some(iat_unix) = iat else {
        return Ok(());
    };

    if iat_unix == 0 {
        return Err(JwtError::InvalidTemporalClaimValue(JwtTemporalClaim::Iat));
    }
    if iat_unix > now_unix.saturating_add(max_future_iat_skew_seconds) {
        return Err(JwtError::IssuedAtInFuture);
    }
    Ok(())
}
