// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value as JsonValue;

use super::{JwtError, JwtTemporalClaim};

const MAX_TEMPORAL_SKEW_SECONDS: u64 = 86_400;

/// Temporal claim validation policy for signed JWT verification.
#[derive(Debug, Clone, Copy)]
pub struct JwtTemporalValidationPolicy {
    /// Require an `exp` claim.
    require_exp: bool,
    /// Require an `nbf` claim.
    require_nbf: bool,
    /// Require an `iat` claim.
    require_iat: bool,
    /// Symmetric leeway applied to `exp` and `nbf`, in seconds.
    clock_skew_seconds: u64,
    /// Maximum accepted future skew for `iat`, in seconds.
    max_future_iat_skew_seconds: u64,
}

impl JwtTemporalValidationPolicy {
    /// Builds a temporal-claim validation policy.
    #[must_use]
    pub const fn new(
        require_exp: bool,
        require_nbf: bool,
        require_iat: bool,
        clock_skew_seconds: u64,
        max_future_iat_skew_seconds: u64,
    ) -> Self {
        Self {
            require_exp,
            require_nbf,
            require_iat,
            clock_skew_seconds,
            max_future_iat_skew_seconds,
        }
    }

    /// Returns a verifier-grade default policy that requires expiration.
    #[must_use]
    pub const fn strict() -> Self {
        Self::new(true, false, false, 60, 60)
    }

    /// Returns whether `exp` is required.
    #[must_use]
    pub const fn require_exp(&self) -> bool {
        self.require_exp
    }

    /// Returns whether `nbf` is required.
    #[must_use]
    pub const fn require_nbf(&self) -> bool {
        self.require_nbf
    }

    /// Returns whether `iat` is required.
    #[must_use]
    pub const fn require_iat(&self) -> bool {
        self.require_iat
    }

    /// Returns symmetric leeway applied to `exp` and `nbf`, in seconds.
    #[must_use]
    pub const fn clock_skew_seconds(&self) -> u64 {
        self.clock_skew_seconds
    }

    /// Returns maximum accepted future skew for `iat`, in seconds.
    #[must_use]
    pub const fn max_future_iat_skew_seconds(&self) -> u64 {
        self.max_future_iat_skew_seconds
    }

    const fn validate(&self) -> Result<(), JwtError> {
        if self.clock_skew_seconds > MAX_TEMPORAL_SKEW_SECONDS {
            return Err(JwtError::InvalidTemporalPolicy);
        }
        if self.max_future_iat_skew_seconds > MAX_TEMPORAL_SKEW_SECONDS {
            return Err(JwtError::InvalidTemporalPolicy);
        }
        Ok(())
    }
}

pub(super) fn validate_temporal_claims(
    payload: &JsonValue,
    now_unix: u64,
    temporal_policy: JwtTemporalValidationPolicy,
) -> Result<(), JwtError> {
    temporal_policy.validate()?;

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
    let expiration_floor = checked_skew_floor(now_unix, clock_skew_seconds)?;
    if expiration_floor > exp_unix {
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
    let not_before_ceiling = checked_skew_ceiling(now_unix, clock_skew_seconds)?;
    if not_before_ceiling < nbf_unix {
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
    let issued_at_ceiling = checked_skew_ceiling(now_unix, max_future_iat_skew_seconds)?;
    if iat_unix > issued_at_ceiling {
        return Err(JwtError::IssuedAtInFuture);
    }
    Ok(())
}

fn checked_skew_floor(now_unix: u64, clock_skew_seconds: u64) -> Result<u64, JwtError> {
    if now_unix < clock_skew_seconds {
        return Ok(0);
    }
    now_unix
        .checked_sub(clock_skew_seconds)
        .ok_or(JwtError::InvalidTemporalPolicy)
}

fn checked_skew_ceiling(now_unix: u64, skew_seconds: u64) -> Result<u64, JwtError> {
    now_unix
        .checked_add(skew_seconds)
        .ok_or(JwtError::InvalidTemporalPolicy)
}
