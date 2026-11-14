// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    validate_numeric_dates, validate_verification_time, JwtError, JwtTemporalClaim,
    JwtTemporalValidationPolicy, MAX_TEMPORAL_SKEW_SECONDS,
};

#[kani::proof]
fn verification_time_and_skew_policy() {
    let now = kani::any::<u64>();
    let skew = kani::any::<u64>();
    let future_iat_skew = kani::any::<u64>();
    let policy = JwtTemporalValidationPolicy::new(
        kani::any(),
        kani::any(),
        kani::any(),
        skew,
        future_iat_skew,
    );

    let result = validate_verification_time(now, policy);
    if now == 0 {
        kani::assert(
            matches!(result, Err(JwtError::InvalidVerificationTime)),
            "zero verification time is rejected",
        );
    } else if skew > MAX_TEMPORAL_SKEW_SECONDS || future_iat_skew > MAX_TEMPORAL_SKEW_SECONDS {
        kani::assert(
            matches!(result, Err(JwtError::InvalidTemporalPolicy)),
            "excess skew is rejected",
        );
    } else {
        kani::assert(
            result.is_ok(),
            "positive time and permitted skew are accepted",
        );
    }

    kani::cover!(now == 0, "zero verification time");
    kani::cover!(
        now > 0 && skew > MAX_TEMPORAL_SKEW_SECONDS,
        "excess clock skew"
    );
    kani::cover!(
        now > 0 && skew <= MAX_TEMPORAL_SKEW_SECONDS && future_iat_skew > MAX_TEMPORAL_SKEW_SECONDS,
        "excess future iat skew"
    );
    kani::cover!(
        result.is_ok() && skew == MAX_TEMPORAL_SKEW_SECONDS && future_iat_skew == skew,
        "maximum permitted skew for both limits"
    );
}

#[kani::proof]
fn numeric_date_acceptance_and_boundaries() {
    let now = kani::any::<u64>();
    let skew = kani::any::<u64>();
    let future_iat_skew = kani::any::<u64>();
    let require_exp = kani::any::<bool>();
    let require_nbf = kani::any::<bool>();
    let require_iat = kani::any::<bool>();
    let exp = kani::any::<Option<u64>>();
    let nbf = kani::any::<Option<u64>>();
    let iat = kani::any::<Option<u64>>();

    // The preceding gate checks these preconditions before parsing any claims.
    kani::assume(now > 0);
    kani::assume(skew <= MAX_TEMPORAL_SKEW_SECONDS);
    kani::assume(future_iat_skew <= MAX_TEMPORAL_SKEW_SECONDS);
    let policy = JwtTemporalValidationPolicy::new(
        require_exp,
        require_nbf,
        require_iat,
        skew,
        future_iat_skew,
    );
    let result = validate_numeric_dates(exp, nbf, iat, now, policy);

    // Use wider arithmetic so the specification can distinguish the exact
    // mathematical endpoints from answers that would overflow u64.
    let now = u128::from(now);
    let nbf_end = now + u128::from(skew);
    let iat_end = now + u128::from(future_iat_skew);
    let max = u128::from(u64::MAX);
    let exp_end = exp.map(|value| u128::from(value) + u128::from(skew));
    let expected = (!require_exp || exp.is_some())
        && (!require_nbf || nbf.is_some())
        && (!require_iat || iat.is_some())
        && exp_end.is_none_or(|end| exp != Some(0) && now < end)
        && nbf.is_none_or(|value| value != 0 && u128::from(value) <= nbf_end && nbf_end <= max)
        && iat.is_none_or(|value| value != 0 && u128::from(value) <= iat_end && iat_end <= max);
    kani::assert(
        result.is_ok() == expected,
        "temporal acceptance agrees with the mathematical bounds",
    );

    kani::cover!(
        result.is_ok() && exp.is_none() && nbf.is_none() && iat.is_none(),
        "all optional claims absent"
    );
    kani::cover!(
        matches!(
            &result,
            Err(JwtError::MissingRequiredTemporalClaim(
                JwtTemporalClaim::Exp
            ))
        ),
        "required expiration missing"
    );
    kani::cover!(
        matches!(
            &result,
            Err(JwtError::MissingRequiredTemporalClaim(
                JwtTemporalClaim::Nbf
            ))
        ),
        "required not-before missing"
    );
    kani::cover!(
        matches!(
            &result,
            Err(JwtError::MissingRequiredTemporalClaim(
                JwtTemporalClaim::Iat
            ))
        ),
        "required issued-at missing"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::InvalidTemporalClaimValue(_))) && exp == Some(0),
        "zero NumericDate rejected"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::Expired)) && exp_end == Some(now),
        "expiration rejects its exact skew boundary"
    );
    kani::cover!(
        result.is_ok()
            && nbf.map(u128::from) == Some(nbf_end)
            && iat.map(u128::from) == Some(iat_end)
            && skew != future_iat_skew,
        "not-before and issued-at accept their distinct exact skew boundaries"
    );
    kani::cover!(
        result.is_ok() && now < u128::from(skew) && exp.is_some(),
        "expiration with skew larger than current time"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::InvalidTemporalPolicy)) && nbf.is_some() && nbf_end > max,
        "not-before ceiling overflow"
    );
    kani::cover!(
        matches!(&result, Err(JwtError::InvalidTemporalPolicy))
            && nbf.is_none()
            && iat.is_some()
            && iat_end > max,
        "issued-at ceiling overflow"
    );
}
