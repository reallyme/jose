// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Map as JsonMap, Value as JsonValue};

use super::{JwtError, JwtRegisteredClaim, JwtTemporalValidationPolicy};

/// Registered-claims policy for verifier-grade signed JWT processing.
///
/// An expected audience is mandatory because signature and time validation do
/// not establish that a token was issued for the current recipient. Issuer and
/// subject constraints are optional, but become required claims when supplied.
///
/// This type intentionally does not implement `Debug`: expected claim values
/// can be correlating identifiers and must not be copied into diagnostics.
#[derive(Clone, Copy)]
pub struct JwtClaimsValidationPolicy<'a> {
    temporal_policy: JwtTemporalValidationPolicy,
    expected_audience: &'a str,
    expected_issuer: Option<&'a str>,
    expected_subject: Option<&'a str>,
}

impl<'a> JwtClaimsValidationPolicy<'a> {
    /// Builds a signed-JWT registered-claims validation policy.
    #[must_use]
    pub const fn new(
        temporal_policy: JwtTemporalValidationPolicy,
        expected_audience: &'a str,
        expected_issuer: Option<&'a str>,
        expected_subject: Option<&'a str>,
    ) -> Self {
        Self {
            temporal_policy,
            expected_audience,
            expected_issuer,
            expected_subject,
        }
    }

    /// Returns a verifier-grade policy requiring expiration and audience.
    #[must_use]
    pub const fn strict(expected_audience: &'a str) -> Self {
        Self::new(
            JwtTemporalValidationPolicy::strict(),
            expected_audience,
            None,
            None,
        )
    }

    /// Returns the temporal validation component.
    #[must_use]
    pub const fn temporal_policy(&self) -> JwtTemporalValidationPolicy {
        self.temporal_policy
    }

    /// Returns the recipient identifier that must appear in `aud`.
    #[must_use]
    pub const fn expected_audience(&self) -> &'a str {
        self.expected_audience
    }

    /// Returns the exact required issuer, when configured.
    #[must_use]
    pub const fn expected_issuer(&self) -> Option<&'a str> {
        self.expected_issuer
    }

    /// Returns the exact required subject, when configured.
    #[must_use]
    pub const fn expected_subject(&self) -> Option<&'a str> {
        self.expected_subject
    }

    fn validate(&self) -> Result<(), JwtError> {
        if self.expected_audience.is_empty()
            || self.expected_issuer.is_some_and(str::is_empty)
            || self.expected_subject.is_some_and(str::is_empty)
        {
            return Err(JwtError::InvalidClaimsPolicy);
        }
        Ok(())
    }
}

pub(super) fn validate_claims_set(
    payload: &JsonValue,
) -> Result<&JsonMap<String, JsonValue>, JwtError> {
    payload.as_object().ok_or(JwtError::InvalidClaims)
}

pub(super) fn validate_registered_claims(
    payload: &JsonValue,
    policy: JwtClaimsValidationPolicy<'_>,
) -> Result<(), JwtError> {
    policy.validate()?;
    let claims = validate_claims_set(payload)?;

    let audience = claims
        .get("aud")
        .ok_or(JwtError::MissingRequiredRegisteredClaim(
            JwtRegisteredClaim::Audience,
        ))?;
    validate_audience(audience, policy.expected_audience)?;
    validate_string_claim(
        claims,
        "iss",
        JwtRegisteredClaim::Issuer,
        policy.expected_issuer,
        JwtError::IssuerMismatch,
    )?;
    validate_string_claim(
        claims,
        "sub",
        JwtRegisteredClaim::Subject,
        policy.expected_subject,
        JwtError::SubjectMismatch,
    )
}

fn validate_audience(value: &JsonValue, expected_audience: &str) -> Result<(), JwtError> {
    match value {
        JsonValue::String(audience) => {
            validate_nonempty_claim_value(audience, JwtRegisteredClaim::Audience)?;
            if audience == expected_audience {
                Ok(())
            } else {
                Err(JwtError::AudienceMismatch)
            }
        }
        JsonValue::Array(audiences) => {
            if audiences.is_empty() {
                return Err(JwtError::InvalidRegisteredClaimValue(
                    JwtRegisteredClaim::Audience,
                ));
            }

            let mut matched = false;
            for audience in audiences {
                let audience = audience
                    .as_str()
                    .ok_or(JwtError::InvalidRegisteredClaimValue(
                        JwtRegisteredClaim::Audience,
                    ))?;
                validate_nonempty_claim_value(audience, JwtRegisteredClaim::Audience)?;
                matched |= audience == expected_audience;
            }

            if matched {
                Ok(())
            } else {
                Err(JwtError::AudienceMismatch)
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::Object(_) => Err(
            JwtError::InvalidRegisteredClaimValue(JwtRegisteredClaim::Audience),
        ),
    }
}

fn validate_string_claim(
    claims: &JsonMap<String, JsonValue>,
    name: &str,
    claim: JwtRegisteredClaim,
    expected: Option<&str>,
    mismatch: JwtError,
) -> Result<(), JwtError> {
    let Some(value) = claims.get(name) else {
        return if expected.is_some() {
            Err(JwtError::MissingRequiredRegisteredClaim(claim))
        } else {
            Ok(())
        };
    };
    let actual = value
        .as_str()
        .ok_or(JwtError::InvalidRegisteredClaimValue(claim))?;
    validate_nonempty_claim_value(actual, claim)?;

    if expected.is_some_and(|expected_value| actual != expected_value) {
        return Err(mismatch);
    }
    Ok(())
}

const fn validate_nonempty_claim_value(
    value: &str,
    claim: JwtRegisteredClaim,
) -> Result<(), JwtError> {
    if value.is_empty() {
        return Err(JwtError::InvalidRegisteredClaimValue(claim));
    }
    Ok(())
}
