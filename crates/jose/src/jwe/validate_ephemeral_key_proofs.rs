// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;

#[cfg(feature = "native")]
use super::EphemeralCurve;
use super::{agree_with_validated_ephemeral_key, read_public_members, JweError};

#[kani::proof]
#[kani::unwind(8)]
fn ephemeral_jwk_requires_exactly_four_public_string_members() {
    let has_key_type = kani::any::<bool>();
    let has_curve = kani::any::<bool>();
    let has_x = kani::any::<bool>();
    let has_y = kani::any::<bool>();
    let has_private_member = kani::any::<bool>();
    let has_other_member = kani::any::<bool>();
    let x_is_string = kani::any::<bool>();
    // A JSON object's size counts distinct names, even when a member's value
    // has the wrong type. Model both adding and substituting private members.
    let member_count = [
        has_key_type,
        has_curve,
        has_x,
        has_y,
        has_private_member,
        has_other_member,
    ]
    .into_iter()
    .map(usize::from)
    .sum();
    let result = read_public_members(member_count, |name| match name {
        "kty" if has_key_type => Some("EC"),
        "crv" if has_curve => Some("P-256"),
        "x" if has_x && x_is_string => Some("AQ"),
        "y" if has_y => Some("Ag"),
        _ => None,
    });
    let valid = has_key_type
        && has_curve
        && has_x
        && x_is_string
        && has_y
        && !has_private_member
        && !has_other_member;

    match result {
        Ok(jwk) => kani::assert(
            valid && jwk.key_type == "EC" && jwk.curve == "P-256" && jwk.x == "AQ" && jwk.y == "Ag",
            "the validated view contains only the four required public members",
        ),
        Err(error) => kani::assert(
            !valid && matches!(error, JweError::InvalidKeyAgreementKey),
            "invalid member sets are rejected with a typed error",
        ),
    }
    kani::cover!(valid, "four public string members");
    kani::cover!(
        has_private_member && member_count == 5 && has_x && has_y,
        "an extra private scalar"
    );
    kani::cover!(
        has_private_member && member_count == 4 && !has_y && !has_other_member,
        "private scalar replacing a public member"
    );
    kani::cover!(
        !x_is_string && has_x && member_count == 4 && !has_private_member && !has_other_member,
        "non-string coordinate"
    );
}

#[kani::proof]
#[kani::unwind(10)]
#[cfg(feature = "native")]
fn ephemeral_key_requires_resolver_curve_and_exact_coordinate_widths() {
    let (expected, name, width) = match kani::any::<u8>() {
        0 => (EphemeralCurve::P256, b"P-256", 32),
        1 => (EphemeralCurve::P384, b"P-384", 48),
        _ => (EphemeralCurve::P521, b"P-521", 66),
    };
    // Symbolic bytes cover every five-byte name. Include a longer unsupported
    // name to exercise the length mismatch in the identity comparison.
    let curve_bytes = kani::any::<[u8; 5]>();
    let full_name = kani::any::<bool>();
    let curve = if full_name {
        curve_bytes.as_slice()
    } else {
        b"X25519"
    };
    let key_type = kani::any::<[u8; 2]>();
    let x_len = kani::any::<usize>();
    let y_len = kani::any::<usize>();
    let identity = expected.validate_identity(&key_type, curve);
    let lengths = expected.validate_coordinate_lengths(x_len, y_len);

    kani::assert(
        identity.is_ok() == (full_name && &curve_bytes == name && &key_type == b"EC"),
        "only the resolver's named EC curve is accepted",
    );
    kani::assert(
        lengths.is_ok() == (x_len == width && y_len == width),
        "both decoded coordinates must independently have the JWA width",
    );
    kani::assert(
        matches!(identity, Ok(()) | Err(JweError::InvalidKeyAgreementKey))
            && matches!(lengths, Ok(()) | Err(JweError::InvalidKeyAgreementKey)),
        "curve and width failures use the key-agreement input error",
    );
    kani::cover!(
        identity.is_ok() && lengths.is_ok() && width == 32,
        "P-256 full widths"
    );
    kani::cover!(
        identity.is_ok() && lengths.is_ok() && width == 48,
        "P-384 full widths"
    );
    kani::cover!(
        identity.is_ok() && lengths.is_ok() && width == 66,
        "P-521 full widths"
    );
    kani::cover!(
        identity.is_err() && lengths.is_ok() && !full_name && &key_type == b"EC",
        "unsupported curve with correct widths"
    );
    kani::cover!(
        identity.is_err()
            && lengths.is_ok()
            && full_name
            && curve_bytes == *b"P-384"
            && width == 32
            && &key_type == b"EC",
        "different supported curve"
    );
    kani::cover!(
        identity.is_ok() && lengths.is_err() && x_len < width && y_len == width,
        "short x with full-width y"
    );
    kani::cover!(
        identity.is_ok() && lengths.is_err() && x_len == width && y_len > width,
        "long y with full-width x"
    );
}

#[kani::proof]
fn agreement_requires_successful_ephemeral_key_validation() {
    let present = kani::any::<bool>();
    let valid = kani::any::<bool>();
    let peer_key = kani::any::<u8>();
    let decoded = Cell::new(false);
    let agreed = Cell::new(false);

    let result = agree_with_validated_ephemeral_key(
        present.then_some(&peer_key),
        |input| {
            decoded.set(true);
            if valid {
                Ok(*input)
            } else {
                Err(JweError::InvalidKeyAgreementKey)
            }
        },
        |public_key| {
            kani::assert(
                decoded.get() && valid,
                "agreement follows successful validation",
            );
            kani::assert(
                public_key == peer_key,
                "agreement receives the validated key",
            );
            agreed.set(true);
            Ok(())
        },
    );
    kani::assert(
        decoded.get() == present,
        "only a present key can be decoded",
    );
    kani::assert(
        agreed.get() == (present && valid) && result.is_ok() == agreed.get(),
        "a missing or rejected key cannot reach agreement",
    );

    kani::cover!(
        !present && matches!(result, Err(JweError::MissingRequiredHeaderParameter)),
        "missing ephemeral key"
    );
    kani::cover!(
        present
            && decoded.get()
            && !agreed.get()
            && matches!(result, Err(JweError::InvalidKeyAgreementKey)),
        "validation rejects a present key"
    );
    kani::cover!(
        result.is_ok() && agreed.get(),
        "valid key reaches agreement"
    );
}
