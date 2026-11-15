// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ec_keys::{check_coordinate_encoding, ephemeral_coordinates, is_unescaped_base64url},
    measure_compact_jwe, validate_gcm_output_len, JweContentEncryptionAlgorithm, JweError,
};
use crate::jwe::parse_compact::MAX_COMPACT_JWE_BYTES;
use crate::jwe::validate_ephemeral_key::EphemeralCurve;

#[kani::proof]
fn base64url_coordinate_alphabet_never_requires_json_escaping() {
    let byte = kani::any::<u8>();
    let admitted = is_unescaped_base64url(byte);
    let expected = (b'a'..=b'z').contains(&byte)
        || (b'A'..=b'Z').contains(&byte)
        || (b'0'..=b'9').contains(&byte)
        || matches!(byte, b'-' | b'_');
    kani::assert(
        admitted == expected,
        "only the Base64URL alphabet is accepted",
    );
    kani::assert(
        !admitted || ((0x20..=0x7e).contains(&byte) && !matches!(byte, b'"' | b'\\')),
        "accepted bytes serialize without JSON escapes",
    );
    kani::cover!(admitted, "Base64URL character");
    kani::cover!(!admitted && byte == b'"', "escaped JSON delimiter rejected");
}

#[kani::proof]
#[kani::unwind(5)]
fn accepted_coordinate_encoding_keeps_its_width_and_uses_only_safe_bytes() {
    let token = kani::any::<[u8; 4]>();
    let len = kani::any_where(|len: &usize| *len <= 4);
    let width = kani::any::<usize>();
    let Some(token) = token
        .get(..len)
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
    else {
        return;
    };
    let result = check_coordinate_encoding(width, token);
    if result.is_ok() {
        kani::assert(
            encoded_width(width) == Some(len),
            "accepted string has the exact width",
        );
        kani::assert(
            token.bytes().all(is_unescaped_base64url),
            "every accepted byte is JSON safe",
        );
    }
    kani::cover!(
        result.is_ok() && width == 3,
        "a full Base64URL quantum passes"
    );
    kani::cover!(
        matches!(result, Err(JweError::InvalidEncoding)),
        "invalid coordinate representation"
    );
}

#[kani::proof]
fn ephemeral_coordinates_have_the_curve_width_for_all_point_bytes() {
    let curve = match kani::any::<u8>() {
        0 => EphemeralCurve::P256,
        #[cfg(feature = "native")]
        1 => EphemeralCurve::P384,
        #[cfg(feature = "native")]
        _ => EphemeralCurve::P521,
        #[cfg(not(feature = "native"))]
        _ => EphemeralCurve::P256,
    };
    let sec1 = kani::any::<[u8; 133]>();
    let (expected, end) = match curve {
        EphemeralCurve::P256 => (32, 65),
        #[cfg(feature = "native")]
        EphemeralCurve::P384 => (48, 97),
        #[cfg(feature = "native")]
        EphemeralCurve::P521 => (66, 133),
    };
    let Some(point) = sec1.get(..end) else {
        kani::assert(false, "the array can hold every supported curve");
        return;
    };
    match ephemeral_coordinates(point, curve) {
        Ok((x, y)) => {
            kani::assert(
                x.len() == expected && y.len() == expected,
                "fresh coordinates keep the same width",
            );
            // Compare addresses so the proof also checks that no leading byte
            // can be omitted by trimming the encoded coordinate.
            kani::assert(
                x.as_ptr() == point.as_ptr().wrapping_add(1),
                "x starts after the SEC1 tag",
            );
            kani::assert(
                y.as_ptr() == x.as_ptr().wrapping_add(expected),
                "y starts immediately after x",
            );
        }
        Err(_) => kani::assert(false, "a complete SEC1 point has both coordinates"),
    }
    kani::cover!(expected == 32, "P-256");
    #[cfg(feature = "native")]
    kani::cover!(expected == 48, "P-384");
    #[cfg(feature = "native")]
    kani::cover!(expected == 66, "P-521");
}

// The width of the deterministic part includes the JSON syntax and all
// request fields. Both coordinates have the fixed width established above.
fn encoded_width(length: usize) -> Option<usize> {
    length.checked_mul(4)?.checked_add(2)?.checked_div(3)
}

#[kani::proof]
#[kani::unwind(7)]
fn compact_width_matches_the_fixed_json_and_gcm_segment_widths() {
    let enc = match kani::any::<u8>() {
        0 => JweContentEncryptionAlgorithm::A128Gcm,
        1 => JweContentEncryptionAlgorithm::A192Gcm,
        _ => JweContentEncryptionAlgorithm::A256Gcm,
    };
    let deterministic_header = kani::any::<usize>();
    let plaintext = kani::any::<usize>();
    kani::assume(
        deterministic_header <= MAX_COMPACT_JWE_BYTES && plaintext <= MAX_COMPACT_JWE_BYTES,
    );
    // Each request uses one key-management mode in both calls. The two
    // coordinate strings contribute 0 (dir), 86, 128, or 176 bytes.
    let epk_contribution = match kani::any::<u8>() {
        0 => 0,
        1 => 86,
        2 => 128,
        _ => 176,
    };
    let Some(header) = deterministic_header.checked_add(epk_contribution) else {
        kani::assert(false, "header width is bounded");
        return;
    };
    let expected = encoded_width(header)
        .and_then(|size| size.checked_add(encoded_width(plaintext)?))
        // The IV and tag encode to 16 and 22 bytes, with four separators.
        .and_then(|size| size.checked_add(42));
    let actual = measure_compact_jwe(header, 0, plaintext, enc);
    match expected {
        Some(size) if size <= MAX_COMPACT_JWE_BYTES => {
            kani::assert(
                matches!(actual, Ok(len) if len == size),
                "measure the exact compact length",
            );
        }
        Some(_) => kani::assert(
            matches!(actual, Err(JweError::InputTooLarge)),
            "the compact limit is precise",
        ),
        None => kani::assert(false, "bounded segment widths cannot overflow"),
    }
    kani::cover!(actual.is_ok() && epk_contribution == 0, "direct mode");
    kani::cover!(actual.is_ok() && epk_contribution != 0, "ECDH-ES mode");
    kani::cover!(
        matches!(actual, Err(JweError::InputTooLarge)),
        "compact exceeds the limit"
    );
}

#[kani::proof]
fn gcm_accepts_only_the_expected_ciphertext_and_tag_width() {
    let plaintext = kani::any::<usize>();
    let combined = kani::any::<usize>();
    let result = validate_gcm_output_len(plaintext, 16, combined);
    match combined.checked_sub(16) {
        Some(ciphertext) if ciphertext == plaintext => {
            kani::assert(
                matches!(result, Ok(len) if len == plaintext),
                "ciphertext width equals plaintext width",
            );
        }
        _ => kani::assert(result.is_err(), "reject every other backend output width"),
    }
    kani::cover!(result.is_ok(), "valid GCM result");
    kani::cover!(
        matches!(result, Err(JweError::Encrypt)),
        "incorrect backend width"
    );
    kani::cover!(
        matches!(result, Err(JweError::LengthOverflow)),
        "plaintext plus tag overflows"
    );
}
