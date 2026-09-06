// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::measure_encoding::base64url_len;

#[test]
fn accounts_for_unpadded_tails_and_overflow() {
    for (input, expected) in [(0, 0), (1, 2), (2, 3), (3, 4), (4, 6), (5, 7)] {
        assert_eq!(base64url_len(input), Some(expected));
    }
    assert_eq!(base64url_len(usize::MAX), None);
}

#[test]
fn measured_lengths_match_the_codec() {
    let bytes = [0_u8; 4096];
    for length in 0..=bytes.len() {
        let (input, _) = bytes.split_at(length);
        assert_eq!(
            base64url_len(length),
            Some(reallyme_codec::base64url::bytes_to_base64url(input).len())
        );
    }
}
