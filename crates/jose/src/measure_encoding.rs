// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checked size calculations performed before allocating encoded input.

pub(crate) fn base64url_len(length: usize) -> Option<usize> {
    let tail = match length.checked_rem(3)? {
        0 => 0,
        1 => 2,
        _ => 3,
    };
    length.checked_div(3)?.checked_mul(4)?.checked_add(tail)
}
