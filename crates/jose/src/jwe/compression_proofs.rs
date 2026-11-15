// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{checked_decompressed_length, JweError, MAX_DECOMPRESSED_JWE_BYTES};

#[kani::proof]
fn decompressed_length_enforces_ceiling_without_wraparound() {
    let produced = kani::any::<usize>();
    let emitted = kani::any::<usize>();
    let result = checked_decompressed_length(produced, emitted);

    // Express both limits as remaining space so the specification does not
    // share the implementation's addition or overflow behavior.
    let representable = usize::MAX
        .checked_sub(produced)
        .is_some_and(|remaining| emitted <= remaining);
    let within_limit = MAX_DECOMPRESSED_JWE_BYTES
        .checked_sub(produced)
        .is_some_and(|remaining| emitted <= remaining);

    if within_limit {
        kani::assert(
            result.as_ref().is_ok_and(|length| {
                *length <= MAX_DECOMPRESSED_JWE_BYTES
                    && length.checked_sub(produced) == Some(emitted)
            }),
            "successful append accounts for every byte and stays within the limit",
        );
    } else if representable {
        kani::assert(
            matches!(result, Err(JweError::DecompressedPlaintextTooLarge)),
            "a representable length above the limit is rejected",
        );
    } else {
        kani::assert(
            matches!(result, Err(JweError::LengthOverflow)),
            "an overflowing append is rejected before allocating",
        );
    }

    kani::cover!(
        matches!(result, Ok(MAX_DECOMPRESSED_JWE_BYTES)) && produced > 0 && emitted > 0,
        "append reaches the exact output ceiling"
    );
    kani::cover!(
        produced == MAX_DECOMPRESSED_JWE_BYTES
            && emitted == 1
            && matches!(result, Err(JweError::DecompressedPlaintextTooLarge)),
        "one byte past the output ceiling"
    );
    kani::cover!(
        matches!(result, Err(JweError::LengthOverflow)),
        "length addition overflows usize"
    );
}
