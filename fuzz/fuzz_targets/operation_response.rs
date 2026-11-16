// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz the untrusted canonical operation-response decoder.

#![no_main]

mod operation_kinds;

use libfuzzer_sys::fuzz_target;
use operation_kinds::operation_kinds;
use reallyme_jose::wire::decode_operation_response_v1;

const HEX_INPUT_MASK: u8 = 0x08;

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(input: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(input.len() / 2);
    let mut high_nibble = None;
    for byte in input {
        if byte.is_ascii_whitespace() {
            continue;
        }
        let nibble = decode_hex_nibble(*byte)?;
        match high_nibble.take() {
            Some(high) => decoded.push((high << 4) | nibble),
            None => high_nibble = Some(nibble),
        }
    }
    if high_nibble.is_none() {
        Some(decoded)
    } else {
        None
    }
}

fn validate_decoder_consistency(response: &[u8]) {
    let operations = operation_kinds();
    let accepted_operations = operations
        .iter()
        .filter(|operation| decode_operation_response_v1(response, **operation).is_ok())
        .count();

    // Malformed responses are rejected for every operation, a valid selected
    // operation is accepted once, and a valid boundary error is accepted for
    // all operations. No other acceptance cardinality is meaningful.
    if !matches!(accepted_operations, 0 | 1) && accepted_operations != operations.len() {
        std::process::abort();
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };

    if selector & HEX_INPUT_MASK != 0 {
        let Some(decoded) = decode_hex(body) else {
            return;
        };
        validate_decoder_consistency(&decoded);
    } else {
        validate_decoder_consistency(body);
    }
});
