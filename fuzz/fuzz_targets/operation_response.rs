// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Fuzz the untrusted canonical operation-response decoder.

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_jose::wire::{decode_operation_response_v1, JoseOperationKind};

const OPERATION_SELECTOR_MASK: u8 = 0x07;
const HEX_INPUT_MASK: u8 = 0x08;
const OPERATION_KINDS: [JoseOperationKind; 8] = [
    JoseOperationKind::JwsSign,
    JoseOperationKind::JwsVerify,
    JoseOperationKind::JwtEncodeUnsigned,
    JoseOperationKind::JwtDecodeUnsigned,
    JoseOperationKind::JwtSign,
    JoseOperationKind::JwtVerify,
    JoseOperationKind::JweEncrypt,
    JoseOperationKind::JweDecrypt,
];

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

fn assert_decoder_consistency(response: &[u8]) {
    let accepted_operations = OPERATION_KINDS
        .iter()
        .filter(|operation| decode_operation_response_v1(response, **operation).is_ok())
        .count();

    // Malformed responses are rejected for every operation, a valid selected
    // operation is accepted once, and a valid boundary error is accepted for
    // all operations. No other acceptance cardinality is meaningful.
    assert!(matches!(accepted_operations, 0 | 1 | 8));
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let selected_index = usize::from(selector & OPERATION_SELECTOR_MASK);
    let selected_operation = OPERATION_KINDS[selected_index];

    if selector & HEX_INPUT_MASK != 0 {
        let Some(decoded) = decode_hex(body) else {
            return;
        };
        let _ = decode_operation_response_v1(&decoded, selected_operation);
        assert_decoder_consistency(&decoded);
    } else {
        let _ = decode_operation_response_v1(body, selected_operation);
        assert_decoder_consistency(body);
    }
});
