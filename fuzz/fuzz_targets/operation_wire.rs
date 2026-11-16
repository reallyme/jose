// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz canonical protobuf and ProtoJSON execution boundaries.

#![no_main]

mod operation_kinds;

use libfuzzer_sys::fuzz_target;
use operation_kinds::operation_kinds;
use reallyme_crypto::core::{CryptoError, RngOutputKind};
use reallyme_crypto::csprng::SecureRandom;
use reallyme_jose::wire::{
    decode_operation_response_v1, execute_operation_json_v1, execute_operation_v1,
    MAX_JOSE_PROTO_MESSAGE_BYTES, MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES,
};

const FORMAT_JSON_MASK: u8 = 0x01;

struct FuzzRandom {
    seed: u8,
}

impl SecureRandom for FuzzRandom {
    fn fill_secure(
        &mut self,
        output: &mut [u8],
        _output_kind: RngOutputKind,
    ) -> Result<(), CryptoError> {
        for (index, byte) in output.iter_mut().enumerate() {
            let offset = match u8::try_from(index % 251) {
                Ok(value) => value,
                Err(_) => return Err(CryptoError::PRIMITIVE_INVALID_LENGTH),
            };
            *byte = self.seed.wrapping_add(offset);
        }
        Ok(())
    }
}

fn validate_trusted_canonical_response(response: &[u8]) {
    let Some(maximum_response_bytes) =
        MAX_JOSE_PROTO_MESSAGE_BYTES.checked_add(MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES)
    else {
        return;
    };
    if response.len() > maximum_response_bytes {
        std::process::abort();
    }

    // A boundary error is valid for every expected operation. Once request
    // decoding selected an operation, exactly that operation must accept the
    // response. A response produced by the trusted processor must never be
    // rejected by every canonical decoder path.
    let operations = operation_kinds();
    let accepted_operations = operations
        .iter()
        .filter(|operation| decode_operation_response_v1(response, **operation).is_ok())
        .count();
    if accepted_operations != 1 && accepted_operations != operations.len() {
        std::process::abort();
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let mut rng = FuzzRandom { seed: selector };
    match selector & FORMAT_JSON_MASK != 0 {
        false => {
            let response = execute_operation_v1(body, &mut rng);
            validate_trusted_canonical_response(&response);
        }
        true => {
            let response = execute_operation_json_v1(body, &mut rng);
            validate_trusted_canonical_response(&response);
        }
    }
});
