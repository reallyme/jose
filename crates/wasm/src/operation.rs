// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Canonical generated-operation adapter for the TypeScript package.

use js_sys::Uint8Array;
use reallyme_crypto::csprng::OsSecureRandom;
use reallyme_jose::wire::{
    execute_operation_json_v1, execute_operation_v1, MAX_JOSE_PROTO_JSON_BYTES,
    MAX_JOSE_PROTO_MESSAGE_BYTES,
};
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroizing;

#[wasm_bindgen(js_name = executeOperation)]
/// Execute one binary `JoseOperationRequest` and return a binary response.
#[must_use]
pub fn execute_operation(request: &Uint8Array) -> Uint8Array {
    let request = bounded_request(request, MAX_JOSE_PROTO_MESSAGE_BYTES);
    let mut random = OsSecureRandom;
    let response = execute_operation_v1(request.as_slice(), &mut random);
    Uint8Array::from(response.as_slice())
}

#[wasm_bindgen(js_name = executeOperationJson)]
/// Execute one generated ProtoJSON request and return a binary response.
#[must_use]
pub fn execute_operation_json(request: &Uint8Array) -> Uint8Array {
    let request = bounded_request(request, MAX_JOSE_PROTO_JSON_BYTES);
    let mut random = OsSecureRandom;
    let response = execute_operation_json_v1(request.as_slice(), &mut random);
    Uint8Array::from(response.as_slice())
}

fn bounded_request(request: &Uint8Array, maximum: usize) -> Zeroizing<Vec<u8>> {
    let request_length = match usize::try_from(request.length()) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    };
    if request_length <= maximum {
        return Zeroizing::new(request.to_vec());
    }

    // Route oversized input through the canonical Rust decoder without first
    // copying attacker-controlled bytes into the WASM linear memory.
    let Some(sentinel_length) = maximum.checked_add(1) else {
        return Zeroizing::new(Vec::new());
    };
    Zeroizing::new(vec![0_u8; sentinel_length])
}
