// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the exported JOSE C ABI contract.

#![allow(unsafe_code)]

use reallyme_jose::wire::{
    decode_json, decode_operation_response_v1, encode_protobuf,
    proto::proto::reallyme::jose::v1::JoseOperationRequest, JoseOperationKind,
    MAX_JOSE_PROTO_JSON_BYTES, MAX_JOSE_PROTO_MESSAGE_BYTES,
    MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES,
};
use reallyme_jose_ffi::status::JoseFfiStatus;
use reallyme_jose_ffi::{
    rm_jose_abi_version, rm_jose_execute_operation_json_v1, rm_jose_execute_operation_v1,
    rm_jose_max_json_request_bytes, rm_jose_max_request_bytes, rm_jose_max_response_bytes,
    rm_jose_zeroize_buffer, JOSE_ABI_VERSION,
};

type ExecuteOperation =
    unsafe extern "C" fn(u32, *const u8, usize, *mut u8, usize, *mut usize) -> i32;

const OPERATIONS: [(JoseOperationKind, &[u8]); 8] = [
    (JoseOperationKind::JwsSign, br#"{"jwsSign":{}}"#),
    (JoseOperationKind::JwsVerify, br#"{"jwsVerify":{}}"#),
    (
        JoseOperationKind::JwtEncodeUnsigned,
        br#"{"jwtEncodeUnsigned":{}}"#,
    ),
    (
        JoseOperationKind::JwtDecodeUnsigned,
        br#"{"jwtDecodeUnsigned":{}}"#,
    ),
    (JoseOperationKind::JwtSign, br#"{"jwtSign":{}}"#),
    (JoseOperationKind::JwtVerify, br#"{"jwtVerify":{}}"#),
    (JoseOperationKind::JweEncrypt, br#"{"jweEncrypt":{}}"#),
    (JoseOperationKind::JweDecrypt, br#"{"jweDecrypt":{}}"#),
];

const RANDOMIZED_JWE_ENCRYPT_REQUEST: &[u8] = br#"{
  "jweEncrypt": {
    "keyManagementAlgorithm": "JOSE_JWE_KEY_MANAGEMENT_ALGORITHM_DIRECT",
    "contentEncryptionAlgorithm": "JOSE_JWE_CONTENT_ENCRYPTION_ALGORITHM_A128GCM",
    "key": "AAAAAAAAAAAAAAAAAAAAAA==",
    "plaintext": "cHJvYmU="
  }
}"#;

fn execute(operation: ExecuteOperation, input: &[u8]) -> Vec<u8> {
    execute_with_lengths(operation, input).0
}

fn execute_with_lengths(operation: ExecuteOperation, input: &[u8]) -> (Vec<u8>, usize, usize) {
    let mut required = usize::MAX;
    // SAFETY: Input and produced-length storage are live and disjoint. A null
    // output pointer is valid for the zero-capacity sizing call.
    let probe = unsafe {
        operation(
            JOSE_ABI_VERSION,
            input.as_ptr(),
            input.len(),
            core::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    assert_eq!(
        probe,
        JoseFfiStatus::OutputCapacityMismatch.code(),
        "unexpected sizing status"
    );
    assert!(required > 0);

    let mut output = vec![0_u8; required];
    let mut produced = usize::MAX;
    // SAFETY: Input, output, and produced-length storage are distinct live
    // allocations with the exact capacities passed to the boundary.
    let status = unsafe {
        operation(
            JOSE_ABI_VERSION,
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut produced,
        )
    };
    assert_eq!(status, JoseFfiStatus::Success.code());
    assert_eq!(produced, required);
    output.truncate(produced);
    (output, required, produced)
}

#[test]
fn version_and_limits_are_exported_from_rust() {
    assert_eq!(rm_jose_abi_version(), JOSE_ABI_VERSION);
    assert_eq!(rm_jose_max_request_bytes(), MAX_JOSE_PROTO_MESSAGE_BYTES);
    assert_eq!(rm_jose_max_json_request_bytes(), MAX_JOSE_PROTO_JSON_BYTES);
    assert_eq!(
        rm_jose_max_response_bytes(),
        MAX_JOSE_PROTO_MESSAGE_BYTES + MAX_JOSE_PROTO_RESPONSE_OVERHEAD_BYTES
    );
}

#[test]
fn binary_and_proto_json_routes_match_for_every_operation() {
    for (operation, json) in OPERATIONS {
        let request = decode_json::<JoseOperationRequest>(json);
        assert!(request.is_ok());
        let Some(request) = request.ok() else {
            continue;
        };
        let binary_request = encode_protobuf(&request);
        let binary_response = execute(rm_jose_execute_operation_v1, &binary_request);
        let json_response = execute(rm_jose_execute_operation_json_v1, json);
        assert_eq!(binary_response, json_response);
        assert!(decode_operation_response_v1(&binary_response, operation).is_ok());
    }
}

#[test]
fn probe_and_write_lengths_match_for_every_operation() {
    for (_, json) in OPERATIONS {
        let request = decode_json::<JoseOperationRequest>(json);
        assert!(request.is_ok());
        let Some(request) = request.ok() else {
            continue;
        };
        let binary_request = encode_protobuf(&request);

        let (_, binary_probe_len, binary_write_len) =
            execute_with_lengths(rm_jose_execute_operation_v1, &binary_request);
        assert_eq!(binary_probe_len, binary_write_len);

        let (_, json_probe_len, json_write_len) =
            execute_with_lengths(rm_jose_execute_operation_json_v1, json);
        assert_eq!(json_probe_len, json_write_len);
    }
}

#[test]
fn probe_and_write_lengths_match_for_randomized_jwe() {
    let request = decode_json::<JoseOperationRequest>(RANDOMIZED_JWE_ENCRYPT_REQUEST);
    assert!(request.is_ok());
    let Some(request) = request.ok() else {
        return;
    };
    let binary_request = encode_protobuf(&request);

    let (_, binary_probe_len, binary_write_len) =
        execute_with_lengths(rm_jose_execute_operation_v1, &binary_request);
    assert_eq!(binary_probe_len, binary_write_len);

    let (_, json_probe_len, json_write_len) = execute_with_lengths(
        rm_jose_execute_operation_json_v1,
        RANDOMIZED_JWE_ENCRYPT_REQUEST,
    );
    assert_eq!(json_probe_len, json_write_len);
}

#[test]
fn capacity_mismatch_reports_exact_length_without_modifying_output() {
    let input = br#"{}"#;
    let mut output = [0xa5_u8; 1];
    let mut required = usize::MAX;
    // SAFETY: All three storage regions are valid and disjoint.
    let status = unsafe {
        rm_jose_execute_operation_json_v1(
            JOSE_ABI_VERSION,
            input.as_ptr(),
            input.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut required,
        )
    };
    assert_eq!(status, JoseFfiStatus::OutputCapacityMismatch.code());
    assert!(required > output.len());
    assert_eq!(output, [0xa5]);
}

#[test]
fn unsupported_abi_and_invalid_pointer_fail_with_zero_length() {
    let input = br#"{}"#;
    let mut produced = usize::MAX;
    // SAFETY: Input and produced-length storage are valid; output is the
    // permitted null/zero pair.
    let unsupported = unsafe {
        rm_jose_execute_operation_json_v1(
            JOSE_ABI_VERSION + 1,
            input.as_ptr(),
            input.len(),
            core::ptr::null_mut(),
            0,
            &mut produced,
        )
    };
    assert_eq!(unsupported, JoseFfiStatus::UnsupportedAbi.code());
    assert_eq!(produced, 0);

    produced = usize::MAX;
    // SAFETY: The deliberately invalid null/nonzero input pair is rejected
    // before dereference; produced-length storage is valid.
    let invalid = unsafe {
        rm_jose_execute_operation_v1(
            JOSE_ABI_VERSION,
            core::ptr::null(),
            1,
            core::ptr::null_mut(),
            0,
            &mut produced,
        )
    };
    assert_eq!(invalid, JoseFfiStatus::CallerError.code());
    assert_eq!(produced, usize::MAX);
}

#[test]
fn overlapping_input_and_output_are_rejected_before_mutation() {
    let mut shared = br#"{}"#.to_vec();
    let original = shared.clone();
    let mut produced = usize::MAX;
    // SAFETY: The alias is deliberate and points into one live allocation;
    // the boundary rejects it before constructing Rust references.
    let status = unsafe {
        rm_jose_execute_operation_json_v1(
            JOSE_ABI_VERSION,
            shared.as_ptr(),
            shared.len(),
            shared.as_mut_ptr(),
            shared.len(),
            &mut produced,
        )
    };
    assert_eq!(status, JoseFfiStatus::CallerError.code());
    assert_eq!(produced, usize::MAX);
    assert_eq!(shared, original);
}

#[test]
fn oversized_sentinel_preserves_resource_limit_but_larger_input_is_rejected() {
    let sentinel = vec![0_u8; MAX_JOSE_PROTO_MESSAGE_BYTES + 1];
    let response = execute(rm_jose_execute_operation_v1, &sentinel);
    assert!(decode_operation_response_v1(&response, JoseOperationKind::JwsSign).is_ok());

    let rejected = vec![0_u8; MAX_JOSE_PROTO_MESSAGE_BYTES + 2];
    let mut produced = usize::MAX;
    // SAFETY: Input and produced-length storage are valid and disjoint.
    let status = unsafe {
        rm_jose_execute_operation_v1(
            JOSE_ABI_VERSION,
            rejected.as_ptr(),
            rejected.len(),
            core::ptr::null_mut(),
            0,
            &mut produced,
        )
    };
    assert_eq!(status, JoseFfiStatus::CallerError.code());
    assert_eq!(produced, 0);
}

#[test]
fn zeroize_export_clears_exact_caller_owned_range() {
    let mut bytes = [0x5a_u8; 32];
    // SAFETY: The array is exclusively writable for its full length.
    let status =
        unsafe { rm_jose_zeroize_buffer(JOSE_ABI_VERSION, bytes.as_mut_ptr(), bytes.len()) };
    assert_eq!(status, JoseFfiStatus::Success.code());
    assert_eq!(bytes, [0_u8; 32]);
}

#[test]
fn zeroize_export_rejects_wrapping_address_range() {
    let wrapping = core::ptr::without_provenance_mut::<u8>(usize::MAX);
    // SAFETY: This deliberately invalid address range is rejected by the
    // shared validator before a mutable slice is constructed or memory is
    // accessed.
    let status = unsafe { rm_jose_zeroize_buffer(JOSE_ABI_VERSION, wrapping, 2) };
    assert_eq!(status, JoseFfiStatus::CallerError.code());
}

#[test]
fn concurrent_calls_have_independent_outputs() {
    let mut threads = Vec::new();
    for (_, json) in OPERATIONS {
        let owned = json.to_vec();
        threads.push(std::thread::spawn(move || {
            execute(rm_jose_execute_operation_json_v1, &owned)
        }));
    }
    for thread in threads {
        let result = thread.join();
        assert!(result.is_ok());
        assert!(result.is_ok_and(|bytes| !bytes.is_empty()));
    }
}
