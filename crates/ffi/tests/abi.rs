// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for the exported JOSE C ABI contract.

#![allow(unsafe_code)]

#[path = "abi/jwe_response_width.rs"]
mod jwe_response_width;

#[path = "abi/pointer_rejection.rs"]
mod pointer_rejection;

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
    jwe_response_width::exercise_randomized_jwe_matrix();
}

#[test]
#[allow(clippy::unwrap_used)]
fn capacity_mismatch_reports_exact_length_without_modifying_output() {
    use reallyme_crypto::csprng::OsSecureRandom;
    use reallyme_jose::wire::execute_operation_v1;

    let json = br#"{"jwtEncodeUnsigned":{"claimsJson":"e30="}}"#;
    let request = decode_json::<JoseOperationRequest>(json).unwrap();
    let binary = encode_protobuf(&request);
    let routes: [(ExecuteOperation, &[u8]); 2] = [
        (rm_jose_execute_operation_v1, &binary),
        (rm_jose_execute_operation_json_v1, json),
    ];
    let expected = execute_operation_v1(&binary, &mut OsSecureRandom);
    let required = expected.len();
    let short = required.checked_sub(1).unwrap();
    assert!(short > 0);

    for (operation, input) in routes {
        for capacity in [0, short, required, required.checked_add(17).unwrap()] {
            let original = vec![0xa5_u8; capacity.checked_add(8).unwrap()];
            let mut output = original.clone();
            let mut reported = usize::MAX;
            let mut expected_output = original;
            let expected_status = if capacity < required {
                JoseFfiStatus::OutputCapacityMismatch
            } else {
                expected_output
                    .get_mut(..required)
                    .unwrap()
                    .copy_from_slice(&expected);
                JoseFfiStatus::Success
            };

            let output_ptr = if capacity == 0 {
                core::ptr::null_mut()
            } else {
                output.as_mut_ptr()
            };
            // SAFETY: Each nonempty region is a live disjoint allocation.
            // The last eight output bytes are outside the advertised capacity.
            let status = unsafe {
                operation(
                    JOSE_ABI_VERSION,
                    input.as_ptr(),
                    input.len(),
                    output_ptr,
                    capacity,
                    &mut reported,
                )
            };
            assert_eq!(status, expected_status.code());
            assert_eq!(reported, required);
            assert_eq!(output, expected_output);
        }
    }
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
#[allow(clippy::unwrap_used)]
fn oversized_sentinel_preserves_resource_limit_but_larger_input_is_rejected() {
    use reallyme_jose::wire::proto::proto::reallyme::jose::v1::{
        __buffa::oneof::{jose_error::Error, jose_operation_response::Response},
        JoseErrorReason,
    };

    let entrypoints: [(ExecuteOperation, usize); 2] = [
        (rm_jose_execute_operation_v1, rm_jose_max_request_bytes()),
        (
            rm_jose_execute_operation_json_v1,
            rm_jose_max_json_request_bytes(),
        ),
    ];
    for (operation, maximum) in entrypoints {
        let sentinel = vec![0_u8; maximum.checked_add(1).unwrap()];
        let response = execute(operation, &sentinel);
        let decoded = decode_operation_response_v1(&response, JoseOperationKind::JwsSign).unwrap();
        assert!(
            matches!(&decoded.response, Some(Response::BoundaryError(boundary))
            if matches!(&boundary.error, Some(Error::Primitive(error))
                if error.reason == JoseErrorReason::JOSE_ERROR_REASON_COMMON_RESOURCE_LIMIT_EXCEEDED))
        );

        let rejected = vec![0_u8; maximum.checked_add(2).unwrap()];
        let mut produced = usize::MAX;
        let mut output = [0xa5_u8; 32];
        // SAFETY: All storage is valid and disjoint. The request length is
        // deliberately above the largest length accepted by this export.
        let status = unsafe {
            operation(
                JOSE_ABI_VERSION,
                rejected.as_ptr(),
                rejected.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut produced,
            )
        };
        assert_eq!(status, JoseFfiStatus::CallerError.code());
        assert_eq!(produced, usize::MAX);
        assert_eq!(output, [0xa5; 32]);
    }
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
