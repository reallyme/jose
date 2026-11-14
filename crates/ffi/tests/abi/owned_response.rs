// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::ptr;

use reallyme_jose::wire::proto::proto::reallyme::jose::v1::__buffa::oneof::jose_operation_response::Response;
use reallyme_jose_ffi::{
    rm_jose_execute_owned_operation_json_v1, rm_jose_execute_owned_operation_v1,
    rm_jose_owned_response_release_v1, rm_jose_owned_response_view_v1, JoseOwnedResponse,
};

use super::{
    decode_json, decode_operation_response_v1, encode_protobuf, execute,
    rm_jose_execute_operation_json_v1, JoseFfiStatus, JoseOperationKind, JoseOperationRequest,
    JOSE_ABI_VERSION, OPERATIONS,
};

const REQUEST: &[u8] = br#"{"jwtEncodeUnsigned":{"claimsJson":"e30="}}"#;

#[derive(Default)]
struct ResponseOwner {
    slot: *mut JoseOwnedResponse,
}

impl ResponseOwner {
    fn release(&mut self) -> i32 {
        // SAFETY: The test owns the unique slot, and borrowing through bytes()
        // prevents release while an issued view is still used.
        unsafe { rm_jose_owned_response_release_v1(JOSE_ABI_VERSION, &mut self.slot) }
    }

    fn bytes(&self) -> &[u8] {
        let mut data = ptr::null();
        let mut len = 0;
        // SAFETY: self keeps the owner alive and the output slots are disjoint.
        let status = unsafe {
            rm_jose_owned_response_view_v1(JOSE_ABI_VERSION, self.slot, &mut data, &mut len)
        };
        assert_eq!(status, JoseFfiStatus::Success.code());
        assert!(!data.is_null());
        assert!(len > 0);
        // SAFETY: A successful view names the immutable response prefix.
        // The returned borrow ends before this owner can be released.
        unsafe { core::slice::from_raw_parts(data, len) }
    }
}

impl Drop for ResponseOwner {
    fn drop(&mut self) {
        self.release();
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn owned_routes_return_the_same_canonical_bytes_for_every_operation() {
    for (kind, json) in OPERATIONS
        .into_iter()
        .chain([(JoseOperationKind::JwtEncodeUnsigned, REQUEST)])
    {
        let request = decode_json::<JoseOperationRequest>(json).unwrap();
        let binary = encode_protobuf(&request);
        let mut from_binary = ResponseOwner::default();
        let mut from_json = ResponseOwner::default();
        // SAFETY: The requests and initialized slots are live and disjoint.
        let binary_status = unsafe {
            rm_jose_execute_owned_operation_v1(
                JOSE_ABI_VERSION,
                binary.as_ptr(),
                binary.len(),
                &mut from_binary.slot,
            )
        };
        // SAFETY: The requests and initialized slots are live and disjoint.
        let json_status = unsafe {
            rm_jose_execute_owned_operation_json_v1(
                JOSE_ABI_VERSION,
                json.as_ptr(),
                json.len(),
                &mut from_json.slot,
            )
        };
        assert_eq!(binary_status, JoseFfiStatus::Success.code());
        assert_eq!(json_status, JoseFfiStatus::Success.code());
        assert_eq!(from_binary.bytes(), from_json.bytes());
        assert_eq!(
            from_json.bytes(),
            execute(rm_jose_execute_operation_json_v1, json)
        );
        assert!(decode_operation_response_v1(from_binary.bytes(), kind).is_ok());
        assert_ne!(from_binary.bytes().as_ptr(), from_json.bytes().as_ptr());
        assert_eq!(from_binary.release(), JoseFfiStatus::Success.code());
        assert!(from_binary.slot.is_null());
        assert_eq!(from_binary.release(), JoseFfiStatus::Success.code());
        assert!(decode_operation_response_v1(from_json.bytes(), kind).is_ok());
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn malformed_request_is_a_transport_success_with_a_typed_response() {
    let mut owner = ResponseOwner::default();
    let malformed = b"{";
    // SAFETY: The initialized slot and request are live and disjoint.
    let status = unsafe {
        rm_jose_execute_owned_operation_json_v1(
            JOSE_ABI_VERSION,
            malformed.as_ptr(),
            malformed.len(),
            &mut owner.slot,
        )
    };
    assert_eq!(status, JoseFfiStatus::Success.code());
    let response =
        decode_operation_response_v1(owner.bytes(), JoseOperationKind::JwtEncodeUnsigned).unwrap();
    assert!(matches!(
        response.response,
        Some(Response::BoundaryError(_))
    ));
}

#[test]
fn rejected_calls_preserve_the_existing_owner_and_view_outputs() {
    let mut owner = ResponseOwner::default();
    // SAFETY: The initialized slot and request are live and disjoint.
    let create = unsafe {
        rm_jose_execute_owned_operation_json_v1(
            JOSE_ABI_VERSION,
            REQUEST.as_ptr(),
            REQUEST.len(),
            &mut owner.slot,
        )
    };
    assert_eq!(create, JoseFfiStatus::Success.code());
    let original = owner.slot;
    let mut data = ptr::null();
    let mut len = usize::MAX;
    let data_slot = &raw mut data;

    // SAFETY: Every call uses live storage for non-null pointers. The output
    // alias and null cases are intentionally rejected during validation.
    let (overwrite, unsupported, aliased, null_output, bad_release) = unsafe {
        (
            rm_jose_execute_owned_operation_json_v1(
                JOSE_ABI_VERSION,
                REQUEST.as_ptr(),
                REQUEST.len(),
                &mut owner.slot,
            ),
            rm_jose_owned_response_view_v1(0, original, data_slot, &mut len),
            rm_jose_owned_response_view_v1(JOSE_ABI_VERSION, original, data_slot, data_slot.cast()),
            rm_jose_owned_response_view_v1(JOSE_ABI_VERSION, original, ptr::null_mut(), &mut len),
            rm_jose_owned_response_release_v1(0, &mut owner.slot),
        )
    };
    assert_eq!(overwrite, JoseFfiStatus::CallerError.code());
    assert_eq!(unsupported, JoseFfiStatus::UnsupportedAbi.code());
    assert_eq!(aliased, JoseFfiStatus::CallerError.code());
    assert_eq!(null_output, JoseFfiStatus::CallerError.code());
    assert_eq!(bad_release, JoseFfiStatus::UnsupportedAbi.code());
    assert_eq!(owner.slot, original);
    assert!(data.is_null());
    assert_eq!(len, usize::MAX);
    assert!(
        decode_operation_response_v1(owner.bytes(), JoseOperationKind::JwtEncodeUnsigned).is_ok()
    );
}

#[test]
fn invalid_execute_metadata_cannot_publish_an_owner() {
    let mut owner = ResponseOwner::default();
    let slot = &raw mut owner.slot;
    // SAFETY: The null, oversized and overlapping metadata is rejected before
    // any byte access. The actual slot is initialized and live.
    let (unsupported, null_request, oversized, overlapping, null_slot) = unsafe {
        (
            rm_jose_execute_owned_operation_v1(0, ptr::null(), 0, slot),
            rm_jose_execute_owned_operation_v1(JOSE_ABI_VERSION, ptr::null(), 1, slot),
            rm_jose_execute_owned_operation_v1(
                JOSE_ABI_VERSION,
                REQUEST.as_ptr(),
                usize::MAX,
                slot,
            ),
            rm_jose_execute_owned_operation_v1(JOSE_ABI_VERSION, slot.cast(), 1, slot),
            rm_jose_execute_owned_operation_v1(JOSE_ABI_VERSION, ptr::null(), 0, ptr::null_mut()),
        )
    };
    assert_eq!(unsupported, JoseFfiStatus::UnsupportedAbi.code());
    for status in [null_request, oversized, overlapping, null_slot] {
        assert_eq!(status, JoseFfiStatus::CallerError.code());
    }
    assert!(owner.slot.is_null());
}
