// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;

use reallyme_jose::wire::{decode_operation_response_v1, JoseOperationKind};

use super::{transfer_c_response, JoseFfiStatus, JoseOwnedResponse, JOSE_ABI_VERSION};
use crate::operation::rm_jose_abi_version;
use crate::owned_response::rm_jose_execute_owned_operation_json_v1;

#[test]
fn jni_and_c_abi_versions_are_identical() {
    assert_eq!(rm_jose_abi_version(), JOSE_ABI_VERSION);
}

thread_local! {
    static EXECUTIONS: Cell<usize> = const { Cell::new(0) };
}

unsafe extern "C" fn count_json_execution(
    version: u32,
    request: *const u8,
    len: usize,
    slot: *mut *mut JoseOwnedResponse,
) -> i32 {
    let first = EXECUTIONS.replace(1) == 0;
    if !first {
        return JoseFfiStatus::CallerError.code();
    }
    // SAFETY: The JNI adapter supplied valid disjoint request and owner slots.
    unsafe { rm_jose_execute_owned_operation_json_v1(version, request, len, slot) }
}

#[test]
fn jni_transfers_one_complete_response() {
    EXECUTIONS.set(0);
    let response = transfer_c_response(
        br#"{"jwtEncodeUnsigned":{"claimsJson":"e30="}}"#,
        count_json_execution,
    );
    assert!(response.is_ok());
    if let Ok(response) = response {
        assert!(decode_operation_response_v1(
            response.as_bytes().unwrap_or_default(),
            JoseOperationKind::JwtEncodeUnsigned
        )
        .is_ok());
    }
    assert_eq!(EXECUTIONS.get(), 1);
}
