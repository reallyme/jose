// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! JNI bridge for the typed Kotlin/JVM JOSE facade.
//!
//! JNI owns only managed-array conversion and typed transport failures. Every
//! request is executed through the frozen C ABI so JVM and Swift cannot drift
//! onto a second semantic path.

// JNI pointer use is confined to this adapter and reviewed at each call site.
#![allow(unsafe_code)]

use std::ptr;

use jni::objects::{JByteArray, JObject};
use jni::sys::{jbyteArray, jint, jlong};
use jni::{EnvUnowned, Outcome};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::guard::catch_boundary_unwind;
use crate::operation::{
    rm_jose_abi_version, rm_jose_max_json_request_bytes, rm_jose_max_request_bytes,
    rm_jose_max_response_bytes, JOSE_ABI_VERSION,
};
use crate::owned_response::{
    rm_jose_execute_owned_operation_json_v1, rm_jose_execute_owned_operation_v1,
    rm_jose_owned_response_release_v1, rm_jose_owned_response_view_v1, JoseOwnedResponse,
};
use crate::pointer::read_slice;
use crate::status::JoseFfiStatus;

type ExecuteFunction =
    unsafe extern "C" fn(u32, *const u8, usize, *mut *mut JoseOwnedResponse) -> i32;

/// Verifies that the loaded native image contains the expected JNI exports.
#[unsafe(no_mangle)]
pub const extern "system" fn Java_me_really_jose_ReallyMeJoseNative_probeNative(
    _env: EnvUnowned<'_>,
    _receiver: JObject<'_>,
) -> jint {
    1
}

/// Returns the exact C ABI version implemented by this native image.
#[unsafe(no_mangle)]
pub extern "system" fn Java_me_really_jose_ReallyMeJoseNative_abiVersionNative(
    _env: EnvUnowned<'_>,
    _receiver: JObject<'_>,
) -> jint {
    jint::try_from(rm_jose_abi_version()).unwrap_or(-1)
}

/// Returns the authoritative binary request limit.
#[unsafe(no_mangle)]
pub extern "system" fn Java_me_really_jose_ReallyMeJoseNative_maxRequestBytesNative(
    _env: EnvUnowned<'_>,
    _receiver: JObject<'_>,
) -> jlong {
    jlong::try_from(rm_jose_max_request_bytes()).unwrap_or(-1)
}

/// Returns the authoritative ProtoJSON request limit.
#[unsafe(no_mangle)]
pub extern "system" fn Java_me_really_jose_ReallyMeJoseNative_maxJsonRequestBytesNative(
    _env: EnvUnowned<'_>,
    _receiver: JObject<'_>,
) -> jlong {
    jlong::try_from(rm_jose_max_json_request_bytes()).unwrap_or(-1)
}

/// Returns the authoritative canonical response limit.
#[unsafe(no_mangle)]
pub extern "system" fn Java_me_really_jose_ReallyMeJoseNative_maxResponseBytesNative(
    _env: EnvUnowned<'_>,
    _receiver: JObject<'_>,
) -> jlong {
    jlong::try_from(rm_jose_max_response_bytes()).unwrap_or(-1)
}

/// Executes one binary protobuf operation request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_me_really_jose_ReallyMeJoseNative_executeOperationNative<'local>(
    env: EnvUnowned<'local>,
    _receiver: JObject<'local>,
    request: JByteArray<'local>,
) -> jbyteArray {
    execute_operation(
        env,
        request,
        rm_jose_max_request_bytes(),
        rm_jose_execute_owned_operation_v1,
    )
}

/// Executes one generated ProtoJSON operation request.
#[unsafe(no_mangle)]
pub extern "system" fn Java_me_really_jose_ReallyMeJoseNative_executeOperationJsonNative<'local>(
    env: EnvUnowned<'local>,
    _receiver: JObject<'local>,
    request: JByteArray<'local>,
) -> jbyteArray {
    execute_operation(
        env,
        request,
        rm_jose_max_json_request_bytes(),
        rm_jose_execute_owned_operation_json_v1,
    )
}

fn execute_operation<'local>(
    mut env: EnvUnowned<'local>,
    request: JByteArray<'local>,
    maximum_request_bytes: usize,
    execute: ExecuteFunction,
) -> jbyteArray {
    let guarded_outcome = catch_boundary_unwind(|| {
        env.with_env(|env| -> jni::errors::Result<jbyteArray> {
            let request = bounded_request(env, request, maximum_request_bytes)?;
            let response = match transfer_c_response(request.as_slice(), execute) {
                Ok(response) => response,
                Err(failure) => {
                    return throw_provider_failure(env, failure);
                }
            };
            let bytes = match response.as_bytes() {
                Ok(bytes) => bytes,
                Err(failure) => return throw_provider_failure(env, failure),
            };
            env.byte_array_from_slice(bytes)
                .map(|array| array.into_raw())
        })
    });
    match guarded_outcome {
        Ok(outcome) => match outcome.into_outcome() {
            Outcome::Ok(value) => value,
            Outcome::Err(_) | Outcome::Panic(_) => {
                throw_provider_failure_if_clear(&mut env);
                ptr::null_mut()
            }
        },
        Err(_) => {
            throw_provider_failure_if_clear(&mut env);
            ptr::null_mut()
        }
    }
}

fn bounded_request<'local>(
    env: &mut jni::Env<'local>,
    request: JByteArray<'local>,
    maximum_request_bytes: usize,
) -> jni::errors::Result<Zeroizing<Vec<u8>>> {
    let request_len = match request.len(env) {
        Ok(value) => value,
        Err(_) => return throw_provider_failure(env, NativeProviderFailure),
    };
    if request_len > maximum_request_bytes {
        // Ask Rust to produce its canonical resource-limit response without
        // copying an attacker-sized managed array into native memory.
        let sentinel_len = match maximum_request_bytes.checked_add(1) {
            Some(value) => value,
            None => return throw_provider_failure(env, NativeProviderFailure),
        };
        return Ok(Zeroizing::new(vec![0_u8; sentinel_len]));
    }
    match env.convert_byte_array(&request) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(_) => throw_provider_failure(env, NativeProviderFailure),
    }
}

// Retain the C owner through the JVM copy. Dropping it on every return or
// unwind cleans the native allocation, including when the VM rejects a copy.
struct NativeResponse {
    owner: *mut JoseOwnedResponse,
    data: *const u8,
    len: usize,
}

impl NativeResponse {
    fn as_bytes(&self) -> Result<&[u8], NativeProviderFailure> {
        // SAFETY: transfer_c_response obtained this view from self.owner.
        // Its allocation is immutable and the borrow cannot outlive self.
        unsafe { read_slice(self.data, self.len) }.map_err(|_| NativeProviderFailure)
    }
}

impl Drop for NativeResponse {
    fn drop(&mut self) {
        // SAFETY: self owns the unique slot. All byte borrows ended before
        // this drop, and the slot remains valid through the release.
        unsafe { rm_jose_owned_response_release_v1(JOSE_ABI_VERSION, &mut self.owner) };
    }
}

fn transfer_c_response(
    request: &[u8],
    execute: ExecuteFunction,
) -> Result<NativeResponse, NativeProviderFailure> {
    let mut response = NativeResponse {
        owner: ptr::null_mut(),
        data: ptr::null(),
        len: 0,
    };
    // SAFETY: The request and initialized null slot are live and disjoint.
    let status = unsafe {
        execute(
            JOSE_ABI_VERSION,
            request.as_ptr(),
            request.len(),
            &mut response.owner,
        )
    };
    if status != JoseFfiStatus::Success.code() || response.owner.is_null() {
        return Err(NativeProviderFailure);
    }
    // SAFETY: The unique owner is live and both output slots are disjoint.
    let status = unsafe {
        rm_jose_owned_response_view_v1(
            JOSE_ABI_VERSION,
            response.owner,
            &mut response.data,
            &mut response.len,
        )
    };
    if status != JoseFfiStatus::Success.code()
        || response.data.is_null()
        || response.len == 0
        || response.len > rm_jose_max_response_bytes()
    {
        return Err(NativeProviderFailure);
    }
    Ok(response)
}

#[derive(Debug, PartialEq, Eq, Error)]
#[error("native provider failure")]
struct NativeProviderFailure;

impl NativeProviderFailure {
    const fn exception_class(&self) -> &'static jni::strings::JNIStr {
        jni::jni_str!("me/really/jose/ReallyMeJoseException$NativeProviderFailure")
    }
}

fn throw_provider_failure_if_clear(env: &mut EnvUnowned<'_>) {
    let _outcome = env.with_env(|env| -> jni::errors::Result<()> {
        if !env.exception_check() {
            env.throw_new_void(NativeProviderFailure.exception_class())?;
        }
        Ok(())
    });
}

fn throw_provider_failure<T>(
    env: &mut jni::Env<'_>,
    failure: NativeProviderFailure,
) -> jni::errors::Result<T> {
    env.throw_new_void(failure.exception_class())?;
    Err(jni::errors::Error::JavaException)
}

#[cfg(test)]
#[path = "kotlin_tests.rs"]
mod kotlin_tests;
