// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! JNI bridge for the typed Kotlin/JVM JOSE facade.
//!
//! JNI owns only managed-array conversion and typed transport failures. Every
//! request is executed through the frozen C ABI so JVM and Swift cannot drift
//! onto a second semantic path.

use std::ptr;

use jni::objects::{JByteArray, JObject};
use jni::sys::{jbyteArray, jint, jlong};
use jni::{EnvUnowned, Outcome};
use zeroize::Zeroizing;

use crate::guard::catch_boundary_unwind;
use crate::operation::{
    rm_jose_abi_version, rm_jose_execute_operation_json_v1, rm_jose_execute_operation_v1,
    rm_jose_max_json_request_bytes, rm_jose_max_request_bytes, rm_jose_max_response_bytes,
    JOSE_ABI_VERSION,
};
use crate::status::JoseFfiStatus;

type ExecuteFunction =
    unsafe extern "C" fn(u32, *const u8, usize, *mut u8, usize, *mut usize) -> i32;

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
        rm_jose_execute_operation_v1,
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
        rm_jose_execute_operation_json_v1,
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
            let response = call_c_boundary(env, request.as_slice(), execute)?;
            env.byte_array_from_slice(response.as_slice())
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
        Err(_) => return throw_provider_failure(env),
    };
    if request_len > maximum_request_bytes {
        // Ask Rust to produce its canonical resource-limit response without
        // copying an attacker-sized managed array into native memory.
        let sentinel_len = match maximum_request_bytes.checked_add(1) {
            Some(value) => value,
            None => return throw_provider_failure(env),
        };
        return Ok(Zeroizing::new(vec![0_u8; sentinel_len]));
    }
    match env.convert_byte_array(&request) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(_) => throw_provider_failure(env),
    }
}

fn call_c_boundary<'local>(
    env: &mut jni::Env<'local>,
    request: &[u8],
    execute: ExecuteFunction,
) -> jni::errors::Result<Zeroizing<Vec<u8>>> {
    let mut produced_len = 0_usize;
    // SAFETY: The JNI-frame-owned request and stack-owned length remain live
    // for the call; the capacity probe deliberately supplies no output range.
    let probe_status = unsafe {
        execute(
            JOSE_ABI_VERSION,
            request.as_ptr(),
            request.len(),
            ptr::null_mut(),
            0,
            &mut produced_len,
        )
    };
    if probe_status != JoseFfiStatus::OutputCapacityMismatch.code()
        || produced_len == 0
        || produced_len > rm_jose_max_response_bytes()
    {
        return throw_provider_failure(env);
    }

    let mut output = Zeroizing::new(vec![0_u8; produced_len]);
    // SAFETY: Request and output are distinct owned vectors and the exact
    // probed capacity is live and exclusively writable for this call.
    let status = unsafe {
        execute(
            JOSE_ABI_VERSION,
            request.as_ptr(),
            request.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut produced_len,
        )
    };
    if status != JoseFfiStatus::Success.code() || produced_len != output.len() {
        return throw_provider_failure(env);
    }
    Ok(output)
}

fn throw_provider_failure_if_clear(env: &mut EnvUnowned<'_>) {
    let _outcome = env.with_env(|env| -> jni::errors::Result<()> {
        if !env.exception_check() {
            env.throw_new_void(jni::jni_str!(
                "me/really/jose/ReallyMeJoseException$NativeProviderFailure"
            ))?;
        }
        Ok(())
    });
}

fn throw_provider_failure<'local, T>(env: &mut jni::Env<'local>) -> jni::errors::Result<T> {
    env.throw_new_void(jni::jni_str!(
        "me/really/jose/ReallyMeJoseException$NativeProviderFailure"
    ))?;
    Err(jni::errors::Error::JavaException)
}

#[cfg(test)]
#[path = "kotlin_tests.rs"]
mod kotlin_tests;
