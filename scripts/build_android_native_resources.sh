#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JNI_LIBS_ROOT="${1:-${ROOT_DIR}/packages/kotlin-android/build/generated/android-jniLibs}"
ANDROID_API="${ANDROID_API:-24}"

# Packaged FFI binaries must be governed only by the reviewed workspace
# profile; inherited codegen flags could silently change its unwind contract.
unset CARGO_ENCODED_RUSTFLAGS
unset RUSTFLAGS

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  printf 'ANDROID_NDK_HOME must point to an installed Android NDK\n' >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin)
    NDK_HOST_TAG="darwin-x86_64"
    ;;
  Linux)
    NDK_HOST_TAG="linux-x86_64"
    ;;
  *)
    printf 'unsupported host for Android native resource build\n' >&2
    exit 1
    ;;
esac

TOOLCHAIN_BIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/${NDK_HOST_TAG}/bin"
if [ ! -d "${TOOLCHAIN_BIN}" ]; then
  printf 'Android NDK LLVM toolchain not found at %s\n' "${TOOLCHAIN_BIN}" >&2
  exit 1
fi

build_android_target() {
  local abi="$1"
  local rust_target="$2"
  local clang_prefix="$3"
  local linker_var="$4"
  local ar_var="$5"

  rustup target add "${rust_target}"
  export "${linker_var}=${TOOLCHAIN_BIN}/${clang_prefix}${ANDROID_API}-clang"
  export "${ar_var}=${TOOLCHAIN_BIN}/llvm-ar"
  cargo build --locked -p reallyme-jose-ffi --profile release-ffi --target "${rust_target}"

  mkdir -p "${JNI_LIBS_ROOT}/${abi}"
  local staged_library="${JNI_LIBS_ROOT}/${abi}/libreallyme_jose_ffi.so"
  cp "${ROOT_DIR}/target/${rust_target}/release-ffi/libreallyme_jose_ffi.so" \
    "${staged_library}"
  "${TOOLCHAIN_BIN}/llvm-strip" --strip-debug "${staged_library}"
}

build_android_target \
  "arm64-v8a" \
  "aarch64-linux-android" \
  "aarch64-linux-android" \
  "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER" \
  "AR_aarch64_linux_android"

build_android_target \
  "armeabi-v7a" \
  "armv7-linux-androideabi" \
  "armv7a-linux-androideabi" \
  "CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER" \
  "AR_armv7_linux_androideabi"

build_android_target \
  "x86_64" \
  "x86_64-linux-android" \
  "x86_64-linux-android" \
  "CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER" \
  "AR_x86_64_linux_android"

build_android_target \
  "x86" \
  "i686-linux-android" \
  "i686-linux-android" \
  "CARGO_TARGET_I686_LINUX_ANDROID_LINKER" \
  "AR_i686_linux_android"
