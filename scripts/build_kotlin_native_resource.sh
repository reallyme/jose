#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT_DIR
readonly RESOURCES_ROOT="${1:-${ROOT_DIR}/build/kotlin-native-resources}"
export CARGO_TARGET_DIR="${ROOT_DIR}/target"

# Packaged FFI binaries must be governed only by the reviewed workspace
# profile; inherited codegen flags could silently change its unwind contract.
unset CARGO_ENCODED_RUSTFLAGS
RUSTFLAGS=""
export RUSTFLAGS
for variable in ${!CARGO_@}; do
  case "${variable}" in
    CARGO_BUILD_RUSTFLAGS|CARGO_BUILD_TARGET|CARGO_TARGET_*_RUSTFLAGS|CARGO_PROFILE_*)
      unset "${variable}" ;;
  esac
done

case "$(uname -s):$(uname -m)" in
  Darwin:x86_64) platform="macos-x86_64"; library="libreallyme_jose_ffi.dylib" ;;
  Darwin:arm64) platform="macos-aarch64"; library="libreallyme_jose_ffi.dylib" ;;
  Linux:x86_64) platform="linux-x86_64"; library="libreallyme_jose_ffi.so" ;;
  Linux:aarch64) platform="linux-aarch64"; library="libreallyme_jose_ffi.so" ;;
  MINGW*:x86_64|MSYS*:x86_64|CYGWIN*:x86_64)
    platform="windows-x86_64"; library="reallyme_jose_ffi.dll" ;;
  *) printf 'unsupported host for Kotlin native resource staging\n' >&2; exit 1 ;;
esac

(
  cd "${ROOT_DIR}"
  rm -f -- "${CARGO_TARGET_DIR}/release-ffi/${library}"
  cargo build --locked -p reallyme-jose-ffi --profile release-ffi
)
readonly OUTPUT_DIR="${RESOURCES_ROOT}/me/really/jose/native/${platform}"
mkdir -p "${OUTPUT_DIR}"
cp "${ROOT_DIR}/target/release-ffi/${library}" "${OUTPUT_DIR}/${library}"
