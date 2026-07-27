#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SYMBOLS=(
  rm_jose_abi_version
  rm_jose_max_request_bytes
  rm_jose_max_json_request_bytes
  rm_jose_max_response_bytes
  rm_jose_execute_operation_v1
  rm_jose_execute_operation_json_v1
  rm_jose_zeroize_buffer
)

case "$(uname -s)" in
  Darwin)
    readonly LIBRARY_PATH="${ROOT_DIR}/target/release-ffi/libreallyme_jose_ffi.dylib"
    ;;
  Linux)
    readonly LIBRARY_PATH="${ROOT_DIR}/target/release-ffi/libreallyme_jose_ffi.so"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    readonly LIBRARY_PATH="${ROOT_DIR}/target/release-ffi/reallyme_jose_ffi.dll"
    ;;
  *)
    echo "unsupported host for release artifact ABI test" >&2
    exit 1
    ;;
esac

cd "${ROOT_DIR}"

readonly TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reallyme-jose-ffi.XXXXXX")"
trap 'rm -rf "${TEMP_DIR}"' EXIT

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
  -I crates/ffi/include \
  -c crates/ffi/tests/header_smoke.c \
  -o "${TEMP_DIR}/header_smoke.o"

if env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS \
  cargo build --locked -p reallyme-jose-ffi --release \
  >"${TEMP_DIR}/abort-build.log" 2>&1; then
  echo "release FFI build unexpectedly succeeded without panic=unwind" >&2
  exit 1
fi

env -u CARGO_ENCODED_RUSTFLAGS RUSTFLAGS="" \
  cargo build --locked -p reallyme-jose-ffi --profile release-ffi

if [[ ! -f "${LIBRARY_PATH}" ]]; then
  echo "release FFI artifact was not produced at ${LIBRARY_PATH}" >&2
  exit 1
fi

if command -v nm >/dev/null 2>&1; then
  readonly NM_TOOL="nm"
elif command -v llvm-nm >/dev/null 2>&1; then
  readonly NM_TOOL="llvm-nm"
else
  echo "nm or llvm-nm is required for release artifact symbol verification" >&2
  exit 1
fi

"${NM_TOOL}" -g "${LIBRARY_PATH}" >"${TEMP_DIR}/symbols.txt"
for symbol in "${SYMBOLS[@]}"; do
  if ! grep -Eq "(^|[[:space:]])_?${symbol}$" "${TEMP_DIR}/symbols.txt"; then
    echo "release FFI artifact is missing exported symbol ${symbol}" >&2
    exit 1
  fi
done

echo "release FFI ABI artifact verified: ${LIBRARY_PATH}"
