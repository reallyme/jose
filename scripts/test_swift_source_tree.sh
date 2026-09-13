#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
runtime_marker="${repository_root}/.reallyme-jose-runtime-ffi"
native_library="${repository_root}/target/debug/libreallyme_jose_ffi.dylib"
created_marker=0

cleanup() {
  if [[ "${created_marker}" -eq 1 ]]; then
    rm -f -- "${runtime_marker}"
  fi
}
trap cleanup EXIT HUP INT TERM

cargo build --locked --manifest-path "${repository_root}/Cargo.toml" -p reallyme-jose-ffi
if [[ ! -e "${runtime_marker}" ]]; then
  touch "${runtime_marker}"
  created_marker=1
fi

REALLYME_JOSE_FFI_LIBRARY_PATH="${native_library}" \
  REALLYME_JOSE_SWIFTPM_RUNTIME_FFI=1 \
  swift test \
    --package-path "${repository_root}" \
    -Xswiftc -strict-concurrency=complete \
    -Xswiftc -warnings-as-errors
