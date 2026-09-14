#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# Encoded flags take precedence over RUSTFLAGS and would disable instrumentation.
unset CARGO_ENCODED_RUSTFLAGS

readonly TOOLCHAIN="${REALLYME_JOSE_SANITIZER_TOOLCHAIN:-nightly-2026-07-01}"
readonly TARGET="${REALLYME_JOSE_SANITIZER_TARGET:-$(rustc +"${TOOLCHAIN}" -vV | sed -n 's/^host: //p')}"
readonly TEST_ARGS=(
  test
  --locked
  -p reallyme-jose-ffi
  --tests
  --target "${TARGET}"
)

RUSTFLAGS="-Zsanitizer=address" cargo +"${TOOLCHAIN}" "${TEST_ARGS[@]}"

# This pinned nightly does not expose LLVM UBSan as
# `-Zsanitizer=undefined`; these are the available runtime UB checks.
RUSTFLAGS="-Zub-checks=yes -Zextra-const-ub-checks=yes" \
  cargo +"${TOOLCHAIN}" "${TEST_ARGS[@]}"
