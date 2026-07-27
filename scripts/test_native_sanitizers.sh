#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

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
