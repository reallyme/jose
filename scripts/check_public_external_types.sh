#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly TOOLCHAIN="nightly-2026-03-20"

if [ "$#" -eq 0 ]; then
  ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  readonly ROOT_DIR
  cd "${ROOT_DIR}"
  # The checker consumes rustdoc JSON format 57 from this nightly. Only its
  # documentation pass uses the older compiler; normal builds enforce Rust 1.99.
  export CARGO="${ROOT_DIR}/scripts/check_public_external_types.sh"
  export RUSTUP_TOOLCHAIN="${TOOLCHAIN}"
  exec cargo-check-external-types check-external-types \
    --manifest-path crates/jose/Cargo.toml --all-features
fi

if [ "$1" = "rustdoc" ]; then
  shift
  exec cargo +"${TOOLCHAIN}" rustdoc --locked --ignore-rust-version "$@"
fi

exec cargo +"${TOOLCHAIN}" "$@"
