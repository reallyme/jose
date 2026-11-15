#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if [[ -n "${FORMAL_RESULTS_DIRECTORY:-}" ]]; then
  results_directory="$FORMAL_RESULTS_DIRECTORY"
  mkdir -p "$results_directory"
else
  results_directory="$(mktemp -d)"
  trap 'rm -rf "$results_directory"' EXIT
fi

lock_object="$(git hash-object Cargo.lock)"
cargo fetch --locked
CARGO_NET_OFFLINE=true cargo kani --package reallyme-jose --lib --no-default-features \
  --features native,wire --output-format terse -Z stubbing -Z unstable-options \
  --jobs 2 --export-json "$results_directory/verification-jose.json"
CARGO_NET_OFFLINE=true cargo kani --package reallyme-jose-ffi --lib --no-default-features \
  --features native --output-format terse -Z stubbing -Z unstable-options \
  --jobs 2 --export-json "$results_directory/verification-ffi.json"
test "$(git hash-object Cargo.lock)" = "$lock_object"

# A Kani success status alone does not require that all cover goals be reachable.
for report in "$results_directory"/verification-*.json; do
  jq --exit-status '
    .verification_results.results as $results
    | ($results | length > 0) and all($results[];
        .status == "Success"
        and ([.checks[] | select(.category == "cover")] as $covers
          | ($covers | length > 0) and all($covers[]; .status == "Satisfied")))
  ' "$report"
done
