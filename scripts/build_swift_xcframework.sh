#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Cargo gives encoded flags precedence over RUSTFLAGS. Release packaging owns
# the complete codegen policy, so inherited encoded flags must not participate.
unset CARGO_ENCODED_RUSTFLAGS
readonly BUILD_DIR="${ROOT_DIR}/build/swift"
readonly HEADERS_DIR="${BUILD_DIR}/headers"
readonly FRAMEWORK_DIR="${BUILD_DIR}/ReallyMeJOSEFFI.xcframework"
readonly ZIP_PATH="${BUILD_DIR}/ReallyMeJOSEFFI.xcframework.zip"
readonly CHECKSUM_PATH="${BUILD_DIR}/ReallyMeJOSEFFI.xcframework.checksum"

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required tool not found: %s\n' "$1" >&2
    exit 1
  fi
}

build_target() {
  local target="$1"
  rustup target add "${target}"
  # Do not let ambient codegen flags override the audited panic strategy.
  RUSTFLAGS="" cargo build --locked -p reallyme-jose-ffi \
    --profile release-ffi \
    --target "${target}"
}

copy_or_lipo() {
  local output="$1"
  shift
  if [ "$#" -eq 1 ]; then
    cp "$1" "${output}"
  else
    lipo -create "$@" -output "${output}"
  fi
}

install_module_maps() {
  local slice
  for slice in "${FRAMEWORK_DIR}"/*; do
    if [ -d "${slice}/Headers" ]; then
      mkdir -p "${slice}/Modules"
      cp "${ROOT_DIR}/crates/ffi/include/reallyme_jose.modulemap" \
        "${slice}/Modules/module.modulemap"
    fi
  done
}

verify_xcframework_layout() {
  local header_modulemap
  header_modulemap="$(find "${FRAMEWORK_DIR}" -path '*/Headers/module.modulemap' -print -quit)"
  if [ -n "${header_modulemap}" ]; then
    printf 'invalid SwiftPM artifact layout: module map must not be exported from Headers: %s\n' \
      "${header_modulemap}" >&2
    exit 1
  fi
}

for tool in cargo rustup xcodebuild lipo find sort swift touch zip; do
  require_tool "${tool}"
done

rm -rf "${BUILD_DIR}"
mkdir -p "${HEADERS_DIR}" "${BUILD_DIR}/libs"
cp "${ROOT_DIR}/crates/ffi/include/reallyme_jose.h" "${HEADERS_DIR}/reallyme_jose.h"

build_target aarch64-apple-darwin
build_target x86_64-apple-darwin
build_target aarch64-apple-ios
build_target aarch64-apple-ios-sim
build_target x86_64-apple-ios

copy_or_lipo "${BUILD_DIR}/libs/libreallyme_jose_ffi_macos.a" \
  "${ROOT_DIR}/target/aarch64-apple-darwin/release-ffi/libreallyme_jose_ffi.a" \
  "${ROOT_DIR}/target/x86_64-apple-darwin/release-ffi/libreallyme_jose_ffi.a"
copy_or_lipo "${BUILD_DIR}/libs/libreallyme_jose_ffi_ios.a" \
  "${ROOT_DIR}/target/aarch64-apple-ios/release-ffi/libreallyme_jose_ffi.a"
copy_or_lipo "${BUILD_DIR}/libs/libreallyme_jose_ffi_ios_simulator.a" \
  "${ROOT_DIR}/target/aarch64-apple-ios-sim/release-ffi/libreallyme_jose_ffi.a" \
  "${ROOT_DIR}/target/x86_64-apple-ios/release-ffi/libreallyme_jose_ffi.a"

xcodebuild -create-xcframework \
  -library "${BUILD_DIR}/libs/libreallyme_jose_ffi_macos.a" -headers "${HEADERS_DIR}" \
  -library "${BUILD_DIR}/libs/libreallyme_jose_ffi_ios.a" -headers "${HEADERS_DIR}" \
  -library "${BUILD_DIR}/libs/libreallyme_jose_ffi_ios_simulator.a" -headers "${HEADERS_DIR}" \
  -output "${FRAMEWORK_DIR}"

cp "${ROOT_DIR}/scripts/swift-xcframework-info.plist" "${FRAMEWORK_DIR}/Info.plist"
install_module_maps
verify_xcframework_layout

(
  cd "${BUILD_DIR}"
  TZ=UTC find "ReallyMeJOSEFFI.xcframework" -exec touch -t 198001010000 {} +
  find "ReallyMeJOSEFFI.xcframework" -print \
    | LC_ALL=C sort \
    | zip -X -q "ReallyMeJOSEFFI.xcframework.zip" -@
)
swift package compute-checksum "${ZIP_PATH}" >"${CHECKSUM_PATH}"
printf 'SwiftPM artifact: %s\n' "${ZIP_PATH}"
printf 'SwiftPM checksum: %s\n' "$(cat "${CHECKSUM_PATH}")"
