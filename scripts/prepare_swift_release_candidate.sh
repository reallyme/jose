#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [ "$#" -ne 1 ] || [[ ! "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'usage: scripts/prepare_swift_release_candidate.sh <semantic-version>\n' >&2
  exit 2
fi

readonly RELEASE_VERSION_INPUT="$1"
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ARCHIVE_PATH="${ROOT_DIR}/build/swift/ReallyMeJOSEFFI.xcframework.zip"
readonly CHECKSUM_PATH="${ROOT_DIR}/build/swift/ReallyMeJOSEFFI.xcframework.checksum"

cd "${ROOT_DIR}"
# Package.swift does not participate in the Rust build. Binding its checksum
# after archive creation therefore records the bytes produced from this source
# tree without creating a checksum/build cycle.
scripts/build_swift_xcframework.sh
IFS= read -r swiftpm_checksum <"${CHECKSUM_PATH}"
if [[ ! "${swiftpm_checksum}" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'generated SwiftPM checksum is malformed\n' >&2
  exit 1
fi
node scripts/prepare_swift_binary_manifest.mjs "${RELEASE_VERSION_INPUT}" "${swiftpm_checksum}"
node scripts/verify_swift_release_artifact.mjs \
  "${ARCHIVE_PATH}" "${CHECKSUM_PATH}" Package.swift "${RELEASE_VERSION_INPUT}"
printf 'Prepared Package.swift for %s with SwiftPM checksum %s\n' \
  "${RELEASE_VERSION_INPUT}" "${swiftpm_checksum}"
