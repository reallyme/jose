#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly root
readonly repository="${1:?expected an absolute Maven repository path}"
[[ "$repository" = /* && -d "$repository" && -z "$(ls -A "$repository")" ]]

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$root"

scripts/build_android_native_resources.sh "$work/jniLibs"
node scripts/write_native_manifest.mjs "$work/jniLibs" "$work/assets/reallyme-jose/native-manifest.json"
packages/kotlin-android/gradlew --no-daemon --dependency-verification strict -p packages/kotlin-android \
    verifyAndroidJniLibs verifyReleaseAarContainsJniLibs publishReleasePublicationToLocalReleaseRepository \
    -Preallyme.jose.androidJniLibsDir="$work/jniLibs" \
    -Preallyme.jose.androidNativeAssetsDir="$work/assets" \
    -Preallyme.jose.requireAndroidJniLibs=true \
    -Preallyme.maven.localReleaseRepositoryDir="$repository"

version="$(sed -n 's/^version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p' packages/kotlin-android/build.gradle.kts)"
node scripts/verify_maven_release_repository.mjs "$repository" "$version" --android-only
