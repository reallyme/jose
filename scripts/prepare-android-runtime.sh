#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly root
readonly apk="${1:?expected an APK output path}"
readonly avd="${2:?expected an AVD name}"
readonly repository="${3:?expected an absolute Maven repository path}"
readonly sdk="${ANDROID_HOME:?expected Android SDK path}"
readonly avd_home="${ANDROID_AVD_HOME:?expected an isolated AVD directory}"
readonly avd_device="${ANDROID_AVD_DEVICE:-pixel}"
readonly image="system-images;android-37.0;google_apis_ps16k;x86_64"
readonly sdk_image="system-images/android-37.0/google_apis_ps16k/x86_64"
[[ "$apk" = /* && "$repository" = /* && -d "$repository" && "$avd" =~ ^[a-zA-Z0-9_-]+$ ]]

cd "$root"
version="$(sed -n 's/^version = "\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)"$/\1/p' packages/kotlin-android/build.gradle.kts)"
node scripts/verify_maven_release_repository.mjs "$repository" "$version" --android-only

# Build against the staged Maven coordinates so R8 loads the consumer rules
# shipped in the distributed AAR and uses the same JNI bytes as preflight.
packages/kotlin-android/gradlew --no-daemon --dependency-verification strict -p packages/kotlin-android \
    :consumer-r8-runtime:assembleRelease \
    -Preallyme.jose.androidConsumerRepository="$repository"
cp packages/kotlin-android/consumer-r8-runtime/build/outputs/apk/release/consumer-r8-runtime-release.apk "$apk"

mkdir -p "$avd_home"
for package in emulator platforms/android-37.0 "$sdk_image"; do
  { yes 2>/dev/null || true; } | "$sdk/cmdline-tools/23.0/bin/android" --sdk="$sdk" --no-metrics sdk install "$package"
done
printf 'no\n' | "$sdk/cmdline-tools/23.0/bin/avdmanager" create avd --force --name "$avd" --package "$image" --device "$avd_device"
# Reject the known Major.Minor parsing failure before booting a broken guest.
if ! grep -Fxq 'target=android-37.0' "$avd_home/$avd.ini"; then
  echo 'Android AVD target does not match the required API 37.0 image.' >&2
  exit 1
fi
