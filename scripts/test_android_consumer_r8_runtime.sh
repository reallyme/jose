#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ANDROID_HOME_VALUE="${ANDROID_HOME:-"$HOME/Library/Android/sdk"}"
readonly ANDROID_NDK_HOME_VALUE="${ANDROID_NDK_HOME:-"$ANDROID_HOME_VALUE/ndk/29.0.14206865"}"
readonly ADB="${ADB:-"$ANDROID_HOME_VALUE/platform-tools/adb"}"
readonly EMULATOR="${EMULATOR:-"$ANDROID_HOME_VALUE/emulator/emulator"}"
readonly SDKMANAGER="${SDKMANAGER:-"$ANDROID_HOME_VALUE/cmdline-tools/latest/bin/sdkmanager"}"
readonly AVDMANAGER="${AVDMANAGER:-"$ANDROID_HOME_VALUE/cmdline-tools/latest/bin/avdmanager"}"
readonly ANDROID_AVD_HOME_VALUE="${ANDROID_AVD_HOME:-"$HOME/.android/avd"}"
readonly AVD_NAME="${REALLYME_JOSE_ANDROID_AVD:-}"
readonly ANDROID_R8_PLATFORM="platforms;android-36"
readonly ANDROID_R8_SYSTEM_IMAGE="system-images;android-36;google_apis;x86_64"
readonly APP_ID="me.really.jose.consumer.r8"
readonly ACTIVITY="me.really.jose.consumer.r8.ConsumerR8RuntimeActivity"
readonly LOG_TAG="ReallyMeJoseR8Gate"
readonly JNILIBS_DIR="$REPO_ROOT/build/android-jniLibs"
readonly NATIVE_ASSETS_DIR="$REPO_ROOT/build/android-native-assets"
readonly APK_PATH="$REPO_ROOT/packages/kotlin-android/consumer-r8-runtime/build/outputs/apk/release/consumer-r8-runtime-release.apk"

emulator_pid=""
app_installed="false"
export ANDROID_AVD_HOME="$ANDROID_AVD_HOME_VALUE"

cleanup() {
    if [[ "$app_installed" == "true" ]]; then
        "$ADB" uninstall "$APP_ID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$emulator_pid" ]]; then
        "$ADB" emu kill >/dev/null 2>&1 || true
        wait "$emulator_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

dump_emulator_log() {
    if [[ -f /tmp/reallyme-jose-r8-emulator.log ]]; then
        tail -200 /tmp/reallyme-jose-r8-emulator.log >&2 || true
    fi
}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

ensure_avd_exists() {
    mkdir -p "$ANDROID_AVD_HOME_VALUE"
    [[ -x "$SDKMANAGER" ]] || fail "Android sdkmanager is required at $SDKMANAGER"
    [[ -x "$AVDMANAGER" ]] || fail "Android avdmanager is required at $AVDMANAGER"

    if [[ ! -x "$EMULATOR" ]]; then
        { yes 2>/dev/null || true; } | "$SDKMANAGER" "emulator" >/dev/null
    fi
    [[ -x "$EMULATOR" ]] || fail "Android emulator is required at $EMULATOR"

    local avd_exists="false"
    while IFS= read -r existing_avd; do
        if [[ "$existing_avd" == "$AVD_NAME" ]]; then
            avd_exists="true"
            break
        fi
    done < <("$EMULATOR" -list-avds)

    if [[ "$avd_exists" == "true" ]]; then
        return
    fi

    { yes 2>/dev/null || true; } | "$SDKMANAGER" "emulator" "$ANDROID_R8_PLATFORM" "$ANDROID_R8_SYSTEM_IMAGE" >/dev/null
    printf 'no\n' | "$AVDMANAGER" create avd --force -n "$AVD_NAME" -k "$ANDROID_R8_SYSTEM_IMAGE" --device "pixel" >/tmp/reallyme-jose-r8-avdmanager.log

    while IFS= read -r existing_avd; do
        if [[ "$existing_avd" == "$AVD_NAME" ]]; then
            return
        fi
    done < <("$EMULATOR" -list-avds)

    if [[ -f /tmp/reallyme-jose-r8-avdmanager.log ]]; then
        cat /tmp/reallyme-jose-r8-avdmanager.log >&2 || true
    fi
    "$EMULATOR" -list-avds >&2 || true
    fail "Android AVD was not available after creation"
}

[[ -x "$ADB" ]] || fail "adb is required at $ADB"
[[ -d "$ANDROID_NDK_HOME_VALUE" ]] || fail "ANDROID_NDK_HOME is required at $ANDROID_NDK_HOME_VALUE"

if [[ -n "$AVD_NAME" ]]; then
    ensure_avd_exists
    "$EMULATOR" -avd "$AVD_NAME" -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect >/tmp/reallyme-jose-r8-emulator.log 2>&1 &
    emulator_pid="$!"
fi

device_deadline=$((SECONDS + 120))
until "$ADB" get-state >/dev/null 2>&1; do
    if [[ -n "$emulator_pid" ]] && ! kill -0 "$emulator_pid" >/dev/null 2>&1; then
        dump_emulator_log
        fail "Android emulator exited before adb detected a device"
    fi
    if (( SECONDS > device_deadline )); then
        dump_emulator_log
        fail "Android device was not detected before timeout"
    fi
    sleep 2
done

boot_deadline=$((SECONDS + 240))
while [[ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]]; do
    if (( SECONDS > boot_deadline )); then
        dump_emulator_log
        fail "Android device did not finish booting"
    fi
    sleep 2
done

ANDROID_NDK_HOME="$ANDROID_NDK_HOME_VALUE" "$REPO_ROOT/scripts/build_android_native_resources.sh" "$JNILIBS_DIR"
node "$REPO_ROOT/scripts/write_native_manifest.mjs" "$JNILIBS_DIR" "$NATIVE_ASSETS_DIR/reallyme-jose/native-manifest.json"

ANDROID_NDK_HOME="$ANDROID_NDK_HOME_VALUE" "$REPO_ROOT/packages/kotlin/gradlew" \
    -p "$REPO_ROOT/packages/kotlin-android" \
    :consumer-r8-runtime:assembleRelease \
    -Preallyme.jose.androidJniLibsDir="$JNILIBS_DIR" \
    -Preallyme.jose.androidNativeAssetsDir="$NATIVE_ASSETS_DIR" \
    -Preallyme.jose.requireAndroidJniLibs=true

"$ADB" install -r "$APK_PATH" >/dev/null
app_installed="true"
"$ADB" logcat -c
"$ADB" shell am force-stop "$APP_ID" >/dev/null 2>&1 || true
"$ADB" shell am start -W -n "$APP_ID/$ACTIVITY" >/dev/null

log_deadline=$((SECONDS + 60))
while (( SECONDS <= log_deadline )); do
    logs="$("$ADB" logcat -d -v brief -s "$LOG_TAG:I" 2>/dev/null || true)"
    if [[ "$logs" == *"$LOG_TAG"*"FAIL"* ]]; then
        printf '%s\n' "$logs" >&2
        fail "Android consumer R8 runtime gate failed"
    fi
    if [[ "$logs" == *"$LOG_TAG"*"PASS"* ]]; then
        printf '%s\n' "Android consumer R8 runtime gate passed"
        exit 0
    fi
    sleep 1
done

"$ADB" logcat -d -v brief -s "$LOG_TAG:I" >&2 || true
fail "Android consumer R8 runtime gate timed out"
