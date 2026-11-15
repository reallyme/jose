#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly serial="${1:?expected a device serial}"
readonly adb="${ADB:-${ANDROID_HOME:?expected Android SDK path}/platform-tools/adb}"
readonly APP_ID="me.really.jose.consumer.r8"
readonly ACTIVITY="me.really.jose.consumer.r8.ConsumerR8RuntimeActivity"
readonly LOG_TAG="ReallyMeJoseR8Gate"
if [[ ! "$serial" =~ ^[a-zA-Z0-9_.:-]+$ || ! -x "$adb" ]]; then
    printf '%s\n' 'Expected a valid Android device serial and an executable adb' >&2
    exit 1
fi

device_adb() {
    if command -v timeout >/dev/null 2>&1; then
        timeout --kill-after=2s 15s "$adb" -s "$serial" "$@"
    else
        "$adb" -s "$serial" "$@"
    fi
}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

device_adb shell am force-stop "$APP_ID" >/dev/null 2>&1 || true
device_adb shell am start -W -n "$APP_ID/$ACTIVITY" >/dev/null

log_deadline=$((SECONDS + 60))
while (( SECONDS <= log_deadline )); do
    logs="$(device_adb logcat -d -v brief -s "$LOG_TAG:I" 2>/dev/null || true)"
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

device_adb logcat -d -v brief -s "$LOG_TAG:I" >&2 || true
fail "Android consumer R8 runtime gate timed out"
