#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

sha=$(git rev-parse --verify HEAD)
test "$sha" = "$GITHUB_SHA"
export ADB="${ANDROID_HOME:?}/platform-tools/adb"
helper=.release-readiness/scripts/android-runtime.mjs
# The cold-boot deadline covers ADB discovery, boot, and system services.
readonly readiness_wait_seconds=420
readonly service_recovery_wait_seconds=60
readonly max_install_attempts=3
readonly install_retry_delay_seconds=5
emulator_log="$RUNNER_TEMP/android-runtime-emulator.log"
emulator_pid=

stop_emulator() {
  if [[ -z "$emulator_pid" ]]; then
    return
  fi
  kill -TERM "$emulator_pid" 2>/dev/null || true
  for ((poll = 0; poll < 5; poll += 1)); do
    kill -0 "$emulator_pid" 2>/dev/null || break
    sleep 1
  done
  kill -KILL "$emulator_pid" 2>/dev/null || true
  wait "$emulator_pid" 2>/dev/null || true
  emulator_pid=
}

collect_diagnostics() {
  node "$helper" diagnostics "$ANDROID_SERIAL" || true
  # Prefix host output and neutralize legacy workflow command markers.
  LC_ALL=C tail -n 200 "$emulator_log" | tr -cd '\11\12\40-\176' | sed 's/##\[/# #[/g; s/^/emulator | /' >&2 || true
}

cleanup() {
  local result=$?
  trap - EXIT
  if [[ -n "$emulator_pid" ]]; then
    if (( result != 0 )); then
      collect_diagnostics
    fi
    stop_emulator
  fi
  exit "$result"
}
trap cleanup EXIT

timeout --kill-after=2s 10s "$ADB" start-server
for attempt in 1 2; do
  "$ANDROID_HOME/emulator/emulator" -avd "$ANDROID_AVD_NAME" -port 5554 \
    -no-window -no-audio -no-boot-anim -no-snapshot -wipe-data \
    -gpu swiftshader -partition-size 4096 \
    >"$emulator_log" 2>&1 &
  emulator_pid=$!

  if node "$helper" wait "$ANDROID_SERIAL" "$readiness_wait_seconds"; then
    break
  else
    result=$?
    if (( result != 75 || attempt == 2 )); then
      exit "$result"
    fi
    echo "Restarting the Android emulator after a cold-boot readiness timeout." >&2
    collect_diagnostics
    stop_emulator
  fi
done

for ((attempt = 1; attempt <= max_install_attempts; attempt++)); do
  if node "$helper" install "$ANDROID_SERIAL" "$APK_PATH"; then
    break
  else
    result=$?
    if (( result != 75 || attempt == max_install_attempts )); then
      exit "$result"
    fi
  fi
  # Wiping the emulator would repeat the package-service startup race.
  echo "Rechecking Android package services before retrying APK installation." >&2
  sleep "$install_retry_delay_seconds"
  node "$helper" wait "$ANDROID_SERIAL" "$service_recovery_wait_seconds"
done

# Confirm that JNI runs on a guest with the release's required page size.
page_size="$(timeout --kill-after=2s 10s "$ADB" -s "$ANDROID_SERIAL" shell getconf PAGE_SIZE | tr -d '\r')"
if [[ "$page_size" != 16384 ]]; then
  echo '::error::Android runtime CI requires a 16 KiB page-size guest.' >&2
  exit 1
fi

# Preserve system, events and crash buffers for failure diagnostics.
timeout --kill-after=2s 10s "$ADB" -s "$ANDROID_SERIAL" logcat -b main -c
bash -e -o pipefail scripts/test-android-runtime.sh "$ANDROID_SERIAL"
node "$helper" verify-publication "$MAVEN_REPOSITORY" "$sha"
printf 'sha=%s\n' "$sha" >>"$GITHUB_OUTPUT"
