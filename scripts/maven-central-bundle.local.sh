#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

# Usage:
#   MAVEN_SIGNING_KEY_ID=<long-gpg-key-id-or-fingerprint> \
#   MAVEN_SIGNING_PASSWORD="..." \
#   KOTLIN_NATIVE_RESOURCES_DIR=/path/to/full/jvm-native-resources \
#   ANDROID_NDK_HOME=/path/to/android-ndk \
#   ./scripts/maven-central-bundle.local.sh
#
# Output:
#   build/maven-central-upload/out/reallyme-maven-central-<version>.zip
#
# Upload the printed zip in Central Portal as a deployment bundle. The bundle is
# assembled in Maven repository layout and includes the JVM jar and Android AAR.
# If KOTLIN_NATIVE_RESOURCES_DIR is incomplete, this script populates it from
# the Kotlin Android package preflight GitHub Actions matrix for the current commit,
# dispatching that workflow and waiting for it when necessary.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${MAVEN_CENTRAL_WORK_DIR:-${ROOT_DIR}/build/maven-central-upload}"
BUNDLE_ROOT="${WORK_DIR}/bundle-root"
OUTPUT_DIR="${WORK_DIR}/out"
GRADLE="${ROOT_DIR}/packages/kotlin/gradlew"
ANDROID_GRADLE="${ROOT_DIR}/packages/kotlin-android/gradlew"
KOTLIN_NATIVE_RESOURCES_DIR="${KOTLIN_NATIVE_RESOURCES_DIR:-${ROOT_DIR}/build/kotlin-native-resources}"
ANDROID_JNI_LIBS_DIR_WAS_SET="${ANDROID_JNI_LIBS_DIR+x}"
ANDROID_JNI_LIBS_DIR="${ANDROID_JNI_LIBS_DIR:-${WORK_DIR}/android-jniLibs}"
ANDROID_NATIVE_ASSETS_DIR="${WORK_DIR}/android-native-assets"
ANDROID_NDK_VERSION="${ANDROID_NDK_VERSION:-29.0.14206865}"
NATIVE_RESOURCE_WORKFLOW="${MAVEN_NATIVE_RESOURCE_WORKFLOW:-kotlin-android-package-preflight.yml}"
NATIVE_RESOURCE_ARTIFACT_PATTERN="${MAVEN_NATIVE_RESOURCE_ARTIFACT_PATTERN:-kotlin-native-*}"
NATIVE_DIGEST_ARTIFACT_PATTERN="${MAVEN_NATIVE_DIGEST_ARTIFACT_PATTERN:-kotlin-digest-*}"
NATIVE_RESOURCE_DOWNLOAD_DIR="${WORK_DIR}/kotlin-native-artifacts"
NATIVE_DIGEST_DOWNLOAD_DIR="${WORK_DIR}/kotlin-native-digests-artifacts"
KOTLIN_NATIVE_DIGESTS_DIR="${WORK_DIR}/kotlin-native-digests"
NATIVE_RESOURCE_WORKFLOW_TIMEOUT_SECONDS="${MAVEN_NATIVE_RESOURCE_WORKFLOW_TIMEOUT_SECONDS:-3600}"
NATIVE_RESOURCE_RUN_ID="${MAVEN_NATIVE_RESOURCE_RUN_ID:-}"
NATIVE_RESOURCE_COMMIT_MARKER="${KOTLIN_NATIVE_RESOURCES_DIR%/}.reallyme-jose-source-commit"
NATIVE_RESOURCE_LEGACY_COMMIT_MARKER="${KOTLIN_NATIVE_RESOURCES_DIR}/.reallyme-jose-source-commit"

fail() {
  printf 'maven central bundle failed: %s\n' "$1" >&2
  exit 1
}

info() {
  printf '%s\n' "$1" >&2
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required tool not found: $1"
  fi
}

read_gradle_version() {
  local file="$1"
  sed -n 's/^version = "\([^"]*\)".*/\1/p' "$file" | head -n 1
}

require_file() {
  if [ ! -f "$1" ]; then
    fail "missing required file: $1"
  fi
}

require_dir() {
  if [ ! -d "$1" ]; then
    fail "missing required directory: $1"
  fi
}

validate_work_dir() {
  case "$WORK_DIR" in
    /*) ;;
    *) fail "MAVEN_CENTRAL_WORK_DIR must be an absolute path" ;;
  esac
  case "/${WORK_DIR}/" in
    *'/../'*|*'/./'*) fail "MAVEN_CENTRAL_WORK_DIR must not contain dot path segments" ;;
  esac
  case "$WORK_DIR" in
    /|"$ROOT_DIR"|"$ROOT_DIR"/) fail "MAVEN_CENTRAL_WORK_DIR must name a dedicated build directory" ;;
  esac
}

require_zip_entry() {
  local archive="$1"
  local entry="$2"
  if ! jar tf "$archive" | grep -Fx -- "$entry" >/dev/null; then
    fail "$archive is missing archive entry: $entry"
  fi
}

reject_zip_entry_prefix() {
  local archive="$1"
  local prefix="$2"
  if jar tf "$archive" | grep -F -- "$prefix" >/dev/null; then
    fail "$archive contains forbidden archive entries with prefix: $prefix"
  fi
}

kotlin_native_resource_files() {
  printf '%s\n' \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/jose/native/linux-x86_64/libreallyme_jose_ffi.so" \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/jose/native/linux-aarch64/libreallyme_jose_ffi.so" \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/jose/native/macos-x86_64/libreallyme_jose_ffi.dylib" \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/jose/native/macos-aarch64/libreallyme_jose_ffi.dylib" \
    "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/jose/native/windows-x86_64/reallyme_jose_ffi.dll"
}

kotlin_native_resource_root() {
  printf '%s\n' "${KOTLIN_NATIVE_RESOURCES_DIR}/me/really/jose/native"
}

kotlin_native_resources_are_complete() {
  local native_file
  while IFS= read -r native_file; do
    if [ ! -f "$native_file" ]; then
      return 1
    fi
  done < <(kotlin_native_resource_files)
  return 0
}

current_git_ref() {
  local branch
  branch="$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)"
  if [ "$branch" = "HEAD" ]; then
    git -C "$ROOT_DIR" rev-parse HEAD
  else
    printf '%s\n' "$branch"
  fi
}

find_successful_native_resource_run() {
  local head_sha="$1"
  gh run list \
    --workflow "$NATIVE_RESOURCE_WORKFLOW" \
    --commit "$head_sha" \
    --status success \
    --limit 20 \
    --json databaseId,displayTitle,headSha \
    --jq ".[] | select(.headSha == \"${head_sha}\" and .displayTitle == \"Kotlin Android package preflight ${VERSION}\") | .databaseId" \
    | head -n 1
}

latest_native_resource_run_for_head() {
  local head_sha="$1"
  gh run list \
    --workflow "$NATIVE_RESOURCE_WORKFLOW" \
    --commit "$head_sha" \
    --limit 20 \
    --json databaseId,displayTitle,headSha \
    --jq ".[] | select(.headSha == \"${head_sha}\" and .displayTitle == \"Kotlin Android package preflight ${VERSION}\") | .databaseId" \
    | head -n 1
}

native_resource_run_status() {
  local run_id="$1"
  gh run view "$run_id" \
    --json status,conclusion \
    --jq '[.status, (.conclusion // "")] | @tsv'
}

validate_native_resource_run() {
  local run_id="$1"
  local expected_head_sha="$2"
  local expected_workflow_id
  local run_metadata
  local run_head_sha
  local run_status
  local run_conclusion
  local run_workflow_id
  local run_title

  case "$run_id" in
    ''|0|*[!0-9]*)
      fail "Kotlin native resource run id must be a positive GitHub Actions run id"
      ;;
  esac

  expected_workflow_id="$(
    gh api "repos/{owner}/{repo}/actions/workflows/${NATIVE_RESOURCE_WORKFLOW}" --jq '.id'
  )"
  run_metadata="$(
    gh run view "$run_id" \
      --json displayTitle,headSha,status,conclusion,workflowDatabaseId \
      --jq '[.headSha, .status, (.conclusion // ""), (.workflowDatabaseId | tostring), .displayTitle] | @tsv'
  )"
  IFS=$'\t' read -r run_head_sha run_status run_conclusion run_workflow_id run_title <<<"$run_metadata"

  if [ "$run_workflow_id" != "$expected_workflow_id" ]; then
    fail "GitHub Actions run ${run_id} was not produced by ${NATIVE_RESOURCE_WORKFLOW}"
  fi
  if [ "$run_head_sha" != "$expected_head_sha" ]; then
    fail "GitHub Actions run ${run_id} does not belong to the current commit"
  fi
  if [ "$run_title" != "Kotlin Android package preflight ${VERSION}" ]; then
    fail "GitHub Actions run ${run_id} does not certify package version ${VERSION}"
  fi
  if [ "$run_status" != "completed" ] || [ "$run_conclusion" != "success" ]; then
    fail "GitHub Actions run ${run_id} has not completed successfully"
  fi
}

native_resources_match_commit() {
  local expected_head_sha="$1"
  local recorded_head_sha

  if ! kotlin_native_resources_are_complete || [ ! -f "$NATIVE_RESOURCE_COMMIT_MARKER" ]; then
    return 1
  fi
  IFS= read -r recorded_head_sha <"$NATIVE_RESOURCE_COMMIT_MARKER" || return 1
  if [ "$recorded_head_sha" != "$expected_head_sha" ]; then
    return 1
  fi
  node "${ROOT_DIR}/scripts/verify_native_artifact_handoff.mjs" verify \
    "$KOTLIN_NATIVE_RESOURCES_DIR" "$KOTLIN_NATIVE_DIGESTS_DIR" >/dev/null 2>&1
}

record_native_resource_commit() {
  local head_sha="$1"
  mkdir -p "$(dirname "$NATIVE_RESOURCE_COMMIT_MARKER")"
  printf '%s\n' "$head_sha" >"$NATIVE_RESOURCE_COMMIT_MARKER"
  rm -f "$NATIVE_RESOURCE_LEGACY_COMMIT_MARKER"
}

wait_for_native_resource_run_id() {
  local head_sha="$1"
  local excluded_run_id="${2:-}"
  local deadline
  local run_id
  deadline=$((SECONDS + NATIVE_RESOURCE_WORKFLOW_TIMEOUT_SECONDS))

  while [ "$SECONDS" -lt "$deadline" ]; do
    run_id="$(latest_native_resource_run_for_head "$head_sha")"
    if [ -n "$run_id" ] && [ "$run_id" != "$excluded_run_id" ]; then
      printf '%s\n' "$run_id"
      return
    fi
    sleep 5
  done

  fail "timed out waiting for ${NATIVE_RESOURCE_WORKFLOW} to start for ${head_sha}"
}

download_kotlin_native_resources_from_run() {
  local run_id="$1"
  local artifact_dir

  rm -rf \
    "$NATIVE_RESOURCE_DOWNLOAD_DIR" \
    "$NATIVE_DIGEST_DOWNLOAD_DIR" \
    "$KOTLIN_NATIVE_DIGESTS_DIR" \
    "$(kotlin_native_resource_root)"
  rm -f "$NATIVE_RESOURCE_COMMIT_MARKER" "$NATIVE_RESOURCE_LEGACY_COMMIT_MARKER"
  mkdir -p \
    "$NATIVE_RESOURCE_DOWNLOAD_DIR" \
    "$NATIVE_DIGEST_DOWNLOAD_DIR" \
    "$KOTLIN_NATIVE_RESOURCES_DIR" \
    "$KOTLIN_NATIVE_DIGESTS_DIR"
  info "Downloading Kotlin native resource artifacts from GitHub Actions run ${run_id}"
  gh run download "$run_id" \
    --pattern "$NATIVE_RESOURCE_ARTIFACT_PATTERN" \
    --dir "$NATIVE_RESOURCE_DOWNLOAD_DIR"
  gh run download "$run_id" \
    --pattern "$NATIVE_DIGEST_ARTIFACT_PATTERN" \
    --dir "$NATIVE_DIGEST_DOWNLOAD_DIR"

  while IFS= read -r artifact_dir; do
    cp -R "${artifact_dir}/." "$KOTLIN_NATIVE_RESOURCES_DIR/"
  done < <(find "$NATIVE_RESOURCE_DOWNLOAD_DIR" -mindepth 1 -maxdepth 1 -type d | sort)

  while IFS= read -r artifact_dir; do
    cp -R "${artifact_dir}/." "$KOTLIN_NATIVE_DIGESTS_DIR/"
  done < <(find "$NATIVE_DIGEST_DOWNLOAD_DIR" -mindepth 1 -maxdepth 1 -type d | sort)

  node "${ROOT_DIR}/scripts/verify_native_artifact_handoff.mjs" verify \
    "$KOTLIN_NATIVE_RESOURCES_DIR" "$KOTLIN_NATIVE_DIGESTS_DIR"
}

ensure_kotlin_native_resources() {
  local head_sha
  local git_ref
  local run_id
  local run_state
  local run_status
  local run_conclusion
  local stale_run_id=""

  mkdir -p "$KOTLIN_NATIVE_RESOURCES_DIR"
  require_tool git
  head_sha="$(git -C "$ROOT_DIR" rev-parse HEAD)"

  if [ -n "$NATIVE_RESOURCE_RUN_ID" ]; then
    require_tool gh
    validate_native_resource_run "$NATIVE_RESOURCE_RUN_ID" "$head_sha"
    download_kotlin_native_resources_from_run "$NATIVE_RESOURCE_RUN_ID"
    if ! kotlin_native_resources_are_complete; then
      fail "downloaded Kotlin native resources are incomplete; check GitHub Actions run ${NATIVE_RESOURCE_RUN_ID}"
    fi
    record_native_resource_commit "$head_sha"
    return
  fi

  if native_resources_match_commit "$head_sha"; then
    info "Reusing Kotlin native resources verified for current commit ${head_sha}"
    return
  fi

  require_tool gh
  git_ref="$(current_git_ref)"
  run_id="$(find_successful_native_resource_run "$head_sha")"
  if [ -z "$run_id" ]; then
    run_id="$(latest_native_resource_run_for_head "$head_sha")"
    if [ -n "$run_id" ]; then
      run_state="$(native_resource_run_status "$run_id")"
      run_status="${run_state%%$'\t'*}"
      run_conclusion="${run_state#*$'\t'}"
      if [ "$run_status" = "completed" ] && [ "$run_conclusion" != "success" ]; then
        info "Latest ${NATIVE_RESOURCE_WORKFLOW} run ${run_id} for ${head_sha} concluded ${run_conclusion}; dispatching a fresh run"
        stale_run_id="$run_id"
        run_id=""
      else
        info "Waiting for existing ${NATIVE_RESOURCE_WORKFLOW} run ${run_id} for ${head_sha}"
        gh run watch "$run_id" --exit-status
      fi
    fi
  fi
  if [ -z "$run_id" ]; then
    info "No successful or running ${NATIVE_RESOURCE_WORKFLOW} native-resource run found for ${head_sha}"
    info "Kotlin native resources are absent or stale; staging the current host library while the cross-platform run is prepared"
    rm -rf "$(kotlin_native_resource_root)"
    rm -rf "$KOTLIN_NATIVE_DIGESTS_DIR"
    rm -f "$NATIVE_RESOURCE_COMMIT_MARKER" "$NATIVE_RESOURCE_LEGACY_COMMIT_MARKER"
    "${ROOT_DIR}/scripts/build_kotlin_native_resource.sh" "$KOTLIN_NATIVE_RESOURCES_DIR"
    if kotlin_native_resources_are_complete; then
      record_native_resource_commit "$head_sha"
      return
    fi
    info "Dispatching ${NATIVE_RESOURCE_WORKFLOW} on ${git_ref} to build cross-platform Kotlin native resources"
    gh workflow run "$NATIVE_RESOURCE_WORKFLOW" \
      --ref "$git_ref" \
      -f release_sha="$head_sha" \
      -f version="$VERSION"
    run_id="$(wait_for_native_resource_run_id "$head_sha" "$stale_run_id")"
    gh run watch "$run_id" --exit-status
  fi

  validate_native_resource_run "$run_id" "$head_sha"
  download_kotlin_native_resources_from_run "$run_id"
  if ! kotlin_native_resources_are_complete; then
    fail "downloaded Kotlin native resources are incomplete; check GitHub Actions run ${run_id}"
  fi
  record_native_resource_commit "$head_sha"
}

prepare_android_ndk_home() {
  if [ -n "${ANDROID_NDK_HOME:-}" ]; then
    return
  fi
  if [ -n "${ANDROID_HOME:-}" ] && [ -d "${ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION}" ]; then
    export ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION}"
    return
  fi
  fail "ANDROID_NDK_HOME is not set and ${ANDROID_HOME:-\$ANDROID_HOME}/ndk/${ANDROID_NDK_VERSION} was not found"
}

write_checksums() {
  local root="$1"
  node - "$root" <<'NODE'
const { createHash } = require("node:crypto");
const { readdirSync, readFileSync, statSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");

const root = process.argv[2];
const checksumExtensions = new Set([".md5", ".sha1", ".sha256", ".sha512"]);
const algorithms = [
  ["md5", ".md5"],
  ["sha1", ".sha1"],
  ["sha256", ".sha256"],
  ["sha512", ".sha512"],
];

function walk(directory) {
  const entries = [];
  for (const dirent of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, dirent.name);
    if (dirent.isDirectory()) {
      entries.push(...walk(path));
    } else if (dirent.isFile()) {
      entries.push(path);
    }
  }
  return entries;
}

if (!statSync(root).isDirectory()) {
  throw new Error(`${root} is not a directory`);
}

for (const path of walk(root)) {
  if (checksumExtensions.has(path.slice(path.lastIndexOf(".")))) {
    continue;
  }
  const bytes = readFileSync(path);
  for (const [algorithm, extension] of algorithms) {
    writeFileSync(`${path}${extension}`, `${createHash(algorithm).update(bytes).digest("hex")}\n`);
  }
}
NODE
}

validate_bundle_files() {
  local version="$1"
  local jvm_dir="${BUNDLE_ROOT}/me/really/jose/${version}"
  local android_dir="${BUNDLE_ROOT}/me/really/jose-android/${version}"

  require_dir "$jvm_dir"
  require_dir "$android_dir"

  for file in \
    "${jvm_dir}/jose-${version}.jar" \
    "${jvm_dir}/jose-${version}-sources.jar" \
    "${jvm_dir}/jose-${version}-javadoc.jar" \
    "${jvm_dir}/jose-${version}.pom" \
    "${jvm_dir}/jose-${version}.module" \
    "${android_dir}/jose-android-${version}.aar" \
    "${android_dir}/jose-android-${version}-sources.jar" \
    "${android_dir}/jose-android-${version}.pom" \
    "${android_dir}/jose-android-${version}.module"; do
    require_file "$file"
    require_file "${file}.asc"
    require_file "${file}.md5"
    require_file "${file}.sha1"
    require_file "${file}.sha256"
    require_file "${file}.sha512"
    require_file "${file}.asc.md5"
    require_file "${file}.asc.sha1"
    require_file "${file}.asc.sha256"
    require_file "${file}.asc.sha512"
  done

  local jvm_jar="${jvm_dir}/jose-${version}.jar"
  require_zip_entry "$jvm_jar" "me/really/jose/native/linux-x86_64/libreallyme_jose_ffi.so"
  require_zip_entry "$jvm_jar" "me/really/jose/native/linux-aarch64/libreallyme_jose_ffi.so"
  require_zip_entry "$jvm_jar" "me/really/jose/native/macos-x86_64/libreallyme_jose_ffi.dylib"
  require_zip_entry "$jvm_jar" "me/really/jose/native/macos-aarch64/libreallyme_jose_ffi.dylib"
  require_zip_entry "$jvm_jar" "me/really/jose/native/windows-x86_64/reallyme_jose_ffi.dll"
  require_zip_entry "$jvm_jar" "me/really/jose/native/native-manifest.json"
  reject_zip_entry_prefix "${jvm_dir}/jose-${version}-sources.jar" "me/really/jose/native/"
  reject_zip_entry_prefix "${android_dir}/jose-android-${version}-sources.jar" "jni/"
  reject_zip_entry_prefix "${android_dir}/jose-android-${version}-sources.jar" "assets/reallyme-jose/"

  local android_aar="${android_dir}/jose-android-${version}.aar"
  require_zip_entry "$android_aar" "jni/arm64-v8a/libreallyme_jose_ffi.so"
  require_zip_entry "$android_aar" "jni/armeabi-v7a/libreallyme_jose_ffi.so"
  require_zip_entry "$android_aar" "jni/x86_64/libreallyme_jose_ffi.so"
  require_zip_entry "$android_aar" "jni/x86/libreallyme_jose_ffi.so"
  require_zip_entry "$android_aar" "assets/reallyme-jose/native-manifest.json"
}

sign_bundle_files() {
  local root="$1"
  local file

  find "$root" -type f -name '*.asc' -delete
  while IFS= read -r -d '' file; do
    case "$file" in
      *.md5|*.sha1|*.sha256|*.sha512)
        continue
        ;;
    esac
    gpg \
      --batch \
      --yes \
      --pinentry-mode loopback \
      --passphrase-fd 0 \
      --local-user "$MAVEN_SIGNING_KEY_ID" \
      --armor \
      --detach-sign \
      --output "${file}.asc" \
      "$file" <<<"$MAVEN_SIGNING_PASSWORD"
  done < <(find "$root" -type f -print0)
}

verify_bundle_signatures() {
  local root="$1"
  local signature
  local artifact

  while IFS= read -r -d '' signature; do
    artifact="${signature%.asc}"
    require_file "$artifact"
    if ! gpg --batch --verify "$signature" "$artifact" >/dev/null 2>&1; then
      fail "bundle contains an invalid detached signature"
    fi
  done < <(find "$root" -type f -name '*.asc' -print0)
}

remove_local_repository_metadata() {
  local root="$1"
  find "$root" -type f -name 'maven-metadata.xml*' -delete
}

require_tool cargo
require_tool find
require_tool grep
require_tool gpg
require_tool jar
require_tool node
require_tool rustup
require_tool sed
require_tool sleep
require_tool zip
validate_work_dir

if [ -z "${MAVEN_SIGNING_PASSWORD:-}" ]; then
  fail "MAVEN_SIGNING_PASSWORD must contain the GPG private key passphrase"
fi
if [ -z "${MAVEN_SIGNING_KEY_ID:-}" ]; then
  fail "MAVEN_SIGNING_KEY_ID must contain the GPG secret key id or fingerprint"
fi
GPG_SIGN_ARGS=(
  --batch
  --yes
  --pinentry-mode
  loopback
  --passphrase-fd
  0
  --armor
  --detach-sign
  --output
  /dev/null
  --local-user
  "$MAVEN_SIGNING_KEY_ID"
)
if ! printf '%s' "$MAVEN_SIGNING_PASSWORD" | gpg "${GPG_SIGN_ARGS[@]}" >/dev/null 2>&1; then
  fail "GPG could not sign with the configured key id and passphrase; check MAVEN_SIGNING_KEY_ID and MAVEN_SIGNING_PASSWORD"
fi

VERSION="${MAVEN_RELEASE_VERSION:-$(read_gradle_version "${ROOT_DIR}/packages/kotlin/build.gradle.kts")}"
ANDROID_VERSION="$(read_gradle_version "${ROOT_DIR}/packages/kotlin-android/build.gradle.kts")"
if [ -z "$VERSION" ]; then
  fail "unable to read JVM package version"
fi
if [ "$VERSION" != "$ANDROID_VERSION" ]; then
  fail "JVM package version $VERSION does not match Android package version $ANDROID_VERSION"
fi
if [[ "$VERSION" == *SNAPSHOT* ]]; then
  fail "Central Portal release bundles must not use SNAPSHOT versions"
fi

require_file "$GRADLE"
require_file "$ANDROID_GRADLE"
require_file "${ROOT_DIR}/scripts/verify_maven_release_repository.mjs"
require_file "${ROOT_DIR}/scripts/verify_native_artifact_handoff.mjs"
require_file "${ROOT_DIR}/scripts/verify_sdk_release_version.mjs"
info "Using version ${VERSION}"
node "${ROOT_DIR}/scripts/verify_sdk_release_version.mjs" "$VERSION"
info "Using Kotlin native resources from ${KOTLIN_NATIVE_RESOURCES_DIR}"
ensure_kotlin_native_resources
info "Writing JVM native checksum manifest"
node "${ROOT_DIR}/scripts/write_native_manifest.mjs" \
  "$(kotlin_native_resource_root)" \
  "$(kotlin_native_resource_root)/native-manifest.json"

while IFS= read -r native_file; do
  require_file "$native_file"
done < <(kotlin_native_resource_files)
require_file "$(kotlin_native_resource_root)/native-manifest.json"

if [ -z "$ANDROID_JNI_LIBS_DIR_WAS_SET" ]; then
  prepare_android_ndk_home
  info "Building Android JNI libraries into ${ANDROID_JNI_LIBS_DIR}"
  rm -rf "$ANDROID_JNI_LIBS_DIR"
  "${ROOT_DIR}/scripts/build_android_native_resources.sh" "$ANDROID_JNI_LIBS_DIR"
else
  require_dir "$ANDROID_JNI_LIBS_DIR"
  info "Using Android JNI libraries from ${ANDROID_JNI_LIBS_DIR}"
fi

info "Writing Android native checksum manifest"
rm -rf "$ANDROID_NATIVE_ASSETS_DIR"
node "${ROOT_DIR}/scripts/write_native_manifest.mjs" \
  "$ANDROID_JNI_LIBS_DIR" \
  "${ANDROID_NATIVE_ASSETS_DIR}/reallyme-jose/native-manifest.json"

rm -rf "$BUNDLE_ROOT"
mkdir -p "$BUNDLE_ROOT" "$OUTPUT_DIR"

info "Publishing JVM artifacts to the local release repository"
(
  unset MAVEN_SIGNING_KEY MAVEN_SIGNING_PASSWORD
  "$GRADLE" --dependency-verification strict -p "${ROOT_DIR}/packages/kotlin" \
    test \
    verifyJarContainsNativeResources \
    publishMavenPublicationToLocalReleaseRepository \
    -Preallyme.jose.nativeResourcesDir="$KOTLIN_NATIVE_RESOURCES_DIR" \
    -Preallyme.jose.requireFullNativeResources=true \
    -Preallyme.maven.localReleaseRepositoryDir="$BUNDLE_ROOT"
)

info "Publishing Android artifacts to the local release repository"
(
  unset MAVEN_SIGNING_KEY MAVEN_SIGNING_PASSWORD
  "$ANDROID_GRADLE" --dependency-verification strict -p "${ROOT_DIR}/packages/kotlin-android" \
    verifyAndroidJniLibs \
    bundleReleaseAar \
    verifyReleaseAarContainsJniLibs \
    publishReleasePublicationToLocalReleaseRepository \
    -Preallyme.jose.androidJniLibsDir="$ANDROID_JNI_LIBS_DIR" \
    -Preallyme.jose.androidNativeAssetsDir="$ANDROID_NATIVE_ASSETS_DIR" \
    -Preallyme.jose.requireAndroidJniLibs=true \
    -Preallyme.maven.localReleaseRepositoryDir="$BUNDLE_ROOT"
)

info "Verifying staged Maven repository"
node "${ROOT_DIR}/scripts/verify_maven_release_repository.mjs" "$BUNDLE_ROOT" "$VERSION"

info "Removing local Maven repository metadata"
remove_local_repository_metadata "$BUNDLE_ROOT"

info "Signing Maven bundle files with local GPG"
sign_bundle_files "$BUNDLE_ROOT"

info "Verifying Maven bundle signatures"
verify_bundle_signatures "$BUNDLE_ROOT"

info "Writing checksums for artifacts and signatures"
write_checksums "$BUNDLE_ROOT"

info "Validating bundle contents"
validate_bundle_files "$VERSION"

BUNDLE_ZIP="${OUTPUT_DIR}/reallyme-maven-central-${VERSION}.zip"
rm -f "$BUNDLE_ZIP"
info "Creating ${BUNDLE_ZIP}"
(
  cd "$BUNDLE_ROOT"
  COPYFILE_DISABLE=1 zip -X -q -r "$BUNDLE_ZIP" .
)

require_file "$BUNDLE_ZIP"
info "Maven Central upload bundle ready:"
printf '%s\n' "$BUNDLE_ZIP"
