<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe JOSE for Android

`me.really:jose-android:0.3.0` is the Android AAR form of the typed Kotlin/JVM
JOSE facade. It packages the same Java/Kotlin API and Rust JNI boundary for
API 24 or newer; application code never loads an arbitrary native path.

The release AAR contains `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`
libraries built from the reviewed source checkout with the workspace-owned
`release-ffi` profile. That profile fixes the FFI unwind contract independently
of ambient Rust code-generation flags. A
SHA-256/size manifest records every exact `.so`, the source commit, and package
schema. AAR verification re-hashes the bytes after packaging.
The 64-bit ELF LOAD segments are also checked for Android's 16 KiB page-size
alignment requirement; 32-bit libraries remain covered by exact inventory and
manifest verification.

Consumer rules preserve the JNI-resolved class and generated Protobuf Lite
field layout. The release gate builds a minified consumer APK and an emulator
test launches the consumer activity through all 96 checked-in JWS, JWT, JWE,
and panva cases, binary/ProtoJSON parity, typed wire failures, and managed
cleanup paths.

```sh
ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865" \
  scripts/build_android_native_resources.sh build/android-jniLibs
node scripts/write_native_manifest.mjs \
  build/android-jniLibs \
  build/android-native-assets/reallyme-jose/native-manifest.json
packages/kotlin/gradlew -p packages/kotlin-android \
  bundleReleaseAar verifyReleaseAarContainsJniLibs \
  :consumer-r8-runtime:assembleRelease \
  -Preallyme.jose.androidJniLibsDir="$PWD/build/android-jniLibs" \
  -Preallyme.jose.androidNativeAssetsDir="$PWD/build/android-native-assets" \
  -Preallyme.jose.requireAndroidJniLibs=true
```

The Android managed-memory limitations are identical to the JVM package:
callers should clear returned plaintext/claims arrays promptly, while strings,
protobuf internals, and runtime copies cannot guarantee native-style erasure.

The package preflight stages both `me.really:jose` and
`me.really:jose-android` into one isolated Maven repository, validates their
POM and Gradle metadata, and executes the minified emulator corpus. The
credentialed workflow publishes only after the exact current `main` SHA and
version-bound preflight are re-attested. One job signs and promotes the exact
staged JVM and Android bytes together, uses conditional remote creation to
reject an existing version, rolls back files created by a partial attempt, and
downloads every published file for byte verification. Remote publication
requires an HTTPS repository, credentials, and in-memory signing material.

The Android package launcher delegates to the repository's single pinned
Gradle 9.6.1 wrapper, avoiding a second wrapper JAR and distribution checksum
that could drift independently.
