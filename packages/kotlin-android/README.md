# ReallyMe JOSE for Android

`me.really:jose-android` provides the Kotlin/JVM JOSE API on Android API 24 or
newer. The AAR includes `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86` native
libraries and supports the Android 16 KiB page-size requirement on 64-bit ABIs.

## Install

```kotlin
repositories { mavenCentral() }
dependencies { implementation("me.really:jose-android:0.7.0") }
```

Use the packaged native library and consumer R8 rules. `loadLibrary(path)` is
for explicit development/test use and does not verify a caller-supplied file
digest. API usage, verification modes, and caller-owned buffer cleanup are
covered by the [Kotlin/JVM package](../kotlin/README.md).

## Source-tree build

With the Android SDK and NDK installed, run from the repository root:

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

The `:consumer-r8-runtime:assembleRelease` task builds a minified consumer APK
for checking the packaged JNI and R8 rules.

## License

Licensed under either the [MIT License](../../LICENSE-MIT) or the
[Apache License, Version 2.0](../../LICENSE-APACHE), at your option. See
[NOTICE](../../NOTICE).
